import csv
from datetime import date

from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db import transaction
from django.db.models import Case, IntegerField, Value, When
from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest
from django.shortcuts import get_object_or_404, render
from django.utils import timezone
from django.views.decorators.http import require_GET, require_POST

from accounts.permissions import require_triage
from accounts.tenancy import get_active_membership
from compliance import selectors
from compliance.models import Finding, Repository, ScanRun, TriageEvent
from compliance.pdf_export import render_ropa_pdf

SEVERITY_RANK = Case(
    When(severity=Finding.Severity.CRITICAL, then=Value(0)),
    When(severity=Finding.Severity.HIGH, then=Value(1)),
    When(severity=Finding.Severity.MEDIUM, then=Value(2)),
    default=Value(3),
    output_field=IntegerField(),
)
NOTE_REQUIRED = {
    Finding.ResolutionStatus.DPA_VERIFIED,
    Finding.ResolutionStatus.ACCEPTED_RISK,
    Finding.ResolutionStatus.FALSE_POSITIVE,
}
NOTE_MAX_LENGTH = 2000
CSV_MAX_ROWS = 50_000


def _ordered(qs):
    return qs.annotate(_rank=SEVERITY_RANK).order_by("_rank", "provider", "file_path", "line_number")


def _htmx_partial(request: HttpRequest) -> bool:
    return bool(request.htmx) and not request.htmx.history_restore_request


@login_required
def dashboard_overview(request: HttpRequest) -> HttpResponse:
    membership = get_active_membership(request)
    if membership is None:
        return render(
            request,
            "compliance/dashboard.html",
            {"active_nav": "audit", "page_title": "Cross-border data flows", "no_org_assigned": True},
        )
    org = membership.organization

    scan_ids = selectors.current_scan_ids(org)
    current = selectors.current_findings(org, scan_ids)
    filters = selectors.FindingFilters.from_params(request.GET)

    paginator = Paginator(_ordered(filters.apply(current)).select_related("scan_run__repository"), selectors.PAGE_SIZE)
    page = paginator.get_page(filters.page)

    context = {
        "active_nav": "audit",
        "page_title": "Cross-border data flows",
        "filters": filters,
        "page": page,
        "total_matches": paginator.count,
        "prev_qs": filters.querystring(page=page.previous_page_number()) if page.has_previous() else "",
        "next_qs": filters.querystring(page=page.next_page_number()) if page.has_next() else "",
        "export_qs": filters.querystring(),
    }

    if _htmx_partial(request):
        response = render(request, "compliance/partials/findings_table.html", context)
        response["Vary"] = "HX-Request"
        return response

    latest_scan = ScanRun.objects.filter(pk__in=scan_ids).order_by("-created_at").first()
    context.update(
        {
            "kpi": selectors.kpis(current),
            "repo_count": Repository.objects.filter(organization=org).count(),
            "subprocessors": selectors.subprocessor_inventory(current),
            "recent_scans": ScanRun.objects.filter(repository__organization=org).select_related("repository")[:12],
            "latest_scan": latest_scan,
        }
    )
    response = render(request, "compliance/dashboard.html", context)
    response["Vary"] = "HX-Request"
    return response


def _get_finding_for_org(request: HttpRequest, finding_id):
    membership = get_active_membership(request)
    org = membership.organization if membership else None
    finding = get_object_or_404(
        Finding.objects.select_related("scan_run__repository", "reviewed_by"),
        pk=finding_id,
        scan_run__repository__organization=org,
    )
    return membership, finding


def _drawer_context(finding: Finding, membership, **extra) -> dict:
    history = TriageEvent.objects.filter(
        repository=finding.scan_run.repository, fingerprint=finding.fingerprint
    ).select_related("actor")[:20]
    return {
        "finding": finding,
        "resolution_choices": Finding.ResolutionStatus.choices,
        "history": history,
        "can_triage": bool(membership and membership.can_triage),
        "note_required": sorted(NOTE_REQUIRED),
        **extra,
    }


@login_required
def finding_detail_drawer(request: HttpRequest, finding_id) -> HttpResponse:
    membership, finding = _get_finding_for_org(request, finding_id)
    return render(request, "compliance/partials/finding_drawer.html", _drawer_context(finding, membership))


@login_required
@require_POST
def update_finding_resolution(request: HttpRequest, finding_id) -> HttpResponse:
    membership, finding = _get_finding_for_org(request, finding_id)
    require_triage(membership)  # owners and DPOs only; auditors/engineers are read-only

    new_status = request.POST.get("resolution_status", "").strip()
    note = request.POST.get("review_note", "").strip()[:NOTE_MAX_LENGTH]

    error = None
    if new_status not in Finding.ResolutionStatus.values:
        error = "Choose a valid resolution status."
    elif new_status in NOTE_REQUIRED and not note:
        error = "A justification or DPA reference is required for this decision."

    if error:
        return render(
            request,
            "compliance/partials/finding_drawer.html",
            _drawer_context(finding, membership, form_error=error, draft_status=new_status, draft_note=note),
            status=422,
        )

    with transaction.atomic():
        locked = Finding.objects.select_for_update().get(pk=finding.pk)
        changed = locked.resolution_status != new_status or locked.review_note != note
        if changed:
            TriageEvent.objects.create(
                repository=locked.scan_run.repository,
                fingerprint=locked.fingerprint,
                rule_id=locked.rule_id,
                file_path=locked.file_path,
                from_status=locked.resolution_status,
                to_status=new_status,
                note=note,
                actor=request.user,
                actor_email=request.user.email,
            )
            locked.resolution_status = new_status
            locked.review_note = note
            locked.reviewed_by = request.user
            locked.reviewed_at = timezone.now()
            locked.save(update_fields=["resolution_status", "review_note", "reviewed_by", "reviewed_at"])
    finding.refresh_from_db()

    response = render(
        request,
        "compliance/partials/finding_drawer.html",
        _drawer_context(finding, membership, saved_banner=changed, unchanged_banner=not changed),
    )
    response["HX-Trigger"] = "findingsUpdated"
    return response


def _csv_safe(value) -> str:
    """Neutralise spreadsheet formula injection (cells starting with = + - @)."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


@login_required
@require_GET
def export_findings_csv(request: HttpRequest) -> HttpResponse:
    membership = get_active_membership(request)
    if membership is None:
        return HttpResponseBadRequest("No active organization selected.")
    org = membership.organization

    filters = selectors.FindingFilters.from_params(request.GET)
    qs = _ordered(filters.apply(selectors.current_findings(org))).select_related(
        "scan_run__repository", "reviewed_by"
    )[:CSV_MAX_ROWS]

    response = HttpResponse(content_type="text/csv; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="sovereigngate-findings-{org.slug}-{date.today():%Y%m%d}.csv"'
    response.write("\ufeff")  # BOM so Excel opens UTF-8 correctly
    writer = csv.writer(response)
    writer.writerow(
        ["severity", "jurisdiction", "sub_processor", "rule_id", "title", "legal_basis", "repository", "branch",
         "commit", "file", "line", "matched_indicator", "triage_status", "reviewed_by", "reviewed_at", "justification",
         "scanned_at"]
    )
    for f in qs:
        writer.writerow(
            [_csv_safe(v) for v in (
                f.severity, f.jurisdiction, f.provider, f.rule_id, f.title, f.primary_legal_article,
                f.scan_run.repository.name, f.scan_run.branch, f.scan_run.commit_sha[:12], f.file_path, f.line_number,
                f.matched_indicator, f.resolution_status, f.reviewed_by.email if f.reviewed_by else "",
                f.reviewed_at.isoformat() if f.reviewed_at else "", f.review_note, f.scan_run.created_at.isoformat(),
            )]
        )
    return response


@login_required
@require_GET
def export_ropa_pdf(request: HttpRequest) -> HttpResponse:
    membership = get_active_membership(request)
    if membership is None:
        return HttpResponseBadRequest("No active organization selected.")

    pdf_bytes, filename = render_ropa_pdf(organization=membership.organization, generated_by=request.user)
    response = HttpResponse(pdf_bytes, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response
