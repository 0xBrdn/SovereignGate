from django.contrib.auth.decorators import login_required
from django.db.models import Count, OuterRef, Q, Subquery
from django.http import HttpRequest, HttpResponse, HttpResponseBadRequest
from django.shortcuts import get_object_or_404, render
from django.views.decorators.http import require_GET, require_POST

from accounts.models import Organization
from compliance.models import Finding, Repository, ScanRun
from compliance.pdf_export import render_ropa_pdf


def _get_active_org(request: HttpRequest) -> Organization | None:
    orgs = Organization.objects.filter(memberships__user=request.user).distinct().order_by("name")
    slug = request.session.get("active_org_slug")
    if slug:
        selected = orgs.filter(slug=slug).first()
        if selected:
            return selected
    return orgs.first()


def _latest_scan_ids_for_org(org: Organization) -> list:
    latest_scan_subquery = (
        ScanRun.objects.filter(repository=OuterRef("pk"))
        .order_by("-created_at")
        .values("id")[:1]
    )
    return list(
        Repository.objects.filter(organization=org)
        .annotate(latest_scan_id=Subquery(latest_scan_subquery))
        .exclude(latest_scan_id__isnull=True)
        .values_list("latest_scan_id", flat=True)
    )


def _filtered_findings_queryset(request: HttpRequest, org: Organization):
    latest_ids = _latest_scan_ids_for_org(org)
    qs = Finding.objects.filter(scan_run_id__in=latest_ids).select_related(
        "scan_run", "scan_run__repository", "reviewed_by"
    )

    severity = request.GET.get("severity", "").strip().lower()
    if severity in {"critical", "high", "medium", "low"}:
        qs = qs.filter(severity=severity)

    jurisdiction = request.GET.get("jurisdiction", "").strip().upper()
    if jurisdiction == "THIRD_COUNTRY":
        qs = qs.filter(
            jurisdiction__in=[
                Finding.Jurisdiction.US,
                Finding.Jurisdiction.CN,
                Finding.Jurisdiction.NON_ADEQUATE,
            ]
        )
    elif jurisdiction in {"US", "CN", "NON_ADEQUATE", "EU_EEA", "CH"}:
        qs = qs.filter(jurisdiction=jurisdiction)

    status = request.GET.get("status", "open").strip().lower()
    if status != "all" and status in {
        Finding.ResolutionStatus.OPEN,
        Finding.ResolutionStatus.DPA_VERIFIED,
        Finding.ResolutionStatus.FALSE_POSITIVE,
        Finding.ResolutionStatus.ACCEPTED_RISK,
    }:
        qs = qs.filter(resolution_status=status)

    query = request.GET.get("q", "").strip()
    if query:
        qs = qs.filter(
            Q(provider__icontains=query)
            | Q(rule_id__icontains=query)
            | Q(file_path__icontains=query)
            | Q(primary_legal_article__icontains=query)
        )

    return qs


def _build_subprocessor_inventory(org: Organization) -> list[dict]:
    latest_ids = _latest_scan_ids_for_org(org)
    rows = (
        Finding.objects.filter(scan_run_id__in=latest_ids)
        .values("provider", "jurisdiction", "category", "primary_legal_article")
        .annotate(
            total_occurrences=Count("id"),
            open_occurrences=Count(
                "id", filter=Q(resolution_status=Finding.ResolutionStatus.OPEN)
            ),
            verified_occurrences=Count(
                "id", filter=Q(resolution_status=Finding.ResolutionStatus.DPA_VERIFIED)
            ),
        )
        .order_by("-open_occurrences", "provider")
    )
    return list(rows)


@login_required
def dashboard_overview(request: HttpRequest) -> HttpResponse:
    active_org = _get_active_org(request)
    if active_org is None:
        return render(
            request,
            "compliance/dashboard.html",
            {
                "active_nav": "audit",
                "page_title": "Cross-Border Data Flow Audit",
                "no_org_assigned": True,
            },
        )

    latest_ids = _latest_scan_ids_for_org(active_org)
    all_latest_findings = Finding.objects.filter(scan_run_id__in=latest_ids)
    open_latest_findings = all_latest_findings.filter(
        resolution_status=Finding.ResolutionStatus.OPEN
    )

    filtered_findings = _filtered_findings_queryset(request, active_org)
    subprocessors = _build_subprocessor_inventory(active_org)
    recent_scans = ScanRun.objects.filter(repository__organization=active_org).select_related(
        "repository"
    )[:12]

    context = {
        "active_nav": "audit",
        "page_title": "Cross-Border Data Flow Audit",
        "repo_count": Repository.objects.filter(organization=active_org).count(),
        "critical_total": open_latest_findings.filter(severity=Finding.Severity.CRITICAL).count(),
        "high_total": open_latest_findings.filter(severity=Finding.Severity.HIGH).count(),
        "us_transfers_total": open_latest_findings.filter(
            jurisdiction=Finding.Jurisdiction.US
        ).count(),
        "non_adequate_total": open_latest_findings.filter(
            jurisdiction__in=[Finding.Jurisdiction.CN, Finding.Jurisdiction.NON_ADEQUATE]
        ).count(),
        "findings": filtered_findings[:150],
        "subprocessors": subprocessors,
        "recent_scans": recent_scans,
        "selected_severity": request.GET.get("severity", ""),
        "selected_jurisdiction": request.GET.get("jurisdiction", ""),
        "selected_status": request.GET.get("status", "open"),
        "search_query": request.GET.get("q", ""),
    }

    if request.htmx:
        return render(request, "compliance/partials/findings_table.html", context)

    return render(request, "compliance/dashboard.html", context)


@login_required
def finding_detail_drawer(request: HttpRequest, finding_id) -> HttpResponse:
    active_org = _get_active_org(request)
    finding = get_object_or_404(
        Finding.objects.select_related("scan_run__repository", "reviewed_by"),
        pk=finding_id,
        scan_run__repository__organization=active_org,
    )
    return render(
        request,
        "compliance/partials/finding_drawer.html",
        {
            "finding": finding,
            "resolution_choices": Finding.ResolutionStatus.choices,
        },
    )


@login_required
@require_POST
def update_finding_resolution(request: HttpRequest, finding_id) -> HttpResponse:
    active_org = _get_active_org(request)
    finding = get_object_or_404(
        Finding.objects.select_related("scan_run__repository", "reviewed_by"),
        pk=finding_id,
        scan_run__repository__organization=active_org,
    )

    new_status = request.POST.get("resolution_status", "").strip()
    valid_statuses = {choice[0] for choice in Finding.ResolutionStatus.choices}
    if new_status not in valid_statuses:
        return HttpResponseBadRequest("Invalid resolution status.")

    finding.resolution_status = new_status
    finding.review_note = request.POST.get("review_note", "").strip()
    finding.reviewed_by = request.user
    finding.save(update_fields=["resolution_status", "review_note", "reviewed_by"])

    response = render(
        request,
        "compliance/partials/finding_drawer.html",
        {
            "finding": finding,
            "resolution_choices": Finding.ResolutionStatus.choices,
            "saved_banner": True,
        },
    )
    response["HX-Trigger"] = "findingsUpdated"
    return response


@login_required
@require_GET
def export_ropa_pdf(request: HttpRequest) -> HttpResponse:
    active_org = _get_active_org(request)
    if active_org is None:
        return HttpResponseBadRequest("No active organization selected.")

    pdf_bytes, filename = render_ropa_pdf(
        organization=active_org,
        generated_by=request.user,
        base_url=request.build_absolute_uri("/"),
    )
    response = HttpResponse(pdf_bytes, content_type="application/pdf")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response