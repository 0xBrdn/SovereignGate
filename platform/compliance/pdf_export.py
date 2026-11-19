from datetime import datetime
from typing import Any

from django.db.models import Case, Count, IntegerField, Q, Value, When
from django.template.loader import render_to_string
from django.utils import timezone
from weasyprint import HTML, default_url_fetcher

from accounts.models import Organization, User
from compliance import selectors
from compliance.models import Finding, Repository, ScanRun


def _offline_url_fetcher(url, *args, **kwargs):
    """The report is self-contained: refuse every network or file fetch.

    Ingested text is attacker-influenced (any holder of an API token can submit
    it); even though templates auto-escape, never let the PDF renderer reach out.
    """
    if url.startswith("data:"):
        return default_url_fetcher(url, *args, **kwargs)
    raise ValueError(f"External resource blocked in ROPA rendering: {url[:80]}")


TRANSFER_MECHANISM_BY_JURISDICTION = {
    Finding.Jurisdiction.US: "EU-US / Swiss-US Data Privacy Framework (DPF) or Standard Contractual Clauses (SCCs) + TIA",
    Finding.Jurisdiction.CN: "Non-Adequate Jurisdiction — Explicit Transfer Impact Assessment (TIA) & Supplementary Encryption Required",
    Finding.Jurisdiction.NON_ADEQUATE: "Standard Contractual Clauses (Art. 46(2)(c) GDPR / Art. 16(2)(d) nDSG) + TIA",
    Finding.Jurisdiction.EU_EEA: "EEA Free Flow / Swiss Federal Council Adequacy Recognition (Art. 45 GDPR / Art. 16(1) nDSG)",
    Finding.Jurisdiction.CH: "Swiss Domestic Processing / EU Adequacy Decision 2000/518/EC",
}


def build_ropa_report_context(organization: Organization, generated_by: User) -> dict[str, Any]:
    latest_scan_ids = selectors.current_scan_ids(organization)
    latest_scans = {
        sr.repository_id: sr
        for sr in ScanRun.objects.filter(id__in=latest_scan_ids).select_related("repository")
    }

    repo_rows = []
    for repo in Repository.objects.filter(organization=organization).order_by("name"):
        scan = latest_scans.get(repo.id)
        repo_rows.append(
            {
                "name": repo.name,
                "branch": scan.branch if scan else repo.default_branch,
                "commit_sha": scan.commit_sha[:8] if (scan and scan.commit_sha) else "—",
                "data_classification": repo.data_classification,
                "status": scan.status if scan else "unscanned",
                "critical": scan.critical_count if scan else 0,
                "high": scan.high_count if scan else 0,
                "medium": scan.medium_count if scan else 0,
                "scanned_at": scan.created_at if scan else None,
            }
        )

    findings_qs = selectors.current_findings(organization, latest_scan_ids).select_related(
        "scan_run__repository", "reviewed_by"
    )

    subprocessor_groups = (
        findings_qs.values("provider", "jurisdiction", "category", "primary_legal_article")
        .annotate(
            total_refs=Count("id"),
            open_refs=Count("id", filter=Q(resolution_status=Finding.ResolutionStatus.OPEN)),
            verified_refs=Count(
                "id", filter=Q(resolution_status=Finding.ResolutionStatus.DPA_VERIFIED)
            ),
            accepted_refs=Count(
                "id", filter=Q(resolution_status=Finding.ResolutionStatus.ACCEPTED_RISK)
            ),
        )
        .order_by("-open_refs", "provider")
    )

    # One query for the provider -> repositories mapping (was one query per entry).
    repos_by_provider: dict[tuple[str, str], set[str]] = {}
    for provider, jurisdiction, repo_name in findings_qs.order_by().values_list(
        "provider", "jurisdiction", "scan_run__repository__name"
    ).distinct():
        repos_by_provider.setdefault((provider, jurisdiction), set()).add(repo_name)

    ropa_entries = []
    for idx, entry in enumerate(subprocessor_groups, start=1):
        jurisdiction = entry["jurisdiction"]
        repo_names = sorted(repos_by_provider.get((entry["provider"], jurisdiction), set()))
        ropa_entries.append(
            {
                "activity_code": f"ROPA-{idx:03d}",
                "provider": entry["provider"],
                "jurisdiction": jurisdiction,
                "category": entry["category"].replace("_", " ").upper(),
                "legal_article": entry["primary_legal_article"],
                "safeguard_mechanism": TRANSFER_MECHANISM_BY_JURISDICTION.get(
                    jurisdiction,
                    TRANSFER_MECHANISM_BY_JURISDICTION[Finding.Jurisdiction.NON_ADEQUATE],
                ),
                "repositories": ", ".join(repo_names),
                "total_refs": entry["total_refs"],
                "open_refs": entry["open_refs"],
                "verified_refs": entry["verified_refs"],
                "accepted_refs": entry["accepted_refs"],
            }
        )

    unmitigated_findings = list(
        findings_qs.filter(
            resolution_status=Finding.ResolutionStatus.OPEN,
            severity__in=[Finding.Severity.CRITICAL, Finding.Severity.HIGH],
        )
        .annotate(
            _rank=Case(
                When(severity=Finding.Severity.CRITICAL, then=Value(0)),
                default=Value(1),
                output_field=IntegerField(),
            )
        )
        .order_by("_rank", "file_path", "line_number")[:100]
    )

    generated_at: datetime = timezone.now()
    document_ref = f"SG-ROPA-{organization.slug.upper()}-{generated_at.strftime('%Y%m%d-%H%M')}"

    return {
        "organization": organization,
        "generated_by": generated_by,
        "generated_at": generated_at,
        "document_ref": document_ref,
        "repo_rows": repo_rows,
        "ropa_entries": ropa_entries,
        "unmitigated_findings": unmitigated_findings,
        "summary": {
            "total_repositories": len(repo_rows),
            "total_subprocessors": len(ropa_entries),
            "critical_open": findings_qs.filter(
                resolution_status=Finding.ResolutionStatus.OPEN,
                severity=Finding.Severity.CRITICAL,
            ).count(),
            "high_open": findings_qs.filter(
                resolution_status=Finding.ResolutionStatus.OPEN,
                severity=Finding.Severity.HIGH,
            ).count(),
            "dpa_verified_total": findings_qs.filter(
                resolution_status=Finding.ResolutionStatus.DPA_VERIFIED
            ).count(),
        },
    }


def render_ropa_pdf(organization: Organization, generated_by: User) -> tuple[bytes, str]:
    context = build_ropa_report_context(organization=organization, generated_by=generated_by)
    html_string = render_to_string("compliance/pdf/ropa_audit_report.html", context)
    pdf_bytes = HTML(string=html_string, url_fetcher=_offline_url_fetcher).write_pdf()
    filename = f"{context['document_ref'].lower()}.pdf"
    return pdf_bytes, filename