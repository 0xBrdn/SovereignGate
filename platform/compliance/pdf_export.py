from datetime import datetime
from typing import Any

from django.db.models import Count, OuterRef, Q, Subquery
from django.template.loader import render_to_string
from django.utils import timezone
from weasyprint import HTML

from accounts.models import Organization, User
from compliance.models import Finding, Repository, ScanRun


TRANSFER_MECHANISM_BY_JURISDICTION = {
    Finding.Jurisdiction.US: "EU-US / Swiss-US Data Privacy Framework (DPF) or Standard Contractual Clauses (SCCs) + TIA",
    Finding.Jurisdiction.CN: "Non-Adequate Jurisdiction — Explicit Transfer Impact Assessment (TIA) & Supplementary Encryption Required",
    Finding.Jurisdiction.NON_ADEQUATE: "Standard Contractual Clauses (Art. 46(2)(c) GDPR / Art. 16(2)(d) nDSG) + TIA",
    Finding.Jurisdiction.EU_EEA: "EEA Free Flow / Swiss Federal Council Adequacy Recognition (Art. 45 GDPR / Art. 16(1) nDSG)",
    Finding.Jurisdiction.CH: "Swiss Domestic Processing / EU Adequacy Decision 2000/518/EC",
}


def build_ropa_report_context(organization: Organization, generated_by: User) -> dict[str, Any]:
    latest_scan_subquery = (
        ScanRun.objects.filter(repository=OuterRef("pk"))
        .order_by("-created_at")
        .values("id")[:1]
    )
    repositories = list(
        Repository.objects.filter(organization=organization)
        .annotate(latest_scan_id=Subquery(latest_scan_subquery))
        .order_by("name")
    )

    latest_scan_ids = [r.latest_scan_id for r in repositories if r.latest_scan_id]
    latest_scans_by_id = {
        sr.id: sr
        for sr in ScanRun.objects.filter(id__in=latest_scan_ids).select_related("repository")
    }

    repo_rows = []
    for repo in repositories:
        scan = latest_scans_by_id.get(repo.latest_scan_id)
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

    findings_qs = Finding.objects.filter(scan_run_id__in=latest_scan_ids).select_related(
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

    ropa_entries = []
    for idx, entry in enumerate(subprocessor_groups, start=1):
        jurisdiction = entry["jurisdiction"]
        repo_names = sorted(
            set(
                findings_qs.filter(
                    provider=entry["provider"], jurisdiction=jurisdiction
                ).values_list("scan_run__repository__name", flat=True)
            )
        )
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
        ).order_by("severity", "file_path", "line_number")[:100]
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


def render_ropa_pdf(organization: Organization, generated_by: User, base_url: str) -> tuple[bytes, str]:
    context = build_ropa_report_context(organization=organization, generated_by=generated_by)
    html_string = render_to_string("compliance/pdf/ropa_audit_report.html", context)
    pdf_bytes = HTML(string=html_string, base_url=base_url).write_pdf()
    filename = f"{context['document_ref'].lower()}.pdf"
    return pdf_bytes, filename