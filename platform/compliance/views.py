from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render

from accounts.models import Organization
from compliance.models import Finding, Repository, ScanRun


def _get_active_org(request: HttpRequest) -> Organization | None:
    orgs = Organization.objects.filter(memberships__user=request.user).distinct().order_by("name")
    slug = request.session.get("active_org_slug")
    if slug:
        selected = orgs.filter(slug=slug).first()
        if selected:
            return selected
    return orgs.first()


@login_required
def dashboard_overview(request: HttpRequest) -> HttpResponse:
    active_org = _get_active_org(request)
    if active_org is None:
        return render(
            request,
            "base.html",
            {
                "active_nav": "audit",
                "page_title": "Compliance Audit",
                "no_org_assigned": True,
            },
        )

    repos = Repository.objects.filter(organization=active_org)
    recent_scans = ScanRun.objects.filter(repository__organization=active_org).select_related(
        "repository"
    )[:10]
    open_findings = Finding.objects.filter(
        scan_run__repository__organization=active_org,
        resolution_status=Finding.ResolutionStatus.OPEN,
    ).select_related("scan_run__repository")

    context = {
        "active_nav": "audit",
        "page_title": "Cross-Border Audit",
        "repo_count": repos.count(),
        "recent_scans": recent_scans,
        "findings": open_findings[:50],
        "critical_total": open_findings.filter(severity=Finding.Severity.CRITICAL).count(),
        "high_total": open_findings.filter(severity=Finding.Severity.HIGH).count(),
        "us_transfers_total": open_findings.filter(jurisdiction=Finding.Jurisdiction.US).count(),
        "non_adequate_total": open_findings.filter(
            jurisdiction__in=[Finding.Jurisdiction.CN, Finding.Jurisdiction.NON_ADEQUATE]
        ).count(),
    }
    return render(request, "base.html", context)