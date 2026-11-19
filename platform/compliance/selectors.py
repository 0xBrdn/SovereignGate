"""Read-side queries shared by the dashboard, CSV export and ROPA PDF.

"Current posture" of a repository = its latest scan on the default branch
(falling back to its latest scan on any branch when none exists). Without this,
a scan of a throw-away feature branch would silently replace the main-branch
picture that the DPO signs off.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urlencode

from django.db.models import Count, OuterRef, Q, QuerySet, Subquery

from accounts.models import Organization
from compliance.models import Finding, Repository, ScanRun

PAGE_SIZE = 25

SEVERITIES = {c for c, _ in Finding.Severity.choices}
JURISDICTIONS = {c for c, _ in Finding.Jurisdiction.choices}
STATUSES = {c for c, _ in Finding.ResolutionStatus.choices}
THIRD_COUNTRY = (Finding.Jurisdiction.US, Finding.Jurisdiction.CN, Finding.Jurisdiction.NON_ADEQUATE)


def current_scan_ids(org: Organization) -> list:
    on_default = (
        ScanRun.objects.filter(repository=OuterRef("pk"), branch=OuterRef("default_branch"))
        .order_by("-created_at")
        .values("id")[:1]
    )
    on_any = ScanRun.objects.filter(repository=OuterRef("pk")).order_by("-created_at").values("id")[:1]
    rows = Repository.objects.filter(organization=org).annotate(
        _default=Subquery(on_default), _any=Subquery(on_any)
    )
    return [r._default or r._any for r in rows if (r._default or r._any)]


def current_findings(org: Organization, scan_ids: Iterable | None = None) -> QuerySet[Finding]:
    ids = list(scan_ids) if scan_ids is not None else current_scan_ids(org)
    return Finding.objects.filter(scan_run_id__in=ids)


def kpis(findings: QuerySet[Finding]) -> dict:
    open_ = Q(resolution_status=Finding.ResolutionStatus.OPEN)
    return findings.aggregate(
        critical=Count("id", filter=open_ & Q(severity=Finding.Severity.CRITICAL)),
        high=Count("id", filter=open_ & Q(severity=Finding.Severity.HIGH)),
        us=Count("id", filter=open_ & Q(jurisdiction=Finding.Jurisdiction.US)),
        non_adequate=Count(
            "id",
            filter=open_ & Q(jurisdiction__in=[Finding.Jurisdiction.CN, Finding.Jurisdiction.NON_ADEQUATE]),
        ),
    )


def subprocessor_inventory(findings: QuerySet[Finding]) -> list[dict]:
    return list(
        findings.order_by()
        .values("provider", "jurisdiction", "category", "primary_legal_article")
        .annotate(
            total_occurrences=Count("id"),
            open_occurrences=Count("id", filter=Q(resolution_status=Finding.ResolutionStatus.OPEN)),
            verified_occurrences=Count("id", filter=Q(resolution_status=Finding.ResolutionStatus.DPA_VERIFIED)),
        )
        .order_by("-open_occurrences", "provider")
    )


@dataclass(frozen=True)
class FindingFilters:
    q: str = ""
    severity: str = ""
    jurisdiction: str = ""
    status: str = "open"
    page: int = 1
    extras: dict = field(default_factory=dict, compare=False)

    @classmethod
    def from_params(cls, params) -> "FindingFilters":
        severity = params.get("severity", "").strip().lower()
        jurisdiction = params.get("jurisdiction", "").strip().upper()
        status = params.get("status", "open").strip().lower()
        try:
            page = max(1, int(params.get("page", 1)))
        except (TypeError, ValueError):
            page = 1
        return cls(
            q=params.get("q", "").strip()[:120],
            severity=severity if severity in SEVERITIES else "",
            jurisdiction=jurisdiction if jurisdiction in JURISDICTIONS or jurisdiction == "THIRD_COUNTRY" else "",
            status=status if status in STATUSES or status == "all" else "open",
            page=page,
        )

    def apply(self, qs: QuerySet[Finding]) -> QuerySet[Finding]:
        if self.severity:
            qs = qs.filter(severity=self.severity)
        if self.jurisdiction == "THIRD_COUNTRY":
            qs = qs.filter(jurisdiction__in=THIRD_COUNTRY)
        elif self.jurisdiction:
            qs = qs.filter(jurisdiction=self.jurisdiction)
        if self.status != "all":
            qs = qs.filter(resolution_status=self.status)
        if self.q:
            qs = qs.filter(
                Q(provider__icontains=self.q)
                | Q(rule_id__icontains=self.q)
                | Q(file_path__icontains=self.q)
                | Q(primary_legal_article__icontains=self.q)
            )
        return qs

    def querystring(self, **overrides) -> str:
        data = {"q": self.q, "severity": self.severity, "jurisdiction": self.jurisdiction, "status": self.status}
        data.update(overrides)
        return urlencode({k: v for k, v in data.items() if v not in ("", None)})
