from typing import Any

from django.db import transaction
from django.utils.text import slugify

from accounts.models import Organization
from compliance.models import Finding, Repository, ScanRun


SEVERITY_MAP = {
    "critical": Finding.Severity.CRITICAL,
    "high": Finding.Severity.HIGH,
    "medium": Finding.Severity.MEDIUM,
    "low": Finding.Severity.LOW,
    "error": Finding.Severity.HIGH,
    "warning": Finding.Severity.MEDIUM,
    "note": Finding.Severity.LOW,
}

JURISDICTION_MAP = {
    "US": Finding.Jurisdiction.US,
    "CN": Finding.Jurisdiction.CN,
    "NON_ADEQUATE": Finding.Jurisdiction.NON_ADEQUATE,
    "EU_EEA": Finding.Jurisdiction.EU_EEA,
    "EU/EEA": Finding.Jurisdiction.EU_EEA,
    "CH": Finding.Jurisdiction.CH,
}


def _normalize_jurisdiction(raw: str | None) -> str:
    if not raw:
        return Finding.Jurisdiction.NON_ADEQUATE
    return JURISDICTION_MAP.get(raw.strip().upper(), Finding.Jurisdiction.NON_ADEQUATE)


def _format_primary_article(legal_refs: list[dict[str, Any]]) -> str:
    if not legal_refs:
        return "Art. 44 GDPR / Art. 16 nDSG"
    parts = []
    for ref in legal_refs[:2]:
        article = str(ref.get("article", "")).strip()
        framework = str(ref.get("framework", "")).strip()
        if article and framework:
            parts.append(f"{article} {framework}")
        elif article:
            parts.append(article)
    return " · ".join(parts) if parts else "Art. 44 GDPR / Art. 16 nDSG"


def parse_native_json_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    summary = payload.get("summary") or {}
    raw_findings = payload.get("findings") or []

    parsed_findings = []
    for item in raw_findings:
        legal_refs = item.get("legal_references") or []
        parsed_findings.append(
            {
                "rule_id": str(item.get("rule_id", "SG-CUSTOM"))[:32],
                "title": str(item.get("title", "Cross-Border Data Flow"))[:255],
                "provider": str(item.get("provider", "Unknown Sub-Processor"))[:160],
                "category": str(item.get("category", "cloud_infrastructure"))[:64],
                "severity": SEVERITY_MAP.get(
                    str(item.get("severity", "medium")).lower(), Finding.Severity.MEDIUM
                ),
                "jurisdiction": _normalize_jurisdiction(item.get("jurisdiction")),
                "target_type": str(item.get("target", "source_code"))[:32],
                "file_path": str(item.get("file_path", "unknown"))[:512],
                "line_number": max(1, int(item.get("line", 1))),
                "snippet": str(item.get("snippet", "")),
                "matched_indicator": str(item.get("matched_indicator", ""))[:255],
                "primary_legal_article": _format_primary_article(legal_refs)[:120],
                "legal_references": legal_refs,
                "description": str(item.get("description", "")),
                "remediation": str(item.get("remediation", "")),
            }
        )

    meta = {
        "engine_version": str(payload.get("engine_version", "0.1.0"))[:32],
        "files_scanned": int(summary.get("files_scanned", 0)),
        "duration_ms": int(summary.get("duration_ms", 0)),
    }
    return meta, parsed_findings


def parse_sarif_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    runs = payload.get("runs") or []
    if not runs:
        return {"engine_version": "0.1.0", "files_scanned": 0, "duration_ms": 0}, []

    run = runs[0]
    driver = (run.get("tool") or {}).get("driver") or {}
    rule_lookup: dict[str, dict[str, Any]] = {}
    for descriptor in driver.get("rules") or []:
        rule_id = descriptor.get("id")
        if rule_id:
            rule_lookup[rule_id] = descriptor

    parsed_findings = []
    for result in run.get("results") or []:
        rule_id = str(result.get("ruleId", "SG-SARIF"))[:32]
        descriptor = rule_lookup.get(rule_id, {})
        res_props = result.get("properties") or {}
        desc_props = descriptor.get("properties") or {}

        locations = result.get("locations") or []
        phys = (locations[0].get("physicalLocation") if locations else {}) or {}
        uri = (phys.get("artifactLocation") or {}).get("uri", "unknown")
        region = phys.get("region") or {}
        line_num = max(1, int(region.get("startLine", 1)))
        snippet = (region.get("snippet") or {}).get("text", "")

        raw_sev = res_props.get("severity") or desc_props.get("severity") or result.get("level", "warning")
        legal_refs = res_props.get("legalReferences") or desc_props.get("legalReferences") or []

        parsed_findings.append(
            {
                "rule_id": rule_id,
                "title": str(descriptor.get("name") or rule_id)[:255],
                "provider": str(res_props.get("provider") or desc_props.get("provider") or "Unknown")[:160],
                "category": str(desc_props.get("category") or "third_party")[:64],
                "severity": SEVERITY_MAP.get(str(raw_sev).lower(), Finding.Severity.MEDIUM),
                "jurisdiction": _normalize_jurisdiction(
                    res_props.get("jurisdiction") or desc_props.get("jurisdiction")
                ),
                "target_type": "sarif",
                "file_path": str(uri)[:512],
                "line_number": line_num,
                "snippet": str(snippet),
                "matched_indicator": str(res_props.get("matchedIndicator", ""))[:255],
                "primary_legal_article": _format_primary_article(legal_refs)[:120],
                "legal_references": legal_refs,
                "description": str((descriptor.get("fullDescription") or {}).get("text", "")),
                "remediation": str((descriptor.get("help") or {}).get("text", "")),
            }
        )

    meta = {
        "engine_version": str(driver.get("version", "0.1.0"))[:32],
        "files_scanned": 0,
        "duration_ms": 0,
    }
    return meta, parsed_findings


@transaction.atomic
def ingest_scan_report(
    *,
    organization: Organization,
    repository_name: str,
    branch: str,
    commit_sha: str,
    vcs_url: str,
    payload: dict[str, Any],
) -> ScanRun:
    repo_slug = slugify(repository_name)[:200] or "default-repo"
    repository, created = Repository.objects.get_or_create(
        organization=organization,
        slug=repo_slug,
        defaults={
            "name": repository_name[:200],
            "vcs_url": vcs_url[:200],
            "default_branch": branch[:100] or "main",
        },
    )
    if not created and vcs_url and repository.vcs_url != vcs_url:
        repository.vcs_url = vcs_url[:200]
        repository.save(update_fields=["vcs_url", "updated_at"])

    is_sarif = payload.get("version") == "2.1.0" and "runs" in payload
    meta, parsed_findings = (
        parse_sarif_payload(payload) if is_sarif else parse_native_json_payload(payload)
    )

    crit = sum(1 for f in parsed_findings if f["severity"] == Finding.Severity.CRITICAL)
    high = sum(1 for f in parsed_findings if f["severity"] == Finding.Severity.HIGH)
    med = sum(1 for f in parsed_findings if f["severity"] == Finding.Severity.MEDIUM)
    low = sum(1 for f in parsed_findings if f["severity"] == Finding.Severity.LOW)

    if crit > 0 or high > 0:
        status = ScanRun.Status.FAIL
    elif med > 0 or low > 0:
        status = ScanRun.Status.WARN
    else:
        status = ScanRun.Status.PASS

    scan_run = ScanRun.objects.create(
        repository=repository,
        commit_sha=commit_sha[:64],
        branch=branch[:120] or "main",
        engine_version=meta["engine_version"],
        status=status,
        files_scanned=meta["files_scanned"],
        duration_ms=meta["duration_ms"],
        critical_count=crit,
        high_count=high,
        medium_count=med,
        low_count=low,
        raw_report=payload,
    )

    # Carry forward prior DPO triage decisions for identical (rule_id, file_path, matched_indicator)
    prior_resolutions: dict[tuple[str, str, str], tuple[str, Any, str]] = {}
    previous_scan = (
        ScanRun.objects.filter(repository=repository)
        .exclude(pk=scan_run.pk)
        .order_by("-created_at")
        .first()
    )
    if previous_scan:
        resolved_qs = previous_scan.findings.exclude(
            resolution_status=Finding.ResolutionStatus.OPEN
        ).values_list(
            "rule_id",
            "file_path",
            "matched_indicator",
            "resolution_status",
            "reviewed_by_id",
            "review_note",
        )
        for r_id, f_path, indicator, res_status, rev_by, note in resolved_qs:
            prior_resolutions[(r_id, f_path, indicator)] = (res_status, rev_by, note)

    finding_objects = []
    for item in parsed_findings:
        key = (item["rule_id"], item["file_path"], item["matched_indicator"])
        res_status, rev_by, note = prior_resolutions.get(
            key, (Finding.ResolutionStatus.OPEN, None, "")
        )
        finding_objects.append(
            Finding(
                scan_run=scan_run,
                resolution_status=res_status,
                reviewed_by_id=rev_by,
                review_note=note,
                **item,
            )
        )

    if finding_objects:
        Finding.objects.bulk_create(finding_objects)

    return scan_run