"""Scan-report ingestion: validation, normalisation, redaction and persistence."""
from __future__ import annotations

import re
from typing import Any

from django.conf import settings
from django.db import transaction
from django.utils.text import slugify

from accounts.models import Organization
from compliance.models import Finding, Repository, ScanRun, TriageEvent
from compliance.redaction import redact_secrets

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

DEFAULT_ARTICLE = "Art. 44 GDPR / Art. 16 nDSG"
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_MAX_INT = 2_147_483_647


class PayloadError(ValueError):
    """The submitted report is structurally invalid (HTTP 422)."""


class PayloadTooLarge(PayloadError):
    """The submitted report exceeds configured limits (HTTP 413)."""


# ---------------------------------------------------------------- coercion
def _text(value: Any, limit: int, default: str = "") -> str:
    if value is None:
        return default
    return _CONTROL_CHARS.sub("", str(value))[:limit]


def _int(value: Any, default: int = 0, minimum: int = 0) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(_MAX_INT, number))


def _normalize_jurisdiction(raw: Any) -> str:
    if not raw:
        return Finding.Jurisdiction.NON_ADEQUATE
    return JURISDICTION_MAP.get(str(raw).strip().upper(), Finding.Jurisdiction.NON_ADEQUATE)


def _clean_legal_refs(raw: Any) -> list[dict[str, str]]:
    if not isinstance(raw, list):
        return []
    refs = []
    for ref in raw[:8]:
        if not isinstance(ref, dict):
            continue
        refs.append(
            {
                "framework": _text(ref.get("framework"), 40),
                "article": _text(ref.get("article"), 80),
                "summary": _text(ref.get("summary"), 600),
            }
        )
    return refs


def _format_primary_article(legal_refs: list[dict[str, str]]) -> str:
    parts = []
    for ref in legal_refs[:2]:
        article, framework = ref["article"].strip(), ref["framework"].strip()
        if article and framework:
            parts.append(f"{article} {framework}")
        elif article:
            parts.append(article)
    return " · ".join(parts) if parts else DEFAULT_ARTICLE


def _check_count(items: Any, label: str) -> list:
    if items is None:
        return []
    if not isinstance(items, list):
        raise PayloadError(f"'{label}' must be an array.")
    limit = settings.SG_MAX_FINDINGS_PER_SCAN
    if len(items) > limit:
        raise PayloadTooLarge(f"Report contains {len(items)} entries; the limit is {limit}.")
    return items


# ----------------------------------------------------------------- parsers
def parse_native_json_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    raw_findings = _check_count(payload.get("findings"), "findings")

    parsed = []
    for index, item in enumerate(raw_findings):
        if not isinstance(item, dict):
            raise PayloadError(f"findings[{index}] must be an object.")
        legal_refs = _clean_legal_refs(item.get("legal_references"))
        parsed.append(
            {
                "rule_id": _text(item.get("rule_id"), 32, "SG-CUSTOM"),
                "title": _text(item.get("title"), 255, "Cross-Border Data Flow"),
                "provider": _text(item.get("provider"), 160, "Unknown Sub-Processor"),
                "category": _text(item.get("category"), 64, "cloud_infrastructure"),
                "severity": SEVERITY_MAP.get(str(item.get("severity", "medium")).lower(), Finding.Severity.MEDIUM),
                "jurisdiction": _normalize_jurisdiction(item.get("jurisdiction")),
                "target_type": _text(item.get("target"), 32, "source_code"),
                "file_path": _text(item.get("file_path"), 512, "unknown"),
                "line_number": _int(item.get("line"), 1, minimum=1),
                "snippet": redact_secrets(_text(item.get("snippet"), 2000)),
                "matched_indicator": _text(item.get("matched_indicator"), 255),
                "primary_legal_article": _format_primary_article(legal_refs)[:120],
                "legal_references": legal_refs,
                "description": _text(item.get("description"), 4000),
                "remediation": _text(item.get("remediation"), 4000),
            }
        )

    meta = {
        "engine_version": _text(payload.get("engine_version"), 32, "0.1.0"),
        "files_scanned": _int(summary.get("files_scanned")),
        "duration_ms": _int(summary.get("duration_ms")),
        "target_path": _text(payload.get("target_path"), 255),
    }
    return meta, parsed


def parse_sarif_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    runs = payload.get("runs")
    if not isinstance(runs, list) or not runs or not isinstance(runs[0], dict):
        return {"engine_version": "0.1.0", "files_scanned": 0, "duration_ms": 0, "target_path": ""}, []

    run = runs[0]
    driver = (run.get("tool") or {}).get("driver") or {}
    rule_lookup: dict[str, dict[str, Any]] = {}
    for descriptor in driver.get("rules") or []:
        if isinstance(descriptor, dict) and descriptor.get("id"):
            rule_lookup[str(descriptor["id"])] = descriptor

    results = _check_count(run.get("results"), "runs[0].results")
    parsed = []
    for index, result in enumerate(results):
        if not isinstance(result, dict):
            raise PayloadError(f"runs[0].results[{index}] must be an object.")
        rule_id = _text(result.get("ruleId"), 32, "SG-SARIF")
        descriptor = rule_lookup.get(rule_id, {})
        res_props = result.get("properties") if isinstance(result.get("properties"), dict) else {}
        desc_props = descriptor.get("properties") if isinstance(descriptor.get("properties"), dict) else {}

        locations = result.get("locations") if isinstance(result.get("locations"), list) else []
        phys = (locations[0].get("physicalLocation") if locations and isinstance(locations[0], dict) else {}) or {}
        uri = (phys.get("artifactLocation") or {}).get("uri", "unknown")
        region = phys.get("region") or {}
        snippet = (region.get("snippet") or {}).get("text", "")

        raw_sev = res_props.get("severity") or desc_props.get("severity") or result.get("level", "warning")
        legal_refs = _clean_legal_refs(res_props.get("legalReferences") or desc_props.get("legalReferences"))

        parsed.append(
            {
                "rule_id": rule_id,
                "title": _text(descriptor.get("name") or rule_id, 255),
                "provider": _text(res_props.get("provider") or desc_props.get("provider"), 160, "Unknown"),
                "category": _text(desc_props.get("category"), 64, "third_party"),
                "severity": SEVERITY_MAP.get(str(raw_sev).lower(), Finding.Severity.MEDIUM),
                "jurisdiction": _normalize_jurisdiction(res_props.get("jurisdiction") or desc_props.get("jurisdiction")),
                "target_type": "sarif",
                "file_path": _text(uri, 512, "unknown"),
                "line_number": _int(region.get("startLine"), 1, minimum=1),
                "snippet": redact_secrets(_text(snippet, 2000)),
                "matched_indicator": _text(res_props.get("matchedIndicator"), 255),
                "primary_legal_article": _format_primary_article(legal_refs)[:120],
                "legal_references": legal_refs,
                "description": _text((descriptor.get("fullDescription") or {}).get("text"), 4000),
                "remediation": _text((descriptor.get("help") or {}).get("text"), 4000),
            }
        )

    meta = {
        "engine_version": _text(driver.get("version"), 32, "0.1.0"),
        "files_scanned": 0,
        "duration_ms": 0,
        "target_path": "",
    }
    return meta, parsed


# --------------------------------------------------------------- triage carry-over
def _prior_decisions(repository: Repository, exclude_scan_id) -> dict[str, tuple]:
    """fingerprint -> (status, reviewer_id, note, reviewed_at).

    Legacy decisions (made before the audit trail existed) come from the previous
    scan; the append-only TriageEvent log is authoritative and overrides them.
    """
    decisions: dict[str, tuple] = {}

    previous = (
        ScanRun.objects.filter(repository=repository).exclude(pk=exclude_scan_id).order_by("-created_at").first()
    )
    if previous:
        for rule_id, path, indicator, status, reviewer, note, at in previous.findings.exclude(
            resolution_status=Finding.ResolutionStatus.OPEN
        ).values_list(
            "rule_id", "file_path", "matched_indicator", "resolution_status", "reviewed_by_id", "review_note", "reviewed_at"
        ):
            decisions[Finding.compute_fingerprint(rule_id, path, indicator)] = (status, reviewer, note, at)

    for event in TriageEvent.objects.filter(repository=repository).order_by("created_at").iterator():
        decisions[event.fingerprint] = (event.to_status, event.actor_id, event.note, event.created_at)
    return decisions


# ------------------------------------------------------------------ ingestion
@transaction.atomic
def ingest_scan_report(
    *,
    organization: Organization,
    repository_name: str,
    branch: str,
    commit_sha: str,
    vcs_url: str,
    payload: dict[str, Any],
    default_branch: str = "",
) -> ScanRun:
    repository_name = _text(repository_name, 200, "default-repository")
    branch = _text(branch, 120, "main") or "main"
    commit_sha = _text(commit_sha, 64)
    vcs_url = _text(vcs_url, 200)
    default_branch = _text(default_branch, 100)

    is_sarif = payload.get("version") == "2.1.0" and "runs" in payload
    meta, parsed_findings = parse_sarif_payload(payload) if is_sarif else parse_native_json_payload(payload)

    repo_slug = slugify(repository_name)[:200] or "default-repo"
    repository, created = Repository.objects.get_or_create(
        organization=organization,
        slug=repo_slug,
        defaults={
            "name": repository_name,
            "vcs_url": vcs_url,
            "default_branch": default_branch or "main",
        },
    )
    changed = []
    if not created and vcs_url and repository.vcs_url != vcs_url:
        repository.vcs_url = vcs_url
        changed.append("vcs_url")
    if not created and default_branch and repository.default_branch != default_branch:
        repository.default_branch = default_branch
        changed.append("default_branch")
    if changed:
        repository.save(update_fields=[*changed, "updated_at"])

    counts = {sev: 0 for sev in Finding.Severity.values}
    for finding in parsed_findings:
        counts[finding["severity"]] += 1

    if counts["critical"] or counts["high"]:
        status = ScanRun.Status.FAIL
    elif counts["medium"] or counts["low"]:
        status = ScanRun.Status.WARN
    else:
        status = ScanRun.Status.PASS

    # Findings and snippets live in Finding rows (redacted); the raw report keeps
    # only scan metadata, so no unredacted payload is ever persisted.
    raw_report = {
        "format": "sarif" if is_sarif else "native",
        "engine_version": meta["engine_version"],
        "target_path": meta["target_path"],
        "summary": {
            "files_scanned": meta["files_scanned"],
            "duration_ms": meta["duration_ms"],
            "total_findings": len(parsed_findings),
            "unique_subprocessors": sorted({f["provider"] for f in parsed_findings})[:200],
        },
    }

    scan_run = ScanRun.objects.create(
        repository=repository,
        commit_sha=commit_sha,
        branch=branch,
        engine_version=meta["engine_version"],
        status=status,
        files_scanned=meta["files_scanned"],
        duration_ms=meta["duration_ms"],
        critical_count=counts["critical"],
        high_count=counts["high"],
        medium_count=counts["medium"],
        low_count=counts["low"],
        raw_report=raw_report,
    )

    decisions = _prior_decisions(repository, exclude_scan_id=scan_run.pk)
    objects = []
    for item in parsed_findings:
        fingerprint = Finding.compute_fingerprint(item["rule_id"], item["file_path"], item["matched_indicator"])
        res_status, reviewer_id, note, reviewed_at = decisions.get(
            fingerprint, (Finding.ResolutionStatus.OPEN, None, "", None)
        )
        objects.append(
            Finding(
                scan_run=scan_run,
                fingerprint=fingerprint,
                resolution_status=res_status,
                reviewed_by_id=reviewer_id,
                review_note=note,
                reviewed_at=reviewed_at,
                **item,
            )
        )
    if objects:
        Finding.objects.bulk_create(objects, batch_size=500)
    return scan_run
