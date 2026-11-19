import json
import logging

from django.conf import settings
from django.core.exceptions import RequestDataTooBig
from django.http import HttpRequest, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from accounts.models import ApiToken
from accounts.throttle import hit
from compliance.services import PayloadError, PayloadTooLarge, ingest_scan_report

logger = logging.getLogger("sovereigngate.ingest")


def _error(message: str, status: int, **headers) -> JsonResponse:
    response = JsonResponse({"error": message}, status=status)
    for name, value in headers.items():
        response[name.replace("_", "-")] = value
    return response


def _extract_bearer_token(request: HttpRequest) -> str | None:
    auth_header = request.headers.get("Authorization", "").strip()
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    return None


@csrf_exempt
@require_POST
def ingest_scan_endpoint(request: HttpRequest) -> JsonResponse:
    """Token-authenticated ingestion of a CLI JSON report or a SARIF 2.1.0 log."""
    raw_token = _extract_bearer_token(request)
    if not raw_token:
        return _error(
            "Missing Authorization: Bearer <sg_live_...> header.", 401, WWW_Authenticate='Bearer realm="sovereigngate"'
        )

    api_token = ApiToken.authenticate(raw_token)
    if api_token is None:
        return _error("Invalid or revoked API token.", 403)

    if not hit("ingest", str(api_token.pk), limit=settings.SG_INGEST_RATE_LIMIT, window=60):
        return _error("Rate limit exceeded for this token. Retry in a minute.", 429, Retry_After="60")

    try:
        body = json.loads(request.body.decode("utf-8"))
    except RequestDataTooBig:
        return _error("Payload exceeds the configured upload limit.", 413)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return _error("Malformed JSON payload.", 400)

    if not isinstance(body, dict):
        return _error("JSON root must be an object.", 400)

    # Wrapped envelope {"repository": ..., "report": {...}} or the bare CLI output.
    report_payload = body.get("report") if isinstance(body.get("report"), dict) else body

    target_path = str(report_payload.get("target_path") or "")
    repository_name = (
        body.get("repository")
        or request.headers.get("X-SovereignGate-Repository")
        or target_path.rstrip("/").split("/")[-1]
        or "default-repository"
    )
    branch = body.get("branch") or request.headers.get("X-SovereignGate-Branch") or "main"
    commit_sha = body.get("commit_sha") or request.headers.get("X-SovereignGate-Commit") or ""
    vcs_url = body.get("vcs_url") or request.headers.get("X-SovereignGate-VCS-URL") or ""
    default_branch = body.get("default_branch") or request.headers.get("X-SovereignGate-Default-Branch") or ""

    try:
        scan_run = ingest_scan_report(
            organization=api_token.organization,
            repository_name=str(repository_name),
            branch=str(branch),
            commit_sha=str(commit_sha),
            vcs_url=str(vcs_url),
            default_branch=str(default_branch),
            payload=report_payload,
        )
    except PayloadTooLarge as exc:
        return _error(str(exc), 413)
    except PayloadError as exc:
        return _error(str(exc), 422)

    logger.info(
        "scan ingested org=%s repo=%s branch=%s findings=%s token=%s",
        api_token.organization.slug, scan_run.repository.slug, scan_run.branch, scan_run.total_findings, api_token.prefix,
    )
    return JsonResponse(
        {
            "scan_run_id": str(scan_run.id),
            "organization": api_token.organization.slug,
            "repository": scan_run.repository.slug,
            "status": scan_run.status,
            "summary": {
                "total_findings": scan_run.total_findings,
                "critical": scan_run.critical_count,
                "high": scan_run.high_count,
                "medium": scan_run.medium_count,
                "low": scan_run.low_count,
            },
        },
        status=201,
    )
