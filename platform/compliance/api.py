import json

from django.http import HttpRequest, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from accounts.models import ApiToken
from compliance.services import ingest_scan_report


def _extract_bearer_token(request: HttpRequest) -> str | None:
    auth_header = request.headers.get("Authorization", "").strip()
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:].strip()
    return None


@csrf_exempt
@require_POST
def ingest_scan_endpoint(request: HttpRequest) -> JsonResponse:
    raw_token = _extract_bearer_token(request)
    if not raw_token:
        return JsonResponse(
            {"error": "Missing Authorization: Bearer <sg_live_...> header."},
            status=401,
        )

    api_token = ApiToken.authenticate(raw_token)
    if api_token is None:
        return JsonResponse(
            {"error": "Invalid or revoked API token."},
            status=403,
        )

    try:
        body = json.loads(request.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return JsonResponse({"error": "Malformed JSON payload."}, status=400)

    if not isinstance(body, dict):
        return JsonResponse({"error": "JSON root must be an object."}, status=400)

    # Support either wrapped envelope {"repository": "...", "report": {...}}
    # or direct CLI stdout piped straight into the endpoint with headers.
    report_payload = body.get("report") if isinstance(body.get("report"), dict) else body

    repository_name = (
        body.get("repository")
        or request.headers.get("X-SovereignGate-Repository")
        or report_payload.get("target_path", "default-repository").rstrip("/").split("/")[-1]
        or "default-repository"
    )
    branch = (
        body.get("branch")
        or request.headers.get("X-SovereignGate-Branch")
        or "main"
    )
    commit_sha = (
        body.get("commit_sha")
        or request.headers.get("X-SovereignGate-Commit")
        or ""
    )
    vcs_url = body.get("vcs_url") or request.headers.get("X-SovereignGate-VCS-URL") or ""

    scan_run = ingest_scan_report(
        organization=api_token.organization,
        repository_name=str(repository_name),
        branch=str(branch),
        commit_sha=str(commit_sha),
        vcs_url=str(vcs_url),
        payload=report_payload,
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