#!/usr/bin/env bash
set -euo pipefail

SCAN_PATH="${INPUT_PATH:-.}"
FAIL_ON="${INPUT_FAIL_ON:-high}"
RULES_DIR="${INPUT_RULES_DIR:-}"
SARIF_OUT="${INPUT_SARIF_OUTPUT:-sovereigngate-results.sarif}"
JSON_OUT="${INPUT_JSON_OUTPUT:-sovereigngate-results.json}"
PLATFORM_URL="${INPUT_PLATFORM_URL:-}"
API_TOKEN="${INPUT_API_TOKEN:-}"
COMMENT_PR="${INPUT_COMMENT_PR:-true}"

RULE_ARGS=()
if [[ -n "$RULES_DIR" ]]; then
  RULE_ARGS=(--rules-dir "$RULES_DIR")
fi

# Generate JSON report without failing yet so SARIF, SaaS ingestion, and PR comments always execute
set +e
sovereigngate scan "$SCAN_PATH" \
  --format json \
  --output "$JSON_OUT" \
  --fail-on "$FAIL_ON" \
  "${RULE_ARGS[@]}"
SCAN_EXIT_CODE=$?
set -e

# Generate SARIF v2.1.0 report for GitHub Code Scanning / Security tab
sovereigngate scan "$SCAN_PATH" \
  --format sarif \
  --output "$SARIF_OUT" \
  --fail-on none \
  "${RULE_ARGS[@]}"

# Print concise CLI summary to runner logs
sovereigngate scan "$SCAN_PATH" \
  --format cli \
  --fail-on none \
  "${RULE_ARGS[@]}"

TOTAL_FINDINGS=$(jq -r '.summary.total_findings // 0' "$JSON_OUT")
CRITICAL_COUNT=$(jq -r '.summary.critical // 0' "$JSON_OUT")
HIGH_COUNT=$(jq -r '.summary.high // 0' "$JSON_OUT")
MEDIUM_COUNT=$(jq -r '.summary.medium // 0' "$JSON_OUT")
LOW_COUNT=$(jq -r '.summary.low // 0' "$JSON_OUT")
FILES_SCANNED=$(jq -r '.summary.files_scanned // 0' "$JSON_OUT")

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "sarif_file=$SARIF_OUT"
    echo "json_file=$JSON_OUT"
    echo "total_findings=$TOTAL_FINDINGS"
    echo "critical_count=$CRITICAL_COUNT"
    echo "high_count=$HIGH_COUNT"
  } >> "$GITHUB_OUTPUT"
fi

# Stream telemetry to SovereignGate SaaS platform when configured
if [[ -n "$PLATFORM_URL" && -n "$API_TOKEN" ]]; then
  INGEST_URL="${PLATFORM_URL%/}/api/v1/scans/ingest/"
  REPO_NAME="${GITHUB_REPOSITORY:-$(basename "$(pwd)")}"
  BRANCH_NAME="${GITHUB_HEAD_REF:-${GITHUB_REF_NAME:-main}}"
  COMMIT_SHA="${GITHUB_SHA:-}"
  VCS_URL="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-}"

  ENVELOPE=$(jq -n \
    --arg repo "$REPO_NAME" \
    --arg branch "$BRANCH_NAME" \
    --arg sha "$COMMIT_SHA" \
    --arg vcs "$VCS_URL" \
    --slurpfile report "$JSON_OUT" \
    '{repository: $repo, branch: $branch, commit_sha: $sha, vcs_url: $vcs, report: $report[0]}')

  curl -fsSL -X POST "$INGEST_URL" \
    -H "Authorization: Bearer $API_TOKEN" \
    -H "Content-Type: application/json" \
    -d "$ENVELOPE" > /dev/null
  echo "Ingested scan telemetry into SovereignGate platform ($REPO_NAME @ ${COMMIT_SHA:0:8})."
fi

# Post Pull Request compliance audit table when running in a PR context
if [[ "$COMMENT_PR" == "true" && -n "${GITHUB_TOKEN:-}" && -n "${GITHUB_EVENT_PATH:-}" && -f "${GITHUB_EVENT_PATH}" ]]; then
  PR_NUMBER=$(jq -r '.pull_request.number // empty' "$GITHUB_EVENT_PATH")
  if [[ -n "$PR_NUMBER" && -n "${GITHUB_REPOSITORY:-}" ]]; then
    STATUS_BADGE="PASS"
    if [[ "$SCAN_EXIT_CODE" -ne 0 ]]; then
      STATUS_BADGE="FAIL (Threshold: \`${FAIL_ON^^}\`)"
    fi

    FINDINGS_ROWS=$(jq -r '
      .findings[:15] | map(
        "| `\(.severity | ascii_upcase)` | `\(.rule_id)` | \(.provider) | `\(.jurisdiction)` | `\(.file_path):\(.line)` |"
      ) | join("\n")
    ' "$JSON_OUT")

    if [[ -z "$FINDINGS_ROWS" ]]; then
      BODY=$(cat <<EOF
### SovereignGate Compliance Audit — ${STATUS_BADGE}

No unauthorized cross-border data flows or non-EU/CH sub-processors detected across **${FILES_SCANNED}** scanned files.
EOF
)
    else
      BODY=$(cat <<EOF
### SovereignGate Compliance Audit — ${STATUS_BADGE}

| Severity | Rule | Sub-Processor | Jurisdiction | Location |
| :--- | :--- | :--- | :--- | :--- |
${FINDINGS_ROWS}

**Summary:** ${TOTAL_FINDINGS} findings (**${CRITICAL_COUNT}** Critical, **${HIGH_COUNT}** High, **${MEDIUM_COUNT}** Medium, **${LOW_COUNT}** Low) across ${FILES_SCANNED} files.
EOF
)
    fi

    COMMENT_PAYLOAD=$(jq -n --arg body "$BODY" '{body: $body}')
    API_BASE="${GITHUB_API_URL:-https://api.github.com}"

    # Update existing SovereignGate PR comment if present to avoid PR noise
    EXISTING_COMMENT_ID=$(curl -fsSL \
      -H "Authorization: Bearer $GITHUB_TOKEN" \
      -H "Accept: application/vnd.github+json" \
      "${API_BASE}/repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments" \
      | jq -r '[.[] | select(.body | startswith("### SovereignGate Compliance Audit"))][0].id // empty')

    if [[ -n "$EXISTING_COMMENT_ID" ]]; then
      curl -fsSL -X PATCH \
        -H "Authorization: Bearer $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github+json" \
        "${API_BASE}/repos/${GITHUB_REPOSITORY}/issues/comments/${EXISTING_COMMENT_ID}" \
        -d "$COMMENT_PAYLOAD" > /dev/null
    else
      curl -fsSL -X POST \
        -H "Authorization: Bearer $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github+json" \
        "${API_BASE}/repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments" \
        -d "$COMMENT_PAYLOAD" > /dev/null
    fi
  fi
fi

exit "$SCAN_EXIT_CODE"