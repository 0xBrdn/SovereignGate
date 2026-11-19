"""Best-effort secret redaction for code snippets.

SovereignGate stores the line that triggered a rule. That line is regularly an
SDK initialisation next to a credential. A compliance tool must not become a
secondary store of API keys, so likely secrets are masked at ingestion.
This is defence in depth, not a secret scanner: keep scanning your repos for
secrets with a dedicated tool.
"""
from __future__ import annotations

import re

MASK = "[REDACTED]"

_TOKEN_PATTERNS = [
    re.compile(r"\bsk-[A-Za-z0-9_\-]{16,}"),                                   # OpenAI / Anthropic style
    re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{8,}"),                # Stripe style
    re.compile(r"\bsg_live_[A-Za-z0-9_\-]{8,}"),                               # SovereignGate tokens
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),                                       # AWS access key id
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),                             # GitHub tokens
    re.compile(r"\bglpat-[A-Za-z0-9_\-]{16,}"),                                # GitLab PAT
    re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"),                            # Slack
    re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),  # JWT
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]

_ASSIGNMENT = re.compile(
    r"""(?ix)
    \b(?P<key>[\w.-]*(?:api[_-]?key|secret|token|passw(?:or)?d|pwd|credential)[\w.-]*)
    (?P<sep>\s*[:=]\s*)
    (?P<quote>["']?)
    (?P<value>[^\s"',;)}\]]{6,})
    (?P=quote)
    """
)

# Values that are references to a secret (env lookups, templates), not the secret itself.
_REFERENCE_HINT = re.compile(r"environ|getenv|process\.env|\$\{|\{\{|<%|settings\.|config\.|secrets\.", re.I)
_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.]*$")


def _mask_assignment(match: re.Match) -> str:
    value = match.group("value")
    quoted = bool(match.group("quote"))
    if _REFERENCE_HINT.search(value):
        return match.group(0)
    if not quoted and _IDENTIFIER.match(value) and not any(c.isdigit() for c in value):
        return match.group(0)  # `api_key=api_key` is a variable, not a literal
    quote = match.group("quote")
    return f"{match.group('key')}{match.group('sep')}{quote}{MASK}{quote}"


def redact_secrets(text: str) -> str:
    if not text:
        return text
    for pattern in _TOKEN_PATTERNS:
        text = pattern.sub(MASK, text)
    return _ASSIGNMENT.sub(_mask_assignment, text)
