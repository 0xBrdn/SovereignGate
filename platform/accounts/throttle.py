"""Tiny fixed-window rate limiter on top of Django's cache.

Good enough to blunt password guessing and runaway CI loops without adding a
dependency. For multi-host deployments point CACHES at a shared backend.
"""
from __future__ import annotations

import hashlib

from django.conf import settings
from django.core.cache import cache
from django.http import HttpRequest


def client_ip(request: HttpRequest) -> str:
    """Caddy sets X-Real-IP; it is only trusted when TRUST_PROXY_HEADERS is on."""
    if getattr(settings, "TRUST_PROXY_HEADERS", False):
        forwarded = request.META.get("HTTP_X_REAL_IP", "").strip()
        if forwarded:
            return forwarded[:64]
    return request.META.get("REMOTE_ADDR", "unknown")[:64]


def _key(scope: str, identity: str) -> str:
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]
    return f"throttle:{scope}:{digest}"


def hit(scope: str, identity: str, *, limit: int, window: int) -> bool:
    """Record one attempt. Returns True while the caller is still within the limit."""
    key = _key(scope, identity)
    if cache.add(key, 1, timeout=window):
        return True
    try:
        return cache.incr(key) <= limit
    except ValueError:  # key expired between add() and incr()
        cache.set(key, 1, timeout=window)
        return True


def is_blocked(scope: str, identity: str, *, limit: int) -> bool:
    return (cache.get(_key(scope, identity)) or 0) >= limit


def reset(scope: str, identity: str) -> None:
    cache.delete(_key(scope, identity))
