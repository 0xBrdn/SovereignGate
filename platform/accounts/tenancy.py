"""Resolve the active tenant (organisation) for a request, once per request."""
from __future__ import annotations

from django.http import HttpRequest

from accounts.models import OrganizationMembership

SESSION_KEY = "active_org_slug"


def get_memberships(request: HttpRequest) -> list[OrganizationMembership]:
    cached = getattr(request, "_sg_memberships", None)
    if cached is not None:
        return cached
    user = getattr(request, "user", None)
    if user is None or not user.is_authenticated:
        memberships: list[OrganizationMembership] = []
    else:
        memberships = list(
            OrganizationMembership.objects.filter(user=user)
            .select_related("organization")
            .order_by("organization__name")
        )
    request._sg_memberships = memberships
    return memberships


def get_active_membership(request: HttpRequest) -> OrganizationMembership | None:
    memberships = get_memberships(request)
    if not memberships:
        return None
    slug = request.session.get(SESSION_KEY)
    active = next((m for m in memberships if m.organization.slug == slug), None)
    if active is None:
        active = memberships[0]
        request.session[SESSION_KEY] = active.organization.slug
    return active
