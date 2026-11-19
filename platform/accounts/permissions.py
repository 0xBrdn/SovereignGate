"""Authorization helpers. Authentication proves who the user is, membership
proves which organisation they may touch, the role decides what they may do."""
from __future__ import annotations

from django.core.exceptions import PermissionDenied

from accounts.models import OrganizationMembership


def require_triage(membership: OrganizationMembership | None) -> OrganizationMembership:
    """Only owners and DPOs may record compliance sign-offs."""
    if membership is None or not membership.can_triage:
        raise PermissionDenied("Your role does not allow recording compliance sign-offs.")
    return membership
