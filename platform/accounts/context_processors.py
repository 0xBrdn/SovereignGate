from accounts.tenancy import get_active_membership, get_memberships


def tenant_context(request):
    """Active organisation, the user's role in it, and the tenant switcher list."""
    memberships = get_memberships(request)
    active = get_active_membership(request) if memberships else None
    return {
        "organizations": [m.organization for m in memberships],
        "active_org": active.organization if active else None,
        "active_membership": active,
        "can_triage": bool(active and active.can_triage),
    }
