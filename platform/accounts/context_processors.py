from accounts.models import Organization


def tenant_context(request):
    """Provides the active organization and membership list across all workspace templates."""
    if not request.user.is_authenticated:
        return {"organizations": [], "active_org": None}

    organizations = list(
        Organization.objects.filter(memberships__user=request.user).distinct().order_by("name")
    )
    active_org = None

    selected_slug = request.session.get("active_org_slug")
    if selected_slug:
        active_org = next((org for org in organizations if org.slug == selected_slug), None)

    if active_org is None and organizations:
        active_org = organizations[0]
        request.session["active_org_slug"] = active_org.slug

    return {
        "organizations": organizations,
        "active_org": active_org,
    }