from django.contrib.auth import views as auth_views
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.urls import path
from django.views.decorators.http import require_POST

from accounts.models import Organization

app_name = "accounts"


@require_POST
def switch_organization(request: HttpRequest) -> HttpResponse:
    slug = request.POST.get("org_slug", "").strip()
    if request.user.is_authenticated and slug:
        exists = Organization.objects.filter(
            slug=slug, memberships__user=request.user
        ).exists()
        if exists:
            request.session["active_org_slug"] = slug
    next_url = request.POST.get("next") or request.META.get("HTTP_REFERER") or "/"
    return redirect(next_url)


urlpatterns = [
    path(
        "login/",
        auth_views.LoginView.as_view(template_name="registration/login.html"),
        name="login",
    ),
    path("logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("switch-org/", switch_organization, name="switch_org"),
]