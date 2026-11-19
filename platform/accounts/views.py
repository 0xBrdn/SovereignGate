from django.conf import settings
from django.contrib.auth.views import LoginView
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.utils.http import url_has_allowed_host_and_scheme
from django.views.decorators.http import require_POST

from accounts.tenancy import SESSION_KEY, get_memberships
from accounts.throttle import client_ip, hit, is_blocked, reset


def _safe_next(request: HttpRequest, candidate: str | None) -> str:
    """Never redirect off-site: `next` and Referer are attacker-controllable."""
    if candidate and url_has_allowed_host_and_scheme(
        candidate, allowed_hosts={request.get_host()}, require_https=request.is_secure()
    ):
        return candidate
    return "/"


@require_POST
def switch_organization(request: HttpRequest) -> HttpResponse:
    slug = request.POST.get("org_slug", "").strip()
    if request.user.is_authenticated and slug:
        if any(m.organization.slug == slug for m in get_memberships(request)):
            request.session[SESSION_KEY] = slug
    target = request.POST.get("next") or request.META.get("HTTP_REFERER")
    return redirect(_safe_next(request, target))


class ThrottledLoginView(LoginView):
    """Login with per-(IP, email) and per-IP failure throttling."""

    template_name = "registration/login.html"
    redirect_authenticated_user = True

    IP_FACTOR = 5  # an IP may fail this many times more than one (ip, email) pair

    def _ids(self, request):
        ip = client_ip(request)
        email = request.POST.get("username", "").strip().lower()
        return f"{ip}|{email}", ip

    def post(self, request, *args, **kwargs):
        pair, ip = self._ids(request)
        limit = settings.SG_LOGIN_MAX_ATTEMPTS
        if is_blocked("login", pair, limit=limit) or is_blocked("login-ip", ip, limit=limit * self.IP_FACTOR):
            form = self.get_form()
            form.add_error(None, "Too many sign-in attempts. Please wait a few minutes and try again.")
            return self.render_to_response(self.get_context_data(form=form), status=429)
        return super().post(request, *args, **kwargs)

    def form_invalid(self, form):
        pair, ip = self._ids(self.request)
        window = settings.SG_LOGIN_WINDOW_SECONDS
        hit("login", pair, limit=settings.SG_LOGIN_MAX_ATTEMPTS, window=window)
        hit("login-ip", ip, limit=settings.SG_LOGIN_MAX_ATTEMPTS * self.IP_FACTOR, window=window)
        return super().form_invalid(form)

    def form_valid(self, form):
        reset("login", self._ids(self.request)[0])
        return super().form_valid(form)
