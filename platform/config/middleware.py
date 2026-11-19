"""Security headers that Django does not set on its own."""

_APP_CSP = "; ".join(
    [
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "base-uri 'none'",
    ]
)

# Django admin still emits a few inline style attributes.
_ADMIN_CSP = _APP_CSP.replace("style-src 'self'", "style-src 'self' 'unsafe-inline'")

_PERMISSIONS_POLICY = (
    "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
    "microphone=(), payment=(), usb=(), interest-cohort=()"
)


class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        csp = _ADMIN_CSP if request.path.startswith("/admin/") else _APP_CSP
        response.setdefault("Content-Security-Policy", csp)
        response.setdefault("Permissions-Policy", _PERMISSIONS_POLICY)
        response.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        return response
