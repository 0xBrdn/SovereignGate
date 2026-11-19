from django.contrib import admin
from django.urls import include, path

from compliance.api import ingest_scan_endpoint
from config.views import healthz

urlpatterns = [
    path("admin/", admin.site.urls),
    path("healthz/", healthz, name="healthz"),
    path("api/v1/scans/ingest/", ingest_scan_endpoint, name="api_scan_ingest"),
    path("accounts/", include("accounts.urls")),
    path("", include("compliance.urls")),
]
