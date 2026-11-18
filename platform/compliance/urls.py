from django.urls import path

from compliance import views

app_name = "compliance"

urlpatterns = [
    path("", views.dashboard_overview, name="dashboard"),
    path(
        "findings/<uuid:finding_id>/drawer/",
        views.finding_detail_drawer,
        name="finding_drawer",
    ),
    path(
        "findings/<uuid:finding_id>/resolve/",
        views.update_finding_resolution,
        name="finding_resolve",
    ),
]