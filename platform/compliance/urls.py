from django.urls import path

from compliance import views

app_name = "compliance"

urlpatterns = [
    path("", views.dashboard_overview, name="dashboard"),
    path("reports/ropa.pdf", views.export_ropa_pdf, name="export_ropa_pdf"),
    path("reports/findings.csv", views.export_findings_csv, name="export_findings_csv"),
    path("findings/<uuid:finding_id>/drawer/", views.finding_detail_drawer, name="finding_drawer"),
    path("findings/<uuid:finding_id>/resolve/", views.update_finding_resolution, name="finding_resolve"),
]
