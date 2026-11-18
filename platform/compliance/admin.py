from django.contrib import admin

from .models import Finding, Repository, ScanRun


@admin.register(Repository)
class RepositoryAdmin(admin.ModelAdmin):
    list_display = ["name", "organization", "default_branch", "data_classification", "updated_at"]
    list_filter = ["organization"]
    search_fields = ["name", "slug"]


@admin.register(ScanRun)
class ScanRunAdmin(admin.ModelAdmin):
    list_display = [
        "repository",
        "branch",
        "commit_sha",
        "status",
        "critical_count",
        "high_count",
        "medium_count",
        "created_at",
    ]
    list_filter = ["status", "repository__organization"]
    readonly_fields = ["created_at"]


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = [
        "rule_id",
        "severity",
        "provider",
        "jurisdiction",
        "primary_legal_article",
        "file_path",
        "line_number",
        "resolution_status",
    ]
    list_filter = ["severity", "jurisdiction", "resolution_status"]
    search_fields = ["rule_id", "provider", "file_path", "snippet"]