from django.contrib import admin

from .models import Finding, Repository, ScanRun, TriageEvent


@admin.register(Repository)
class RepositoryAdmin(admin.ModelAdmin):
    list_display = ["name", "organization", "default_branch", "data_classification", "updated_at"]
    list_filter = ["organization"]
    search_fields = ["name", "slug"]


@admin.register(ScanRun)
class ScanRunAdmin(admin.ModelAdmin):
    list_display = ["repository", "branch", "commit_sha", "status", "critical_count", "high_count", "medium_count", "created_at"]
    list_filter = ["status", "repository__organization"]
    readonly_fields = ["created_at"]


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ["rule_id", "severity", "provider", "jurisdiction", "primary_legal_article", "file_path", "line_number", "resolution_status"]
    list_filter = ["severity", "jurisdiction", "resolution_status"]
    search_fields = ["rule_id", "provider", "file_path"]
    # Triage decisions go through the console so that each one is written to the audit trail.
    readonly_fields = ["resolution_status", "review_note", "reviewed_by", "reviewed_at", "fingerprint"]


@admin.register(TriageEvent)
class TriageEventAdmin(admin.ModelAdmin):
    """Read-only: the audit trail is append-only by design."""

    list_display = ["created_at", "actor_email", "repository", "rule_id", "from_status", "to_status"]
    list_filter = ["to_status", "repository__organization"]
    search_fields = ["actor_email", "rule_id", "file_path", "note"]
    date_hierarchy = "created_at"

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False
