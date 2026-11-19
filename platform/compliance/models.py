import hashlib
import uuid

from django.db import models

from accounts.models import Organization, User


class Repository(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="repositories",
    )
    name = models.CharField(max_length=200)
    slug = models.SlugField(max_length=200)
    vcs_url = models.URLField(blank=True)
    default_branch = models.CharField(max_length=100, default="main")
    data_classification = models.CharField(
        max_length=32,
        default="customer_pii",
        help_text="Primary personal data category processed by this repository.",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("organization", "slug")
        ordering = ["name"]
        verbose_name_plural = "repositories"

    def __str__(self) -> str:
        return f"{self.organization.slug}/{self.name}"


class ScanRun(models.Model):
    class Status(models.TextChoices):
        PASS = "pass", "Compliant"
        WARN = "warn", "Warnings Present"
        FAIL = "fail", "Non-Compliant"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    repository = models.ForeignKey(
        Repository,
        on_delete=models.CASCADE,
        related_name="scan_runs",
    )
    commit_sha = models.CharField(max_length=64, blank=True, db_index=True)
    branch = models.CharField(max_length=120, default="main")
    engine_version = models.CharField(max_length=32, default="0.1.0")
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.PASS)
    files_scanned = models.PositiveIntegerField(default=0)
    duration_ms = models.PositiveIntegerField(default=0)
    critical_count = models.PositiveIntegerField(default=0)
    high_count = models.PositiveIntegerField(default=0)
    medium_count = models.PositiveIntegerField(default=0)
    low_count = models.PositiveIntegerField(default=0)
    raw_report = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        short_sha = self.commit_sha[:8] if self.commit_sha else "manual"
        return f"{self.repository.name} @ {short_sha} ({self.status})"

    @property
    def total_findings(self) -> int:
        return self.critical_count + self.high_count + self.medium_count + self.low_count


class Finding(models.Model):
    class Severity(models.TextChoices):
        CRITICAL = "critical", "Critical"
        HIGH = "high", "High"
        MEDIUM = "medium", "Medium"
        LOW = "low", "Low"

    class Jurisdiction(models.TextChoices):
        US = "US", "United States (US)"
        CN = "CN", "China (CN)"
        NON_ADEQUATE = "NON_ADEQUATE", "Non-Adequate Third Country"
        EU_EEA = "EU_EEA", "EU / EEA"
        CH = "CH", "Switzerland (CH)"

    class ResolutionStatus(models.TextChoices):
        OPEN = "open", "Open / Unmitigated"
        DPA_VERIFIED = "dpa_verified", "DPA & SCC/DPF Verified"
        FALSE_POSITIVE = "false_positive", "False Positive"
        ACCEPTED_RISK = "accepted_risk", "Risk Accepted by DPO"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_run = models.ForeignKey(
        ScanRun,
        on_delete=models.CASCADE,
        related_name="findings",
    )
    rule_id = models.CharField(max_length=32, db_index=True)
    title = models.CharField(max_length=255)
    provider = models.CharField(max_length=160, db_index=True)
    category = models.CharField(max_length=64)
    severity = models.CharField(max_length=16, choices=Severity.choices, db_index=True)
    jurisdiction = models.CharField(max_length=20, choices=Jurisdiction.choices, db_index=True)
    target_type = models.CharField(max_length=32, default="source_code")
    file_path = models.CharField(max_length=512)
    line_number = models.PositiveIntegerField(default=1)
    snippet = models.TextField(blank=True)
    matched_indicator = models.CharField(max_length=255, blank=True)
    primary_legal_article = models.CharField(
        max_length=120,
        help_text="Primary GDPR or Swiss nDSG article triggered (e.g., Art. 44 GDPR / Art. 16 nDSG).",
    )
    legal_references = models.JSONField(default=list, blank=True)
    description = models.TextField(blank=True)
    remediation = models.TextField(blank=True)
    resolution_status = models.CharField(
        max_length=24,
        choices=ResolutionStatus.choices,
        default=ResolutionStatus.OPEN,
        db_index=True,
    )
    reviewed_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="reviewed_findings",
    )
    review_note = models.TextField(blank=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    fingerprint = models.CharField(
        max_length=64,
        blank=True,
        db_index=True,
        help_text="Stable identity of a finding across scans (rule + file + matched indicator).",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["file_path", "line_number", "rule_id"]
        indexes = [
            models.Index(fields=["scan_run", "severity"]),
            models.Index(fields=["scan_run", "jurisdiction"]),
            models.Index(fields=["scan_run", "resolution_status"]),
        ]

    @staticmethod
    def compute_fingerprint(rule_id: str, file_path: str, matched_indicator: str) -> str:
        """Line numbers are deliberately excluded so a finding survives unrelated edits."""
        raw = "\x1f".join((rule_id, file_path, matched_indicator))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def __str__(self) -> str:
        return f"[{self.severity.upper()}] {self.rule_id} in {self.file_path}:{self.line_number}"


class TriageEvent(models.Model):
    """Append-only audit trail of DPO decisions (accountability, Art. 5(2) GDPR).

    Findings are re-created on every scan; events are keyed by fingerprint so the
    history of a decision follows the finding across scans.
    """

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    repository = models.ForeignKey(
        Repository, on_delete=models.CASCADE, related_name="triage_events"
    )
    fingerprint = models.CharField(max_length=64, db_index=True)
    rule_id = models.CharField(max_length=32)
    file_path = models.CharField(max_length=512)
    from_status = models.CharField(max_length=24, choices=Finding.ResolutionStatus.choices)
    to_status = models.CharField(max_length=24, choices=Finding.ResolutionStatus.choices)
    note = models.TextField(blank=True)
    actor = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="triage_events"
    )
    actor_email = models.EmailField(blank=True, help_text="Snapshot kept if the account is deleted.")
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["repository", "fingerprint", "-created_at"])]

    def __str__(self) -> str:
        return f"{self.actor_email or 'system'}: {self.from_status} -> {self.to_status} ({self.rule_id})"
