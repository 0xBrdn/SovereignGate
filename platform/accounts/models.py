import hashlib
import secrets
import uuid

from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.utils import timezone


class UserManager(BaseUserManager):
    use_in_migrations = True

    def _create_user(self, email: str, password: str | None, **extra_fields):
        if not email:
            raise ValueError("An email address must be provided.")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email: str, password: str | None = None, **extra_fields):
        extra_fields.setdefault("is_staff", False)
        extra_fields.setdefault("is_superuser", False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email: str, password: str | None = None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        if not extra_fields.get("is_staff") or not extra_fields.get("is_superuser"):
            raise ValueError("Superuser must have is_staff=True and is_superuser=True.")
        return self._create_user(email, password, **extra_fields)


class User(AbstractUser):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    username = None
    email = models.EmailField(unique=True)
    full_name = models.CharField(max_length=150, blank=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    objects = UserManager()

    class Meta:
        ordering = ["email"]

    def __str__(self) -> str:
        return self.email


class Organization(models.Model):
    class PrimaryRegime(models.TextChoices):
        GDPR = "GDPR", "EU GDPR (Regulation 2016/679)"
        NDSG = "NDSG", "Swiss nDSG / nLPD (SR 235.1)"
        DUAL = "DUAL", "Dual EU GDPR + Swiss nDSG"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=160)
    slug = models.SlugField(max_length=80, unique=True)
    primary_regime = models.CharField(
        max_length=12,
        choices=PrimaryRegime.choices,
        default=PrimaryRegime.DUAL,
    )
    dpo_name = models.CharField(max_length=160, blank=True)
    dpo_email = models.EmailField(blank=True)
    headquarters_country = models.CharField(max_length=2, default="CH")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["name"]

    def __str__(self) -> str:
        return self.name


class OrganizationMembership(models.Model):
    class Role(models.TextChoices):
        OWNER = "owner", "Owner"
        DPO = "dpo", "Data Protection Officer"
        ENGINEER = "engineer", "Security / DevOps Engineer"
        AUDITOR = "auditor", "Read-Only Auditor"

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="memberships",
    )
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="memberships",
    )
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.ENGINEER)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("organization", "user")
        ordering = ["organization__name", "user__email"]

    def __str__(self) -> str:
        return f"{self.user.email} -> {self.organization.slug} ({self.role})"


class ApiToken(models.Model):
    """Bearer token used by CI/CD pipelines to ingest Rust engine scan payloads."""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="api_tokens",
    )
    name = models.CharField(max_length=120)
    prefix = models.CharField(max_length=12, db_index=True)
    token_hash = models.CharField(max_length=64, unique=True)
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_api_tokens",
    )
    last_used_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.organization.slug}:{self.name} ({self.prefix}...)"

    @classmethod
    def generate(
        cls,
        organization: Organization,
        name: str,
        created_by: User | None = None,
    ) -> tuple["ApiToken", str]:
        raw_secret = f"sg_live_{secrets.token_urlsafe(32)}"
        digest = hashlib.sha256(raw_secret.encode("utf-8")).hexdigest()
        instance = cls.objects.create(
            organization=organization,
            name=name,
            prefix=raw_secret[:12],
            token_hash=digest,
            created_by=created_by,
        )
        return instance, raw_secret

    @classmethod
    def authenticate(cls, raw_token: str) -> "ApiToken | None":
        if not raw_token.startswith("sg_live_"):
            return None
        digest = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
        token = (
            cls.objects.select_related("organization")
            .filter(token_hash=digest, revoked_at__isnull=True)
            .first()
        )
        if token is not None:
            cls.objects.filter(pk=token.pk).update(last_used_at=timezone.now())
        return token