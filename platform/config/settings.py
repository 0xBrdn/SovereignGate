"""SovereignGate platform settings.

Everything environment-specific comes from environment variables (optionally
loaded from platform/.env). Production defaults are secure; DEBUG relaxes them.
"""
import sys
import tempfile
from pathlib import Path

import environ
from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent

env = environ.Env(
    DEBUG=(bool, False),
    ALLOWED_HOSTS=(list, ["localhost", "127.0.0.1"]),
)

env_file = BASE_DIR / ".env"
if env_file.exists():
    environ.Env.read_env(env_file)

DEBUG = env("DEBUG")
TESTING = len(sys.argv) > 1 and sys.argv[1] == "test"

# --------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------
_INSECURE_KEY_PREFIXES = ("unsafe", "dev-", "replace-with", "insecure")
SECRET_KEY = env("SECRET_KEY", default="")
if DEBUG or TESTING:
    SECRET_KEY = SECRET_KEY or "insecure-development-key-" + "x" * 32
elif len(SECRET_KEY) < 32 or SECRET_KEY.lower().startswith(_INSECURE_KEY_PREFIXES):
    raise ImproperlyConfigured(
        "SECRET_KEY must be set to a unique random value of at least 32 characters "
        "when DEBUG is off. Generate one with: "
        "python -c 'from django.core.management.utils import get_random_secret_key as g; print(g())'"
    )

ALLOWED_HOSTS = env("ALLOWED_HOSTS")

# --------------------------------------------------------------------------
# Applications
# --------------------------------------------------------------------------
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django_htmx",
    "accounts",
    "compliance",
]

AUTH_USER_MODEL = "accounts.User"
LOGIN_URL = "/accounts/login/"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/accounts/login/"

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "config.middleware.SecurityHeadersMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "django_htmx.middleware.HtmxMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "accounts.context_processors.tenant_context",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------
DATABASES = {
    "default": env.db("DATABASE_URL", default=f"sqlite:///{BASE_DIR / 'db.sqlite3'}")
}
DATABASES["default"]["CONN_MAX_AGE"] = env.int("DB_CONN_MAX_AGE", default=60)
DATABASES["default"]["CONN_HEALTH_CHECKS"] = True
if DATABASES["default"]["ENGINE"].endswith("mysql"):
    DATABASES["default"].setdefault("OPTIONS", {}).setdefault("charset", "utf8mb4")

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# --------------------------------------------------------------------------
# Cache (also backs the rate limiter). File-based so that all gunicorn workers
# of one container share counters; use Redis/Memcached for multi-host setups.
# --------------------------------------------------------------------------
if TESTING:
    CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}
else:
    CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.filebased.FileBasedCache",
            "LOCATION": env(
                "CACHE_DIR", default=str(Path(tempfile.gettempdir()) / "sovereigngate-cache")
            ),
        }
    }

# --------------------------------------------------------------------------
# Authentication & sessions
# --------------------------------------------------------------------------
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 12}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

SESSION_COOKIE_NAME = "sg_session"
SESSION_COOKIE_AGE = env.int("SESSION_COOKIE_AGE", default=60 * 60 * 8)
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"

# --------------------------------------------------------------------------
# Transport security (behind the Caddy reverse proxy in production)
# --------------------------------------------------------------------------
# Trust X-Forwarded-Proto / X-Real-IP only when the app is NOT directly exposed.
TRUST_PROXY_HEADERS = env.bool("TRUST_PROXY_HEADERS", default=False)
if TRUST_PROXY_HEADERS:
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

_PUBLIC_HOSTS = [h for h in ALLOWED_HOSTS if h not in {"localhost", "127.0.0.1", "*"} and not h.startswith(".")]
CSRF_TRUSTED_ORIGINS = env.list(
    "CSRF_TRUSTED_ORIGINS",
    default=[] if DEBUG else [f"https://{host}" for host in _PUBLIC_HOSTS],
)

SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SECURE_HSTS_SECONDS = env.int("SECURE_HSTS_SECONDS", default=0 if DEBUG else 31_536_000)
SECURE_HSTS_INCLUDE_SUBDOMAINS = env.bool("SECURE_HSTS_INCLUDE_SUBDOMAINS", default=False)
SECURE_REFERRER_POLICY = "same-origin"
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"
CSRF_FAILURE_VIEW = "config.views.csrf_failure"

# --------------------------------------------------------------------------
# Ingestion API limits and throttling
# --------------------------------------------------------------------------
DATA_UPLOAD_MAX_MEMORY_SIZE = env.int("MAX_UPLOAD_BYTES", default=10 * 1024 * 1024)
SG_MAX_FINDINGS_PER_SCAN = env.int("SG_MAX_FINDINGS_PER_SCAN", default=5000)
SG_INGEST_RATE_LIMIT = env.int("SG_INGEST_RATE_LIMIT", default=60)          # requests / minute / token
SG_LOGIN_MAX_ATTEMPTS = env.int("SG_LOGIN_MAX_ATTEMPTS", default=8)         # failures / window / (ip, email)
SG_LOGIN_WINDOW_SECONDS = env.int("SG_LOGIN_WINDOW_SECONDS", default=15 * 60)

# --------------------------------------------------------------------------
# i18n
# --------------------------------------------------------------------------
LANGUAGE_CODE = "en-us"
TIME_ZONE = "Europe/Zurich"
USE_I18N = True
USE_TZ = True

# --------------------------------------------------------------------------
# Static files (all assets, including fonts and htmx, are self-hosted)
# --------------------------------------------------------------------------
STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"
_static_backend = (
    "django.contrib.staticfiles.storage.StaticFilesStorage"
    if (DEBUG or TESTING)
    else "whitenoise.storage.CompressedManifestStaticFilesStorage"
)
STORAGES = {
    "default": {"BACKEND": "django.core.files.storage.FileSystemStorage"},
    "staticfiles": {"BACKEND": _static_backend},
}

# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "plain": {"format": "%(asctime)s %(levelname)s %(name)s %(message)s"},
    },
    "handlers": {"console": {"class": "logging.StreamHandler", "formatter": "plain"}},
    "root": {"handlers": ["console"], "level": env("LOG_LEVEL", default="INFO")},
    "loggers": {
        "django.security": {"handlers": ["console"], "level": "WARNING", "propagate": False},
        "sovereigngate": {"handlers": ["console"], "level": "INFO", "propagate": False},
    },
}
