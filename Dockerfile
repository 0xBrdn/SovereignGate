# Stage 1: Build static Rust CLI engine
FROM rust:1.88-slim-bookworm AS rust-builder

WORKDIR /build/engine
COPY engine/Cargo.toml engine/Cargo.lock ./
COPY engine/rules ./rules
COPY engine/src ./src

RUN cargo build --release --locked

# Stage 2: Build Python wheels
FROM python:3.12-slim-bookworm AS python-builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY platform/requirements.txt ./requirements.txt
RUN pip wheel --no-cache-dir --wheel-dir /wheels -r requirements.txt

# Stage 3: Minimal hardened production runtime (Django + WeasyPrint + Rust binary)
FROM python:3.12-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DJANGO_SETTINGS_MODULE=config.settings \
    PORT=8000

# System libraries required by WeasyPrint (Pango, Cairo, GDK-PixBuf) & MySQL TLS
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    fonts-inter \
    fonts-jetbrains-mono \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libffi8 \
    shared-mime-info \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 sovereigngate && \
    useradd --system --uid 10001 --gid sovereigngate --create-home sovereigngate

COPY --from=rust-builder /build/engine/target/release/sovereigngate /usr/local/bin/sovereigngate
RUN chmod 0755 /usr/local/bin/sovereigngate

COPY --from=python-builder /wheels /wheels
RUN pip install --no-cache-dir --no-index --find-links=/wheels /wheels/*.whl && rm -rf /wheels
WORKDIR /app/platform
COPY --chown=sovereigngate:sovereigngate platform/ /app/platform/

RUN SECRET_KEY=build-only-placeholder-never-used-at-runtime-0000 python manage.py collectstatic --noinput

USER sovereigngate

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/healthz/ || exit 1

CMD ["sh", "-c", "python manage.py migrate --noinput && gunicorn config.wsgi:application --bind 0.0.0.0:8000 --workers 3 --threads 2 --timeout 60 --access-logfile - --error-logfile -"]