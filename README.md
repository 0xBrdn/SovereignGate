# SovereignGate

**Automated EU GDPR & Swiss nDSG/nLPD Cross-Border Data Flow Compliance Auditing Platform.**

SovereignGate deterministically scans source code, dependency manifests, and Infrastructure-as-Code (Terraform, Docker, Kubernetes) to detect unauthorized cross-border personal data transfers and third-party sub-processors outside Switzerland (`CH`) and the European Economic Area (`EU/EEA`).

Licensed under **AGPLv3**.

---

## Architecture Overview

SovereignGate is split into two decoupled, sovereign components:

1. **Core Compliance Engine (`engine/` — Pure Rust):**
   - High-speed `.gitignore`-aware parallel traversal (`ignore` + `rayon`).
   - Deterministic rule engine (`YAML`) covering 30+ high-risk US/non-adequate sub-processors (OpenAI, Anthropic, AWS non-EU regions, Google Cloud, Stripe, Segment, Mixpanel, GA4, Twilio, SendGrid, Sentry, Datadog) mapped to **EU GDPR Art. 44–49** and **Swiss nDSG Art. 16–17**.
   - Multi-format inspection:
     - **Manifests:** `package.json`, `requirements.txt`, `pyproject.toml`, `Cargo.toml`, `go.mod`
     - **Infrastructure-as-Code:** `*.tf`, `*.tfvars`, `docker-compose.yml`, `Dockerfile`, Kubernetes YAML, `.env.example`
     - **Source Code:** Python, TypeScript/JavaScript, Rust, Go, Java, Kotlin, Ruby, PHP, C#, Swift, HTML/Vue/Svelte
   - Outputs **CLI tables**, **structured JSON**, and **SARIF v2.1.0** for GitHub Code Scanning and GitLab SAST.

2. **Governance & ROPA SaaS Platform (`platform/` — Django 5 + HTMX + Tailwind CSS + MySQL):**
   - Multi-tenant data controller architecture (`Organization`, `Repository`, `ScanRun`, `Finding`).
   - Token-authenticated REST ingestion endpoint (`POST /api/v1/scans/ingest/`).
   - Interactive Swiss-grid audit console with live HTMX filtering, slide-over code/legal evidence inspector, and persistent DPO triage sign-off.
   - Executive-ready **Record of Processing Activities (ROPA)** PDF generator (`WeasyPrint`) compliant with **Art. 30 GDPR** and **Art. 12 nDSG**.

---

## Repository Structure

```text
SovereignGate/
├── engine/                     # Rust CLI & static analysis library
│   ├── Cargo.toml
│   ├── rules/                  # Embedded GDPR & Swiss nDSG threat intelligence YAML rules
│   └── src/
│       ├── cli.rs
│       ├── report/             # CLI table, JSON, and SARIF v2.1.0 formatters
│       ├── rules/              # Rule schema & regex compiler
│       └── scanner/            # Parallel walker, manifest, IaC, and source scanners
├── platform/                   # Django 5 + HTMX + WeasyPrint web console
│   ├── accounts/               # Custom User, Organization, RBAC memberships & API tokens
│   ├── compliance/             # Ingestion API, audit views, ROPA PDF generator
│   ├── config/                 # Django settings, URLs, WSGI/ASGI
│   ├── static/css/             # Swiss typography & design system tokens
│   └── templates/              # Base shell, HTMX partials, WeasyPrint PDF template
├── ci/github-action/           # Containerized GitHub Action (SARIF + PR comment + SaaS sync)
├── deploy/caddy/               # Production reverse-proxy & automatic TLS config
├── .gitlab-ci.yml              # GitLab CI/CD compliance stage template
├── Dockerfile                  # Multi-stage production build (Rust + Python + WeasyPrint)
├── docker-compose.prod.yml     # Sovereign EU/CH production stack (MySQL 8.4 + Web + Caddy)
├── DEPLOYMENT.md               # Step-by-step Infomaniak (CH) / Hetzner (DE) deployment guide
└── Makefile                    # Unified build, test, and local development targets
```

---

## Quickstart (Local Development)

### Prerequisites
- **Rust toolchain** (`1.75+`)
- **Python** (`3.11+`)
- **MySQL** (`8.0+` or `8.4` via Homebrew or Docker)
- **System libraries for WeasyPrint** (macOS: `brew install pango libffi`; Debian/Ubuntu: `apt-get install libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0`)

### 1. Start MySQL & Provision Database
```bash
docker run -d \
  --name sovereigngate-mysql \
  -e MYSQL_ROOT_PASSWORD=root \
  -e MYSQL_DATABASE=sovereigngate_db \
  -e MYSQL_USER=sovereigngate_user \
  -e MYSQL_PASSWORD='SovereignGate_Dev_2026!' \
  -p 3306:3306 \
  mysql:8.4
```

### 2. Bootstrap Python Environment, Compile Rust Engine & Migrate
```bash
make setup-platform
make build-engine
make migrate
```

### 3. Create Initial DPO Account & Start Web Platform
```bash
cd platform
.venv/bin/python manage.py createsuperuser
cd ..
make run-platform
```
Access the console at `http://localhost:8000` (Admin at `http://localhost:8000/admin/`).

---

## CLI Usage

```bash
# Audit current repository with terminal table output (exits 1 if HIGH or CRITICAL found)
./engine/target/release/sovereigngate scan .

# Export SARIF v2.1.0 for GitHub Security tab
./engine/target/release/sovereigngate scan . --format sarif --output results.sarif

# Export structured JSON for SaaS ingestion
./engine/target/release/sovereigngate scan . --format json --output report.json --fail-on critical

# Inspect all active compliance rules
./engine/target/release/sovereigngate rules
```

---

## Stream Scan Results to the SaaS Platform

1. Log into `http://localhost:8000/admin/`.
2. Create an **Organization** (e.g. `Helvetia FinTech AG`, regime `DUAL`), link your user via **Organization Membership**, and create an **API Token** (`sg_live_...`).
3. Post a CLI scan report to the ingestion endpoint:

```bash
curl -X POST http://localhost:8000/api/v1/scans/ingest/ \
  -H "Authorization: Bearer sg_live_YOUR_TOKEN_HERE" \
  -H "Content-Type: application/json" \
  -H "X-SovereignGate-Repository: my-service" \
  -H "X-SovereignGate-Branch: main" \
  --data-binary @report.json
```

---

## Production Deployment

See [DEPLOYMENT.md](DEPLOYMENT.md) for deploying the hardened multi-container stack (`MySQL 8.4` + `Gunicorn/Django` + `Caddy TLS`) on sovereign Swiss (**Infomaniak**, **Exoscale**) or EU (**Hetzner**) infrastructure.