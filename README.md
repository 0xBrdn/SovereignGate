<p align="center">
  <img src="docs/media/logo.svg" width="80" alt="SovereignGate logo">
</p>

<h1 align="center">SovereignGate</h1>

<p align="center">
  <b>Know where personal data goes before a regulator asks</b><br>
  a deterministic EU GDPR and Swiss nDSG cross-border transfer auditor for code, dependencies and infrastructure, with a CI scanner, an audit console and a ready-to-sign ROPA.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-AGPLv3-A42E2B?style=for-the-badge&logo=gnu&logoColor=white" alt="License AGPLv3"></a>
  <img src="https://img.shields.io/badge/Engine-Rust_2021-DEA584?style=for-the-badge&logo=rust&logoColor=black" alt="Rust engine">
  <img src="https://img.shields.io/badge/Console-Django_5.1_%2B_HTMX-092E20?style=for-the-badge&logo=django&logoColor=white" alt="Django and HTMX console">
  <img src="https://img.shields.io/badge/Database-MySQL_8.4-4479A1?style=for-the-badge&logo=mysql&logoColor=white" alt="MySQL 8.4">
  <img src="https://img.shields.io/badge/Law-GDPR_%7C_nDSG-0D47A1?style=for-the-badge" alt="GDPR and nDSG">
  <img src="https://img.shields.io/badge/Output-CLI_%7C_JSON_%7C_SARIF_2.1.0-2E7D32?style=for-the-badge" alt="CLI, JSON and SARIF output">
  <img src="https://img.shields.io/badge/Assets-100%25_self--hosted-555555?style=for-the-badge" alt="Self-hosted assets">
</p>

<p align="center">
  <a href="#quickstart">Quickstart</a> ·
  <a href="#features">Features</a> ·
  <a href="#detection-methodology">Detection</a> ·
  <a href="#security-model">Security</a> ·
  <a href="#legal-notice-and-responsible-use">Legal notice</a> ·
  <a href="#license">License</a>
</p>

SovereignGate is a two-part system. A single Rust binary scans a repository and reports every place where
personal data can leave Switzerland or the EEA. A Django console receives those reports from CI, lets your
Data Protection Officer triage each finding with a permanent audit trail, and exports the Record of
Processing Activities. It never executes your code and never sends your source anywhere: the scanner is
local and deterministic, and the console is yours to host.

New here? Run `make build-engine`, then `./engine/target/release/sovereigngate scan .` on any project.
No account, no network, no configuration.

## Why it exists

Since the Swiss nDSG (2023) and the EU-US Data Privacy Framework, "which US vendors see our users' data?"
is a question auditors ask and engineers cannot answer quickly. Sub-processors enter through an SDK in
`package.json`, a Terraform region, an analytics snippet or a `docker-compose.yml`, long after the legal
review. SovereignGate finds them where they are introduced, maps each one to the GDPR and nDSG article it
triggers, and keeps the decision your DPO made about it, so the next scan does not start from zero.

## Features

### A transfer register, not a pile of alerts

Every finding carries its severity, the recipient's jurisdiction, the legal basis (for example
`Art. 44 & Art. 46 GDPR`), the matched evidence line and a concrete remediation. The console shows them as
a single register with live filtering by severity, jurisdiction, decision and free text, server-side
pagination, and a shareable URL for every filtered view.

### 34 rules for the sub-processors that matter

Rules are plain YAML, grouped by domain: AI and ML APIs, cloud regions, payments and communications,
telemetry and analytics. Each maps to GDPR Art. 44 to 49 and nDSG Art. 16 and 17. Load your own with
`--rules-dir` or `SOVEREIGNGATE_RULES_DIR`.

### Three inspectors, one pass

| Inspector | Files |
| :--- | :--- |
| Manifests | `package.json`, `requirements.txt`, `pyproject.toml`, `Cargo.toml`, `go.mod` |
| Infrastructure as code | `*.tf`, `*.tfvars`, `docker-compose.yml`, `Dockerfile`, Kubernetes YAML, `.env.example` |
| Source code | Python, JS/TS, Rust, Go, Java, Kotlin, Ruby, PHP, C#, Swift, Scala, HTML, Vue, Svelte, Astro, shell |

The walk is `.gitignore`-aware and parallel (`ignore` + `rayon`). Lockfiles, minified bundles, binaries and
files over 2 MiB are skipped.

### DPO sign-off with an audit trail

Open a finding, read the evidence, then record one of four decisions: **DPA and SCC/DPF verified**,
**risk accepted**, **false positive** or **open**. A justification is mandatory for every decision except
*open*. Each decision is written to an append-only log (who, when, from, to, why) that follows the finding
across scans, and it is carried over automatically when the same finding reappears. This is the evidence
behind accountability under Art. 5(2) GDPR.

### Role-based access

| Role | Read | Export | Record decisions |
| :--- | :---: | :---: | :---: |
| Owner | yes | yes | yes |
| Data Protection Officer | yes | yes | yes |
| Security / DevOps Engineer | yes | yes | no |
| Read-only Auditor | yes | yes | no |

### Reports your auditor will accept

- **ROPA PDF** compliant with Art. 30 GDPR and Art. 12 nDSG, built with WeasyPrint and fully offline.
- **CSV export** of the current filtered view, safe against spreadsheet formula injection.
- **SARIF 2.1.0** for GitHub Code Scanning and GitLab SAST.

### Posture that reflects `main`, not the last experiment

The console computes each repository's current posture from its latest scan on the **default branch**,
falling back to the latest scan on any branch. A throw-away feature branch can no longer overwrite what the
DPO has signed off.

### CI/CD integration

| Integration | Where |
| :--- | :--- |
| GitHub Action (SARIF upload, PR comment, console sync) | `ci/github-action/` |
| GitLab CI template | `.gitlab-ci.yml` |
| Plain CLI | exit code `0` clean, `1` threshold breached, `2` error |

### Telemetry and ingestion API

| Endpoint | Method | Auth | Purpose |
| :--- | :--- | :--- | :--- |
| `/api/v1/scans/ingest/` | POST | Bearer `sg_live_…` | Ingest a CLI JSON report or a SARIF log |
| `/reports/ropa.pdf` | GET | Session | Download the ROPA |
| `/reports/findings.csv` | GET | Session | Export filtered findings |
| `/healthz/` | GET | None | Liveness probe |

## System architecture

```text
+-----------------------------------+
|   Repository / CI checkout        |
|   code · manifests · IaC          |
+-----------------+-----------------+
                  | read-only traversal (.gitignore aware, parallel)
                  v
+-----------------------------------+
|     Rust engine (sovereigngate)   |
|  - Manifest / IaC / Source scan   |
|  - YAML rule catalog (34 rules)   |
|  - GDPR Art. 44-49, nDSG 16-17    |
+-----------------+-----------------+
                  | CLI table · JSON · SARIF 2.1.0
                  v
+-----------------------------------+
|   POST /api/v1/scans/ingest/      |
|  - Bearer token, rate limited     |
|  - Validation + secret redaction  |
|  - Triage carry-over (fingerprint)|
+-----------------+-----------------+
                  v
+-----------------------------------+
|    Django console (HTMX, no JS    |
|    framework, strict CSP)         |
|  - Register · sub-processors      |
|  - DPO sign-off + audit trail     |
|  - ROPA PDF · CSV export          |
+-----------------+-----------------+
                  v
+-----------------------------------+
|             MySQL 8.4             |
+-----------------------------------+
```

## Quickstart

### Prerequisites

- Rust toolchain 1.75 or newer
- Python 3.11 or newer
- MySQL 8.0 or 8.4 (or skip `DATABASE_URL` to use SQLite for a quick look)
- WeasyPrint system libraries: macOS `brew install pango libffi`; Debian/Ubuntu
  `apt-get install libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0`

### Scan a project (no server needed)

```sh
make build-engine
./engine/target/release/sovereigngate scan .                            # table, exit 1 on HIGH or CRITICAL
./engine/target/release/sovereigngate scan . --format sarif -o results.sarif
./engine/target/release/sovereigngate scan . --format json -o report.json --fail-on critical
./engine/target/release/sovereigngate rules                             # list the catalog
```

### Run the console

```sh
docker run -d --name sovereigngate-mysql \
  -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=sovereigngate_db \
  -e MYSQL_USER=sovereigngate_user -e MYSQL_PASSWORD='choose-a-password' \
  -p 127.0.0.1:3306:3306 mysql:8.4

make setup-platform        # venv, dependencies, platform/.env (edit DATABASE_URL)
make migrate
make superuser
make run-platform          # http://127.0.0.1:8000
```

In `/admin/`, create an **Organization**, add yourself under **Organization memberships** as `DPO` or
`Owner`, and create an **API token** (shown once).

### Stream a scan to the console

```sh
curl -fsS -X POST http://127.0.0.1:8000/api/v1/scans/ingest/ \
  -H "Authorization: Bearer sg_live_YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-SovereignGate-Repository: my-service" \
  -H "X-SovereignGate-Branch: main" \
  -H "X-SovereignGate-Default-Branch: main" \
  --data-binary @report.json
```

Responses: `201` created, `400` malformed JSON, `401/403` auth, `413` over the size or findings limit,
`422` structurally invalid report, `429` rate limited.

### Tests

```sh
make check        # fmt, clippy, Rust tests, Django tests
```

## Detection methodology

1. **Deterministic matching.** A rule fires on a package name in a manifest, a domain or regex in
   infrastructure or source, or an import statement. There is no model, no heuristic scoring and no network
   access: the same input always yields the same report, which is what makes it auditable.
2. **Severity and jurisdiction.** Each rule declares a severity (`critical`, `high`, `medium`, `low`) and the
   recipient's jurisdiction (`US`, `CN`, `NON_ADEQUATE`, `EU_EEA`, `CH`).
3. **Legal mapping.** Each rule cites the provisions it implicates, for example Art. 44 and 46 GDPR with
   Art. 16 and 17 nDSG, and the safeguard to put in place (DPF certification, SCCs plus a transfer impact
   assessment, EU or Swiss hosting).
4. **Stable identity.** A finding is fingerprinted from `rule + file + matched indicator`, excluding the
   line number, so a decision survives unrelated edits and re-formatting.
5. **Gate.** `--fail-on` (default `high`) turns the report into a CI verdict.

A hit means "personal data may flow to this recipient", not "you are non-compliant". Whether a transfer is
lawful depends on your contracts and data, which is why the DPO decision step exists.

## Security model

| Concern | Measure |
| :--- | :--- |
| Third-party requests from the browser | None. Fonts (SIL OFL), htmx and all assets are self-hosted. A transfer auditor must not leak its users' IPs to a font or script CDN |
| Script and style injection | Strict CSP: `default-src 'none'; script-src 'self'; style-src 'self'`, no inline scripts, no `eval` |
| Authorization | Tenant-scoped queries on every object; role checked server-side for sign-off |
| Open redirect | `next` and `Referer` validated against the host |
| Brute force | Per (IP, email) and per-IP login throttling; per-token ingest rate limit |
| Secrets in evidence | Likely credentials in snippets are masked at ingestion; raw payloads are not stored |
| Ingestion abuse | Size cap, findings cap, strict type coercion, `422` instead of `500` |
| API tokens | 256-bit random, stored as SHA-256, revocable, never shown again |
| Transport | `SECRET_KEY` enforced, secure cookies, HSTS, trusted-proxy handling, CSRF origins derived from `ALLOWED_HOSTS` |
| PDF rendering | External resource fetching disabled |
| Audit trail | Append-only, read-only in the admin |

Report vulnerabilities privately to the maintainer rather than in a public issue.

## Production deployment

A hardened stack (MySQL 8.4, Gunicorn, Caddy with automatic TLS) ships in `docker-compose.prod.yml`.
See [DEPLOYMENT.md](DEPLOYMENT.md) for the full guide, including roles, CI wiring and a hardening checklist.

## Repository layout

| Path | Contents |
| :--- | :--- |
| `engine/` | Rust scanner: `scanner/` (walker, manifest, IaC, source), `rules/` (schema, loader), `report/` (CLI, JSON, SARIF) and the embedded YAML catalog |
| `platform/accounts/` | Custom user, organizations, role memberships, API tokens, tenancy, throttling |
| `platform/compliance/` | Ingestion API, selectors, audit console views, redaction, ROPA PDF |
| `platform/config/` | Settings, security-headers middleware, URLs |
| `platform/static/` | Design system (`tokens`, `base`, `components`, `pages` CSS), vanilla JS, self-hosted fonts and htmx |
| `platform/templates/` | Shell, HTMX partials, login, error pages, PDF template |
| `ci/github-action/` | Containerized GitHub Action |
| `deploy/caddy/` | Reverse proxy and TLS |

## Design language

The console is built like a register, not a dashboard: warm paper and ink, one signal red reserved for
critical transfers, hairline rules instead of cards. Newsreader sets headings and figures, IBM Plex Sans the
interface, IBM Plex Mono identifiers and paths. Severity is always carried by a label and a shape as well as
a colour. Light and dark themes follow the system and every text pair meets WCAG AA. Motion is limited to
short state transitions and honours `prefers-reduced-motion`.

## Legal notice and responsible use

SovereignGate is a **static analysis tool**. It reads source files you point it at and reports what it
finds; it does not observe live traffic or process your users' data. This section is a plain-language
summary and **not legal advice**; obligations differ per organisation and jurisdiction.

**You may**

- Scan code, dependencies and infrastructure you own or are authorized to assess.
- Self-host the console and store its reports in a jurisdiction that suits your obligations.
- Read, modify and redistribute the code under the AGPLv3.

**You must not**

- Treat a report as a legal opinion or a certificate of compliance. Decisions about adequacy, SCCs and
  transfer impact assessments rest with you and your DPO.
- Scan repositories you are not authorized to access, or upload third-party code to a console you do not
  control.
- Put real personal data in test fixtures, scan reports or the justification field.
- Remove or alter this notice and the license terms when you redistribute the software.

The AGPLv3 grants software freedoms. As stated in its sections 15 and 16, the program comes with no
warranty. If you run a modified version as a network service, you must offer its source to its users.

## Roadmap

- Token and repository management in the console (today: Django admin)
- Posture trend per repository and diff between two scans
- Inline suppressions (`sovereigngate:ignore <rule> reason`) and a baseline file in the CLI
- Secret masking in the engine itself, before a report leaves the CI runner
- Webhooks and email digests for new critical findings
- SSO (OIDC) and two-factor authentication
- French, German and Italian interface

## Contributing

Issues and pull requests are welcome. Add or update tests (`make check`), state which rule, severity or
legal mapping changes, and cite the provision in the rule's `legal_references`. New rules need a positive
and a negative fixture.

## License

SovereignGate is free software under the [GNU Affero General Public License v3.0](LICENSE). You can use,
study, change and share it; if you run a modified version as a service, you must publish its source under
the same license. The software is provided without warranty of any kind.
