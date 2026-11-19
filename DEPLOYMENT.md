# Deploying SovereignGate

A hardened three-container stack: **MySQL 8.4**, **Gunicorn/Django**, **Caddy** (automatic TLS).
Host it in a jurisdiction that matches the data you audit, for example Infomaniak or Exoscale (CH),
or Hetzner (DE).

## 1. Prerequisites

- A VM with Docker and the Compose plugin, ports 80/443 open.
- A DNS `A`/`AAAA` record for your audit domain pointing at the VM.

## 2. Configure

```sh
cp .env.prod.example .env.prod
python3 -c "import secrets; print(secrets.token_urlsafe(48))"   # use for SECRET_KEY
```

Edit `.env.prod`:

| Variable | Notes |
| :--- | :--- |
| `SOVEREIGNGATE_DOMAIN`, `ACME_EMAIL` | Used by Caddy for Let's Encrypt |
| `SECRET_KEY` | At least 32 random characters. The app **refuses to start** otherwise |
| `ALLOWED_HOSTS` | Your domain. `CSRF_TRUSTED_ORIGINS` is derived from it |
| `TRUST_PROXY_HEADERS` | `True` behind Caddy (client IP for rate limiting, HTTPS detection) |
| `MYSQL_*`, `DATABASE_URL` | Passwords must match between the two |

`.env.prod` is git-ignored. Never commit it, never ship it in an archive.

## 3. Launch

```sh
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
docker compose -f docker-compose.prod.yml exec web python manage.py createsuperuser
```

Open `https://<your-domain>/admin/`, then:

1. Create an **Organization** (regime `GDPR`, `NDSG` or `DUAL`).
2. Add users under **Organization memberships** with the right role (see below).
3. Create an **API token** and copy it immediately; it is shown once.

### Roles

| Role | Read findings | Export CSV / ROPA | Record decisions |
| :--- | :---: | :---: | :---: |
| Owner | yes | yes | yes |
| Data Protection Officer | yes | yes | yes |
| Security / DevOps Engineer | yes | yes | no |
| Read-only Auditor | yes | yes | no |

## 4. Connect CI

Send the report with the default branch so the console tracks the right baseline:

```sh
curl -fsS -X POST "https://<your-domain>/api/v1/scans/ingest/" \
  -H "Authorization: Bearer $SOVEREIGNGATE_API_TOKEN" \
  -H "Content-Type: application/json" \
  -H "X-SovereignGate-Repository: my-service" \
  -H "X-SovereignGate-Branch: $BRANCH" \
  -H "X-SovereignGate-Default-Branch: main" \
  --data-binary @report.json
```

Limits (override in `.env.prod`): 10 MB per request, 5,000 findings per scan, 60 requests per minute
per token. Likely secrets in snippets are masked before storage.

## 5. Operate

```sh
docker compose -f docker-compose.prod.yml logs -f web          # application + ingestion log
docker compose -f docker-compose.prod.yml exec db sh -c \
  'mysqldump -u root -p"$MYSQL_ROOT_PASSWORD" "$MYSQL_DATABASE"' > backup-$(date +%F).sql
```

- **Upgrades:** `git pull && docker compose ... up -d --build`. Migrations run at container start.
- **Back up** the `mysql_data` volume: the audit trail (`TriageEvent`) is your accountability record.
- **Rotate** `SECRET_KEY` and database passwords if `.env.prod` was ever shared or committed.

## 6. Hardening checklist

- [ ] Admin reachable only from your network or VPN (Caddy `remote_ip` matcher on `/admin/*`).
- [ ] Off-host, encrypted database backups with a tested restore.
- [ ] Containers and base images rebuilt monthly.
- [ ] Two-factor authentication in front of the console (SSO proxy) for production use.
