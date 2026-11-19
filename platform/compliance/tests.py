import json

from django.core.cache import cache
from django.test import TestCase, override_settings
from django.urls import reverse

from accounts.models import ApiToken, Organization, OrganizationMembership, User
from compliance.models import Finding, Repository, ScanRun, TriageEvent
from compliance.redaction import MASK, redact_secrets


def make_report(findings=None, **extra):
    return {
        "engine_version": "0.1.0",
        "target_path": ".",
        "summary": {"files_scanned": 42, "duration_ms": 14},
        "findings": findings if findings is not None else [openai_finding()],
        **extra,
    }


def openai_finding(**over):
    base = {
        "rule_id": "SG-AI-001",
        "title": "OpenAI API Cross-Border Data Transfer",
        "provider": "OpenAI OpCo, LLC",
        "category": "ai_llm",
        "severity": "critical",
        "jurisdiction": "US",
        "target": "source_code",
        "file_path": "src/assistant.py",
        "line": 18,
        "snippet": "client = OpenAI(api_key=os.environ['OPENAI_API_KEY'])",
        "matched_indicator": "import:openai",
        "legal_references": [{"framework": "GDPR", "article": "Art. 44 & Art. 46", "summary": "Transfer to US."}],
        "description": "Detects OpenAI usage.",
        "remediation": "Use EU-hosted inference.",
    }
    base.update(over)
    return base


class Base(TestCase):
    def setUp(self):
        cache.clear()
        self.org = Organization.objects.create(name="Helvetia FinTech AG", slug="helvetia")
        self.other_org = Organization.objects.create(name="Other AG", slug="other")
        self.dpo = self._user("dpo@helvetia.ch", OrganizationMembership.Role.DPO)
        self.auditor = self._user("aud@helvetia.ch", OrganizationMembership.Role.AUDITOR)
        self.engineer = self._user("eng@helvetia.ch", OrganizationMembership.Role.ENGINEER)
        _, self.token = ApiToken.generate(organization=self.org, name="ci")

    def _user(self, email, role, org=None):
        user = User.objects.create_user(email=email, password="SecurePassword2026!")
        OrganizationMembership.objects.create(organization=org or self.org, user=user, role=role)
        return user

    def ingest(self, payload, token=None, **headers):
        return self.client.post(
            reverse("api_scan_ingest"),
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {token or self.token}",
            **headers,
        )


class IngestionTests(Base):
    def test_ingests_report_and_exports_ropa_pdf(self):
        resp = self.ingest({"repository": "core-payments-api", "branch": "main", "report": make_report()})
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(Finding.objects.filter(scan_run__repository__organization=self.org).count(), 1)
        self.client.force_login(self.dpo)
        pdf = self.client.get(reverse("compliance:export_ropa_pdf"))
        self.assertEqual(pdf.status_code, 200)
        self.assertTrue(pdf.content.startswith(b"%PDF-"))

    def test_requires_valid_token(self):
        self.assertEqual(self.client.post(reverse("api_scan_ingest"), "{}", content_type="application/json").status_code, 401)
        self.assertEqual(self.ingest({}, token="sg_live_nope").status_code, 403)

    def test_malformed_values_are_rejected_not_500(self):
        for bad in (
            make_report(findings=["not-an-object"]),
            make_report(findings="nope"),
        ):
            self.assertEqual(self.ingest(bad).status_code, 422)
        # hostile scalars are coerced, never crash
        resp = self.ingest(make_report(findings=[openai_finding(line="abc", legal_references="x")], summary={"files_scanned": "-5"}))
        self.assertEqual(resp.status_code, 201)
        self.assertEqual(Finding.objects.get().line_number, 1)
        self.assertEqual(ScanRun.objects.get().files_scanned, 0)

    @override_settings(SG_MAX_FINDINGS_PER_SCAN=2)
    def test_finding_count_limit(self):
        self.assertEqual(self.ingest(make_report(findings=[openai_finding()] * 3)).status_code, 413)

    @override_settings(SG_INGEST_RATE_LIMIT=2)
    def test_ingest_rate_limit(self):
        codes = [self.ingest(make_report()).status_code for _ in range(3)]
        self.assertEqual(codes, [201, 201, 429])

    def test_secrets_redacted_and_raw_payload_not_stored(self):
        snippet = 'client = OpenAI(api_key="sk-abcdefghijklmnopqrstuvwx")'
        self.ingest(make_report(findings=[openai_finding(snippet=snippet)]))
        self.assertNotIn("sk-abcdef", Finding.objects.get().snippet)
        self.assertNotIn("sk-abcdef", json.dumps(ScanRun.objects.get().raw_report))

    def test_redaction_keeps_env_references(self):
        keep = "OpenAI(api_key=os.environ['OPENAI_API_KEY'])"
        self.assertEqual(redact_secrets(keep), keep)
        self.assertIn(MASK, redact_secrets('password = "hunter2hunter2"'))
        self.assertIn(MASK, redact_secrets("key AKIAABCDEFGHIJKLMNOP"))

    def test_triage_carries_over_and_default_branch_wins(self):
        self.ingest({"repository": "svc", "branch": "main", "default_branch": "main", "report": make_report()})
        finding = Finding.objects.get()
        self.client.force_login(self.dpo)
        r = self.client.post(
            reverse("compliance:finding_resolve", args=[finding.id]),
            {"resolution_status": "dpa_verified", "review_note": "DPA 2026-03-14"},
        )
        self.assertEqual(r.status_code, 200)
        self.ingest({"repository": "svc", "branch": "main", "default_branch": "main", "report": make_report()})
        self.assertEqual(Finding.objects.filter(resolution_status="dpa_verified").count(), 2)
        # a feature-branch scan must not replace the main-branch posture
        self.ingest({"repository": "svc", "branch": "feature/x", "report": make_report(findings=[])})
        resp = self.client.get(reverse("compliance:dashboard") + "?status=all")
        self.assertContains(resp, "OpenAI OpCo")


class TriageTests(Base):
    def setUp(self):
        super().setUp()
        self.ingest({"repository": "svc", "report": make_report()})
        self.finding = Finding.objects.get()
        self.url = reverse("compliance:finding_resolve", args=[self.finding.id])

    def test_read_only_roles_cannot_triage(self):
        for user in (self.auditor, self.engineer):
            self.client.force_login(user)
            r = self.client.post(self.url, {"resolution_status": "false_positive", "review_note": "x"})
            self.assertEqual(r.status_code, 403)
        self.finding.refresh_from_db()
        self.assertEqual(self.finding.resolution_status, "open")
        self.assertEqual(TriageEvent.objects.count(), 0)

    def test_justification_required_and_audit_event_written(self):
        self.client.force_login(self.dpo)
        r = self.client.post(self.url, {"resolution_status": "accepted_risk", "review_note": ""})
        self.assertEqual(r.status_code, 422)
        self.client.post(self.url, {"resolution_status": "accepted_risk", "review_note": "Board approved"})
        event = TriageEvent.objects.get()
        self.assertEqual((event.from_status, event.to_status, event.actor_email), ("open", "accepted_risk", "dpo@helvetia.ch"))
        # identical resubmission is not logged twice
        self.client.post(self.url, {"resolution_status": "accepted_risk", "review_note": "Board approved"})
        self.assertEqual(TriageEvent.objects.count(), 1)

    def test_tenant_isolation(self):
        outsider = self._user("x@other.ch", OrganizationMembership.Role.DPO, org=self.other_org)
        self.client.force_login(outsider)
        self.assertEqual(self.client.get(reverse("compliance:finding_drawer", args=[self.finding.id])).status_code, 404)
        self.assertEqual(self.client.post(self.url, {"resolution_status": "false_positive", "review_note": "x"}).status_code, 404)


class ViewTests(Base):
    def setUp(self):
        super().setUp()
        self.ingest({"repository": "svc", "report": make_report()})
        self.client.force_login(self.dpo)

    def test_dashboard_and_partial_render(self):
        full = self.client.get(reverse("compliance:dashboard"))
        self.assertContains(full, "Cross-border data flows")
        self.assertNotContains(full, "googleapis")
        partial = self.client.get(reverse("compliance:dashboard"), HTTP_HX_REQUEST="true")
        self.assertNotContains(partial, "<html")
        self.assertContains(partial, "findings-table-container")

    def test_drawer_renders_for_each_role(self):
        fid = Finding.objects.get().id
        for user in (self.dpo, self.auditor):
            self.client.force_login(user)
            self.assertContains(self.client.get(reverse("compliance:finding_drawer", args=[fid])), "Audit trail")

    def test_security_headers(self):
        r = self.client.get(reverse("compliance:dashboard"))
        csp = r["Content-Security-Policy"]
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("unsafe", csp)

    def test_csv_export_neutralises_formulas(self):
        Finding.objects.update(provider="=HYPERLINK(\"http://evil\")")
        body = self.client.get(reverse("compliance:export_findings_csv")).content.decode()
        self.assertIn("'=HYPERLINK", body)

    def test_switch_org_rejects_open_redirect(self):
        r = self.client.post(reverse("accounts:switch_org"), {"org_slug": "helvetia", "next": "https://evil.example/"})
        self.assertEqual(r["Location"], "/")
        r = self.client.post(reverse("accounts:switch_org"), {"org_slug": "helvetia", "next": "/reports/findings.csv"})
        self.assertEqual(r["Location"], "/reports/findings.csv")


class LoginTests(Base):
    def test_login_page_and_throttle(self):
        self.client.logout()
        self.assertContains(self.client.get(reverse("accounts:login")), "Sign in")
        with override_settings(SG_LOGIN_MAX_ATTEMPTS=3):
            codes = [
                self.client.post(reverse("accounts:login"), {"username": "dpo@helvetia.ch", "password": "wrong"}).status_code
                for _ in range(5)
            ]
        self.assertEqual(codes[:3], [200, 200, 200])
        self.assertEqual(codes[-1], 429)
