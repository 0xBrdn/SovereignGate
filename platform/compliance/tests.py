import json

from django.test import TestCase
from django.urls import reverse

from accounts.models import ApiToken, Organization
from compliance.models import Finding


class ScanIngestionApiTests(TestCase):
    def setUp(self):
        self.org = Organization.objects.create(
            name="Helvetia FinTech AG",
            slug="helvetia-fintech",
            primary_regime=Organization.PrimaryRegime.DUAL,
            headquarters_country="CH",
        )
        _, self.raw_token = ApiToken.generate(organization=self.org, name="ci-runner")

    def test_ingests_native_rust_cli_report(self):
        payload = {
            "repository": "core-payments-api",
            "branch": "main",
            "commit_sha": "a1b2c3d4e5f67890",
            "report": {
                "engine_version": "0.1.0",
                "target_path": ".",
                "summary": {
                    "files_scanned": 42,
                    "total_findings": 1,
                    "critical": 1,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "unique_subprocessors": ["OpenAI OpCo, LLC"],
                    "duration_ms": 14,
                },
                "findings": [
                    {
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
                        "legal_references": [
                            {
                                "framework": "GDPR",
                                "article": "Art. 44 & Art. 46",
                                "summary": "Cross-border transfer to US sub-processor.",
                            }
                        ],
                        "description": "Detects OpenAI usage.",
                        "remediation": "Use EU-hosted inference.",
                    }
                ],
            },
        }

        resp = self.client.post(
            reverse("api_scan_ingest"),
            data=json.dumps(payload),
            content_type="application/json",
            HTTP_AUTHORIZATION=f"Bearer {self.raw_token}",
        )

        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertEqual(data["status"], "fail")
        self.assertEqual(data["summary"]["critical"], 1)
        self.assertEqual(Finding.objects.filter(scan_run__repository__organization=self.org).count(), 1)