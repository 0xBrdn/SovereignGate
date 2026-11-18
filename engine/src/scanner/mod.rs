pub mod iac;
pub mod manifest;
pub mod source;
pub mod walker;

use crate::rules::schema::{Jurisdiction, LegalReference, ProviderCategory, ScanTarget, Severity};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub title: String,
    pub provider: String,
    pub category: ProviderCategory,
    pub severity: Severity,
    pub jurisdiction: Jurisdiction,
    pub target: ScanTarget,
    pub file_path: String,
    pub line: usize,
    pub snippet: String,
    pub matched_indicator: String,
    pub legal_references: Vec<LegalReference>,
    pub description: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub files_scanned: usize,
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub unique_subprocessors: Vec<String>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub engine_version: String,
    pub target_path: String,
    pub summary: ScanSummary,
    pub findings: Vec<Finding>,
}

pub use walker::{scan_path, ScanError};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::load_embedded_rules;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn detects_violations_across_manifests_iac_and_source() {
        let dir = tempdir().expect("create temp workspace");

        fs::write(
            dir.path().join("package.json"),
            r#"{
  "name": "acme-saas",
  "dependencies": {
    "openai": "^4.70.0",
    "stripe": "^17.0.0"
  }
}"#,
        )
        .unwrap();

        fs::write(
            dir.path().join("main.tf"),
            r#"
provider "aws" {
  region = "us-east-1"
}
"#,
        )
        .unwrap();

        fs::write(
            dir.path().join("analytics.ts"),
            r#"
import posthog from 'posthog-js';
posthog.init('phc_test', { api_host: 'https://us.i.posthog.com' });
"#,
        )
        .unwrap();

        let rules = load_embedded_rules().expect("load rules");
        let report = scan_path(dir.path(), &rules).expect("scan temp workspace");

        assert_eq!(report.summary.files_scanned, 3);
        assert!(report.findings.iter().any(|f| f.rule_id == "SG-AI-001"));
        assert!(report.findings.iter().any(|f| f.rule_id == "SG-PAY-001"));
        assert!(report.findings.iter().any(|f| f.rule_id == "SG-IAC-001"));
        assert!(report.findings.iter().any(|f| f.rule_id == "SG-ANA-005"));
    }
}
