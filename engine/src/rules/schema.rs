use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Jurisdiction {
    Us,
    Cn,
    NonAdequate,
    EuEea,
    Ch,
}

impl fmt::Display for Jurisdiction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Jurisdiction::Us => write!(f, "US"),
            Jurisdiction::Cn => write!(f, "CN"),
            Jurisdiction::NonAdequate => write!(f, "NON_ADEQUATE"),
            Jurisdiction::EuEea => write!(f, "EU/EEA"),
            Jurisdiction::Ch => write!(f, "CH"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderCategory {
    AiLlm,
    CloudInfrastructure,
    PaymentsBilling,
    AnalyticsTelemetry,
    Communications,
    AuthIdentity,
    CdnEdge,
    ErrorMonitoring,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanTarget {
    Manifest,
    Iac,
    SourceCode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegalReference {
    pub framework: String,
    pub article: String,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleMatchers {
    #[serde(default)]
    pub packages: Vec<String>,
    #[serde(default)]
    pub regex_patterns: Vec<String>,
    #[serde(default)]
    pub domains: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub title: String,
    pub provider: String,
    pub category: ProviderCategory,
    pub severity: Severity,
    pub jurisdiction: Jurisdiction,
    pub targets: Vec<ScanTarget>,
    pub legal_references: Vec<LegalReference>,
    pub description: String,
    pub remediation: String,
    pub matchers: RuleMatchers,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleSetFile {
    pub version: String,
    pub rules: Vec<Rule>,
}

/// Pre-compiled representation of a `Rule` used on the hot scanning path.
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub rule: Rule,
    pub compiled_patterns: Vec<Regex>,
}
