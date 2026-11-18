use crate::rules::schema::{CompiledRule, Severity};
use crate::scanner::ScanReport;
use serde::Serialize;
use serde_json::json;

/// Static Analysis Results Interchange Format (SARIF) v2.1.0 schema structures
/// compatible with GitHub Code Scanning, GitLab SAST, and VS Code SARIF Viewer.
#[derive(Serialize)]
struct SarifLog {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifDriver {
    name: &'static str,
    version: String,
    information_uri: &'static str,
    rules: Vec<SarifReportingDescriptor>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifReportingDescriptor {
    id: String,
    name: String,
    short_description: SarifMessage,
    full_description: SarifMessage,
    help: SarifMultiformatMessage,
    default_configuration: SarifConfiguration,
    properties: serde_json::Value,
}

#[derive(Serialize)]
struct SarifConfiguration {
    level: &'static str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifResult {
    rule_id: String,
    level: &'static str,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
    properties: serde_json::Value,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

#[derive(Serialize)]
struct SarifMultiformatMessage {
    text: String,
    markdown: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifLocation {
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifPhysicalLocation {
    artifact_location: SarifArtifactLocation,
    region: SarifRegion,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SarifRegion {
    start_line: usize,
    snippet: SarifArtifactContent,
}

#[derive(Serialize)]
struct SarifArtifactContent {
    text: String,
}

fn severity_to_sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

pub fn render_sarif(
    report: &ScanReport,
    compiled_rules: &[CompiledRule],
) -> Result<String, serde_json::Error> {
    let descriptors: Vec<SarifReportingDescriptor> = compiled_rules
        .iter()
        .map(|cr| {
            let r = &cr.rule;
            let articles: Vec<String> = r
                .legal_references
                .iter()
                .map(|lr| format!("{} ({})", lr.article, lr.framework))
                .collect();

            SarifReportingDescriptor {
                id: r.id.clone(),
                name: r.title.clone(),
                short_description: SarifMessage {
                    text: format!("{} [{}]", r.title, r.jurisdiction),
                },
                full_description: SarifMessage {
                    text: r.description.clone(),
                },
                help: SarifMultiformatMessage {
                    text: r.remediation.clone(),
                    markdown: format!(
                        "**Sub-Processor:** {} (`{}`)\n\n**Legal Basis:** {}\n\n**Remediation:** {}",
                        r.provider,
                        r.jurisdiction,
                        articles.join(", "),
                        r.remediation
                    ),
                },
                default_configuration: SarifConfiguration {
                    level: severity_to_sarif_level(r.severity),
                },
                properties: json!({
                    "provider": r.provider,
                    "jurisdiction": r.jurisdiction,
                    "severity": r.severity,
                    "legalReferences": r.legal_references,
                    "tags": ["gdpr", "ndsg", "privacy", "cross-border-transfer"]
                }),
            }
        })
        .collect();

    let results: Vec<SarifResult> = report
        .findings
        .iter()
        .map(|f| {
            let articles: Vec<String> = f
                .legal_references
                .iter()
                .map(|lr| format!("{} {}", lr.article, lr.framework))
                .collect();

            SarifResult {
                rule_id: f.rule_id.clone(),
                level: severity_to_sarif_level(f.severity),
                message: SarifMessage {
                    text: format!(
                        "{}: {} ({}) detected via '{}' — {}",
                        f.title,
                        f.provider,
                        f.jurisdiction,
                        f.matched_indicator,
                        articles.join(", ")
                    ),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            // Normalize Windows backslashes to forward slashes per SARIF URI spec
                            uri: f.file_path.replace('\\', "/"),
                        },
                        region: SarifRegion {
                            start_line: f.line,
                            snippet: SarifArtifactContent {
                                text: f.snippet.clone(),
                            },
                        },
                    },
                }],
                properties: json!({
                    "provider": f.provider,
                    "jurisdiction": f.jurisdiction,
                    "severity": f.severity,
                    "matchedIndicator": f.matched_indicator,
                    "legalReferences": f.legal_references,
                }),
            }
        })
        .collect();

    let log = SarifLog {
        schema: "https://json.schemastore.org/sarif-2.1.0.json",
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "SovereignGate",
                    version: report.engine_version.clone(),
                    information_uri: "https://github.com/sovereigngate/sovereigngate",
                    rules: descriptors,
                },
            },
            results,
        }],
    };

    serde_json::to_string_pretty(&log)
}