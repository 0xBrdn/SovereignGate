use crate::rules::schema::Severity;
use crate::scanner::ScanReport;
use comfy_table::{presets::UTF8_FULL_CONDENSED, Attribute, Cell, Color, ContentArrangement, Table};
use std::fmt::Write;

pub fn render_cli_table(report: &ScanReport) -> String {
    let mut out = String::new();

    writeln!(
        out,
        "\nSovereignGate v{} — GDPR & Swiss nDSG Compliance Audit",
        report.engine_version
    )
    .ok();
    writeln!(
        out,
        "Target: {} | Files Scanned: {} | Duration: {}ms",
        report.target_path, report.summary.files_scanned, report.summary.duration_ms
    )
    .ok();
    writeln!(
        out,
        "Findings: {} total (CRITICAL: {}, HIGH: {}, MEDIUM: {}, LOW: {})\n",
        report.summary.total_findings,
        report.summary.critical,
        report.summary.high,
        report.summary.medium,
        report.summary.low
    )
    .ok();

    if report.findings.is_empty() {
        writeln!(
            out,
            "PASS: No unauthorized cross-border data flows or non-EU/CH sub-processors detected."
        )
        .ok();
        return out;
    }

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL_CONDENSED)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            Cell::new("SEVERITY").add_attribute(Attribute::Bold),
            Cell::new("RULE").add_attribute(Attribute::Bold),
            Cell::new("SUB-PROCESSOR").add_attribute(Attribute::Bold),
            Cell::new("JURISDICTION").add_attribute(Attribute::Bold),
            Cell::new("LEGAL BASIS").add_attribute(Attribute::Bold),
            Cell::new("LOCATION").add_attribute(Attribute::Bold),
        ]);

    for f in &report.findings {
        let sev_color = match f.severity {
            Severity::Critical => Color::Red,
            Severity::High => Color::Yellow,
            Severity::Medium => Color::Cyan,
            Severity::Low => Color::Grey,
        };

        let legal_basis: Vec<String> = f
            .legal_references
            .iter()
            .map(|lr| format!("{} ({})", lr.article, lr.framework))
            .collect();

        table.add_row(vec![
            Cell::new(f.severity.to_string())
                .fg(sev_color)
                .add_attribute(Attribute::Bold),
            Cell::new(&f.rule_id),
            Cell::new(&f.provider),
            Cell::new(f.jurisdiction.to_string()).add_attribute(Attribute::Bold),
            Cell::new(legal_basis.join("\n")),
            Cell::new(format!("{}:{}", f.file_path, f.line)),
        ]);
    }

    writeln!(out, "{table}").ok();

    if !report.summary.unique_subprocessors.is_empty() {
        writeln!(
            out,
            "\nDetected Third-Party Sub-Processors ({}): {}",
            report.summary.unique_subprocessors.len(),
            report.summary.unique_subprocessors.join(", ")
        )
        .ok();
    }

    out
}