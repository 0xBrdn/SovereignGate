use anyhow::{Context, Result};
use clap::Parser;
use comfy_table::{presets::UTF8_FULL_CONDENSED, Attribute, Cell, Table};
use sovereigngate::cli::{Cli, Commands, OutputFormat, RulesArgs, ScanArgs};
use sovereigngate::report::{render_cli_table, render_json, render_sarif};
use sovereigngate::rules::{load_embedded_rules, load_rules_from_dir, CompiledRule};
use sovereigngate::scanner::scan_path;
use std::fs;
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Scan(args) => execute_scan(args),
        Commands::Rules(args) => execute_rules(args),
    }
}

fn load_ruleset(rules_dir: Option<&std::path::Path>) -> Result<Vec<CompiledRule>> {
    match rules_dir {
        Some(dir) => load_rules_from_dir(dir)
            .with_context(|| format!("failed to load rules from '{}'", dir.display())),
        None => load_embedded_rules().context("failed to load embedded compliance rules"),
    }
}

fn execute_scan(args: ScanArgs) -> Result<ExitCode> {
    let rules = load_ruleset(args.rules_dir.as_deref())?;
    let report = scan_path(&args.path, &rules)
        .with_context(|| format!("scan failed for '{}'", args.path.display()))?;

    let rendered = match args.format {
        OutputFormat::Cli => render_cli_table(&report),
        OutputFormat::Json => render_json(&report).context("failed to serialize JSON report")?,
        OutputFormat::Sarif => {
            render_sarif(&report, &rules).context("failed to serialize SARIF report")?
        }
    };

    if let Some(output_path) = &args.output {
        if let Some(parent) = output_path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create output directory '{}'", parent.display())
            })?;
        }
        fs::write(output_path, &rendered)
            .with_context(|| format!("failed to write report to '{}'", output_path.display()))?;
    } else {
        print!("{rendered}");
        if !rendered.ends_with('\n') {
            println!();
        }
    }

    if let Some(threshold) = args.fail_on.to_severity() {
        let breached = report.findings.iter().any(|f| f.severity >= threshold);
        if breached {
            return Ok(ExitCode::from(1));
        }
    }

    Ok(ExitCode::SUCCESS)
}

fn execute_rules(args: RulesArgs) -> Result<ExitCode> {
    let compiled = load_ruleset(args.rules_dir.as_deref())?;

    if args.json {
        let raw_rules: Vec<_> = compiled.iter().map(|c| &c.rule).collect();
        let json = serde_json::to_string_pretty(&raw_rules)?;
        println!("{json}");
        return Ok(ExitCode::SUCCESS);
    }

    let mut table = Table::new();
    table.load_preset(UTF8_FULL_CONDENSED).set_header(vec![
        Cell::new("ID").add_attribute(Attribute::Bold),
        Cell::new("SEVERITY").add_attribute(Attribute::Bold),
        Cell::new("JURISDICTION").add_attribute(Attribute::Bold),
        Cell::new("PROVIDER").add_attribute(Attribute::Bold),
        Cell::new("TITLE").add_attribute(Attribute::Bold),
    ]);

    for c in &compiled {
        let r = &c.rule;
        table.add_row(vec![
            Cell::new(&r.id),
            Cell::new(r.severity.to_string()),
            Cell::new(r.jurisdiction.to_string()),
            Cell::new(&r.provider),
            Cell::new(&r.title),
        ]);
    }

    println!(
        "SovereignGate Rule Catalog ({} active rules):\n{table}",
        compiled.len()
    );
    Ok(ExitCode::SUCCESS)
}
