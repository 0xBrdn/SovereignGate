use crate::rules::Severity;
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "sovereigngate",
    version,
    about = "Automated GDPR (EU) and nDSG/nLPD (Switzerland) compliance auditing engine"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Scan a repository, directory, or file for cross-border data flows and sub-processors
    Scan(ScanArgs),
    /// List all active compliance rules in the threat intelligence database
    Rules(RulesArgs),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Cli,
    Json,
    Sarif,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum FailThreshold {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl FailThreshold {
    pub fn to_severity(self) -> Option<Severity> {
        match self {
            FailThreshold::None => None,
            FailThreshold::Low => Some(Severity::Low),
            FailThreshold::Medium => Some(Severity::Medium),
            FailThreshold::High => Some(Severity::High),
            FailThreshold::Critical => Some(Severity::Critical),
        }
    }
}

#[derive(Debug, Parser)]
pub struct ScanArgs {
    /// Path to target repository, directory, or file
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Output report format
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Cli)]
    pub format: OutputFormat,

    /// Write report output to a file path instead of stdout
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Optional directory containing custom YAML compliance rules (overrides embedded rules)
    #[arg(long, env = "SOVEREIGNGATE_RULES_DIR")]
    pub rules_dir: Option<PathBuf>,

    /// Exit with non-zero status code (1) if findings at or above this severity exist
    #[arg(long, value_enum, default_value_t = FailThreshold::High)]
    pub fail_on: FailThreshold,
}

#[derive(Debug, Parser)]
pub struct RulesArgs {
    /// Optional directory containing custom YAML compliance rules
    #[arg(long, env = "SOVEREIGNGATE_RULES_DIR")]
    pub rules_dir: Option<PathBuf>,

    /// Output rule catalog as JSON
    #[arg(long)]
    pub json: bool,
}