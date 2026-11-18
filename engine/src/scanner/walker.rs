use crate::rules::schema::CompiledRule;
use crate::scanner::iac::{scan_iac, IacFormat};
use crate::scanner::manifest::{scan_manifest, ManifestFormat};
use crate::scanner::source::{is_supported_source_file, scan_source_code};
use crate::scanner::{Finding, ScanReport, ScanSummary};
use ignore::WalkBuilder;
use rayon::prelude::*;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use thiserror::Error;

/// Skip files larger than 2 MiB to prevent minified JS bundles or lockfile blobs
/// from stalling regex engines during CI runs.
const MAX_SCANNABLE_FILE_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("scan target path does not exist: '{0}'")]
    TargetNotFound(String),
    #[error("failed to traverse target directory: {0}")]
    WalkError(#[from] ignore::Error),
}

pub fn scan_path(root: &Path, rules: &[CompiledRule]) -> Result<ScanReport, ScanError> {
    if !root.exists() {
        return Err(ScanError::TargetNotFound(root.display().to_string()));
    }

    let start = Instant::now();
    let canonical_root = root.canonicalize().unwrap_or_else(|_| root.to_path_buf());

    let candidate_files = collect_candidate_files(&canonical_root)?;
    let files_scanned = candidate_files.len();

    let mut findings: Vec<Finding> = candidate_files
        .par_iter()
        .flat_map(|abs_path| scan_single_file(&canonical_root, abs_path, rules))
        .collect();

    // Deterministic ordering: highest severity first, then file path, then line number
    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.file_path.cmp(&b.file_path))
            .then_with(|| a.line.cmp(&b.line))
            .then_with(|| a.rule_id.cmp(&b.rule_id))
    });

    let summary = ScanSummary::from_findings(&findings, files_scanned, start.elapsed());

    Ok(ScanReport {
        engine_version: crate::ENGINE_VERSION.to_string(),
        target_path: root.display().to_string(),
        summary,
        findings,
    })
}

fn collect_candidate_files(root: &Path) -> Result<Vec<PathBuf>, ScanError> {
    if root.is_file() {
        return Ok(vec![root.to_path_buf()]);
    }

    let mut files = Vec::new();
    let walker = WalkBuilder::new(root)
        .hidden(false)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .filter_entry(|entry| {
            let name = entry.file_name().to_string_lossy();
            !matches!(
                name.as_ref(),
                ".git" | "node_modules" | "target" | ".venv" | "venv" | "__pycache__" | ".next"
            )
        })
        .build();

    for result in walker {
        let entry = result?;
        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            continue;
        }

        let path = entry.path();
        if is_lockfile_or_minified(path) {
            continue;
        }

        if ManifestFormat::from_path(path).is_some()
            || IacFormat::from_path(path).is_some()
            || is_supported_source_file(path)
        {
            if let Ok(meta) = entry.metadata() {
                if meta.len() <= MAX_SCANNABLE_FILE_BYTES {
                    files.push(path.to_path_buf());
                }
            }
        }
    }

    Ok(files)
}

fn is_lockfile_or_minified(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "package-lock.json"
            | "yarn.lock"
            | "pnpm-lock.yaml"
            | "cargo.lock"
            | "poetry.lock"
            | "go.sum"
    ) || lower.ends_with(".min.js")
        || lower.ends_with(".min.css")
}

fn scan_single_file(root: &Path, abs_path: &Path, rules: &[CompiledRule]) -> Vec<Finding> {
    let Ok(bytes) = fs::read(abs_path) else {
        return Vec::new();
    };
    // Skip binary files containing NUL bytes
    if bytes.contains(&0) {
        return Vec::new();
    }
    let Ok(content) = String::from_utf8(bytes) else {
        return Vec::new();
    };

    let rel_path = if root.is_file() {
        abs_path
            .file_name()
            .map(PathBuf::from)
            .unwrap_or_else(|| abs_path.to_path_buf())
    } else {
        abs_path
            .strip_prefix(root)
            .unwrap_or(abs_path)
            .to_path_buf()
    };

    if let Some(fmt) = ManifestFormat::from_path(abs_path) {
        return scan_manifest(&rel_path, &content, fmt, rules);
    }

    if let Some(fmt) = IacFormat::from_path(abs_path) {
        return scan_iac(&rel_path, &content, fmt, rules);
    }

    if is_supported_source_file(abs_path) {
        return scan_source_code(&rel_path, &content, rules);
    }

    Vec::new()
}

impl ScanSummary {
    pub fn from_findings(
        findings: &[Finding],
        files_scanned: usize,
        elapsed: std::time::Duration,
    ) -> Self {
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;
        let mut providers = BTreeSet::new();

        for f in findings {
            match f.severity {
                crate::rules::Severity::Critical => critical += 1,
                crate::rules::Severity::High => high += 1,
                crate::rules::Severity::Medium => medium += 1,
                crate::rules::Severity::Low => low += 1,
            }
            providers.insert(f.provider.clone());
        }

        Self {
            files_scanned,
            total_findings: findings.len(),
            critical,
            high,
            medium,
            low,
            unique_subprocessors: providers.into_iter().collect(),
            duration_ms: elapsed.as_millis() as u64,
        }
    }
}
