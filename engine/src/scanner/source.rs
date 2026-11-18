use crate::rules::schema::{CompiledRule, ScanTarget};
use crate::scanner::Finding;
use regex::Regex;
use std::collections::HashSet;
use std::path::Path;
use std::sync::OnceLock;

const SUPPORTED_SOURCE_EXTENSIONS: &[&str] = &[
    "py", "js", "jsx", "ts", "tsx", "mjs", "cjs", "rs", "go", "java", "kt", "rb", "php", "cs",
    "swift", "scala", "html", "vue", "svelte", "astro", "sh",
];

pub fn is_supported_source_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| {
            SUPPORTED_SOURCE_EXTENSIONS
                .iter()
                .any(|supported| ext.eq_ignore_ascii_case(supported))
        })
}

/// Extracts imported module/package names from Python, JS/TS, Go, and Rust import statements
/// so SDK usage is caught even before an external HTTP endpoint is explicitly constructed.
fn extract_line_imports(line: &str) -> Vec<String> {
    static PY_IMPORT_RE: OnceLock<Regex> = OnceLock::new();
    static JS_IMPORT_RE: OnceLock<Regex> = OnceLock::new();
    static RUST_USE_RE: OnceLock<Regex> = OnceLock::new();

    let py_re = PY_IMPORT_RE.get_or_init(|| {
        Regex::new(r"^\s*(?:from|import)\s+([a-zA-Z0-9_.-]+)").expect("valid python import regex")
    });
    let js_re = JS_IMPORT_RE.get_or_init(|| {
        Regex::new(r#"(?:import\s+.*?\s+from\s+|require\s*\(\s*)["'](@?[a-zA-Z0-9_./-]+)["']"#)
            .expect("valid js import regex")
    });
    let rust_re = RUST_USE_RE
        .get_or_init(|| Regex::new(r"^\s*use\s+([a-zA-Z0-9_]+)::").expect("valid rust use regex"));

    let mut modules = Vec::new();

    if let Some(caps) = py_re.captures(line) {
        if let Some(m) = caps.get(1) {
            let root = m.as_str().split('.').next().unwrap_or(m.as_str());
            modules.push(root.to_string());
        }
    }

    for caps in js_re.captures_iter(line) {
        if let Some(m) = caps.get(1) {
            let spec = m.as_str();
            if !spec.starts_with('.') && !spec.starts_with('/') {
                let pkg = if spec.starts_with('@') {
                    spec.split('/').take(2).collect::<Vec<_>>().join("/")
                } else {
                    spec.split('/').next().unwrap_or(spec).to_string()
                };
                modules.push(pkg);
            }
        }
    }

    if let Some(caps) = rust_re.captures(line) {
        if let Some(m) = caps.get(1) {
            let crate_name = m.as_str().replace('_', "-");
            modules.push(crate_name);
        }
    }

    modules
}

pub fn scan_source_code(rel_path: &Path, content: &str, rules: &[CompiledRule]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut emitted = HashSet::new();

    for (idx, raw_line) in content.lines().enumerate() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("//")
            || trimmed.starts_with('#')
            || trimmed.starts_with("/*")
            || trimmed.starts_with('*')
        {
            continue;
        }

        let line_num = idx + 1;
        let imports = extract_line_imports(trimmed);
        let lower_line = raw_line.to_ascii_lowercase();

        for compiled in rules {
            if !compiled.rule.targets.contains(&ScanTarget::SourceCode) {
                continue;
            }

            let mut matched_indicator: Option<String> = None;

            // 1. Check regex patterns (endpoints, region literals, tracking IDs)
            for regex in &compiled.compiled_patterns {
                if let Some(mat) = regex.find(raw_line) {
                    matched_indicator = Some(mat.as_str().to_string());
                    break;
                }
            }

            // 2. Check hardcoded sub-processor domains
            if matched_indicator.is_none() {
                for domain in &compiled.rule.matchers.domains {
                    if lower_line.contains(&domain.to_ascii_lowercase()) {
                        matched_indicator = Some(domain.clone());
                        break;
                    }
                }
            }

            // 3. Check direct SDK imports against rule package list
            if matched_indicator.is_none() && !imports.is_empty() {
                for imported in &imports {
                    let norm_imported = imported.to_ascii_lowercase().replace('_', "-");
                    if compiled
                        .rule
                        .matchers
                        .packages
                        .iter()
                        .any(|p| p.to_ascii_lowercase().replace('_', "-") == norm_imported)
                    {
                        matched_indicator = Some(format!("import:{imported}"));
                        break;
                    }
                }
            }

            if let Some(indicator) = matched_indicator {
                if emitted.insert((compiled.rule.id.clone(), line_num)) {
                    findings.push(Finding {
                        rule_id: compiled.rule.id.clone(),
                        title: compiled.rule.title.clone(),
                        provider: compiled.rule.provider.clone(),
                        category: compiled.rule.category,
                        severity: compiled.rule.severity,
                        jurisdiction: compiled.rule.jurisdiction,
                        target: ScanTarget::SourceCode,
                        file_path: rel_path.to_string_lossy().into_owned(),
                        line: line_num,
                        snippet: truncate_snippet(trimmed, 220),
                        matched_indicator: indicator,
                        legal_references: compiled.rule.legal_references.clone(),
                        description: compiled.rule.description.clone(),
                        remediation: compiled.rule.remediation.clone(),
                    });
                }
            }
        }
    }

    findings
}

fn truncate_snippet(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max_chars).collect();
        format!("{truncated}...")
    }
}