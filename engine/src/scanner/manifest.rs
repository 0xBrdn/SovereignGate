use crate::rules::schema::{
    CompiledRule, Jurisdiction, LegalReference, ProviderCategory, ScanTarget, Severity,
};
use crate::scanner::Finding;
use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestFormat {
    PackageJson,
    RequirementsTxt,
    PyprojectToml,
    CargoToml,
    GoMod,
}

impl ManifestFormat {
    pub fn from_path(path: &Path) -> Option<Self> {
        let name = path.file_name()?.to_str()?;
        match name {
            "package.json" => Some(Self::PackageJson),
            "pyproject.toml" => Some(Self::PyprojectToml),
            "Cargo.toml" => Some(Self::CargoToml),
            "go.mod" => Some(Self::GoMod),
            n if n == "requirements.txt"
                || (n.starts_with("requirements") && n.ends_with(".txt")) =>
            {
                Some(Self::RequirementsTxt)
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
struct ExtractedDependency {
    name: String,
    line: usize,
    snippet: String,
}

pub fn scan_manifest(
    rel_path: &Path,
    content: &str,
    format: ManifestFormat,
    rules: &[CompiledRule],
) -> Vec<Finding> {
    let deps = match format {
        ManifestFormat::PackageJson => parse_package_json(content),
        ManifestFormat::RequirementsTxt => parse_requirements_txt(content),
        ManifestFormat::PyprojectToml => parse_pyproject_toml(content),
        ManifestFormat::CargoToml => parse_cargo_toml(content),
        ManifestFormat::GoMod => parse_go_mod(content),
    };

    if deps.is_empty() {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let mut emitted = HashSet::new();

    for compiled in rules {
        if !compiled.rule.targets.contains(&ScanTarget::Manifest)
            || compiled.rule.matchers.packages.is_empty()
        {
            continue;
        }

        for dep in &deps {
            let matched = compiled
                .rule
                .matchers
                .packages
                .iter()
                .any(|pkg| normalize_pkg_name(pkg) == normalize_pkg_name(&dep.name));

            if matched && emitted.insert((compiled.rule.id.clone(), dep.line)) {
                findings.push(Finding {
                    rule_id: compiled.rule.id.clone(),
                    title: compiled.rule.title.clone(),
                    provider: compiled.rule.provider.clone(),
                    category: compiled.rule.category,
                    severity: compiled.rule.severity,
                    jurisdiction: compiled.rule.jurisdiction,
                    target: ScanTarget::Manifest,
                    file_path: rel_path.to_string_lossy().into_owned(),
                    line: dep.line,
                    snippet: dep.snippet.clone(),
                    matched_indicator: dep.name.clone(),
                    legal_references: compiled.rule.legal_references.clone(),
                    description: compiled.rule.description.clone(),
                    remediation: compiled.rule.remediation.clone(),
                });
            }
        }
    }

    findings
}

fn normalize_pkg_name(name: &str) -> String {
    // PEP 503 normalizes underscores, dots, and hyphens equivalently for Python packages,
    // while keeping scoped npm packages (@org/pkg) intact.
    if name.starts_with('@') {
        name.trim().to_ascii_lowercase()
    } else {
        name.trim().to_ascii_lowercase().replace(['_', '.'], "-")
    }
}

fn find_line_for_token(lines: &[&str], token: &str) -> (usize, String) {
    for (idx, line) in lines.iter().enumerate() {
        if line.contains(token) {
            return (idx + 1, line.trim().to_string());
        }
    }
    (1, token.to_string())
}

fn parse_package_json(content: &str) -> Vec<ExtractedDependency> {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(content) else {
        return Vec::new();
    };
    let lines: Vec<&str> = content.lines().collect();
    let sections = [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ];

    let mut deps = Vec::new();
    for section in sections {
        if let Some(obj) = val.get(section).and_then(|v| v.as_object()) {
            for key in obj.keys() {
                let needle = format!("\"{key}\"");
                let (line, snippet) = find_line_for_token(&lines, &needle);
                deps.push(ExtractedDependency {
                    name: key.clone(),
                    line,
                    snippet,
                });
            }
        }
    }
    deps
}

fn parse_requirements_txt(content: &str) -> Vec<ExtractedDependency> {
    let mut deps = Vec::new();
    for (idx, raw_line) in content.lines().enumerate() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed.starts_with('-')
            || trimmed.starts_with("git+")
            || trimmed.starts_with("http://")
            || trimmed.starts_with("https://")
        {
            continue;
        }

        // Strip inline comments and environment markers (; python_version < "3.12")
        let no_comment = trimmed.split('#').next().unwrap_or("").trim();
        let no_marker = no_comment.split(';').next().unwrap_or("").trim();

        // Extract distribution name before version specifiers or extras (e.g., sentry-sdk[fastapi]>=2.0)
        let pkg = no_marker
            .split(['=', '<', '>', '!', '~', '[', '@', ' '])
            .next()
            .unwrap_or("")
            .trim();

        if !pkg.is_empty() {
            deps.push(ExtractedDependency {
                name: pkg.to_string(),
                line: idx + 1,
                snippet: trimmed.to_string(),
            });
        }
    }
    deps
}

fn parse_pyproject_toml(content: &str) -> Vec<ExtractedDependency> {
    let Ok(val) = content.parse::<toml::Table>() else {
        return Vec::new();
    };
    let lines: Vec<&str> = content.lines().collect();
    let mut deps = Vec::new();

    // PEP 621 [project.dependencies] & [project.optional-dependencies]
    if let Some(project) = val.get("project").and_then(|v| v.as_table()) {
        if let Some(arr) = project.get("dependencies").and_then(|v| v.as_array()) {
            for item in arr {
                if let Some(spec) = item.as_str() {
                    if let Some(name) = extract_pep508_name(spec) {
                        let (line, snippet) = find_line_for_token(&lines, &name);
                        deps.push(ExtractedDependency {
                            name,
                            line,
                            snippet,
                        });
                    }
                }
            }
        }
        if let Some(opt_table) = project
            .get("optional-dependencies")
            .and_then(|v| v.as_table())
        {
            for group in opt_table.values() {
                if let Some(arr) = group.as_array() {
                    for item in arr {
                        if let Some(spec) = item.as_str() {
                            if let Some(name) = extract_pep508_name(spec) {
                                let (line, snippet) = find_line_for_token(&lines, &name);
                                deps.push(ExtractedDependency {
                                    name,
                                    line,
                                    snippet,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // Poetry [tool.poetry.dependencies] & [tool.poetry.group.*.dependencies]
    if let Some(poetry) = val
        .get("tool")
        .and_then(|v| v.as_table())
        .and_then(|t| t.get("poetry"))
        .and_then(|v| v.as_table())
    {
        if let Some(p_deps) = poetry.get("dependencies").and_then(|v| v.as_table()) {
            for key in p_deps.keys() {
                if key != "python" {
                    let (line, snippet) = find_line_for_token(&lines, key);
                    deps.push(ExtractedDependency {
                        name: key.clone(),
                        line,
                        snippet,
                    });
                }
            }
        }
        if let Some(groups) = poetry.get("group").and_then(|v| v.as_table()) {
            for group in groups.values() {
                if let Some(g_deps) = group
                    .as_table()
                    .and_then(|g| g.get("dependencies"))
                    .and_then(|v| v.as_table())
                {
                    for key in g_deps.keys() {
                        let (line, snippet) = find_line_for_token(&lines, key);
                        deps.push(ExtractedDependency {
                            name: key.clone(),
                            line,
                            snippet,
                        });
                    }
                }
            }
        }
    }

    deps
}

fn extract_pep508_name(spec: &str) -> Option<String> {
    let name = spec
        .trim()
        .split(['=', '<', '>', '!', '~', '[', ';', '@', ' '])
        .next()?
        .trim();
    if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    }
}

fn parse_cargo_toml(content: &str) -> Vec<ExtractedDependency> {
    let Ok(val) = content.parse::<toml::Table>() else {
        return Vec::new();
    };
    let lines: Vec<&str> = content.lines().collect();
    let mut deps = Vec::new();

    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(table) = val.get(section).and_then(|v| v.as_table()) {
            for key in table.keys() {
                let (line, snippet) = find_line_for_token(&lines, key);
                deps.push(ExtractedDependency {
                    name: key.clone(),
                    line,
                    snippet,
                });
            }
        }
    }
    deps
}

fn parse_go_mod(content: &str) -> Vec<ExtractedDependency> {
    let mut deps = Vec::new();
    let mut in_require_block = false;

    for (idx, raw_line) in content.lines().enumerate() {
        let line = raw_line.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("require (") || line == "require(" {
            in_require_block = true;
            continue;
        }
        if in_require_block && line == ")" {
            in_require_block = false;
            continue;
        }

        let module_path = if in_require_block {
            line.split_whitespace().next()
        } else if let Some(rest) = line.strip_prefix("require ") {
            rest.split_whitespace().next()
        } else {
            None
        };

        if let Some(mod_path) = module_path {
            // Match both full module path and final package segment (e.g. github.com/stripe/stripe-go/v79 -> stripe-go)
            let short_name = mod_path
                .split('/')
                .rfind(|seg| !seg.starts_with('v') || seg.len() > 4)
                .unwrap_or(mod_path);

            deps.push(ExtractedDependency {
                name: short_name.to_string(),
                line: idx + 1,
                snippet: raw_line.trim().to_string(),
            });
        }
    }

    deps
}

#[allow(dead_code)]
fn _keep_imports_used(_: (Jurisdiction, LegalReference, ProviderCategory, Severity)) {}
