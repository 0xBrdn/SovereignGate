use crate::rules::schema::{CompiledRule, Rule, RuleSetFile};
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuleLoadError {
    #[error("failed to read rules directory or file at '{path}': {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to parse YAML rule file '{path}': {source}")]
    Yaml {
        path: String,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("invalid regex pattern '{pattern}' in rule '{rule_id}': {source}")]
    InvalidRegex {
        rule_id: String,
        pattern: String,
        #[source]
        source: regex::Error,
    },
    #[error("duplicate rule ID detected: '{0}'")]
    DuplicateRuleId(String),
    #[error("rule '{0}' defines no matchers (packages, domains, or regex_patterns)")]
    EmptyMatchers(String),
}

/// Embedded default threat intelligence database compiled directly into the CLI binary
/// so air-gapped CI runners execute identically without external rule fetches.
const EMBEDDED_RULE_FILES: &[(&str, &str)] = &[
    ("ai_ml.yaml", include_str!("../../rules/ai_ml.yaml")),
    (
        "cloud_regions.yaml",
        include_str!("../../rules/cloud_regions.yaml"),
    ),
    (
        "payments_comms.yaml",
        include_str!("../../rules/payments_comms.yaml"),
    ),
    (
        "telemetry_analytics.yaml",
        include_str!("../../rules/telemetry_analytics.yaml"),
    ),
];

pub fn load_embedded_rules() -> Result<Vec<CompiledRule>, RuleLoadError> {
    let mut raw_rules = Vec::new();
    for (name, content) in EMBEDDED_RULE_FILES {
        let parsed: RuleSetFile =
            serde_yaml::from_str(content).map_err(|source| RuleLoadError::Yaml {
                path: (*name).to_string(),
                source,
            })?;
        raw_rules.extend(parsed.rules);
    }
    compile_and_validate(raw_rules)
}

pub fn load_rules_from_dir(dir: &Path) -> Result<Vec<CompiledRule>, RuleLoadError> {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .map_err(|source| RuleLoadError::Io {
            path: dir.display().to_string(),
            source,
        })?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext| ext.eq_ignore_ascii_case("yaml") || ext.eq_ignore_ascii_case("yml"))
        })
        .collect();

    // Deterministic load order across operating systems
    entries.sort();

    let mut raw_rules = Vec::new();
    for path in entries {
        let content = fs::read_to_string(&path).map_err(|source| RuleLoadError::Io {
            path: path.display().to_string(),
            source,
        })?;
        let parsed: RuleSetFile =
            serde_yaml::from_str(&content).map_err(|source| RuleLoadError::Yaml {
                path: path.display().to_string(),
                source,
            })?;
        raw_rules.extend(parsed.rules);
    }

    compile_and_validate(raw_rules)
}

fn compile_and_validate(rules: Vec<Rule>) -> Result<Vec<CompiledRule>, RuleLoadError> {
    let mut seen_ids = HashSet::with_capacity(rules.len());
    let mut compiled = Vec::with_capacity(rules.len());

    for rule in rules {
        if !seen_ids.insert(rule.id.clone()) {
            return Err(RuleLoadError::DuplicateRuleId(rule.id));
        }

        if rule.matchers.packages.is_empty()
            && rule.matchers.domains.is_empty()
            && rule.matchers.regex_patterns.is_empty()
        {
            return Err(RuleLoadError::EmptyMatchers(rule.id));
        }

        let mut compiled_patterns = Vec::with_capacity(rule.matchers.regex_patterns.len());
        for pattern in &rule.matchers.regex_patterns {
            let regex = Regex::new(pattern).map_err(|source| RuleLoadError::InvalidRegex {
                rule_id: rule.id.clone(),
                pattern: pattern.clone(),
                source,
            })?;
            compiled_patterns.push(regex);
        }

        compiled.push(CompiledRule {
            rule,
            compiled_patterns,
        });
    }

    Ok(compiled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_rules_parse_and_compile_cleanly() {
        let rules = load_embedded_rules().expect("embedded YAML rules must compile cleanly");
        assert!(
            rules.len() >= 30,
            "expected at least 30 compliance rules, found {}",
            rules.len()
        );
    }
}