use crate::rules::schema::{CompiledRule, ScanTarget};
use crate::scanner::Finding;
use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IacFormat {
    Terraform,
    DockerCompose,
    Dockerfile,
    KubernetesOrYaml,
    EnvConfig,
}

impl IacFormat {
    pub fn from_path(path: &Path) -> Option<Self> {
        let name = path.file_name()?.to_str()?;
        let lower_name = name.to_ascii_lowercase();

        if lower_name.ends_with(".tf") || lower_name.ends_with(".tfvars") {
            return Some(Self::Terraform);
        }
        if lower_name == "dockerfile" || lower_name.starts_with("dockerfile.") {
            return Some(Self::Dockerfile);
        }
        if lower_name.starts_with("docker-compose")
            && (lower_name.ends_with(".yml") || lower_name.ends_with(".yaml"))
        {
            return Some(Self::DockerCompose);
        }
        if lower_name == ".env.example"
            || lower_name == ".env.template"
            || lower_name == "vercel.json"
        {
            return Some(Self::EnvConfig);
        }
        if lower_name.ends_with(".yaml") || lower_name.ends_with(".yml") {
            return Some(Self::KubernetesOrYaml);
        }
        None
    }
}

pub fn scan_iac(
    rel_path: &Path,
    content: &str,
    format: IacFormat,
    rules: &[CompiledRule],
) -> Vec<Finding> {
    // Only inspect generic YAML files if they look like Kubernetes manifests, Helm values,
    // or infrastructure configs to prevent false positives on unrelated YAML documents.
    if format == IacFormat::KubernetesOrYaml && !looks_like_infra_yaml(rel_path, content) {
        return Vec::new();
    }

    let mut findings = Vec::new();
    let mut emitted = HashSet::new();

    for (idx, raw_line) in content.lines().enumerate() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || is_comment_line(trimmed, format) {
            continue;
        }

        let line_num = idx + 1;

        for compiled in rules {
            if !compiled.rule.targets.contains(&ScanTarget::Iac) {
                continue;
            }

            let mut matched_indicator: Option<String> = None;

            for regex in &compiled.compiled_patterns {
                if let Some(mat) = regex.find(raw_line) {
                    matched_indicator = Some(mat.as_str().to_string());
                    break;
                }
            }

            if matched_indicator.is_none() {
                for domain in &compiled.rule.matchers.domains {
                    if raw_line.to_ascii_lowercase().contains(&domain.to_ascii_lowercase()) {
                        matched_indicator = Some(domain.clone());
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
                        target: ScanTarget::Iac,
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

fn looks_like_infra_yaml(path: &Path, content: &str) -> bool {
    let path_str = path.to_string_lossy().to_ascii_lowercase();
    if path_str.contains("k8s")
        || path_str.contains("kube")
        || path_str.contains("helm")
        || path_str.contains("deploy")
        || path_str.contains("infra")
        || path_str.contains("terraform")
        || path_str.contains("ansible")
    {
        return true;
    }

    content.contains("apiVersion:")
        || content.contains("kind:")
        || content.contains("AWS_REGION")
        || content.contains("AWS_DEFAULT_REGION")
        || content.contains("CLOUDSDK_COMPUTE_REGION")
        || content.contains("AZURE_REGION")
}

fn is_comment_line(trimmed: &str, format: IacFormat) -> bool {
    match format {
        IacFormat::Terraform => {
            trimmed.starts_with('#') || trimmed.starts_with("//") || trimmed.starts_with("/*")
        }
        IacFormat::DockerCompose
        | IacFormat::Dockerfile
        | IacFormat::KubernetesOrYaml
        | IacFormat::EnvConfig => trimmed.starts_with('#'),
    }
}

fn truncate_snippet(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max_chars).collect();
        format!("{truncated}...")
    }
}