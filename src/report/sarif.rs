//! SARIF (Static Analysis Results Interchange Format) output.
//!
//! SARIF is a JSON-based format defined by OASIS. It is what GitHub Code
//! Scanning, GitLab, Azure DevOps, and most other CI/CD security dashboards
//! consume.
//!
//! We implement the SARIF 2.1.0 schema directly with `serde` rather than
//! pulling in a dedicated crate, because:
//!
//! 1. The schema is large and SARIF-supporting crates tend to be either
//!    out-of-date or only partially implemented.
//! 2. We only need a tiny slice of the schema: one `run` with results and
//!    a rules table. Adding the rest of the schema would just be dead code.
//! 3. Hand-written types keep the output verifiable: you can read this
//!    module and see exactly what bytes hit the wire.
//!
//! Reference: <https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html>

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::rule_id::RuleId;
use crate::scanner::Violation;
use crate::severity::Severity;

#[derive(Debug, Serialize)]
pub struct SarifLog {
  #[serde(rename = "$schema")]
  pub schema: &'static str,
  pub version: &'static str,
  pub runs: Vec<SarifRun>,
}

#[derive(Debug, Serialize)]
pub struct SarifRun {
  pub tool: SarifTool,
  pub results: Vec<SarifResult>,
}

#[derive(Debug, Serialize)]
pub struct SarifTool {
  pub driver: SarifDriver,
}

#[derive(Debug, Serialize)]
pub struct SarifDriver {
  pub name: &'static str,
  pub information_uri: &'static str,
  pub version: &'static str,
  pub rules: Vec<SarifRule>,
}

#[derive(Debug, Serialize)]
pub struct SarifRule {
  pub id: String,
  pub name: String,
  pub short_description: SarifMessage,
  pub full_description: SarifMessage,
  pub help: SarifMessage,
  pub default_configuration: SarifConfiguration,
  pub properties: SarifRuleProperties,
}

#[derive(Debug, Serialize)]
pub struct SarifMessage {
  pub text: String,
}

#[derive(Debug, Serialize)]
pub struct SarifConfiguration {
  pub level: &'static str,
}

#[derive(Debug, Serialize)]
pub struct SarifRuleProperties {
  pub category: &'static str,
  pub security_severity: &'static str,
}

#[derive(Debug, Serialize)]
pub struct SarifResult {
  #[serde(rename = "ruleId")]
  pub rule_id: String,
  #[serde(rename = "ruleIndex")]
  pub rule_index: usize,
  pub level: &'static str,
  pub message: SarifMessage,
  pub locations: Vec<SarifLocation>,
}

#[derive(Debug, Serialize)]
pub struct SarifLocation {
  #[serde(rename = "physicalLocation")]
  pub physical_location: SarifPhysicalLocation,
}

#[derive(Debug, Serialize)]
pub struct SarifPhysicalLocation {
  #[serde(rename = "artifactLocation")]
  pub artifact_location: SarifArtifactLocation,
  pub region: SarifRegion,
}

#[derive(Debug, Serialize)]
pub struct SarifArtifactLocation {
  pub uri: String,
  #[serde(rename = "uriBaseId", skip_serializing_if = "Option::is_none")]
  pub uri_base_id: Option<&'static str>,
}

#[derive(Debug, Serialize)]
pub struct SarifRegion {
  #[serde(rename = "startLine")]
  pub start_line: u32,
  #[serde(rename = "startColumn", skip_serializing_if = "Option::is_none")]
  pub start_column: Option<u32>,
  #[serde(rename = "endLine", skip_serializing_if = "Option::is_none")]
  pub end_line: Option<u32>,
  #[serde(rename = "endColumn", skip_serializing_if = "Option::is_none")]
  pub end_column: Option<u32>,
  #[serde(rename = "byteOffset", skip_serializing_if = "Option::is_none")]
  pub byte_offset: Option<usize>,
  #[serde(rename = "byteLength", skip_serializing_if = "Option::is_none")]
  pub byte_length: Option<usize>,
}

/// Build a SARIF log from a slice of violations plus the rule registry. The
/// rules table is built up from the registry so every emitted result maps to
/// a declared rule.
///
/// `source_per_file` maps a file path to the source bytes for that file. The
/// line/column calculation needs the original source so that SARIF consumers
/// can render the right region.
pub fn build_sarif(
  violations: &[Violation],
  source_per_file: &BTreeMap<PathBuf, String>,
) -> SarifLog {
  // Collect the unique rules that appear in the violations. The registry
  // knows the metadata; the violations only know the rule id and the
  // diagnostic.
  let mut rule_indices: Vec<RuleId> = Vec::new();
  for v in violations {
    if !rule_indices.iter().any(|r| r.as_str() == v.rule_id) {
      rule_indices.push(RuleId::new(v.rule_id.clone()));
    }
  }
  // Also include every rule that the registry knows about, so the rules
  // table is stable even on a clean run.
  for rule_id in known_rule_ids() {
    if !rule_indices.iter().any(|r| r.as_str() == rule_id.as_str()) {
      rule_indices.push(rule_id);
    }
  }

  let mut rules: Vec<SarifRule> = Vec::new();
  for (idx, rule_id) in rule_indices.iter().enumerate() {
    rules.push(build_rule(rule_id, idx));
  }

  let results: Vec<SarifResult> = violations
    .iter()
    .map(|v| {
      let source = source_per_file
        .get(&v.file)
        .map(String::as_str)
        .unwrap_or("");
      build_result(v, &rule_indices, source)
    })
    .collect();

  SarifLog {
    schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: vec![SarifRun {
      tool: SarifTool {
        driver: SarifDriver {
          name: "vuer",
          information_uri: "https://github.com/suradet-ps/vuer",
          version: env!("CARGO_PKG_VERSION"),
          rules,
        },
      },
      results,
    }],
  }
}

fn build_rule(id: &RuleId, _idx: usize) -> SarifRule {
  let meta = rule_meta(id);
  SarifRule {
    id: id.as_str().to_string(),
    name: id.as_str().to_string(),
    short_description: SarifMessage {
      text: meta.short.to_string(),
    },
    full_description: SarifMessage {
      text: meta.full.to_string(),
    },
    help: SarifMessage {
      text: meta.help.to_string(),
    },
    default_configuration: SarifConfiguration {
      level: meta.severity.to_sarif_level(),
    },
    properties: SarifRuleProperties {
      category: meta.category,
      security_severity: meta.severity.as_str(),
    },
  }
}

fn build_result(v: &Violation, rule_indices: &[RuleId], source: &str) -> SarifResult {
  let rule_index = rule_indices
    .iter()
    .position(|r| r.as_str() == v.rule_id)
    .unwrap_or(0);
  let (start_line, start_column, end_line, end_column) =
    byte_offset_to_line_col(source, v.span_offset(), v.span_len());
  SarifResult {
    rule_id: v.rule_id.clone(),
    rule_index,
    level: v.severity.to_sarif_level(),
    message: SarifMessage {
      text: v.diagnostic_message(),
    },
    locations: vec![SarifLocation {
      physical_location: SarifPhysicalLocation {
        artifact_location: SarifArtifactLocation {
          uri: path_to_uri(&v.file),
          uri_base_id: Some("%SRCROOT%"),
        },
        region: SarifRegion {
          start_line,
          start_column,
          end_line,
          end_column,
          byte_offset: Some(v.span_offset()),
          byte_length: Some(v.span_len()),
        },
      },
    }],
  }
}

fn byte_offset_to_line_col(
  source: &str,
  offset: usize,
  length: usize,
) -> (u32, Option<u32>, Option<u32>, Option<u32>) {
  if source.is_empty() {
    return (1, None, None, None);
  }
  let offset = offset.min(source.len());
  let end = offset.saturating_add(length).min(source.len());

  let mut start_line: u32 = 1;
  let mut start_col: u32 = 1;
  for (i, ch) in source.char_indices() {
    if i >= offset {
      break;
    }
    if ch == '\n' {
      start_line += 1;
      start_col = 1;
    } else {
      start_col += 1;
    }
  }

  let mut end_line = start_line;
  let mut end_col = start_col;
  for (i, ch) in source[offset..end].char_indices() {
    if ch == '\n' {
      end_line += 1;
      end_col = 1;
    } else {
      end_col += 1;
    }
    let _ = i;
  }
  (start_line, Some(start_col), Some(end_line), Some(end_col))
}

fn path_to_uri(path: &Path) -> String {
  // SARIF URIs are absolute paths; we use the file:// scheme on Unix and
  // Windows-friendly paths otherwise.
  if let Some(s) = path.to_str() {
    if s.starts_with('/') {
      return format!("file://{s}");
    }
    return s.replace('\\', "/");
  }
  String::from("unknown")
}

struct RuleMeta {
  short: &'static str,
  full: &'static str,
  help: &'static str,
  severity: Severity,
  category: &'static str,
}

fn rule_meta(id: &RuleId) -> RuleMeta {
  match id.as_str() {
    "vue/security/no-v-html" => RuleMeta {
      short: "Disallow `v-html` directive",
      full: "Rendering untrusted HTML can execute arbitrary JavaScript.",
      help: "Sanitise with DOMPurify or use `v-text` / interpolation.",
      severity: Severity::Critical,
      category: "security",
    },
    "vue/security/no-inner-html" => RuleMeta {
      short: "Disallow `el.innerHTML = ...`",
      full: "Writing to `.innerHTML` lets attackers inject script tags.",
      help: "Use `textContent` for plain text or sanitise with DOMPurify.",
      severity: Severity::Critical,
      category: "security",
    },
    "vue/security/no-document-write" => RuleMeta {
      short: "Disallow `document.write`",
      full: "`document.write` is a known XSS sink.",
      help: "Use `appendChild` or update via Vue reactivity instead.",
      severity: Severity::High,
      category: "security",
    },
    "vue/security/no-eval" => RuleMeta {
      short: "Disallow `eval` / `new Function`",
      full: "Evaluating strings as code is RCE if any input is attacker-controlled.",
      help: "Refactor to a static expression or a lookup table.",
      severity: Severity::Critical,
      category: "security",
    },
    "vue/security/no-dangerous-url" => RuleMeta {
      short: "Disallow dangerous URL schemes",
      full: "`javascript:`, `data:text/html`, and `vbscript:` URLs execute code.",
      help: "Use `https?://` URLs or a router.",
      severity: Severity::Critical,
      category: "security",
    },
    "vue/security/no-open-redirect" => RuleMeta {
      short: "Disallow open redirect sinks",
      full: "Forwarding user-controlled data to `location.*` enables open-redirect attacks.",
      help: "Validate the URL against an allow-list of hostnames.",
      severity: Severity::High,
      category: "security",
    },
    "vue/security/no-unsafe-localstorage" => RuleMeta {
      short: "Disallow auth tokens in `localStorage`",
      full: "Tokens in `localStorage` are reachable by any injected script.",
      help: "Prefer an `HttpOnly; Secure` cookie set by the server.",
      severity: Severity::High,
      category: "security",
    },
    "vue/security/no-unsafe-iframe" => RuleMeta {
      short: "Disallow `<iframe>` without `sandbox`",
      full: "An `iframe` without `sandbox` inherits the embedding origin's capabilities.",
      help: "Add `sandbox=\"\"` (or an explicit allow-list).",
      severity: Severity::Medium,
      category: "security",
    },
    "vue/security/no-dynamic-bind-src" => RuleMeta {
      short: "Disallow dynamic `src` binding",
      full: "A dynamic `src` can load attacker-controlled resources.",
      help: "Validate and sanitise the URL against an allow-list.",
      severity: Severity::High,
      category: "security",
    },
    "vue/best-practice/no-inline-style" => RuleMeta {
      short: "Disallow inline `style`",
      full: "Inline styles bypass the cascade and are hard to maintain.",
      help: "Use a CSS class instead.",
      severity: Severity::Low,
      category: "best-practice",
    },
    "vue/best-practice/no-watch-with-callback" => RuleMeta {
      short: "Disallow `watch` with callback (memory leak risk)",
      full: "`watch(source, cb)` returns a stop handle that is easy to forget to call.",
      help: "Prefer `watchEffect` or stop the handle in `onScopeDispose`.",
      severity: Severity::Low,
      category: "best-practice",
    },
    "vue/best-practice/v-for-missing-key" => RuleMeta {
      short: "Require `:key` on `v-for`",
      full: "Without a stable `:key`, Vue falls back to index-based reconciliation.",
      help: "Add `:key=\"item.id\"`.",
      severity: Severity::Medium,
      category: "best-practice",
    },
    _ => RuleMeta {
      short: "Vuer rule",
      full: "No description available.",
      help: "Run `vuer --list` for details.",
      severity: Severity::Info,
      category: "best-practice",
    },
  }
}

fn known_rule_ids() -> Vec<RuleId> {
  vec![
    RuleId::new("vue/security/no-v-html"),
    RuleId::new("vue/security/no-inner-html"),
    RuleId::new("vue/security/no-document-write"),
    RuleId::new("vue/security/no-eval"),
    RuleId::new("vue/security/no-dangerous-url"),
    RuleId::new("vue/security/no-open-redirect"),
    RuleId::new("vue/security/no-unsafe-localstorage"),
    RuleId::new("vue/security/no-unsafe-iframe"),
    RuleId::new("vue/security/no-dynamic-bind-src"),
    RuleId::new("vue/best-practice/no-inline-style"),
    RuleId::new("vue/best-practice/no-watch-with-callback"),
    RuleId::new("vue/best-practice/v-for-missing-key"),
  ]
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn builds_empty_log() {
    let log = build_sarif(&[], &BTreeMap::new());
    let json = serde_json::to_string(&log).unwrap();
    assert!(json.contains("\"version\":\"2.1.0\""));
    assert!(json.contains("vuer"));
  }
}
