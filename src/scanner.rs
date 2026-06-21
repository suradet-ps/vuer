use std::path::{Path, PathBuf};

use ignore::WalkBuilder;
use miette::{Diagnostic, IntoDiagnostic, Report};
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::parse_sfc;
use crate::rules::{Category, RuleRegistry};
use crate::severity::Severity;

#[derive(Error, Diagnostic, Debug)]
#[error("Could not read file `{path}`")]
#[diagnostic(code(vuer::file_read_error))]
pub struct FileReadError {
  path: String,
  #[diagnostic(help("Check that the file exists and you have read permissions."))]
  pub source: std::io::Error,
}

#[derive(Debug)]
pub struct Violation {
  pub file: PathBuf,
  pub diagnostic: Box<dyn Diagnostic>,
  pub rule_name: String,
  /// Stable rule id (e.g. `vue/security/no-v-html`). Used for SARIF and JSON
  /// output; `rule_name` is the short name kept for the legacy CLI flag.
  pub rule_id: String,
  pub severity: Severity,
  pub category: Category,
  pub span_offset: usize,
  pub span_length: usize,
}

impl Violation {
  /// Read the diagnostic's primary label and produce `(start, length)`. This
  /// is the same offset the SARIF report uses, so JSON, SARIF, and pretty
  /// output all line up.
  pub fn span_offset(&self) -> usize {
    self.span_offset
  }

  pub fn span_len(&self) -> usize {
    self.span_length
  }

  pub fn diagnostic_message(&self) -> String {
    self.diagnostic.to_string()
  }
}

pub struct Scanner {
  registry: RuleRegistry,
}

impl Scanner {
  pub fn new() -> Self {
    Self {
      registry: RuleRegistry::new(),
    }
  }

  pub fn scan_path(&self, path: &Path, enabled_rules: &[String]) -> Result<Vec<Violation>, Report> {
    if path.is_file() {
      return self.scan_file(path, enabled_rules);
    }

    let mut violations = Vec::new();
    let walker = WalkBuilder::new(path)
      .hidden(false)
      .git_ignore(true)
      .build();

    for entry in walker {
      let entry = entry.into_diagnostic()?;
      if entry.file_type().is_some_and(|ft| ft.is_file())
        && entry.path().extension().and_then(|e| e.to_str()) == Some("vue")
      {
        let file_violations = self.scan_file(entry.path(), enabled_rules)?;
        violations.extend(file_violations);
      }
    }

    Ok(violations)
  }

  pub fn scan_file(&self, path: &Path, enabled_rules: &[String]) -> Result<Vec<Violation>, Report> {
    let source = std::fs::read_to_string(path).map_err(|e| FileReadError {
      path: path.display().to_string(),
      source: e,
    })?;

    let mut ctx = ScanContext::new(path.to_path_buf(), source);
    parse_sfc(&mut ctx);

    let rules = self.registry.get_enabled(enabled_rules);
    let mut violations = Vec::new();

    for rule in &rules {
      for diagnostic in rule.check(&ctx) {
        let (offset, length) = primary_span(diagnostic.as_ref());
        violations.push(Violation {
          file: path.to_path_buf(),
          diagnostic,
          rule_name: rule.name().to_string(),
          rule_id: rule.id().as_str().to_string(),
          severity: rule.severity(),
          category: rule.category(),
          span_offset: offset,
          span_length: length,
        });
      }
    }

    Ok(violations)
  }

  pub fn registry(&self) -> &RuleRegistry {
    &self.registry
  }
}

impl Default for Scanner {
  fn default() -> Self {
    Self::new()
  }
}

fn primary_span(d: &dyn Diagnostic) -> (usize, usize) {
  let Some(labels) = d.labels() else {
    return (0, 0);
  };
  for label in labels {
    let span = label.inner();
    if span.offset() == 0 && span.len() == 0 {
      continue;
    }
    return (span.offset(), span.len());
  }
  (0, 0)
}
