use std::path::{Path, PathBuf};

use ignore::{DirEntry, WalkBuilder};
use miette::{Diagnostic, Report};
use rayon::prelude::*;
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::parse_sfc;
use crate::parser::template::TemplateError;
use crate::rules::{Category, RuleRegistry};
use crate::severity::Severity;
use crate::suppression::violation_is_ignored;

#[derive(Error, Diagnostic, Debug)]
#[error("Could not read file `{path}`")]
#[diagnostic(code(vuer::file_read_error))]
pub struct FileReadError {
  path: String,
  #[diagnostic(help("Check that the file exists and you have read permissions."))]
  pub source: std::io::Error,
}

/// One file whose `<template>` block did not parse cleanly. A parse
/// failure degrades the file to "needs review" — findings computed on a
/// partial tree may be incomplete, so the CLI warns instead of letting
/// the file look clean.
#[derive(Debug)]
pub struct ParseIssue {
  pub file: PathBuf,
  pub errors: Vec<TemplateError>,
}

/// The result of scanning one path (file or directory).
#[derive(Debug)]
pub struct ScanReport {
  pub violations: Vec<Violation>,
  /// Files with non-empty `ScanContext::template_errors`.
  pub parse_issues: Vec<ParseIssue>,
}

#[derive(Debug)]
pub struct Violation {
  pub file: PathBuf,
  // The `Send + Sync` bound lets the scanner parallelise file scans
  // across rayon workers: every rule's diagnostic struct is plain data
  // (it only borrows from the rule's `Allocator` for the lifetime of
  // the `scan_file` call, which is `'static` by construction).
  pub diagnostic: Box<dyn Diagnostic + Send + Sync>,
  pub rule_name: String,
  /// Stable rule id (e.g. `vue/security/no-v-html`). Used for SARIF and JSON
  /// output; `rule_name` is the short name kept for the legacy CLI flag.
  pub rule_id: String,
  pub severity: Severity,
  pub category: Category,
  pub span_offset: usize,
  pub span_length: usize,
  /// True when the violation sits under a `// vuer-ignore[...]` (or HTML
  /// equivalent) comment and `--no-ignores` is not set.
  pub ignored: bool,
  /// Taint flow paths reaching this finding, when the rule ran taint
  /// analysis.
  pub flow: Option<Vec<crate::taint::FlowPath>>,
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

/// Knobs that change how a scan interprets the input. The fields are passed
/// through from the CLI; they let us add behaviour without expanding every
/// `scan_*` signature forever.
#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
  /// When true, treat every inline `vuer-ignore` comment as a no-op. Useful
  /// for "what would the linter say without any suppression?" runs in CI.
  pub no_ignores: bool,
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

  pub fn scan_path(
    &self,
    path: &Path,
    enabled_rules: &[String],
    options: &ScanOptions,
  ) -> Result<ScanReport, Report> {
    if path.is_file() {
      return self.scan_file(path, enabled_rules, options);
    }

    // Walk the directory tree first (single-threaded, but cheap — ignore is
    // just path walking + gitignore checks), then fan out the actual
    // parsing across rayon workers. This keeps thread-pool pressure low
    // for shallow trees and gives N-core speedup for big monorepos.
    let walker = WalkBuilder::new(path)
      .hidden(false)
      .git_ignore(true)
      .build();

    let entries: Vec<DirEntry> = walker
      .filter_map(Result::ok)
      .filter(|e| e.file_type().is_some_and(|ft| ft.is_file()))
      .filter(|e| e.path().extension().and_then(|ext| ext.to_str()) == Some("vue"))
      .collect();

    let per_file: Vec<Result<ScanReport, Report>> = entries
      .par_iter()
      .map(|entry| self.scan_file(entry.path(), enabled_rules, options))
      .collect();

    let mut report = ScanReport {
      violations: Vec::new(),
      parse_issues: Vec::new(),
    };
    for result in per_file {
      let scanned = result?;
      report.violations.extend(scanned.violations);
      report.parse_issues.extend(scanned.parse_issues);
    }
    Ok(report)
  }

  pub fn scan_file(
    &self,
    path: &Path,
    enabled_rules: &[String],
    options: &ScanOptions,
  ) -> Result<ScanReport, Report> {
    let source = std::fs::read_to_string(path).map_err(|e| FileReadError {
      path: path.display().to_string(),
      source: e,
    })?;

    let mut ctx = ScanContext::new(path.to_path_buf(), source);
    parse_sfc(&mut ctx);

    let rules = self.registry.get_enabled(enabled_rules);
    let mut violations = Vec::new();

    for rule in &rules {
      for finding in rule.check(&ctx) {
        let (offset, length) = primary_span(finding.diagnostic.as_ref());
        let rule_name = rule.name().to_string();
        let rule_id = rule.id().as_str().to_string();
        let ignored =
          !options.no_ignores && violation_is_ignored(&ctx.source, offset, &rule_name, &rule_id);
        violations.push(Violation {
          file: path.to_path_buf(),
          diagnostic: finding.diagnostic,
          rule_name,
          rule_id,
          severity: rule.severity(),
          category: rule.category(),
          span_offset: offset,
          span_length: length,
          ignored,
          flow: finding.flow,
        });
      }
    }

    let parse_issues = if ctx.template_errors.is_empty() {
      Vec::new()
    } else {
      vec![ParseIssue {
        file: path.to_path_buf(),
        errors: ctx.template_errors,
      }]
    };

    Ok(ScanReport {
      violations,
      parse_issues,
    })
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

fn primary_span(d: &(dyn Diagnostic + Send + Sync)) -> (usize, usize) {
  let Some(labels) = d.labels() else {
    return (0, 0);
  };
  for label in labels {
    let span = label.inner();
    if span.offset() == 0 && span.is_empty() {
      continue;
    }
    return (span.offset(), span.len());
  }
  (0, 0)
}
