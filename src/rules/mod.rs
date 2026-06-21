use miette::Diagnostic;
use thiserror::Error;

use crate::context::ScanContext;
use crate::rule_id::RuleId;
use crate::severity::Severity;

pub mod no_dangerous_url;
pub mod no_document_write;
pub mod no_dynamic_bind;
pub mod no_eval;
pub mod no_inline_styles;
pub mod no_inner_html;
pub mod no_open_redirect;
pub mod no_unsafe_iframe;
pub mod no_unsafe_localstorage;
pub mod no_v_html;
pub mod no_watch_with_callback;
pub mod v_for_missing_key;

/// A category groups rules so that the user can opt in or out of whole areas
/// of analysis with a single flag (e.g. `--category security`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
  Security,
  BestPractice,
  Performance,
  Accessibility,
  Architecture,
}

impl Category {
  #[must_use]
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Security => "security",
      Self::BestPractice => "best-practice",
      Self::Performance => "performance",
      Self::Accessibility => "accessibility",
      Self::Architecture => "architecture",
    }
  }
}

#[derive(Error, Diagnostic, Debug)]
#[error("Unknown rule error")]
#[diagnostic(code(vuer::unknown_rule))]
pub struct UnknownRuleError {
  #[diagnostic(help("Check the rule name and try again."))]
  pub name: String,
}

/// Every rule implements this trait. Rules must be:
/// * independent of other rules
/// * deterministic (same input -> same output)
/// * free of global mutable state, filesystem access, and network access
pub trait Rule: Send + Sync {
  /// Stable id used for CLI flag matching, SARIF, and suppression comments.
  fn id(&self) -> RuleId;

  /// Short human-readable name, used in `vuer --list`.
  fn name(&self) -> &'static str;

  /// One-line description for `vuer --list` and SARIF `shortDescription`.
  fn description(&self) -> &'static str;

  /// Severity bucket for this rule. Stable across runs.
  fn severity(&self) -> Severity;

  /// Which category this rule belongs to.
  fn category(&self) -> Category;

  /// The actual analysis. Receives an immutable `ScanContext` and returns
  /// zero or more diagnostics.
  fn check(&self, ctx: &ScanContext) -> Vec<Box<dyn Diagnostic>>;
}

pub struct RuleRegistry {
  rules: Vec<Box<dyn Rule>>,
}

impl RuleRegistry {
  pub fn new() -> Self {
    let rules: Vec<Box<dyn Rule>> = vec![
      // Security
      Box::new(no_v_html::NoVHtml),
      Box::new(no_inner_html::NoInnerHtml),
      Box::new(no_document_write::NoDocumentWrite),
      Box::new(no_eval::NoEval),
      Box::new(no_dangerous_url::NoDangerousUrl),
      Box::new(no_open_redirect::NoOpenRedirect),
      Box::new(no_unsafe_localstorage::NoUnsafeLocalStorage),
      Box::new(no_unsafe_iframe::NoUnsafeIframe),
      Box::new(no_dynamic_bind::NoDynamicBindSrc),
      // Best practice
      Box::new(no_inline_styles::NoInlineStyle),
      Box::new(no_watch_with_callback::NoWatchWithCallback),
      Box::new(v_for_missing_key::VForMissingKey),
    ];
    Self { rules }
  }

  pub fn get_all(&self) -> &[Box<dyn Rule>] {
    &self.rules
  }

  pub fn get_by_id(&self, id: &str) -> Option<&dyn Rule> {
    self
      .rules
      .iter()
      .find(|r| r.id().as_str() == id)
      .map(|r| r.as_ref())
  }

  pub fn get_by_name(&self, name: &str) -> Option<&dyn Rule> {
    self
      .rules
      .iter()
      .find(|r| r.name() == name)
      .map(|r| r.as_ref())
  }

  /// Filter the registry by id/name list. An empty list means "all rules".
  pub fn get_enabled(&self, enabled: &[String]) -> Vec<&dyn Rule> {
    if enabled.is_empty() {
      return self.rules.iter().map(|r| r.as_ref()).collect();
    }
    self
      .rules
      .iter()
      .filter(|r| {
        let name = r.name();
        let id = r.id();
        let id_str = id.as_str();
        enabled.iter().any(|e| e == name || e == id_str)
      })
      .map(|r| r.as_ref())
      .collect()
  }
}

impl Default for RuleRegistry {
  fn default() -> Self {
    Self::new()
  }
}
