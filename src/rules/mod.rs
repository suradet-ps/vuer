use miette::Diagnostic;
use thiserror::Error;

use crate::context::ScanContext;
use crate::rule_id::RuleId;
use crate::severity::Severity;
use crate::taint::FlowPath;

pub mod no_button_without_type;
pub mod no_click_without_role_keyboard;
pub mod no_dangerous_url;
pub mod no_deep_watch_without_handler;
pub mod no_document_write;
pub mod no_dynamic_bind;
pub mod no_eval;
pub mod no_fetch_without_timeout;
pub mod no_form_without_label;
pub mod no_img_without_alt;
pub mod no_inline_styles;
pub mod no_inner_html;
pub mod no_large_list_without_virtualization;
pub mod no_open_redirect;
pub mod no_postmessage_wildcard;
pub mod no_reactive_in_v_for;
pub mod no_unsafe_iframe;
pub mod no_unsafe_localstorage;
pub mod no_v_html;
pub mod no_v_if_with_v_for;
pub mod no_watch_with_callback;
pub mod no_window_open_blank_noopener;
pub mod v_for_missing_key;

/// How a rule reasons about its findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleKind {
  /// The rule matches a syntactic pattern ("this pattern exists").
  Syntactic,
  /// The rule additionally asks the taint engine whether the matched
  /// pattern carries untrusted data ("this pattern carries untrusted
  /// data"), cutting false positives while keeping the unsafe path.
  Taint,
}

/// One rule finding: the diagnostic plus optional taint flow paths.
///
/// Rules that did not run taint analysis return `flow: None`; the report
/// layer consumes the field only when present.
pub struct Finding {
  pub diagnostic: Box<dyn Diagnostic + Send + Sync>,
  /// Untrusted-data flow(s) reaching this finding, when the rule queried
  /// the taint engine.
  pub flow: Option<Vec<FlowPath>>,
}

impl Finding {
  pub fn new(diagnostic: Box<dyn Diagnostic + Send + Sync>) -> Self {
    Self {
      diagnostic,
      flow: None,
    }
  }

  pub fn with_flow(diagnostic: Box<dyn Diagnostic + Send + Sync>, flow: Vec<FlowPath>) -> Self {
    Self {
      diagnostic,
      flow: Some(flow),
    }
  }
}

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

  /// How the rule reasons about findings. Defaults to [`RuleKind::Syntactic`];
  /// rules upgraded to query the taint engine override it.
  fn kind(&self) -> RuleKind {
    RuleKind::Syntactic
  }

  /// The actual analysis. Receives an immutable `ScanContext` and returns
  /// zero or more findings (diagnostic + optional taint flows).
  ///
  /// The `Send + Sync` bound on the returned diagnostics lets the
  /// scanner parallelise per-file work across rayon workers (see
  /// `scanner::Scanner::scan_path`).
  fn check(&self, ctx: &ScanContext) -> Vec<Finding>;
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
      Box::new(no_postmessage_wildcard::NoPostmessageWildcard),
      Box::new(no_window_open_blank_noopener::NoWindowOpenBlankNoopener),
      Box::new(no_fetch_without_timeout::NoFetchWithoutTimeout),
      // Best practice
      Box::new(no_inline_styles::NoInlineStyle),
      Box::new(no_watch_with_callback::NoWatchWithCallback),
      Box::new(v_for_missing_key::VForMissingKey),
      // Performance
      Box::new(no_v_if_with_v_for::NoVIfWithVFor),
      Box::new(no_deep_watch_without_handler::NoDeepWatchWithoutHandler),
      Box::new(no_reactive_in_v_for::NoReactiveInVFor),
      Box::new(no_large_list_without_virtualization::NoLargeListWithoutVirtualization),
      // Accessibility
      Box::new(no_img_without_alt::NoImgWithoutAlt),
      Box::new(no_click_without_role_keyboard::NoClickWithoutRoleKeyboard),
      Box::new(no_form_without_label::NoFormWithoutLabel),
      Box::new(no_button_without_type::NoButtonWithoutType),
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
