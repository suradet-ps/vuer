//! Detect `window.open(url, '_blank', ...)` without `noopener`/`noreferrer`.
//!
//! Opening a new browsing context with the `_blank` target is a known
//! reverse-tabnabbing / window-opener vector: the new tab receives a
//! `window.opener` reference back to the originating page and can navigate
//! it to a phishing URL. The mitigation is to pass `noopener` (or
//! `noreferrer`, which implies `noopener`) in the `windowFeatures` argument.
//!
//! See MDN's [`Window.open`][1] reference for the `noopener` semantics.
//!
//! Detection:
//! 1. Find calls whose callee is exactly `window.open`.
//! 2. Require the second argument to be the string literal `'_blank'` (the
//!    only target that opens a new context with `window.opener` set).
//! 3. Inspect the third argument (`windowFeatures`):
//!    - missing: flag (only the `noopener`/`noreferrer` keywords explicitly
//!      disable it in browsers that do not default to noopener).
//!    - string literal without `noopener` and without `noreferrer`: flag.
//!    - any other expression (a variable, a template literal, a computed
//!      value): leave alone to keep the false-positive rate low.
//!
//! Phase 2 (taint): the danger of reverse tabnabbing is that the *opened*
//! page is attacker-influenced. A URL that is provably clean — a hardcoded
//! literal or a value derived only from trusted data — opens a page the
//! developer chose, so the reverse-tabnabbing surface is gone. Such calls
//! are the false-positive cut and are not reported. A URL carrying
//! untrusted data (route query, storage, props, ...) is reported at High
//! with the source→sink flow path; an unanalysable URL is reported
//! conservatively without a flow.
//!
//! [1]: https://developer.mozilla.org/en-US/docs/Web/API/Window/open#noopener

use miette::{Diagnostic, NamedSource, SourceSpan};
use oxc_allocator::Allocator;
use oxc_ast::ast::Argument;
use oxc_ast_visit::Visit;
use oxc_span::{GetSpan, Span};
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::script::{is_call_named, parse_script};
use crate::rule_id::RuleId;
use crate::rules::{Category, Finding, Rule, RuleKind};
use crate::severity::Severity;
use crate::taint::TaintStatus;

#[derive(Error, Diagnostic, Debug)]
#[error("`window.open` with `_blank` is missing `noopener`")]
#[diagnostic(
  code(vuer::security::no_window_open_blank_noopener),
  severity(Warning),
  help(
    "Add `noopener` (or `noreferrer`, which implies `noopener`) to the \
     `windowFeatures` string: `window.open(url, '_blank', 'noopener,width=400')`. \
     Without it the opened tab can call `window.opener.location = ...` and \
     phish the originating page."
  )
)]
pub struct NoWindowOpenBlankNoopenerViolation {
  #[source_code]
  pub src: NamedSource<String>,
  #[label("window.open call here")]
  pub span: SourceSpan,
}

pub struct NoWindowOpenBlankNoopener;

impl Rule for NoWindowOpenBlankNoopener {
  fn id(&self) -> RuleId {
    RuleId::new("vue/security/no-window-open-blank-noopener")
  }

  fn name(&self) -> &'static str {
    "no-window-open-blank-noopener"
  }

  fn description(&self) -> &'static str {
    "Disallow `window.open(url, '_blank', ...)` without `noopener` when the URL may carry untrusted data"
  }

  fn severity(&self) -> Severity {
    Severity::High
  }

  fn category(&self) -> Category {
    Category::Security
  }

  fn kind(&self) -> RuleKind {
    RuleKind::Taint
  }

  fn check(&self, ctx: &ScanContext) -> Vec<Finding> {
    let mut violations = Vec::new();
    let Some(script) = ctx.script.as_ref() else {
      return violations;
    };

    let allocator = Allocator::default();
    let program = parse_script(&allocator, script, ctx.lang.clone());
    let mut finder = WindowOpenFinder { hits: Vec::new() };
    finder.visit_program(&program);

    for (call_span, url_span) in finder.hits {
      // Phase 2: report only when the URL may carry untrusted data. A
      // provably clean URL (hardcoded literal, or a value derived only
      // from trusted data) opens a page the developer chose — the
      // reverse-tabnabbing surface is gone. Unknown (unanalysable) URLs
      // are reported conservatively.
      let abs_url = ctx.script_offset as u32 + url_span.start;
      if ctx.taint.status_at(abs_url) == TaintStatus::Clean {
        continue;
      }
      let absolute = (ctx.script_offset as u32 + call_span.start) as usize;
      let diagnostic = Box::new(NoWindowOpenBlankNoopenerViolation {
        src: ctx.named_source.clone(),
        span: SourceSpan::new(absolute.into(), (call_span.end - call_span.start) as usize),
      });
      let flow = ctx.taint.flow_at(abs_url, "`window.open` URL");
      violations.push(match flow {
        Some(flow) => Finding::with_flow(diagnostic, vec![flow]),
        None => Finding::new(diagnostic),
      });
    }

    violations
  }
}

struct WindowOpenFinder {
  /// (call span, url argument span) for every unsafe `_blank` open.
  hits: Vec<(Span, Span)>,
}

impl<'a> Visit<'a> for WindowOpenFinder {
  fn visit_call_expression(&mut self, call: &oxc_ast::ast::CallExpression<'a>) {
    if is_call_named(call, &["window", "open"])
      && let Some(url_span) = unsafe_blank_open_url(call)
    {
      self.hits.push((call.span, url_span));
    }
    self.visit_arguments(&call.arguments);
    self.visit_expression(&call.callee);
  }
}

/// The span of the URL argument when `call` is a `window.open` with the
/// `'_blank'` target and no `noopener`/`noreferrer` in the features, else
/// `None`.
fn unsafe_blank_open_url(call: &oxc_ast::ast::CallExpression<'_>) -> Option<Span> {
  let url_span = call.arguments.first()?.span();
  let Argument::StringLiteral(target_lit) = call.arguments.get(1)? else {
    return None;
  };
  if target_lit.value != "_blank" {
    return None;
  }
  // Third argument is windowFeatures. Missing means noopener is NOT set.
  match call.arguments.get(2) {
    None => Some(url_span),
    Some(Argument::StringLiteral(features)) if !features_contain_noopener(&features.value) => {
      Some(url_span)
    }
    // Variable / computed / template literal: we can't tell, so don't flag
    // and keep the false-positive rate low.
    _ => None,
  }
}

fn features_contain_noopener(features: &str) -> bool {
  // windowFeatures is a comma-separated `name=value` list; bare flags like
  // `noopener` are equivalent to `noopener=true`. We do a substring check
  // on the comma-separated tokens to avoid matching `noopenered` (which
  // isn't a valid feature but a defensive check) and similar prefixes.
  features.split(',').any(|token| {
    token
      .trim()
      .split('=')
      .next()
      .is_some_and(|k| matches!(k, "noopener" | "noreferrer"))
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::parser::parse_sfc;

  /// Scan a `<script setup>` block for the rule.
  fn scan(script: &str) -> Vec<Finding> {
    let source = format!("<script setup>\n{script}\n</script>");
    let mut ctx = ScanContext::new("test.vue".into(), source);
    parse_sfc(&mut ctx);
    NoWindowOpenBlankNoopener.check(&ctx)
  }

  /// Scan a `<script setup lang="ts">` block for the rule.
  fn scan_ts(script: &str) -> Vec<Finding> {
    let source = format!("<script setup lang=\"ts\">\n{script}\n</script>");
    let mut ctx = ScanContext::new("test.vue".into(), source);
    parse_sfc(&mut ctx);
    NoWindowOpenBlankNoopener.check(&ctx)
  }

  #[test]
  fn literal_url_is_clean_and_not_reported() {
    // The false-positive cut: a hardcoded URL opens a page the developer
    // chose, so there is no reverse-tabnabbing surface.
    assert!(scan("window.open('https://example.com', '_blank')").is_empty());
  }

  #[test]
  fn literal_url_with_other_features_is_not_reported() {
    assert!(
      scan("window.open('https://example.com', '_blank', 'width=400,height=300')").is_empty()
    );
  }

  #[test]
  fn flags_tainted_url() {
    let v = scan("const url = localStorage.getItem('redirect')\nwindow.open(url, '_blank')");
    assert_eq!(v.len(), 1);
    let flow = v[0].flow.as_ref().expect("tainted finding carries flow");
    assert_eq!(flow[0].sink, "`window.open` URL");
    assert!(flow[0].source.contains("localStorage"));
  }

  #[test]
  fn flags_tainted_url_via_route_query() {
    let v = scan_ts("const route = useRoute()\nwindow.open(route.query.url as string, '_blank')");
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_tainted_url_via_local_function() {
    // Inter-procedural: the taint flows through `build` into the sink.
    let v = scan_ts(
      "function build(u: string) { return u }\n\
       const url = localStorage.getItem('u')\n\
       window.open(build(url), '_blank')",
    );
    assert_eq!(v.len(), 1);
    let flow = v[0].flow.as_ref().expect("flow");
    assert!(flow[0].via.iter().any(|id| id == "build"));
  }

  #[test]
  fn sanitized_url_is_clean() {
    assert!(
      scan("const url = DOMPurify.sanitize(localStorage.getItem('u'))\nwindow.open(url, '_blank')")
        .is_empty()
    );
  }

  #[test]
  fn allows_tainted_blank_with_noopener() {
    // The features check runs first: `noopener` in the feature string is
    // safe regardless of the URL's taint.
    let v = scan("const url = localStorage.getItem('u')\nwindow.open(url, '_blank', 'noopener')");
    assert!(v.is_empty());
  }

  #[test]
  fn allows_tainted_blank_with_noreferrer() {
    let v = scan("const url = localStorage.getItem('u')\nwindow.open(url, '_blank', 'noreferrer')");
    assert!(v.is_empty());
  }

  #[test]
  fn allows_non_blank_target() {
    let v = scan("const url = localStorage.getItem('u')\nwindow.open(url, '_self')");
    assert!(v.is_empty());
  }

  #[test]
  fn allows_named_target() {
    let v = scan("const url = localStorage.getItem('u')\nwindow.open(url, 'docsTab')");
    assert!(v.is_empty());
  }

  #[test]
  fn ignores_open_on_other_receivers() {
    let v = scan("const url = localStorage.getItem('u')\npopup.open(url, '_blank')");
    assert!(v.is_empty());
  }

  #[test]
  fn no_script_no_violation() {
    assert!(scan("").is_empty());
  }
}
