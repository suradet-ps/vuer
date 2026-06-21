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
//!    - missing: flag (modern browsers default to `noopener=false` when
//!      `windowFeatures` is omitted entirely; only `<a rel="noopener">`
//!      enables it implicitly).
//!    - string literal without `noopener` and without `noreferrer`: flag.
//!    - any other expression (a variable, a template literal, a computed
//!      value): leave alone to keep the false-positive rate low.
//!
//! [1]: https://developer.mozilla.org/en-US/docs/Web/API/Window/open#noopener

use miette::{Diagnostic, NamedSource, SourceSpan};
use oxc_allocator::Allocator;
use oxc_ast::ast::Argument;
use oxc_ast_visit::Visit;
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::script::{is_call_named, parse_script};
use crate::rule_id::RuleId;
use crate::rules::{Category, Rule};
use crate::severity::Severity;

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
    "Disallow `window.open(url, '_blank', ...)` without `noopener` to prevent reverse tabnabbing"
  }

  fn severity(&self) -> Severity {
    Severity::High
  }

  fn category(&self) -> Category {
    Category::Security
  }

  fn check(&self, ctx: &ScanContext) -> Vec<Box<dyn Diagnostic>> {
    let mut violations = Vec::new();
    let Some(script) = ctx.script.as_ref() else {
      return violations;
    };

    let allocator = Allocator::default();
    let program = parse_script(&allocator, script, ctx.lang.clone());
    let mut finder = WindowOpenFinder {
      hits: &mut violations,
      named_source: &ctx.named_source,
      script_offset: ctx.script_offset,
    };
    finder.visit_program(&program);
    violations
  }
}

struct WindowOpenFinder<'a, 'b> {
  hits: &'a mut Vec<Box<dyn Diagnostic>>,
  named_source: &'b NamedSource<String>,
  script_offset: usize,
}

impl<'a, 'b, 'c> Visit<'c> for WindowOpenFinder<'a, 'b> {
  fn visit_call_expression(&mut self, call: &oxc_ast::ast::CallExpression<'c>) {
    if is_call_named(call, &["window", "open"]) && is_unsafe_blank_open(call) {
      let span = call.span;
      let absolute = (self.script_offset as u32 + span.start) as usize;
      self.hits.push(Box::new(NoWindowOpenBlankNoopenerViolation {
        src: self.named_source.clone(),
        span: SourceSpan::new(absolute.into(), (span.end - span.start) as usize),
      }));
    }
    self.visit_arguments(&call.arguments);
    self.visit_expression(&call.callee);
  }
}

fn is_unsafe_blank_open(call: &oxc_ast::ast::CallExpression<'_>) -> bool {
  let Some(target) = call.arguments.get(1) else {
    return false;
  };
  let Argument::StringLiteral(target_lit) = target else {
    return false;
  };
  if target_lit.value != "_blank" {
    return false;
  }
  // Third argument is windowFeatures. Missing means noopener is NOT set in
  // older browsers, and only the `noopener`/`noreferrer` keywords explicitly
  // disable it in modern browsers.
  match call.arguments.get(2) {
    None => true,
    Some(Argument::StringLiteral(features)) => !features_contain_noopener(&features.value),
    // Variable / computed / template literal: we can't tell, so don't flag
    // and keep the false-positive rate low.
    _ => false,
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

  fn scan(source: &str) -> Vec<Box<dyn Diagnostic>> {
    let mut ctx = ScanContext::new("test.vue".into(), source.to_string());
    parse_sfc(&mut ctx);
    NoWindowOpenBlankNoopener.check(&ctx)
  }

  #[test]
  fn flags_blank_without_features() {
    let src = r#"<script setup>
window.open('https://example.com', '_blank')
</script>"#;
    assert_eq!(scan(src).len(), 1);
  }

  #[test]
  fn flags_blank_with_other_features() {
    let src = r#"<script setup>
window.open('https://example.com', '_blank', 'width=400,height=300')
</script>"#;
    assert_eq!(scan(src).len(), 1);
  }

  #[test]
  fn allows_blank_with_noopener() {
    let src = r#"<script setup>
window.open('https://example.com', '_blank', 'noopener,width=400')
</script>"#;
    assert!(scan(src).is_empty());
  }

  #[test]
  fn allows_blank_with_noreferrer() {
    let src = r#"<script setup>
window.open('https://example.com', '_blank', 'noreferrer')
</script>"#;
    assert!(scan(src).is_empty());
  }

  #[test]
  fn allows_non_blank_target() {
    let src = r#"<script setup>
window.open('https://example.com', '_self')
</script>"#;
    assert!(scan(src).is_empty());
  }

  #[test]
  fn allows_named_target() {
    let src = r#"<script setup>
window.open('https://example.com', 'docsTab')
</script>"#;
    assert!(scan(src).is_empty());
  }

  #[test]
  fn ignores_open_on_other_receivers() {
    let src = r#"<script setup>
popup.open('https://example.com', '_blank')
</script>"#;
    assert!(scan(src).is_empty());
  }

  #[test]
  fn no_script_no_violation() {
    assert!(scan("").is_empty());
  }
}
