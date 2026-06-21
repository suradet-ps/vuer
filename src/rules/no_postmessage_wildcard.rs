//! Detect `postMessage(..., '*')` calls.
//!
//! `postMessage` is a safe cross-origin communication channel *only* when the
//! caller pins a specific `targetOrigin`. Passing the literal `'*'` (or `"*"`,
//! or the options-object equivalent) tells the browser to deliver the message
//! to whichever window happens to be there — including a window that an
//! attacker has just navigated to the same name.
//!
//! See MDN's [postMessage security concerns][1] for the canonical warning.
//!
//! Detection:
//! 1. Find every call whose callee ends in `postMessage` (so `window.postMessage`,
//!    `popup.postMessage`, and bare `postMessage` are all covered).
//! 2. Inspect the second argument:
//!    - legacy form `postMessage(msg, targetOrigin)`: flag if `targetOrigin`
//!      is the string literal `'*'` / `"*"`.
//!    - options form `postMessage(msg, options)`: flag if `options` is an
//!      object literal whose `targetOrigin` property is the string literal
//!      `'*'` / `"*"`.
//!
//! Anything else (a URL string, an undefined value, a variable we can't
//! inspect) is left alone, keeping the false-positive rate low.
//!
//! [1]: https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage#security_concerns

use miette::{Diagnostic, NamedSource, SourceSpan};
use oxc_allocator::Allocator;
use oxc_ast::ast::Argument;
use oxc_ast::ast::Expression;
use oxc_ast::ast::ObjectPropertyKind;
use oxc_ast::ast::PropertyKey;
use oxc_ast_visit::Visit;
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::script::{callee_path, parse_script};
use crate::rule_id::RuleId;
use crate::rules::{Category, Rule};
use crate::severity::Severity;

#[derive(Error, Diagnostic, Debug)]
#[error("`postMessage` is called with a wildcard `targetOrigin` of `'*'`")]
#[diagnostic(
  code(vuer::security::no_postmessage_wildcard),
  severity(Warning),
  help(
    "Always pin a specific `targetOrigin` (for example `https://app.example.com`). \
     The wildcard `'*'` lets a malicious site that has navigated the target \
     window intercept the message. Use the URL of the receiver, or `/` only \
     when you genuinely want same-origin delivery."
  )
)]
pub struct NoPostmessageWildcardViolation {
  #[source_code]
  pub src: NamedSource<String>,
  #[label("wildcard targetOrigin here")]
  pub span: SourceSpan,
}

pub struct NoPostmessageWildcard;

impl Rule for NoPostmessageWildcard {
  fn id(&self) -> RuleId {
    RuleId::new("vue/security/no-postmessage-wildcard")
  }

  fn name(&self) -> &'static str {
    "no-postmessage-wildcard"
  }

  fn description(&self) -> &'static str {
    "Disallow `postMessage(..., '*')` to prevent cross-origin message interception"
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
    let mut finder = PostmessageWildcardFinder {
      hits: &mut violations,
      named_source: &ctx.named_source,
      script_offset: ctx.script_offset,
    };
    finder.visit_program(&program);
    violations
  }
}

struct PostmessageWildcardFinder<'a, 'b> {
  hits: &'a mut Vec<Box<dyn Diagnostic>>,
  named_source: &'b NamedSource<String>,
  script_offset: usize,
}

impl<'a, 'b, 'c> Visit<'c> for PostmessageWildcardFinder<'a, 'b> {
  fn visit_call_expression(&mut self, call: &oxc_ast::ast::CallExpression<'c>) {
    if is_postmessage_call(call) && has_wildcard_target_origin(call) {
      let span = call.span;
      let absolute = (self.script_offset as u32 + span.start) as usize;
      self.hits.push(Box::new(NoPostmessageWildcardViolation {
        src: self.named_source.clone(),
        span: SourceSpan::new(absolute.into(), (span.end - span.start) as usize),
      }));
    }
    self.visit_arguments(&call.arguments);
    self.visit_expression(&call.callee);
  }
}

fn is_postmessage_call(call: &oxc_ast::ast::CallExpression<'_>) -> bool {
  matches!(callee_path(call).last(), Some(&"postMessage"))
}

fn has_wildcard_target_origin(call: &oxc_ast::ast::CallExpression<'_>) -> bool {
  let Some(arg) = call.arguments.get(1) else {
    return false;
  };
  match arg {
    Argument::StringLiteral(lit) => lit.value == "*",
    Argument::ObjectExpression(obj) => object_has_wildcard_target_origin(obj),
    _ => false,
  }
}

fn object_has_wildcard_target_origin(obj: &oxc_ast::ast::ObjectExpression<'_>) -> bool {
  obj.properties.iter().any(|prop| match prop {
    ObjectPropertyKind::ObjectProperty(p) => {
      let key_matches = match &p.key {
        PropertyKey::StaticIdentifier(id) => id.name == "targetOrigin",
        PropertyKey::StringLiteral(s) => s.value == "targetOrigin",
        _ => false,
      };
      key_matches && matches!(&p.value, Expression::StringLiteral(lit) if lit.value == "*")
    }
    ObjectPropertyKind::SpreadProperty(_) => false,
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::parser::parse_sfc;

  fn scan(source: &str) -> Vec<Box<dyn Diagnostic>> {
    let mut ctx = ScanContext::new("test.vue".into(), source.to_string());
    parse_sfc(&mut ctx);
    NoPostmessageWildcard.check(&ctx)
  }

  #[test]
  fn flags_single_quoted_wildcard() {
    let src = r#"<script setup>
iframe.contentWindow.postMessage({type: 'ping'}, '*')
</script>"#;
    assert_eq!(scan(src).len(), 1);
  }

  #[test]
  fn flags_double_quoted_wildcard() {
    let src = r#"<script setup>
window.postMessage(msg, "*")
</script>"#;
    assert_eq!(scan(src).len(), 1);
  }

  #[test]
  fn flags_window_postmessage() {
    let src = r#"<script setup>
window.postMessage('hi', '*')
</script>"#;
    assert_eq!(scan(src).len(), 1);
  }

  #[test]
  fn flags_options_object_form() {
    let src = r#"<script setup>
popup.postMessage(payload, { targetOrigin: '*' })
</script>"#;
    assert_eq!(scan(src).len(), 1);
  }

  #[test]
  fn allows_specific_origin() {
    let src = r#"<script setup>
iframe.contentWindow.postMessage({type: 'ping'}, 'https://app.example.com')
</script>"#;
    assert!(scan(src).is_empty());
  }

  #[test]
  fn allows_same_origin_slash() {
    let src = r#"<script setup>
window.postMessage(msg, '/')
</script>"#;
    assert!(scan(src).is_empty());
  }

  #[test]
  fn allows_options_object_with_specific_origin() {
    let src = r#"<script setup>
popup.postMessage(payload, { targetOrigin: 'https://app.example.com' })
</script>"#;
    assert!(scan(src).is_empty());
  }

  #[test]
  fn allows_options_object_without_target_origin() {
    // The options form without targetOrigin falls back to '/', which is
    // same-origin and safe.
    let src = r#"<script setup>
popup.postMessage(payload, { transfer: [channel] })
</script>"#;
    assert!(scan(src).is_empty());
  }

  #[test]
  fn ignores_non_postmessage_calls() {
    let src = r#"<script setup>
worker.postMessage('*')
notAPostMessage('*')
</script>"#;
    assert!(scan(src).is_empty());
  }

  #[test]
  fn no_script_no_violation() {
    assert!(scan("").is_empty());
  }
}
