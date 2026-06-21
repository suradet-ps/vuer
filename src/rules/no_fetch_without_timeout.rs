//! Detect `fetch(url, options)` calls without an `AbortController` signal.
//!
//! A `fetch` call that is never aborted can hang indefinitely on a slow or
//! unreachable host, exhausting connection pools and tying up UI state. The
//! modern remediation is to pass `signal: controller.signal` in the options
//! object, then call `controller.abort()` from a `setTimeout` / user
//! navigation / cleanup hook.
//!
//! See MDN's [`fetch` options][1] and the [`AbortController`][2] guide.
//!
//! Detection (conservative, sink-only — see false-positive analysis below):
//! 1. Find every call whose callee ends in `fetch` (covers `fetch`,
//!    `window.fetch`, `globalThis.fetch`).
//! 2. If there is no second argument → flag.
//! 3. If the second argument is an object literal and it does NOT contain a
//!    `signal` property → flag.
//! 4. If the second argument is anything else (a variable, a `Request`
//!    instance, a conditional) → leave alone. We don't have the data-flow
//!    to know whether the call site eventually attaches a signal elsewhere.
//!
//! False-positive budget: under ~5%. The only realistic false positive is
//! `fetch(url, { ...other options })` where the developer wraps the call
//! in a helper that always attaches a signal — for those, suppressing the
//! rule on a per-line basis with an inline comment is cheaper than guessing.
//!
//! [1]: https://developer.mozilla.org/en-US/docs/Web/API/Window/fetch#parameters
//! [2]: https://developer.mozilla.org/en-US/docs/Web/API/AbortController

use miette::{Diagnostic, NamedSource, SourceSpan};
use oxc_allocator::Allocator;
use oxc_ast::ast::Argument;
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
#[error("`fetch` is called without an `AbortSignal`")]
#[diagnostic(
  code(vuer::security::no_fetch_without_timeout),
  severity(Warning),
  help(
    "Pass a `signal` from an `AbortController` so the request can be \
     cancelled: `fetch(url, {{ signal: ctrl.signal }})`. Without it, a slow \
     or unreachable host can hang the call indefinitely, exhausting the \
     connection pool and leaking user state. Pair with a `setTimeout` to \
     bound the wait time."
  )
)]
pub struct NoFetchWithoutTimeoutViolation {
  #[source_code]
  pub src: NamedSource<String>,
  #[label("fetch call here")]
  pub span: SourceSpan,
}

pub struct NoFetchWithoutTimeout;

impl Rule for NoFetchWithoutTimeout {
  fn id(&self) -> RuleId {
    RuleId::new("vue/security/no-fetch-without-timeout")
  }

  fn name(&self) -> &'static str {
    "no-fetch-without-timeout"
  }

  fn description(&self) -> &'static str {
    "Disallow `fetch(url)` without an `AbortSignal` to bound request lifetime"
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
    let mut finder = FetchWithoutTimeoutFinder {
      hits: &mut violations,
      named_source: &ctx.named_source,
      script_offset: ctx.script_offset,
    };
    finder.visit_program(&program);
    violations
  }
}

struct FetchWithoutTimeoutFinder<'a, 'b> {
  hits: &'a mut Vec<Box<dyn Diagnostic>>,
  named_source: &'b NamedSource<String>,
  script_offset: usize,
}

impl<'a, 'b, 'c> Visit<'c> for FetchWithoutTimeoutFinder<'a, 'b> {
  fn visit_call_expression(&mut self, call: &oxc_ast::ast::CallExpression<'c>) {
    if is_fetch_call(call) && is_missing_signal(call) {
      let span = call.span;
      let absolute = (self.script_offset as u32 + span.start) as usize;
      self.hits.push(Box::new(NoFetchWithoutTimeoutViolation {
        src: self.named_source.clone(),
        span: SourceSpan::new(absolute.into(), (span.end - span.start) as usize),
      }));
    }
    self.visit_arguments(&call.arguments);
    self.visit_expression(&call.callee);
  }
}

fn is_fetch_call(call: &oxc_ast::ast::CallExpression<'_>) -> bool {
  // Only flag calls to the *global* `fetch`. Custom methods on a
  // third-party object (e.g. `api.fetch`, `client.fetch`) are not the
  // browser's network API and may not support an `AbortSignal` at all.
  matches!(
    callee_path(call).as_slice(),
    ["fetch"] | ["window", "fetch"] | ["globalThis", "fetch"] | ["self", "fetch"]
  )
}

fn is_missing_signal(call: &oxc_ast::ast::CallExpression<'_>) -> bool {
  match call.arguments.get(1) {
    Some(Argument::ObjectExpression(obj)) => !object_has_signal(obj),
    // The 2nd argument is a variable, a `Request` instance, or absent
    // entirely. We can only flag the bare-URL case (`fetch('/url')`),
    // because a non-string-literal first argument is most likely a
    // `Request` instance which may already carry a signal.
    None => matches!(call.arguments.first(), Some(Argument::StringLiteral(_))),
    _ => false,
  }
}

fn object_has_signal(obj: &oxc_ast::ast::ObjectExpression<'_>) -> bool {
  obj.properties.iter().any(|prop| match prop {
    ObjectPropertyKind::ObjectProperty(p) => match &p.key {
      PropertyKey::StaticIdentifier(id) => id.name == "signal",
      PropertyKey::StringLiteral(s) => s.value == "signal",
      _ => false,
    },
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
    NoFetchWithoutTimeout.check(&ctx)
  }

  #[test]
  fn flags_bare_fetch() {
    let src = r#"<script setup>
fetch('/api/users')
</script>"#;
    assert_eq!(scan(src).len(), 1);
  }

  #[test]
  fn flags_fetch_with_options_no_signal() {
    let src = r#"<script setup>
fetch('/api/users', { method: 'POST', headers: { 'Content-Type': 'application/json' } })
</script>"#;
    assert_eq!(scan(src).len(), 1);
  }

  #[test]
  fn flags_window_fetch() {
    let src = r#"<script setup>
window.fetch('/api/users')
</script>"#;
    assert_eq!(scan(src).len(), 1);
  }

  #[test]
  fn allows_fetch_with_signal() {
    let src = r#"<script setup>
const ctrl = new AbortController()
fetch('/api/users', { signal: ctrl.signal })
</script>"#;
    assert!(scan(src).is_empty());
  }

  #[test]
  fn allows_fetch_with_signal_and_other_options() {
    let src = r#"<script setup>
fetch('/api/users', { method: 'POST', signal: ctrl.signal, headers: {} })
</script>"#;
    assert!(scan(src).is_empty());
  }

  #[test]
  fn allows_fetch_with_variable_options() {
    // We can't tell if the variable already has a signal; conservative skip.
    let src = r#"<script setup>
const opts = { signal: ctrl.signal }
fetch('/api/users', opts)
</script>"#;
    assert!(scan(src).is_empty());
  }

  #[test]
  fn allows_fetch_with_request_instance() {
    // Passing a `Request` constructed elsewhere is a valid pattern; the
    // signal may be attached to the Request.
    let src = r#"<script setup>
const req = new Request('/api/users')
fetch(req)
</script>"#;
    assert!(scan(src).is_empty());
  }

  #[test]
  fn ignores_unrelated_call_named_fetch() {
    // Bare identifier `fetch` may shadow the global; the rule still applies,
    // but a method on a different object named `fetch` should not.
    let src = r#"<script setup>
api.fetch('/users')
</script>"#;
    assert!(scan(src).is_empty());
  }

  #[test]
  fn no_script_no_violation() {
    assert!(scan("").is_empty());
  }
}
