use miette::{Diagnostic, NamedSource, SourceSpan};
use oxc_allocator::Allocator;
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::script::{find_calls, is_call_named, parse_script};
use crate::rule_id::RuleId;
use crate::rules::{Category, Rule};
use crate::severity::Severity;

#[derive(Error, Diagnostic, Debug)]
#[error("`watch` with a callback can leak memory if not cleaned up")]
#[diagnostic(
  code(vue_scanner::best_practice::no_watch_with_callback),
  severity(Info),
  help(
    "Prefer `watchEffect`, or make sure the watcher is stopped via the returned \
     handle inside `onScopeDispose` / `onUnmounted`."
  )
)]
pub struct NoWatchWithCallbackViolation {
  #[source_code]
  pub src: NamedSource<String>,
  #[label("`watch(source, callback)` call here")]
  pub span: SourceSpan,
}

pub struct NoWatchWithCallback;

impl Rule for NoWatchWithCallback {
  fn id(&self) -> RuleId {
    RuleId::new("vue/best-practice/no-watch-with-callback")
  }

  fn name(&self) -> &'static str {
    "no-watch-with-callback"
  }

  fn description(&self) -> &'static str {
    "Warn about `watch(source, callback)` calls that may leak when not disposed"
  }

  fn severity(&self) -> Severity {
    Severity::Low
  }

  fn category(&self) -> Category {
    Category::BestPractice
  }

  fn check(&self, ctx: &ScanContext) -> Vec<Box<dyn Diagnostic>> {
    let mut violations = Vec::new();
    let Some(script) = ctx.script.as_ref() else {
      return violations;
    };

    let allocator = Allocator::default();
    let program = parse_script(&allocator, script, ctx.lang.clone());

    let matches = find_calls(&program, |call| {
      if is_call_named(call, &["watch"]) && has_function_arg(call) {
        Some("watch(source, callback)")
      } else {
        None
      }
    });

    for m in matches {
      let absolute = ctx.script_offset as u32 + m.call.start;
      violations.push(Box::new(NoWatchWithCallbackViolation {
        src: ctx.named_source.clone(),
        span: SourceSpan::new((absolute as usize).into(), m.call.len() as usize),
      }));
    }

    violations
  }
}

fn has_function_arg(call: &oxc_ast::ast::CallExpression<'_>) -> bool {
  use oxc_ast::ast::Argument;
  call.arguments.len() >= 2
    && matches!(
      call.arguments.get(1),
      Some(Argument::ArrowFunctionExpression(_) | Argument::FunctionExpression(_))
    )
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::parser::parse_sfc;

  fn scan(source: &str) -> Vec<Box<dyn Diagnostic>> {
    let mut ctx = ScanContext::new("test.vue".into(), source.to_string());
    parse_sfc(&mut ctx);
    NoWatchWithCallback.check(&ctx)
  }

  #[test]
  fn no_violation_when_watch_has_no_callback() {
    let src = r#"<script setup>
const r = ref(0)
watch(r, null)
</script>"#;
    assert!(scan(src).is_empty());
  }

  #[test]
  fn flags_watch_with_callback() {
    let src = r#"<script setup>
const r = ref(0)
watch(r, (n) => { console.log(n) })
</script>"#;
    assert_eq!(scan(src).len(), 1);
  }

  #[test]
  fn flags_watch_with_function_argument() {
    let src = r#"<script setup>
const r = ref(0)
watch(r, function (n) { console.log(n) })
</script>"#;
    assert_eq!(scan(src).len(), 1);
  }

  #[test]
  fn no_script_no_violation() {
    assert!(scan("").is_empty());
  }

  #[test]
  fn ignores_unrelated_call() {
    let src = r#"<script setup>
const r = ref(0)
something(r, (n) => n + 1)
</script>"#;
    assert!(scan(src).is_empty());
  }
}
