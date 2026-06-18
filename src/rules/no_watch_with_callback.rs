use miette::{Diagnostic, NamedSource, SourceSpan};
use oxc_allocator::Allocator;
use oxc_ast::ast::{Argument, CallExpression, Expression};
use oxc_ast_visit::Visit;
use oxc_parser::Parser;
use oxc_span::SourceType;
use thiserror::Error;

use crate::context::{ScanContext, ScriptLang};
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
    let source_type = match ctx.lang {
      ScriptLang::TypeScript => SourceType::ts(),
      _ => SourceType::default(),
    };
    let parsed = Parser::new(&allocator, script, source_type).parse();
    if !parsed.diagnostics.is_empty() {
      return violations;
    }

    let mut visitor = WatchCallFinder {
      violations: &mut violations,
      named_source: &ctx.named_source,
      script_offset: ctx.script_offset,
    };
    visitor.visit_program(&parsed.program);

    violations
  }
}

struct WatchCallFinder<'a, 'b> {
  violations: &'a mut Vec<Box<dyn Diagnostic>>,
  named_source: &'b NamedSource<String>,
  script_offset: usize,
}

impl<'a, 'b> WatchCallFinder<'a, 'b> {
  fn report(&mut self, call: &CallExpression<'_>) {
    let span = call.span;
    let absolute = (self.script_offset as u32 + span.start) as usize;
    let len = (span.end - span.start) as usize;
    self.violations.push(Box::new(NoWatchWithCallbackViolation {
      src: self.named_source.clone(),
      span: SourceSpan::new(absolute.into(), len),
    }));
  }
}

impl<'a, 'b, 'c> Visit<'c> for WatchCallFinder<'a, 'b> {
  fn visit_call_expression(&mut self, call: &CallExpression<'c>) {
    if is_watch_call(call) && has_callback_argument(call) {
      self.report(call);
    }
    // Continue traversal: a watch call can appear inside a deeper expression.
    self.visit_arguments(&call.arguments);
    self.visit_expression(&call.callee);
  }
}

fn is_watch_call(call: &CallExpression<'_>) -> bool {
  matches!(&call.callee, Expression::Identifier(ident) if ident.name == "watch")
}

fn has_callback_argument(call: &CallExpression<'_>) -> bool {
  call.arguments.len() >= 2 && is_function_like_arg(&call.arguments[1])
}

fn is_function_like_arg(arg: &Argument<'_>) -> bool {
  match arg {
    Argument::ArrowFunctionExpression(_) => true,
    Argument::FunctionExpression(_) => true,
    _ => false,
  }
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
