//! Flag `watch(source, callback, { deep: true })` watchers that traverse
//! the entire object graph on every change.
//!
//! A `deep: true` watcher re-runs its comparison over the whole nested
//! object on every mutation, which is the single most common source of
//! Vue performance problems in large components. The cheaper patterns
//! are watching an explicit path (`() => obj.field`) or, when only the
//! first notification matters (Vue 3.4+), `{ once: true }`.
//!
//! Scope boundary (documented): only the composition `watch()` call form
//! with an inline options object is analysed. Options API
//! `watch: { key: { deep: true } }` declarations and options objects
//! stored in a variable are not resolved — that would require
//! cross-statement constant resolution the rule deliberately avoids.

use miette::{Diagnostic, NamedSource, SourceSpan};
use oxc_allocator::Allocator;
use oxc_ast::ast::{Argument, CallExpression, Expression};
use oxc_ast_visit::{Visit, walk};
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::script::{is_call_named, parse_script};
use crate::rule_id::RuleId;
use crate::rules::{Category, Finding, Rule};
use crate::severity::Severity;

#[derive(Error, Diagnostic, Debug)]
#[error("`watch(..., {{ deep: true }})` traverses the whole object graph on every change")]
#[diagnostic(
  code(vuer::performance::no_deep_watch_without_handler),
  severity(Info),
  help(
    "Deep watchers re-compare every nested property on each mutation, which \
     degrades as the object grows. Prefer watching an explicit path \
     (`() => obj.field`), splitting the watcher per field, or `{{ once: true }}` \
     when only the first notification is needed."
  )
)]
pub struct NoDeepWatchWithoutHandlerViolation {
  #[source_code]
  pub src: NamedSource<String>,
  #[label("`deep: true` watcher here")]
  pub span: SourceSpan,
}

pub struct NoDeepWatchWithoutHandler;

impl Rule for NoDeepWatchWithoutHandler {
  fn id(&self) -> RuleId {
    RuleId::new("vue/performance/no-deep-watch-without-handler")
  }

  fn name(&self) -> &'static str {
    "no-deep-watch-without-handler"
  }

  fn description(&self) -> &'static str {
    "Warn about `watch(source, callback, { deep: true })` watchers that traverse the whole object on every change"
  }

  fn severity(&self) -> Severity {
    Severity::Low
  }

  fn category(&self) -> Category {
    Category::Performance
  }

  fn check(&self, ctx: &ScanContext) -> Vec<Finding> {
    let mut violations = Vec::new();
    let Some(script) = ctx.script.as_ref() else {
      return violations;
    };

    let allocator = Allocator::default();
    let program = parse_script(&allocator, script, ctx.lang.clone());
    let mut finder = DeepWatchFinder { hits: Vec::new() };
    finder.visit_program(&program);

    for call_span in finder.hits {
      let absolute = (ctx.script_offset as u32 + call_span.start) as usize;
      violations.push(Finding::new(Box::new(NoDeepWatchWithoutHandlerViolation {
        src: ctx.named_source.clone(),
        span: SourceSpan::new(absolute.into(), (call_span.end - call_span.start) as usize),
      })));
    }

    violations
  }
}

struct DeepWatchFinder {
  hits: Vec<oxc_span::Span>,
}

impl<'a> Visit<'a> for DeepWatchFinder {
  fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
    if is_call_named(call, &["watch"]) && has_deep_true_options(call) {
      self.hits.push(call.span);
    }
    walk::walk_call_expression(self, call);
  }
}

/// `watch(src, cb, { deep: true })` with an inline options object whose
/// `deep` is the literal `true` and which does not also pass `once: true`
/// (a once-watcher fires exactly once, so deep traversal is not the cost).
fn has_deep_true_options(call: &CallExpression<'_>) -> bool {
  let Some(Argument::ObjectExpression(options)) = call.arguments.get(2) else {
    return false;
  };
  let mut deep = false;
  let mut once = false;
  for prop in &options.properties {
    let Some(prop) = prop.as_property() else {
      continue;
    };
    let Some(key) = prop.key.static_name() else {
      continue;
    };
    match (key.as_ref(), &prop.value) {
      ("deep", Expression::BooleanLiteral(lit)) => deep = lit.value,
      ("once", Expression::BooleanLiteral(lit)) => once = lit.value,
      _ => {}
    }
  }
  deep && !once
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::parser::parse_sfc;

  fn scan(script: &str) -> Vec<Finding> {
    let source = format!("<script setup>\n{script}\n</script>");
    let mut ctx = ScanContext::new("test.vue".into(), source);
    parse_sfc(&mut ctx);
    NoDeepWatchWithoutHandler.check(&ctx)
  }

  #[test]
  fn flags_deep_watch_with_options_object() {
    let v = scan("watch(form, (v) => console.log(v), { deep: true })");
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_deep_true_watch_on_ref() {
    let v =
      scan("const user = ref({ name: '' })\nwatch(user, (u) => console.log(u), { deep: true })");
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn ignores_watch_without_options() {
    assert!(scan("watch(form, (v) => console.log(v))").is_empty());
  }

  #[test]
  fn ignores_watch_with_plain_options() {
    assert!(scan("watch(form, (v) => console.log(v), { immediate: true })").is_empty());
  }

  #[test]
  fn ignores_deep_false() {
    assert!(scan("watch(form, (v) => console.log(v), { deep: false })").is_empty());
  }

  #[test]
  fn ignores_deep_with_once() {
    // Fires at most once; the traversal cost is bounded.
    assert!(scan("watch(form, (v) => console.log(v), { deep: true, once: true })").is_empty());
  }

  #[test]
  fn ignores_variable_options_object() {
    // Boundary: options stored in a variable are not resolved.
    assert!(
      scan("const opts = { deep: true }\nwatch(form, (v) => console.log(v), opts)").is_empty()
    );
  }

  #[test]
  fn ignores_non_watch_calls() {
    assert!(scan("fetch(form, { deep: true })").is_empty());
  }

  #[test]
  fn no_script_no_violation() {
    assert!(scan("").is_empty());
  }
}
