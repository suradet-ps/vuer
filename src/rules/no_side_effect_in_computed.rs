//! Flag side effects inside `computed(() => ...)` getters.
//!
//! A computed getter must be a pure function of reactive state: Vue
//! re-evaluates it lazily and possibly re-runs it on every dependency
//! change, so anything it mutates, writes, or fires happens an
//! unpredictable number of times. The rule flags:
//!
//! * assignment / update expressions (`x = 1`, `x++`, `x += y`),
//! * calls to mutating collection / DOM methods (`push`, `splice`,
//!   `set`, `remove`, ...),
//! * calls to side-effecting APIs (`fetch`, `console.*`, `watch`,
//!   `setTimeout`, `axios.*`, `emit`, ...),
//! * `async` getters (Vue cannot await a computed — the getter returns a
//!   Promise, not the value).
//!
//! Nested function bodies are deliberately NOT descended into: a helper
//! that happens to be *declared* inside the getter is not executed
//! during evaluation. Options API `computed: { ... }` declarations are
//! out of scope (documented).

use miette::{Diagnostic, NamedSource, SourceSpan};
use oxc_allocator::Allocator;
use oxc_ast::ast::{
  ArrowFunctionExpression, CallExpression, Expression, Function, ObjectExpression,
  ObjectPropertyKind,
};
use oxc_ast_visit::{Visit, walk};
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::script::{callee_path, is_call_named, parse_script};
use crate::rule_id::RuleId;
use crate::rules::{Category, Finding, Rule};
use crate::severity::Severity;

/// Collection / DOM methods that mutate their receiver.
const MUTATING_METHODS: &[&str] = &[
  "push",
  "pop",
  "shift",
  "unshift",
  "splice",
  "sort",
  "reverse",
  "fill",
  "copyWithin",
  "set",
  "add",
  "delete",
  "clear",
  "write",
  "writeln",
  "open",
  "close",
  "assign",
  "setItem",
  "removeItem",
  "setAttribute",
  "removeAttribute",
  "setProperty",
  "removeProperty",
  "appendChild",
  "insertBefore",
  "replaceChild",
  "removeChild",
];

#[derive(Error, Diagnostic, Debug)]
#[error("Side effect inside a `computed` getter")]
#[diagnostic(
  code(vuer::architecture::no_side_effect_in_computed),
  severity(Warning),
  help(
    "A computed getter must be pure: Vue re-evaluates it lazily and \
     unpredictably, so mutations, writes, `fetch`, `watch`, `console`, and \
     `emit` inside it fire an unknown number of times. Move the side effect \
     to a `watch`/event handler, or use a plain `function`. An `async` \
     getter returns a Promise, which Vue cannot react to."
  )
)]
pub struct NoSideEffectInComputedViolation {
  #[source_code]
  pub src: NamedSource<String>,
  #[label("`computed` with side effects")]
  pub span: SourceSpan,
}

pub struct NoSideEffectInComputed;

impl Rule for NoSideEffectInComputed {
  fn id(&self) -> RuleId {
    RuleId::new("vue/architecture/no-side-effect-in-computed")
  }

  fn name(&self) -> &'static str {
    "no-side-effect-in-computed"
  }

  fn description(&self) -> &'static str {
    "Disallow side effects inside `computed(...)` getters"
  }

  fn severity(&self) -> Severity {
    Severity::Medium
  }

  fn category(&self) -> Category {
    Category::Architecture
  }

  fn check(&self, ctx: &ScanContext) -> Vec<Finding> {
    let mut violations = Vec::new();
    let Some(script) = ctx.script.as_ref() else {
      return violations;
    };

    let allocator = Allocator::default();
    let program = parse_script(&allocator, script, ctx.lang.clone());
    let mut finder = ComputedFinder { hits: Vec::new() };
    finder.visit_program(&program);

    for call_span in finder.hits {
      let absolute = (ctx.script_offset as u32 + call_span.start) as usize;
      violations.push(Finding::new(Box::new(NoSideEffectInComputedViolation {
        src: ctx.named_source.clone(),
        span: SourceSpan::new(absolute.into(), (call_span.end - call_span.start) as usize),
      })));
    }

    violations
  }
}

struct ComputedFinder {
  hits: Vec<oxc_span::Span>,
}

impl<'a> Visit<'a> for ComputedFinder {
  fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
    if is_call_named(call, &["computed"]) && has_side_effect_getter(call) {
      self.hits.push(call.span);
    }
    walk::walk_call_expression(self, call);
  }
}

/// Whether the first argument of `computed(...)` is a getter that
/// contains side effects (or is async).
fn has_side_effect_getter(call: &CallExpression<'_>) -> bool {
  let Some(expr) = call.arguments.first().and_then(|a| a.as_expression()) else {
    return false;
  };
  match expr {
    // `computed(() => ...)` / `computed(function () { ... })`
    Expression::ArrowFunctionExpression(arrow) => arrow_getter_has_side_effects(arrow),
    Expression::FunctionExpression(f) => f.r#async || getter_function_has_side_effects(f),
    // `computed({ get() { ... } })` — only the getter is checked.
    Expression::ObjectExpression(obj) => getter_property_has_side_effects(obj),
    _ => false,
  }
}

fn getter_function_has_side_effects(f: &Function<'_>) -> bool {
  let Some(body) = &f.body else {
    return false;
  };
  let mut detector = SideEffectDetector { found: f.r#async };
  for stmt in &body.statements {
    detector.visit_statement(stmt);
  }
  detector.found
}

/// A `computed({ get() { ... } })` call: analyse the `get` property only.
fn getter_property_has_side_effects(obj: &ObjectExpression<'_>) -> bool {
  obj.properties.iter().any(|prop| {
    let ObjectPropertyKind::ObjectProperty(p) = prop else {
      return false;
    };
    if p.key.static_name().as_deref() != Some("get") {
      return false;
    }
    match &p.value {
      Expression::ArrowFunctionExpression(arrow) => arrow_getter_has_side_effects(arrow),
      Expression::FunctionExpression(f) => f.r#async || getter_function_has_side_effects(f),
      _ => false,
    }
  })
}

fn arrow_getter_has_side_effects(arrow: &ArrowFunctionExpression<'_>) -> bool {
  let mut detector = SideEffectDetector {
    found: arrow.r#async,
  };
  if let Some(body) = arrow.body.as_function_body() {
    for stmt in &body.statements {
      detector.visit_statement(stmt);
    }
  } else if let Some(expr) = arrow.body.as_expression() {
    detector.visit_expression(expr);
  }
  detector.found
}

/// Walks a getter body looking for side effects. Nested function bodies
/// are skipped: they are only *declared* during evaluation.
struct SideEffectDetector {
  found: bool,
}

impl<'a> Visit<'a> for SideEffectDetector {
  fn visit_assignment_expression(&mut self, _: &oxc_ast::ast::AssignmentExpression<'a>) {
    self.found = true;
  }

  fn visit_update_expression(&mut self, _: &oxc_ast::ast::UpdateExpression<'a>) {
    self.found = true;
  }

  fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
    if is_side_effect_call(call) {
      self.found = true;
    }
    walk::walk_call_expression(self, call);
  }

  fn visit_function(&mut self, _: &Function<'a>, _: oxc_syntax::scope::ScopeFlags) {
    // Declared, not executed, during evaluation.
  }

  fn visit_arrow_function_expression(&mut self, _: &ArrowFunctionExpression<'a>) {
    // Same: a nested callback is not invoked by the getter itself.
  }
}

fn is_side_effect_call(call: &CallExpression<'_>) -> bool {
  let path = callee_path(call);
  match path.as_slice() {
    [] => false,
    ["fetch"]
    | ["alert"]
    | ["confirm"]
    | ["prompt"]
    | ["setTimeout"]
    | ["setInterval"]
    | ["watch"]
    | ["watchEffect"]
    | ["nextTick"]
    | ["emit"] => true,
    [head, ..] if *head == "console" || *head == "axios" => true,
    [.., last] if last.len() >= 2 && MUTATING_METHODS.contains(last) => true,
    _ => false,
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::parser::parse_sfc;

  fn scan(script: &str) -> Vec<Finding> {
    let source = format!("<script setup>\n{script}\n</script>");
    let mut ctx = ScanContext::new("test.vue".into(), source);
    parse_sfc(&mut ctx);
    NoSideEffectInComputed.check(&ctx)
  }

  #[test]
  fn flags_assignment_in_computed() {
    let v = scan("const c = computed(() => { count = 1; return count })");
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_update_expression_in_computed() {
    let v = scan("const c = computed(() => { count++; return count })");
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_push_in_computed() {
    let v = scan("const c = computed(() => { list.push(x); return list })");
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_fetch_in_computed() {
    let v = scan("const c = computed(() => fetch('/api'))");
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_console_in_computed() {
    let v = scan("const c = computed(() => { console.log('x'); return 1 })");
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_watch_inside_computed() {
    let v = scan("const c = computed(() => { watch(a, cb); return 1 })");
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_async_computed() {
    let v = scan("const c = computed(async () => 42)");
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_async_get_in_object_form() {
    let v = scan("const c = computed({ async get() { return 1 } })");
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_side_effect_in_object_get() {
    let v = scan("const c = computed({ get() { items.push(x); return 1 } })");
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn ignores_pure_computed() {
    assert!(scan("const c = computed(() => count * 2)").is_empty());
  }

  #[test]
  fn ignores_arrow_body_with_nested_callback() {
    // The nested `map` callback is not executed during evaluation.
    let v = scan("const c = computed(() => items.map((i) => { list.push(i); return i }))");
    assert!(v.is_empty());
  }

  #[test]
  fn ignores_declared_helper_function() {
    let v = scan("const c = computed(() => { const helper = () => { count = 1 }; return 1 })");
    assert!(v.is_empty());
  }

  #[test]
  fn ignores_get_in_object_form_without_effects() {
    assert!(scan("const c = computed({ get() { return count * 2 } })").is_empty());
  }

  #[test]
  fn ignores_non_computed_calls() {
    let v = scan("const c = something(() => { count++; return 1 })");
    assert!(v.is_empty());
  }

  #[test]
  fn no_script_no_violation() {
    assert!(scan("").is_empty());
  }
}
