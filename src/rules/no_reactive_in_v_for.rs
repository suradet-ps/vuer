//! Flag reactive object creation (`ref`, `reactive`, `shallowRef`, ...)
//! inside loop bodies.
//!
//! Creating a reactive wrapper inside a `for`/`for...of`/`for...in` loop
//! or an array-iteration callback (`map`, `filter`, `forEach`, ...)
//! allocates a fresh wrapper and effect per iteration. The wrappers are
//! not owned by Vue's render tree, so they are never released when the
//! list changes — a silent per-render leak that grows with list size.
//!
//! Per-item derived *values* are fine (that is what the render already
//! does); the rule targets the reactive wrappers that carry per-iteration
//! state.
//!
//! Scope boundary (documented): the rule walks the `<script>` block.
//! Reactive calls reachable only through template expressions or
//! cross-file composables are not resolved. `computed` inside a loop
//! callback is included: each iteration allocates its own effect.

use miette::{Diagnostic, NamedSource, SourceSpan};
use oxc_allocator::Allocator;
use oxc_ast::ast::CallExpression;
use oxc_ast_visit::{Visit, walk};
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::script::{callee_path, parse_script};
use crate::rule_id::RuleId;
use crate::rules::{Category, Finding, Rule};
use crate::severity::Severity;

/// Reactive constructors that allocate per-call state and an effect.
const REACTIVE_CALLS: &[&str] = &[
  "ref",
  "reactive",
  "shallowRef",
  "shallowReactive",
  "computed",
];

/// Array iteration methods whose callback runs per element.
const ITERATION_METHODS: &[&str] = &[
  "map",
  "filter",
  "forEach",
  "flatMap",
  "reduce",
  "reduceRight",
  "flat",
  "some",
  "every",
];

#[derive(Error, Diagnostic, Debug)]
#[error("Reactive object created inside a loop body")]
#[diagnostic(
  code(vuer::performance::no_reactive_in_v_for),
  severity(Info),
  help(
    "Each iteration allocates a fresh reactive wrapper and effect that is \
     never released when the collection changes. Hoist the wrapper out of \
     the loop, or keep plain per-item values — the render already derives \
     them on demand."
  )
)]
pub struct NoReactiveInVForViolation {
  #[source_code]
  pub src: NamedSource<String>,
  #[label("reactive wrapper created per iteration")]
  pub span: SourceSpan,
}

pub struct NoReactiveInVFor;

impl Rule for NoReactiveInVFor {
  fn id(&self) -> RuleId {
    RuleId::new("vue/performance/no-reactive-in-v-for")
  }

  fn name(&self) -> &'static str {
    "no-reactive-in-v-for"
  }

  fn description(&self) -> &'static str {
    "Disallow reactive object creation inside loop bodies"
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
    let mut finder = ReactiveInLoopFinder {
      hits: Vec::new(),
      loop_depth: 0,
    };
    finder.visit_program(&program);

    for call_span in finder.hits {
      let absolute = (ctx.script_offset as u32 + call_span.start) as usize;
      violations.push(Finding::new(Box::new(NoReactiveInVForViolation {
        src: ctx.named_source.clone(),
        span: SourceSpan::new(absolute.into(), (call_span.end - call_span.start) as usize),
      })));
    }

    violations
  }
}

struct ReactiveInLoopFinder {
  hits: Vec<oxc_span::Span>,
  loop_depth: usize,
}

impl<'a> Visit<'a> for ReactiveInLoopFinder {
  fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
    let path = callee_path(call);
    if self.loop_depth > 0 && path.len() == 1 && REACTIVE_CALLS.contains(&path[0]) {
      self.hits.push(call.span);
      return;
    }
    if path.last().is_some_and(|m| ITERATION_METHODS.contains(m)) {
      // The callback of an iteration method is a loop body.
      self.loop_depth += 1;
      walk::walk_call_expression(self, call);
      self.loop_depth -= 1;
      return;
    }
    walk::walk_call_expression(self, call);
  }

  fn visit_for_statement(&mut self, stmt: &oxc_ast::ast::ForStatement<'a>) {
    self.loop_depth += 1;
    walk::walk_for_statement(self, stmt);
    self.loop_depth -= 1;
  }

  fn visit_for_in_statement(&mut self, stmt: &oxc_ast::ast::ForInStatement<'a>) {
    self.loop_depth += 1;
    walk::walk_for_in_statement(self, stmt);
    self.loop_depth -= 1;
  }

  fn visit_for_of_statement(&mut self, stmt: &oxc_ast::ast::ForOfStatement<'a>) {
    self.loop_depth += 1;
    walk::walk_for_of_statement(self, stmt);
    self.loop_depth -= 1;
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
    NoReactiveInVFor.check(&ctx)
  }

  #[test]
  fn flags_ref_inside_for_of() {
    let v = scan("for (const item of items) {\n  const r = ref(item)\n}");
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_reactive_inside_map_callback() {
    let v = scan("const wrapped = items.map((i) => reactive(i))");
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_computed_inside_filter_callback() {
    let v = scan("const seen = items.filter((i) => computed(() => i.n > 1))");
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_shallow_ref_inside_for_in() {
    let v = scan("for (const key in obj) {\n  shallowRef(obj[key])\n}");
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_ref_inside_classic_for() {
    let v = scan("for (let i = 0; i < items.length; i++) {\n  const r = ref(items[i])\n}");
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_nested_callback_inside_loop() {
    let v = scan("for (const g of groups) {\n  g.items.forEach((i) => ref(i))\n}");
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn ignores_ref_outside_loop() {
    let v = scan("const r = ref(items)\nconst doubled = items.map((i) => i * 2)");
    assert!(v.is_empty());
  }

  #[test]
  fn ignores_ref_inside_non_iteration_callback() {
    assert!(scan("promise.then((v) => ref(v))").is_empty());
  }

  #[test]
  fn ignores_plain_values_in_loop() {
    assert!(scan("const doubled = items.map((i) => i * 2)").is_empty());
  }

  #[test]
  fn ignores_member_call_named_ref() {
    assert!(scan("const x = items.map((i) => utils.ref(i))").is_empty());
  }

  #[test]
  fn no_script_no_violation() {
    assert!(scan("").is_empty());
  }
}
