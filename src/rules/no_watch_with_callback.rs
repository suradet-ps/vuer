//! Flag `watch(source, callback)` calls that have no owner to dispose
//! them.
//!
//! Vue 3 disposes watchers automatically when they are created inside a
//! component scope:
//!
//! * `<script setup>` — every top-level statement runs inside the
//!   component's setup scope; watchers are stopped with the component.
//! * Options API — `this.$watch` is bound to the instance and stopped
//!   on unmount; a `watch()` call inside `setup()`/`created()`/... is
//!   equally owned by the instance.
//!
//! The one place a `watch()` call genuinely leaks is **module scope** in
//! a plain `<script>` block (no `setup` attribute): the watcher is
//! created once when the module loads, has no component lifecycle to be
//! torn down with, and keeps its closure alive until the page unloads.
//!
//! Detection (module scope only):
//! 1. Skip the whole rule when the `<script>` block is `<script setup>`
//!    (auto-disposed).
//! 2. In a plain `<script>`, find calls whose callee is exactly `watch`
//!    with a function as the second argument, and keep only the ones at
//!    module top level — not nested inside a function, class, or object
//!    literal (e.g. an `export default { ... }` component definition).

use miette::{Diagnostic, NamedSource, SourceSpan};
use oxc_allocator::Allocator;
use oxc_ast::ast::{ArrowFunctionExpression, CallExpression, Class, Function, ObjectExpression};
use oxc_ast_visit::{Visit, walk};
use oxc_syntax::scope::ScopeFlags;
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::script::{is_call_named, parse_script};
use crate::rule_id::RuleId;
use crate::rules::{Category, Finding, Rule};
use crate::severity::Severity;

#[derive(Error, Diagnostic, Debug)]
#[error("`watch` at module scope has no component lifecycle to dispose it")]
#[diagnostic(
  code(vuer::best_practice::no_watch_with_callback),
  severity(Info),
  help(
    "In `<script setup>` and Options API, Vue disposes watchers automatically \
     with the component. A module-scope `watch` (outside any component) has no \
     owner and keeps its closure alive until the page unloads — move it into a \
     component, or stop it explicitly with the returned stop handle."
  )
)]
pub struct NoWatchWithCallbackViolation {
  #[source_code]
  pub src: NamedSource<String>,
  #[label("module-scope `watch(source, callback)` call here")]
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
    "Warn about `watch(source, callback)` calls at module scope that have no owner to dispose them"
  }

  fn severity(&self) -> Severity {
    Severity::Low
  }

  fn category(&self) -> Category {
    Category::BestPractice
  }

  fn check(&self, ctx: &ScanContext) -> Vec<Finding> {
    let mut violations = Vec::new();
    let Some(script) = ctx.script.as_ref() else {
      return violations;
    };
    // `<script setup>`: watchers are created inside the component's
    // setup scope and disposed with it — nothing to flag.
    if ctx.script_setup {
      return violations;
    }

    let allocator = Allocator::default();
    let program = parse_script(&allocator, script, ctx.lang.clone());
    let mut finder = WatchFinder {
      hits: Vec::new(),
      depth: 0,
    };
    finder.visit_program(&program);

    for call_span in finder.hits {
      let absolute = (ctx.script_offset as u32 + call_span.start) as usize;
      violations.push(Finding::new(Box::new(NoWatchWithCallbackViolation {
        src: ctx.named_source.clone(),
        span: SourceSpan::new(absolute.into(), (call_span.end - call_span.start) as usize),
      })));
    }

    violations
  }
}

struct WatchFinder {
  /// Spans of module-scope `watch(source, callback)` calls.
  hits: Vec<oxc_span::Span>,
  /// How many scope-creating nodes (functions, classes, object
  /// literals) we are nested inside. Depth 0 = module scope.
  depth: usize,
}

impl<'a> Visit<'a> for WatchFinder {
  fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
    if self.depth == 0 && is_call_named(call, &["watch"]) && has_function_arg(call) {
      self.hits.push(call.span);
    }
    walk::walk_call_expression(self, call);
  }

  fn visit_function(&mut self, f: &Function<'a>, flags: ScopeFlags) {
    self.depth += 1;
    walk::walk_function(self, f, flags);
    self.depth -= 1;
  }

  fn visit_arrow_function_expression(&mut self, f: &ArrowFunctionExpression<'a>) {
    self.depth += 1;
    walk::walk_arrow_function_expression(self, f);
    self.depth -= 1;
  }

  fn visit_object_expression(&mut self, o: &ObjectExpression<'a>) {
    self.depth += 1;
    walk::walk_object_expression(self, o);
    self.depth -= 1;
  }

  fn visit_class(&mut self, c: &Class<'a>) {
    self.depth += 1;
    walk::walk_class(self, c);
    self.depth -= 1;
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

  /// Scan a `<script setup>` block (watchers auto-disposed).
  fn scan_setup(script: &str) -> Vec<Finding> {
    let source = format!("<script setup>\n{script}\n</script>");
    let mut ctx = ScanContext::new("test.vue".into(), source);
    parse_sfc(&mut ctx);
    NoWatchWithCallback.check(&ctx)
  }

  /// Scan a plain `<script>` block (module scope).
  fn scan_plain(script: &str) -> Vec<Finding> {
    let source = format!("<script>\n{script}\n</script>");
    let mut ctx = ScanContext::new("test.vue".into(), source);
    parse_sfc(&mut ctx);
    NoWatchWithCallback.check(&ctx)
  }

  #[test]
  fn skips_watch_in_script_setup() {
    // Vue 3 disposes setup-scope watchers with the component.
    let v = scan_setup("const r = ref(0)\nwatch(r, (n) => { console.log(n) })");
    assert!(v.is_empty());
  }

  #[test]
  fn flags_module_scope_watch_in_plain_script() {
    let v = scan_plain("const r = ref(0)\nwatch(r, (n) => { console.log(n) })");
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_module_scope_watch_with_function_argument() {
    let v = scan_plain("const r = ref(0)\nwatch(r, function (n) { console.log(n) })");
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn skips_watch_inside_export_default() {
    // Options API: `watch` inside the component definition is owned by
    // the instance (and would not even run at module scope).
    let v = scan_plain(
      "export default {\n  created() {\n    watch(this.msg, (n) => console.log(n))\n  }\n}",
    );
    assert!(v.is_empty());
  }

  #[test]
  fn skips_watch_inside_function_in_plain_script() {
    let v = scan_plain(
      "function setup() {\n  watch(a, (n) => console.log(n))\n}\nwatch(b, (n) => console.log(n))",
    );
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn skips_watch_inside_arrow_and_object() {
    let v = scan_plain(
      "const fn = () => watch(a, (n) => console.log(n))\n\
       const cfg = { hook: watch(b, (n) => console.log(n)) }",
    );
    assert!(v.is_empty());
  }

  #[test]
  fn no_violation_when_watch_has_no_callback() {
    let v = scan_plain("const r = ref(0)\nwatch(r, null)");
    assert!(v.is_empty());
  }

  #[test]
  fn ignores_unrelated_call() {
    let v = scan_plain("const r = ref(0)\nsomething(r, (n) => n + 1)");
    assert!(v.is_empty());
  }

  #[test]
  fn no_script_no_violation() {
    assert!(scan_plain("").is_empty());
    assert!(scan_setup("").is_empty());
  }
}
