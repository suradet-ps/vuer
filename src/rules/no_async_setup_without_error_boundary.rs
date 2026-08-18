//! Flag `async setup()` in a component whose template contains no
//! `<Suspense>` boundary.
//!
//! **Heuristic, low severity (documented).** Vue 3 requires an `async
//! setup()` component to be wrapped in `<Suspense>` at the *parent* to
//! show a loading fallback while the promise resolves; without it the
//! component renders nothing until the promise settles. The rule cannot
//! see the parent's template, so it uses the component's own template as
//! a proxy: an `async setup()` with no `<Suspense>` in the same file is
//! reported, and the diagnostic invites suppression with
//! `vuer-ignore[no-async-setup-without-error-boundary]` when the
//! component is always mounted inside a router-level `Suspense`.
//!
//! Detection: any async function named `setup` in an object literal
//! (`export default { async setup() {} }`, `setup: async () => {}`,
//! `defineComponent({...})`, ...).

use miette::{Diagnostic, NamedSource, SourceSpan};
use oxc_allocator::Allocator;
use oxc_ast::ast::{Expression, ObjectPropertyKind};
use oxc_ast_visit::{Visit, walk};
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::script::parse_script;
use crate::rule_id::RuleId;
use crate::rules::{Category, Finding, Rule};
use crate::severity::Severity;
use crate::visitor::for_each_element;

#[derive(Error, Diagnostic, Debug)]
#[error("`async setup()` has no `<Suspense>` boundary")]
#[diagnostic(
  code(vuer::architecture::no_async_setup_without_error_boundary),
  severity(Info),
  help(
    "Vue 3 requires an `async setup()` component to be wrapped in \
     `<Suspense>` (at the parent) to render a fallback while the promise \
     resolves. If this component is always mounted inside a router-level \
     `Suspense`, silence with `vuer-ignore[no-async-setup-without-error-boundary]`."
  )
)]
pub struct NoAsyncSetupWithoutErrorBoundaryViolation {
  #[source_code]
  pub src: NamedSource<String>,
  #[label("async setup here")]
  pub span: SourceSpan,
}

pub struct NoAsyncSetupWithoutErrorBoundary;

impl Rule for NoAsyncSetupWithoutErrorBoundary {
  fn id(&self) -> RuleId {
    RuleId::new("vue/architecture/no-async-setup-without-error-boundary")
  }

  fn name(&self) -> &'static str {
    "no-async-setup-without-error-boundary"
  }

  fn description(&self) -> &'static str {
    "Heuristic: `async setup()` without a `<Suspense>` boundary"
  }

  fn severity(&self) -> Severity {
    Severity::Low
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
    let mut finder = AsyncSetupFinder { hits: Vec::new() };
    finder.visit_program(&program);

    // A `<Suspense>` in the same template makes the boundary explicit.
    let has_suspense = ctx.template_ast.as_ref().is_some_and(|root| {
      let mut found = false;
      for_each_element(root, |el| {
        if el.name.eq_ignore_ascii_case("suspense") {
          found = true;
        }
      });
      found
    });
    if has_suspense {
      return violations;
    }

    for span in finder.hits {
      let absolute = (ctx.script_offset as u32 + span.start) as usize;
      violations.push(Finding::new(Box::new(
        NoAsyncSetupWithoutErrorBoundaryViolation {
          src: ctx.named_source.clone(),
          span: SourceSpan::new(absolute.into(), (span.end - span.start) as usize),
        },
      )));
    }

    violations
  }
}

struct AsyncSetupFinder {
  hits: Vec<oxc_span::Span>,
}

impl<'a> Visit<'a> for AsyncSetupFinder {
  fn visit_object_expression(&mut self, obj: &oxc_ast::ast::ObjectExpression<'a>) {
    for prop in &obj.properties {
      let ObjectPropertyKind::ObjectProperty(prop) = prop else {
        continue;
      };
      if prop.key.static_name().as_deref() != Some("setup") {
        continue;
      }
      let is_async = match &prop.value {
        Expression::FunctionExpression(f) => f.r#async,
        Expression::ArrowFunctionExpression(a) => a.r#async,
        _ => false,
      };
      if is_async {
        self.hits.push(prop.span);
      }
    }
    walk::walk_object_expression(self, obj);
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::parser::parse_sfc;

  fn scan_with_template(template: &str, script: &str) -> Vec<Finding> {
    let source = format!("<template>\n{template}\n</template>\n<script>\n{script}\n</script>");
    let mut ctx = ScanContext::new("test.vue".into(), source);
    parse_sfc(&mut ctx);
    NoAsyncSetupWithoutErrorBoundary.check(&ctx)
  }

  fn scan(script: &str) -> Vec<Finding> {
    scan_with_template("<div>hi</div>", script)
  }

  #[test]
  fn flags_async_setup_method() {
    let v = scan(
      "export default {\n  async setup() {\n    const data = await fetch('/api')\n    return { data }\n  }\n}",
    );
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_async_setup_arrow_property() {
    let v =
      scan("export default {\n  setup: async () => {\n    return { data: await load() }\n  }\n}");
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_async_setup_inside_define_component() {
    let v = scan("const comp = defineComponent({\n  async setup() { return {} }\n})");
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn ignores_sync_setup() {
    assert!(scan("export default {\n  setup() {\n    return { x: 1 }\n  }\n}").is_empty());
  }

  #[test]
  fn ignores_sync_arrow_setup() {
    assert!(scan("export default {\n  setup: () => ({ x: 1 })\n}").is_empty());
  }

  #[test]
  fn ignores_async_setup_with_sibling_suspense() {
    let v = scan_with_template(
      "<Suspense><div/></Suspense>",
      "export default {\n  async setup() { return {} }\n}",
    );
    assert!(v.is_empty());
  }

  #[test]
  fn ignores_setup_like_functions() {
    assert!(scan("export default {\n  async setupForm() { return {} }\n}").is_empty());
  }

  #[test]
  fn ignores_module_scope_async_function() {
    assert!(scan("async function setup() { return {} }").is_empty());
  }

  #[test]
  fn no_script_no_violation() {
    assert!(scan("").is_empty());
  }
}
