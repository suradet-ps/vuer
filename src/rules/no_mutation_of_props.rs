//! Flag writes to props declared via `defineProps`.
//!
//! Props are read-only one-way data flow: the parent owns the state. A
//! write (`props.x = 1`, `props.x++`, or an assignment to a
//! destructured prop) silently diverges the child from the parent —
//! Vue logs a dev-time warning and the change is lost on the next
//! parent re-render. The fix is to `emit` an event and let the parent
//! update its own state.
//!
//! Detection covers `<script setup>`:
//!
//! * `const props = defineProps({...})` / `const props =
//!   withDefaults(defineProps<...>(), {...})` → writes to `props.<field>`
//!   and `props['field']`,
//! * `const { a, b } = defineProps({...})` → writes to `a` / `b`
//!   (assignment or update).
//!
//! Options API `this.x = ...` writes are out of scope (documented).

use miette::{Diagnostic, NamedSource, SourceSpan};
use oxc_allocator::Allocator;
use oxc_ast::ast::{
  AssignmentExpression, AssignmentTarget, Expression, SimpleAssignmentTarget, UpdateExpression,
  VariableDeclaration, VariableDeclarator,
};
use oxc_ast_visit::{Visit, walk};
use oxc_syntax::operator::{AssignmentOperator, UpdateOperator};
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::script::{is_call_named, parse_script};
use crate::rule_id::RuleId;
use crate::rules::{Category, Finding, Rule};
use crate::severity::Severity;

#[derive(Error, Diagnostic, Debug)]
#[error("Mutation of a `defineProps` prop breaks one-way data flow")]
#[diagnostic(
  code(vuer::architecture::no_mutation_of_props),
  severity(Warning),
  help(
    "Props are owned by the parent; writing `props.x = ...` (or to a \
     destructured prop) diverges the child from the parent and the change is \
     lost on the next re-render. `emit` an event and let the parent update \
     its own state."
  )
)]
pub struct NoMutationOfPropsViolation {
  #[source_code]
  pub src: NamedSource<String>,
  #[label("props write here")]
  pub span: SourceSpan,
}

pub struct NoMutationOfProps;

impl Rule for NoMutationOfProps {
  fn id(&self) -> RuleId {
    RuleId::new("vue/architecture/no-mutation-of-props")
  }

  fn name(&self) -> &'static str {
    "no-mutation-of-props"
  }

  fn description(&self) -> &'static str {
    "Disallow writes to props declared with `defineProps`"
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
    let mut finder = PropsMutationFinder {
      props_binding: None,
      destructured: Vec::new(),
      hits: Vec::new(),
    };
    finder.visit_program(&program);

    for span in finder.hits {
      let absolute = (ctx.script_offset as u32 + span.start) as usize;
      violations.push(Finding::new(Box::new(NoMutationOfPropsViolation {
        src: ctx.named_source.clone(),
        span: SourceSpan::new(absolute.into(), (span.end - span.start) as usize),
      })));
    }

    violations
  }
}

struct PropsMutationFinder {
  /// The identifier bound to the whole props object, if any.
  props_binding: Option<String>,
  /// Prop names destructured out of `defineProps`, if any.
  destructured: Vec<String>,
  hits: Vec<oxc_span::Span>,
}

impl<'a> Visit<'a> for PropsMutationFinder {
  fn visit_variable_declaration(&mut self, decl: &VariableDeclaration<'a>) {
    if !decl.kind.is_const() {
      return;
    }
    for declarator in &decl.declarations {
      self.record_props_binding(declarator);
    }
    walk::walk_variable_declaration(self, decl);
  }

  fn visit_assignment_expression(&mut self, expr: &AssignmentExpression<'a>) {
    if expr.operator == AssignmentOperator::Assign && self.is_props_write(&expr.left) {
      self.hits.push(expr.span);
    }
    walk::walk_assignment_expression(self, expr);
  }

  fn visit_update_expression(&mut self, expr: &UpdateExpression<'a>) {
    if matches!(
      expr.operator,
      UpdateOperator::Increment | UpdateOperator::Decrement
    ) && self.is_props_write_simple(&expr.argument)
    {
      self.hits.push(expr.span);
    }
    walk::walk_update_expression(self, expr);
  }
}

impl PropsMutationFinder {
  /// `const props = defineProps(...)` (incl. `withDefaults` wrappers)
  /// and `const { a, b } = defineProps(...)`.
  fn record_props_binding(&mut self, declarator: &VariableDeclarator<'_>) {
    let Some(init) = &declarator.init else {
      return;
    };
    if is_props_call(init) {
      if let Some(ident) = declarator.id.get_identifier_name() {
        self.props_binding = Some(ident.as_str().to_string());
      }
      if let oxc_ast::ast::BindingPattern::ObjectPattern(pattern) = &declarator.id {
        for prop in &pattern.properties {
          let Some(name) = prop.value.get_identifier_name() else {
            continue;
          };
          self.destructured.push(name.as_str().to_string());
        }
      }
    }
  }

  /// Is the left side of an assignment a write to a prop?
  fn is_props_write(&self, target: &AssignmentTarget<'_>) -> bool {
    match target {
      AssignmentTarget::AssignmentTargetIdentifier(ident) => {
        self.destructured.iter().any(|p| p == ident.name.as_str())
      }
      AssignmentTarget::StaticMemberExpression(member) => {
        self.is_props_object(&member.object) && member.property.name != "__proto__"
      }
      AssignmentTarget::ComputedMemberExpression(member) => {
        // `props['x'] = ...` — the key may be dynamic; any member write
        // to the props object is a props write.
        self.is_props_object(&member.object)
      }
      _ => false,
    }
  }

  /// Same check for update-expression targets (`props.x++`).
  fn is_props_write_simple(&self, target: &SimpleAssignmentTarget<'_>) -> bool {
    match target {
      SimpleAssignmentTarget::AssignmentTargetIdentifier(ident) => {
        self.destructured.iter().any(|p| p == ident.name.as_str())
      }
      SimpleAssignmentTarget::StaticMemberExpression(member) => {
        self.is_props_object(&member.object)
      }
      SimpleAssignmentTarget::ComputedMemberExpression(member) => {
        self.is_props_object(&member.object)
      }
      _ => false,
    }
  }

  fn is_props_object(&self, object: &Expression<'_>) -> bool {
    match object {
      Expression::Identifier(ident) => self.props_binding.as_deref() == Some(ident.name.as_str()),
      _ => false,
    }
  }
}

/// `defineProps(...)` directly, or `withDefaults(defineProps(...), ...)`.
fn is_props_call(expr: &Expression<'_>) -> bool {
  let call = match expr {
    Expression::CallExpression(call) => call,
    _ => return false,
  };
  if is_call_named(call, &["defineProps"]) {
    return true;
  }
  if is_call_named(call, &["withDefaults"])
    && let Some(inner) = call.arguments.first().and_then(|a| a.as_expression())
    && let Expression::CallExpression(inner_call) = inner
    && is_call_named(inner_call, &["defineProps"])
  {
    return true;
  }
  false
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::parser::parse_sfc;

  fn scan_with_lang(script: &str, lang: &str) -> Vec<Finding> {
    let source = format!("<script setup lang=\"{lang}\">\n{script}\n</script>");
    let mut ctx = ScanContext::new("test.vue".into(), source);
    parse_sfc(&mut ctx);
    NoMutationOfProps.check(&ctx)
  }

  fn scan(script: &str) -> Vec<Finding> {
    scan_with_lang(script, "js")
  }

  #[test]
  fn flags_props_member_assignment() {
    let v = scan("const props = defineProps({ msg: String })\nprops.msg = 'x'");
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_props_member_update() {
    let v = scan("const props = defineProps({ count: Number })\nprops.count++");
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_props_computed_member_write() {
    let v = scan("const props = defineProps({ msg: String })\nprops['msg'] = 'x'");
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_destructured_prop_assignment() {
    let v = scan("const { msg } = defineProps({ msg: String })\nmsg = 'x'");
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_destructured_prop_update() {
    let v = scan("const { count } = defineProps({ count: Number })\ncount++");
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_with_defaults_wrapper() {
    let v = scan_with_lang(
      "const props = withDefaults(defineProps<{ msg: string }>(), { msg: '' })\nprops.msg = 'x'",
      "ts",
    );
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_multiple_writes() {
    let v =
      scan("const props = defineProps({ a: String, b: String })\nprops.a = '1'\nprops.b = '2'");
    assert_eq!(v.len(), 2);
  }

  #[test]
  fn ignores_reads_of_props() {
    assert!(
      scan("const props = defineProps({ msg: String })\nconst out = props.msg.toUpperCase()")
        .is_empty()
    );
  }

  #[test]
  fn ignores_unrelated_assignments() {
    let v = scan(
      "const props = defineProps({ msg: String })\nconst local = { msg: '' }\nlocal.msg = 'x'\nmsg2 = 'y'",
    );
    assert!(v.is_empty());
  }

  #[test]
  fn ignores_destructure_without_define_props() {
    let v = scan("const { count } = someOther()\ncount++");
    assert!(v.is_empty());
  }

  #[test]
  fn ignores_member_write_to_other_object() {
    let v = scan("const props = defineProps({ msg: String })\nstate.msg = 'x'");
    assert!(v.is_empty());
  }

  #[test]
  fn ignores_read_of_destructured_prop() {
    assert!(scan("const { msg } = defineProps({ msg: String })\nconst out = msg").is_empty());
  }

  #[test]
  fn no_script_no_violation() {
    assert!(scan("").is_empty());
  }
}
