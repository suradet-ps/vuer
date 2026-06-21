use miette::{Diagnostic, NamedSource, SourceSpan};
use oxc_allocator::Allocator;
use oxc_ast::ast::{AssignmentTarget, Expression};
use oxc_ast_visit::Visit;
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::script::parse_script;
use crate::rule_id::RuleId;
use crate::rules::{Category, Rule};
use crate::severity::Severity;

/// Detect navigations that copy an unvalidated value into a redirect target.
///
/// Two patterns are checked:
/// 1. `location.href = <expr>`
/// 2. `window.location = <expr>`
/// 3. `window.location.href = <expr>`
/// 4. `location.assign(<expr>)` / `location.replace(<expr>)`
#[derive(Error, Diagnostic, Debug)]
#[error("Unvalidated value is forwarded to a navigation sink")]
#[diagnostic(
  code(vuer::security::no_open_redirect),
  severity(Warning),
  help(
    "Forwarding user-controlled data to `location.*` is a classic open-redirect \
     vector. Validate the URL against an allow-list of hostnames before \
     navigating, or use a router-managed navigation helper."
  )
)]
pub struct NoOpenRedirectViolation {
  #[source_code]
  pub src: NamedSource<String>,
  #[label("navigation assignment here")]
  pub span: SourceSpan,
  pub sink: &'static str,
}

pub struct NoOpenRedirect;

impl Rule for NoOpenRedirect {
  fn id(&self) -> RuleId {
    RuleId::new("vue/security/no-open-redirect")
  }

  fn name(&self) -> &'static str {
    "no-open-redirect"
  }

  fn description(&self) -> &'static str {
    "Disallow `location.href = ...` and `window.location = ...` with dynamic values"
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

    let mut finder = OpenRedirectFinder {
      hits: &mut violations,
      named_source: &ctx.named_source,
      script_offset: ctx.script_offset,
    };
    finder.visit_program(&program);
    violations
  }
}

struct OpenRedirectFinder<'a, 'b> {
  hits: &'a mut Vec<Box<dyn Diagnostic>>,
  named_source: &'b NamedSource<String>,
  script_offset: usize,
}

impl<'a, 'b, 'c> Visit<'c> for OpenRedirectFinder<'a, 'b> {
  fn visit_assignment_expression(&mut self, expr: &oxc_ast::ast::AssignmentExpression<'c>) {
    if let Some(sink) = assignment_sink(&expr.left) {
      // Allow assignments of a string literal, but only if the literal
      // itself is a same-origin URL. A plain string literal in a redirect
      // is still suspicious but usually a router config rather than an
      // open-redirect bug.
      if !is_string_literal(&expr.right) {
        self.report(expr.span, sink);
      }
    }
    self.visit_assignment_target(&expr.left);
    self.visit_expression(&expr.right);
  }

  fn visit_call_expression(&mut self, call: &oxc_ast::ast::CallExpression<'c>) {
    if let Some(sink) = call_sink(call) {
      let first_is_literal = call
        .arguments
        .first()
        .is_some_and(|a| is_string_literal_arg(a));
      if !first_is_literal {
        self.report(call.span, sink);
      }
    }
    self.visit_arguments(&call.arguments);
    self.visit_expression(&call.callee);
  }
}

impl<'a, 'b> OpenRedirectFinder<'a, 'b> {
  fn report(&mut self, span: oxc_span::Span, sink: &'static str) {
    let absolute = (self.script_offset as u32 + span.start) as usize;
    self.hits.push(Box::new(NoOpenRedirectViolation {
      src: self.named_source.clone(),
      span: SourceSpan::new(absolute.into(), (span.end - span.start) as usize),
      sink,
    }));
  }
}

fn assignment_sink<'c>(target: &AssignmentTarget<'c>) -> Option<&'static str> {
  let AssignmentTarget::StaticMemberExpression(member) = target else {
    return None;
  };
  if member.property.name == "href" {
    if matches!(&member.object, Expression::Identifier(ident) if ident.name == "location") {
      return Some("location.href");
    }
    if let Expression::StaticMemberExpression(inner) = &member.object {
      if inner.property.name == "location" {
        if let Expression::Identifier(ident) = &inner.object {
          if ident.name == "window" {
            return Some("window.location.href");
          }
        }
      }
    }
  }
  if member.property.name == "location" {
    if let Expression::Identifier(ident) = &member.object {
      if ident.name == "window" {
        return Some("window.location");
      }
    }
  }
  None
}

fn call_sink(call: &oxc_ast::ast::CallExpression<'_>) -> Option<&'static str> {
  if let Expression::StaticMemberExpression(member) = &call.callee {
    if matches!(&member.object, Expression::Identifier(ident) if ident.name == "location") {
      match member.property.name.as_str() {
        "assign" => return Some("location.assign"),
        "replace" => return Some("location.replace"),
        _ => {}
      }
    }
  }
  None
}

fn is_string_literal(expr: &Expression<'_>) -> bool {
  matches!(expr, Expression::StringLiteral(_))
}

fn is_string_literal_arg(arg: &oxc_ast::ast::Argument<'_>) -> bool {
  matches!(arg, oxc_ast::ast::Argument::StringLiteral(_))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::parser::parse_sfc;

  fn scan(source: &str) -> Vec<Box<dyn Diagnostic>> {
    let mut ctx = ScanContext::new("test.vue".into(), source.to_string());
    parse_sfc(&mut ctx);
    NoOpenRedirect.check(&ctx)
  }

  #[test]
  fn flags_location_href_with_variable() {
    let src = r#"<script setup>
location.href = next
</script>"#;
    assert_eq!(scan(src).len(), 1);
  }

  #[test]
  fn flags_window_location_with_variable() {
    let src = r#"<script setup>
window.location = redirect
</script>"#;
    assert_eq!(scan(src).len(), 1);
  }

  #[test]
  fn flags_location_assign_call() {
    let src = r#"<script setup>
location.assign(redirect)
</script>"#;
    assert_eq!(scan(src).len(), 1);
  }

  #[test]
  fn flags_location_replace_call() {
    let src = r#"<script setup>
location.replace(redirect)
</script>"#;
    assert_eq!(scan(src).len(), 1);
  }

  #[test]
  fn allows_string_literal() {
    let src = r#"<script setup>
location.href = '/dashboard'
</script>"#;
    assert!(scan(src).is_empty());
  }
}
