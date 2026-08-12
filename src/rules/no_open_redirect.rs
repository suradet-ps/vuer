use miette::{Diagnostic, NamedSource, SourceSpan};
use oxc_allocator::Allocator;
use oxc_ast::ast::{AssignmentTarget, Expression};
use oxc_ast_visit::Visit;
use oxc_span::GetSpan;
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::script::parse_script;
use crate::rule_id::RuleId;
use crate::rules::{Category, Finding, Rule, RuleKind};
use crate::severity::Severity;
use crate::taint::TaintStatus;

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

  fn kind(&self) -> RuleKind {
    RuleKind::Taint
  }

  fn check(&self, ctx: &ScanContext) -> Vec<Finding> {
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
      taint: &ctx.taint,
    };
    finder.visit_program(&program);
    violations
  }
}

struct OpenRedirectFinder<'a, 'b> {
  hits: &'a mut Vec<Finding>,
  named_source: &'b NamedSource<String>,
  script_offset: usize,
  taint: &'b crate::taint::TaintResult,
}

impl<'a, 'b, 'c> Visit<'c> for OpenRedirectFinder<'a, 'b> {
  fn visit_assignment_expression(&mut self, expr: &oxc_ast::ast::AssignmentExpression<'c>) {
    if let Some(sink) = assignment_sink(&expr.left) {
      // Phase 2: report only when the assigned value may carry untrusted
      // data (subsumes the old "not a string literal" check and cuts
      // false positives on constant redirects).
      let rhs_start = self.script_offset as u32 + expr.right.span().start;
      if self.taint.status_at(rhs_start) != TaintStatus::Clean {
        let flow = self.taint.flow_at(rhs_start, "navigation assignment");
        self.report(expr.span, sink, flow);
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
      if !first_is_literal
        && let Some(first) = call.arguments.first()
        && let Some(e) = first.as_expression()
      {
        let arg_start = self.script_offset as u32 + e.span().start;
        if self.taint.status_at(arg_start) != TaintStatus::Clean {
          let flow = self.taint.flow_at(arg_start, "navigation call");
          self.report(call.span, sink, flow);
        }
      }
    }
    self.visit_arguments(&call.arguments);
    self.visit_expression(&call.callee);
  }
}

impl<'a, 'b> OpenRedirectFinder<'a, 'b> {
  fn report(
    &mut self,
    span: oxc_span::Span,
    sink: &'static str,
    flow: Option<crate::taint::FlowPath>,
  ) {
    let absolute = (self.script_offset as u32 + span.start) as usize;
    let diagnostic = Box::new(NoOpenRedirectViolation {
      src: self.named_source.clone(),
      span: SourceSpan::new(absolute.into(), (span.end - span.start) as usize),
      sink,
    });
    self.hits.push(match flow {
      Some(flow) => Finding::with_flow(diagnostic, vec![flow]),
      None => Finding::new(diagnostic),
    });
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
    if let Expression::StaticMemberExpression(inner) = &member.object
      && inner.property.name == "location"
      && let Expression::Identifier(ident) = &inner.object
      && ident.name == "window"
    {
      return Some("window.location.href");
    }
  }
  if member.property.name == "location"
    && let Expression::Identifier(ident) = &member.object
    && ident.name == "window"
  {
    return Some("window.location");
  }
  None
}

fn call_sink(call: &oxc_ast::ast::CallExpression<'_>) -> Option<&'static str> {
  if let Expression::StaticMemberExpression(member) = &call.callee
    && matches!(&member.object, Expression::Identifier(ident) if ident.name == "location")
  {
    match member.property.name.as_str() {
      "assign" => return Some("location.assign"),
      "replace" => return Some("location.replace"),
      _ => {}
    }
  }
  None
}

fn is_string_literal_arg(arg: &oxc_ast::ast::Argument<'_>) -> bool {
  matches!(arg, oxc_ast::ast::Argument::StringLiteral(_))
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::parser::parse_sfc;

  fn scan(source: &str) -> Vec<Finding> {
    let mut ctx = ScanContext::new("test.vue".into(), source.to_string());
    parse_sfc(&mut ctx);
    NoOpenRedirect.check(&ctx)
  }

  #[test]
  fn flags_location_href_with_tainted_value() {
    let src = r#"<script setup>
const next = localStorage.getItem('next')
location.href = next
</script>"#;
    let v = scan(src);
    assert_eq!(v.len(), 1);
    let flow = v[0].flow.as_ref().expect("flow");
    assert_eq!(flow[0].sink, "navigation assignment");
  }

  #[test]
  fn flags_window_location_with_variable() {
    let src = r#"<script setup>
const redirect = localStorage.getItem('r')
window.location = redirect
</script>"#;
    assert_eq!(scan(src).len(), 1);
  }

  #[test]
  fn flags_location_assign_call() {
    let src = r#"<script setup>
const redirect = localStorage.getItem('r')
location.assign(redirect)
</script>"#;
    assert_eq!(scan(src).len(), 1);
  }

  #[test]
  fn flags_location_replace_call() {
    let src = r#"<script setup>
const redirect = localStorage.getItem('r')
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

  #[test]
  fn stays_silent_for_clean_values() {
    // The false-positive cut: a constant redirect (router config style)
    // is not an open redirect.
    let src = r#"<script setup>
const dest = '/dashboard'
location.href = dest
</script>"#;
    assert!(scan(src).is_empty());
  }
}
