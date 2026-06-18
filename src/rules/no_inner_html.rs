use miette::{Diagnostic, NamedSource, SourceSpan};
use oxc_allocator::Allocator;
use oxc_ast::ast::AssignmentTarget;
use oxc_ast::ast::Expression;
use oxc_ast_visit::Visit;
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::script::parse_script;
use crate::rule_id::RuleId;
use crate::rules::{Category, Rule};
use crate::severity::Severity;

#[derive(Error, Diagnostic, Debug)]
#[error("`.innerHTML` assignment introduces a DOM XSS sink")]
#[diagnostic(
  code(vue_scanner::security::no_inner_html),
  severity(Warning),
  help(
    "Setting `.innerHTML` from a dynamic value lets an attacker inject \
     script tags and event handlers. Use `textContent` for plain text, or \
     sanitise the value with DOMPurify before insertion."
  )
)]
pub struct NoInnerHtmlViolation {
  #[source_code]
  pub src: NamedSource<String>,
  #[label("innerHTML write here")]
  pub span: SourceSpan,
}

pub struct NoInnerHtml;

impl Rule for NoInnerHtml {
  fn id(&self) -> RuleId {
    RuleId::new("vue/security/no-inner-html")
  }

  fn name(&self) -> &'static str {
    "no-inner-html"
  }

  fn description(&self) -> &'static str {
    "Disallow `el.innerHTML = ...` writes to prevent DOM XSS"
  }

  fn severity(&self) -> Severity {
    Severity::Critical
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
    let mut finder = InnerHtmlFinder { hits: &mut violations, named_source: &ctx.named_source, script_offset: ctx.script_offset };
    finder.visit_program(&program);
    violations
  }
}

struct InnerHtmlFinder<'a, 'b> {
  hits: &'a mut Vec<Box<dyn Diagnostic>>,
  named_source: &'b NamedSource<String>,
  script_offset: usize,
}

impl<'a, 'b, 'c> Visit<'c> for InnerHtmlFinder<'a, 'b> {
  fn visit_assignment_expression(&mut self, expr: &oxc_ast::ast::AssignmentExpression<'c>) {
    if is_inner_html_target(&expr.left) {
      let span = expr.span;
      let absolute = (self.script_offset as u32 + span.start) as usize;
      self.hits.push(Box::new(NoInnerHtmlViolation {
        src: self.named_source.clone(),
        span: SourceSpan::new(absolute.into(), (span.end - span.start) as usize),
      }));
    }
    // Recurse to handle nested assignments (`a = b = el.innerHTML = ...`).
    self.visit_assignment_target(&expr.left);
    self.visit_expression(&expr.right);
  }
}

fn is_inner_html_target(target: &AssignmentTarget<'_>) -> bool {
  let AssignmentTarget::StaticMemberExpression(member) = target else {
    return false;
  };
  if member.property.name != "innerHTML" {
    return false;
  }
  // Skip identifiers that are themselves "innerHTML" (which would be a
  // bizarre variable name); we only care about property access.
  if matches!(&member.object, Expression::Identifier(_)) {
    return true;
  }
  // Even chained like `el.shadowRoot.innerHTML` or `a.b.innerHTML` we still flag.
  true
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::parser::parse_sfc;

  fn scan(source: &str) -> Vec<Box<dyn Diagnostic>> {
    let mut ctx = ScanContext::new("test.vue".into(), source.to_string());
    parse_sfc(&mut ctx);
    NoInnerHtml.check(&ctx)
  }

  #[test]
  fn flags_inner_html_assignment() {
    let src = r#"<script setup>
const el = document.getElementById('x')
el.innerHTML = userInput
</script>"#;
    assert_eq!(scan(src).len(), 1);
  }

  #[test]
  fn flags_chained_inner_html() {
    let src = r#"<script setup>
root.shadowRoot.innerHTML = x
</script>"#;
    assert_eq!(scan(src).len(), 1);
  }

  #[test]
  fn ignores_text_content() {
    let src = r#"<script setup>
el.textContent = userInput
</script>"#;
    assert!(scan(src).is_empty());
  }

  #[test]
  fn ignores_assignment_of_inner_html_to_variable() {
    // The dangerous direction is writing TO innerHTML. Reading from it is fine.
    let src = r#"<script setup>
const html = el.innerHTML
</script>"#;
    assert!(scan(src).is_empty());
  }

  #[test]
  fn no_script_no_violation() {
    assert!(scan("").is_empty());
  }
}
