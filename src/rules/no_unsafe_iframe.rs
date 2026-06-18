use miette::{Diagnostic, NamedSource, SourceSpan};
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::template::Attribute;
use crate::rule_id::RuleId;
use crate::rules::{Category, Rule};
use crate::severity::Severity;
use crate::visitor::for_each_element;

#[derive(Error, Diagnostic, Debug)]
#[error("`iframe` is missing a `sandbox` attribute")]
#[diagnostic(
  code(vue_scanner::security::no_unsafe_iframe),
  severity(Warning),
  help(
    "An `iframe` without `sandbox` inherits the embedding origin's full \
     capabilities. Add at minimum `sandbox=\"\"` (or an explicit allow-list) \
     to neutralise framed content that turns malicious."
  )
)]
pub struct NoUnsafeIframeViolation {
  #[source_code]
  pub src: NamedSource<String>,
  #[label("iframe without sandbox here")]
  pub span: SourceSpan,
}

pub struct NoUnsafeIframe;

impl Rule for NoUnsafeIframe {
  fn id(&self) -> RuleId {
    RuleId::new("vue/security/no-unsafe-iframe")
  }

  fn name(&self) -> &'static str {
    "no-unsafe-iframe"
  }

  fn description(&self) -> &'static str {
    "Disallow `<iframe>` without a `sandbox` attribute"
  }

  fn severity(&self) -> Severity {
    Severity::Medium
  }

  fn category(&self) -> Category {
    Category::Security
  }

  fn check(&self, ctx: &ScanContext) -> Vec<Box<dyn Diagnostic>> {
    let mut violations = Vec::new();
    let Some(root) = ctx.template_ast.as_ref() else {
      return violations;
    };

    for_each_element(root, |el| {
      if el.name != "iframe" {
        return;
      }
      let has_sandbox = el.attributes.iter().any(|a| matches!(a, Attribute::Static(s) if s.key.name == "sandbox"));
      if !has_sandbox {
        let span = el.span;
        violations.push(Box::new(NoUnsafeIframeViolation {
          src: ctx.named_source.clone(),
          span: SourceSpan::new((span.start as usize).into(), (span.end - span.start) as usize),
        }));
      }
    });

    violations
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::parser::parse_sfc;

  fn scan(template: &str) -> Vec<Box<dyn Diagnostic>> {
    let source = format!("<template>\n{template}\n</template>");
    let mut ctx = ScanContext::new("test.vue".into(), source);
    parse_sfc(&mut ctx);
    NoUnsafeIframe.check(&ctx)
  }

  #[test]
  fn flags_iframe_without_sandbox() {
    assert_eq!(scan(r#"<iframe src="https://example.com"></iframe>"#).len(), 1);
  }

  #[test]
  fn ignores_iframe_with_empty_sandbox() {
    assert!(scan(r#"<iframe src="x" sandbox=""></iframe>"#).is_empty());
  }

  #[test]
  fn ignores_iframe_with_explicit_sandbox_flags() {
    assert!(scan(r#"<iframe src="x" sandbox="allow-scripts"></iframe>"#).is_empty());
  }

  #[test]
  fn ignores_other_elements() {
    assert!(scan(r#"<div>x</div>"#).is_empty());
  }
}
