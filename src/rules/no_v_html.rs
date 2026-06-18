use miette::{Diagnostic, NamedSource, SourceSpan};
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::template::Attribute;
use crate::rule_id::RuleId;
use crate::rules::{Category, Rule};
use crate::severity::Severity;
use crate::visitor::for_each_element;

#[derive(Error, Diagnostic, Debug)]
#[error("Unsafe `v-html` directive renders untrusted HTML")]
#[diagnostic(
  code(vue_scanner::security::no_v_html),
  severity(Warning),
  help(
    "Rendering untrusted HTML can execute arbitrary JavaScript. \
     Sanitise the input with DOMPurify (or an equivalent library), or use \
     `v-text` / `{{ }}` interpolation instead."
  )
)]
pub struct NoVHtmlViolation {
  #[source_code]
  pub src: NamedSource<String>,
  #[label("`v-html` used here")]
  pub span: SourceSpan,
}

pub struct NoVHtml;

impl Rule for NoVHtml {
  fn id(&self) -> RuleId {
    RuleId::new("vue/security/no-v-html")
  }

  fn name(&self) -> &'static str {
    "no-v-html"
  }

  fn description(&self) -> &'static str {
    "Disallow the `v-html` directive to prevent XSS"
  }

  fn severity(&self) -> Severity {
    Severity::Critical
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
      for attr in &el.attributes {
        if let Attribute::Directive(d) = attr {
          if d.name.name == "v-html" {
            let span = d.span;
            violations.push(Box::new(NoVHtmlViolation {
              src: ctx.named_source.clone(),
              span: SourceSpan::new((span.start as usize).into(), (span.end - span.start) as usize),
            }));
          }
        }
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
    NoVHtml.check(&ctx)
  }

  #[test]
  fn no_violation_on_clean_template() {
    assert!(scan(r#"<div>{{ message }}</div>"#).is_empty());
  }

  #[test]
  fn flags_v_html_directive() {
    let v = scan(r#"<div v-html="raw"></div>"#);
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_v_html_with_dynamic_argument() {
    let v = scan(r#"<div v-html="user.bio"></div>"#);
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_v_html_in_nested_element() {
    let v = scan(r#"<div><span v-html="raw"></span></div>"#);
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn ignores_static_html_attribute() {
    // v-html only matches the directive, never a static attribute
    assert!(scan(r#"<div title="v-html"></div>"#).is_empty());
  }

  #[test]
  fn ignores_v_text_directive() {
    assert!(scan(r#"<div v-text="raw"></div>"#).is_empty());
  }
}
