use miette::{Diagnostic, NamedSource, SourceSpan};
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::template::Attribute;
use crate::rule_id::RuleId;
use crate::rules::{Category, Rule};
use crate::severity::Severity;
use crate::visitor::for_each_element;

#[derive(Error, Diagnostic, Debug)]
#[error("Inline styles can hurt performance and maintainability")]
#[diagnostic(
  code(vue_scanner::best_practice::no_inline_style),
  severity(Info),
  help(
    "Use a CSS class instead. Inline styles bypass the cascade, prevent theming, \
     and tend to grow as the component evolves."
  )
)]
pub struct NoInlineStyleViolation {
  #[source_code]
  pub src: NamedSource<String>,
  #[label("inline `style` here")]
  pub span: SourceSpan,
}

pub struct NoInlineStyle;

impl Rule for NoInlineStyle {
  fn id(&self) -> RuleId {
    RuleId::new("vue/best-practice/no-inline-style")
  }

  fn name(&self) -> &'static str {
    "no-inline-style"
  }

  fn description(&self) -> &'static str {
    "Disallow inline `style` and `:style` bindings in templates"
  }

  fn severity(&self) -> Severity {
    Severity::Low
  }

  fn category(&self) -> Category {
    Category::BestPractice
  }

  fn check(&self, ctx: &ScanContext) -> Vec<Box<dyn Diagnostic>> {
    let mut violations = Vec::new();
    let Some(root) = ctx.template_ast.as_ref() else {
      return violations;
    };

    for_each_element(root, |el| {
      for attr in &el.attributes {
        let matches = match attr {
          Attribute::Static(s) => s.key.name == "style",
          Attribute::Directive(d) => match d.argument.as_ref() {
            Some(crate::parser::template::DirectiveArgument::Static(arg)) => arg.name == "style",
            Some(crate::parser::template::DirectiveArgument::Dynamic(_)) => d.name.name == "v-bind",
            None => false,
          },
          _ => false,
        };
        if matches {
          let span = attr.span();
          violations.push(Box::new(NoInlineStyleViolation {
            src: ctx.named_source.clone(),
            span: SourceSpan::new((span.start as usize).into(), (span.end - span.start) as usize),
          }));
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
    NoInlineStyle.check(&ctx)
  }

  #[test]
  fn clean_no_styles() {
    assert!(scan(r#"<div class="box">hi</div>"#).is_empty());
  }

  #[test]
  fn flags_static_style() {
    assert_eq!(scan(r#"<div style="color: red">x</div>"#).len(), 1);
  }

  #[test]
  fn flags_dynamic_style_binding() {
    assert_eq!(scan(r#"<div :style="styles">x</div>"#).len(), 1);
  }

  #[test]
  fn flags_v_bind_style() {
    assert_eq!(scan(r#"<div v-bind:style="styles">x</div>"#).len(), 1);
  }

  #[test]
  fn ignores_unrelated_attribute() {
    assert!(scan(r#"<div :class="cls">x</div>"#).is_empty());
  }
}
