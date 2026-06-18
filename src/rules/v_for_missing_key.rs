use miette::{Diagnostic, NamedSource, SourceSpan};
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::template::Attribute;
use crate::rule_id::RuleId;
use crate::rules::{Category, Rule};
use crate::severity::Severity;
use crate::visitor::for_each_element;

#[derive(Error, Diagnostic, Debug)]
#[error("`v-for` is missing a `:key` binding")]
#[diagnostic(
  code(vue_scanner::best_practice::v_for_missing_key),
  severity(Warning),
  help(
    "Without a stable `:key`, Vue falls back to index-based reconciliation \
     which produces wrong DOM updates and loses component state when the \
     list reorders. Add `:key=\"item.id\"` (or any stable identifier)."
  )
)]
pub struct VForMissingKeyViolation {
  #[source_code]
  pub src: NamedSource<String>,
  #[label("v-for here")]
  pub span: SourceSpan,
}

pub struct VForMissingKey;

impl Rule for VForMissingKey {
  fn id(&self) -> RuleId {
    RuleId::new("vue/best-practice/v-for-missing-key")
  }

  fn name(&self) -> &'static str {
    "v-for-missing-key"
  }

  fn description(&self) -> &'static str {
    "Require `:key` on `v-for` elements"
  }

  fn severity(&self) -> Severity {
    Severity::Medium
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
      let has_v_for = el.attributes.iter().any(|a| matches!(a, Attribute::ForDirective(_)));
      if !has_v_for {
        return;
      }
      let has_key = el.attributes.iter().any(|a| match a {
        Attribute::Directive(d) => match &d.argument {
          Some(crate::parser::template::DirectiveArgument::Static(arg)) => arg.name == "key",
          _ => false,
        },
        _ => false,
      });
      if !has_key {
        let span = el.span;
        violations.push(Box::new(VForMissingKeyViolation {
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
    VForMissingKey.check(&ctx)
  }

  #[test]
  fn flags_v_for_without_key() {
    let v = scan(r#"<li v-for="x in items">{{ x }}</li>"#);
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn ignores_v_for_with_key() {
    assert!(scan(r#"<li v-for="x in items" :key="x.id">{{ x }}</li>"#).is_empty());
  }

  #[test]
  fn ignores_non_v_for() {
    assert!(scan(r#"<li>x</li>"#).is_empty());
  }

  #[test]
  fn flags_nested_v_for_without_key() {
    let v = scan(
      r#"<ul><li v-for="x in xs"><span v-for="y in x.ys">{{ y }}</span></li></ul>"#,
    );
    assert_eq!(v.len(), 2);
  }
}
