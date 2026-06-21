use miette::{Diagnostic, NamedSource, SourceSpan};
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::template::{Attribute, DirectiveArgument};
use crate::rule_id::RuleId;
use crate::rules::{Category, Rule};
use crate::severity::Severity;
use crate::visitor::for_each_element;

#[derive(Error, Diagnostic, Debug)]
#[error("Dynamic `src` binding can load untrusted resources")]
#[diagnostic(
  code(vuer::security::no_dynamic_bind_src),
  severity(Warning),
  help(
    "Validate and sanitise the URL before binding it. Allow only an explicit \
     allow-list of schemes (https, /) and hosts, and never concatenate user \
     input into the URL."
  )
)]
pub struct NoDynamicBindSrcViolation {
  #[source_code]
  pub src: NamedSource<String>,
  #[label("dynamic `src` binding here")]
  pub span: SourceSpan,
}

pub struct NoDynamicBindSrc;

impl Rule for NoDynamicBindSrc {
  fn id(&self) -> RuleId {
    RuleId::new("vue/security/no-dynamic-bind-src")
  }

  fn name(&self) -> &'static str {
    "no-dynamic-bind-src"
  }

  fn description(&self) -> &'static str {
    "Disallow dynamic `src` bindings to prevent loading untrusted resources"
  }

  fn severity(&self) -> Severity {
    Severity::High
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
        let directive = match attr {
          Attribute::Directive(d) | Attribute::OnDirective(d) => d,
          _ => continue,
        };
        if !is_bind_directive(directive) {
          continue;
        }
        let targets_src = match &directive.argument {
          Some(DirectiveArgument::Static(arg)) => arg.name == "src",
          Some(DirectiveArgument::Dynamic(_)) => true,
          None => false,
        };
        if targets_src {
          let span = directive.span;
          violations.push(Box::new(NoDynamicBindSrcViolation {
            src: ctx.named_source.clone(),
            span: SourceSpan::new(
              (span.start as usize).into(),
              (span.end - span.start) as usize,
            ),
          }));
        }
      }
    });

    violations
  }
}

fn is_bind_directive(d: &crate::parser::template::Directive) -> bool {
  matches!(d.name.name.as_str(), "v-bind" | "bind" | ":")
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::parser::parse_sfc;

  fn scan(template: &str) -> Vec<Box<dyn Diagnostic>> {
    let source = format!("<template>\n{template}\n</template>");
    let mut ctx = ScanContext::new("test.vue".into(), source);
    parse_sfc(&mut ctx);
    NoDynamicBindSrc.check(&ctx)
  }

  #[test]
  fn clean_static_src_passes() {
    assert!(scan(r#"<img src="logo.png">"#).is_empty());
  }

  #[test]
  fn flags_v_bind_src() {
    assert_eq!(scan(r#"<img v-bind:src="url">"#).len(), 1);
  }

  #[test]
  fn flags_shorthand_bind_src() {
    assert_eq!(scan(r#"<img :src="url">"#).len(), 1);
  }

  #[test]
  fn flags_dynamic_argument_for_src() {
    assert_eq!(scan(r#"<img :[dynamicAttr]="value">"#).len(), 1);
  }

  #[test]
  fn ignores_v_bind_href() {
    // :href is not :src
    assert!(scan(r#"<a :href="url">link</a>"#).is_empty());
  }

  #[test]
  fn ignores_v_bind_with_literal_value() {
    // `v-bind:src="'literal'"` is still dynamic from a taint-flow perspective
    // so we still flag it.
    assert_eq!(scan(r#"<img v-bind:src="'literal'">"#).len(), 1);
  }
}
