//! Flag `<button>` elements without an explicit `type`.
//!
//! A `<button>` without `type` defaults to `type="submit"`. Inside a
//! form, any click — including one meant to collapse a panel or clear
//! the form — submits the form and navigates. Explicitness is also an
//! accessibility signal: assistive technology announces the button by
//! its type.

use miette::{Diagnostic, NamedSource, SourceSpan};
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::template::{Attribute, DirectiveArgument};
use crate::rule_id::RuleId;
use crate::rules::{Category, Finding, Rule};
use crate::severity::Severity;
use crate::visitor::for_each_element;

#[derive(Error, Diagnostic, Debug)]
#[error("`<button>` without an explicit `type` attribute")]
#[diagnostic(
  code(vuer::accessibility::no_button_without_type),
  severity(Info),
  help(
    "A `<button>` without `type` defaults to `type=\"submit\"`, so a click \
     inside a form submits and navigates. Set `type=\"button\"` for \
     in-page actions, or `type=\"submit\"` explicitly when submitting."
  )
)]
pub struct NoButtonWithoutTypeViolation {
  #[source_code]
  pub src: NamedSource<String>,
  #[label("<button> without type")]
  pub span: SourceSpan,
}

pub struct NoButtonWithoutType;

impl Rule for NoButtonWithoutType {
  fn id(&self) -> RuleId {
    RuleId::new("vue/accessibility/no-button-without-type")
  }

  fn name(&self) -> &'static str {
    "no-button-without-type"
  }

  fn description(&self) -> &'static str {
    "Require an explicit `type` on every `<button>`"
  }

  fn severity(&self) -> Severity {
    Severity::Low
  }

  fn category(&self) -> Category {
    Category::Accessibility
  }

  fn check(&self, ctx: &ScanContext) -> Vec<Finding> {
    let mut violations = Vec::new();
    let Some(root) = ctx.template_ast.as_ref() else {
      return violations;
    };

    for_each_element(root, |el| {
      if el.name != "button" {
        return;
      }
      if el.attributes.iter().any(has_type) {
        return;
      }
      violations.push(Finding::new(Box::new(NoButtonWithoutTypeViolation {
        src: ctx.named_source.clone(),
        span: SourceSpan::new(
          (el.span.start as usize).into(),
          (el.span.end - el.span.start) as usize,
        ),
      })));
    });

    violations
  }
}

/// A `type` attribute, static or bound (`:type`, `v-bind:type`). A bare
/// `v-bind="attrs"` spread or a dynamic `:[key]` argument could also
/// carry it — accepted.
fn has_type(attr: &Attribute) -> bool {
  match attr {
    Attribute::Static(a) => a.key.name == "type",
    Attribute::Directive(d) | Attribute::OnDirective(d) | Attribute::SlotDirective(d) => {
      if !matches!(d.name.name.as_str(), "v-bind" | "bind" | ":") {
        return false;
      }
      match &d.argument {
        Some(DirectiveArgument::Static(arg)) => arg.name == "type",
        Some(DirectiveArgument::Dynamic(_)) | None => true,
      }
    }
    Attribute::ForDirective(_) => false,
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::parser::parse_sfc;

  fn scan(template: &str) -> Vec<Finding> {
    let source = format!("<template>\n{template}\n</template>");
    let mut ctx = ScanContext::new("test.vue".into(), source);
    parse_sfc(&mut ctx);
    NoButtonWithoutType.check(&ctx)
  }

  #[test]
  fn flags_button_without_type() {
    let v = scan(r#"<button @click="count++">+</button>"#);
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_button_in_form() {
    let v = scan(r#"<form @submit.prevent="save()"><button>Save</button></form>"#);
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn accepts_button_with_type_button() {
    assert!(scan(r#"<button type="button" @click="open()">Open</button>"#).is_empty());
  }

  #[test]
  fn accepts_button_with_type_submit() {
    assert!(scan(r#"<button type="submit">Save</button>"#).is_empty());
  }

  #[test]
  fn accepts_button_with_type_reset() {
    assert!(scan(r#"<button type="reset">Reset</button>"#).is_empty());
  }

  #[test]
  fn accepts_bound_type() {
    assert!(scan(r#"<button :type="btnType">x</button>"#).is_empty());
    assert!(scan(r#"<button v-bind:type="'button'">x</button>"#).is_empty());
  }

  #[test]
  fn accepts_bind_spread() {
    assert!(scan(r#"<button v-bind="attrs">x</button>"#).is_empty());
  }

  #[test]
  fn ignores_non_button_elements() {
    assert!(scan(r#"<div type="text">x</div>"#).is_empty());
    assert!(scan(r#"<input type="submit">"#).is_empty());
  }

  #[test]
  fn no_template_no_violation() {
    let mut ctx = ScanContext::new("test.vue".into(), "".into());
    parse_sfc(&mut ctx);
    assert!(NoButtonWithoutType.check(&ctx).is_empty());
  }
}
