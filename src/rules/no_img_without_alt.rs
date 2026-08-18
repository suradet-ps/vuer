//! Flag `<img>` elements that carry no `alt` attribute.
//!
//! Screen readers announce the `alt` text in place of the image; an
//! image without `alt` is announced as its filename (or skipped
//! entirely), so blind and low-vision users miss the content. An
//! explicit empty `alt=""` is intentional (decorative image) and is
//! accepted, as are bound forms (`:alt`, `v-bind:alt`) and a bare
//! `v-bind="attrs"` spread that could carry the attribute.

use miette::{Diagnostic, NamedSource, SourceSpan};
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::template::{Attribute, Directive, DirectiveArgument};
use crate::rule_id::RuleId;
use crate::rules::{Category, Finding, Rule};
use crate::severity::Severity;
use crate::visitor::for_each_element;

#[derive(Error, Diagnostic, Debug)]
#[error("`<img>` without an `alt` attribute")]
#[diagnostic(
  code(vuer::accessibility::no_img_without_alt),
  severity(Warning),
  help(
    "Screen readers announce the `alt` text in place of the image. Add \
     `alt=\"description\"`, or `alt=\"\"` for purely decorative images. \
     Dynamic images can bind `:alt=\"item.label\"`."
  )
)]
pub struct NoImgWithoutAltViolation {
  #[source_code]
  pub src: NamedSource<String>,
  #[label("<img> without alt")]
  pub span: SourceSpan,
}

pub struct NoImgWithoutAlt;

impl Rule for NoImgWithoutAlt {
  fn id(&self) -> RuleId {
    RuleId::new("vue/accessibility/no-img-without-alt")
  }

  fn name(&self) -> &'static str {
    "no-img-without-alt"
  }

  fn description(&self) -> &'static str {
    "Require an `alt` attribute on every `<img>`"
  }

  fn severity(&self) -> Severity {
    Severity::Medium
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
      if el.name != "img" {
        return;
      }
      if el.attributes.iter().any(has_alt) {
        return;
      }
      violations.push(Finding::new(Box::new(NoImgWithoutAltViolation {
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

/// Whether an attribute carries an `alt` key: static `alt`, `:alt` /
/// `v-bind:alt`, a dynamic `:[x]` argument (could bind `alt`), or a
/// bare `v-bind="attrs"` spread.
fn has_alt(attr: &Attribute) -> bool {
  match attr {
    Attribute::Static(a) => a.key.name == "alt",
    Attribute::Directive(d) | Attribute::OnDirective(d) | Attribute::SlotDirective(d) => {
      is_alt_binding(d)
    }
    Attribute::ForDirective(_) => false,
  }
}

fn is_alt_binding(d: &Directive) -> bool {
  if !matches!(d.name.name.as_str(), "v-bind" | "bind" | ":") {
    return false;
  }
  match &d.argument {
    Some(DirectiveArgument::Static(arg)) => arg.name == "alt",
    // `:[key]` could bind `alt`; a bare `v-bind="attrs"` spread could
    // carry it too. Treat both as present to avoid false positives.
    Some(DirectiveArgument::Dynamic(_)) | None => true,
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
    NoImgWithoutAlt.check(&ctx)
  }

  #[test]
  fn flags_img_without_alt() {
    let v = scan(r#"<img src="logo.png">"#);
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_img_without_alt_nested() {
    let v = scan(r#"<div><p><img src="photo.jpg"></p></div>"#);
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn accepts_img_with_static_alt() {
    assert!(scan(r#"<img src="logo.png" alt="Vuer logo">"#).is_empty());
  }

  #[test]
  fn accepts_empty_alt_for_decorative_images() {
    assert!(scan(r#"<img src="divider.png" alt="">"#).is_empty());
  }

  #[test]
  fn accepts_boolean_alt_attribute() {
    assert!(scan(r#"<img src="x.png" alt>"#).is_empty());
  }

  #[test]
  fn accepts_bound_alt() {
    assert!(scan(r#"<img :src="url" :alt="item.label">"#).is_empty());
    assert!(scan(r#"<img :src="url" v-bind:alt="item.label">"#).is_empty());
  }

  #[test]
  fn accepts_bind_spread_and_dynamic_argument() {
    // Cannot prove `alt` is absent: keep the false-positive rate low.
    assert!(scan(r#"<img v-bind="attrs">"#).is_empty());
    assert!(scan(r#"<img :[key]="value">"#).is_empty());
  }

  #[test]
  fn ignores_non_img_elements() {
    assert!(scan(r#"<div><span>text</span></div>"#).is_empty());
  }

  #[test]
  fn no_template_no_violation() {
    let mut ctx = ScanContext::new("test.vue".into(), "".into());
    parse_sfc(&mut ctx);
    assert!(NoImgWithoutAlt.check(&ctx).is_empty());
  }
}
