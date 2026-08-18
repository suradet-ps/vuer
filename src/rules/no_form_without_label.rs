//! Flag `<input>` / `<select>` / `<textarea>` fields that have no
//! accessible label.
//!
//! A field is considered labelled when ANY of these holds (checked in
//! this order, so the common patterns never produce noise):
//!
//! 1. it carries `aria-label` or `aria-labelledby` (static or bound),
//! 2. its `id` matches the `for` of some `<label>` in the template,
//! 3. it is wrapped inside a `<label>` element,
//! 4. it carries a bare `v-bind="attrs"` / dynamic `:[key]` binding that
//!    could supply a label (unprovable → accepted, low false positives).
//!
//! `type="hidden"` inputs are skipped — they are not rendered and need
//! no label. The rule never tries to resolve labels from other files
//! (slots, partials, v-if'd labels from a composable) — documented
//! boundary of the template-only analysis.

use miette::{Diagnostic, NamedSource, SourceSpan};
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::template::{Attribute, Directive, DirectiveArgument, Element, TemplateNode};
use crate::rule_id::RuleId;
use crate::rules::{Category, Finding, Rule};
use crate::severity::Severity;
use crate::visitor::for_each_element;

const FORM_FIELD_ELEMENTS: &[&str] = &["input", "select", "textarea"];

#[derive(Error, Diagnostic, Debug)]
#[error("Form field without an associated `<label>` or `aria-label`")]
#[diagnostic(
  code(vuer::accessibility::no_form_without_label),
  severity(Warning),
  help(
    "Associate a `<label for=\"field-id\">` with the field, wrap it in a \
     `<label>`, or add `aria-label=\"...\"`. Screen readers announce a field \
     by its label; an unlabelled input is announced only as its type."
  )
)]
pub struct NoFormWithoutLabelViolation {
  #[source_code]
  pub src: NamedSource<String>,
  #[label("form field without a label")]
  pub span: SourceSpan,
}

pub struct NoFormWithoutLabel;

impl Rule for NoFormWithoutLabel {
  fn id(&self) -> RuleId {
    RuleId::new("vue/accessibility/no-form-without-label")
  }

  fn name(&self) -> &'static str {
    "no-form-without-label"
  }

  fn description(&self) -> &'static str {
    "Require an associated `<label>` or `aria-label` on form fields"
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

    // Pass 1: every `for="..."` target the labels in this template
    // reference. The scan covers the whole tree so a label elsewhere in
    // the template (before/after the field) still counts.
    let mut labelled_ids: Vec<String> = Vec::new();
    for_each_element(root, |el| {
      if el.name != "label" {
        return;
      }
      for attr in &el.attributes {
        if let Attribute::Static(a) = attr
          && a.key.name == "for"
          && let Some(value) = &a.value
        {
          labelled_ids.push(value.value.clone());
        }
      }
    });

    // Pass 2: check every form field with its ancestor stack (for the
    // `<label><input>` wrapper pattern).
    let mut walker = FieldWalker {
      labelled_ids: &labelled_ids,
      violations: &mut violations,
      named_source: &ctx.named_source,
    };
    walker.walk(&root.children, &mut Vec::new());

    violations
  }
}

struct FieldWalker<'a, 'b> {
  labelled_ids: &'a [String],
  violations: &'a mut Vec<Finding>,
  named_source: &'b miette::NamedSource<String>,
}

impl<'a> FieldWalker<'a, '_> {
  fn walk(&mut self, nodes: &'a [TemplateNode], ancestors: &mut Vec<&'a Element>) {
    for node in nodes {
      let TemplateNode::Element(el) = node else {
        continue;
      };
      if FORM_FIELD_ELEMENTS.contains(&el.name.as_str())
        && !has_label(el, self.labelled_ids, ancestors)
      {
        self
          .violations
          .push(Finding::new(Box::new(NoFormWithoutLabelViolation {
            src: self.named_source.clone(),
            span: SourceSpan::new(
              (el.span.start as usize).into(),
              (el.span.end - el.span.start) as usize,
            ),
          })));
      }
      ancestors.push(el);
      self.walk(&el.children, ancestors);
      ancestors.pop();
    }
  }
}

fn has_label(el: &Element, labelled_ids: &[String], ancestors: &[&Element]) -> bool {
  if static_attr_value(el, "type") == Some("hidden") {
    return true;
  }
  if el.attributes.iter().any(has_aria_label) {
    return true;
  }
  if let Some(id) = static_attr_value(el, "id")
    && labelled_ids.iter().any(|target| target == id)
  {
    return true;
  }
  if ancestors.iter().any(|a| a.name == "label") {
    return true;
  }
  // Unprovable bindings (`v-bind="attrs"`, `:[key]`) are accepted.
  if el
    .attributes
    .iter()
    .any(|a| matches!(a, Attribute::Directive(d) if is_unprovable_spread(d)))
  {
    return true;
  }
  false
}

/// `aria-label` or `aria-labelledby`, static or bound.
fn has_aria_label(attr: &Attribute) -> bool {
  match attr {
    Attribute::Static(a) => matches!(a.key.name.as_str(), "aria-label" | "aria-labelledby"),
    Attribute::Directive(d) | Attribute::OnDirective(d) | Attribute::SlotDirective(d) => {
      matches!(d.name.name.as_str(), "v-bind" | "bind" | ":")
        && matches!(d.argument, Some(DirectiveArgument::Static(ref arg)) if matches!(arg.name.as_str(), "aria-label" | "aria-labelledby"))
    }
    Attribute::ForDirective(_) => false,
  }
}

/// A `v-bind` with no static argument: a bare `v-bind="attrs"` spread or
/// a dynamic `:[key]` — either could carry a label.
fn is_unprovable_spread(d: &Directive) -> bool {
  matches!(d.name.name.as_str(), "v-bind" | "bind" | ":")
    && !matches!(d.argument, Some(DirectiveArgument::Static(_)))
}

fn static_attr_value<'a>(el: &'a Element, name: &str) -> Option<&'a str> {
  el.attributes.iter().find_map(|attr| match attr {
    Attribute::Static(a) if a.key.name == name => a.value.as_ref().map(|v| v.value.as_str()),
    _ => None,
  })
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::parser::parse_sfc;

  fn scan(template: &str) -> Vec<Finding> {
    let source = format!("<template>\n{template}\n</template>");
    let mut ctx = ScanContext::new("test.vue".into(), source);
    parse_sfc(&mut ctx);
    NoFormWithoutLabel.check(&ctx)
  }

  #[test]
  fn flags_input_without_label() {
    let v = scan(r#"<input type="text" v-model="name">"#);
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_select_and_textarea_without_label() {
    let v =
      scan(r#"<select v-model="s"><option>a</option></select><textarea v-model="t"></textarea>"#);
    assert_eq!(v.len(), 2);
  }

  #[test]
  fn accepts_label_for_association() {
    assert!(scan(r#"<label for="name">Name</label><input id="name" type="text">"#).is_empty());
  }

  #[test]
  fn accepts_wrapping_label() {
    assert!(scan(r#"<label>Name <input type="text"></label>"#).is_empty());
  }

  #[test]
  fn accepts_nested_wrapping_label() {
    assert!(scan(r#"<form><div><label>Name <input type="text"></label></div></form>"#).is_empty());
  }

  #[test]
  fn accepts_aria_label() {
    assert!(scan(r#"<input type="text" aria-label="Name">"#).is_empty());
    assert!(scan(r#"<input type="text" :aria-label="msg">"#).is_empty());
  }

  #[test]
  fn accepts_aria_labelledby() {
    assert!(scan(r#"<input type="text" aria-labelledby="name-label">"#).is_empty());
  }

  #[test]
  fn skips_hidden_input() {
    assert!(scan(r#"<input type="hidden" name="csrf" value="1">"#).is_empty());
  }

  #[test]
  fn accepts_bind_spread() {
    assert!(scan(r#"<input v-bind="attrs">"#).is_empty());
  }

  #[test]
  fn label_for_matches_bound_id() {
    // id must be static for the association to be provable.
    let v = scan(r#"<label for="f">F</label><input :id="fieldId">"#);
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn no_template_no_violation() {
    let mut ctx = ScanContext::new("test.vue".into(), "".into());
    parse_sfc(&mut ctx);
    assert!(NoFormWithoutLabel.check(&ctx).is_empty());
  }
}
