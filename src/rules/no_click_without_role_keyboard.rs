//! Flag `@click` handlers on non-interactive elements that have neither
//! a `role` nor a keyboard handler.
//!
//! An element that responds to a click but cannot receive keyboard focus
//! is unreachable for keyboard-only users. The safe fix is one of:
//!
//! * use a real interactive element (`<button>`, `<a href>`, `<input>`),
//! * add `role="button"` (or similar) **and** a matching keyboard
//!   handler (`@keydown.enter` / `@keyup.enter`), or
//! * add `tabindex="0"` so the element can at least receive focus.
//!
//! The rule reports only the clear-cut case — a click handler on a
//! non-interactive element with **neither** `role` **nor** any keyboard
//! handler — to keep the false-positive rate low. Native interactive
//! elements (`a`, `button`, `input`, ...) are never reported.

use miette::{Diagnostic, NamedSource, SourceSpan};
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::template::{Attribute, Directive, DirectiveArgument};
use crate::rule_id::RuleId;
use crate::rules::{Category, Finding, Rule};
use crate::severity::Severity;
use crate::visitor::for_each_element;

/// Elements the browser already treats as interactive: they receive
/// focus and react to keyboard natively.
const INTERACTIVE_ELEMENTS: &[&str] = &[
  "a", "button", "input", "select", "textarea", "label", "details", "summary", "option", "audio",
  "video",
];

/// Keyboard event names that make a click-handling element reachable.
const KEYBOARD_EVENTS: &[&str] = &["keydown", "keyup", "keypress"];

#[derive(Error, Diagnostic, Debug)]
#[error("`@click` on a non-interactive element without `role` or a keyboard handler")]
#[diagnostic(
  code(vuer::accessibility::no_click_without_role_keyboard),
  severity(Warning),
  help(
    "An element that reacts to clicks but cannot receive keyboard focus is \
     unreachable for keyboard-only users. Use a real interactive element \
     (`<button>` / `<a href>`), or add `role=\"button\"` plus a matching \
     `@keydown.enter` handler and `tabindex=\"0\"`."
  )
)]
pub struct NoClickWithoutRoleKeyboardViolation {
  #[source_code]
  pub src: NamedSource<String>,
  #[label("@click on non-interactive element")]
  pub span: SourceSpan,
}

pub struct NoClickWithoutRoleKeyboard;

impl Rule for NoClickWithoutRoleKeyboard {
  fn id(&self) -> RuleId {
    RuleId::new("vue/accessibility/no-click-without-role-keyboard")
  }

  fn name(&self) -> &'static str {
    "no-click-without-role-keyboard"
  }

  fn description(&self) -> &'static str {
    "Require `role` and a keyboard handler on `@click` of non-interactive elements"
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
      if INTERACTIVE_ELEMENTS.contains(&el.name.as_str()) {
        return;
      }
      if !el.attributes.iter().any(is_click_handler) {
        return;
      }
      if el.attributes.iter().any(has_role) {
        return;
      }
      if el.attributes.iter().any(is_keyboard_handler) {
        return;
      }
      violations.push(Finding::new(Box::new(
        NoClickWithoutRoleKeyboardViolation {
          src: ctx.named_source.clone(),
          span: SourceSpan::new(
            (el.span.start as usize).into(),
            (el.span.end - el.span.start) as usize,
          ),
        },
      )));
    });

    violations
  }
}

/// `@click` or `v-on:click` (including `v-on` with a dynamic argument
/// that could resolve to `click`).
fn is_click_handler(attr: &Attribute) -> bool {
  match attr {
    Attribute::OnDirective(d) => handler_event(d) == Some("click"),
    Attribute::Directive(d) if d.name.name == "v-on" => handler_event(d) == Some("click"),
    _ => false,
  }
}

/// The static event name of a `v-on`-family directive.
fn handler_event(d: &Directive) -> Option<&str> {
  match &d.argument {
    Some(DirectiveArgument::Static(arg)) => Some(arg.name.as_str()),
    Some(DirectiveArgument::Dynamic(_)) => None,
    None => None,
  }
}

fn is_keyboard_handler(attr: &Attribute) -> bool {
  let d = match attr {
    Attribute::OnDirective(d) => d,
    Attribute::Directive(d) if d.name.name == "v-on" => d,
    _ => return false,
  };
  handler_event(d).is_some_and(|e| KEYBOARD_EVENTS.contains(&e))
}

fn has_role(attr: &Attribute) -> bool {
  match attr {
    Attribute::Static(a) => a.key.name == "role",
    Attribute::Directive(d) | Attribute::OnDirective(d) | Attribute::SlotDirective(d) => {
      matches!(d.name.name.as_str(), "v-bind" | "bind" | ":")
        && matches!(d.argument, Some(DirectiveArgument::Static(ref arg)) if arg.name == "role")
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
    NoClickWithoutRoleKeyboard.check(&ctx)
  }

  #[test]
  fn flags_click_on_div() {
    let v = scan(r#"<div @click="open()">Open</div>"#);
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_click_on_span_and_section() {
    let v = scan(r#"<span @click="go()">x</span><section @click="go()">y</section>"#);
    assert_eq!(v.len(), 2);
  }

  #[test]
  fn flags_v_on_click_on_li() {
    let v = scan(r#"<li v-on:click="select()">item</li>"#);
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn ignores_click_on_button() {
    assert!(scan(r#"<button @click="count++">+</button>"#).is_empty());
  }

  #[test]
  fn ignores_click_on_link() {
    assert!(scan(r#"<a href="/x" @click="track()">link</a>"#).is_empty());
  }

  #[test]
  fn ignores_click_on_input() {
    assert!(scan(r#"<input type="text" @click="focus()">"#).is_empty());
  }

  #[test]
  fn ignores_with_role() {
    assert!(scan(r#"<div role="button" @click="open()">Open</div>"#).is_empty());
    assert!(scan(r#"<div :role="'button'" @click="open()">Open</div>"#).is_empty());
  }

  #[test]
  fn ignores_with_keyboard_handler() {
    assert!(scan(r#"<div @click="open()" @keydown.enter="open()">Open</div>"#).is_empty());
    assert!(scan(r#"<div @click="open()" @keyup="open()">Open</div>"#).is_empty());
  }

  #[test]
  fn ignores_click_on_label() {
    assert!(scan(r#"<label @click="toggle()">x</label>"#).is_empty());
  }

  #[test]
  fn ignores_no_click() {
    assert!(scan(r#"<div>static</div>"#).is_empty());
  }

  #[test]
  fn ignores_dynamic_event_argument() {
    // `@[ev]` could be any event; cannot prove it is a click.
    assert!(scan(r#"<div @[ev]="doIt()">x</div>"#).is_empty());
  }

  #[test]
  fn no_template_no_violation() {
    let mut ctx = ScanContext::new("test.vue".into(), "".into());
    parse_sfc(&mut ctx);
    assert!(NoClickWithoutRoleKeyboard.check(&ctx).is_empty());
  }
}
