//! Shared helpers for the template-parser test suites (conformance,
//! edge cases, offset integrity). Each test file in `tests/` is its own
//! crate; this module is compiled into each of them via `mod common;`.

use std::path::PathBuf;

use vuer::context::ScanContext;
use vuer::parser::parse_sfc;
use vuer::parser::template::{
  Attribute, Directive, DirectiveArgument, DirectiveValue, Element, TemplateNode, TemplateRoot,
};

/// Parse a full `.vue` source and produce the structural dump of its
/// `<template>` block (see [`describe_root`]). Panics if the template
/// does not parse cleanly — conformance fixtures must be clean.
pub fn describe_sfc(vue: &str) -> String {
  let mut ctx = ScanContext::new(PathBuf::from("fixture.vue"), vue.to_string());
  parse_sfc(&mut ctx);
  assert!(
    ctx.template_errors.is_empty(),
    "fixture must parse without errors, got: {:#?}",
    ctx.template_errors
  );
  let root = ctx
    .template_ast
    .as_ref()
    .expect("fixture has a template block");
  describe_root(root)
}

/// Render a `TemplateRoot` as an indented structural dump:
/// element/attribute/directive names and values, interpolations,
/// comments, and CDATA sections. This is the "expected structural
/// snapshot" of the conformance suite.
pub fn describe_root(root: &TemplateRoot) -> String {
  let mut out = String::from("root\n");
  for child in &root.children {
    describe_node(child, 1, &mut out);
  }
  out
}

fn describe_node(node: &TemplateNode, depth: usize, out: &mut String) {
  let indent = "  ".repeat(depth);
  match node {
    TemplateNode::Element(el) => {
      out.push_str(&indent);
      out.push_str(&format_element_open(el));
      out.push('\n');
      for child in &el.children {
        describe_node(child, depth + 1, out);
      }
      if !el.self_closing {
        out.push_str(&indent);
        out.push_str(&format!("</{}>\n", el.raw_name));
      }
    }
    TemplateNode::Text(t) => {
      out.push_str(&indent);
      out.push_str(&format!("{:?}\n", t.text));
    }
    TemplateNode::Interpolation(i) => {
      out.push_str(&indent);
      out.push_str(&format!("{{{{ {} }}}}\n", i.expression.raw));
    }
    TemplateNode::Comment(c) => {
      out.push_str(&indent);
      out.push_str(&format!("<!-- {} -->\n", c.value));
    }
    TemplateNode::CData(c) => {
      out.push_str(&indent);
      out.push_str(&format!("<![CDATA[{}]]>\n", c.text));
    }
  }
}

fn format_element_open(el: &Element) -> String {
  let mut s = format!("<{}", el.raw_name);
  for attr in &el.attributes {
    s.push(' ');
    s.push_str(&format_attribute(attr));
  }
  if el.self_closing {
    s.push_str("/>");
  } else {
    s.push('>');
  }
  s
}

pub fn format_attribute(attr: &Attribute) -> String {
  match attr {
    Attribute::Static(a) => match &a.value {
      Some(v) => format!("{}={:?}", a.key.raw_name, v.value),
      None => a.key.raw_name.clone(),
    },
    Attribute::Directive(d)
    | Attribute::OnDirective(d)
    | Attribute::SlotDirective(d)
    | Attribute::ForDirective(d) => format_directive(d),
  }
}

fn format_directive(d: &Directive) -> String {
  let mut s = d.name.raw_name.clone();
  if let Some(arg) = &d.argument {
    // Shorthand names already carry the separator (`:src`, `@click`,
    // `#header`); long form needs one added (`v-bind:src`).
    let sep = match d.name.raw_name.as_str() {
      ":" | "@" | "#" => "",
      _ => ":",
    };
    match arg {
      DirectiveArgument::Static(id) => s.push_str(&format!("{sep}{}", id.raw_name)),
      DirectiveArgument::Dynamic(expr) => s.push_str(&format!("{sep}[{}]", expr.raw)),
    }
  }
  for m in &d.modifiers {
    s.push_str(&format!(".{}", m.raw_name));
  }
  match &d.value {
    Some(DirectiveValue::Expression(e)) => s.push_str(&format!("={:?}", e.raw)),
    Some(DirectiveValue::Empty) => s.push_str("=\"\""),
    None => {}
  }
  s
}
