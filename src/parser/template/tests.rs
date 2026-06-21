use crate::parser::template::parse_template;

#[test]
fn parses_simple_element() {
  let (root, errors) = parse_template("<div></div>", 0);
  assert!(errors.is_empty());
  assert_eq!(root.children.len(), 1);
}

#[test]
fn parses_self_closing() {
  let (root, errors) = parse_template("<img/>", 0);
  assert!(errors.is_empty());
  assert_eq!(root.children.len(), 1);
}

#[test]
fn parses_nested_children() {
  let (root, errors) = parse_template("<div><span>x</span></div>", 0);
  assert!(errors.is_empty());
  let TemplateNode::Element(el) = &root.children[0] else {
    panic!("expected element");
  };
  assert_eq!(el.name, "div");
  assert_eq!(el.children.len(), 1);
  let TemplateNode::Element(child) = &el.children[0] else {
    panic!("expected element child");
  };
  assert_eq!(child.name, "span");
}

#[test]
fn parses_directive_with_argument() {
  let (root, errors) = parse_template(r#"<a v-bind:href="url">x</a>"#, 0);
  assert!(errors.is_empty());
  let TemplateNode::Element(el) = &root.children[0] else {
    panic!("expected element");
  };
  assert_eq!(el.attributes.len(), 1);
  match &el.attributes[0] {
    Attribute::Directive(d) => {
      assert_eq!(d.name.name, "v-bind");
      assert!(d.argument.is_some());
    }
    _ => panic!("expected directive"),
  }
}

#[test]
fn parses_v_html_directive() {
  let (root, errors) = parse_template(r#"<div v-html="raw"></div>"#, 0);
  assert!(errors.is_empty());
  let TemplateNode::Element(el) = &root.children[0] else {
    panic!();
  };
  match &el.attributes[0] {
    Attribute::Directive(d) => assert_eq!(d.name.name, "v-html"),
    _ => panic!("expected directive"),
  }
}

#[test]
fn parses_shorthand_directives() {
  let cases = [
    r#"<img :src="u"/>"#,
    r#"<button @click="h"/>"#,
    r#"<Comp #header/>"#,
  ];
  for src in cases {
    let (root, errors) = parse_template(src, 0);
    assert!(errors.is_empty(), "errors for {src}: {errors:?}");
    let TemplateNode::Element(el) = &root.children[0] else {
      panic!();
    };
    assert_eq!(el.attributes.len(), 1, "expected 1 attribute for {src}");
    assert!(
      matches!(
        el.attributes[0],
        Attribute::Directive(_) | Attribute::OnDirective(_) | Attribute::SlotDirective(_)
      ),
      "expected directive-shaped attribute for {src}"
    );
  }
}

#[test]
fn parses_static_attributes() {
  let (root, errors) = parse_template(r#"<div class="a" id="b"></div>"#, 0);
  assert!(errors.is_empty());
  let TemplateNode::Element(el) = &root.children[0] else {
    panic!();
  };
  assert_eq!(el.attributes.len(), 2);
  for attr in &el.attributes {
    assert!(matches!(attr, Attribute::Static(_)));
  }
}

#[test]
fn parses_interpolation() {
  let (root, errors) = parse_template("Hello {{ name }}!", 0);
  assert!(errors.is_empty());
  assert_eq!(root.children.len(), 3);
  let TemplateNode::Interpolation(interp) = &root.children[1] else {
    panic!();
  };
  assert_eq!(interp.expression.raw, " name ");
}

#[test]
fn parses_comment() {
  let (root, errors) = parse_template("<!-- hello --><div></div>", 0);
  assert!(errors.is_empty());
  assert_eq!(root.children.len(), 2);
  assert!(matches!(root.children[0], TemplateNode::Comment(_)));
}

#[test]
fn parses_dynamic_argument() {
  let (root, errors) = parse_template(r#"<div :[dynamicKey]="value"/>"#, 0);
  assert!(errors.is_empty());
  let TemplateNode::Element(el) = &root.children[0] else {
    panic!();
  };
  match &el.attributes[0] {
    Attribute::Directive(d) => match d.argument.as_ref().expect("argument") {
      DirectiveArgument::Dynamic(expr) => assert_eq!(expr.raw, "dynamicKey"),
      _ => panic!(),
    },
    _ => panic!(),
  }
}

#[test]
fn base_offset_applied_to_spans() {
  let (root, _) = parse_template("<div></div>", 100);
  let TemplateNode::Element(el) = &root.children[0] else {
    panic!();
  };
  assert_eq!(el.span.start, 100);
  assert_eq!(el.span.end, 111);
}

use crate::parser::template::{Attribute, DirectiveArgument, TemplateNode};
