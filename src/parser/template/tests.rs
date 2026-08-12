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

// ---------------------------------------------------------------------
// Phase 1 hardening regressions: malformed input must never hang the
// parser, and edge-case constructs must produce the right tree.
// ---------------------------------------------------------------------

#[test]
fn parses_multiple_root_nodes() {
  let (root, errors) = parse_template("<div></div><p></p><span/>", 0);
  assert!(errors.is_empty());
  assert_eq!(root.children.len(), 3);
}

#[test]
fn parses_cdata_in_foreign_content() {
  let (root, errors) = parse_template("<svg><![CDATA[<circle r=\"5\"/>]]></svg>", 0);
  assert!(errors.is_empty(), "errors: {errors:?}");
  let TemplateNode::Element(svg) = &root.children[0] else {
    panic!();
  };
  let TemplateNode::CData(cdata) = &svg.children[0] else {
    panic!("expected CData child, got: {:?}", svg.children);
  };
  assert_eq!(cdata.text, "<circle r=\"5\"/>");
}

#[test]
fn unterminated_cdata_records_error_without_hanging() {
  let (root, errors) = parse_template("<svg><![CDATA[never closed", 0);
  assert!(
    errors
      .iter()
      .any(|e| matches!(e.message, "Unterminated CDATA section")),
    "errors: {errors:?}"
  );
  // The svg element itself is also unterminated (no closing tag at all),
  // so it never completes and the root ends up empty.
  assert_eq!(errors.len(), 2);
  assert_eq!(root.children.len(), 0);
}

#[test]
fn comments_become_children_of_elements() {
  let (root, errors) = parse_template("<div>a<!-- note -->b</div>", 0);
  assert!(errors.is_empty());
  let TemplateNode::Element(el) = &root.children[0] else {
    panic!();
  };
  assert_eq!(el.children.len(), 3);
  assert!(matches!(el.children[1], TemplateNode::Comment(_)));
}

#[test]
fn v_pre_makes_subtree_raw_text() {
  let (root, errors) = parse_template("<div v-pre>{{ a }} <b>x</b></div>", 0);
  assert!(errors.is_empty());
  let TemplateNode::Element(el) = &root.children[0] else {
    panic!();
  };
  assert_eq!(el.children.len(), 1);
  let TemplateNode::Text(t) = &el.children[0] else {
    panic!("v-pre subtree should be raw text, got: {:?}", el.children);
  };
  assert_eq!(t.text, "{{ a }} <b>x</b>");
}

#[test]
fn v_pre_does_not_leak_into_siblings() {
  let (root, errors) = parse_template("<div v-pre>x</div><span>{{ real }}</span>", 0);
  assert!(errors.is_empty());
  let TemplateNode::Element(span) = &root.children[1] else {
    panic!();
  };
  assert!(matches!(span.children[0], TemplateNode::Interpolation(_)));
}

#[test]
fn stray_closing_tag_at_root_errors_and_terminates() {
  let (root, errors) = parse_template("<div></div></div>", 0);
  assert_eq!(errors.len(), 1);
  assert!(matches!(errors[0].message, "Unexpected closing tag"));
  assert_eq!(root.children.len(), 1);
}

#[test]
fn mismatched_closing_tag_records_error() {
  let (root, errors) = parse_template("<div><span></div></span>", 0);
  assert!(
    errors
      .iter()
      .any(|e| matches!(e.message, "Mismatched closing tag")),
    "errors: {errors:?}"
  );
  assert_eq!(root.children.len(), 1);
}

#[test]
fn unterminated_element_records_error_without_hanging() {
  let (root, errors) = parse_template("<div><span></div>", 0);
  assert!(!errors.is_empty());
  assert_eq!(root.children.len(), 1);
}

#[test]
fn stray_lt_consumed_as_text() {
  let (root, errors) = parse_template("a <1 b", 0);
  assert!(errors.is_empty());
  let TemplateNode::Text(t) = &root.children[0] else {
    panic!();
  };
  assert_eq!(t.text, "a <1 b");
}

#[test]
fn interpolation_span_excludes_closing_braces() {
  let (root, _) = parse_template("{{ name }}", 0);
  let TemplateNode::Interpolation(interp) = &root.children[0] else {
    panic!();
  };
  assert_eq!(interp.expression.raw, " name ");
  assert_eq!(interp.expression.span.start, 2);
  assert_eq!(interp.expression.span.end, 8);
  assert_eq!(interp.span.start, 0);
  assert_eq!(interp.span.end, 10);
}

#[test]
fn interpolation_handles_quoted_braces() {
  let (root, errors) = parse_template(r#"{{ "}}" }}"#, 0);
  assert!(errors.is_empty(), "errors: {errors:?}");
  let TemplateNode::Interpolation(interp) = &root.children[0] else {
    panic!();
  };
  assert_eq!(interp.expression.raw, r#" "}}" "#);
}

#[test]
fn interpolation_handles_nested_braces() {
  let (root, errors) = parse_template("{{ {a: {b: 1}} }}", 0);
  assert!(errors.is_empty(), "errors: {errors:?}");
  let TemplateNode::Interpolation(interp) = &root.children[0] else {
    panic!();
  };
  assert_eq!(interp.expression.raw, " {a: {b: 1}} ");
}

#[test]
fn interpolation_does_not_swallow_closing_tag() {
  let (root, errors) = parse_template("<div>{{ x </div>", 0);
  assert_eq!(errors.len(), 1);
  assert!(matches!(
    errors[0].message,
    "Unterminated `{{` interpolation"
  ));
  let TemplateNode::Element(el) = &root.children[0] else {
    panic!();
  };
  assert_eq!(el.children.len(), 0);
}

#[test]
fn dynamic_argument_span_excludes_bracket() {
  let (root, _) = parse_template(r#"<div :[key]="v"/>"#, 0);
  let TemplateNode::Element(el) = &root.children[0] else {
    panic!();
  };
  match &el.attributes[0] {
    Attribute::Directive(d) => match d.argument.as_ref().expect("argument") {
      DirectiveArgument::Dynamic(expr) => {
        assert_eq!(expr.raw, "key");
        assert_eq!(expr.span.start, 7);
        assert_eq!(expr.span.end, 10);
      }
      _ => panic!(),
    },
    _ => panic!(),
  }
}

#[test]
fn dynamic_argument_handles_nested_brackets() {
  let (root, errors) = parse_template(r#"<div :[arr[0]]="v"/>"#, 0);
  assert!(errors.is_empty(), "errors: {errors:?}");
  let TemplateNode::Element(el) = &root.children[0] else {
    panic!();
  };
  match &el.attributes[0] {
    Attribute::Directive(d) => match d.argument.as_ref().expect("argument") {
      DirectiveArgument::Dynamic(expr) => assert_eq!(expr.raw, "arr[0]"),
      _ => panic!(),
    },
    _ => panic!(),
  }
}

#[test]
fn dynamic_event_argument_parses() {
  let (root, errors) = parse_template(r#"<button @[event]="onEvent"/>"#, 0);
  assert!(errors.is_empty(), "errors: {errors:?}");
  let TemplateNode::Element(el) = &root.children[0] else {
    panic!();
  };
  match &el.attributes[0] {
    Attribute::OnDirective(d) => match d.argument.as_ref().expect("argument") {
      DirectiveArgument::Dynamic(expr) => assert_eq!(expr.raw, "event"),
      _ => panic!(),
    },
    _ => panic!("expected @ directive, got: {:?}", el.attributes[0]),
  }
}

#[test]
fn custom_directive_is_a_directive() {
  let (root, errors) = parse_template(r#"<input v-focus="true"/>"#, 0);
  assert!(errors.is_empty(), "errors: {errors:?}");
  let TemplateNode::Element(el) = &root.children[0] else {
    panic!();
  };
  assert!(matches!(el.attributes[0], Attribute::Directive(_)));
}

#[test]
fn v_slot_with_argument_parses() {
  let (root, errors) = parse_template(
    r#"<Comp><template v-slot:header="props">h</template></Comp>"#,
    0,
  );
  assert!(errors.is_empty(), "errors: {errors:?}");
  let TemplateNode::Element(comp) = &root.children[0] else {
    panic!();
  };
  let TemplateNode::Element(template) = &comp.children[0] else {
    panic!();
  };
  match &template.attributes[0] {
    Attribute::SlotDirective(d) => {
      let DirectiveArgument::Static(arg) = d.argument.as_ref().expect("argument") else {
        panic!();
      };
      assert_eq!(arg.name, "header");
    }
    _ => panic!("expected slot directive, got: {:?}", template.attributes[0]),
  }
}

#[test]
fn v_pre_inside_interpolation_is_unaffected() {
  // `v-pre` only guards the subtree of the element that carries it;
  // text outside must still produce interpolation nodes.
  let (root, errors) = parse_template("{{ x }}<div v-pre>{{ raw }}</div>", 0);
  assert!(errors.is_empty(), "errors: {errors:?}");
  assert!(matches!(root.children[0], TemplateNode::Interpolation(_)));
}

use crate::parser::template::{Attribute, DirectiveArgument, TemplateNode};
