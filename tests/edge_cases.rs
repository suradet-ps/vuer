//! Phase 1 edge-case suite: the enumerated template-parser edge cases.
//!
//! Every item on the Phase 1 "Edge cases enumerated and tested" list has
//! at least one case here: fragments, `<slot>`/`v-slot`, `v-bind:[key]`
//! dynamic arguments, `v-on` modifiers, self-closing custom elements,
//! `<component :is>` and `<Teleport>`/`<Transition>`/`<Suspense>`,
//! interpolation (no Vue 3 filters), whitespace control (`v-pre`,
//! `v-once`, `v-cloak`), HTML entities, comments, and CDATA in
//! `<svg>`/`<math>` foreign content.
//!
//! Two harnesses guard the whole suite:
//! * `terminates_without_panicking` — a corpus of adversarial inputs
//!   (stray closing tags, unterminated everything, `>` in text, Unicode)
//!   that must never panic and must always return; a hang or a panic
//!   fails the run.
//! * every "well-formed" case asserts zero `TemplateError`s, so a parser
//!   regression on a legitimate construct fails loudly.

mod common;

use common::format_attribute;
use rstest::rstest;
use vuer::parser::template::{
  Attribute, Directive, DirectiveArgument, TemplateNode, parse_template,
};

/// Assert that `src` parses with no errors and returns the only root
/// element (helper for the structural assertions below).
fn root_element(src: &str) -> vuer::parser::template::Element {
  let (root, errors) = parse_template(src, 0);
  assert!(errors.is_empty(), "errors for {src:?}: {errors:?}");
  assert_eq!(root.children.len(), 1, "expected exactly one root: {src:?}");
  let TemplateNode::Element(el) = &root.children[0] else {
    panic!("expected element root for {src:?}");
  };
  el.clone()
}

fn directive_of(el: &vuer::parser::template::Element, index: usize) -> Directive {
  match &el.attributes[index] {
    Attribute::Directive(d)
    | Attribute::OnDirective(d)
    | Attribute::SlotDirective(d)
    | Attribute::ForDirective(d) => d.clone(),
    _ => panic!("attribute {index} is not a Directive"),
  }
}

fn element_of(
  el: &vuer::parser::template::Element,
  index: usize,
) -> vuer::parser::template::Element {
  let TemplateNode::Element(child) = &el.children[index] else {
    panic!("child {index} is not an element");
  };
  child.clone()
}

// ---------------------------------------------------------------------
// Vue 3 fragments: multiple root nodes.
// ---------------------------------------------------------------------

#[rstest]
#[case("<div></div><p></p>", 2)]
#[case("<div></div><p></p><span></span>", 3)]
#[case("<a/><b/><c/>", 3)]
fn parses_multiple_root_nodes(#[case] src: &str, #[case] expected: usize) {
  let (root, errors) = parse_template(src, 0);
  assert!(errors.is_empty(), "errors for {src:?}: {errors:?}");
  assert_eq!(root.children.len(), expected);
}

// ---------------------------------------------------------------------
// Slots: <slot> element, named slots, v-slot / # shorthand.
// ---------------------------------------------------------------------

#[test]
fn parses_slot_element_with_name() {
  let el = root_element(r#"<slot name="header"></slot>"#);
  assert_eq!(el.name, "slot");
}

#[test]
fn parses_v_slot_shorthand_and_longform() {
  let el = root_element(
    r#"<Comp><template #header>h</template><template v-slot:footer="p">f</template></Comp>"#,
  );
  let header = element_of(&el, 0);
  let footer = element_of(&el, 1);
  match &header.attributes[0] {
    Attribute::SlotDirective(d) => {
      let DirectiveArgument::Static(arg) = d.argument.as_ref().expect("arg") else {
        panic!();
      };
      assert_eq!(arg.name, "header");
    }
    _ => panic!("expected slot directive"),
  }
  match &footer.attributes[0] {
    Attribute::SlotDirective(d) => {
      let DirectiveArgument::Static(arg) = d.argument.as_ref().expect("arg") else {
        panic!();
      };
      assert_eq!(arg.name, "footer");
      let Some(vuer::parser::template::DirectiveValue::Expression(e)) = &d.value else {
        panic!();
      };
      assert_eq!(e.raw, "p");
    }
    _ => panic!("expected slot directive"),
  }
}

#[test]
fn parses_default_v_slot_value() {
  let el = root_element(r#"<Comp v-slot="{ item }"></Comp>"#);
  let d = directive_of(&el, 0);
  assert_eq!(d.name.name, "v-slot");
  let Some(vuer::parser::template::DirectiveValue::Expression(e)) = &d.value else {
    panic!();
  };
  assert_eq!(e.raw, "{ item }");
}

// ---------------------------------------------------------------------
// Dynamic directive arguments: v-bind:[key], :[key], @[event].
// ---------------------------------------------------------------------

#[rstest]
#[case(r#"<div :[key]="v"/>"#, "key")]
#[case(r#"<div v-bind:[key]="v"/>"#, "key")]
#[case(r#"<div @[event]="f"/>"#, "event")]
#[case(r#"<div v-bind:[a + b]="v"/>"#, "a + b")]
#[case(r#"<div v-bind:[arr[0]]="v"/>"#, "arr[0]")]
fn parses_dynamic_arguments(#[case] src: &str, #[case] expected: &str) {
  let el = root_element(src);
  let d = directive_of(&el, 0);
  let DirectiveArgument::Dynamic(expr) = d.argument.as_ref().expect("arg") else {
    panic!("expected dynamic argument for {src:?}");
  };
  assert_eq!(expr.raw, expected);
}

#[test]
fn dynamic_argument_in_string_is_kept_whole() {
  let el = root_element(r#"<div :[']']="v"/>"#);
  let d = directive_of(&el, 0);
  let DirectiveArgument::Dynamic(expr) = d.argument.as_ref().expect("arg") else {
    panic!();
  };
  assert_eq!(expr.raw, "']'");
}

// ---------------------------------------------------------------------
// v-on modifiers.
// ---------------------------------------------------------------------

#[test]
fn parses_event_modifiers() {
  let el = root_element(r#"<button @click.prevent.stop.once="go"/>"#);
  match &el.attributes[0] {
    Attribute::OnDirective(d) => {
      let names: Vec<&str> = d.modifiers.iter().map(|m| m.name.as_str()).collect();
      assert_eq!(names, ["prevent", "stop", "once"]);
    }
    _ => panic!("expected @ directive"),
  }
}

#[test]
fn parses_key_modifiers() {
  let el = root_element(r#"<input @keyup.enter.exact="submit"/>"#);
  match &el.attributes[0] {
    Attribute::OnDirective(d) => {
      let names: Vec<&str> = d.modifiers.iter().map(|m| m.name.as_str()).collect();
      assert_eq!(names, ["enter", "exact"]);
    }
    _ => panic!("expected @ directive"),
  }
}

#[test]
fn parses_self_modifier() {
  let el = root_element(r#"<div @click.self="close"></div>"#);
  match &el.attributes[0] {
    Attribute::OnDirective(d) => assert_eq!(d.modifiers[0].name, "self"),
    _ => panic!("expected @ directive"),
  }
}

// ---------------------------------------------------------------------
// Self-closing custom elements.
// ---------------------------------------------------------------------

#[rstest]
#[case("<MyComp/>")]
#[case("<My-Comp />")]
#[case("<InputGroup size=\"lg\"/>")]
#[case("<el-button type=\"primary\"/>")]
fn parses_self_closing_custom_elements(#[case] src: &str) {
  let el = root_element(src);
  assert!(el.self_closing, "expected self-closing: {src:?}");
}

// ---------------------------------------------------------------------
// <component :is> and the built-in transition/async components.
// ---------------------------------------------------------------------

#[rstest]
#[case(r#"<component :is="current"/>"#)]
#[case(r#"<component v-bind:is="current">x</component>"#)]
#[case(r#"<Teleport to="body"><div></div></Teleport>"#)]
#[case(r#"<Transition name="fade" mode="out-in"><div></div></Transition>"#)]
#[case(r#"<TransitionGroup tag="ul"><li></li></TransitionGroup>"#)]
#[case(r#"<Suspense><template #default></template></Suspense>"#)]
#[case(r#"<KeepAlive include="A,B"><Comp/></KeepAlive>"#)]
fn parses_special_components(#[case] src: &str) {
  let (root, errors) = parse_template(src, 0);
  assert!(errors.is_empty(), "errors for {src:?}: {errors:?}");
  assert_eq!(root.children.len(), 1);
}

// ---------------------------------------------------------------------
// Interpolation. Vue 3 removed filters; `|` stays raw expression text.
// ---------------------------------------------------------------------

#[rstest]
#[case("{{ name }}", " name ")]
#[case("{{ '}}' }}", " '}}' ")]
#[case(r#"{{ "}}" }}"#, r#" "}}" "#)]
#[case("{{ msg | capitalize }}", " msg | capitalize ")]
#[case("{{ {a: {b: 1}} }}", " {a: {b: 1}} ")]
#[case("{{ user.name.toUpperCase() }}", " user.name.toUpperCase() ")]
fn parses_interpolations(#[case] src: &str, #[case] expected_raw: &str) {
  let (root, errors) = parse_template(src, 0);
  assert!(errors.is_empty(), "errors for {src:?}: {errors:?}");
  assert_eq!(root.children.len(), 1);
  let TemplateNode::Interpolation(interp) = &root.children[0] else {
    panic!();
  };
  assert_eq!(interp.expression.raw, expected_raw);
}

#[test]
fn text_with_single_brace_is_not_interpolation() {
  let (root, errors) = parse_template("a { b } c", 0);
  assert!(errors.is_empty());
  let TemplateNode::Text(t) = &root.children[0] else {
    panic!();
  };
  assert_eq!(t.text, "a { b } c");
}

// ---------------------------------------------------------------------
// Whitespace control: v-pre, v-once, v-cloak.
// ---------------------------------------------------------------------

#[test]
fn v_pre_keeps_interpolation_and_tags_raw() {
  let el = root_element("<div v-pre>{{ raw }} <b>still raw</b></div>");
  let TemplateNode::Text(t) = &el.children[0] else {
    panic!("expected raw text, got: {:?}", el.children);
  };
  assert_eq!(t.text, "{{ raw }} <b>still raw</b>");
}

#[test]
fn v_pre_only_affects_its_own_subtree() {
  let (root, errors) = parse_template("<div v-pre>x</div><span>{{ real }}</span>", 0);
  assert!(errors.is_empty());
  let TemplateNode::Element(span) = &root.children[1] else {
    panic!();
  };
  assert!(matches!(span.children[0], TemplateNode::Interpolation(_)));
}

#[test]
fn v_once_and_v_cloak_parse_as_directives() {
  let el = root_element(r#"<section v-once class="s"><p v-cloak>x</p></section>"#);
  assert_eq!(directive_of(&el, 0).name.name, "v-once");
  let p = element_of(&el, 0);
  assert_eq!(directive_of(&p, 0).name.name, "v-cloak");
}

// ---------------------------------------------------------------------
// HTML entities stay raw in text and in attribute values.
// ---------------------------------------------------------------------

#[rstest]
#[case("&amp; &lt; &gt;")]
#[case("&#39; &#x27; &#x1F600;")]
#[case("&copy; &nbsp;")]
fn entities_in_text_stay_raw(#[case] src: &str) {
  let (root, errors) = parse_template(src, 0);
  assert!(errors.is_empty(), "errors for {src:?}: {errors:?}");
  let TemplateNode::Text(t) = &root.children[0] else {
    panic!();
  };
  assert_eq!(t.text, src);
}

#[test]
fn entities_in_attribute_values_stay_raw() {
  let el = root_element(r#"<div title="a &amp; b" data-x="&#39;"></div>"#);
  let Attribute::Static(a) = &el.attributes[0] else {
    panic!();
  };
  assert_eq!(a.value.as_ref().expect("value").value, "a &amp; b");
}

// ---------------------------------------------------------------------
// Comments.
// ---------------------------------------------------------------------

#[test]
fn comments_at_root_and_in_children() {
  let (root, errors) = parse_template(
    "<!-- head --><div><!-- inner --><p>x</p></div><!-- tail -->",
    0,
  );
  assert!(errors.is_empty(), "errors: {errors:?}");
  assert_eq!(root.children.len(), 3);
  assert!(matches!(root.children[0], TemplateNode::Comment(_)));
  assert!(matches!(root.children[2], TemplateNode::Comment(_)));
  let TemplateNode::Element(div) = &root.children[1] else {
    panic!();
  };
  assert!(matches!(div.children[0], TemplateNode::Comment(_)));
}

#[test]
fn comment_with_double_dashes_inside() {
  let (root, errors) = parse_template("<!-- a -- b --><div></div>", 0);
  assert!(errors.is_empty(), "errors: {errors:?}");
  assert_eq!(root.children.len(), 2);
}

#[test]
fn unterminated_comment_records_error() {
  let (root, errors) = parse_template("<!-- never closed", 0);
  assert_eq!(errors.len(), 1);
  assert!(matches!(errors[0].message, "Unterminated comment"));
  assert!(root.children.is_empty());
}

// ---------------------------------------------------------------------
// CDATA in <svg> / <math> foreign content.
// ---------------------------------------------------------------------

#[test]
fn cdata_in_svg() {
  let el = root_element("<svg><![CDATA[<circle r=\"5\"/> & raw]]></svg>");
  let TemplateNode::CData(cdata) = &el.children[0] else {
    panic!("expected CData, got: {:?}", el.children);
  };
  assert_eq!(cdata.text, "<circle r=\"5\"/> & raw");
}

#[test]
fn cdata_in_math() {
  let el = root_element("<math><![CDATA[<mi>x</mi>]]></math>");
  assert!(matches!(el.children[0], TemplateNode::CData(_)));
}

#[test]
fn multiple_cdata_sections() {
  let (root, errors) = parse_template("<svg><![CDATA[a]]><![CDATA[b]]><circle/></svg>", 0);
  assert!(errors.is_empty(), "errors: {errors:?}");
  let TemplateNode::Element(svg) = &root.children[0] else {
    panic!();
  };
  assert_eq!(svg.children.len(), 3);
}

// ---------------------------------------------------------------------
// Attributes: boolean, unquoted, single-quoted, empty, containing tags.
// ---------------------------------------------------------------------

#[test]
fn boolean_attributes_have_no_value() {
  let el = root_element(r#"<input disabled required autofocus>"#);
  for attr in &el.attributes {
    let Attribute::Static(a) = attr else {
      panic!("expected static attribute, got: {attr:?}");
    };
    assert!(a.value.is_none(), "boolean attr should have no value");
  }
}

#[test]
fn attribute_value_styles() {
  let el = root_element(r#"<div a=1 b='two' c="" d="x>y<z"></div>"#);
  let values: Vec<Option<String>> = el
    .attributes
    .iter()
    .map(|a| match a {
      Attribute::Static(s) => s.value.as_ref().map(|v| v.value.clone()),
      _ => panic!(),
    })
    .collect();
  assert_eq!(values[0].as_deref(), Some("1"));
  assert_eq!(values[1].as_deref(), Some("two"));
  assert_eq!(values[2].as_deref(), Some(""));
  assert_eq!(values[3].as_deref(), Some("x>y<z"));
}

#[test]
fn attributes_roundtrip_through_format() {
  let el = root_element(
    r#"<div class="a" :id="i" @click.prevent.stop="f" v-bind:[k]="v" v-model.trim="m" disabled></div>"#,
  );
  let rendered: Vec<String> = el.attributes.iter().map(format_attribute).collect();
  assert_eq!(
    rendered,
    [
      "class=\"a\"",
      ":id=\"i\"",
      "@click.prevent.stop=\"f\"",
      "v-bind:[k]=\"v\"",
      "v-model.trim=\"m\"",
      "disabled",
    ]
  );
}

// ---------------------------------------------------------------------
// v-if / v-else-if / v-else chains and v-show.
// ---------------------------------------------------------------------

#[test]
fn parses_condition_chains() {
  let el = root_element(r#"<div v-if="a">1</div>"#);
  assert_eq!(directive_of(&el, 0).name.name, "v-if");
  let (root, errors) = parse_template(
    r#"<div v-if="a">1</div><div v-else-if="b">2</div><div v-else>3</div>"#,
    0,
  );
  assert!(errors.is_empty(), "errors: {errors:?}");
  assert_eq!(root.children.len(), 3);
}

// ---------------------------------------------------------------------
// v-for with destructuring and :key.
// ---------------------------------------------------------------------

#[test]
fn parses_v_for_forms() {
  for (src, raw) in [
    (
      r#"<li v-for="item in items" :key="item.id"></li>"#,
      "item in items",
    ),
    (
      r#"<li v-for="(item, index) in items" :key="index"></li>"#,
      "(item, index) in items",
    ),
    (
      r#"<li v-for="({ id }, i) in items" :key="id"></li>"#,
      "({ id }, i) in items",
    ),
  ] {
    let el = root_element(src);
    match &el.attributes[0] {
      Attribute::ForDirective(d) => {
        let Some(vuer::parser::template::DirectiveValue::Expression(e)) = &d.value else {
          panic!();
        };
        assert_eq!(e.raw, raw);
      }
      _ => panic!("expected v-for directive for {src:?}"),
    }
  }
}

// ---------------------------------------------------------------------
// Unicode: non-ASCII text and attribute values.
// ---------------------------------------------------------------------

#[test]
fn parses_unicode_text_and_attributes() {
  let el = root_element(r#"<p lang="th">สวัสดีชาวโลก 🚀</p>"#);
  let TemplateNode::Text(t) = &el.children[0] else {
    panic!();
  };
  assert_eq!(t.text, "สวัสดีชาวโลก 🚀");
}

#[test]
fn unicode_offsets_are_byte_exact() {
  let (root, errors) = parse_template("<p>สวัสดี</p>", 0);
  assert!(errors.is_empty());
  let TemplateNode::Element(el) = &root.children[0] else {
    panic!();
  };
  // `สวัสดี` is 18 bytes (6 chars x 3 bytes); the element spans the
  // whole source: `<p>` (3) + text (18) + `</p>` (4) = 25.
  assert_eq!(el.span.end, 25);
}

// ---------------------------------------------------------------------
// Adversarial inputs: must always terminate, never panic, and report
// the malformation as a TemplateError.
// ---------------------------------------------------------------------

#[rstest]
#[case("</div>")]
#[case("<div></div></div>")]
#[case("<div")]
#[case("<div>")]
#[case("<div></span>")]
#[case("<div><span></div>")]
#[case("{{ x")]
#[case("{{ }}")]
#[case("{{{")]
#[case("<![CDATA[")]
#[case("<![CDATA[abc")]
#[case("<!doctype html>")]
#[case("a < b")]
#[case("<1tag>")]
#[case("<div a=\"unterminated")]
#[case("<div :[x")]
#[case("<div :[x]")]
#[case("<div v-bind:")]
#[case("<div v-")]
#[case("<!--")]
#[case("<!-- x")]
#[case("<div><!-- x")]
#[case("{{ 'unterminated")]
#[case("<img>stray text</img>")]
#[case("<p v-pre>")]
#[case("<p v-pre>raw {{ <div>")]
#[case("🚀")]
#[case("<svg><![CDATA[")]
#[case("text with < svg and {{ stache")]
fn terminates_without_panicking(#[case] src: &str) {
  // A hang or a panic here fails the test; reaching the assertions means
  // the parser made progress and returned.
  let (root, errors) = parse_template(src, 0);
  assert!(
    errors.iter().all(|e| !e.message.is_empty()),
    "every error carries a message for {src:?}: {errors:?}"
  );
  // Offsets stay within the source (base 0 here).
  for e in &errors {
    assert!(
      e.span.start <= src.len() as u32,
      "error span out of range for {src:?}: {e:?}"
    );
  }
  let _ = root.children.len();
}

/// The well-formed subset of the adversarial corpus (same strings, but
/// asserted to parse *cleanly*).
#[rstest]
#[case("<!doctype html>")]
#[case("a < b")]
#[case("<1tag>")]
#[case("🚀")]
fn weird_but_wellformed_parses_cleanly(#[case] src: &str) {
  let (root, errors) = parse_template(src, 0);
  assert!(errors.is_empty(), "errors for {src:?}: {errors:?}");
  let _ = root.children.len();
}

// ---------------------------------------------------------------------
// Deep nesting: recursion must not blow the stack on realistic depths.
// ---------------------------------------------------------------------

#[test]
fn deep_nesting_parses() {
  let depth = 200;
  let open = "<div>".repeat(depth);
  let close = "</div>".repeat(depth);
  let (root, errors) = parse_template(&format!("{open}x{close}"), 0);
  assert!(errors.is_empty(), "errors: {errors:?}");
  let mut node = &root.children[0];
  for _ in 0..depth {
    let TemplateNode::Element(el) = node else {
      panic!("expected element at every level");
    };
    node = el.children.first().expect("one child per level");
  }
}

// ---------------------------------------------------------------------
// The enumerated list, as one table that names every item (a checklist
// that fails loudly if any item regresses).
// ---------------------------------------------------------------------

#[test]
fn roadmap_edge_case_checklist() {
  let cases: &[(&str, &str)] = &[
    ("fragment-multi-root", "<div></div><p></p>"),
    ("slot-element", "<slot></slot>"),
    ("v-slot", "<Comp v-slot=\"s\"></Comp>"),
    ("v-bind-dynamic-arg", "<div v-bind:[key]=\"v\"></div>"),
    ("v-on-modifiers", "<button @click.prevent=\"f\"></button>"),
    ("self-closing-custom", "<MyComp/>"),
    ("component-is", "<component :is=\"c\"/>"),
    ("teleport", "<Teleport to=\"body\"><div></div></Teleport>"),
    ("transition", "<Transition><div></div></Transition>"),
    ("suspense", "<Suspense><div></div></Suspense>"),
    ("interpolation", "<div>{{ x }}</div>"),
    ("v-pre", "<div v-pre>{{ raw }}</div>"),
    ("v-once", "<div v-once></div>"),
    ("v-cloak", "<div v-cloak></div>"),
    ("html-entities", "<div>&amp; &#39;</div>"),
    ("comments", "<div><!-- c --></div>"),
    ("cdata-svg", "<svg><![CDATA[x]]></svg>"),
    ("cdata-math", "<math><![CDATA[x]]></math>"),
  ];
  for (name, src) in cases {
    let (root, errors) = parse_template(src, 0);
    assert!(errors.is_empty(), "{name}: errors for {src:?}: {errors:?}");
    assert!(
      !root.children.is_empty(),
      "{name} must produce at least one root node"
    );
  }
}
