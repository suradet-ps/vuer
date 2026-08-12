//! Phase 1 offset-integrity property tests.
//!
//! The core property: **every node's span resolves to the exact source
//! bytes that produced the node**. For leaf nodes the span slice must
//! equal the node's stored text; for elements the slice must start with
//! `<name` and end with `</name>` / `/>`, and children must lie inside
//! the parent, in order, without overlapping.
//!
//! This catches the class of bug where a span drifts from the bytes that
//! produced it (e.g. an interpolation expression span that included the
//! closing `}}`), which silently mis-locates diagnostics in the original
//! file. The same walker runs over:
//!
//!   1. the conformance corpus (real offsets inside `.vue` files, with a
//!      non-zero base — the SFC template offset);
//!   2. a canonical inline corpus of tricky constructs;
//!   3. a small *generated* corpus (nesting x attribute-count sweep) at
//!      two base offsets (0 and a large one), which is the property-test
//!      flavour — full `proptest` fuzzing is scheduled for Phase 8.

mod common;

use std::path::PathBuf;

use common::format_attribute;
use vuer::context::ScanContext;
use vuer::parser::parse_sfc;
use vuer::parser::template::{Attribute, DirectiveValue, TemplateNode, parse_template};
use vuer::parser::template::{Directive, StaticAttribute};

struct Checker<'a> {
  source: &'a str,
  base: u32,
  failures: Vec<String>,
  path: String,
}

/// Renderer emits double quotes around values; source may use single
/// quotes or none. Normalise both sides by stripping the value quotes so
/// the comparison is quote-style agnostic.
fn strip_value_quotes(s: &str) -> String {
  match s.find('=') {
    Some(eq) => {
      let value = &s[eq + 1..];
      let value = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
        .unwrap_or(value);
      format!("{}={}", &s[..eq], value)
    }
    None => s.to_string(),
  }
}

impl<'a> Checker<'a> {
  fn new(source: &'a str, base: u32, path: String) -> Self {
    Self {
      source,
      base,
      failures: Vec::new(),
      path,
    }
  }

  /// Slice `source` by the absolute span, shifted back by `base`.
  fn slice(&self, span: oxc_span::Span) -> Option<&'a str> {
    let start = span.start.checked_sub(self.base)? as usize;
    let end = span.end.checked_sub(self.base)? as usize;
    if start <= end && end <= self.source.len() {
      Some(&self.source[start..end])
    } else {
      None
    }
  }

  fn expect(&mut self, span: oxc_span::Span, expected: &str, what: &str) {
    match self.slice(span) {
      Some(actual) if actual == expected => {}
      Some(actual) => self.fail(&format!(
        "{what}: expected {expected:?}, got {actual:?} (span {span:?})"
      )),
      None => self.fail(&format!(
        "{what}: span {span:?} out of bounds (base {}, len {})",
        self.base,
        self.source.len()
      )),
    }
  }

  fn fail(&mut self, msg: &str) {
    self.failures.push(format!("{}: {}", self.path, msg));
  }

  fn check_attr(&mut self, attr: &Attribute, index: usize) {
    let what = format!("attr[{index}]");
    let expected = strip_value_quotes(&format_attribute(attr));
    match self.slice(attr.span()) {
      Some(actual) if strip_value_quotes(actual) == expected => {}
      Some(actual) => self.fail(&format!(
        "{what}: expected {expected:?}, got {:?} (span {:?})",
        actual,
        attr.span()
      )),
      None => self.fail(&format!("{what}: span {:?} out of bounds", attr.span())),
    }

    match attr {
      Attribute::Static(a) => self.check_static(a),
      Attribute::Directive(d)
      | Attribute::OnDirective(d)
      | Attribute::SlotDirective(d)
      | Attribute::ForDirective(d) => self.check_directive(d),
    }
  }

  fn check_static(&mut self, a: &StaticAttribute) {
    self.expect(a.key.span, &a.key.raw_name, "static key");
    if let Some(v) = &a.value {
      self.expect_value(v.span, &v.value, "static value");
    }
  }

  fn check_directive(&mut self, d: &Directive) {
    self.expect(d.name.span, &d.name.raw_name, "directive name");
    if let Some(arg) = &d.argument {
      match arg {
        vuer::parser::template::DirectiveArgument::Static(id) => {
          self.expect(id.span, &id.raw_name, "argument");
        }
        vuer::parser::template::DirectiveArgument::Dynamic(expr) => {
          self.expect(expr.span, &expr.raw, "dynamic argument");
        }
      }
    }
    for m in &d.modifiers {
      self.expect(m.span, &m.raw_name, "modifier");
    }
    if let Some(DirectiveValue::Expression(e)) = &d.value {
      self.expect_value(e.span, &e.raw, "directive value");
    }
  }

  /// Value spans cover the quoted string, so strip the surrounding
  /// quotes (when present) before comparing with the stored raw text.
  fn expect_value(&mut self, span: oxc_span::Span, expected: &str, what: &str) {
    match self.slice(span) {
      Some(actual) => {
        let stripped = actual
          .strip_prefix('"')
          .and_then(|s| s.strip_suffix('"'))
          .or_else(|| actual.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
          .unwrap_or(actual);
        if stripped != expected {
          self.fail(&format!("{what}: expected {expected:?}, got {actual:?}"));
        }
      }
      None => self.fail(&format!("{what}: span {span:?} out of bounds")),
    }
  }

  fn check_node(&mut self, node: &TemplateNode) {
    match node {
      TemplateNode::Text(t) => self.expect(t.span, &t.text, "text"),
      TemplateNode::Comment(c) => self.expect(c.span, &format!("<!--{}-->", c.value), "comment"),
      TemplateNode::CData(c) => self.expect(c.span, &format!("<![CDATA[{}]]>", c.text), "cdata"),
      TemplateNode::Interpolation(i) => {
        self.expect(
          i.span,
          &format!("{{{{{}}}}}", i.expression.raw),
          "interpolation",
        );
        self.expect(i.expression.span, &i.expression.raw, "interpolation expr");
      }
      TemplateNode::Element(el) => self.check_element(el),
    }
  }

  fn check_element(&mut self, el: &vuer::parser::template::Element) {
    let Some(text) = self.slice(el.span) else {
      self.fail(&format!(
        "element <{}>: span {el:?} out of bounds",
        el.raw_name
      ));
      return;
    };
    let open = format!("<{}", el.raw_name);
    if !text.starts_with(&open) {
      self.fail(&format!(
        "element <{}>: slice starts with {:?}, expected {:?}",
        el.raw_name,
        &text[..text.len().min(open.len())],
        open
      ));
    }
    if el.self_closing {
      if !(text.ends_with("/>") || text.ends_with('>')) {
        self.fail(&format!(
          "self-closing element <{}>: slice {:?} does not end with /> or >",
          el.raw_name, text
        ));
      }
    } else {
      let close = format!("</{}>", el.raw_name);
      if !text.ends_with(&close) {
        self.fail(&format!(
          "element <{}>: slice {:?} does not end with {:?}",
          el.raw_name, text, close
        ));
      }
    }

    for (i, attr) in el.attributes.iter().enumerate() {
      self.check_attr(attr, i);
    }

    // Children: inside the element, in source order, non-overlapping.
    let start = (el.span.start - self.base) as usize;
    let end = (el.span.end - self.base) as usize;
    let mut prev = start;
    for child in &el.children {
      let cs = (child.span().start - self.base) as usize;
      let ce = (child.span().end - self.base) as usize;
      if cs < prev || ce > end || cs > ce {
        self.fail(&format!(
          "element <{}>: child span {cs}..{ce} violates containment/order inside {start}..{end}",
          el.raw_name
        ));
      }
      prev = ce;
      self.check_node(child);
    }
  }
}

fn assert_integrity(src: &str, base: u32, path: &str) {
  let (root, errors) = parse_template(src, base);
  assert!(
    errors.is_empty(),
    "{path}: integrity corpus must parse cleanly, got: {errors:?}"
  );
  let mut checker = Checker::new(src, base, path.to_string());
  for node in &root.children {
    checker.check_node(node);
  }
  assert!(
    checker.failures.is_empty(),
    "offset integrity violations for {path} (base {base}):\n{}",
    checker.failures.join("\n")
  );
}

fn manifest_dir() -> PathBuf {
  PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

// ---------------------------------------------------------------------
// 1. The conformance corpus: real SFC offsets (non-zero base).
// ---------------------------------------------------------------------

#[test]
fn conformance_fixtures_keep_offsets_integrity() {
  let dir = manifest_dir().join("tests/fixtures/templates");
  let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
    .expect("conformance corpus dir")
    .map(|e| e.expect("dir entry").path())
    .collect();
  files.sort();
  assert!(!files.is_empty());

  for path in &files {
    let name = path.file_name().unwrap().to_string_lossy().into_owned();
    let source = std::fs::read_to_string(path).expect("fixture readable");
    let mut ctx = ScanContext::new(path.clone(), source);
    parse_sfc(&mut ctx);
    assert!(ctx.template_errors.is_empty(), "{name} must be clean");
    let root = ctx.template_ast.as_ref().expect("template block");
    // Spans are absolute byte offsets into the whole `.vue` file, so the
    // checker slices `ctx.source` with base 0.
    let mut checker = Checker::new(&ctx.source, 0, name.clone());
    for node in &root.children {
      checker.check_node(node);
    }
    assert!(
      checker.failures.is_empty(),
      "offset integrity violations for {name}:\n{}",
      checker.failures.join("\n")
    );
  }
}

// ---------------------------------------------------------------------
// 2. Canonical inline corpus of tricky constructs.
// ---------------------------------------------------------------------

const CANONICAL: &[&str] = &[
  "<div></div>",
  "<div a=\"1\">x</div>",
  "<div a=\"1\" b=\"2\" c></div>",
  "<div :a=\"x\" @click=\"f\" v-if=\"ok\">y</div>",
  "<div v-bind:src=\"u\" v-on:click.prevent=\"f\" v-slot:default=\"p\"></div>",
  "<div :[k]=\"v\" @[e]=\"f\" #[\"s\"]></div>",
  "<div :x=\"a ? 'b' : 'c'\"></div>",
  "<MyComp/><Other-Comp size=\"lg\"/>",
  "<svg><![CDATA[<circle/> & raw]]><path/></svg>",
  "<math><![CDATA[x]]></math>",
  "<!-- top --><div><!-- inner --><p>{{ name }}</p></div><!-- tail -->",
  "<div v-pre>{{ raw }} <b>x</b></div>",
  "<div v-once v-cloak class=\"s\">x</div>",
  "<ul><li v-for=\"(item, i) in items\" :key=\"i\">{{ item }}</li></ul>",
  "<div>{{ {a: {b: 1}} }}</div>",
  "<div>{{ '}}' }}</div>",
  "<div>{{ }} </div>",
  "<p lang=\"th\">สวัสดี 🚀</p>",
  "<div title=\"a &amp; b\" data-x=\"&#39;\"></div>",
  "<component :is=\"c\"/><Teleport to=\"body\"><Transition name=\"f\"><div v-if=\"x\"></div></Transition></Teleport>",
  "<div a=1 b='two'></div>",
  "<input required disabled>",
  "<br/><img src=\"i.png\" alt=\"\"><hr/>",
  "<div class=\"a\">text with < b and {{ x }} inside</div>",
  "<div>\n  <span>multi</span>\n  line\n</div>",
];

#[test]
fn canonical_corpus_keeps_offsets_integrity() {
  for (i, src) in CANONICAL.iter().enumerate() {
    assert_integrity(src, 0, &format!("canonical[{i}]"));
  }
}

// ---------------------------------------------------------------------
// 3. Generated corpus: nesting x attribute-count sweep, at two bases.
// ---------------------------------------------------------------------

fn generated_corpus() -> Vec<String> {
  let mut out = Vec::new();
  for depth in 0..=3 {
    for attrs in 0..=3 {
      let mut s = String::new();
      for _ in 0..depth {
        s.push_str("<div");
        for i in 0..attrs {
          s.push_str(&format!(" a{i}=\"v{i}\""));
        }
        s.push('>');
      }
      s.push_str("{{ x }}");
      for _ in 0..depth {
        s.push_str("</div>");
      }
      out.push(s);
    }
  }
  // Interpolation-dense and attribute-dense shapes.
  out.push("{{ a }}{{ b }}{{ c }}".to_string());
  out.push("<div :x=\"1\" :y=\"2\" :z=\"3\" @k=\"f\" v-a=\"1\" v-b=\"2\"></div>".to_string());
  out
}

#[test]
fn generated_corpus_keeps_offsets_integrity() {
  let corpus = generated_corpus();
  assert!(!corpus.is_empty());
  for (i, src) in corpus.iter().enumerate() {
    // Base 0 and a large base: the property must hold regardless of the
    // offset the SFC extractor would choose.
    assert_integrity(src, 0, &format!("generated[{i}](base=0)"));
    assert_integrity(src, 100_000, &format!("generated[{i}](base=100k)"));
  }
}

// ---------------------------------------------------------------------
// 4. The documented span contracts, asserted individually.
// ---------------------------------------------------------------------

#[test]
fn span_contracts_hold() {
  let (root, errors) = parse_template("<div :[key]=\"v\">{{ x }}</div>", 500);
  assert!(errors.is_empty());

  let TemplateNode::Element(el) = &root.children[0] else {
    panic!();
  };
  // Element span is absolute (base included).
  assert_eq!(el.span.start, 500);
  assert_eq!(
    el.span.end,
    500 + "<div :[key]=\"v\">{{ x }}</div>".len() as u32
  );

  // Dynamic argument excludes the brackets.
  let Attribute::Directive(d) = &el.attributes[0] else {
    panic!();
  };
  let vuer::parser::template::DirectiveArgument::Dynamic(expr) = d.argument.as_ref().expect("arg")
  else {
    panic!();
  };
  assert_eq!(expr.raw, "key");
  assert_eq!(expr.span.start, 500 + 7);
  assert_eq!(expr.span.end, 500 + 10);

  // Interpolation expression excludes the braces.
  let TemplateNode::Interpolation(interp) = &el.children[0] else {
    panic!();
  };
  assert_eq!(interp.expression.raw, " x ");
  assert_eq!(interp.expression.span.start, 500 + 18);
  assert_eq!(interp.expression.span.end, 500 + 21);
}

#[test]
fn root_span_covers_the_whole_input() {
  let src = "<div>a</div><p>b</p>";
  let (root, _) = parse_template(src, 7);
  assert_eq!(root.span.start, 7);
  assert_eq!(root.span.end, 7 + src.len() as u32);
}

// ---------------------------------------------------------------------
// 5. Rule-level spot check: diagnostics reported by a template rule
//    point at the same bytes the AST claims. Guards against a future
//    rule reading spans off the trimmed block instead of the file.
// ---------------------------------------------------------------------

#[test]
fn rule_diagnostics_line_up_with_ast_spans() {
  use vuer::scanner::{ScanOptions, Scanner};

  let fixture = manifest_dir().join("tests/fixtures/vulnerable_full.vue");
  let scanner = Scanner::new();
  let report = scanner
    .scan_file(&fixture, &[], &ScanOptions::default())
    .expect("scan succeeds");

  // Every v-for-missing-key finding must sit on the exact <li v-for>
  // element the template parser produced.
  let source = std::fs::read_to_string(&fixture).expect("fixture readable");
  let mut ctx = ScanContext::new(fixture.clone(), source);
  parse_sfc(&mut ctx);
  let root = ctx.template_ast.as_ref().expect("template");

  fn collect_vfor(node: &TemplateNode, out: &mut Vec<oxc_span::Span>) {
    if let TemplateNode::Element(el) = node {
      if el
        .attributes
        .iter()
        .any(|a| matches!(a, Attribute::ForDirective(_)))
      {
        out.push(el.span);
      }
      for child in &el.children {
        collect_vfor(child, out);
      }
    }
  }
  let mut ast_spans: Vec<oxc_span::Span> = Vec::new();
  for node in &root.children {
    collect_vfor(node, &mut ast_spans);
  }
  assert!(!ast_spans.is_empty(), "fixture must contain v-for elements");

  let vfmk: Vec<&vuer::scanner::Violation> = report
    .violations
    .iter()
    .filter(|v| v.rule_id == "vue/best-practice/v-for-missing-key")
    .collect();
  assert_eq!(
    vfmk.len(),
    ast_spans.len(),
    "rule findings must match AST v-for count"
  );
  for v in vfmk {
    let span = oxc_span::Span::new(
      v.span_offset() as u32,
      (v.span_offset() + v.span_len()) as u32,
    );
    assert!(
      ast_spans.iter().any(|s| s.start == span.start),
      "diagnostic span {span:?} must start at a v-for element: {ast_spans:?}"
    );
  }
}
