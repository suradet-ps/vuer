//! Lightweight intra-file taint analysis over the `oxc` script AST and the
//! template AST.
//!
//! The engine computes, for every expression in a `.vue` file, whether its
//! value may carry *untrusted data* (Phase 2 core). Rules stay syntactic
//! sink detectors — "this pattern exists" — and additionally query the
//! engine for the "this pattern carries untrusted data" half:
//!
//! * [`TaintResult::status_at`] — the taint state of an expression span.
//! * [`TaintResult::flow_at`] — the source->sink flow for a reported sink.
//!
//! The analysis runs once per file inside `parse_sfc`, so every rule sees
//! the same facts (and the results are deterministic: the pass walks the
//! AST in source order, never a hash map).
//!
//! ## Model
//!
//! * **Sources** (seeded where external input enters):
//!   - `localStorage.getItem` / `sessionStorage.getItem`
//!   - `fetch`, `axios.*`, `useFetch` responses
//!   - `useRoute()` (route params/query), the `$route` global
//!   - `defineProps` props (setup + options form), the `props` object
//!   - `window.location`, `location.search`/`hash`, `document.cookie`,
//!     `document.referrer`
//!   - `document.getElementById`/`querySelector`/... results (DOM reads)
//!   - `new FormData()`, `new URLSearchParams(...)`
//!   - the `event` / `$event` identifiers
//! * **Propagators**: assignment, string concat, template literals,
//!   ternaries, method calls on tainted receivers, `.map`/`.filter`/
//!   `.then` callbacks, `ref`/`reactive`/`computed`, destructuring,
//!   object-literal members, and bounded inter-procedural flow through
//!   local function calls (a call result is tainted when a tainted
//!   argument reaches a parameter the function's return depends on, or
//!   when the body returns a tainted value).
//! * **Sanitizers** (downgrade): `DOMPurify.sanitize`, `sanitize`,
//!   `escapeHtml`, `htmlEscape`, `escape`, `xss`. A sanitized value is
//!   clean; if it is *re-assigned* from tainted data afterwards, the flow
//!   carries a note naming the earlier sanitizer so the user can verify.
//!
//! ## Scope boundary (documented)
//!
//! * Cross-file flow (imports, composables, mixins) is explicitly
//!   deferred to Phase 6.
//! * A call to an *unknown* function never taints its result (it could be
//!   a sanitizer); this is the price of the false-positive cut and is
//!   re-examined when imports are resolved.
//! * Template expressions are analysed with the identifier facts from the
//!   `<script>` block; expressions that fail to parse yield
//!   [`TaintStatus::Unknown`], which sink rules report conservatively.

use std::collections::{HashMap, HashSet};

use oxc_allocator::Allocator;
use oxc_ast::ast::{
  Argument, AssignmentTarget, BindingPattern, CallExpression, Expression, FormalParameters,
  Function, FunctionBody, ReturnStatement, StaticMemberExpression, TSSignature, VariableDeclarator,
};
use oxc_ast_visit::{Visit, walk};
use oxc_parser::Parser;
use oxc_span::SourceType;
use oxc_span::{GetSpan, Span};

use crate::context::ScanContext;
use crate::parser::script::parse_script;
use crate::parser::template::{Attribute, DirectiveValue, TemplateNode, TemplateRoot};

/// Taint state of an expression's value at a given span.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum TaintStatus {
  /// The value is definitely not carrying untrusted data (a literal, or
  /// derived only from clean values).
  Clean,
  /// The value may carry untrusted data from a recognised source.
  Tainted,
  /// The expression could not be analysed (e.g. unparseable template
  /// binding). Sink rules report these conservatively.
  Unknown,
}

/// One untrusted-data flow, from a source to a sink.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FlowPath {
  /// The sink label the reporting rule attaches (e.g. "`v-html` binding").
  pub sink: String,
  /// Where the taint entered, e.g. `localStorage.getItem (line 12)`.
  pub source: String,
  /// Identifiers / member chains the taint passed through.
  pub via: Vec<String>,
  /// When a value was sanitized and later re-tainted, a note naming the
  /// sanitizer so the user can verify the downgrade.
  pub sanitizer_note: Option<String>,
}

/// The per-expression facts computed for one file.
#[derive(Debug, Clone, Default)]
pub struct TaintResult {
  /// Absolute span start of every analysed expression -> its taint info.
  spans: HashMap<u32, TaintInfo>,
}

impl TaintResult {
  /// Taint state of the expression starting at absolute byte `abs_start`.
  /// Spans that were never analysed (e.g. a script expression the pass
  /// did not visit) are reported as [`TaintStatus::Clean`].
  #[must_use]
  pub fn status_at(&self, abs_start: u32) -> TaintStatus {
    self
      .spans
      .get(&abs_start)
      .map_or(TaintStatus::Clean, |info| info.status)
  }

  /// Build the flow path for a reported sink at `abs_start`, using
  /// `sink` as the sink label.
  #[must_use]
  pub fn flow_at(&self, abs_start: u32, sink: &str) -> Option<FlowPath> {
    let info = self.spans.get(&abs_start)?;
    if info.status != TaintStatus::Tainted {
      return None;
    }
    Some(FlowPath {
      sink: sink.to_string(),
      source: info
        .source
        .clone()
        .unwrap_or_else(|| "unknown source".to_string()),
      via: info.via.clone(),
      sanitizer_note: info.sanitizer_note.clone(),
    })
  }
}

#[derive(Debug, Clone)]
struct TaintInfo {
  status: TaintStatus,
  /// Description of the originating source (only for `Tainted`).
  source: Option<String>,
  /// Identifiers / chains the taint flowed through.
  via: Vec<String>,
  /// Set when the value was sanitized earlier and is tainted again.
  sanitizer_note: Option<String>,
  /// Set on a sanitizer call's result: (sanitizer name, absolute span).
  sanitized_by: Option<(String, u32)>,
}

impl TaintInfo {
  fn clean() -> Self {
    Self {
      status: TaintStatus::Clean,
      source: None,
      via: Vec::new(),
      sanitizer_note: None,
      sanitized_by: None,
    }
  }

  fn tainted(source: String, via: Vec<String>) -> Self {
    Self {
      status: TaintStatus::Tainted,
      source: Some(source),
      via,
      sanitizer_note: None,
      sanitized_by: None,
    }
  }

  fn unknown() -> Self {
    Self {
      status: TaintStatus::Unknown,
      source: None,
      via: Vec::new(),
      sanitizer_note: None,
      sanitized_by: None,
    }
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdState {
  Tainted,
  Clean,
}

/// Inter-procedural summary of one local function.
#[derive(Debug, Default, Clone)]
struct FunctionSummary {
  params: Vec<String>,
  /// `param_deps[i]` — the function's return expressions reference
  /// parameter `i`.
  param_deps: Vec<bool>,
  /// Every `return <expr>` argument (and arrow expression bodies), in
  /// source order, as script-relative spans.
  returns: Vec<Span>,
}

/// Recognised sanitizer call paths (callee segments). A tainted value
/// that passes through one of these is downgraded to clean.
const SANITIZERS: &[&[&str]] = &[
  &["DOMPurify", "sanitize"],
  &["sanitize"],
  &["escapeHtml"],
  &["htmlEscape"],
  &["escape"],
  &["xss"],
];

/// Recognised taint-source call paths.
const SOURCE_CALLS: &[&[&str]] = &[
  &["localStorage", "getItem"],
  &["sessionStorage", "getItem"],
  &["fetch"],
  &["axios", "get"],
  &["axios", "post"],
  &["axios", "put"],
  &["axios", "patch"],
  &["axios", "delete"],
  &["axios", "request"],
  &["useFetch"],
  &["useRoute"],
];

/// Call paths whose result is a *source object*: the value and every
/// member read of it are external input.
const SOURCE_OBJECT_CALLS: &[&[&str]] = &[
  &["defineProps"],
  &["document", "getElementById"],
  &["document", "getElementsByClassName"],
  &["document", "getElementsByTagName"],
  &["document", "querySelector"],
  &["document", "querySelectorAll"],
];

/// Method calls whose result is *not* tainted even when the receiver is
/// (they return a boolean / index / key rather than a value).
const BOOLEAN_METHODS: &[&str] = &[
  "includes",
  "indexOf",
  "lastIndexOf",
  "startsWith",
  "endsWith",
  "some",
  "every",
  "findIndex",
  "findLastIndex",
  "has",
  "isArray",
  "keys",
  "values",
  "entries",
];

pub struct Analyzer<'a> {
  script: Option<&'a str>,
  script_offset: u32,
  template_ast: Option<&'a TemplateRoot>,

  /// Identifier -> state.
  ids: HashMap<String, IdState>,
  /// Identifier -> source description.
  source_of: HashMap<String, String>,
  /// Exact member chains ("a.b") that carry taint -> source description.
  chains: HashMap<String, String>,
  /// Identifiers whose value was sanitized at some point: id ->
  /// (sanitizer name, absolute span) — used for the re-taint note.
  sanitized_ids: HashMap<String, (String, u32)>,

  /// Per-expression facts, keyed by absolute span start.
  spans: HashMap<u32, TaintInfo>,

  /// Local function summaries (inter-procedural).
  functions: HashMap<String, FunctionSummary>,
  /// Guards against recursive local-call classification.
  call_stack: HashSet<String>,
}

impl<'a> Analyzer<'a> {
  fn new(ctx: &'a ScanContext) -> Self {
    Self {
      script: ctx.script.as_deref(),
      script_offset: ctx.script_offset as u32,
      template_ast: ctx.template_ast.as_ref(),
      ids: HashMap::new(),
      source_of: HashMap::new(),
      chains: HashMap::new(),
      sanitized_ids: HashMap::new(),
      spans: HashMap::new(),
      functions: HashMap::new(),
      call_stack: HashSet::new(),
    }
  }
}

/// Run the analysis over one file's `ScanContext` and return the facts.
/// Called at the end of `parse_sfc`, so every rule sees the same result.
pub fn analyze(ctx: &ScanContext) -> TaintResult {
  // The script is parsed once; the summaries and both passes borrow it,
  // so it is created up here and lives for the whole analysis.
  let allocator = Allocator::default();
  let program = ctx
    .script
    .as_deref()
    .map(|script| parse_script(&allocator, script, ctx.lang.clone()));
  let mut analyzer = Analyzer::new(ctx);

  if let (Some(script), Some(program)) = (ctx.script.as_deref(), &program) {
    // Pre-pass: structural function summaries (params + return exprs +
    // which params the returns depend on).
    let mut collector = SummaryCollector {
      script,
      functions: HashMap::new(),
    };
    collector.visit_program(program);
    analyzer.functions = collector.functions;

    // Two passes so facts that appear after a function definition still
    // reach later uses of that function (deterministic: both passes walk
    // the AST in source order).
    analyzer.visit_program(program);
    analyzer.visit_program(program);
  }

  if let Some(root) = analyzer.template_ast {
    analyzer.analyze_template(root);
  }

  TaintResult {
    spans: analyzer.spans,
  }
}

// ---------------------------------------------------------------------
// Main visitor pass
// ---------------------------------------------------------------------

impl<'a> Visit<'a> for Analyzer<'a> {
  fn visit_variable_declarator(&mut self, decl: &VariableDeclarator<'a>) {
    if let Some(init) = &decl.init {
      let info = self.classify_expr(init, self.script_offset);
      // Record the declared identifier's own span so "is this variable
      // tainted" is directly queryable at its declaration site.
      self
        .spans
        .insert(self.script_offset + decl.id.span().start, info.clone());
      self.bind_pattern(&decl.id, init, &info);
    }
    walk::walk_variable_declarator(self, decl);
  }

  fn visit_assignment_expression(&mut self, expr: &oxc_ast::ast::AssignmentExpression<'a>) {
    let info = self.classify_expr(&expr.right, self.script_offset);
    self.bind_assignment_target(&expr.left, &info);
    walk::walk_assignment_expression(self, expr);
  }

  fn visit_expression_statement(&mut self, stmt: &oxc_ast::ast::ExpressionStatement<'a>) {
    self.classify_expr(&stmt.expression, self.script_offset);
    walk::walk_expression_statement(self, stmt);
  }

  fn visit_return_statement(&mut self, stmt: &ReturnStatement<'a>) {
    if let Some(arg) = &stmt.argument {
      self.classify_expr(arg, self.script_offset);
    }
    walk::walk_return_statement(self, stmt);
  }

  fn visit_export_default_declaration(
    &mut self,
    decl: &oxc_ast::ast::ExportDefaultDeclaration<'a>,
  ) {
    if let oxc_ast::ast::ExportDefaultDeclarationKind::ObjectExpression(obj) = &decl.declaration {
      self.analyze_component_options(obj);
    }
    walk::walk_export_default_declaration(self, decl);
  }

  fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
    if let Expression::Identifier(id) = &call.callee
      && id.name == "defineComponent"
      && let Some(Argument::ObjectExpression(obj)) = call.arguments.first()
    {
      self.analyze_component_options(obj);
    }
    walk::walk_call_expression(self, call);
  }
}

// ---------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------

impl<'a> Analyzer<'a> {
  /// Classify an expression, record its span, and recurse into children.
  fn classify_expr<'e>(&mut self, expr: &'e Expression<'e>, abs_base: u32) -> TaintInfo {
    let info = self.classify_expr_inner(expr, abs_base);
    self
      .spans
      .insert(abs_base + expr.span().start, info.clone());
    info
  }

  fn classify_expr_inner<'e>(&mut self, expr: &'e Expression<'e>, abs_base: u32) -> TaintInfo {
    match expr {
      Expression::StringLiteral(_)
      | Expression::NumericLiteral(_)
      | Expression::BooleanLiteral(_)
      | Expression::NullLiteral(_)
      | Expression::BigIntLiteral(_)
      | Expression::RegExpLiteral(_)
      | Expression::Super(_)
      | Expression::MetaProperty(_)
      | Expression::ThisExpression(_)
      | Expression::ClassExpression(_)
      | Expression::JSXElement(_)
      | Expression::JSXFragment(_)
      | Expression::V8IntrinsicExpression(_)
      | Expression::PrivateInExpression(_)
      | Expression::YieldExpression(_) => TaintInfo::clean(),

      Expression::Identifier(id) => self.classify_identifier(&id.name),

      Expression::TemplateLiteral(t) => {
        let mut tainted: Option<TaintInfo> = None;
        for e in &t.expressions {
          let info = self.classify_expr(e, abs_base);
          if tainted.is_none() && info.status == TaintStatus::Tainted {
            tainted = Some(info);
          }
        }
        tainted.unwrap_or_else(TaintInfo::clean)
      }

      Expression::ChainExpression(c) => match &c.expression {
        oxc_ast::ast::ChainElement::CallExpression(inner) => self.classify_call(inner, abs_base),
        oxc_ast::ast::ChainElement::TSNonNullExpression(n) => {
          self.classify_expr(&n.expression, abs_base)
        }
        oxc_ast::ast::ChainElement::ComputedMemberExpression(m) => {
          let index = self.classify_expr(&m.expression, abs_base);
          let object = self.classify_member_object(&m.object, abs_base);
          combine_taint(object, index)
        }
        oxc_ast::ast::ChainElement::StaticMemberExpression(m) => self.classify_member(m, abs_base),
        oxc_ast::ast::ChainElement::PrivateFieldExpression(_) => TaintInfo::clean(),
      },
      Expression::ParenthesizedExpression(p) => self.classify_expr(&p.expression, abs_base),
      Expression::TSAsExpression(e) => self.classify_expr(&e.expression, abs_base),
      Expression::TSSatisfiesExpression(e) => self.classify_expr(&e.expression, abs_base),
      Expression::TSTypeAssertion(e) => self.classify_expr(&e.expression, abs_base),
      Expression::TSNonNullExpression(e) => self.classify_expr(&e.expression, abs_base),
      Expression::TSInstantiationExpression(e) => self.classify_expr(&e.expression, abs_base),
      Expression::AwaitExpression(a) => self.classify_expr(&a.argument, abs_base),

      Expression::UnaryExpression(u) => self.classify_expr(&u.argument, abs_base),

      Expression::BinaryExpression(b) => combine_taint(
        self.classify_expr(&b.left, abs_base),
        self.classify_expr(&b.right, abs_base),
      ),
      Expression::LogicalExpression(l) => combine_taint(
        self.classify_expr(&l.left, abs_base),
        self.classify_expr(&l.right, abs_base),
      ),
      Expression::ConditionalExpression(c) => combine_taint(
        self.classify_expr(&c.consequent, abs_base),
        self.classify_expr(&c.alternate, abs_base),
      ),
      Expression::SequenceExpression(s) => {
        let mut last = TaintInfo::clean();
        for e in &s.expressions {
          last = self.classify_expr(e, abs_base);
        }
        last
      }
      Expression::ArrayExpression(a) => {
        let mut tainted: Option<TaintInfo> = None;
        for e in a.elements.iter().filter_map(|e| e.as_expression()) {
          let info = self.classify_expr(e, abs_base);
          if tainted.is_none() && info.status == TaintStatus::Tainted {
            tainted = Some(info);
          }
        }
        tainted.unwrap_or_else(TaintInfo::clean)
      }
      Expression::ObjectExpression(_) => TaintInfo::clean(),

      Expression::UpdateExpression(_) => TaintInfo::clean(),

      // Nested assignment: the value is the right-hand side.
      Expression::AssignmentExpression(a) => self.classify_expr(&a.right, abs_base),
      Expression::TaggedTemplateExpression(t) => {
        let tag = self.classify_expr(&t.tag, abs_base);
        let mut quasi_tainted: Option<TaintInfo> = None;
        for e in &t.quasi.expressions {
          let info = self.classify_expr(e, abs_base);
          if quasi_tainted.is_none() && info.status == TaintStatus::Tainted {
            quasi_tainted = Some(info);
          }
        }
        quasi_tainted.unwrap_or(tag)
      }
      Expression::PrivateFieldExpression(_) => TaintInfo::clean(),

      Expression::ImportExpression(i) => self.classify_expr(&i.source, abs_base),

      Expression::CallExpression(c) => self.classify_call(c, abs_base),

      Expression::NewExpression(n) => {
        if let Expression::Identifier(id) = &n.callee {
          match id.name.as_str() {
            "FormData" => {
              return TaintInfo::tainted(
                "new FormData()".to_string(),
                vec!["FormData".to_string()],
              );
            }
            "URLSearchParams" => {
              return TaintInfo::tainted(
                "new URLSearchParams()".to_string(),
                vec!["URLSearchParams".to_string()],
              );
            }
            _ => {}
          }
        }
        let mut tainted: Option<TaintInfo> = None;
        for arg in &n.arguments {
          if let Some(e) = arg.as_expression() {
            let info = self.classify_expr(e, abs_base);
            if tainted.is_none() && info.status == TaintStatus::Tainted {
              tainted = Some(info);
            }
          }
        }
        tainted.unwrap_or_else(TaintInfo::clean)
      }

      // A function *value* is never tainted itself; only calls to it
      // propagate. The body is walked by the default traversal.
      Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_) => {
        TaintInfo::clean()
      }

      Expression::StaticMemberExpression(m) => self.classify_member(m, abs_base),
      Expression::ComputedMemberExpression(m) => {
        let index = self.classify_expr(&m.expression, abs_base);
        let object = self.classify_member_object(&m.object, abs_base);
        combine_taint(object, index)
      }
    }
  }

  fn classify_identifier(&self, name: &str) -> TaintInfo {
    match name {
      "$route" => {
        return TaintInfo::tainted(
          "$route (route params/query)".to_string(),
          vec![name.to_string()],
        );
      }
      "event" | "$event" => {
        return TaintInfo::tainted("event payload".to_string(), vec![name.to_string()]);
      }
      _ => {}
    }
    match self.ids.get(name) {
      Some(IdState::Tainted) => {
        let mut info = TaintInfo::tainted(
          self
            .source_of
            .get(name)
            .cloned()
            .unwrap_or_else(|| name.to_string()),
          vec![name.to_string()],
        );
        if let Some((san, span)) = self.sanitized_ids.get(name) {
          info.sanitizer_note = Some(format!(
            "value was sanitized by {san} (line {}) earlier and is tainted again",
            self.line_of(*span)
          ));
        }
        info
      }
      Some(IdState::Clean) | None => TaintInfo::clean(),
    }
  }

  /// Classify a member read `a.b.c`, honouring exact chains, prefixes,
  /// and the special global chains.
  fn classify_member<'e>(&mut self, m: &'e StaticMemberExpression<'e>, abs_base: u32) -> TaintInfo {
    if let Some(chain_info) = self.named_chain(m) {
      return chain_info;
    }
    // Chain could not be named (e.g. `foo().bar`): fall back to the
    // object's own taint.
    self.classify_member_object(&m.object, abs_base)
  }

  fn classify_member_object<'e>(&mut self, object: &'e Expression<'e>, abs_base: u32) -> TaintInfo {
    let info = self.classify_expr(object, abs_base);
    match info.status {
      TaintStatus::Tainted => info,
      _ => TaintInfo::clean(),
    }
  }

  /// Try to build a named chain like `a.b.c` from a member expression
  /// and resolve its taint.
  fn named_chain(&self, m: &StaticMemberExpression<'_>) -> Option<TaintInfo> {
    let mut segments = vec![m.property.name.to_string()];
    let mut object = &m.object;
    loop {
      match object {
        Expression::Identifier(id) => {
          segments.push(id.name.to_string());
          break;
        }
        Expression::StaticMemberExpression(inner) => {
          segments.push(inner.property.name.to_string());
          object = &inner.object;
        }
        _ => return None,
      }
    }
    segments.reverse();
    let chain = segments.join(".");

    if let Some(src) = global_chain_source(&chain) {
      return Some(TaintInfo::tainted(src.to_string(), vec![chain.clone()]));
    }

    // Exact chain, then prefixes.
    let mut partial = String::new();
    for (i, seg) in segments.iter().enumerate() {
      if i > 0 {
        partial.push('.');
      }
      partial.push_str(seg);
      if let Some(src) = self.chains.get(&partial) {
        return Some(TaintInfo::tainted(src.clone(), vec![partial.clone()]));
      }
      if i == 0 {
        // Whole identifier tainted: any member is tainted.
        if self.ids.get(&segments[0]) == Some(&IdState::Tainted) {
          let src = self
            .source_of
            .get(&segments[0])
            .cloned()
            .unwrap_or_else(|| segments[0].clone());
          return Some(TaintInfo::tainted(src, vec![chain]));
        }
      }
    }
    None
  }

  fn classify_call<'e>(&mut self, call: &'e CallExpression<'e>, abs_base: u32) -> TaintInfo {
    let path = crate::parser::script::callee_path(call);

    // Sanitizers downgrade.
    if SANITIZERS.contains(&path.as_slice()) {
      self.record_arguments(call, abs_base);
      let mut info = TaintInfo::clean();
      info.sanitized_by = Some((path.join("."), abs_base + call.span.start));
      return info;
    }

    // Source calls.
    if SOURCE_CALLS.contains(&path.as_slice()) {
      let source = format!(
        "{} (line {})",
        path.join("."),
        self.line_of(call.span.start)
      );
      self.record_arguments(call, abs_base);
      return TaintInfo::tainted(source, vec![path.join(".")]);
    }
    if SOURCE_OBJECT_CALLS.contains(&path.as_slice()) {
      let source = format!(
        "{} (line {})",
        path.join("."),
        self.line_of(call.span.start)
      );
      if path.as_slice() == ["defineProps"] {
        // Also seed the prop names so template bindings that reference a
        // prop bare (`v-html="msg"`) are tainted.
        self.props_from_call(call);
      }
      self.record_arguments(call, abs_base);
      return TaintInfo::tainted(source, vec![path.join(".")]);
    }

    // Local function call (inter-procedural).
    if path.len() == 1
      && self.functions.contains_key(path[0])
      && let Some(info) = self.classify_local_call(path[0], call, abs_base)
    {
      return info;
    }

    // `obj.method(...)` on a tainted receiver (except boolean checks),
    // and `.map`/`.filter`/`.then` callback propagation.
    if let Some(recv_info) = self.tainted_receiver(call, abs_base) {
      let method = path.last().map_or("", |p| *p);
      if !BOOLEAN_METHODS.contains(&method) {
        return recv_info;
      }
    }

    // Vue reactivity constructors: `ref(x)` / `computed(() => x)` /
    // `reactive(x)` wrap a value — the wrapper carries the taint.
    if matches!(
      path.as_slice(),
      ["computed"] | ["ref"] | ["reactive"] | ["shallowRef"]
    ) {
      let mut tainted: Option<TaintInfo> = None;
      for arg in &call.arguments {
        match arg {
          Argument::ArrowFunctionExpression(f) => {
            let info = self.classify_arrow_body(f, abs_base);
            if tainted.is_none() && info.status == TaintStatus::Tainted {
              tainted = Some(info);
            }
          }
          Argument::FunctionExpression(f) => {
            let info = self.classify_function_returns(f);
            if tainted.is_none() && info.status == TaintStatus::Tainted {
              tainted = Some(info);
            }
          }
          _ => {
            if let Some(e) = arg.as_expression() {
              let info = self.classify_expr(e, abs_base);
              if tainted.is_none() && info.status == TaintStatus::Tainted {
                tainted = Some(info);
              }
            }
          }
        }
      }
      if let Some(info) = tainted {
        return info;
      }
    }

    // Known propagators: the result keeps the argument taint.
    if matches!(path.as_slice(), ["String"]) || matches!(path.as_slice(), ["JSON", "stringify"]) {
      let mut tainted: Option<TaintInfo> = None;
      for arg in &call.arguments {
        if let Some(e) = arg.as_expression() {
          let info = self.classify_expr(e, abs_base);
          if tainted.is_none() && info.status == TaintStatus::Tainted {
            tainted = Some(info);
          }
        }
      }
      if let Some(info) = tainted {
        return info;
      }
    }

    // Otherwise: unknown callee — the result is clean (documented
    // boundary). Arguments are still classified for their own spans.
    self.record_arguments(call, abs_base);
    TaintInfo::clean()
  }

  /// `.map` / `.filter` / `.then` style propagation: a tainted receiver
  /// taints the callback's parameters (and thus its return, hence the
  /// call's result).
  fn tainted_receiver<'e>(
    &mut self,
    call: &'e CallExpression<'e>,
    abs_base: u32,
  ) -> Option<TaintInfo> {
    let Expression::StaticMemberExpression(member) = &call.callee else {
      return None;
    };
    let recv = self.classify_expr(&member.object, abs_base);
    if recv.status != TaintStatus::Tainted {
      return None;
    }
    let Some(callback) = call.arguments.last() else {
      return Some(recv);
    };
    let params: Option<&FormalParameters<'_>> = match callback {
      Argument::ArrowFunctionExpression(f) => Some(&f.params),
      Argument::FunctionExpression(f) => Some(&f.params),
      _ => None,
    };
    if let Some(params) = params {
      for p in &params.items {
        for name in pattern_names(&p.pattern) {
          self.set_id(&name, &recv);
        }
      }
    }
    Some(recv)
  }

  /// Inter-procedural call: tainted when a tainted argument reaches a
  /// parameter the function's return depends on, or when the body
  /// returns a tainted value.
  fn classify_local_call<'e>(
    &mut self,
    name: &str,
    call: &'e CallExpression<'e>,
    abs_base: u32,
  ) -> Option<TaintInfo> {
    if self.call_stack.contains(name) {
      return None;
    }
    let summary = self.functions.get(name).cloned()?;
    self.call_stack.insert(name.to_string());

    let mut arg_infos: Vec<TaintInfo> = Vec::new();
    for arg in &call.arguments {
      if let Some(e) = arg.as_expression() {
        arg_infos.push(self.classify_expr(e, abs_base));
      } else {
        arg_infos.push(TaintInfo::clean());
      }
    }

    // 1. Tainted argument reaching a dependent parameter.
    for i in 0..summary.params.len() {
      let depends = summary.param_deps.get(i).copied().unwrap_or(false);
      if !depends {
        continue;
      }
      if let Some(arg) = arg_infos.get(i)
        && arg.status == TaintStatus::Tainted
      {
        self.call_stack.remove(name);
        let mut info = arg.clone();
        info.via.push(name.to_string());
        return Some(info);
      }
    }

    // 2. Body returns a tainted value (closure over tainted state).
    if let Some(script) = self.script {
      for ret in &summary.returns {
        let Some(raw) = script.get(ret.start as usize..ret.end as usize) else {
          continue;
        };
        let allocator = Allocator::default();
        let Ok(expr) = Parser::new(&allocator, raw, SourceType::default()).parse_expression()
        else {
          continue;
        };
        let info = self.classify_expr(&expr, self.script_offset);
        if info.status == TaintStatus::Tainted {
          self.call_stack.remove(name);
          let mut info = info;
          info.via.push(name.to_string());
          return Some(info);
        }
      }
    }

    self.call_stack.remove(name);
    None
  }

  fn record_arguments(&mut self, call: &CallExpression<'_>, abs_base: u32) {
    for arg in &call.arguments {
      if let Some(e) = arg.as_expression() {
        self.classify_expr(e, abs_base);
      }
    }
  }

  // -------------------------------------------------------------------
  // Binding: where taint is written into identifiers / chains.
  // -------------------------------------------------------------------

  fn bind_pattern<'e>(
    &mut self,
    pattern: &'e BindingPattern<'e>,
    init: &'e Expression<'e>,
    info: &TaintInfo,
  ) {
    match pattern {
      BindingPattern::BindingIdentifier(id) => self.set_id(&id.name, info),
      BindingPattern::ObjectPattern(o) => {
        for prop in &o.properties {
          let key = prop.key.static_name().map(|k| k.to_string());
          if let Some(key) = key {
            let member = self.member_taint(init, &key);
            self.bind_pattern(&prop.value, init, &member);
          } else {
            // Computed key — bind the value from the object as a whole.
            self.bind_pattern(&prop.value, init, info);
          }
        }
        if let Some(rest) = &o.rest
          && let BindingPattern::BindingIdentifier(id) = &rest.argument
        {
          self.set_id(&id.name, info);
        }
      }
      BindingPattern::ArrayPattern(a) => {
        for element in a.elements.iter().flatten() {
          self.bind_pattern(element, init, info);
        }
        if let Some(rest) = &a.rest
          && let BindingPattern::BindingIdentifier(id) = &rest.argument
        {
          self.set_id(&id.name, info);
        }
      }
      BindingPattern::AssignmentPattern(p) => {
        self.bind_pattern(&p.left, init, info);
      }
    }
  }

  fn bind_assignment_target<'e>(&mut self, target: &'e AssignmentTarget<'e>, info: &TaintInfo) {
    match target {
      AssignmentTarget::AssignmentTargetIdentifier(id) => self.set_id(&id.name, info),
      AssignmentTarget::StaticMemberExpression(m) => {
        // `base.prop = value` — record the chain (or clear it on a clean
        // overwrite).
        if let Expression::Identifier(base) = &m.object {
          let chain = format!("{}.{}", base.name, m.property.name);
          match info.status {
            TaintStatus::Tainted => {
              self.chains.insert(
                chain,
                info.source.clone().unwrap_or_else(|| "unknown".to_string()),
              );
            }
            TaintStatus::Clean => {
              self.chains.remove(&chain);
            }
            TaintStatus::Unknown => {}
          }
        }
      }
      AssignmentTarget::ComputedMemberExpression(m) => {
        // Computed writes (`obj[key] = ...`) are not tracked: the key
        // space is unbounded. Documented boundary.
        let _ = m;
      }
      AssignmentTarget::ObjectAssignmentTarget(o) => {
        // `({ a, b: c } = obj)` — every bound name takes its value from
        // the (possibly tainted) right-hand side object.
        for prop in &o.properties {
          match prop {
            oxc_ast::ast::AssignmentTargetProperty::AssignmentTargetPropertyIdentifier(p) => {
              self.set_id(&p.binding.name, info);
            }
            oxc_ast::ast::AssignmentTargetProperty::AssignmentTargetPropertyProperty(p) => {
              if let Some(target) = p.binding.as_assignment_target() {
                self.bind_assignment_target(target, info);
              }
            }
          }
        }
      }
      AssignmentTarget::ArrayAssignmentTarget(a) => {
        for element in a.elements.iter().flatten() {
          if let Some(target) = element.as_assignment_target() {
            self.bind_assignment_target(target, info);
          }
        }
      }
      AssignmentTarget::TSAsExpression(t) => self.bind_simple_target(&t.expression, info),
      AssignmentTarget::TSSatisfiesExpression(t) => self.bind_simple_target(&t.expression, info),
      AssignmentTarget::TSNonNullExpression(t) => self.bind_simple_target(&t.expression, info),
      AssignmentTarget::TSTypeAssertion(t) => self.bind_simple_target(&t.expression, info),
      AssignmentTarget::PrivateFieldExpression(_) => {}
    }
  }

  /// Bind an identifier or member-write target that reached us wrapped
  /// (e.g. inside `TSAsExpression`).
  fn bind_simple_target(&mut self, expr: &Expression<'_>, info: &TaintInfo) {
    match expr {
      Expression::Identifier(id) => self.set_id(&id.name, info),
      Expression::StaticMemberExpression(m) => {
        if let Expression::Identifier(base) = &m.object {
          let chain = format!("{}.{}", base.name, m.property.name);
          match info.status {
            TaintStatus::Tainted => {
              self.chains.insert(
                chain,
                info.source.clone().unwrap_or_else(|| "unknown".to_string()),
              );
            }
            TaintStatus::Clean => {
              self.chains.remove(&chain);
            }
            TaintStatus::Unknown => {}
          }
        }
      }
      _ => {}
    }
  }

  /// `obj.key` read where `obj` is an expression (used for
  /// destructuring).
  fn member_taint<'e>(&self, object: &'e Expression<'e>, key: &str) -> TaintInfo {
    if let Expression::Identifier(id) = object {
      self.member_taint_from_id_named(&id.name, key)
    } else {
      TaintInfo::clean()
    }
  }

  fn member_taint_from_id_named(&self, base: &str, key: &str) -> TaintInfo {
    let chain = format!("{base}.{key}");
    if let Some(src) = self.chains.get(&chain) {
      return TaintInfo::tainted(src.clone(), vec![chain]);
    }
    if self.ids.get(base) == Some(&IdState::Tainted) {
      return TaintInfo::tainted(
        self
          .source_of
          .get(base)
          .cloned()
          .unwrap_or_else(|| base.to_string()),
        vec![chain],
      );
    }
    TaintInfo::clean()
  }

  /// Bind a taint state to an identifier.
  fn set_id(&mut self, name: &str, info: &TaintInfo) {
    match info.status {
      TaintStatus::Tainted => {
        let source = info.source.clone().unwrap_or_else(|| name.to_string());
        self.ids.insert(name.to_string(), IdState::Tainted);
        self.source_of.insert(name.to_string(), source);
      }
      TaintStatus::Clean => {
        self.ids.insert(name.to_string(), IdState::Clean);
        // A sanitized value is clean; remember the sanitizer for the
        // re-taint note.
        if let Some((san, span)) = &info.sanitized_by {
          self
            .sanitized_ids
            .insert(name.to_string(), (san.clone(), *span));
        }
      }
      TaintStatus::Unknown => {
        // Leave the previous state untouched (documented boundary).
      }
    }
  }

  // -------------------------------------------------------------------
  // Sources + helpers
  // -------------------------------------------------------------------

  /// Extract prop names from `defineProps(...)` (object, array, or TS
  /// generic form) so template bindings that reference a prop bare
  /// (`v-html="msg"`) are tainted. Best effort.
  fn props_from_call(&mut self, call: &CallExpression<'_>) {
    for arg in &call.arguments {
      match arg {
        Argument::ObjectExpression(obj) => {
          for pk in &obj.properties {
            let Some(prop) = pk.as_property() else {
              continue;
            };
            if let Some(key) = prop.key.static_name() {
              self.seed_prop(&key);
            }
          }
        }
        Argument::ArrayExpression(arr) => {
          for e in arr.elements.iter().filter_map(|e| e.as_expression()) {
            if let Expression::StringLiteral(s) = e {
              self.seed_prop(&s.value);
            }
          }
        }
        _ => {}
      }
    }
    // TS generic form: `defineProps<{ msg: string }>()`.
    if let Some(tp) = &call.type_arguments {
      for param in &tp.params {
        if let oxc_ast::ast::TSType::TSTypeLiteral(lit) = param {
          for member in &lit.members {
            if let TSSignature::TSPropertySignature(sig) = member
              && let Some(key) = sig.key.static_name()
            {
              self.seed_prop(&key);
            }
          }
        }
      }
    }
  }

  fn seed_prop(&mut self, name: &str) {
    self.ids.insert(name.to_string(), IdState::Tainted);
    self
      .source_of
      .insert(name.to_string(), format!("props ({name})"));
  }

  /// Component options: `export default { props, data, computed,
  /// methods }` (Options API). Template bindings reference these bare.
  fn analyze_component_options(&mut self, obj: &oxc_ast::ast::ObjectExpression<'_>) {
    for kind in &obj.properties {
      let Some(prop) = kind.as_property() else {
        continue;
      };
      let key = match prop.key.static_name() {
        Some(k) => k.to_string(),
        None => continue,
      };
      let value = &prop.value;

      if key == "data" {
        // `data() { return { msg: tainted } }` — seed returned props
        // that hold tainted values.
        if let Expression::FunctionExpression(f) = value
          && let Some(body) = &f.body
        {
          for stmt in &body.statements {
            if let oxc_ast::ast::Statement::ReturnStatement(ret) = stmt
              && let Some(arg) = &ret.argument
              && let Expression::ObjectExpression(ret_obj) = arg
            {
              for pk in &ret_obj.properties {
                let Some(p) = pk.as_property() else {
                  continue;
                };
                if let Some(pk) = p.key.static_name() {
                  let info = self.classify_expr(&p.value, self.script_offset);
                  if info.status == TaintStatus::Tainted {
                    self.set_id(&pk, &info);
                  }
                }
              }
            }
          }
        }
        continue;
      }

      match key.as_str() {
        "props" => {
          if let Expression::ObjectExpression(p) = value {
            for pk in &p.properties {
              let Some(pp) = pk.as_property() else {
                continue;
              };
              if let Some(pk) = pp.key.static_name() {
                self.seed_prop(&pk);
              }
            }
          } else if let Expression::ArrayExpression(arr) = value {
            for e in arr.elements.iter().filter_map(|e| e.as_expression()) {
              if let Expression::StringLiteral(s) = e {
                self.seed_prop(&s.value);
              }
            }
          }
        }
        "computed" => {
          if let Expression::ObjectExpression(c) = value {
            for ck in &c.properties {
              let Some(cp) = ck.as_property() else {
                continue;
              };
              if let Some(ck) = cp.key.static_name() {
                // `computed: { foo() { return tainted } }`
                if let Expression::FunctionExpression(f) = &cp.value {
                  let info = self.classify_function_returns(f);
                  if info.status == TaintStatus::Tainted {
                    self.set_id(&ck, &info);
                  }
                }
              }
            }
          }
        }
        "methods" => {
          if let Expression::ObjectExpression(m) = value {
            for mk in &m.properties {
              let Some(mp) = mk.as_property() else {
                continue;
              };
              if let Some(mk) = mp.key.static_name()
                && let Expression::FunctionExpression(f) = &mp.value
              {
                self.register_function(&mk, &f.params, f.body.as_deref());
              }
            }
          }
        }
        _ => {}
      }
    }
  }

  /// Classify a function's return expressions with the current facts.
  /// Classify an arrow function's implicit/explicit return with the
  /// current facts.
  fn classify_arrow_body(
    &mut self,
    f: &oxc_ast::ast::ArrowFunctionExpression<'_>,
    abs_base: u32,
  ) -> TaintInfo {
    if f.expression {
      if let Some(oxc_ast::ast::Statement::ExpressionStatement(s)) = f.body.statements.first() {
        return self.classify_expr(&s.expression, abs_base);
      }
      return TaintInfo::clean();
    }
    let mut tainted: Option<TaintInfo> = None;
    for stmt in &f.body.statements {
      if let oxc_ast::ast::Statement::ReturnStatement(ret) = stmt
        && let Some(arg) = &ret.argument
      {
        let info = self.classify_expr(arg, abs_base);
        if tainted.is_none() && info.status == TaintStatus::Tainted {
          tainted = Some(info);
        }
      }
    }
    tainted.unwrap_or_else(TaintInfo::clean)
  }

  fn classify_function_returns(&mut self, f: &Function<'_>) -> TaintInfo {
    let mut tainted: Option<TaintInfo> = None;
    if let Some(body) = &f.body {
      for stmt in &body.statements {
        if let oxc_ast::ast::Statement::ReturnStatement(ret) = stmt
          && let Some(arg) = &ret.argument
        {
          let info = self.classify_expr(arg, self.script_offset);
          if tainted.is_none() && info.status == TaintStatus::Tainted {
            tainted = Some(info);
          }
        }
      }
    }
    tainted.unwrap_or_else(TaintInfo::clean)
  }

  fn register_function(
    &mut self,
    name: &str,
    params: &FormalParameters<'_>,
    body: Option<&FunctionBody<'_>>,
  ) {
    let params: Vec<String> = params
      .items
      .iter()
      .flat_map(|p| pattern_names(&p.pattern))
      .collect();
    let mut returns: Vec<Span> = Vec::new();
    if let Some(body) = body {
      collect_returns(body, &mut returns);
    }
    let mut param_deps = vec![false; params.len()];
    if let Some(script) = self.script {
      for (i, param) in params.iter().enumerate() {
        param_deps[i] = returns
          .iter()
          .any(|span| span_references_param(script, *span, param));
      }
    }
    self.functions.insert(
      name.to_string(),
      FunctionSummary {
        params,
        param_deps,
        returns,
      },
    );
  }

  fn line_of(&self, abs_span: u32) -> usize {
    let offset = abs_span.saturating_sub(self.script_offset) as usize;
    match self.script {
      Some(script) => {
        1 + script[..script.len().min(offset)]
          .bytes()
          .filter(|b| *b == b'\n')
          .count()
      }
      None => 0,
    }
  }

  // -------------------------------------------------------------------
  // Template pass
  // -------------------------------------------------------------------

  fn analyze_template(&mut self, root: &TemplateRoot) {
    let mut stack: Vec<&TemplateNode> = root.children.iter().collect();
    while let Some(node) = stack.pop() {
      if let TemplateNode::Element(el) = node {
        for attr in &el.attributes {
          if let Attribute::Directive(d) | Attribute::OnDirective(d) = attr
            && let Some(DirectiveValue::Expression(e)) = &d.value
          {
            self.analyze_template_expr(&e.raw, e.span.start);
          }
        }
        stack.extend(el.children.iter());
      }
    }
  }

  fn analyze_template_expr(&mut self, raw: &str, abs_base: u32) {
    let allocator = Allocator::default();
    let Ok(expr) = Parser::new(&allocator, raw, SourceType::default()).parse_expression() else {
      // Unparseable binding: record Unknown so sink rules report
      // conservatively.
      self.spans.insert(abs_base, TaintInfo::unknown());
      return;
    };
    self.classify_expr(&expr, abs_base);
  }
}

// ---------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------

fn combine_taint(a: TaintInfo, b: TaintInfo) -> TaintInfo {
  if a.status == TaintStatus::Tainted {
    a
  } else if b.status == TaintStatus::Tainted {
    b
  } else {
    TaintInfo::clean()
  }
}

/// Special member chains that are sources by themselves.
fn global_chain_source(chain: &str) -> Option<&'static str> {
  if chain == "window.location" || chain.starts_with("window.location.") {
    Some("window.location")
  } else if chain == "location.search" || chain == "location.hash" {
    Some("location.search/hash")
  } else if chain == "document.cookie" {
    Some("document.cookie")
  } else if chain == "document.referrer" {
    Some("document.referrer")
  } else {
    None
  }
}

fn pattern_names(pattern: &BindingPattern<'_>) -> Vec<String> {
  let mut names = Vec::new();
  collect_pattern_names(pattern, &mut names);
  names
}

fn collect_pattern_names(pattern: &BindingPattern<'_>, out: &mut Vec<String>) {
  match pattern {
    BindingPattern::BindingIdentifier(id) => out.push(id.name.to_string()),
    BindingPattern::ObjectPattern(o) => {
      for prop in &o.properties {
        collect_pattern_names(&prop.value, out);
      }
    }
    BindingPattern::ArrayPattern(a) => {
      for e in a.elements.iter().flatten() {
        collect_pattern_names(e, out);
      }
    }
    BindingPattern::AssignmentPattern(p) => collect_pattern_names(&p.left, out),
  }
}

/// Collect the script-relative span of every `return <expr>` argument
/// in a function body.
fn collect_returns(body: &FunctionBody<'_>, out: &mut Vec<Span>) {
  for stmt in &body.statements {
    collect_returns_in_stmt(stmt, out);
  }
}

fn collect_returns_in_stmt(stmt: &oxc_ast::ast::Statement<'_>, out: &mut Vec<Span>) {
  match stmt {
    oxc_ast::ast::Statement::ReturnStatement(ret) => {
      if let Some(arg) = &ret.argument {
        out.push(arg.span());
      }
    }
    oxc_ast::ast::Statement::IfStatement(s) => {
      collect_returns_in_stmt(&s.consequent, out);
      if let Some(alt) = &s.alternate {
        collect_returns_in_stmt(alt, out);
      }
    }
    oxc_ast::ast::Statement::BlockStatement(b) => {
      for s in &b.body {
        collect_returns_in_stmt(s, out);
      }
    }
    _ => {}
  }
}

/// True when an expression (or any of its sub-expressions) references
/// the identifier `name`.
fn expression_references(expr: &Expression<'_>, name: &str) -> bool {
  match expr {
    Expression::Identifier(id) => id.name == name,
    Expression::StaticMemberExpression(m) => expression_references(&m.object, name),
    Expression::ComputedMemberExpression(m) => {
      expression_references(&m.object, name) || expression_references(&m.expression, name)
    }
    Expression::CallExpression(c) => {
      expression_references(&c.callee, name)
        || c.arguments.iter().any(|a| {
          a.as_expression()
            .is_some_and(|e| expression_references(e, name))
        })
    }
    Expression::BinaryExpression(b) => {
      expression_references(&b.left, name) || expression_references(&b.right, name)
    }
    Expression::LogicalExpression(l) => {
      expression_references(&l.left, name) || expression_references(&l.right, name)
    }
    Expression::ConditionalExpression(c) => {
      expression_references(&c.test, name)
        || expression_references(&c.consequent, name)
        || expression_references(&c.alternate, name)
    }
    Expression::TemplateLiteral(t) => t.expressions.iter().any(|e| expression_references(e, name)),
    Expression::ArrayExpression(a) => a
      .elements
      .iter()
      .filter_map(|e| e.as_expression())
      .any(|e| expression_references(e, name)),
    Expression::ObjectExpression(o) => o
      .properties
      .iter()
      .filter_map(|p| p.as_property())
      .any(|p| expression_references(&p.value, name)),
    Expression::ChainExpression(c) => match &c.expression {
      oxc_ast::ast::ChainElement::CallExpression(inner) => {
        expression_references(&inner.callee, name)
          || inner.arguments.iter().any(|a| {
            a.as_expression()
              .is_some_and(|e| expression_references(e, name))
          })
      }
      oxc_ast::ast::ChainElement::TSNonNullExpression(n) => {
        expression_references(&n.expression, name)
      }
      oxc_ast::ast::ChainElement::ComputedMemberExpression(m) => {
        expression_references(&m.object, name) || expression_references(&m.expression, name)
      }
      oxc_ast::ast::ChainElement::StaticMemberExpression(m) => {
        expression_references(&m.object, name)
      }
      oxc_ast::ast::ChainElement::PrivateFieldExpression(_) => false,
    },
    Expression::ParenthesizedExpression(p) => expression_references(&p.expression, name),
    Expression::UnaryExpression(u) => expression_references(&u.argument, name),
    Expression::AwaitExpression(a) => expression_references(&a.argument, name),
    Expression::TSAsExpression(e) => expression_references(&e.expression, name),
    Expression::TSSatisfiesExpression(e) => expression_references(&e.expression, name),
    Expression::TSNonNullExpression(e) => expression_references(&e.expression, name),
    Expression::TSTypeAssertion(e) => expression_references(&e.expression, name),
    Expression::TSInstantiationExpression(e) => expression_references(&e.expression, name),
    Expression::NewExpression(n) => n.arguments.iter().any(|a| {
      a.as_expression()
        .is_some_and(|e| expression_references(e, name))
    }),
    Expression::SequenceExpression(s) => {
      s.expressions.iter().any(|e| expression_references(e, name))
    }
    Expression::ArrowFunctionExpression(f) => f.body.statements.iter().any(|s| {
      if f.expression {
        matches!(
          s,
          oxc_ast::ast::Statement::ExpressionStatement(e)
            if expression_references(&e.expression, name)
        )
      } else {
        false
      }
    }),
    _ => false,
  }
}

// ---------------------------------------------------------------------
// Pre-pass: function summaries
// ---------------------------------------------------------------------

struct SummaryCollector<'a> {
  script: &'a str,
  functions: HashMap<String, FunctionSummary>,
}

impl<'a> Visit<'a> for SummaryCollector<'a> {
  fn visit_declaration(&mut self, decl: &oxc_ast::ast::Declaration<'a>) {
    if let oxc_ast::ast::Declaration::FunctionDeclaration(func) = decl
      && let Some(name) = &func.id
    {
      self.enter(name.name.as_str(), func);
    }
    walk::walk_declaration(self, decl);
  }

  fn visit_variable_declarator(&mut self, decl: &VariableDeclarator<'a>) {
    if let Some(init) = &decl.init
      && let Expression::ArrowFunctionExpression(f) = init
      && let BindingPattern::BindingIdentifier(id) = &decl.id
    {
      let params: Vec<String> = f
        .params
        .items
        .iter()
        .flat_map(|p| pattern_names(&p.pattern))
        .collect();
      let mut returns: Vec<Span> = Vec::new();
      if f.expression {
        if let Some(oxc_ast::ast::Statement::ExpressionStatement(s)) = f.body.statements.first() {
          returns.push(s.expression.span());
        }
      } else {
        collect_returns(&f.body, &mut returns);
      }
      let mut param_deps = vec![false; params.len()];
      for (i, param) in params.iter().enumerate() {
        param_deps[i] = returns
          .iter()
          .any(|span| span_references_param(self.script, *span, param));
      }
      self.functions.insert(
        id.name.to_string(),
        FunctionSummary {
          params,
          param_deps,
          returns,
        },
      );
    }
    walk::walk_variable_declarator(self, decl);
  }
}

impl<'a> SummaryCollector<'a> {
  fn enter(&mut self, name: &str, func: &Function<'a>) {
    let params: Vec<String> = func
      .params
      .items
      .iter()
      .flat_map(|p| pattern_names(&p.pattern))
      .collect();
    let mut returns: Vec<Span> = Vec::new();
    if let Some(body) = &func.body {
      collect_returns(body, &mut returns);
    }
    let mut param_deps = vec![false; params.len()];
    for (i, param) in params.iter().enumerate() {
      param_deps[i] = returns
        .iter()
        .any(|span| span_references_param(self.script, *span, param));
    }
    self.functions.insert(
      name.to_string(),
      FunctionSummary {
        params,
        param_deps,
        returns,
      },
    );
  }
}

/// True when the return expression at `span` (script-relative) references
/// `param`. The small expression is re-parsed from the script.
fn span_references_param(script: &str, span: Span, param: &str) -> bool {
  let Some(raw) = script.get(span.start as usize..span.end as usize) else {
    return false;
  };
  let allocator = Allocator::default();
  Parser::new(&allocator, raw, SourceType::default())
    .parse_expression()
    .is_ok_and(|expr| expression_references(&expr, param))
}

#[cfg(test)]
mod tests {
  use std::path::PathBuf;

  use super::*;
  use crate::parser::parse_sfc;

  fn analyze_script(script: &str) -> ScanContext {
    let source = format!("<template><div></div></template>\n<script setup>\n{script}\n</script>");
    let mut ctx = ScanContext::new(PathBuf::from("test.vue"), source);
    parse_sfc(&mut ctx);
    ctx
  }

  fn analyze_template(template: &str) -> ScanContext {
    let source = format!("<template>{template}</template>");
    let mut ctx = ScanContext::new(PathBuf::from("test.vue"), source);
    parse_sfc(&mut ctx);
    ctx
  }

  /// Status of the expression whose source text contains `needle`
  /// (script-relative lookup).
  fn status_of(ctx: &ScanContext, needle: &str) -> TaintStatus {
    let script = ctx.script.as_deref().expect("script block");
    let rel = script.find(needle).expect("needle in script");
    ctx.taint.status_at(ctx.script_offset as u32 + rel as u32)
  }

  fn flow_of(ctx: &ScanContext, needle: &str, sink: &str) -> Option<FlowPath> {
    let script = ctx.script.as_deref().expect("script block");
    let rel = script.find(needle).expect("needle in script");
    ctx
      .taint
      .flow_at(ctx.script_offset as u32 + rel as u32, sink)
  }

  // ------------------------------------------------------------------
  // Sources
  // ------------------------------------------------------------------

  #[test]
  fn localStorage_is_a_source() {
    let ctx = analyze_script("const x = localStorage.getItem('k')\nconst y = x");
    assert_eq!(
      status_of(&ctx, "localStorage.getItem('k')"),
      TaintStatus::Tainted
    );
    // The later read of `x` carries the taint.
    assert_eq!(status_of(&ctx, "x"), TaintStatus::Tainted);
    let flow = flow_of(&ctx, "localStorage.getItem('k')", "sink").expect("flow");
    assert!(flow.source.contains("localStorage.getItem"));
  }

  #[test]
  fn fetch_response_is_tainted() {
    let ctx =
      analyze_script("const data = await fetch('/api').then(r => r.json())\nconst out = data");
    assert_eq!(status_of(&ctx, "fetch('/api')"), TaintStatus::Tainted);
    assert_eq!(
      status_of(&ctx, "fetch('/api').then(r => r.json())"),
      TaintStatus::Tainted
    );
    assert_eq!(status_of(&ctx, "data"), TaintStatus::Tainted);
  }

  #[test]
  fn route_params_are_tainted() {
    let ctx = analyze_script("const route = useRoute()\nconst id = route.query.id\nconst out = id");
    assert_eq!(status_of(&ctx, "route.query.id"), TaintStatus::Tainted);
    assert_eq!(status_of(&ctx, "id"), TaintStatus::Tainted);
  }

  #[test]
  fn use_route_is_a_source() {
    let ctx = analyze_script(
      "import { useRoute } from 'vue-router'\nconst route = useRoute()\nconst q = route.query.q\nconst result = q",
    );
    assert_eq!(status_of(&ctx, "route.query.q"), TaintStatus::Tainted);
    assert_eq!(status_of(&ctx, "result"), TaintStatus::Tainted);
  }

  #[test]
  fn props_are_tainted() {
    let ctx = analyze_script("const props = defineProps({ msg: String })\nconst m = props.msg");
    assert_eq!(status_of(&ctx, "props.msg"), TaintStatus::Tainted);
    // The bare prop name is seeded too (template binds it directly):
    // `v-html="msg"` is tainted via the template pass.
    let source = format!(
      "<template><div v-html=\"msg\"></div></template>\n<script setup>\nconst props = defineProps({{ msg: String }})\n</script>"
    );
    let mut ctx = ScanContext::new(PathBuf::from("test.vue"), source);
    parse_sfc(&mut ctx);
    let root = ctx.template_ast.as_ref().expect("template");
    let TemplateNode::Element(el) = &root.children[0] else {
      panic!()
    };
    let Attribute::Directive(d) = &el.attributes[0] else {
      panic!()
    };
    let DirectiveValue::Expression(e) = d.value.as_ref().expect("value") else {
      panic!()
    };
    assert_eq!(ctx.taint.status_at(e.span.start), TaintStatus::Tainted);
  }

  #[test]
  fn event_and_window_location_are_sources() {
    let ctx = analyze_script("const a = event.target.value\nconst b = window.location.href");
    assert_eq!(status_of(&ctx, "event.target.value"), TaintStatus::Tainted);
    assert_eq!(
      status_of(&ctx, "window.location.href"),
      TaintStatus::Tainted
    );
  }

  #[test]
  fn document_reads_are_sources() {
    let ctx = analyze_script("const el = document.getElementById('x')\nconst v = el.value");
    assert_eq!(status_of(&ctx, "el.value"), TaintStatus::Tainted);
    let ctx = analyze_script("const c = document.cookie");
    assert_eq!(status_of(&ctx, "document.cookie"), TaintStatus::Tainted);
  }

  #[test]
  fn form_data_and_url_search_params_are_sources() {
    let ctx = analyze_script("const f = new FormData()\nconst p = f.get('name')");
    assert_eq!(status_of(&ctx, "f.get('name')"), TaintStatus::Tainted);
  }

  // ------------------------------------------------------------------
  // Propagation
  // ------------------------------------------------------------------

  #[test]
  fn concat_and_template_literals_propagate() {
    let ctx = analyze_script(
      "const a = localStorage.getItem('a')\nconst b = 'prefix' + a\nconst c = `x${a}y`",
    );
    assert_eq!(status_of(&ctx, "'prefix' + a"), TaintStatus::Tainted);
    assert_eq!(status_of(&ctx, "`x${a}y`"), TaintStatus::Tainted);
  }

  #[test]
  fn clean_values_stay_clean() {
    let ctx = analyze_script("const a = 'static'\nconst b = 42\nconst c = a + b");
    assert_eq!(status_of(&ctx, "a"), TaintStatus::Clean);
    assert_eq!(status_of(&ctx, "c"), TaintStatus::Clean);
  }

  #[test]
  fn member_writes_and_reads() {
    let ctx = analyze_script(
      "const user = {}\nuser.bio = localStorage.getItem('bio')\nconst out = user.bio",
    );
    assert_eq!(status_of(&ctx, "user.bio"), TaintStatus::Tainted);
  }

  #[test]
  fn clean_overwrite_clears_member_chain() {
    let ctx = analyze_script(
      "const user = {}\nuser.bio = localStorage.getItem('b')\nuser.bio = 'safe'\nconst out = user.bio",
    );
    // The overwrite cleared the chain: the read of `out` is clean.
    assert_eq!(status_of(&ctx, "out"), TaintStatus::Clean);
  }

  #[test]
  fn destructuring_propagates() {
    let ctx = analyze_script(
      "const route = useRoute()\nconst { query } = route\nconst { q } = query\nconst result = q",
    );
    assert_eq!(status_of(&ctx, "result"), TaintStatus::Tainted);
  }

  #[test]
  fn ternary_and_logical_propagate() {
    let ctx = analyze_script(
      "const x = localStorage.getItem('x')\nconst y = cond ? x : 'fallback'\nconst z = x || 'd'",
    );
    assert_eq!(
      status_of(&ctx, "cond ? x : 'fallback'"),
      TaintStatus::Tainted
    );
    assert_eq!(status_of(&ctx, "x || 'd'"), TaintStatus::Tainted);
  }

  #[test]
  fn map_filter_propagate_through_callbacks() {
    let ctx = analyze_script(
      "const arr = localStorage.getItem('a').split(',')\nconst out = arr.map(s => s.trim())\nconst used = out",
    );
    assert_eq!(
      status_of(&ctx, "arr.map(s => s.trim())"),
      TaintStatus::Tainted
    );
    assert_eq!(status_of(&ctx, "used"), TaintStatus::Tainted);
  }

  #[test]
  fn computed_and_ref_propagate() {
    let ctx = analyze_script(
      "const raw = ref(localStorage.getItem('r'))\nconst doubled = computed(() => raw.value)\nconst out = doubled",
    );
    assert_eq!(
      status_of(&ctx, "ref(localStorage.getItem('r'))"),
      TaintStatus::Tainted
    );
    assert_eq!(
      status_of(&ctx, "computed(() => raw.value)"),
      TaintStatus::Tainted
    );
    assert_eq!(status_of(&ctx, "doubled"), TaintStatus::Tainted);
  }

  #[test]
  fn boolean_methods_do_not_propagate() {
    let ctx = analyze_script("const x = localStorage.getItem('x')\nconst ok = x.includes('safe')");
    assert_eq!(status_of(&ctx, "x.includes('safe')"), TaintStatus::Clean);
  }

  // ------------------------------------------------------------------
  // Sanitizers
  // ------------------------------------------------------------------

  #[test]
  fn sanitizer_downgrades_taint() {
    let ctx = analyze_script(
      "const raw = localStorage.getItem('raw')\nconst safe = DOMPurify.sanitize(raw)",
    );
    assert_eq!(status_of(&ctx, "safe"), TaintStatus::Clean);
  }

  // ------------------------------------------------------------------
  // Inter-procedural
  // ------------------------------------------------------------------

  #[test]
  fn local_function_call_propagates_tainted_argument() {
    let ctx = analyze_script(
      "function decorate(s) { return s + '!' }\nconst raw = localStorage.getItem('r')\nconst out = decorate(raw)",
    );
    assert_eq!(status_of(&ctx, "decorate(raw)"), TaintStatus::Tainted);
  }

  #[test]
  fn local_function_with_clean_argument_stays_clean() {
    let ctx =
      analyze_script("function decorate(s) { return s + '!' }\nconst out = decorate('static')");
    assert_eq!(status_of(&ctx, "decorate('static')"), TaintStatus::Clean);
  }

  #[test]
  fn function_returning_tainted_closure_value() {
    let ctx = analyze_script(
      "const raw = localStorage.getItem('r')\nfunction leak() { return raw }\nconst out = leak()",
    );
    assert_eq!(status_of(&ctx, "out"), TaintStatus::Tainted);
  }

  #[test]
  fn unknown_call_does_not_taint() {
    // A call to an unknown function could be a sanitizer wrapper —
    // documented boundary: result stays clean.
    let ctx = analyze_script(
      "const raw = localStorage.getItem('r')\nconst out = mystery(raw)\nconst used = out",
    );
    assert_eq!(status_of(&ctx, "mystery(raw)"), TaintStatus::Clean);
    assert_eq!(
      status_of(&ctx, "localStorage.getItem('r')"),
      TaintStatus::Tainted
    );
    assert_eq!(status_of(&ctx, "used"), TaintStatus::Clean);
  }

  // ------------------------------------------------------------------
  // Template bindings
  // ------------------------------------------------------------------

  #[test]
  fn template_binding_referencing_tainted_id_is_tainted() {
    let ctx = analyze_script("const userInput = localStorage.getItem('u')");
    // The analysis ran on the whole SFC; re-check the template binding.
    let source = format!(
      "<template><div v-html=\"userInput\"></div></template>\n<script setup>\nconst userInput = localStorage.getItem('u')\n</script>"
    );
    let mut ctx = ScanContext::new(PathBuf::from("test.vue"), source);
    parse_sfc(&mut ctx);
    let root = ctx.template_ast.as_ref().expect("template");
    let TemplateNode::Element(el) = &root.children[0] else {
      panic!()
    };
    let Attribute::Directive(d) = &el.attributes[0] else {
      panic!()
    };
    let DirectiveValue::Expression(e) = d.value.as_ref().expect("value") else {
      panic!()
    };
    assert_eq!(ctx.taint.status_at(e.span.start), TaintStatus::Tainted);
    let flow = ctx
      .taint
      .flow_at(e.span.start, "v-html binding")
      .expect("flow");
    assert!(flow.source.contains("localStorage.getItem"));
    assert_eq!(flow.via, vec!["userInput".to_string()]);
  }

  #[test]
  fn template_binding_with_clean_value_is_clean() {
    let source = "<template><div v-html=\"'static'\"></div></template>";
    let mut ctx = ScanContext::new(PathBuf::from("test.vue"), source.to_string());
    parse_sfc(&mut ctx);
    let root = ctx.template_ast.as_ref().expect("template");
    let TemplateNode::Element(el) = &root.children[0] else {
      panic!()
    };
    let Attribute::Directive(d) = &el.attributes[0] else {
      panic!()
    };
    let DirectiveValue::Expression(e) = d.value.as_ref().expect("value") else {
      panic!()
    };
    assert_eq!(ctx.taint.status_at(e.span.start), TaintStatus::Clean);
  }

  #[test]
  fn unparseable_binding_is_unknown() {
    let source = "<template><div v-html=\"{{{\"></div></template>";
    let mut ctx = ScanContext::new(PathBuf::from("test.vue"), source.to_string());
    parse_sfc(&mut ctx);
    let root = ctx.template_ast.as_ref().expect("template");
    let TemplateNode::Element(el) = &root.children[0] else {
      panic!()
    };
    let Attribute::Directive(d) = &el.attributes[0] else {
      panic!()
    };
    let DirectiveValue::Expression(e) = d.value.as_ref().expect("value") else {
      panic!()
    };
    assert_eq!(ctx.taint.status_at(e.span.start), TaintStatus::Unknown);
  }

  #[test]
  fn options_api_props_and_data_are_sources() {
    let source = "<template><div v-html=\"msg\"></div></template>\n\
                  <script>\nexport default {\n  props: { msg: String },\n  data() { return { note: localStorage.getItem('n') } }\n}\n</script>";
    let mut ctx = ScanContext::new(PathBuf::from("test.vue"), source.to_string());
    parse_sfc(&mut ctx);
    // The template `v-html="msg"` binding is tainted via the seeded prop.
    let root = ctx.template_ast.as_ref().expect("template");
    let TemplateNode::Element(el) = &root.children[0] else {
      panic!()
    };
    let Attribute::Directive(d) = &el.attributes[0] else {
      panic!()
    };
    let DirectiveValue::Expression(e) = d.value.as_ref().expect("value") else {
      panic!()
    };
    assert_eq!(ctx.taint.status_at(e.span.start), TaintStatus::Tainted);
    // The data() return value is tainted at its source call.
    let script = ctx.script.as_deref().expect("script");
    let rel = script.find("localStorage.getItem('n')").expect("note");
    assert_eq!(
      ctx.taint.status_at(ctx.script_offset as u32 + rel as u32),
      TaintStatus::Tainted
    );
  }

  #[test]
  fn determinism_of_repeated_analysis() {
    // Same input, N analyses: identical span facts.
    let source = "<template><div v-html=\"userInput\"></div></template>\n\
                  <script setup>\nconst userInput = localStorage.getItem('u')\nconst out = userInput.trim()\n</script>";
    let first = {
      let mut ctx = ScanContext::new(PathBuf::from("test.vue"), source.to_string());
      parse_sfc(&mut ctx);
      let root = ctx.template_ast.as_ref().expect("template");
      let TemplateNode::Element(el) = &root.children[0] else {
        panic!()
      };
      let Attribute::Directive(d) = &el.attributes[0] else {
        panic!()
      };
      let DirectiveValue::Expression(e) = d.value.as_ref().expect("value") else {
        panic!()
      };
      (ctx.taint.status_at(e.span.start), ctx.taint.spans.len())
    };
    for _ in 0..5 {
      let mut ctx = ScanContext::new(PathBuf::from("test.vue"), source.to_string());
      parse_sfc(&mut ctx);
      let root = ctx.template_ast.as_ref().expect("template");
      let TemplateNode::Element(el) = &root.children[0] else {
        panic!()
      };
      let Attribute::Directive(d) = &el.attributes[0] else {
        panic!()
      };
      let DirectiveValue::Expression(e) = d.value.as_ref().expect("value") else {
        panic!()
      };
      assert_eq!(ctx.taint.status_at(e.span.start), first.0);
      assert_eq!(ctx.taint.spans.len(), first.1);
    }
  }
}
