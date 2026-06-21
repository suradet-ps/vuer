//! Vue template AST.
//!
//! This module defines the data model for parsed Vue templates. It is intentionally
//! close to the shape produced by `vue-eslint-parser`, so security and best-practice
//! rules can reason about the real structure of the template rather than matching
//! substrings of source code.
//!
//! All node types carry a `Span` from `oxc_span` so that diagnostics can point at the
//! exact source location that produced the node.
//!
//! Strings inside the AST are owned (`String`) so the AST can live independently
//! of the input buffer and be stored on `ScanContext`. Borrow lifetimes would force
//! every rule to thread the input slice through every call, which has no upside
//! for a per-file scanner that owns its source.

use oxc_span::Span;

#[derive(Debug, Clone)]
pub struct TemplateRoot {
  pub children: Vec<TemplateNode>,
  pub span: Span,
}

#[derive(Debug, Clone)]
pub enum TemplateNode {
  Element(Element),
  Text(TextNode),
  Interpolation(Interpolation),
  Comment(CommentNode),
}

impl TemplateNode {
  #[must_use]
  pub fn span(&self) -> Span {
    match self {
      Self::Element(e) => e.span,
      Self::Text(t) => t.span,
      Self::Interpolation(i) => i.span,
      Self::Comment(c) => c.span,
    }
  }
}

#[derive(Debug, Clone)]
pub struct Element {
  pub name: String,
  pub raw_name: String,
  pub attributes: Vec<Attribute>,
  pub children: Vec<TemplateNode>,
  pub self_closing: bool,
  pub span: Span,
}

#[derive(Debug, Clone)]
pub enum Attribute {
  /// `class="foo"`, `id="bar"`, `disabled`, etc.
  Static(StaticAttribute),
  /// `v-if`, `v-show`, `v-bind`, `v-on` shorthand, `v-model`, ...
  Directive(Directive),
  /// `@click="..."` shorthand for `v-on:`
  OnDirective(Directive),
  /// `#header` shorthand for `slot:`
  SlotDirective(Directive),
  /// `(item, index) in items` for `v-for`
  ForDirective(Directive),
}

impl Attribute {
  #[must_use]
  pub fn span(&self) -> Span {
    match self {
      Self::Static(a) => a.span,
      Self::Directive(d)
      | Self::OnDirective(d)
      | Self::SlotDirective(d)
      | Self::ForDirective(d) => d.span,
    }
  }
}

#[derive(Debug, Clone)]
pub struct StaticAttribute {
  pub key: Identifier,
  pub value: Option<Literal>,
  pub span: Span,
}

#[derive(Debug, Clone)]
pub struct Directive {
  /// `v-if`, `bind`, `on`, `model`, `slot`, `for`, `html`, `text`, ...
  pub name: Identifier,
  /// `src` in `:src`, `click` in `@click`. `None` for parameter-less directives
  /// like `v-if`, `v-html`, `v-for`.
  pub argument: Option<DirectiveArgument>,
  /// `native`, `prevent`, `stop`, ...
  pub modifiers: Vec<Identifier>,
  /// The expression on the right side of `=`, if any.
  pub value: Option<DirectiveValue>,
  pub span: Span,
}

#[derive(Debug, Clone)]
pub enum DirectiveArgument {
  /// `v-bind:[dynamic]` / `v-on:[event]`
  Dynamic(Expression),
  /// `v-bind:src`, `v-on:click`
  Static(Identifier),
}

#[derive(Debug, Clone)]
pub enum DirectiveValue {
  Expression(Expression),
  /// `v-html` with no expression
  Empty,
}

#[derive(Debug, Clone)]
pub struct Expression {
  pub raw: String,
  pub span: Span,
}

#[derive(Debug, Clone)]
pub struct Identifier {
  pub name: String,
  /// For Vue, the `raw_name` is the source as written. For most identifiers it
  /// matches `name`. We keep it for parity with the `vue-eslint-parser` shape.
  pub raw_name: String,
  pub span: Span,
}

#[derive(Debug, Clone)]
pub struct Literal {
  pub value: String,
  pub span: Span,
}

#[derive(Debug, Clone)]
pub struct TextNode {
  pub text: String,
  pub span: Span,
}

#[derive(Debug, Clone)]
pub struct Interpolation {
  pub expression: Expression,
  pub span: Span,
}

#[derive(Debug, Clone)]
pub struct CommentNode {
  pub value: String,
  pub span: Span,
}
