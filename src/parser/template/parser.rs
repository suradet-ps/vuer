//! Recursive-descent parser for Vue templates.
//!
//! The parser produces a [`TemplateRoot`](super::ast::TemplateRoot) from a template
//! string and a base offset (the byte offset of the template's first character in
//! the original `.vue` source). All spans are absolute so that diagnostics line up
//! with the original file.
//!
//! Design principles:
//!
//! 1. No regex. The lexer is character-by-character.
//! 2. No string-searching. Detection of `v-html`, `:src`, etc. is structural.
//! 3. Errors are recovered when possible so that one bad node does not blank the
//!    rest of the template.

use oxc_span::Span;

use super::ast::{
  Attribute, CommentNode, Directive, DirectiveArgument, DirectiveValue, Element, Expression,
  Identifier, Interpolation, Literal, StaticAttribute, TemplateNode, TemplateRoot, TextNode,
};

pub struct TemplateParser<'a> {
  source: &'a str,
  base: u32,
  cursor: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct TemplateError {
  pub message: &'static str,
  pub span: Span,
}

impl<'a> TemplateParser<'a> {
  #[must_use]
  pub fn new(source: &'a str, base: u32) -> Self {
    Self {
      source,
      base,
      cursor: 0,
    }
  }

  /// Parse the source into a `TemplateRoot`. Recoverable parse errors are recorded
  /// on `errors`; the returned root still contains every node we managed to
  /// recognise, so rules can still see most of the file.
  pub fn parse(mut self) -> (TemplateRoot, Vec<TemplateError>) {
    let mut children = Vec::new();
    let mut errors = Vec::new();
    let start = self.abs(0);
    loop {
      self.skip_whitespace();
      if self.eof() {
        break;
      }
      if self.starts_with("<!--") {
        match self.parse_comment() {
          Ok(c) => children.push(TemplateNode::Comment(c)),
          Err(e) => {
            errors.push(e);
          }
        }
        continue;
      }
      match self.parse_node() {
        Ok(node) => children.push(node),
        Err(e) => {
          errors.push(e);
          self.recover_to_next_sibling();
        }
      }
    }
    let span = Span::new(start, self.abs(self.cursor));
    (TemplateRoot { children, span }, errors)
  }

  fn parse_node(&mut self) -> Result<TemplateNode, TemplateError> {
    if self.peek() == Some('<') {
      if self.starts_with("<!--") {
        return Ok(TemplateNode::Comment(self.parse_comment()?));
      }
      if self.starts_with("</") {
        return Err(self.error("Unexpected closing tag"));
      }
      if self.is_start_of_element() {
        return Ok(TemplateNode::Element(self.parse_element()?));
      }
    }
    if self.peek() == Some('{') && self.peek_at(1) == Some('{') {
      return Ok(TemplateNode::Interpolation(self.parse_interpolation()?));
    }
    Ok(TemplateNode::Text(self.parse_text()))
  }

  fn parse_element(&mut self) -> Result<Element, TemplateError> {
    let open_start = self.abs(self.cursor);
    self.expect_char('<')?;
    let (name, raw_name) = self.parse_tag_name()?;
    let mut attributes = Vec::new();
    let mut self_closing = false;
    loop {
      self.skip_inside_tag_whitespace();
      match self.peek() {
        Some('/') => {
          self.bump();
          self_closing = true;
          if self.peek() == Some('>') {
            self.bump();
          }
          break;
        }
        Some('>') => {
          self.bump();
          break;
        }
        None => {
          return Err(self.error_at(open_start, "Unterminated element"));
        }
        Some(_) => match self.parse_attribute() {
          Ok(attr) => attributes.push(attr),
          Err(e) => {
            return Err(e);
          }
        },
      }
    }

    // HTML void elements (`<img>`, `<br>`, `<input>`, ...) are implicitly
    // self-closing. Without this, `<img src="...">` would be flagged as
    // unterminated, which is wrong both as a parse error and from the user's
    // point of view.
    if !self_closing && is_void_element(&name) {
      self_closing = true;
    }
    let mut children = Vec::new();
    if !self_closing {
      loop {
        self.skip_whitespace_and_comments();
        if self.eof() {
          return Err(self.error_at(open_start, "Unterminated element (expected </tag>)"));
        }
        if self.starts_with("</") {
          break;
        }
        match self.parse_node() {
          Ok(node) => children.push(node),
          Err(_) => {
            self.recover_to_next_sibling();
          }
        }
      }
      self.skip_whitespace_and_comments();
      if self.starts_with("</") {
        self.bump();
        self.bump();
        let _ = self.parse_tag_name();
        self.skip_inside_tag_whitespace();
        if self.peek() == Some('>') {
          self.bump();
        }
      }
    }
    let span = Span::new(open_start, self.abs(self.cursor));
    Ok(Element {
      name,
      raw_name,
      attributes,
      children,
      self_closing,
      span,
    })
  }

  fn parse_attribute(&mut self) -> Result<Attribute, TemplateError> {
    let attr_start = self.abs(self.cursor);
    let (name, raw_name) = self.parse_attribute_name()?;
    let mut argument: Option<DirectiveArgument> = None;
    let mut modifiers: Vec<Identifier> = Vec::new();
    let mut value: Option<DirectiveValue> = None;
    let mut kind = AttributeKind::Static;

    if name == "v-for" {
      kind = AttributeKind::For;
    } else if name == "v-slot" || name == "slot" {
      kind = AttributeKind::Slot;
    } else if name == "v-on" || name == "v-bind" || is_vue_directive(&name) {
      kind = AttributeKind::Directive;
    } else if name == "@" {
      kind = AttributeKind::On;
    } else if name == ":" {
      kind = AttributeKind::Bind;
    } else if name == "#" {
      kind = AttributeKind::Slot;
    }

    match kind {
      AttributeKind::Bind => {
        // `:foo` or `:[foo]`
        if self.peek() == Some('[') {
          argument = Some(self.parse_dynamic_argument()?);
        } else if matches!(self.peek(), Some(ch) if ch.is_ascii_alphabetic() || ch == '_') {
          let (arg_name, arg_raw) = self.parse_attribute_name()?;
          let start = self.abs(self.cursor - arg_name.len());
          argument = Some(DirectiveArgument::Static(Identifier {
            name: arg_name,
            raw_name: arg_raw,
            span: Span::new(start, self.abs(self.cursor)),
          }));
        }
      }
      AttributeKind::On => {
        // `@foo`
        if matches!(self.peek(), Some(ch) if ch.is_ascii_alphabetic() || ch == '_') {
          let (arg_name, arg_raw) = self.parse_attribute_name()?;
          let start = self.abs(self.cursor - arg_name.len());
          argument = Some(DirectiveArgument::Static(Identifier {
            name: arg_name,
            raw_name: arg_raw,
            span: Span::new(start, self.abs(self.cursor)),
          }));
        }
      }
      AttributeKind::Slot => {
        // `#foo`
        if matches!(self.peek(), Some(ch) if ch.is_ascii_alphabetic() || ch == '_') {
          let (arg_name, arg_raw) = self.parse_attribute_name()?;
          let start = self.abs(self.cursor - arg_name.len());
          argument = Some(DirectiveArgument::Static(Identifier {
            name: arg_name,
            raw_name: arg_raw,
            span: Span::new(start, self.abs(self.cursor)),
          }));
        }
      }
      AttributeKind::Directive if self.peek() == Some(':') => {
        // `v-bind:foo`, `v-on:foo`, or parameter-less like `v-if`, `v-html`
        self.bump();
        argument = Some(self.parse_directive_argument()?);
      }
      AttributeKind::Directive => {}
      _ => {}
    }

    while self.peek() == Some('.') {
      self.bump();
      let (mod_name, mod_raw) = self.parse_simple_ident()?;
      let mod_start = self.abs(self.cursor - mod_name.len());
      modifiers.push(Identifier {
        name: mod_name,
        raw_name: mod_raw,
        span: Span::new(mod_start, self.abs(self.cursor)),
      });
    }

    if self.peek() == Some('=') {
      self.bump();
      let value_start = self.abs(self.cursor);
      let raw = self.parse_attribute_value()?;
      let value_end = self.abs(self.cursor);
      let expr = Expression {
        raw,
        span: Span::new(value_start, value_end),
      };
      value = Some(DirectiveValue::Expression(expr));
    }

    let attr_end = self.abs(self.cursor);
    let span = Span::new(attr_start, attr_end);
    let name_len = name.len() as u32;
    let directive = Directive {
      name: Identifier {
        name,
        raw_name,
        span: Span::new(attr_start, attr_start + name_len),
      },
      argument,
      modifiers,
      value,
      span,
    };
    let attr = match kind {
      AttributeKind::Static => {
        let key = directive.name.clone();
        let value_literal = directive.value.and_then(|v| match v {
          DirectiveValue::Expression(e) => Some(Literal {
            value: e.raw,
            span: e.span,
          }),
          DirectiveValue::Empty => None,
        });
        Attribute::Static(StaticAttribute {
          key,
          value: value_literal,
          span,
        })
      }
      AttributeKind::Directive | AttributeKind::Bind => Attribute::Directive(directive),
      AttributeKind::On => Attribute::OnDirective(directive),
      AttributeKind::Slot => Attribute::SlotDirective(directive),
      AttributeKind::For => Attribute::ForDirective(directive),
    };
    Ok(attr)
  }

  fn parse_directive_argument(&mut self) -> Result<DirectiveArgument, TemplateError> {
    if self.peek() == Some('[') {
      self.parse_dynamic_argument()
    } else {
      let (name, raw_name) = self.parse_attribute_name()?;
      let start = self.abs(self.cursor - name.len());
      Ok(DirectiveArgument::Static(Identifier {
        name,
        raw_name,
        span: Span::new(start, self.abs(self.cursor)),
      }))
    }
  }

  fn parse_dynamic_argument(&mut self) -> Result<DirectiveArgument, TemplateError> {
    self.expect_char('[')?;
    let value_start = self.abs(self.cursor);
    let value_start_byte = self.cursor;
    while let Some(ch) = self.peek() {
      if ch == ']' {
        break;
      }
      self.bump();
    }
    let raw = self.source[value_start_byte..self.cursor].to_string();
    if self.peek() == Some(']') {
      self.bump();
    } else {
      return Err(self.error("Expected `]` in dynamic directive argument"));
    }
    let span = Span::new(value_start, self.abs(self.cursor));
    Ok(DirectiveArgument::Dynamic(Expression { raw, span }))
  }

  fn parse_attribute_value(&mut self) -> Result<String, TemplateError> {
    match self.peek() {
      Some('"') => self.parse_quoted('"'),
      Some('\'') => self.parse_quoted('\''),
      _ => {
        let start = self.cursor;
        while let Some(ch) = self.peek() {
          if ch.is_whitespace() || ch == '>' || ch == '/' || ch == '<' {
            break;
          }
          self.bump();
        }
        Ok(self.source[start..self.cursor].to_string())
      }
    }
  }

  fn parse_quoted(&mut self, quote: char) -> Result<String, TemplateError> {
    self.expect_char(quote)?;
    let value_start = self.cursor;
    while let Some(ch) = self.peek() {
      if ch == quote {
        let raw = self.source[value_start..self.cursor].to_string();
        self.bump();
        return Ok(raw);
      }
      self.bump();
    }
    Err(self.error("Unterminated quoted attribute value"))
  }

  fn parse_attribute_name(&mut self) -> Result<(String, String), TemplateError> {
    let start = self.cursor;
    let first = self
      .peek()
      .ok_or_else(|| self.error("Unexpected end of input"))?;
    if first == ':' || first == '@' || first == '#' {
      self.bump();
      let end = self.cursor;
      let raw = self.source[start..end].to_string();
      return Ok((raw.clone(), raw));
    }
    if first == 'v' && self.peek_at(1) == Some('-') {
      // Consume `v-bind` / `v-on` / `v-html` / `v-for` etc. but stop at the
      // first `:` so that the caller can handle `v-bind:foo` correctly.
      self.bump();
      self.bump();
      while let Some(ch) = self.peek() {
        if ch.is_ascii_alphanumeric() || ch == '-' {
          self.bump();
        } else {
          break;
        }
      }
      let raw = self.source[start..self.cursor].to_string();
      return Ok((raw.clone(), raw));
    }
    while let Some(ch) = self.peek() {
      if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
        self.bump();
      } else {
        break;
      }
    }
    if start == self.cursor {
      return Err(self.error("Expected attribute name"));
    }
    let raw = self.source[start..self.cursor].to_string();
    Ok((raw.clone(), raw))
  }

  fn parse_tag_name(&mut self) -> Result<(String, String), TemplateError> {
    let start = self.cursor;
    while let Some(ch) = self.peek() {
      if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
        self.bump();
      } else {
        break;
      }
    }
    if start == self.cursor {
      return Err(self.error("Expected tag name"));
    }
    let raw = self.source[start..self.cursor].to_string();
    Ok((raw.clone(), raw))
  }

  fn parse_simple_ident(&mut self) -> Result<(String, String), TemplateError> {
    let start = self.cursor;
    while let Some(ch) = self.peek() {
      if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
        self.bump();
      } else {
        break;
      }
    }
    if start == self.cursor {
      return Err(self.error("Expected identifier"));
    }
    let raw = self.source[start..self.cursor].to_string();
    Ok((raw.clone(), raw))
  }

  fn parse_text(&mut self) -> TextNode {
    let start = self.cursor;
    while let Some(ch) = self.peek() {
      if ch == '<' {
        break;
      }
      if ch == '{' && self.peek_at(1) == Some('{') {
        break;
      }
      self.bump();
    }
    TextNode {
      text: self.source[start..self.cursor].to_string(),
      span: Span::new(self.abs(start), self.abs(self.cursor)),
    }
  }

  fn parse_interpolation(&mut self) -> Result<Interpolation, TemplateError> {
    let interp_start = self.abs(self.cursor);
    self.expect_char('{')?;
    self.expect_char('{')?;
    let value_start = self.cursor;
    let mut depth = 0_u32;
    while let Some(ch) = self.peek() {
      if ch == '}' && self.peek_at(1) == Some('}') {
        break;
      }
      if ch == '{' {
        depth += 1;
      } else if ch == '}' && depth > 0 {
        depth -= 1;
      }
      self.bump();
    }
    let raw = self.source[value_start..self.cursor].to_string();
    if self.peek() == Some('}') {
      self.bump();
    }
    if self.peek() == Some('}') {
      self.bump();
    } else {
      return Err(self.error_at(interp_start, "Unterminated `{{` interpolation"));
    }
    let span = Span::new(interp_start, self.abs(self.cursor));
    Ok(Interpolation {
      expression: Expression {
        raw,
        span: Span::new(self.abs(value_start), self.abs(self.cursor)),
      },
      span,
    })
  }

  fn parse_comment(&mut self) -> Result<CommentNode, TemplateError> {
    let start = self.abs(self.cursor);
    self.expect_char('<')?;
    self.expect_char('!')?;
    self.expect_char('-')?;
    self.expect_char('-')?;
    let value_start = self.cursor;
    while !self.eof() {
      if self.starts_with("-->") {
        let value = self.source[value_start..self.cursor].to_string();
        self.bump();
        self.bump();
        self.bump();
        return Ok(CommentNode {
          value,
          span: Span::new(start, self.abs(self.cursor)),
        });
      }
      self.bump();
    }
    Err(self.error_at(start, "Unterminated comment"))
  }

  fn skip_whitespace_and_comments(&mut self) {
    loop {
      if self.starts_with("<!--") {
        let _ = self.parse_comment();
        continue;
      }
      if let Some(ch) = self.peek()
        && ch.is_whitespace()
      {
        self.bump();
        continue;
      }
      break;
    }
  }

  fn skip_whitespace(&mut self) {
    while let Some(ch) = self.peek() {
      if ch.is_whitespace() {
        self.bump();
      } else {
        break;
      }
    }
  }

  fn skip_inside_tag_whitespace(&mut self) {
    while let Some(ch) = self.peek() {
      if ch.is_whitespace() {
        self.bump();
      } else {
        break;
      }
    }
  }

  fn is_start_of_element(&self) -> bool {
    if self.peek() != Some('<') {
      return false;
    }
    if let Some(next) = self.peek_at(1)
      && next.is_ascii_alphabetic()
    {
      return true;
    }
    false
  }

  fn recover_to_next_sibling(&mut self) {
    while !self.eof() {
      if self.peek() == Some('<') && self.peek_at(1) != Some('!') {
        break;
      }
      if self.peek() == Some('<') && self.starts_with("<!--") {
        // skip the comment
        let _ = self.parse_comment();
        continue;
      }
      self.bump();
    }
  }

  fn starts_with(&self, pat: &str) -> bool {
    self.source[self.cursor..].starts_with(pat)
  }

  fn peek(&self) -> Option<char> {
    self.source[self.cursor..].chars().next()
  }

  fn peek_at(&self, offset: usize) -> Option<char> {
    self.source[self.cursor..].chars().nth(offset)
  }

  fn bump(&mut self) {
    if let Some(ch) = self.peek() {
      self.cursor += ch.len_utf8();
    }
  }

  fn eof(&self) -> bool {
    self.cursor >= self.source.len()
  }

  fn abs(&self, offset: usize) -> u32 {
    self.base + offset as u32
  }

  fn expect_char(&mut self, ch: char) -> Result<(), TemplateError> {
    if self.peek() == Some(ch) {
      self.bump();
      Ok(())
    } else {
      Err(self.error_at(self.abs(self.cursor), "Unexpected character"))
    }
  }

  fn error(&self, message: &'static str) -> TemplateError {
    TemplateError {
      message,
      span: Span::new(self.abs(self.cursor), self.abs(self.cursor)),
    }
  }

  fn error_at(&self, span: u32, message: &'static str) -> TemplateError {
    TemplateError {
      message,
      span: Span::new(span, span),
    }
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AttributeKind {
  Static,
  Directive,
  Bind,
  On,
  Slot,
  For,
}

fn is_vue_directive(name: &str) -> bool {
  matches!(
    name,
    "v-if"
      | "v-else"
      | "v-else-if"
      | "v-for"
      | "v-show"
      | "v-html"
      | "v-text"
      | "v-model"
      | "v-once"
      | "v-pre"
      | "v-cloak"
      | "v-memo"
  )
}

/// HTML void elements. These never have a closing tag and never contain
/// children. Treat them as implicitly self-closing.
fn is_void_element(name: &str) -> bool {
  matches!(
    name,
    "area"
      | "base"
      | "br"
      | "col"
      | "embed"
      | "hr"
      | "img"
      | "input"
      | "link"
      | "meta"
      | "param"
      | "source"
      | "track"
      | "wbr"
  )
}
