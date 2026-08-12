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
//! 4. No `unwrap()`/`panic!()` outside `#[cfg(test)]`. Malformed input is a typed
//!    [`TemplateError`], never a crash, and every recovery path is guaranteed to
//!    make progress so the parser always terminates.

use oxc_span::Span;

use super::ast::{
  Attribute, CommentNode, Directive, DirectiveArgument, DirectiveValue, Element, Expression,
  Identifier, Interpolation, Literal, StaticAttribute, TemplateNode, TemplateRoot, TextNode,
};

pub struct TemplateParser<'a> {
  source: &'a str,
  base: u32,
  cursor: usize,
  /// Errors collected while parsing. Child loops push here instead of
  /// propagating so that one bad node does not abort its whole subtree;
  /// [`parse`](Self::parse) drains the accumulator at the end.
  errors: Vec<TemplateError>,
  /// True while parsing the children of a `v-pre` element. Everything
  /// below a `v-pre` element is raw text: `{{ }}` is not an
  /// interpolation and `<b>` is not an element.
  in_pre: bool,
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
      errors: Vec::new(),
      in_pre: false,
    }
  }

  /// Parse the source into a `TemplateRoot`. Recoverable parse errors are recorded
  /// on `errors`; the returned root still contains every node we managed to
  /// recognise, so rules can still see most of the file.
  pub fn parse(mut self) -> (TemplateRoot, Vec<TemplateError>) {
    let mut children = Vec::new();
    let start = self.abs(0);
    loop {
      self.skip_whitespace();
      if self.eof() {
        break;
      }
      if self.starts_with("<!--") {
        match self.parse_comment() {
          Ok(c) => children.push(TemplateNode::Comment(c)),
          Err(e) => self.errors.push(e),
        }
        continue;
      }
      if self.starts_with("</") {
        // A stray closing tag at root level (e.g. an extra `</div>`
        // after its element already closed). Record the error, consume
        // the tag, and keep scanning — the parser must always make
        // progress here or it would loop forever on malformed input.
        self.errors.push(self.error("Unexpected closing tag"));
        self.skip_stray_closing_tag();
        continue;
      }
      match self.parse_node() {
        Ok(node) => children.push(node),
        Err(e) => {
          self.errors.push(e);
          self.recover_to_next_sibling();
        }
      }
    }
    let span = Span::new(start, self.abs(self.cursor));
    (TemplateRoot { children, span }, self.errors)
  }

  fn parse_node(&mut self) -> Result<TemplateNode, TemplateError> {
    if self.peek() == Some('<') {
      if self.starts_with("<!--") {
        return Ok(TemplateNode::Comment(self.parse_comment()?));
      }
      if self.starts_with("<![CDATA[") {
        return Ok(TemplateNode::CData(self.parse_cdata()?));
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

    // `v-pre` turns the whole subtree into raw text; the element's own
    // opening tag and attributes are still parsed normally.
    let prev_pre = self.in_pre;
    if has_v_pre(&attributes) {
      self.in_pre = true;
    }

    let mut children = Vec::new();
    // True when the element was closed by its own `</name>` tag. When a
    // mismatched closing tag is seen instead, we leave it unconsumed so
    // the parent can react to it.
    let mut closed = false;
    if !self_closing {
      loop {
        self.skip_whitespace();
        if self.eof() {
          self.in_pre = prev_pre;
          return Err(self.error_at(open_start, "Unterminated element (expected </tag>)"));
        }
        if self.starts_with("</") {
          match self.peek_tag_name() {
            Some(n) if n == name => {
              closed = true;
              break;
            }
            Some(_) => {
              self.errors.push(self.error("Mismatched closing tag"));
              break;
            }
            None => {
              self.errors.push(self.error("Unexpected closing tag"));
              self.skip_stray_closing_tag();
              continue;
            }
          }
        }
        if self.in_pre {
          // Raw text down to this element's own closing tag (`</name>`).
          // Nested tags like `<b>x</b>` inside a `v-pre` subtree stay
          // raw, mirroring the Vue compiler's raw-text tokenizer.
          let raw_start = self.cursor;
          while !self.eof() {
            if self.starts_with("</") && self.peek_tag_name().as_deref() == Some(name.as_str()) {
              break;
            }
            self.bump();
          }
          if self.cursor > raw_start {
            children.push(TemplateNode::Text(TextNode {
              text: self.source[raw_start..self.cursor].to_string(),
              span: Span::new(self.abs(raw_start), self.abs(self.cursor)),
            }));
          }
          continue;
        }
        match self.parse_node() {
          Ok(node) => children.push(node),
          Err(e) => {
            self.errors.push(e);
            self.recover_to_next_sibling();
          }
        }
      }
      self.skip_whitespace();
      if closed {
        self.bump();
        self.bump();
        let _ = self.parse_tag_name();
        self.skip_inside_tag_whitespace();
        if self.peek() == Some('>') {
          self.bump();
        }
      }
    }
    self.in_pre = prev_pre;
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
    } else if name.starts_with("v-") {
      // Covers the built-ins (`v-if`, `v-show`, `v-model`, `v-bind`,
      // `v-on`, `v-pre`, `v-once`, `v-cloak`, `v-html`, `v-text`, ...)
      // as well as user-registered directives (`v-focus`, ...).
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
        // `@click`, `@[event]`
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
      AttributeKind::Slot => {
        // `#header`, `v-slot:header`, `#[name]`
        if self.peek() == Some(':') {
          self.bump();
          argument = Some(self.parse_directive_argument()?);
        } else if self.peek() == Some('[') {
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
      AttributeKind::Directive if self.peek() == Some(':') => {
        // `v-bind:foo`, `v-on:click`, or parameter-less like `v-if`, `v-html`
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
    // Track bracket nesting (`v-bind:[arr[0]]`) and skip quoted strings
    // (`v-bind:[']']`) so a `]` inside either does not end the argument.
    let mut depth = 0_u32;
    while let Some(ch) = self.peek() {
      if ch == ']' && depth == 0 {
        break;
      }
      if matches!(ch, '\'' | '"') {
        self.skip_quoted(ch);
        continue;
      }
      if ch == '[' {
        depth += 1;
      } else if ch == ']' {
        depth = depth.saturating_sub(1);
      }
      self.bump();
    }
    let raw = self.source[value_start_byte..self.cursor].to_string();
    // The span covers exactly the expression, not the closing `]`.
    let value_end = self.abs(self.cursor);
    if self.peek() == Some(']') {
      self.bump();
    } else {
      return Err(self.error("Expected `]` in dynamic directive argument"));
    }
    Ok(DirectiveArgument::Dynamic(Expression {
      raw,
      span: Span::new(value_start, value_end),
    }))
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
        let tag_like = self.starts_with("<!--")
          || self.starts_with("<![CDATA[")
          || self.starts_with("</")
          || self.peek_at(1).is_some_and(|c| c.is_ascii_alphabetic());
        if tag_like {
          break;
        }
        // A `<` that cannot start a tag (`<1`, `<!foo`, ...) is plain
        // text. Consuming it here guarantees the text lexer always makes
        // progress and the parser cannot spin on empty text nodes.
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
    // Track brace nesting (`{{ {a: {b: 1}} }}`) and skip quoted strings
    // (`{{ "}}" }}`) so a nested `}` / a `}}` inside a string does not
    // end the interpolation early.
    let mut depth = 0_u32;
    while let Some(ch) = self.peek() {
      if ch == '}' && self.peek_at(1) == Some('}') && depth == 0 {
        break;
      }
      if ch == '<' && self.starts_with("</") && depth == 0 {
        // An interpolation cannot legally span a closing tag; stop here
        // so the element can close itself and the unterminated-
        // interpolation error is reported instead of the parser
        // swallowing the rest of the file into the expression.
        break;
      }
      if matches!(ch, '\'' | '"' | '`') {
        self.skip_quoted(ch);
        continue;
      }
      if ch == '{' {
        depth += 1;
      } else if ch == '}' && depth > 0 {
        depth -= 1;
      }
      self.bump();
    }
    let raw = self.source[value_start..self.cursor].to_string();
    // The expression span covers exactly the raw expression; the closing
    // `}}` is not part of it, so slicing the source by the span yields
    // the expression text itself.
    let expression_end = self.abs(self.cursor);
    if self.starts_with("}}") {
      self.bump();
      self.bump();
    } else {
      return Err(self.error_at(interp_start, "Unterminated `{{` interpolation"));
    }
    let span = Span::new(interp_start, self.abs(self.cursor));
    Ok(Interpolation {
      expression: Expression {
        raw,
        span: Span::new(self.abs(value_start), expression_end),
      },
      span,
    })
  }

  fn parse_cdata(&mut self) -> Result<TextNode, TemplateError> {
    let start = self.abs(self.cursor);
    for _ in 0.."<![CDATA[".len() {
      self.bump();
    }
    let value_start = self.cursor;
    while !self.eof() {
      if self.starts_with("]]>") {
        let text = self.source[value_start..self.cursor].to_string();
        self.bump();
        self.bump();
        self.bump();
        return Ok(TextNode {
          text,
          span: Span::new(start, self.abs(self.cursor)),
        });
      }
      self.bump();
    }
    Err(self.error_at(start, "Unterminated CDATA section"))
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

  /// Consume a quoted string (single, double, or backtick) without
  /// interpreting escapes. This is a lexer-level skip so that a `}}` or
  /// `]` inside a string does not end an interpolation or a dynamic
  /// directive argument early.
  fn skip_quoted(&mut self, quote: char) {
    self.bump();
    while let Some(ch) = self.peek() {
      if ch == '\\' {
        self.bump();
        if self.peek().is_some() {
          self.bump();
        }
        continue;
      }
      if ch == quote {
        self.bump();
        break;
      }
      self.bump();
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

  /// Read the tag name of the closing tag at the cursor, if any, without
  /// consuming it. Used to check that a `</...>` actually closes the
  /// current element.
  fn peek_tag_name(&self) -> Option<String> {
    if !self.starts_with("</") {
      return None;
    }
    let start = self.cursor + 2;
    let mut end = start;
    while end < self.source.len() {
      let byte = self.source.as_bytes()[end];
      if byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' {
        end += 1;
      } else {
        break;
      }
    }
    if end == start {
      return None;
    }
    Some(self.source[start..end].to_string())
  }

  /// Consume a stray `</...>` tag (one that does not close the current
  /// element, or a malformed one like `</>`), guaranteeing progress.
  fn skip_stray_closing_tag(&mut self) {
    self.bump();
    self.bump();
    let _ = self.parse_tag_name();
    self.skip_inside_tag_whitespace();
    if self.peek() == Some('>') {
      self.bump();
    }
  }

  /// Skip forward to the next sibling node: the next element opening tag
  /// (`<name`), the next closing tag (`</`), or the end of input.
  /// Comments and CDATA sections are skipped whole. Every other byte is
  /// consumed one at a time so the recovery itself cannot loop.
  fn recover_to_next_sibling(&mut self) {
    while !self.eof() {
      if self.starts_with("<!--") {
        let _ = self.parse_comment();
        continue;
      }
      if self.starts_with("<![CDATA[") {
        let _ = self.parse_cdata();
        continue;
      }
      let next = self.peek_at(1);
      if self.peek() == Some('<')
        && (next.is_some_and(|c| c.is_ascii_alphabetic()) || next == Some('/'))
      {
        break;
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

/// True when the attribute list contains `v-pre`; its subtree is raw text.
fn has_v_pre(attributes: &[Attribute]) -> bool {
  attributes
    .iter()
    .any(|attr| matches!(attr, Attribute::Directive(d) if d.name.name == "v-pre"))
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
