//! AST-based script analysis for security rules.
//!
//! Many security rules share the same shape: "find a call to a known-dangerous
//! function and report it". This module provides:
//!
//! * [`parse_script`] - parse a `<script>` block with oxc into the borrower's
//!   `Allocator`. The allocator is passed in by the caller so that it can be
//!   stored on the rule and outlive the AST.
//! * [`find_calls`] - walk the AST and collect calls whose callee matches
//!   a rule-supplied predicate.
//! * [`callee_path`] / [`is_call_named`] - the helpers needed to recognise
//!   `name(...)`, `obj.name(...)`, and `window.obj.name(...)` call shapes.
//!
//! The visitor intentionally does not try to do taint analysis. That is a
//! research-grade undertaking with a high false-positive rate; the project's
//! philosophy is "low false positives, low false negatives, actionable".

use oxc_allocator::Allocator;
use oxc_ast::ast::{Argument, CallExpression, Expression, Program, StaticMemberExpression};
use oxc_ast_visit::Visit;
use oxc_parser::Parser;
use oxc_span::SourceType;

use crate::context::ScriptLang;

#[derive(Debug, Clone, Copy)]
pub struct SpanInfo {
  pub start: u32,
  pub end: u32,
}

impl SpanInfo {
  #[must_use]
  pub const fn len(self) -> u32 {
    self.end - self.start
  }

  #[must_use]
  pub const fn is_empty(self) -> bool {
    self.end == self.start
  }
}

impl From<oxc_span::Span> for SpanInfo {
  fn from(s: oxc_span::Span) -> Self {
    Self {
      start: s.start,
      end: s.end,
    }
  }
}

#[derive(Debug, Clone)]
pub struct CallMatch {
  pub call: SpanInfo,
  pub label: &'static str,
}

/// Parse a `<script>` block with oxc. The caller owns the `Allocator` and the
/// returned `Program` borrows from it.
pub fn parse_script<'a>(allocator: &'a Allocator, source: &'a str, lang: ScriptLang) -> Program<'a> {
  let source_type = match lang {
    ScriptLang::TypeScript => SourceType::ts(),
    _ => SourceType::default(),
  };
  Parser::new(allocator, source, source_type).parse().program
}

/// Walk the AST and collect calls whose callee matches `predicate`. The
/// predicate returns `Some(label)` to record a hit (label is shown in the
/// diagnostic) or `None` to keep walking.
pub fn find_calls<'a, F>(program: &Program<'a>, mut predicate: F) -> Vec<CallMatch>
where
  F: FnMut(&CallExpression<'a>) -> Option<&'static str>,
{
  let mut collector = CallFinder {
    matches: Vec::new(),
    predicate: &mut predicate,
  };
  collector.visit_program(program);
  collector.matches
}

struct CallFinder<'a, F> {
  matches: Vec<CallMatch>,
  predicate: &'a mut F,
}

impl<'a, 'c, F> Visit<'c> for CallFinder<'a, F>
where
  F: FnMut(&CallExpression<'c>) -> Option<&'static str>,
{
  fn visit_call_expression(&mut self, call: &CallExpression<'c>) {
    if let Some(label) = (self.predicate)(call) {
      self.matches.push(CallMatch {
        call: call.span.into(),
        label,
      });
    }
    // Continue traversal so that nested calls (e.g. `inner(eval(x))`) are
    // also considered.
    self.visit_arguments(&call.arguments);
    self.visit_expression(&call.callee);
  }
}

/// Recognise calls of the shape `name(...)`, `obj.name(...)`, and
/// `window.obj.name(...)`. Returns the segment names ordered from outer to
/// inner.
#[must_use]
pub fn callee_path<'a>(call: &'a CallExpression<'a>) -> Vec<&'a str> {
  let mut path = Vec::new();
  let mut expr: &Expression<'a> = &call.callee;
  loop {
    match expr {
      Expression::Identifier(ident) => {
        path.push(ident.name.as_str());
        break;
      }
      Expression::StaticMemberExpression(member) => {
        path.push(member.property.name.as_str());
        expr = &member.object;
      }
      Expression::ComputedMemberExpression(member) => {
        expr = &member.object;
      }
      _ => return Vec::new(),
    }
  }
  path.reverse();
  path
}

#[must_use]
pub fn is_call_named<'a>(call: &'a CallExpression<'a>, expected: &[&str]) -> bool {
  let path = callee_path(call);
  path.len() == expected.len() && path.iter().zip(expected.iter()).all(|(a, b)| a == b)
}

#[must_use]
pub fn argument_as_string_literal<'a>(call: &'a CallExpression<'a>) -> Option<&'a str> {
  match call.arguments.first()? {
    Argument::StringLiteral(lit) => Some(lit.value.as_str()),
    _ => None,
  }
}

#[allow(dead_code)]
pub fn static_member<'a>(expr: &'a Expression<'a>) -> Option<&'a StaticMemberExpression<'a>> {
  if let Expression::StaticMemberExpression(m) = expr {
    Some(m)
  } else {
    None
  }
}
