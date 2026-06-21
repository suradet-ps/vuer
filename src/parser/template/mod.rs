//! Vue template parsing.
//!
//! Entry point: [`parse_template`]. Internally this wraps the recursive-descent
//! parser in [`parser`].

mod ast;
mod parser;

pub use ast::{
  Attribute, CommentNode, Directive, DirectiveArgument, DirectiveValue, Element, Expression,
  Identifier, Interpolation, Literal, StaticAttribute, TemplateNode, TemplateRoot, TextNode,
};
pub use parser::{TemplateError, TemplateParser};

/// Parse a Vue template string into a [`TemplateRoot`], with all spans adjusted
/// by the given `base` offset.
pub fn parse_template(source: &str, base: u32) -> (TemplateRoot, Vec<TemplateError>) {
  TemplateParser::new(source, base).parse()
}

#[cfg(test)]
mod tests;
