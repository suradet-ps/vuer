//! Single-File Component parsing.
//!
//! Stage 1: split the source into `<template>`, `<script>`, `<style>` blocks.
//! Stage 2: parse each block with the appropriate parser:
//!   * `template` -> our native recursive-descent parser (see
//!     [`crate::parser::template`]).
//!   * `script`   -> deferred to the rule (it can call `oxc_parser` directly when
//!     it needs the JS/TS AST).
//!
//! The block boundaries are detected by a character-based scanner that tracks
//! the byte offset of every block, so spans line up with the original file.

use crate::context::{ScanContext, ScriptLang};
use crate::parser::template::{TemplateError, TemplateRoot};

pub mod script;
pub mod template;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockKind {
  Template,
  Script,
  #[allow(dead_code)]
  Style,
}

#[derive(Debug, Clone, Copy)]
struct BlockMatch<'a> {
  #[allow(dead_code)]
  kind: BlockKind,
  attrs: &'a str,
  /// Offset of the first non-whitespace byte of the block content.
  content_offset: usize,
  /// The trimmed content of the block.
  content: &'a str,
  #[allow(dead_code)]
  open_offset: usize,
}

pub fn parse_sfc(ctx: &mut ScanContext) {
  if let Some(block) = find_block(&ctx.source, BlockKind::Template) {
    ctx.template_offset = block.content_offset;
    let (root, errors) = template::parse_template(block.content, block.content_offset as u32);
    ctx.template = Some(block.content.to_string());
    ctx.template_ast = Some(root);
    ctx.template_errors = errors;
  }

  if let Some(block) = find_block(&ctx.source, BlockKind::Script) {
    ctx.lang = detect_lang(block.attrs);
    ctx.script_offset = block.content_offset;
    ctx.script = Some(block.content.to_string());
  }
}

fn find_block<'a>(source: &'a str, kind: BlockKind) -> Option<BlockMatch<'a>> {
  let tag = kind_tag(kind);
  let open_pat = format!("<{}", tag);
  let close_pat = format!("</{}", tag);

  let bytes = source.as_bytes();
  let search = 0;
  while let Some(rel) = find_subslice(&bytes[search..], open_pat.as_bytes()) {
    let open_offset = search + rel;
    let after_tag = open_offset + open_pat.len();
    let attr_end = source[after_tag..]
      .find('>')
      .map(|p| after_tag + p)?;
    let attrs = &source[after_tag..attr_end];
    let content_start = attr_end + 1;
    let close_rel = source[content_start..].find(&close_pat)?;
    let raw_content = &source[content_start..content_start + close_rel];
    let trimmed_start = raw_content.len() - raw_content.trim_start().len();
    let content_offset = content_start + trimmed_start;
    let content = raw_content.trim();
    return Some(BlockMatch {
      kind,
      attrs,
      content_offset,
      content,
      open_offset,
    });
  }
  None
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
  if needle.is_empty() || needle.len() > haystack.len() {
    return None;
  }
  let mut i = 0;
  while i + needle.len() <= haystack.len() {
    if &haystack[i..i + needle.len()] == needle {
      return Some(i);
    }
    i += 1;
  }
  None
}

fn kind_tag(kind: BlockKind) -> &'static str {
  match kind {
    BlockKind::Template => "template",
    BlockKind::Script => "script",
    BlockKind::Style => "style",
  }
}

fn detect_lang(attrs: &str) -> ScriptLang {
  if attrs.contains("lang=\"ts\"")
    || attrs.contains("lang='ts'")
    || attrs.contains("lang=\"typescript\"")
    || attrs.contains("lang='typescript'")
  {
    ScriptLang::TypeScript
  } else {
    ScriptLang::JavaScript
  }
}

/// Convenience: parse a template that lives outside the SFC (e.g. in tests).
#[allow(dead_code)]
pub fn parse_template_only(source: &str) -> (TemplateRoot, Vec<TemplateError>) {
  template::parse_template(source, 0)
}
