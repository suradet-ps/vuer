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
  // Style blocks are extracted (see `parse_sfc`) so that their content
  // is available on `ScanContext` for future rules; full CSS analysis is
  // explicitly out of scope for v1 (documented in the README).
  Style,
}

#[derive(Debug, Clone, Copy)]
struct BlockMatch<'a> {
  attrs: &'a str,
  /// Offset of the first non-whitespace byte of the block content.
  content_offset: usize,
  /// The trimmed content of the block.
  content: &'a str,
  /// Offset just past the block's closing tag, so the caller can search
  /// for the next block of the same kind.
  close_offset: usize,
}

pub fn parse_sfc(ctx: &mut ScanContext) {
  if let Some(block) = find_block(&ctx.source, BlockKind::Template, 0) {
    ctx.template_offset = block.content_offset;
    let (root, errors) = template::parse_template(block.content, block.content_offset as u32);
    ctx.template = Some(block.content.to_string());
    ctx.template_ast = Some(root);
    ctx.template_errors = errors;
  }

  if let Some(block) = find_block(&ctx.source, BlockKind::Script, 0) {
    ctx.lang = detect_lang(block.attrs);
    ctx.script_offset = block.content_offset;
    ctx.script = Some(block.content.to_string());
  }

  // A `.vue` file may carry several `<style>` blocks (e.g. one plain and
  // one `scoped`); extract every one of them.
  let mut search_from = 0;
  while let Some(block) = find_block(&ctx.source, BlockKind::Style, search_from) {
    ctx.style_blocks.push(block.content.to_string());
    search_from = block.close_offset;
  }
}

fn find_block<'a>(source: &'a str, kind: BlockKind, start: usize) -> Option<BlockMatch<'a>> {
  let tag = kind_tag(kind);
  let open_pat = format!("<{}", tag);
  let close_pat = format!("</{}", tag);

  // The SFC block extractor splits the file on `<template>` /
  // `<script>` / `<style>` boundaries. It is a tiny scanner that runs
  // once per file. We use byte-level substring search rather than
  // building a full SFC parser because:
  //   1. We are looking for *boundaries*, not parsing SFC structure.
  //   2. The patterns are fixed and small.
  // The blocks themselves are then handed to the proper AST parsers
  // (template + script), which are full recursive-descent / oxc parsers.
  let bytes = source.as_bytes();
  let rel = find_subslice(&bytes[start..], open_pat.as_bytes())?;
  let open_offset = start + rel;
  let after_tag = open_offset + open_pat.len();
  let attr_end = source[after_tag..].find('>')? + after_tag;
  let attrs = &source[after_tag..attr_end];
  let content_start = attr_end + 1;
  let close_rel = source[content_start..].find(&close_pat)?;
  let raw_content = &source[content_start..content_start + close_rel];
  let trimmed_start = raw_content.len() - raw_content.trim_start().len();
  let content_offset = content_start + trimmed_start;
  let content = raw_content.trim();
  Some(BlockMatch {
    attrs,
    content_offset,
    content,
    close_offset: content_start + close_rel + close_pat.len(),
  })
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
  // This is the only place in the parser where we look at attribute
  // source text instead of going through the AST, and it is justified
  // for two reasons:
  //   1. The SFC's <script> tag is what we are *splitting on*, not a
  //      Vue element - there is no Vue template AST here yet.
  //   2. The attribute syntax is fixed and tiny: we only need to know
  //      whether `lang` is one of {"ts", "typescript"}.
  // Once a full SFC parser is in place, this should go through the
  // attribute AST instead.
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

#[cfg(test)]
mod tests {
  use std::path::PathBuf;

  use super::*;

  fn parse(source: &str) -> ScanContext {
    let mut ctx = ScanContext::new(PathBuf::from("fixture.vue"), source.to_string());
    parse_sfc(&mut ctx);
    ctx
  }

  #[test]
  fn extracts_template_and_script_with_offsets() {
    let ctx = parse("<template>\n  <div></div>\n</template>\n<script>\nconst x = 1;\n</script>");
    assert_eq!(ctx.template.as_deref(), Some("<div></div>"));
    assert_eq!(ctx.script.as_deref(), Some("const x = 1;"));
    // `<template>` occupies bytes 0..9; the content starts after the
    // `\n  ` padding at byte 13.
    assert_eq!(ctx.template_offset, 13);
    assert_eq!(ctx.script_offset, 46);
  }

  #[test]
  fn extracts_all_style_blocks() {
    let ctx = parse(
      "<template><div></div></template>\n\
       <style>a { color: red; }</style>\n\
       <style scoped>a { color: blue; }</style>",
    );
    assert_eq!(ctx.style_blocks.len(), 2);
    assert_eq!(ctx.style_blocks[0], "a { color: red; }");
    assert_eq!(ctx.style_blocks[1], "a { color: blue; }");
  }

  #[test]
  fn style_blocks_do_not_steal_template_content() {
    // A `<style>`-shaped string inside the template must not be mistaken
    // for a real style block when it appears after the template closed.
    let ctx = parse("<template><span>x</span></template>");
    assert!(ctx.style_blocks.is_empty());
  }

  #[test]
  fn detects_typescript_script_lang() {
    let ctx = parse("<script lang=\"ts\">const x: number = 1;</script>");
    assert_eq!(ctx.lang, ScriptLang::TypeScript);
    let ctx = parse("<script>const x = 1;</script>");
    assert_eq!(ctx.lang, ScriptLang::JavaScript);
  }

  #[test]
  fn missing_blocks_leave_context_empty() {
    let ctx = parse("plain text only");
    assert!(ctx.template.is_none());
    assert!(ctx.script.is_none());
    assert!(ctx.style_blocks.is_empty());
  }
}
