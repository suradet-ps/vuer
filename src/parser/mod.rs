//! Single-File Component parsing.
//!
//! Stage 1: split the source into `<template>`, `<script>`, `<style>` blocks.
//! Stage 2: parse each block with the appropriate parser:
//!   * `template` -> our native recursive-descent parser (see
//!     [`crate::parser::template`]).
//!   * `script`   -> deferred to the rule (it can call `oxc_parser` directly when
//!     it needs the JS/TS AST).
//!
//! The block extractor is a single-pass, nesting-aware scanner. It tracks
//! the byte offset of every block so spans line up with the original file,
//! and it knows about the constructs that would otherwise confuse a naive
//! `find("</template>")` search:
//!
//!   * a `<template v-if="...">` element *inside* the template block
//!     (fragments, `<template v-for>`) — nesting of same-name tags is
//!     counted, so the block ends at the *matching* `</template>`;
//!   * `<script>` / `<style>` elements inside the template block — they
//!     are skipped as content, never mistaken for SFC blocks;
//!   * comments (`<!-- ... -->`) whose text contains a `</template>`-like
//!     string — they are skipped whole;
//!   * self-closing `<template/>` elements, which add no nesting depth.
//!
//! Known limitation (documented, tracked for Phase 8 fuzzing): a `>` or a
//! `</template>`-shaped string inside a *quoted attribute value* of a
//! template-level tag is still matched naively. The template parser that
//! runs afterwards re-reads the content properly; only the boundary can be
//! slightly off in that corner case.

use oxc_span::Span;

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
}

pub fn parse_sfc(ctx: &mut ScanContext) {
  let source = &ctx.source;
  let mut template_block: Option<BlockMatch> = None;
  let mut script_block: Option<BlockMatch> = None;
  let mut style_blocks: Vec<BlockMatch> = Vec::new();

  let mut cursor = 0;
  while cursor < source.len() {
    let Some(lt) = source[cursor..].find('<') else {
      break;
    };
    let lt = cursor + lt;
    if source[lt..].starts_with("<!--") {
      cursor = skip_comment(source, lt);
      continue;
    }
    let Some((kind, open_end)) = match_block_opener(source, lt) else {
      cursor = skip_tag(source, lt);
      continue;
    };

    let name_end = lt + 1 + kind_tag(kind).len();
    let attrs = &source[name_end..open_end];
    let content_start = open_end + 1;

    let block = match scan_block_end(source, content_start, kind) {
      Some(close_start) => {
        let raw = &source[content_start..close_start];
        let trimmed = raw.trim_start();
        let content_offset = content_start + (raw.len() - trimmed.len());
        let content = raw.trim();
        cursor = close_tag_end(source, close_start, kind);
        BlockMatch {
          attrs,
          content_offset,
          content,
        }
      }
      None => {
        // Unterminated block. Parse whatever content exists so rules can
        // still see a partial tree, and record a `TemplateError` so the
        // file degrades to "needs review" instead of "clean".
        if kind == BlockKind::Template {
          let raw = &source[content_start..];
          let trimmed = raw.trim_start();
          let content_offset = content_start + (raw.len() - trimmed.len());
          let content = raw.trim();
          if !content.is_empty() {
            let (root, mut errors) = template::parse_template(content, content_offset as u32);
            ctx.template = Some(content.to_string());
            ctx.template_ast = Some(root);
            ctx.template_errors.append(&mut errors);
          }
          ctx.template_errors.push(TemplateError {
            message: "Unterminated <template> block",
            span: Span::new(lt as u32, open_end as u32),
          });
        }
        break;
      }
    };

    match kind {
      BlockKind::Template => {
        if template_block.is_none() {
          template_block = Some(block);
        }
      }
      BlockKind::Script => {
        if script_block.is_none() {
          script_block = Some(block);
        }
      }
      BlockKind::Style => style_blocks.push(block),
    }
  }

  if let Some(block) = template_block {
    ctx.template_offset = block.content_offset;
    let (root, errors) = template::parse_template(block.content, block.content_offset as u32);
    ctx.template = Some(block.content.to_string());
    ctx.template_ast = Some(root);
    ctx.template_errors = errors;
  }

  if let Some(block) = script_block {
    ctx.lang = detect_lang(block.attrs);
    ctx.script_offset = block.content_offset;
    ctx.script = Some(block.content.to_string());
  }

  // A `.vue` file may carry several `<style>` blocks (e.g. one plain and
  // one `scoped`); extract every one of them.
  for block in style_blocks {
    ctx.style_blocks.push(block.content.to_string());
  }
}

/// Find a top-level `<template>` / `<script>` / `<style>` opener at `lt`
/// and return its kind plus the offset of the `>` that ends the opening
/// tag. `None` when `lt` is not the start of a block opener.
fn match_block_opener(source: &str, lt: usize) -> Option<(BlockKind, usize)> {
  for kind in [BlockKind::Template, BlockKind::Script, BlockKind::Style] {
    let tag = kind_tag(kind);
    let name_end = lt + 1 + tag.len();
    if name_end > source.len() {
      continue;
    }
    if &source[lt + 1..name_end] != tag {
      continue;
    }
    // The character after the name must terminate it: whitespace, `>`,
    // or `/`. This rejects `<template-foo>` and `<templateX>`.
    match source[name_end..].chars().next() {
      Some(c) if !(c.is_whitespace() || c == '>' || c == '/') => continue,
      None => continue,
      Some(_) => {}
    }
    // The `>` that ends the opening tag. Naive: a `>` inside a quoted
    // attribute value would end it early (documented limitation).
    let rel = source[name_end..].find('>')?;
    return Some((kind, name_end + rel));
  }
  None
}

/// Scan from `from` for the closing tag that terminates the block opened
/// by a `<tag>` of `kind`, counting nested same-name elements and
/// skipping comments. Returns the offset of the matching `</tag>`, or
/// `None` when the block is unterminated.
fn scan_block_end(source: &str, from: usize, kind: BlockKind) -> Option<usize> {
  let tag = kind_tag(kind);
  let open_pat = format!("<{tag}");
  let close_pat = format!("</{tag}");
  let mut depth = 1_u32;
  let mut j = from;
  while j < source.len() {
    let rel = source[j..].find('<')?;
    let lt = j + rel;
    if source[lt..].starts_with("<!--") {
      j = skip_comment(source, lt);
      continue;
    }
    if is_tag(source, lt, &close_pat) {
      depth -= 1;
      if depth == 0 {
        return Some(lt);
      }
      j = lt + close_pat.len();
      continue;
    }
    if is_tag(source, lt, &open_pat) {
      let after_name = lt + open_pat.len();
      if !is_self_closing(source, after_name) {
        depth += 1;
      }
      j = after_name;
      continue;
    }
    j = skip_tag(source, lt);
  }
  None
}

/// True when `source[lt..]` starts with `pat` as a *complete* tag name
/// (the next character does not extend the name).
fn is_tag(source: &str, lt: usize, pat: &str) -> bool {
  if !source[lt..].starts_with(pat) {
    return false;
  }
  !matches!(
    source[lt + pat.len()..].chars().next(),
    Some(c) if c.is_ascii_alphanumeric() || c == '-' || c == '_'
  )
}

/// True when the tag whose name ends at `from` is self-closing
/// (`... />`).
fn is_self_closing(source: &str, from: usize) -> bool {
  let Some(rel) = source[from..].find('>') else {
    return false;
  };
  source[from..from + rel].ends_with('/')
}

/// Offset just past the `>` of the closing `</tag ...>` at `close_start`.
fn close_tag_end(source: &str, close_start: usize, kind: BlockKind) -> usize {
  let after_name = close_start + 2 + kind_tag(kind).len();
  match source[after_name..].find('>') {
    Some(rel) => after_name + rel + 1,
    None => source.len(),
  }
}

/// Advance past an HTML comment starting at `lt` (`<!-- ... -->`).
/// Unterminated comments consume the rest of the source.
fn skip_comment(source: &str, lt: usize) -> usize {
  match source[lt + 4..].find("-->") {
    Some(rel) => lt + 4 + rel + 3,
    None => source.len(),
  }
}

/// Advance past the `>` that ends the tag starting at `lt`. Naive: a `>`
/// inside a quoted attribute value ends the skip early (documented
/// limitation of the boundary scanner).
fn skip_tag(source: &str, lt: usize) -> usize {
  match source[lt..].find('>') {
    Some(rel) => lt + rel + 1,
    None => source.len(),
  }
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
  fn nested_template_elements_do_not_truncate_the_block() {
    let ctx = parse(
      "<template>\n\
         <table>\n\
           <template v-for=\"row in rows\">\n\
             <tr><td>{{ row }}</td></tr>\n\
           </template>\n\
         </table>\n\
       </template>\n\
       <script>const x = 1;</script>",
    );
    let template = ctx.template.as_deref().expect("template block");
    assert!(
      template.contains("<table>") && template.contains("</table>"),
      "nested <template> must not truncate the block: {template:?}"
    );
    assert!(
      template.contains("</template>"),
      "the nested element's own closing tag is part of the content: {template:?}"
    );
    assert_eq!(ctx.script.as_deref(), Some("const x = 1;"));
  }

  #[test]
  fn script_element_inside_template_is_not_a_script_block() {
    let ctx = parse(
      "<template><script type=\"text/plain\">not real</script></template>\n\
       <script>const real = true;</script>",
    );
    assert_eq!(ctx.script.as_deref(), Some("const real = true;"));
    assert!(
      ctx
        .template
        .as_deref()
        .expect("template block")
        .contains("not real")
    );
  }

  #[test]
  fn comment_containing_closing_tag_is_skipped() {
    let ctx = parse(
      "<template>\n\
         <div></div>\n\
         <!-- commented-out: </template> <template v-if=\"x\"> -->\n\
       </template>",
    );
    assert_eq!(ctx.template_errors.len(), 0);
    let template = ctx.template.as_deref().expect("template block");
    assert!(template.contains("commented-out"));
  }

  #[test]
  fn self_closing_template_element_adds_no_depth() {
    let ctx = parse(
      "<template>\n\
         <div><template :is=\"x\"/></div>\n\
       </template>",
    );
    assert!(
      ctx.template_errors.is_empty(),
      "errors: {:?}",
      ctx.template_errors
    );
  }

  #[test]
  fn unterminated_template_block_degrades_to_needs_review() {
    let ctx = parse("<template>\n  <div></div>\n  <span>");
    assert!(
      ctx
        .template_errors
        .iter()
        .any(|e| e.message == "Unterminated <template> block"),
      "errors: {:?}",
      ctx.template_errors
    );
    // The partial content is still parsed so rules see most of the file.
    assert!(ctx.template_ast.is_some());
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
