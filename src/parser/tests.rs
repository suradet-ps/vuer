use std::path::PathBuf;

use crate::context::{ScanContext, ScriptLang};

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
fn script_less_than_operator_does_not_truncate_the_block() {
  // `i < items.length` puts a bare `<` in the script body. The boundary
  // scanner must not skip to the next `>` (the close tag's), which would
  // swallow the rest of the block and lose the script entirely.
  let ctx = parse(
    "<script>\n\
       for (let i = 0; i < items.length; i++) {\n\
         const r = ref(items[i])\n\
       }\n\
     </script>",
  );
  assert!(
    ctx
      .script
      .as_deref()
      .expect("script block must be extracted")
      .contains("i < items.length")
  );
  assert!(ctx.template_errors.is_empty());
}

#[test]
fn style_less_than_comparison_does_not_truncate_the_block() {
  let ctx = parse("<style>\n@media (min-width: 600px) { a > b { } }\n</style>");
  assert!(
    ctx
      .style_blocks
      .first()
      .expect("style block must be extracted")
      .contains("min-width")
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
