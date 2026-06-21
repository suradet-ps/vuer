use miette::{Diagnostic, NamedSource, SourceSpan};
use oxc_allocator::Allocator;
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::script::{find_calls, is_call_named, parse_script};
use crate::rule_id::RuleId;
use crate::rules::{Category, Rule};
use crate::severity::Severity;

#[derive(Error, Diagnostic, Debug)]
#[error("`document.write` is a known XSS sink")]
#[diagnostic(
  code(vuer::security::no_document_write),
  severity(Warning),
  help(
    "`document.write` after page load is almost always an XSS risk. Use \
     `appendChild`, `Element.innerHTML` (with sanitisation), or update via \
     Vue reactivity instead."
  )
)]
pub struct NoDocumentWriteViolation {
  #[source_code]
  pub src: NamedSource<String>,
  #[label("document.write call here")]
  pub span: SourceSpan,
}

pub struct NoDocumentWrite;

impl Rule for NoDocumentWrite {
  fn id(&self) -> RuleId {
    RuleId::new("vue/security/no-document-write")
  }

  fn name(&self) -> &'static str {
    "no-document-write"
  }

  fn description(&self) -> &'static str {
    "Disallow `document.write` / `document.writeln` calls"
  }

  fn severity(&self) -> Severity {
    Severity::High
  }

  fn category(&self) -> Category {
    Category::Security
  }

  fn check(&self, ctx: &ScanContext) -> Vec<Box<dyn Diagnostic>> {
    let mut violations = Vec::new();
    let Some(script) = ctx.script.as_ref() else {
      return violations;
    };

    let allocator = Allocator::default();
    let program = parse_script(&allocator, script, ctx.lang.clone());
    let matches = find_calls(&program, |call| {
      if is_call_named(call, &["document", "write"])
        || is_call_named(call, &["document", "writeln"])
      {
        Some("document.write")
      } else {
        None
      }
    });

    for m in matches {
      let absolute = (ctx.script_offset as u32 + m.call.start) as usize;
      violations.push(Box::new(NoDocumentWriteViolation {
        src: ctx.named_source.clone(),
        span: SourceSpan::new(absolute.into(), m.call.len() as usize),
      }));
    }

    violations
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::parser::parse_sfc;

  fn scan(source: &str) -> Vec<Box<dyn Diagnostic>> {
    let mut ctx = ScanContext::new("test.vue".into(), source.to_string());
    parse_sfc(&mut ctx);
    NoDocumentWrite.check(&ctx)
  }

  #[test]
  fn flags_document_write() {
    let src = r#"<script setup>
document.write('<h1>' + name + '</h1>')
</script>"#;
    assert_eq!(scan(src).len(), 1);
  }

  #[test]
  fn flags_document_writeln() {
    let src = r#"<script setup>
document.writeln(line)
</script>"#;
    assert_eq!(scan(src).len(), 1);
  }

  #[test]
  fn ignores_unrelated_document_calls() {
    let src = r#"<script setup>
document.title = 'Hello'
</script>"#;
    assert!(scan(src).is_empty());
  }

  #[test]
  fn ignores_writeln_on_other_objects() {
    // `process.stdout.writeln` is not the same sink.
    let src = r#"<script setup>
process.stdout.writeln('x')
</script>"#;
    assert!(scan(src).is_empty());
  }
}
