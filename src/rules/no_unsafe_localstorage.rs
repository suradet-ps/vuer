use miette::{Diagnostic, NamedSource, SourceSpan};
use oxc_allocator::Allocator;
use oxc_ast::ast::Argument;
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::script::{callee_path, find_calls, parse_script};
use crate::rule_id::RuleId;
use crate::rules::{Category, Rule};
use crate::severity::Severity;

/// Heuristic for "auth token goes into localStorage" patterns.
///
/// Real detection of token leakage requires data-flow analysis. This rule is
/// intentionally narrow: it only flags a call to
/// `localStorage.setItem(k, v)` when the first argument's name (identifier
/// or member expression) contains "token", "jwt", "secret", or "auth" —
/// either as the literal key or as a variable named with those substrings.
/// This produces a low false-positive rate at the cost of catching fewer
/// real cases. Users who want stricter analysis should run a dedicated
/// secrets scanner on top of Vue Scan.
#[derive(Error, Diagnostic, Debug)]
#[error("Auth-looking value is being written to `localStorage`")]
#[diagnostic(
  code(vue_scanner::security::no_unsafe_localstorage),
  severity(Warning),
  help(
    "Tokens in `localStorage` are reachable by any script running on the \
     page (including injected ones) and persist across sessions. Prefer an \
     `HttpOnly; Secure` cookie set by the server, or use `sessionStorage` \
     for short-lived data."
  )
)]
pub struct NoUnsafeLocalStorageViolation {
  #[source_code]
  pub src: NamedSource<String>,
  #[label("localStorage.setItem of auth-looking value here")]
  pub span: SourceSpan,
  pub key: String,
}

const TOKEN_HINTS: &[&str] = &["token", "jwt", "secret", "auth", "password", "credential"];

pub struct NoUnsafeLocalStorage;

impl Rule for NoUnsafeLocalStorage {
  fn id(&self) -> RuleId {
    RuleId::new("vue/security/no-unsafe-localstorage")
  }

  fn name(&self) -> &'static str {
    "no-unsafe-localstorage"
  }

  fn description(&self) -> &'static str {
    "Warn when an auth-looking value is written to `localStorage`"
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
      let path = callee_path(call);
      let is_set = path == ["localStorage", "setItem"];
      if !is_set {
        return None;
      }
      // Inspect both arguments for any token-like identifier. Either the
      // key name or the value name being auth-looking is suspicious.
      let key = call.arguments.first().and_then(arg_text);
      let value = call.arguments.get(1).and_then(arg_text);
      for source in [key, value].into_iter().flatten() {
        let lower = source.to_ascii_lowercase();
        for hint in TOKEN_HINTS {
          if lower.contains(hint) {
            return Some("auth-looking value");
          }
        }
      }
      None
    });

    for m in matches {
      let absolute = (ctx.script_offset as u32 + m.call.start) as usize;
      violations.push(Box::new(NoUnsafeLocalStorageViolation {
        src: ctx.named_source.clone(),
        span: SourceSpan::new(absolute.into(), m.call.len() as usize),
        key: m.label.to_string(),
      }));
    }

    violations
  }
}

fn arg_text(arg: &Argument<'_>) -> Option<String> {
  match arg {
    Argument::StringLiteral(lit) => Some(lit.value.to_string()),
    Argument::Identifier(ident) => Some(ident.name.to_string()),
    Argument::StaticMemberExpression(member) => Some(member.property.name.to_string()),
    Argument::TemplateLiteral(_) => Some("template-literal".to_string()),
    _ => None,
  }
  .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::parser::parse_sfc;

  fn scan(source: &str) -> Vec<Box<dyn Diagnostic>> {
    let mut ctx = ScanContext::new("test.vue".into(), source.to_string());
    parse_sfc(&mut ctx);
    NoUnsafeLocalStorage.check(&ctx)
  }

  #[test]
  fn flags_setItem_with_token() {
    let src = r#"<script setup>
localStorage.setItem('auth_token', jwt)
</script>"#;
    assert_eq!(scan(src).len(), 1);
  }

  #[test]
  fn flags_variable_named_jwt() {
    let src = r#"<script setup>
localStorage.setItem('session', userJwt)
</script>"#;
    assert_eq!(scan(src).len(), 1);
  }

  #[test]
  fn ignores_unrelated_key() {
    let src = r#"<script setup>
localStorage.setItem('theme', 'dark')
</script>"#;
    assert!(scan(src).is_empty());
  }

  #[test]
  fn ignores_sessionStorage() {
    let src = r#"<script setup>
sessionStorage.setItem('auth_token', value)
</script>"#;
    assert!(scan(src).is_empty());
  }

  #[test]
  fn ignores_getItem() {
    let src = r#"<script setup>
const v = localStorage.getItem('auth_token')
</script>"#;
    assert!(scan(src).is_empty());
  }
}
