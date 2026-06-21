use miette::{Diagnostic, NamedSource, SourceSpan};
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::template::{Attribute, DirectiveArgument};
use crate::rule_id::RuleId;
use crate::rules::{Category, Rule};
use crate::severity::Severity;
use crate::visitor::for_each_element;

/// Schemes that are universally dangerous in URLs:
/// * `javascript:` - executes code when clicked/loaded
/// * `data:`       - can host HTML, including scripts
/// * `vbscript:`   - IE-only but still present in some browsers
const DANGEROUS_PREFIXES: &[&str] = &["javascript:", "data:text/html", "vbscript:"];

#[derive(Error, Diagnostic, Debug)]
#[error("URL with dangerous scheme `{scheme}` is a known XSS vector")]
#[diagnostic(
  code(vuer::security::no_dangerous_url),
  severity(Warning),
  help(
    "`javascript:`, `data:text/html`, and `vbscript:` URLs execute code in \
     the caller's origin. Avoid them entirely; for navigation use real \
     `https?://` URLs or a router."
  )
)]
pub struct NoDangerousUrlViolation {
  #[source_code]
  pub src: NamedSource<String>,
  #[label("dangerous URL scheme here")]
  pub span: SourceSpan,
  pub scheme: String,
}

pub struct NoDangerousUrl;

impl Rule for NoDangerousUrl {
  fn id(&self) -> RuleId {
    RuleId::new("vue/security/no-dangerous-url")
  }

  fn name(&self) -> &'static str {
    "no-dangerous-url"
  }

  fn description(&self) -> &'static str {
    "Disallow `javascript:`, `data:text/html`, and `vbscript:` URLs in templates"
  }

  fn severity(&self) -> Severity {
    Severity::Critical
  }

  fn category(&self) -> Category {
    Category::Security
  }

  fn check(&self, ctx: &ScanContext) -> Vec<Box<dyn Diagnostic + Send + Sync>> {
    let mut violations = Vec::new();
    let Some(root) = ctx.template_ast.as_ref() else {
      return violations;
    };

    for_each_element(root, |el| {
      // Only check `href` and `src` attributes. Other attributes can also
      // accept URLs (xlink:href, formaction, ...) but those are less common
      // and we want to keep the false-positive rate near zero.
      for attr in &el.attributes {
        let value = match attr {
          Attribute::Static(s) => s.value.as_ref().map(|v| v.value.as_str()),
          Attribute::Directive(d) | Attribute::OnDirective(d) => {
            if is_href_or_src(d) {
              d.value.as_ref().and_then(|v| match v {
                crate::parser::template::DirectiveValue::Expression(e) => Some(e.raw.as_str()),
                crate::parser::template::DirectiveValue::Empty => None,
              })
            } else {
              None
            }
          }
          _ => None,
        };
        if let Some(v) = value
          && let Some(scheme) = find_dangerous_scheme(v)
        {
          let span = match attr {
            Attribute::Static(s) => s.span,
            _ => attr.span(),
          };
          violations.push(Box::new(NoDangerousUrlViolation {
            src: ctx.named_source.clone(),
            span: SourceSpan::new(
              (span.start as usize).into(),
              (span.end - span.start) as usize,
            ),
            scheme: scheme.to_string(),
          }));
        }
      }
    });

    violations
  }
}

fn is_href_or_src(d: &crate::parser::template::Directive) -> bool {
  matches!(d.name.name.as_str(), "v-bind" | "bind" | ":")
    && matches!(&d.argument, Some(DirectiveArgument::Static(arg)) if matches!(arg.name.as_str(), "href" | "src"))
}

fn find_dangerous_scheme(value: &str) -> Option<&'static str> {
  let trimmed = value.trim().trim_start_matches('"').trim_end_matches('"');
  DANGEROUS_PREFIXES
    .iter()
    .find(|&&prefix| trimmed.to_ascii_lowercase().starts_with(prefix))
    .copied()
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::parser::parse_sfc;

  fn scan(template: &str) -> Vec<Box<dyn Diagnostic + Send + Sync>> {
    let source = format!("<template>\n{template}\n</template>");
    let mut ctx = ScanContext::new("test.vue".into(), source);
    parse_sfc(&mut ctx);
    NoDangerousUrl.check(&ctx)
  }

  #[test]
  fn flags_javascript_href() {
    assert_eq!(scan(r#"<a href="javascript:alert(1)">x</a>"#).len(), 1);
  }

  #[test]
  fn flags_data_url() {
    assert_eq!(
      scan(r#"<a href="data:text/html,<script>alert(1)</script>">x</a>"#).len(),
      1
    );
  }

  #[test]
  fn flags_dynamic_javascript_href() {
    assert_eq!(
      scan(r#"<a :href="jsUrl">x</a>"#).len(),
      0,
      "dynamic values without literals are not flagged"
    );
  }

  #[test]
  fn ignores_https() {
    assert!(scan(r#"<a href="https://example.com">x</a>"#).is_empty());
  }

  #[test]
  fn ignores_relative_path() {
    assert!(scan(r#"<a href="/about">x</a>"#).is_empty());
  }
}
