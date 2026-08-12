use miette::{Diagnostic, NamedSource, SourceSpan};
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::template::{Attribute, DirectiveValue};
use crate::rule_id::RuleId;
use crate::rules::{Category, Finding, Rule, RuleKind};
use crate::severity::Severity;
use crate::taint::TaintStatus;
use crate::visitor::for_each_element;

#[derive(Error, Diagnostic, Debug)]
#[error("Unsafe `v-html` directive renders untrusted HTML")]
#[diagnostic(
  code(vuer::security::no_v_html),
  severity(Warning),
  help(
    "Rendering untrusted HTML can execute arbitrary JavaScript. \
     Sanitise the input with DOMPurify (or an equivalent library), or use \
     `v-text` / `{{ }}` interpolation instead."
  )
)]
pub struct NoVHtmlViolation {
  #[source_code]
  pub src: NamedSource<String>,
  #[label("`v-html` used here")]
  pub span: SourceSpan,
}

pub struct NoVHtml;

impl Rule for NoVHtml {
  fn id(&self) -> RuleId {
    RuleId::new("vue/security/no-v-html")
  }

  fn name(&self) -> &'static str {
    "no-v-html"
  }

  fn description(&self) -> &'static str {
    "Disallow the `v-html` directive when its binding may carry untrusted data"
  }

  fn severity(&self) -> Severity {
    Severity::Critical
  }

  fn category(&self) -> Category {
    Category::Security
  }

  fn kind(&self) -> RuleKind {
    RuleKind::Taint
  }

  fn check(&self, ctx: &ScanContext) -> Vec<Finding> {
    let mut violations = Vec::new();
    let Some(root) = ctx.template_ast.as_ref() else {
      return violations;
    };

    for_each_element(root, |el| {
      for attr in &el.attributes {
        if let Attribute::Directive(d) = attr
          && d.name.name == "v-html"
          && let Some(DirectiveValue::Expression(e)) = &d.value
        {
          // Phase 2: report only when the binding may carry untrusted
          // data. Clean bindings (literals, values derived from clean
          // data) are the false-positive cut; Unknown (unparseable)
          // bindings are reported conservatively.
          if ctx.taint.status_at(e.span.start) == TaintStatus::Clean {
            continue;
          }
          let span = d.span;
          let diagnostic = Box::new(NoVHtmlViolation {
            src: ctx.named_source.clone(),
            span: SourceSpan::new(
              (span.start as usize).into(),
              (span.end - span.start) as usize,
            ),
          });
          let flow = ctx.taint.flow_at(e.span.start, "`v-html` binding");
          violations.push(match flow {
            Some(flow) => Finding::with_flow(diagnostic, vec![flow]),
            None => Finding::new(diagnostic),
          });
        }
      }
    });

    violations
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::parser::parse_sfc;

  /// Scan a full SFC: the template plus an optional script that seeds
  /// tainted sources.
  fn scan_with_script(template: &str, script: &str) -> Vec<Finding> {
    let source =
      format!("<template>\n{template}\n</template>\n<script setup>\n{script}\n</script>");
    let mut ctx = ScanContext::new("test.vue".into(), source);
    parse_sfc(&mut ctx);
    NoVHtml.check(&ctx)
  }

  fn scan(template: &str) -> Vec<Finding> {
    scan_with_script(template, "")
  }

  #[test]
  fn no_violation_on_clean_template() {
    assert!(scan(r#"<div>{{ message }}</div>"#).is_empty());
  }

  #[test]
  fn flags_v_html_with_tainted_source() {
    let v = scan_with_script(
      r#"<div v-html="userInput"></div>"#,
      "const userInput = localStorage.getItem('u')",
    );
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_v_html_with_tainted_member() {
    let v = scan_with_script(
      r#"<div v-html="user.bio"></div>"#,
      "const user = {}\nuser.bio = localStorage.getItem('b')",
    );
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_v_html_in_nested_element() {
    let v = scan_with_script(
      r#"<div><span v-html="raw"></span></div>"#,
      "const route = useRoute()\nconst raw = route.query.q",
    );
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_v_html_with_route_prop() {
    let v = scan_with_script(
      r#"<div v-html="msg"></div>"#,
      "const props = defineProps({ msg: String })",
    );
    assert_eq!(v.len(), 1);
    let flow = v[0].flow.as_ref().expect("flow");
    assert_eq!(flow[0].sink, "`v-html` binding");
    assert!(flow[0].source.contains("props"));
  }

  #[test]
  fn stays_silent_for_clean_bindings() {
    // The false-positive cut: a binding that is provably clean is not
    // reported, even though the directive is present.
    assert!(scan(r#"<div v-html="'static'"></div>"#).is_empty());
    let v = scan_with_script(
      r#"<div v-html="msg"></div>"#,
      "const msg = 'trusted constant'",
    );
    assert!(v.is_empty());
  }

  #[test]
  fn stays_silent_for_undefined_identifiers() {
    // An identifier with no known source is not provably untrusted —
    // documented boundary of the taint model.
    assert!(scan(r#"<div v-html="raw"></div>"#).is_empty());
  }

  #[test]
  fn sanitized_binding_is_clean() {
    let v = scan_with_script(
      r#"<div v-html="safe"></div>"#,
      "const safe = DOMPurify.sanitize(localStorage.getItem('u'))",
    );
    assert!(v.is_empty());
  }

  #[test]
  fn ignores_static_html_attribute() {
    // v-html only matches the directive, never a static attribute
    assert!(scan(r#"<div title="v-html"></div>"#).is_empty());
  }

  #[test]
  fn ignores_v_text_directive() {
    assert!(scan(r#"<div v-text="raw"></div>"#).is_empty());
  }
}
