use miette::{Diagnostic, NamedSource, SourceSpan};
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::template::{Attribute, DirectiveArgument, DirectiveValue};
use crate::rule_id::RuleId;
use crate::rules::{Category, Finding, Rule, RuleKind};
use crate::severity::Severity;
use crate::taint::TaintStatus;
use crate::visitor::for_each_element;

#[derive(Error, Diagnostic, Debug)]
#[error("Dynamic `src` binding can load untrusted resources")]
#[diagnostic(
  code(vuer::security::no_dynamic_bind_src),
  severity(Warning),
  help(
    "Validate and sanitise the URL before binding it. Allow only an explicit \
     allow-list of schemes (https, /) and hosts, and never concatenate user \
     input into the URL."
  )
)]
pub struct NoDynamicBindSrcViolation {
  #[source_code]
  pub src: NamedSource<String>,
  #[label("dynamic `src` binding here")]
  pub span: SourceSpan,
}

pub struct NoDynamicBindSrc;

impl Rule for NoDynamicBindSrc {
  fn id(&self) -> RuleId {
    RuleId::new("vue/security/no-dynamic-bind-src")
  }

  fn name(&self) -> &'static str {
    "no-dynamic-bind-src"
  }

  fn description(&self) -> &'static str {
    "Disallow dynamic `src` bindings to prevent loading untrusted resources"
  }

  fn severity(&self) -> Severity {
    Severity::High
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
        let directive = match attr {
          Attribute::Directive(d) | Attribute::OnDirective(d) => d,
          _ => continue,
        };
        if !is_bind_directive(directive) {
          continue;
        }
        let targets_src = match &directive.argument {
          Some(DirectiveArgument::Static(arg)) => arg.name == "src",
          Some(DirectiveArgument::Dynamic(_)) => true,
          None => false,
        };
        if targets_src {
          // Phase 2: report only when the bound value may carry untrusted
          // data; clean bindings are the false-positive cut, Unknown is
          // reported conservatively.
          let binding_status = match &directive.value {
            Some(DirectiveValue::Expression(e)) => ctx.taint.status_at(e.span.start),
            _ => TaintStatus::Clean,
          };
          if binding_status == TaintStatus::Clean {
            continue;
          }
          let span = directive.span;
          let diagnostic = Box::new(NoDynamicBindSrcViolation {
            src: ctx.named_source.clone(),
            span: SourceSpan::new(
              (span.start as usize).into(),
              (span.end - span.start) as usize,
            ),
          });
          let flow = match &directive.value {
            Some(DirectiveValue::Expression(e)) => {
              ctx.taint.flow_at(e.span.start, "dynamic `src` binding")
            }
            _ => None,
          };
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

fn is_bind_directive(d: &crate::parser::template::Directive) -> bool {
  matches!(d.name.name.as_str(), "v-bind" | "bind" | ":")
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::parser::parse_sfc;

  fn scan_with_script(template: &str, script: &str) -> Vec<Finding> {
    let source =
      format!("<template>\n{template}\n</template>\n<script setup>\n{script}\n</script>");
    let mut ctx = ScanContext::new("test.vue".into(), source);
    parse_sfc(&mut ctx);
    NoDynamicBindSrc.check(&ctx)
  }

  fn scan(template: &str) -> Vec<Finding> {
    scan_with_script(template, "")
  }

  #[test]
  fn clean_static_src_passes() {
    assert!(scan(r#"<img src="logo.png">"#).is_empty());
  }

  #[test]
  fn flags_v_bind_src_with_tainted_value() {
    let v = scan_with_script(
      r#"<img v-bind:src="url">"#,
      "const url = localStorage.getItem('img')",
    );
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_shorthand_bind_src() {
    let v = scan_with_script(
      r#"<img :src="url">"#,
      "const url = localStorage.getItem('img')",
    );
    assert_eq!(v.len(), 1);
    let flow = v[0].flow.as_ref().expect("flow");
    assert_eq!(flow[0].sink, "dynamic `src` binding");
  }

  #[test]
  fn flags_dynamic_argument_for_src() {
    let v = scan_with_script(
      r#"<img :[dynamicAttr]="value">"#,
      "const value = localStorage.getItem('v')",
    );
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn stays_silent_for_clean_bindings() {
    // The false-positive cut: clean/constant bindings are not reported.
    assert!(scan(r#"<img v-bind:src="'literal'">"#).is_empty());
    let v = scan_with_script(r#"<img :src="url">"#, "const url = '/static/logo.png'");
    assert!(v.is_empty());
  }

  #[test]
  fn ignores_v_bind_href() {
    // :href is not :src
    assert!(scan(r#"<a :href="url">link</a>"#).is_empty());
  }
}
