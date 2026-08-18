//! Flag elements that combine `v-if` and `v-for` on the same element.
//!
//! Vue 3 documentation explicitly discourages using `v-if` and `v-for`
//! together on one element: the priority rules changed between Vue 2 and
//! Vue 3 (in Vue 3 `v-if` evaluates first, `v-for` second), so the
//! pattern is both confusing and wasteful — the whole loop is filtered
//! after every iteration bookkeeping instead of before it. The docs
//! recommend replacing the pair with a computed filter.

use miette::{Diagnostic, NamedSource, SourceSpan};
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::template::Attribute;
use crate::rule_id::RuleId;
use crate::rules::{Category, Finding, Rule};
use crate::severity::Severity;
use crate::visitor::for_each_element;

#[derive(Error, Diagnostic, Debug)]
#[error("`v-if` and `v-for` on the same element is discouraged in Vue 3")]
#[diagnostic(
  code(vuer::performance::no_v_if_with_v_for),
  severity(Warning),
  help(
    "Vue 3 evaluates `v-if` before `v-for`, so the list is built and then \
     discarded when the condition is false — and the pair is a well-known \
     source of priority bugs. Filter the list with a computed property \
     instead, and keep `v-if` on a wrapper element."
  )
)]
pub struct NoVIfWithVForViolation {
  #[source_code]
  pub src: NamedSource<String>,
  #[label("`v-if` + `v-for` on the same element")]
  pub span: SourceSpan,
}

pub struct NoVIfWithVFor;

impl Rule for NoVIfWithVFor {
  fn id(&self) -> RuleId {
    RuleId::new("vue/performance/no-v-if-with-v-for")
  }

  fn name(&self) -> &'static str {
    "no-v-if-with-v-for"
  }

  fn description(&self) -> &'static str {
    "Disallow `v-if` together with `v-for` on the same element"
  }

  fn severity(&self) -> Severity {
    Severity::Medium
  }

  fn category(&self) -> Category {
    Category::Performance
  }

  fn check(&self, ctx: &ScanContext) -> Vec<Finding> {
    let mut violations = Vec::new();
    let Some(root) = ctx.template_ast.as_ref() else {
      return violations;
    };

    for_each_element(root, |el| {
      let mut has_v_for = false;
      let mut has_v_if = false;
      for attr in &el.attributes {
        match attr {
          Attribute::ForDirective(_) => has_v_for = true,
          Attribute::Directive(d)
            if matches!(d.name.name.as_str(), "v-if" | "v-else-if" | "v-else") =>
          {
            has_v_if = true;
          }
          _ => {}
        }
      }
      if has_v_for && has_v_if {
        violations.push(Finding::new(Box::new(NoVIfWithVForViolation {
          src: ctx.named_source.clone(),
          span: SourceSpan::new(
            (el.span.start as usize).into(),
            (el.span.end - el.span.start) as usize,
          ),
        })));
      }
    });

    violations
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::parser::parse_sfc;

  fn scan(template: &str) -> Vec<Finding> {
    let source = format!("<template>\n{template}\n</template>");
    let mut ctx = ScanContext::new("test.vue".into(), source);
    parse_sfc(&mut ctx);
    NoVIfWithVFor.check(&ctx)
  }

  #[test]
  fn flags_v_if_with_v_for_on_same_element() {
    let v = scan(r#"<li v-for="item in items" v-if="item.visible">{{ item }}</li>"#);
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_v_for_with_v_else_if() {
    let v = scan(r#"<li v-for="item in items" v-else-if="item.kind === 'x'">{{ item }}</li>"#);
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_v_for_with_v_else() {
    let v = scan(r#"<li v-for="item in items" v-else>{{ item }}</li>"#);
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn ignores_v_if_without_v_for() {
    assert!(scan(r#"<li v-if="show">x</li>"#).is_empty());
  }

  #[test]
  fn ignores_v_for_without_v_if() {
    assert!(scan(r#"<li v-for="item in items" :key="item.id">{{ item }}</li>"#).is_empty());
  }

  #[test]
  fn ignores_separate_elements() {
    // The recommended pattern: filter in a computed, keep v-if on a wrapper.
    let v = scan(r#"<ul v-if="filtered.length"><li v-for="item in filtered">{{ item }}</li></ul>"#);
    assert!(v.is_empty());
  }

  #[test]
  fn flags_nested_pairs_independently() {
    let v = scan(
      r#"<ul><li v-for="a in as" v-if="a.on"><span v-for="b in a.bs" v-if="b.on">{{ b }}</span></li></ul>"#,
    );
    assert_eq!(v.len(), 2);
  }
}
