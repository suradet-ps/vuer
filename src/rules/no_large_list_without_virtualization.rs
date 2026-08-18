//! Flag `v-for` over a collection whose name implies a large/remote
//! dataset when the list is not wrapped in a virtual-scroll component.
//!
//! **Heuristic, best-effort (documented).** Rendering tens of thousands
//! of DOM nodes freezes the main thread. The rule fires only when BOTH:
//!
//! 1. the `v-for` source is a bare identifier whose name is in a curated
//!    list of collection names that typically come from a backend
//!    (`users`, `messages`, `rows`, `logs`, `transactions`, ...), and
//! 2. neither the element nor any ancestor is a known virtual-scroll
//!    wrapper (element name containing `virtual` / `scroller`, e.g.
//!    `RecycleScroller`, `el-virtual-list`, `v-virtual-scroll`).
//!
//! Names outside the list, computed slices, and function results are
//! deliberately ignored to keep the false-positive rate low. Suppress
//! with a `vuer-ignore[no-large-list-without-virtualization]` comment
//! when a list is provably small.

use miette::{Diagnostic, NamedSource, SourceSpan};
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::template::{Attribute, DirectiveValue, Element, TemplateNode};
use crate::rule_id::RuleId;
use crate::rules::{Category, Finding, Rule};
use crate::severity::Severity;

/// Collection identifiers that plausibly hold large/remote datasets.
const LARGE_LIST_NAMES: &[&str] = &[
  "users",
  "messages",
  "logs",
  "rows",
  "transactions",
  "notifications",
  "comments",
  "posts",
  "feeds",
  "results",
  "tickets",
  "orders",
  "events",
  "records",
  "articles",
  "files",
];

#[derive(Error, Diagnostic, Debug)]
#[error("`v-for` over a likely-large collection without a virtual-scroll wrapper")]
#[diagnostic(
  code(vuer::performance::no_large_list_without_virtualization),
  severity(Info),
  help(
    "Rendering every row of a large collection at once freezes the main \
     thread. Wrap the list in a virtual-scroll component (RecycleScroller, \
     el-virtual-list, vue-virtual-scroller, ...) or paginate. Heuristic: \
     if this collection is provably small, silence with \
     `vuer-ignore[no-large-list-without-virtualization]`."
  )
)]
pub struct NoLargeListWithoutVirtualizationViolation {
  #[source_code]
  pub src: NamedSource<String>,
  #[label("`v-for` here")]
  pub span: SourceSpan,
}

pub struct NoLargeListWithoutVirtualization;

impl Rule for NoLargeListWithoutVirtualization {
  fn id(&self) -> RuleId {
    RuleId::new("vue/performance/no-large-list-without-virtualization")
  }

  fn name(&self) -> &'static str {
    "no-large-list-without-virtualization"
  }

  fn description(&self) -> &'static str {
    "Heuristic: `v-for` over a large-looking collection without a virtual-scroll wrapper"
  }

  fn severity(&self) -> Severity {
    Severity::Low
  }

  fn category(&self) -> Category {
    Category::Performance
  }

  fn check(&self, ctx: &ScanContext) -> Vec<Finding> {
    let mut violations = Vec::new();
    let Some(root) = ctx.template_ast.as_ref() else {
      return violations;
    };

    walk_with_ancestors(&root.children, &mut Vec::new(), &mut |el, ancestors| {
      if ancestors.iter().any(|a| is_virtual_scroll_wrapper(a)) {
        return;
      }
      if is_virtual_scroll_wrapper(el) {
        return;
      }
      let Some(source) = v_for_source(el) else {
        return;
      };
      if !LARGE_LIST_NAMES.contains(&source.to_lowercase().as_str()) {
        return;
      }
      violations.push(Finding::new(Box::new(
        NoLargeListWithoutVirtualizationViolation {
          src: ctx.named_source.clone(),
          span: SourceSpan::new(
            (el.span.start as usize).into(),
            (el.span.end - el.span.start) as usize,
          ),
        },
      )));
    });

    violations
  }
}

/// The iterated collection of a `v-for` when it is a bare identifier,
/// e.g. `item in users` -> `users`.
fn v_for_source(el: &Element) -> Option<String> {
  let value = el.attributes.iter().find_map(|attr| match attr {
    Attribute::ForDirective(d) => match &d.value {
      Some(DirectiveValue::Expression(e)) => Some(e.raw.as_str()),
      _ => None,
    },
    _ => None,
  })?;
  let rhs = value
    .split(" in ")
    .nth(1)
    .or_else(|| value.split(" of ").nth(1))?;
  let rhs = rhs.trim();
  if rhs
    .chars()
    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
    && !rhs.is_empty()
  {
    Some(rhs.to_string())
  } else {
    None
  }
}

/// Element name suggesting a virtual-scroll wrapper (`RecycleScroller`,
/// `el-virtual-list`, `v-virtual-scroll`, `vue-virtual-scroller`, ...).
fn is_virtual_scroll_wrapper(el: &Element) -> bool {
  let name = el.name.to_lowercase();
  name.contains("virtual") || name.contains("scroller")
}

fn walk_with_ancestors<'a, F: FnMut(&Element, &[&Element])>(
  nodes: &'a [TemplateNode],
  ancestors: &mut Vec<&'a Element>,
  f: &mut F,
) {
  for node in nodes {
    if let TemplateNode::Element(el) = node {
      f(el, ancestors);
      ancestors.push(el);
      walk_with_ancestors(&el.children, ancestors, f);
      ancestors.pop();
    }
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
    NoLargeListWithoutVirtualization.check(&ctx)
  }

  #[test]
  fn flags_v_for_over_users() {
    let v = scan(r#"<li v-for="user in users" :key="user.id">{{ user.name }}</li>"#);
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_v_for_over_messages_in_nested_element() {
    let v = scan(r#"<ul><li v-for="m in messages" :key="m.id">{{ m.text }}</li></ul>"#);
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn ignores_generic_list_names_like_items() {
    assert!(scan(r#"<li v-for="item in items" :key="item.id">{{ item.name }}</li>"#).is_empty());
  }

  #[test]
  fn flags_v_for_over_rows() {
    let v = scan(r#"<tr v-for="row in rows" :key="row.id"><td>{{ row.name }}</td></tr>"#);
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn flags_upper_camel_collection() {
    let v = scan(r#"<li v-for="item in Users" :key="item.id">{{ item.name }}</li>"#);
    assert_eq!(v.len(), 1);
  }

  #[test]
  fn ignores_v_for_over_small_looking_names() {
    assert!(scan(r#"<li v-for="c in colors" :key="c">{{ c }}</li>"#).is_empty());
    assert!(scan(r#"<li v-for="s in steps" :key="s">{{ s }}</li>"#).is_empty());
  }

  #[test]
  fn ignores_v_for_over_computed_expression() {
    assert!(scan(r#"<li v-for="u in visibleUsers" :key="u.id">{{ u.name }}</li>"#).is_empty());
    assert!(
      scan(r#"<li v-for="u in users.slice(0, 10)" :key="u.id">{{ u.name }}</li>"#).is_empty()
    );
  }

  #[test]
  fn ignores_when_wrapped_in_virtual_scroller() {
    let v = scan(
      r#"<RecycleScroller :items="users"><template #default="{ item }"><li>{{ item.name }}</li></template></RecycleScroller>"#,
    );
    assert!(v.is_empty());
  }

  #[test]
  fn ignores_when_ancestor_is_virtual_wrapper() {
    let v = scan(
      r#"<v-virtual-scroll :items="users"><div><li v-for="u in users" :key="u.id">{{ u.name }}</li></div></v-virtual-scroll>"#,
    );
    assert!(v.is_empty());
  }

  #[test]
  fn ignores_when_ancestor_is_scroller() {
    let v = scan(
      r#"<el-virtual-list :items="messages"><template #default="{ item }"><li>{{ item }}</li></template></el-virtual-list>"#,
    );
    assert!(v.is_empty());
  }

  #[test]
  fn no_template_no_violation() {
    let mut ctx = ScanContext::new("test.vue".into(), "".into());
    parse_sfc(&mut ctx);
    assert!(NoLargeListWithoutVirtualization.check(&ctx).is_empty());
  }
}
