use miette::{Diagnostic, NamedSource, SourceSpan};
use oxc_allocator::Allocator;
use oxc_ast_visit::Visit;
use thiserror::Error;

use crate::context::ScanContext;
use crate::parser::script::{find_calls, is_call_named, parse_script};
use crate::rule_id::RuleId;
use crate::rules::{Category, Rule};
use crate::severity::Severity;

#[derive(Error, Diagnostic, Debug)]
#[error("`eval` and `new Function` execute arbitrary code")]
#[diagnostic(
  code(vue_scanner::security::no_eval),
  severity(Warning),
  help(
    "`eval` (and `new Function`) execute strings as JavaScript. With any \
     attacker-controlled substring this is RCE. Refactor to a static \
     expression, a lookup table, or `Function.prototype` bindings."
  )
)]
pub struct NoEvalViolation {
  #[source_code]
  pub src: NamedSource<String>,
  #[label("eval / new Function call here")]
  pub span: SourceSpan,
}

pub struct NoEval;

impl Rule for NoEval {
  fn id(&self) -> RuleId {
    RuleId::new("vue/security/no-eval")
  }

  fn name(&self) -> &'static str {
    "no-eval"
  }

  fn description(&self) -> &'static str {
    "Disallow `eval(...)`, `new Function(...)`, and `setTimeout`/`setInterval` with string arguments"
  }

  fn severity(&self) -> Severity {
    Severity::Critical
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
      if is_call_named(call, &["eval"]) {
        Some("eval")
      } else if is_set_timeout_string(call) || is_set_interval_string(call) {
        Some("setTimeout/setInterval with string")
      } else {
        None
      }
    });

    for m in matches {
      let absolute = (ctx.script_offset as u32 + m.call.start) as usize;
      violations.push(Box::new(NoEvalViolation {
        src: ctx.named_source.clone(),
        span: SourceSpan::new(absolute.into(), m.call.len() as usize),
      }));
    }

    // `new Function(...)` is a `NewExpression`, not a `CallExpression`, so
    // it is not picked up by `find_calls`. Walk the AST separately to find
    // it.
    let mut new_fn_finder = NewFunctionFinder {
      hits: &mut violations,
      named_source: &ctx.named_source,
      script_offset: ctx.script_offset,
    };
    new_fn_finder.visit_program(&program);

    violations
  }
}

struct NewFunctionFinder<'a, 'b> {
  hits: &'a mut Vec<Box<dyn Diagnostic>>,
  named_source: &'b NamedSource<String>,
  script_offset: usize,
}

impl<'a, 'b, 'c> Visit<'c> for NewFunctionFinder<'a, 'b> {
  fn visit_new_expression(&mut self, expr: &oxc_ast::ast::NewExpression<'c>) {
    if is_new_function(expr) {
      let span = expr.span;
      let absolute = (self.script_offset as u32 + span.start) as usize;
      self.hits.push(Box::new(NoEvalViolation {
        src: self.named_source.clone(),
        span: SourceSpan::new(absolute.into(), (span.end - span.start) as usize),
      }));
    }
    self.visit_expression(&expr.callee);
    self.visit_arguments(&expr.arguments);
  }
}

fn is_new_function(expr: &oxc_ast::ast::NewExpression<'_>) -> bool {
  use oxc_ast::ast::Expression;
  if let Expression::Identifier(ident) = &expr.callee {
    return ident.name == "Function";
  }
  false
}

fn is_set_timeout_string(call: &oxc_ast::ast::CallExpression<'_>) -> bool {
  is_call_named(call, &["setTimeout"])
    && matches!(
      call.arguments.first(),
      Some(oxc_ast::ast::Argument::StringLiteral(_))
    )
}

fn is_set_interval_string(call: &oxc_ast::ast::CallExpression<'_>) -> bool {
  is_call_named(call, &["setInterval"])
    && matches!(
      call.arguments.first(),
      Some(oxc_ast::ast::Argument::StringLiteral(_))
    )
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::parser::parse_sfc;

  fn scan(source: &str) -> Vec<Box<dyn Diagnostic>> {
    let mut ctx = ScanContext::new("test.vue".into(), source.to_string());
    parse_sfc(&mut ctx);
    NoEval.check(&ctx)
  }

  #[test]
  fn flags_eval() {
    let src = r#"<script setup>
const x = eval(input)
</script>"#;
    assert_eq!(scan(src).len(), 1);
  }

  #[test]
  fn flags_new_function() {
    let src = r#"<script setup>
const f = new Function('a', 'return a + 1')
</script>"#;
    assert_eq!(scan(src).len(), 1);
  }

  #[test]
  fn flags_set_timeout_with_string() {
    let src = r#"<script setup>
setTimeout('alert(1)', 100)
</script>"#;
    assert_eq!(scan(src).len(), 1);
  }

  #[test]
  fn ignores_set_timeout_with_function() {
    let src = r#"<script setup>
setTimeout(() => console.log('hi'), 100)
</script>"#;
    assert!(scan(src).is_empty());
  }

  #[test]
  fn no_script_no_violation() {
    assert!(scan("").is_empty());
  }
}
