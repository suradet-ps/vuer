//! Stable identifier for a rule.
//!
//! The id is what users will type on the CLI (`--rules vue/security/no-v-html`),
//! what shows up in SARIF `ruleId`, and what is used to silence a rule in
//! suppression comments. Keep it stable: renaming a rule id is a breaking
//! change.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RuleId(String);

impl RuleId {
  #[must_use]
  pub fn new(s: impl Into<String>) -> Self {
    Self(s.into())
  }

  #[must_use]
  pub fn as_str(&self) -> &str {
    &self.0
  }
}

impl fmt::Display for RuleId {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    f.write_str(&self.0)
  }
}

impl From<&'static str> for RuleId {
  fn from(s: &'static str) -> Self {
    Self(s.to_string())
  }
}

impl From<String> for RuleId {
  fn from(s: String) -> Self {
    Self(s)
  }
}
