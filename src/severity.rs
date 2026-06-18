//! Diagnostic severity.
//!
//! Mirrors the 5-level scale described in the project spec:
//!
//! | Level    | Meaning                                              |
//! |----------|------------------------------------------------------|
//! | Critical | Remote code execution, secret leakage, direct XSS    |
//! | High     | Security vulnerabilities, authentication bypass risk |
//! | Medium   | Dangerous patterns, reliability issues               |
//! | Low      | Best-practice violations                             |
//! | Info     | Style recommendations                                |
//!
//! Severity is part of the rule metadata, not the diagnostic. The diagnostic
//! itself just carries the message, the source location, and the help.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
  Info,
  Low,
  Medium,
  High,
  Critical,
}

impl Severity {
  #[must_use]
  pub const fn as_str(self) -> &'static str {
    match self {
      Self::Info => "info",
      Self::Low => "low",
      Self::Medium => "medium",
      Self::High => "high",
      Self::Critical => "critical",
    }
  }

  /// Map to the closest SARIF `level` enum. SARIF has only 4 buckets; Critical
  /// collapses into `error` (which is what SARIF consumers expect for blocking
  /// issues).
  #[must_use]
  pub const fn to_sarif_level(self) -> &'static str {
    match self {
      Self::Info | Self::Low => "note",
      Self::Medium => "warning",
      Self::High | Self::Critical => "error",
    }
  }
}

impl std::fmt::Display for Severity {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(self.as_str())
  }
}
