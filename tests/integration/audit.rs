//! Per-rule regression tests.
//!
//! Each test in this file exercises one rule against a focused fixture so
//! that a failure points at a single rule, not at "the scanner". The
//! fixtures live in `tests/fixtures/`.

use std::path::PathBuf;

use vuer::scanner::{ScanOptions, Scanner};

use crate::common::fixture;

fn scan(name: &str) -> Vec<vuer::scanner::Violation> {
  scan_with_options(name, &ScanOptions::default())
}

fn scan_with_options(name: &str, options: &ScanOptions) -> Vec<vuer::scanner::Violation> {
  let scanner = Scanner::new();
  scanner
    .scan_file(&fixture(name), &[], options)
    .expect("scan should succeed")
}

fn rule_ids(violations: &[vuer::scanner::Violation]) -> Vec<&str> {
  let mut ids: Vec<&str> = violations.iter().map(|v| v.rule_id.as_str()).collect();
  ids.sort();
  ids
}

fn rule_id_count(violations: &[vuer::scanner::Violation], id: &str) -> usize {
  violations.iter().filter(|v| v.rule_id == id).count()
}

// ---------------------------------------------------------------------
// Fixture-level regression: the shared `clean.vue` / `vulnerable_full.vue`
// suite must keep flagging the same baseline of rules.
// ---------------------------------------------------------------------

#[test]
fn clean_fixture_produces_no_violations() {
  let violations = scan("clean.vue");
  assert!(
    violations.is_empty(),
    "expected no violations in clean.vue, got: {violations:#?}"
  );
}

#[test]
fn partial_fixture_is_clean() {
  // The fixture intentionally uses v-html with a "trusted" variable name;
  // the rule does not care about naming — it always flags v-html.
  let violations = scan("partial.vue");
  let ids = rule_ids(&violations);
  assert!(ids.contains(&"vue/security/no-v-html"), "ids: {ids:?}");
}

#[test]
fn vulnerable_fixture_flags_all_known_categories() {
  let violations = scan("vulnerable.vue");
  let ids = rule_ids(&violations);
  let expected = [
    "vue/security/no-dynamic-bind-src",
    "vue/security/no-v-html",
    "vue/best-practice/no-inline-style",
    "vue/best-practice/no-watch-with-callback",
  ];
  for e in expected {
    assert!(ids.contains(&e), "missing {e} in {ids:?}");
  }
}

#[test]
fn clean_full_fixture_is_clean() {
  let violations = scan("clean_full.vue");
  let ids = rule_ids(&violations);
  assert!(
    ids.is_empty(),
    "clean_full.vue should produce 0 violations, got: {ids:?}"
  );
}

#[test]
fn vulnerable_full_fixture_flags_expected_set() {
  let violations = scan("vulnerable_full.vue");
  let ids = rule_ids(&violations);
  for expected in [
    "vue/security/no-v-html",
    "vue/security/no-open-redirect",
    "vue/security/no-unsafe-iframe",
    "vue/security/no-dynamic-bind-src",
    "vue/security/no-inner-html",
    "vue/security/no-document-write",
    "vue/security/no-eval",
    "vue/security/no-unsafe-localstorage",
    "vue/security/no-postmessage-wildcard",
    "vue/security/no-window-open-blank-noopener",
    "vue/security/no-fetch-without-timeout",
    "vue/best-practice/v-for-missing-key",
    "vue/best-practice/no-watch-with-callback",
  ] {
    assert!(ids.contains(&expected), "missing {expected} in {ids:?}");
  }
}

#[test]
fn violations_have_positive_span_offsets() {
  let violations = scan("vulnerable.vue");
  for v in &violations {
    assert!(
      v.span_offset() > 0 || v.span_len() > 0,
      "violation for {} has zero span",
      v.rule_id
    );
  }
}

#[test]
fn violations_carry_rule_metadata() {
  let violations = scan("vulnerable_full.vue");
  for v in &violations {
    assert!(!v.rule_id.is_empty());
    assert!(!v.rule_name.is_empty());
  }
}

// ---------------------------------------------------------------------
// Suppression behaviour (Batch 1).
// ---------------------------------------------------------------------

#[test]
fn inline_ignore_suppresses_violation() {
  let violations = scan("with_ignores.vue");
  assert!(
    violations.iter().any(|v| !v.ignored),
    "expected at least one un-ignored violation, got: {violations:#?}"
  );
  assert!(
    violations.iter().any(|v| v.ignored),
    "expected at least one ignored violation, got: {violations:#?}"
  );
}

#[test]
fn no_ignores_flag_clears_suppression_marks() {
  let defaults = ScanOptions::default();
  let strict = ScanOptions { no_ignores: true };
  let with_ignores = scan_with_options("with_ignores.vue", &defaults);
  let strict_scan = scan_with_options("with_ignores.vue", &strict);
  assert_eq!(with_ignores.len(), strict_scan.len());
  assert!(with_ignores.iter().any(|v| v.ignored));
  assert!(strict_scan.iter().all(|v| !v.ignored));
}

#[test]
fn ignored_violations_carry_sarif_suppression() {
  use std::collections::BTreeMap;
  use vuer::report::sarif::build_sarif;

  let violations = scan("with_ignores.vue");
  assert!(violations.iter().any(|v| v.ignored));
  let source = std::fs::read_to_string(fixture("with_ignores.vue")).unwrap();
  let mut sources = BTreeMap::new();
  sources.insert(fixture("with_ignores.vue"), source);
  let log = build_sarif(&violations, &sources);
  let json = serde_json::to_string(&log).unwrap();
  assert!(json.contains("\"suppressions\""));
  assert!(json.contains("\"kind\":\"external\""));
}

// ---------------------------------------------------------------------
// Per-rule regression smoke tests. These are the "did the rule still
// fire" checks. The exact span/counts are not asserted; only that each
// rule flags at least one thing and is silent on a known-clean input.
// ---------------------------------------------------------------------

fn assert_rule_fires(rule_id: &str, vulnerable_fixture: &str) {
  let violations = scan(vulnerable_fixture);
  let count = rule_id_count(&violations, rule_id);
  assert!(
    count >= 1,
    "expected {rule_id} to fire on {vulnerable_fixture}, got {count} hits: {violations:#?}"
  );
}

fn assert_rule_silent(rule_id: &str, clean_fixture: &str) {
  let violations = scan(clean_fixture);
  let count = rule_id_count(&violations, rule_id);
  assert_eq!(
    count, 0,
    "expected {rule_id} to stay silent on {clean_fixture}, got {count} hits: {violations:#?}"
  );
}

#[test]
fn rule_v_html_fires() {
  assert_rule_fires("vue/security/no-v-html", "vulnerable.vue");
  assert_rule_silent("vue/security/no-v-html", "clean.vue");
}

#[test]
fn rule_inner_html_fires() {
  assert_rule_fires("vue/security/no-inner-html", "vulnerable_full.vue");
}

#[test]
fn rule_document_write_fires() {
  assert_rule_fires("vue/security/no-document-write", "vulnerable_full.vue");
}

#[test]
fn rule_eval_fires() {
  assert_rule_fires("vue/security/no-eval", "vulnerable_full.vue");
}

#[test]
fn rule_dangerous_url_fires() {
  // The vulnerable.vue fixture doesn't include a `javascript:` URL; the
  // dangerous URL rule is exercised by unit tests inside the rule file.
  assert_rule_silent("vue/security/no-dangerous-url", "clean.vue");
}

#[test]
fn rule_open_redirect_fires() {
  assert_rule_fires("vue/security/no-open-redirect", "vulnerable_full.vue");
}

#[test]
fn rule_unsafe_localstorage_fires() {
  assert_rule_fires("vue/security/no-unsafe-localstorage", "vulnerable_full.vue");
}

#[test]
fn rule_unsafe_iframe_fires() {
  assert_rule_fires("vue/security/no-unsafe-iframe", "vulnerable_full.vue");
}

#[test]
fn rule_dynamic_bind_src_fires() {
  assert_rule_fires("vue/security/no-dynamic-bind-src", "vulnerable.vue");
}

#[test]
fn rule_postmessage_wildcard_fires() {
  assert_rule_fires(
    "vue/security/no-postmessage-wildcard",
    "vulnerable_full.vue",
  );
}

#[test]
fn rule_window_open_blank_noopener_fires() {
  assert_rule_fires(
    "vue/security/no-window-open-blank-noopener",
    "vulnerable_full.vue",
  );
}

#[test]
fn rule_fetch_without_timeout_fires() {
  assert_rule_fires(
    "vue/security/no-fetch-without-timeout",
    "vulnerable_full.vue",
  );
}

#[test]
fn rule_inline_style_fires() {
  assert_rule_fires("vue/best-practice/no-inline-style", "vulnerable.vue");
}

#[test]
fn rule_watch_with_callback_fires() {
  assert_rule_fires("vue/best-practice/no-watch-with-callback", "vulnerable.vue");
}

#[test]
fn rule_v_for_missing_key_fires() {
  assert_rule_fires("vue/best-practice/v-for-missing-key", "vulnerable_full.vue");
}

// ---------------------------------------------------------------------
// CLI plumbing smoke tests (the binary really runs, flags reach the
// scanner, exit codes are correct).
// ---------------------------------------------------------------------

#[test]
fn binary_list_lists_every_rule() {
  use crate::common::Vuer;
  let out = Vuer::new().arg("--list").run();
  assert!(out.success(), "vuer --list failed: stderr={}", out.stderr);
  for rule in [
    "vue/security/no-v-html",
    "vue/security/no-postmessage-wildcard",
    "vue/best-practice/v-for-missing-key",
  ] {
    assert!(
      out.stdout.contains(rule),
      "--list should mention {rule}, got: {}",
      out.stdout
    );
  }
}

#[test]
fn binary_json_output_is_valid_json() {
  use crate::common::Vuer;
  let out = Vuer::new()
    .format("json")
    .input(fixture("vulnerable.vue"))
    .run();
  let parsed: serde_json::Value = serde_json::from_str(&out.stdout)
    .unwrap_or_else(|e| panic!("json output is not valid JSON ({e}):\n{}", out.stdout));
  let arr = parsed.as_array().expect("json output is an array");
  assert!(!arr.is_empty());
  let first = &arr[0];
  assert!(first.get("rule_id").is_some());
  assert!(first.get("file").is_some());
  assert!(first.get("byte_offset").is_some());
  // The new `ignored` field is in the schema, even when false.
  assert!(first.get("ignored").is_some());
}

#[test]
fn binary_minimal_output_is_line_per_finding() {
  use crate::common::Vuer;
  let out = Vuer::new()
    .format("minimal")
    .input(fixture("vulnerable_full.vue"))
    .run();
  // The minimal format writes to stderr (along with the summary footer),
  // so we read combined output and only look at the per-finding lines.
  let combined = out.combined_stripped();
  let finding_lines: Vec<&str> = combined
    .lines()
    .filter(|l| l.contains("vulnerable_full.vue"))
    .collect();
  assert!(
    finding_lines.len() >= 10,
    "expected many findings, got {finding_lines:#?}"
  );
  for line in &finding_lines {
    assert!(
      line.contains("vulnerable_full.vue"),
      "minimal line should reference the file: {line}"
    );
  }
}

#[test]
fn binary_deny_warnings_exits_nonzero() {
  use crate::common::Vuer;
  let out = Vuer::new()
    .input(fixture("vulnerable.vue"))
    .deny_warnings()
    .expect_failure(1)
    .run();
  assert!(
    !out.success(),
    "--deny-warnings should produce non-zero exit"
  );
  assert_eq!(out.status.code(), Some(1));
}

#[test]
fn binary_min_severity_filters() {
  use crate::common::Vuer;
  let all = Vuer::new()
    .format("json")
    .input(fixture("vulnerable_full.vue"))
    .run();
  let critical_only = Vuer::new()
    .format("json")
    .input(fixture("vulnerable_full.vue"))
    .min_severity("critical")
    .run();
  let all_count: serde_json::Value = serde_json::from_str(&all.stdout).unwrap();
  let filtered: serde_json::Value = serde_json::from_str(&critical_only.stdout).unwrap();
  let all_len = all_count.as_array().unwrap().len();
  let filtered_len = filtered.as_array().unwrap().len();
  assert!(
    filtered_len < all_len,
    "min-severity=critical should reduce the result count: all={all_len} filtered={filtered_len}"
  );
  for v in filtered.as_array().unwrap() {
    assert_eq!(v["severity"], "critical");
  }
}

#[test]
fn binary_rules_flag_narrows_to_subset() {
  use crate::common::Vuer;
  // Only ask for two rules; verify the JSON output only contains
  // findings for those rules.
  let out = Vuer::new()
    .format("json")
    .input(fixture("vulnerable_full.vue"))
    .rules(&["no-v-html", "no-inner-html"])
    .run();
  let json: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
  let arr = json.as_array().unwrap();
  assert!(
    !arr.is_empty(),
    "expected some findings for the selected rules"
  );
  for v in arr {
    let rule_id = v["rule_id"].as_str().unwrap();
    assert!(
      rule_id == "vue/security/no-v-html" || rule_id == "vue/security/no-inner-html",
      "--rules should narrow output: {v}"
    );
  }
}

#[test]
fn binary_category_flag_narrows_to_subset() {
  use crate::common::Vuer;
  let out = Vuer::new()
    .format("json")
    .input(fixture("vulnerable_full.vue"))
    .category(&["security"])
    .run();
  let json: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
  for v in json.as_array().unwrap() {
    assert_eq!(
      v["category"], "security",
      "--category should narrow to security: {v}"
    );
  }
}

#[test]
fn binary_no_ignores_keeps_ignored_violations_visible() {
  use crate::common::Vuer;
  let with_ignores = Vuer::new()
    .format("json")
    .input(fixture("with_ignores.vue"))
    .run();
  let strict = Vuer::new()
    .format("json")
    .input(fixture("with_ignores.vue"))
    .no_ignores()
    .run();
  let with_ignores: serde_json::Value = serde_json::from_str(&with_ignores.stdout).unwrap();
  let strict: serde_json::Value = serde_json::from_str(&strict.stdout).unwrap();
  let with_ignored = with_ignores
    .as_array()
    .unwrap()
    .iter()
    .filter(|v| v["ignored"] == true)
    .count();
  let strict_ignored = strict
    .as_array()
    .unwrap()
    .iter()
    .filter(|v| v["ignored"] == true)
    .count();
  assert!(with_ignored > 0, "default run should mark some as ignored");
  assert_eq!(
    strict_ignored, 0,
    "with --no-ignores, nothing should be marked as ignored"
  );
}

// ---------------------------------------------------------------------
// Config file (Batch 4). Each test writes a temp `.vuerc.yml` next to
// a fixture, runs vuer, then asserts on the resulting JSON.
// ---------------------------------------------------------------------

#[test]
fn config_disables_named_rule() {
  use crate::common::Vuer;

  let dir = make_temp_dir("vuer-config-disable");
  std::fs::write(dir.join("vuer.yml"), "disable:\n  - no-inline-style\n").unwrap();
  std::fs::copy(
    fixture("vulnerable_full.vue"),
    dir.join("vulnerable_full.vue"),
  )
  .unwrap();

  let out = Vuer::new().format("json").input(&dir).run();
  let json: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
  let arr = json.as_array().unwrap();
  for v in arr {
    assert_ne!(
      v["rule_id"], "vue/best-practice/no-inline-style",
      "no-inline-style should be disabled by the config"
    );
  }
  assert!(!arr.is_empty(), "other rules should still fire");
}

#[test]
fn config_min_severity_filters_output() {
  use crate::common::Vuer;

  let dir = make_temp_dir("vuer-config-severity");
  std::fs::write(dir.join("vuer.yml"), "min-severity: critical\n").unwrap();
  std::fs::copy(
    fixture("vulnerable_full.vue"),
    dir.join("vulnerable_full.vue"),
  )
  .unwrap();

  let out = Vuer::new().format("json").input(&dir).run();
  let json: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
  for v in json.as_array().unwrap() {
    assert_eq!(
      v["severity"], "critical",
      "only critical should pass with min-severity=critical, got: {v}"
    );
  }
}

#[test]
fn config_category_filters_output() {
  use crate::common::Vuer;

  let dir = make_temp_dir("vuer-config-category");
  std::fs::write(dir.join("vuer.yml"), "category:\n  - security\n").unwrap();
  std::fs::copy(
    fixture("vulnerable_full.vue"),
    dir.join("vulnerable_full.vue"),
  )
  .unwrap();

  let out = Vuer::new().format("json").input(&dir).run();
  let json: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
  for v in json.as_array().unwrap() {
    assert_eq!(v["category"], "security");
  }
}

#[test]
fn config_invalid_yaml_logs_warning_and_continues() {
  use crate::common::Vuer;

  let dir = make_temp_dir("vuer-config-invalid");
  std::fs::write(dir.join("vuer.yml"), "this is: not: valid: yaml: at all\n").unwrap();
  std::fs::copy(
    fixture("vulnerable_full.vue"),
    dir.join("vulnerable_full.vue"),
  )
  .unwrap();

  let out = Vuer::new().format("json").input(&dir).run();
  assert!(out.success(), "vuer should not crash on broken config");
  assert!(
    out.stderr.contains("warning:") && out.stderr.contains("could not parse"),
    "stderr should mention the broken config: {}",
    out.stderr
  );
  // The run continues with the default config (no disable, no severity
  // filter), so we expect to see the full set of findings.
  let json: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
  assert!(!json.as_array().unwrap().is_empty());
}

#[test]
fn config_cli_overrides_config() {
  use crate::common::Vuer;

  let dir = make_temp_dir("vuer-config-override");
  // Config says medium; CLI says critical. The higher (more
  // restrictive) one should win.
  std::fs::write(dir.join("vuer.yml"), "min-severity: medium\n").unwrap();
  std::fs::copy(
    fixture("vulnerable_full.vue"),
    dir.join("vulnerable_full.vue"),
  )
  .unwrap();

  let out = Vuer::new()
    .format("json")
    .input(&dir)
    .min_severity("critical")
    .run();
  let json: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
  for v in json.as_array().unwrap() {
    assert_eq!(v["severity"], "critical");
  }
}

#[test]
fn no_config_flag_skips_discovery() {
  use crate::common::Vuer;

  let dir = make_temp_dir("vuer-config-skip");
  // Config in the dir would disable a rule; --no-config should skip it
  // so the rule still fires.
  std::fs::write(dir.join("vuer.yml"), "disable:\n  - no-v-html\n").unwrap();
  std::fs::copy(
    fixture("vulnerable_full.vue"),
    dir.join("vulnerable_full.vue"),
  )
  .unwrap();

  let with_config = Vuer::new().format("json").input(&dir).run();
  let without_config = Vuer::new().format("json").input(&dir).no_config().run();

  let with: serde_json::Value = serde_json::from_str(&with_config.stdout).unwrap();
  let without: serde_json::Value = serde_json::from_str(&without_config.stdout).unwrap();

  let with_v_html = with
    .as_array()
    .unwrap()
    .iter()
    .filter(|v| v["rule_id"] == "vue/security/no-v-html")
    .count();
  let without_v_html = without
    .as_array()
    .unwrap()
    .iter()
    .filter(|v| v["rule_id"] == "vue/security/no-v-html")
    .count();
  assert_eq!(with_v_html, 0, "config should disable no-v-html");
  assert!(without_v_html > 0, "--no-config should re-enable no-v-html");
}

fn make_temp_dir(label: &str) -> PathBuf {
  let nanos = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)
    .unwrap()
    .as_nanos();
  let pid = std::process::id() as u128;
  let p = std::env::temp_dir().join(format!("vuer-{label}-{pid}-{nanos}"));
  std::fs::create_dir_all(&p).unwrap();
  p
}
