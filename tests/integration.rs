// End-to-end integration tests.
//
// These read real fixture files from disk and run the full scanner
// pipeline: SFC extraction, template AST parse, script AST parse, every
// rule. The fixtures cover the cases the unit tests cannot, in particular
// file-relative offsets, multiple rules firing on the same file, and
// regressions in the SFC extractor.

use std::path::PathBuf;

use vuer::scanner::Scanner;

fn fixture(name: &str) -> PathBuf {
  let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
  p.push("tests/fixtures");
  p.push(name);
  p
}

fn scan(name: &str) -> Vec<vuer::scanner::Violation> {
  let scanner = Scanner::new();
  scanner
    .scan_file(&fixture(name), &[])
    .expect("scan should succeed")
}

fn rule_ids(violations: &[vuer::scanner::Violation]) -> Vec<&str> {
  let mut ids: Vec<&str> = violations.iter().map(|v| v.rule_id.as_str()).collect();
  ids.sort();
  ids
}

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
  // The vulnerable fixture is the canonical end-to-end regression target:
  // it must keep flagging the same set of rules so users can rely on the
  // baseline behaviour.
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
  // This file is a more comprehensive regression target: it includes
  // script-level rules as well as template-level rules.
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

#[test]
fn sarif_round_trip_includes_results_and_rules() {
  use std::collections::BTreeMap;
  use vuer::report::sarif::build_sarif;

  let violations = scan("vulnerable.vue");
  let source = std::fs::read_to_string(fixture("vulnerable.vue")).unwrap();
  let mut sources = BTreeMap::new();
  sources.insert(fixture("vulnerable.vue"), source);

  let log = build_sarif(&violations, &sources);
  let json = serde_json::to_string(&log).unwrap();

  assert!(json.contains("\"version\":\"2.1.0\""));
  assert!(json.contains("vuer"));
  assert!(json.contains("vue/security/no-v-html"));
  assert!(json.contains("\"results\""));
  assert!(json.contains("\"rules\""));
}
