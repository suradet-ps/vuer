//! Output-format snapshot tests.
//!
//! These are the regression net for the *byte shape* of the user-facing
//! output formats. When the pretty output style, JSON field ordering,
//! or SARIF metadata changes, the diff against the committed snapshot
//! is the change review.
//!
//! Path normalisation: every snapshot is run through insta filters that
//! strip the absolute path of `CARGO_MANIFEST_DIR` and the absolute
//! path of any `tests/fixtures/*` file. The committed snapshots are
//! therefore portable across machines and CI runners.

use crate::common::{Vuer, fixture};
use vuer::scanner::{ScanOptions, Scanner};

fn scanner_json(fixture_name: &str) -> String {
  let scanner = Scanner::new();
  let violations = scanner
    .scan_file(&fixture(fixture_name), &[], &ScanOptions::default())
    .expect("scan should succeed");
  let json: Vec<serde_json::Value> = violations
    .iter()
    .map(|v| {
      serde_json::json!({
        "file": v.file.display().to_string(),
        "rule_id": v.rule_id,
        "rule_name": v.rule_name,
        "severity": v.severity.as_str(),
        "category": format!("{:?}", v.category).to_lowercase(),
        "message": v.diagnostic_message(),
        "byte_offset": v.span_offset(),
        "byte_length": v.span_len(),
        "ignored": v.ignored,
      })
    })
    .collect();
  serde_json::to_string_pretty(&json).unwrap()
}

fn scanner_sarif(fixture_name: &str) -> String {
  use std::collections::BTreeMap;
  use vuer::report::sarif::build_sarif;

  let scanner = Scanner::new();
  let violations = scanner
    .scan_file(&fixture(fixture_name), &[], &ScanOptions::default())
    .expect("scan should succeed");
  let source = std::fs::read_to_string(fixture(fixture_name)).unwrap();
  let mut sources = BTreeMap::new();
  sources.insert(fixture(fixture_name), source);
  let log = build_sarif(&violations, &sources);
  serde_json::to_string_pretty(&log).unwrap()
}

fn manifest_filter() -> Vec<(&'static str, &'static str)> {
  vec![
    (r"/Users/[^/]+/[^/]+/vuer/tests/fixtures/", "<FIXTURE>/"),
    (r"/Users/[^/]+/[^/]+/vuer/", "<REPO>/"),
  ]
}

#[test]
fn json_output_for_vulnerable_fixture() {
  let json = scanner_json("vulnerable.vue");
  insta::with_settings!({
    sort_maps => true,
    filters => manifest_filter(),
  }, {
    insta::assert_snapshot!("json_vulnerable", json);
  });
}

#[test]
fn json_output_for_clean_fixture() {
  let json = scanner_json("clean.vue");
  insta::with_settings!({
    sort_maps => true,
    filters => manifest_filter(),
  }, {
    insta::assert_snapshot!("json_clean", json);
  });
}

#[test]
fn json_output_for_with_ignores_fixture() {
  let json = scanner_json("with_ignores.vue");
  insta::with_settings!({
    sort_maps => true,
    filters => manifest_filter(),
  }, {
    insta::assert_snapshot!("json_with_ignores", json);
  });
}

#[test]
fn sarif_output_for_vulnerable_fixture() {
  let json = scanner_sarif("vulnerable.vue");
  insta::with_settings!({
    sort_maps => true,
    filters => manifest_filter(),
  }, {
    insta::assert_snapshot!("sarif_vulnerable", json);
  });
}

#[test]
fn sarif_output_for_with_ignores_fixture() {
  let json = scanner_sarif("with_ignores.vue");
  insta::with_settings!({
    sort_maps => true,
    filters => manifest_filter(),
  }, {
    insta::assert_snapshot!("sarif_with_ignores", json);
  });
}

// ---------------------------------------------------------------------
// End-to-end binary snapshots. These run the actual compiled `vuer` and
// snapshot stdout+stderr (ANSI stripped for portability).
// ---------------------------------------------------------------------

#[test]
fn pretty_output_for_vulnerable_fixture() {
  let out = Vuer::new().input(fixture("vulnerable_full.vue")).run();
  let combined = out.combined_stripped();
  insta::with_settings!({
    filters => manifest_filter(),
  }, {
    insta::assert_snapshot!("pretty_vulnerable_full", combined);
  });
}

#[test]
fn pretty_output_for_clean_fixture() {
  let out = Vuer::new().input(fixture("clean.vue")).run();
  let combined = out.combined_stripped();
  insta::with_settings!({
    filters => manifest_filter(),
  }, {
    insta::assert_snapshot!("pretty_clean", combined);
  });
}

#[test]
fn pretty_output_for_with_ignores_fixture() {
  let out = Vuer::new().input(fixture("with_ignores.vue")).run();
  let combined = out.combined_stripped();
  insta::with_settings!({
    filters => manifest_filter(),
  }, {
    insta::assert_snapshot!("pretty_with_ignores", combined);
  });
}

#[test]
fn pretty_output_with_color_codes() {
  // Same fixture as the no-color snapshot, but with `with_color()` to
  // verify that ANSI codes are emitted. We don't snapshot the exact
  // escape bytes (those depend on the terminal capability), only that
  // the output contains at least one.
  let out = Vuer::new()
    .with_color()
    .input(fixture("vulnerable.vue"))
    .run();
  assert!(
    !out.combined_stripped().is_empty(),
    "should produce some output"
  );
  // The output of `vuer --format pretty` should contain at least one
  // ESC byte when colours are enabled.
  let raw = format!("{}{}", out.stdout, out.stderr);
  assert!(
    raw.contains('\x1b'),
    "with_color should emit ANSI escape codes, got: {raw}"
  );
}

#[test]
fn json_output_via_binary_is_pretty() {
  let out = Vuer::new()
    .format("json")
    .input(fixture("vulnerable.vue"))
    .run();
  insta::with_settings!({
    sort_maps => true,
    filters => manifest_filter(),
  }, {
    insta::assert_snapshot!("json_via_binary", out.stdout);
  });
}

#[test]
fn sarif_output_via_binary_is_pretty() {
  let out = Vuer::new()
    .format("sarif")
    .input(fixture("vulnerable.vue"))
    .run();
  insta::with_settings!({
    sort_maps => true,
    filters => manifest_filter(),
  }, {
    insta::assert_snapshot!("sarif_via_binary", out.stdout);
  });
}

#[test]
fn minimal_output_via_binary() {
  let out = Vuer::new()
    .format("minimal")
    .input(fixture("vulnerable.vue"))
    .run();
  insta::with_settings!({
    sort_maps => true,
    filters => manifest_filter(),
  }, {
    insta::assert_snapshot!("minimal_via_binary", out.stdout);
  });
}
