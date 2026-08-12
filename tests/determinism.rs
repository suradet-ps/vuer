//! Phase 2 determinism guarantee: the same input must always produce the
//! same output.
//!
//! The engine forbids global mutable state and the taint pass walks the
//! AST in source order (never a hash map), so a scan is a pure function
//! of the input tree. This suite runs the compiled binary over the whole
//! fixture directory (including the Phase 1 conformance corpus and the
//! taint-heavy vulnerable fixtures) several times and asserts the
//! machine output is byte-identical across runs — for JSON and SARIF.

mod common;

use std::path::PathBuf;

use assert_cmd::Command;

fn manifest_dir() -> PathBuf {
  PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixtures_dir() -> PathBuf {
  manifest_dir().join("tests/fixtures")
}

/// Run the compiled `vuer` binary and capture stdout.
fn run(args: &[&str]) -> String {
  let mut cmd = Command::cargo_bin("vuer").expect("vuer binary");
  cmd.args(args).env("NO_COLOR", "1");
  let output = cmd.output().expect("vuer should run");
  assert!(
    output.status.success(),
    "vuer failed: {}",
    String::from_utf8_lossy(&output.stderr)
  );
  String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn repeated_scans_produce_byte_identical_json() {
  let mut outputs = Vec::new();
  for _ in 0..5 {
    let out = run(&[
      "--format",
      "json",
      "--no-config",
      fixtures_dir().to_str().expect("path"),
    ]);
    outputs.push(out);
  }
  for (i, out) in outputs.iter().enumerate().skip(1) {
    assert_eq!(
      &outputs[0],
      out,
      "JSON output changed between run 1 and run {} — the engine is not deterministic",
      i + 1
    );
  }
  assert!(!outputs[0].is_empty(), "expected findings in the fixtures");
}

#[test]
fn repeated_scans_produce_byte_identical_sarif() {
  let mut outputs = Vec::new();
  for _ in 0..3 {
    let out = run(&[
      "--format",
      "sarif",
      "--no-config",
      fixtures_dir().to_str().expect("path"),
    ]);
    outputs.push(out);
  }
  for (i, out) in outputs.iter().enumerate().skip(1) {
    assert_eq!(
      &outputs[0],
      out,
      "SARIF output changed between run 1 and run {} — the engine is not deterministic",
      i + 1
    );
  }
}

#[test]
fn repeated_deny_warnings_runs_agree() {
  // The exit code itself is deterministic: the same findings on every run.
  let mut codes = Vec::new();
  for _ in 0..3 {
    let mut cmd = Command::cargo_bin("vuer").expect("vuer binary");
    cmd
      .arg("--no-config")
      .arg("--deny-warnings")
      .arg(fixtures_dir());
    let output = cmd.output().expect("vuer should run");
    codes.push(output.status.code());
  }
  for code in &codes[1..] {
    assert_eq!(&codes[0], code, "exit codes differ across runs");
  }
}
