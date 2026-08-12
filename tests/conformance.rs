//! Phase 1 conformance suite: real-world Vue component templates.
//!
//! The corpus lives in `tests/fixtures/templates/` — original SFCs
//! modelled on common Vue 3 patterns (forms, cards, data tables, SVG
//! foreign content, modals, navigation) covering the constructs the
//! template parser must survive: fragments, slots, dynamic arguments,
//! event modifiers, self-closing custom elements, `<component :is>`,
//! `<Teleport>`/`<Transition>`/`<Suspense>`, `v-pre` raw text, CDATA,
//! entities, and Unicode text.
//!
//! Two invariants hold for every fixture:
//!   1. It parses **without panic and without a single `TemplateError`**
//!      (a conformance failure here means the parser mis-reads real
//!      input, which would hide findings).
//!   2. Its structural snapshot (the element/attribute tree) is committed
//!      under `tests/snapshots/`; any change to the tree shows up as a
//!      snapshot diff during review.

mod common;

use std::path::PathBuf;

use common::{describe_root, describe_sfc};
use vuer::context::ScanContext;
use vuer::parser::parse_sfc;

fn manifest_dir() -> PathBuf {
  PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn corpus_dir() -> PathBuf {
  manifest_dir().join("tests/fixtures/templates")
}

#[test]
fn corpus_has_expected_fixtures() {
  let mut names: Vec<String> = std::fs::read_dir(corpus_dir())
    .expect("conformance corpus dir")
    .map(|e| {
      e.expect("dir entry")
        .file_name()
        .to_string_lossy()
        .into_owned()
    })
    .collect();
  names.sort();
  let expected = [
    "data-table.vue",
    "login-form.vue",
    "modal.vue",
    "nav-menu.vue",
    "product-card.vue",
    "settings-form.vue",
    "svg-badge.vue",
  ];
  assert_eq!(
    names, expected,
    "conformance corpus changed — update this list"
  );
}

#[test]
fn every_fixture_parses_without_errors_or_panic() {
  for entry in std::fs::read_dir(corpus_dir()).expect("conformance corpus dir") {
    let path = entry.expect("dir entry").path();
    let source = std::fs::read_to_string(&path).expect("fixture is readable");
    let mut ctx = ScanContext::new(path.clone(), source);
    parse_sfc(&mut ctx);
    assert!(
      ctx.template_errors.is_empty(),
      "{} must parse without errors, got: {:#?}",
      path.display(),
      ctx.template_errors
    );
    assert!(
      ctx.template_ast.is_some(),
      "{} must yield a TemplateRoot",
      path.display()
    );
  }
}

// One structural snapshot per fixture. The snapshot name is the file
// stem so a diff names the fixture it belongs to.
#[test]
fn structural_snapshots_match() {
  for entry in std::fs::read_dir(corpus_dir()).expect("conformance corpus dir") {
    let path = entry.expect("dir entry").path();
    let stem = path
      .file_stem()
      .expect("fixture stem")
      .to_string_lossy()
      .into_owned();
    let source = std::fs::read_to_string(&path).expect("fixture is readable");
    let mut ctx = ScanContext::new(path, source);
    parse_sfc(&mut ctx);
    let root = ctx.template_ast.as_ref().expect("template block");
    insta::assert_snapshot!(stem, describe_root(root));
  }
}

#[test]
fn describe_roundtrips_the_canonical_shape() {
  // Smoke test the shared helper on a tiny inline SFC so a regression in
  // the describe() renderer itself fails here with a readable diff,
  // before it muddies a corpus snapshot.
  let dump = describe_sfc(
    r#"<template>
  <div v-if="x" class="a" :id="id" @click.prevent="go" v-bind:[k]="v" #slot>
    {{ name }}<img src="icon.png" alt=""><br/>
    <!-- note -->
    <svg><![CDATA[<circle/>]]></svg>
  </div>
</template>"#,
  );
  insta::assert_snapshot!("describe_smoke", dump);
}
