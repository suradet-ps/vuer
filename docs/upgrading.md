# Upgrading `oxc` (and the MSRV)

Vuer leans on `oxc` for script-block parsing (`oxc_parser` + `oxc_allocator` +
`oxc_ast` + `oxc_ast_visit` + `oxc_span`) and for diagnostics primitives
(`oxc_syntax`, `oxc_diagnostics`). The `oxc` crates are pre-1.0 and change
frequently; the renovate bot opens bump PRs for them automatically. This page
is the review checklist every such bump must go through (Phase 1 "oxc upgrade
discipline", enforced for every release in Phase 10/11).

## Why it matters

`oxc` 0.x releases routinely:

- raise the MSRV (each minor can require a newer rustc),
- rename or move AST nodes and visitor traits,
- change span types or arena APIs.

A silent bump can break the build in CI, or — worse — quietly change what the
script rules see, shifting the false-positive/false-negative floor that Phase 1
is meant to hold.

## The checklist

1. **Read the breaking-change notes.** The `oxc` repo keeps a
   [`CHANGELOG.md`](https://github.com/oxc-project/oxc/blob/main/crates/oxc_parser/CHANGELOG.md)
   per crate. Skim the diffs of the crates vuer uses (`oxc_parser`,
   `oxc_allocator`, `oxc_ast`, `oxc_ast_visit`, `oxc_span`, `oxc_syntax`,
   `oxc_diagnostics`) between the old and the new version. Note any change to
   `Span` (offset type, `SourceOffset`), `Allocator`, or the `visit` traits —
   those are the ones that touch vuer's code directly.
2. **Re-check the MSRV pin.** `Cargo.toml`'s `rust-version` must equal the
   highest MSRV in the dependency tree (currently `oxc` 0.136 → 1.97.0). If the
   new `oxc` needs a newer rustc, bump `rust-version` *in the same commit* and
   update the pinned toolchain in `.github/workflows/ci.yml` (the
   `dtolnay/rust-toolchain` step, currently 1.97.1). An MSRV bump is a
   minor-or-major version event for vuer (see the versioning policy in Phase 10).
3. **Keep the versions coherent.** The lockfile currently mixes two `oxc`
   generations (e.g. `oxc_parser` 0.136 with `oxc_syntax` 0.143). That works
   but is fragile: prefer a renovate PR that moves a whole cohort at once, and
   verify with `cargo tree -i oxc_parser` that no duplicate generations remain.
4. **Run the full gate locally before pushing:**
   ```bash
   cargo fmt --all -- --check
   cargo clippy --all-targets -- -D warnings
   cargo test --all-features
   ```
   The conformance suite (`tests/conformance.rs`), the edge-case suite
   (`tests/edge_cases.rs`) and the offset-integrity tests
   (`tests/offset_integrity.rs`) are the regression net: they must stay green
   with zero snapshot diffs. A snapshot diff on an `oxc` bump means the *script*
   analysis changed; review it consciously, never accept blindly.
5. **Run the binary on a real fixture.** `cargo run -- tests/fixtures/` and
   eyeball the JSON/SARIF output for span sanity.
6. **Note it in the changelog.** The release checklist (Phase 10/11) records
   every `oxc` bump with its MSRV consequence.

## MSRV policy

- `rust-version` in `Cargo.toml` is the contract; CI pins a concrete rustc
  (1.97.1) so builds are reproducible and match the declared floor.
- The header comment in `Cargo.toml` names the crate that sets the floor —
  keep it in sync with reality when the floor moves.
- `cargo +1.97.1 build` must succeed on every commit; a renovate bump that
  silently needs a newer compiler fails CI loudly, which is the point.
