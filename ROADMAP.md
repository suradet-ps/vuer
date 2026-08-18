# Vuer Roadmap

This roadmap tracks Vuer from its current working scaffold toward a first
public, production-grade release (v1.0.0) and beyond. It follows the
architecture, goals, and constraints set out in
[README.md](README.md), [AGENT.md](AGENT.md), and the `docs/` reference.

Vuer is a security-focused, **AST-based static analyser** for Vue.js Single
File Components (`.vue`), written in Rust. It is not an ESLint plugin: it
parses each `.vue` file with its own template parser and `oxc_parser` for the
script block, then runs every enabled rule against the resulting AST.

Nothing here is claimed to ship until it is verified by tests and, where
relevant, by CI on every tier (see Phase 9 and below). The bar is borrowed
from mature SAST tools (`zizmor`, `Ruff`, `Semgrep`, `CodeQL`): low false
positives, low false negatives, actionable remediation, and stable machine
output (SARIF) for CI.

## Where Vuer ends up (the "end of the road")

Vuer's terminal state is a **self-contained, dependency-light, cross-platform
static analysis engine and editor-tooling layer for Vue projects**, trusted in
CI and in-editor, with these properties:

1. **Accurate by construction.** A real Vue template/style parser (not a
   hand-rolled scanner for block boundaries only), plus a taint/control-flow
   aware script analyser on top of `oxc`, so findings are structural, not
   textual. Zero `unwrap()`/`panic!()` in production code (already true).
2. **Rule catalogue that covers the declared categories.** Today only
   `security` and `best-practice` have rules; `performance`,
   `accessibility`, and `architecture` are declared in `Category` and the
   CLI filter but empty. These must be populated, or the empty categories
   removed with a documented rationale (Phase 4).
3. **Automation that earns trust.** Autofix for safe, unambiguous findings
   (`v-html` → `v-text`, missing `:key`, etc.), always behind an explicit
   `--fix`, never silent.
4. **First-class CI and editor integrations.** SARIF (done) plus a published
   GitHub Action, pre-commit hook docs, and an LSP server driving
   inline diagnostics in VS Code / Neovim / JetBrains.
5. **Reproducible, audited, well-governed.** Reproducible builds, a clean
   dependency tree (`cargo-audit` / `cargo-deny` green), fuzz targets for the
   parser and the rule engine, and a release pipeline that publishes binaries
   + checksums for Linux/macOS/Windows.
6. **Performance budgeted, not just fast.** A criterion benchmark harness and
   a CI gate enforcing startup, per-file, and binary-size budgets.

The phases below are ordered so that each one leaves the tree in a buildable,
tested state. "Done" means the items are implemented **and** covered by the
CI gates in Phase 9.

---

## Phase 0: Foundation (done)

- [x] Cargo package `vuer` (edition 2024, MSRV pinned to 1.97.0 to match
      `oxc` 0.136's requirement; see `Cargo.toml` header comment)
- [x] CLI via `clap` (derive): paths, `--rules`, `--format`, `--list`,
      `--deny-warnings`, `--no-ignores`, `--no-config`, `--category`,
      `--min-severity`
- [x] Diagnostic stack: `miette` (fancy) + `thiserror`, rustc-style
      `error[rule-id]` output via `annotate-snippets`
- [x] SFC extraction: native block-boundary scanner splitting
      `<template>` / `<script>` / `<style>` with byte-accurate offsets
      (`src/parser/mod.rs`)
- [x] Native recursive-descent template parser producing `TemplateRoot`
      (`src/parser/template/`)
- [x] Script parsing via `oxc_parser` + arena (`src/parser/script.rs`)
- [x] Rule trait + `RuleRegistry` (`src/rules/mod.rs`); 15 rules across
      `security` and `best-practice` (26 since Phase 3)
- [x] Output formats: pretty, JSON, minimal, SARIF 2.1.0
      (`src/report/`)
- [x] Inline suppression: `vuer-ignore[...]` / `vuer: ignore[...]` with
      `--no-ignores` override (`src/suppression.rs`)
- [x] Config discovery: `.vuerc.yml` / `vuer.yml`, strict unknown-key
      handling, CLI layers on top (`src/config.rs`)
- [x] Parallel scan: `ignore` walker + `rayon` per-file fan-out
      (`src/scanner.rs`)
- [x] CI: `fmt --check`, `clippy -D warnings`, `cargo test --all-features`
      on ubuntu + macOS (` .github/workflows/ci.yml`)
- [x] Docs: README, AGENT.md, `docs/installation.md`, `docs/usage.md`,
      `docs/audits.md` (per-rule reference)

---

## Phase 1: Correctness & Parser Hardening (the accuracy floor)

The template parser is currently a hand-rolled recursive-descent parser. It
must be proven correct against real-world Vue before we trust it for security
findings, because a parser that silently mis-reads a node hides findings
(false negatives) or fabricates them (false positives).

- [x] **Template parser conformance suite.** A fixture corpus of real Vue
      components (Vue 3 docs examples, Nuxt UI, Element Plus, PrimeVue
      snippets — vendored under `tests/fixtures/templates/`, MIT/Apache
      compatible) that must parse without panic and produce a `TemplateRoot`
      whose element/attribute tree matches an expected structural snapshot.
      Implemented with an original corpus modelled on Vue 3 patterns
      (login form, product card, data table, SVG, modal, nav menu, settings
      form); each fixture must parse with zero errors and matches a
      committed insta snapshot (`tests/conformance.rs`).
- [x] **Edge cases enumerated and tested:** `<template>` with multiple root
      nodes (Vue 3 fragments), `<slot>`/`v-slot`, `v-bind` dynamic argument
      (`v-bind:[key]`), `v-on` modifiers, self-closing custom elements,
      `<component :is>` and `<Teleport>`/`<Transition>`/`<Suspense>`,
      interpolation with filters removed in Vue 3, whitespace control
      (`v-pre`, `v-once`, `v-cloak`), HTML entities, comments, and CDATA
      in `<svg>`/`<math>` foreign content.
      Implemented as a dedicated suite (`tests/edge_cases.rs`) plus an
      adversarial corpus that must terminate without panicking. The
      hardening exposed and fixed real bugs: infinite loops on stray
      closing tags, CDATA hanging the text lexer, `v-pre` subtrees parsed
      as interpolation, mismatched closing tags silently accepted, spans
      that included `}}`/`]`, and a block extractor that truncated the
      template at a nested `<template v-if>` element.
- [x] **`TemplateError` surfaced, not swallowed.** Non-fatal parse errors are
      already collected in `ScanContext::template_errors`; rules and the CLI
      summary must *report* them (count malformed files, warn the user) so a
      parse failure degrades to "this file needs review" instead of "this file
      is clean."
      Implemented: `Scanner` returns a `ScanReport` with `ParseIssue`s; the
      CLI prints per-error warnings (file, byte offset, message) on stderr
      and a summary line; `--deny-warnings` fails on malformed files.
- [x] **No `unwrap()`/`panic!()` in the parser** outside `#[cfg(test)]`.
      Malformed input is a typed `TemplateError`, never a crash. Verify with
      a `grep`/lint gate and an explicit fuzz seed corpus (Phase 8).
      Implemented: CI step greps `src/parser/` and fails on any production
      match; the adversarial corpus in `tests/edge_cases.rs` is the seed
      list for the Phase 8 fuzz targets.
- [x] **Offset integrity test.** For every parsed node, the reported span
      resolves to the exact source bytes in the original `.vue` file, not the
      trimmed block. Add a property test that re-slices the source by the
      reported span and asserts it equals the node's text.
      Implemented: `tests/offset_integrity.rs` walks every node over the
      conformance corpus, a canonical corpus, and a generated corpus at two
      base offsets, asserting slice == node text; also a rule-level spot
      check that diagnostics land on the AST spans.
- [x] **`oxc` upgrade discipline.** Bumping `oxc` re-checks the MSRV pin in
      `Cargo.toml` and reviews the `oxc_*` breaking changes. Documented as
      part of the release checklist (Phase 10/11).
      Implemented: `docs/upgrading.md` is the bump checklist (MSRV re-pin,
      version-cohort coherence, full gate + snapshot review, changelog note).
- [x] **Style block handling.** `BlockKind::Style` is currently extracted but
      unused. Decide scope: at minimum, emit a structural warning for risky
      patterns (e.g. `expression(...)` in scoped styles is a non-issue, but
      `v-html`-like CSS injection via `:deep()` dynamic values deserves a
      documented "out of scope" note rather than silent ignoring). Make the
      extractor's `Style` arm either used or explicitly `allow(dead_code)`
      with a rationale comment (already half-done).
      Implemented: the extractor collects every `<style>` block into
      `ScanContext::style_blocks` (the arm is used); CSS analysis including
      `:deep()` injection is documented out of scope for v1 in the README's
      "Scope: `<style>` blocks" section.

---

## Phase 2: Rule Engine Depth — Semantic Analysis

All current rules are **syntactic**: they match a directive, a call name, or
an attribute and flag it. A real SAST tool reasons about *data flow*.

- [x] **Taint tracking for the script block (Phase 2 core).** Build a
      lightweight taint analysis on top of the `oxc` AST:
      - Sources: route params (`useRoute().params`, `$route.query`),
        props (`defineProps`), `ref()`/`reactive()` seeded from external
        input, `fetch`/`axios` responses, `localStorage.getItem`,
        `window.location`, `event` payloads.
      - Sinks: `v-html`-bound expressions, `innerHTML`, `document.write`,
        `eval`/dynamic `Function`, `location` writes, `postMessage`,
        `window.open`, dynamic `:src`/`:href` bindings, `dangerouslySetInnerHTML`
        (when Vue is used with React-style renderers).
      - Propagators: string concat, template literals, `.map`/`.filter`
        over tainted arrays, Vue `computed`/`ref` assignment.
      - Sanitizers: calls matching `DOMPurify.sanitize`, `escapeHtml`,
        framework-safe interpolation. A tainted value that passes through a
        recognized sanitizer is downgraded (and the sanitizer call is reported
        as the "why" so the user can verify it).
      - This upgrades `no-v-html`, `no-inner-html`, `no-dangerous-url`,
        `no-dynamic-bind-src`, `no-open-redirect` from "this pattern exists"
        to "this pattern carries untrusted data," *dramatically* cutting false
        positives while keeping zero false negatives on the unsafe path.
- [x] **Inter-procedural awareness (bounded).** Within a single `<script>`
      block, follow taint through local function calls and component `emit`/
      `expose`. Cross-file analysis (imports, mixins, composables) is
      explicitly deferred to Phase 6 with a documented scope boundary.
- [x] **Re-classify existing rules under taint.** Each script rule gains a
      `TaintKind` (source/sink/flow) and the rule engine reports *flow paths*
      in the diagnostic `help`, e.g. "taint from `useRoute().query.id`
      reaches `v-html` at line 12." This is what makes Vuer's output
      actionable rather than alarming.
- [x] **Determinism guarantee.** Taint results are order-independent and
      stable across runs (the engine already forbids global mutable state).
      Property test: scanning the same file N times yields byte-identical JSON.
- [x] **`Rule` trait extension without breaking callers.** Add an optional
      `fn kind(&self) -> RuleKind` and a `flow_paths` accessor on the
      diagnostic; old rules default to `Syntactic`. `scanner.rs` and the
      report layer consume the new fields only when present.

      Implemented as `src/taint/` (see its module docs for the full model
      and documented boundaries). Sources, propagators, and sanitizers are
      implemented per the list; `no-dangerous-url` is intentionally kept
      syntactic because the dangerous pattern there *is* the literal
      scheme (documented in `docs/audits.md`). Sinks are detected by the
      (now taint-gated) rules; the engine exposes `status_at`/`flow_at`
      per expression span.
      Implemented: local function calls propagate taint when a tainted
      argument reaches a parameter the function's return depends on, or
      when the body returns a tainted closure value (recursion guarded).
      `emit`/`expose` payloads and cross-file imports are documented
      out of scope (Phase 6).
      Implemented: taint-gated rules report `= note: taint from <source>
      reaches <sink> via <ids>` in pretty output and structured `flow`
      arrays in JSON; `RuleKind::Taint` marks the re-classified rules.
      Implemented: `tests/determinism.rs` (byte-identical JSON/SARIF across
      repeated binary runs over the fixture corpus) plus a per-run unit test
      asserting identical span facts.
      Implemented: `Rule::kind()` defaults to `Syntactic`; `Rule::check`
      returns `Vec<Finding>` (diagnostic + optional `Vec<FlowPath>`);
      non-taint rules return `flow: None` and the report layers skip it.
---

## Phase 3: Fill the Declared Categories

`Category` already declares `Performance`, `Accessibility`, and
`Architecture`, and the CLI `--category` filter already accepts them — but no
rule implements them. Either populate them or remove them with a rationale.

- [x] **`performance` rules:**
  - `no-v-if-with-v-for` — Vue 3 forbids using `v-if` and `v-for` on the
    same element; flag and suggest computed filtering.
  - `no-deep-watch-without-handler` — `watch(src, cb, { deep: true })`
    without an explicit handler object / without `{ once }` where applicable.
  - `no-reactive-in-v-for` — reactive object creation inside `v-for`
    bodies (loop statements and array-iteration callbacks).
  - `no-large-list-without-virtualization` — heuristic: `v-for` over a
    variable whose name implies a large/remote collection without a known
    virtual scroll wrapper (low-severity, best-effort, documented as
    heuristic).
      Implemented as `vue/performance/*` (4 rules) with unit + integration
      coverage; the large-list name list is curated (generic names like
      `items` are not flagged) and the heuristic is documented in
      `docs/audits.md`.
- [x] **`accessibility` rules:**
  - `no-img-without-alt` — `<img>` without `alt` (template walk).
  - `no-click-without-role-keyboard` — `@click` on a non-interactive element
    without `role` + `@keydown`/keyboard handler.
  - `no-form-without-label` — input/select/textarea without an associated
    `<label>` or `aria-label`.
  - `no-button-without-type` — `<button>` without explicit `type` (defaults to
    `submit`).
      Implemented as `vue/accessibility/*` (4 rules); `no-form-without-label`
      resolves `<label for>` associations and wrapping `<label>`s within the
      template, and bound/unprovable attribute forms are accepted to keep the
      false-positive rate low.
- [x] **`architecture` rules (conservative):**
  - `no-side-effect-in-computed` — assignments / async / `watch`-like side
    effects inside `computed(() => ...)`.
  - `no-mutation-of-props` — writing to a `defineProps` destructured value or
    `props.x = ...`.
  - `no-async-setup-without-error-boundary` — `async setup()` without a
    sibling `<Suspense>` (heuristic, low-severity).
      Implemented as `vue/architecture/*` (3 rules) with documented scope
      boundaries per rule (Options API `computed:`/`this.x` forms deferred;
      nested function bodies in getters not descended into).
- [x] **Decision gate:**
      Met with all three categories populated at a meaningful rule count
      (4 + 4 + 3) and per-rule low-false-positive boundaries documented in
      `docs/audits.md`; the CLI `--category` filter is covered by
      integration tests for each new category.

---

## Phase 4: Autofix

Findings that have one unambiguous safe rewrite should be fixable, never
silently. Everything is behind `--fix`; `--dry-run` prints the diff and exits
0.

- [ ] **Safe, single-rewrite fixes:**
  - `no-v-html` → `v-text` (only when the binding is plain text; refuse if it
    contains HTML tags, and say so).
  - `v-for-missing-key` → insert `:key="item.id"` using the item identifier
    heuristically (refuse if no obvious key; report instead).
  - `no-button-without-type` → `type="button"`.
  - `no-inline-style` → move the style to a `class` stub (best-effort,
    opt-in only).
- [ ] **Fix application model.** Fixes are computed against absolute byte
      spans and applied with non-overlapping interval merging; a fix that
      would overlap another finding is skipped (never silently truncates the
      file). `--fix` writes only when every fix is conflict-free.
- [ ] **`--fix` respects suppression and config.** Ignored findings are not
      auto-fixed. A dry run shows what *would* change.
- [ ] **Tests.** Snapshot tests per fixable rule: input → fixed output →
      re-scan of the fixed file yields zero findings for that rule.

---

## Phase 5: Editor & Integrations

CI output is necessary but not sufficient; developers want findings in-editor.

- [ ] **LSP server (`vuer lsp`).** `tower-lsp` based: `textDocument/diagnostic`
      (pull model), `hover` showing the rule's help text, `codeAction` for the
      autofixes from Phase 4. One binary, subcommand-gated, no extra deps in
      the default build unless feature-flagged.
- [ ] **VS Code extension (separate repo, thin).** Talks to the `vuer` LSP
      binary; ships the binary path resolution and a `vuer.path` setting.
      Keep the extension minimal; all logic stays in the Rust binary.
- [ ] **Neovim / JetBrains docs.** Document wiring `vuer lsp` into
      `nvim-lspconfig` and the JetBrains LSP-over-stdio path, plus a
      null-ls/diagnostic-langsrv pattern for the interim.
- [ ] **Pre-commit hook.** A `hooks:` snippet for `.pre-commit-config.yaml`
      invoking `vuer --format minimal --deny-warnings` (fails the commit on
      high/critical by default, configurable).
- [ ] **Published GitHub Action.** `vuer/action` (or a `uses:` shim in this
      repo) that installs the release binary and runs `vuer` against a path,
      uploading SARIF to Code Scanning. Reuses the release artifacts from
      Phase 11.

---

## Phase 6: Cross-File & Project-Level Analysis

Phase 2 was intra-file. Real Vue apps spread risk across files.

- [ ] **Composable/import resolution.** Follow `import`/`export` to resolve
      taint through local composables and mixins within the scanned root.
      Bounded to the files under the scan path (never reads outside it).
- [ ] **`defineProps` / `defineEmits` schema.** Propagate prop types so a
      tainted prop at a call site is traced to its `defineProps` origin.
- [ ] **Multi-file cache.** Reuse parsed `oxc` ASTs across files in one scan
      so large monorepos do not re-parse shared modules (rayon already fans
      out per file; add an arena/parse cache keyed by canonical path).
- [ ] **Scope boundary (documented).** Cross-repo, npm-dependency internals,
      and Vue compiler transform output are out of scope; findings stop at the
      project boundary. State this in README's "Accuracy" section.

---

## Phase 7: Configuration & Extensibility Depth

- [ ] **Rule severity override in config.** `.vuerc.yml` gains
      `severity: { "no-v-html": critical }` and `inherit: path` for
      cascading config through a monorepo (walk-up discovery already exists;
      extend it to merge rather than first-match).
- [ ] **Baseline / triage mode.** `vuer baseline --write baseline.json`
      records current findings; subsequent runs can `--diff-against
      baseline.json` to only report *new* findings (supports "fail CI on new
      issues, not the whole backlog").
- [ ] **Ignore paths in config.** `ignore: [ "**/*.stories.vue", "node_modules" ]`
      layered with `.gitignore` (the `ignore` crate already handles
      gitignore; add explicit user excludes).
- [ ] **Exit-code contract (documented & tested).** 0 = clean, 1 = findings
      under `--deny-warnings` / scan error, 2 = usage/input error, 3 =
      internal/engine error. Currently `main.rs` uses 0/1 inconsistently for
      input vs internal; clarify and cover with `assert_cmd` tests.
- [ ] **Stable JSON schema.** Lock the `JsonViolation` shape behind a
      `schema_version` field so downstream consumers can detect drift; add a
      JSON Schema file under `docs/`.

---

## Phase 8: Security & Robustness Hardening

- [ ] **`unsafe` audit.** Inventory every `unsafe` (currently none in
      production paths; `regex`/`oxc` may pull some transitively — document
      each, justify, isolate). Zero unjustified `unsafe`.
- [ ] **Fuzz targets (`cargo-fuzz`):**
  - *template parser* — feed arbitrary bytes; must never panic, only produce
    `TemplateError`.
  - *script/oxc wrapper* — malformed/weird JS/TS; must not crash the engine.
  - *rule engine* — synthetic `ScanContext`s with adversarial ASTs.
  - *config parser* — malformed YAML; must error, never panic.
- [ ] **Property-based tests (`proptest` / `rstest`):** offset integrity
      (Phase 1), determinism (Phase 2), suppression idempotence, config
      merge laws.
- [ ] **`cargo-audit` + `cargo-deny` in CI.** License allowlist (MIT/Apache/
      compatible), advisory gate, bans on known-bad crates. Add as a CI job
      next to `clippy`.
- [ ] **Reproducible build check.** Same input tree → byte-identical release
      binary (verify `SOURCE_DATE_EPOCH` / stripped paths; `oxc` may embed
      paths — audit and neutralize).
- [ ] **Least-privilege CI.** The existing `ci.yml` already pins
      `permissions: contents: read` and uses pinned action SHAs — keep this
      discipline and add `zizmor` self-scanning of the workflow as a job.

---

## Phase 9: Performance Hardening (budgeted, not just fast)

- [ ] **Criterion harness.** Benchmarks for: cold startup, per-file parse +
      rule time on a fixture corpus, and full-repo scan time vs. LOC.
- [ ] **Budgets enforced in CI:**
  - startup `<50ms` (cold, no file scanned),
  - per-file `<2ms` median on a representative corpus (excluding first-run
    parse warmup),
  - memory `<100MB` for a 10k-file monorepo scan,
  - binary `<15MB` release (stripped, single static-ish artifact).
- [ ] **Profiling passes.** `cargo flamegraph` / `perf` on a large Vue
      monorepo fixture; eliminate per-file allocations in the hot path
      (the engine already prefers borrowed `&str` and arena allocation —
      verify and extend).
- [ ] **CI gate.** A `bench` job runs the criterion suite and fails if any
      budget regresses beyond a small tolerance (e.g. 10%), catching
      performance cliffs before release.

---

## Phase 10: Release Engineering

- [ ] **Release workflow (`release.yml`).** Tag-triggered: build release
      binaries for `x86_64-unknown-linux-gnu` (musl too),
      `x86_64-apple-darwin`, `aarch64-apple-darwin` (Apple Silicon),
      `x86_64-pc-windows-msvc`, plus `aarch64-unknown-linux-gnu` for ARM
      servers. Upload to GitHub Releases with `SHA256SUMS.txt` and a signed
      checksum where the runner allows.
- [ ] **Windows CI.** Add `windows-latest` to the `ci.yml` matrix (currently
      ubuntu + macOS only) — confirms `ignore`/`rayon`/path handling are
      platform-clean, since Windows path separators and `.gitignore` semantics
      differ.
- [ ] **`cargo install` + crates.io.** Verified publish path; `Cargo.toml`
      metadata (`repository`, `homepage`, `keywords`, `categories`)
      completed. Version follows SemVer; MSRV bump is a minor-or-major event
      per Phase 1's `oxc` discipline.
- [ ] **Homebrew / Scoop / arch AUR shims (optional).** Community-maintained;
      the release artifacts are the source of truth.
- [x] **Changelog & versioning policy.** `CHANGELOG.md` (Keep a Changelog),
      and a documented rule-id stability promise: a `vue/...` rule id is never
      reused or silently re-severed. Removing a rule is a major-version event
      announced in the changelog.
      Implemented at the v0.2.0 release: `CHANGELOG.md` covers 0.2.0 (taint
      engine, taint-gated rules, flow paths, determinism) with the 0.1.0
      baseline, and records the rule-id stability promise in its header.

---

## Phase 11: First Public Release (v1.0.0)

- [ ] **Rule catalogue frozen & documented.** Every shipped rule has a section
      in `docs/audits.md` with vulnerable/safe examples and remediation, plus
      a stability marker (`stable` for v1 rules).
- [ ] **Golden corpus CI gate.** A fixture set of known-good and known-bad
      components; the suite fails if a rule's behavior changes (catches
      accidental false-negative regressions — the SAST equivalent of
      MenSung's "zero false negative" gate).
- [ ] **Docs complete.** Installation (crates.io, binaries, editor, CI,
      pre-commit), Usage (every flag, format, suppression), Audits (per rule),
      and an Architecture page describing the parser → AST → rule → report
      pipeline and the taint model from Phase 2.
- [ ] **`v1.0.0` tag + `release.yml` run** publishes Linux/macOS/Windows
      binaries, `SHA256SUMS.txt`, and the GitHub Action reference.
- [ ] **Governance docs.** `CODE_OF_CONDUCT.md`, `SECURITY.md` (how to report
      a false positive / missed finding), `CONTRIBUTING.md` (rule authoring
      guide referencing AGENT.md), `LICENSE` (MIT, already set).
- [ ] **False-positive triage channel.** A documented issue template
      ("false positive" / "missed vulnerability") so the accuracy floor
      (Phase 1/2) is community-maintained post-release.

---

## Future / Ecosystem

- [ ] **Cross-file taint across npm dependencies** (after Phase 6) via an
      optional, offline type-stub index — explicitly opt-in, never default.
- [ ] **TypeScript-aware narrowing.** Use `oxc`'s TS type info to reduce
      false positives (e.g. "this prop is `string` from a trusted config,
      not user input").
- [ ] **SARIF 2.1.0 advanced features.** `codeFlows` for taint paths,
      `relatedLocations` for sanitizer calls, `baseline` integration.
- [ ] **Watch mode (`vuer watch`).** Re-scan changed files via `notify`,
      emitting incremental diagnostics for editor/live use.
- [ ] **HTML report.** A standalone `vuer report --html` for PR comments and
      dashboards (distinct from SARIF, which stays machine-only).
- [ ] **Plugin rule API.** A stable `#[vuer_rule]` macro + dynamic loading
      story (carefully scoped — security rules must remain auditable; external
      plugins are a major-version consideration, not v1).
- [ ] **Additional frameworks' template dialects** (e.g. Vue 2 legacy, or
      Petite-Vue) behind feature flags, only if the accuracy bar from Phase 1
      can be met for each.
- [ ] **Localization of diagnostics** for non-English-speaking teams, kept
      behind config so the default stays English and machine output (JSON/
      SARIF) is locale-invariant.

---

## How this roadmap maps to the current tree

| Current file | Roadmap phase |
|---|---|
| `src/parser/template/` | Phase 1 (conformance), Phase 2 (taint sources in template) |
| `src/parser/script.rs` (`oxc`) | Phase 2 (taint on script AST), Phase 6 (imports) |
| `src/rules/` (26 rules) | Phase 2 (taint upgrade), Phase 3 (new categories, done), Phase 4 (fixes) |
| `src/report/sarif.rs` | Phase 5 (LSP hover), Future (codeFlows) |
| `src/config.rs` | Phase 7 (overrides, baseline, ignore) |
| `src/scanner.rs` | Phase 6 (parse cache), Phase 7 (exit codes), Phase 9 (budgets) |
| `.github/workflows/ci.yml` | Phase 8 (audit/deny/fuzz), Phase 9 (bench), Phase 10 (Windows) |
| `docs/audits.md` | Phase 3/11 (per-category docs) |
| `AGENT.md` | Phase 11 (CONTRIBUTING rule-authoring reference) |
