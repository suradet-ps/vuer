# Changelog

All notable changes to Vuer are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Rule-id stability promise: a `vue/...` rule id is never reused or silently
re-severed. Removing a rule is a major-version event announced here.

## [Unreleased]

### Changed

- `no-window-open-blank-noopener` is now taint-gated: a provably clean
  URL (a hardcoded literal, or a value derived only from trusted data)
  is no longer reported — the reverse-tabnabbing surface requires an
  attacker-influenced URL. A URL carrying untrusted data is still
  reported at High, with the source→sink flow path in the diagnostic.
  This closes the remaining `window.open` sink from the Phase 2 list.
- `no-watch-with-callback` is now scope-aware: watchers created inside
  a component (`<script setup>` or Options API) are disposed
  automatically by Vue, so they are no longer reported. Only `watch`
  calls at **module scope** in a plain `<script>` block — the one place
  the watcher has no lifecycle to be torn down with — are flagged, with
  a corrected message and help text.
- **`oxc` bumped 0.136/0.143 → 0.144** — the whole cohort moves
  together (parser, allocator, ast, ast_visit, span, syntax,
  diagnostics), removing the mixed-generation lockfile. Breaking
  changes absorbed: `Expression::MetaProperty` split into
  `ImportMeta`/`NewTarget`, and `ArrowFunctionExpression.body` became
  the `ArrowFunctionBody` enum (`FunctionBody` | inherited expression)
  with `as_expression()` accessors. The conformance, edge-case,
  offset-integrity, and snapshot suites pass with zero diffs.
- **MSRV lowered 1.97 → 1.95** — `oxc` 0.144 requires rustc 1.95.0,
  which is now the highest minimum in the dependency tree; CI pins
  `dtolnay/rust-toolchain` 1.95.0 to match.

### Fixed

- Integration snapshot path filters now accept Windows separators and
  JSON-escaped `\\` separators, so the suite runs on Windows.

## [0.2.0] - 2026-08-12

### Added

- **Taint analysis engine** (`src/taint/`) — a single-pass, deterministic,
  intra-file analysis that annotates every script and template expression
  with its taint state:
  - sources: `localStorage`/`sessionStorage.getItem`, `fetch`/`axios`/
    `useFetch`, `useRoute()`/`$route`, `defineProps` props, Options API
    `props`/`data`/`computed`, `event`/`$event`, `window.location`,
    `location.search`/`hash`, `document.cookie`/`referrer`,
    `document.*` DOM reads, `FormData`/`URLSearchParams`;
  - propagators: assignment, concatenation, template literals, ternaries,
    member writes/reads, destructuring, `.map`/`.filter`/`.then`
    callbacks, `ref`/`computed`/`reactive`, and bounded inter-procedural
    flow through local function calls;
  - sanitizers: `DOMPurify.sanitize`, `sanitize`, `escapeHtml`,
    `htmlEscape`, `escape`, `xss` downgrade taint;
  - results exposed per expression span via `TaintResult::status_at` /
    `flow_at`.
- **Taint-gated rules** — `no-v-html`, `no-inner-html`,
  `no-dynamic-bind-src`, and `no-open-redirect` now report only when the
  matched pattern carries untrusted data, cutting false positives while
  keeping the unsafe path fully reported.
- **Flow paths in diagnostics** — pretty output shows
  `= note: taint from <source> reaches <sink> via <ids>`; JSON output
  gains a structured `flow` field; `--list` shows the rule kind
  (`taint`/`syntactic`).
- **`RuleKind`** on the `Rule` trait (defaults to `Syntactic`) and
  `Rule::check` returning `Vec<Finding>` (diagnostic + optional flows).
- **Determinism property suite** (`tests/determinism.rs`) — repeated
  scans produce byte-identical JSON/SARIF.

### Changed

- `no-dangerous-url` stays syntactic by design: the dangerous pattern is
  the literal `javascript:`/`data:`/`vbscript:` scheme itself (see
  `docs/audits.md`).
- Shared fixtures now seed realistic tainted sources; integration
  snapshots updated accordingly.

## [0.1.0] - 2026-06-21

### Added

- Initial release: SFC extraction, template parser, `oxc`-based script
  analysis, 15 rules across `security` and `best-practice`, pretty/JSON/
  minimal/SARIF output, inline suppression, config discovery, parallel
  scanning, Phase 1 parser-hardening suites (conformance corpus, edge
  cases, offset integrity).
