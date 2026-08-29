# Vuer

```
██╗   ██╗██╗   ██╗███████╗██████╗
██║   ██║██║   ██║██╔════╝██╔══██╗
██║   ██║██║   ██║█████╗  ██████╔╝
╚██╗ ██╔╝██║   ██║██╔══╝  ██╔══██╗
 ╚████╔╝ ╚██████╔╝███████╗██║  ██║
  ╚═══╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝
```

---

## ◆ PULSE

`v-html` looks like a feature until it looks like a CVE. Vuer is a
security-focused, AST-based static analyser for Vue Single File
Components, written in Rust - not an ESLint plugin, not a regex sweep.
It parses every `.vue` file with its own template parser and
`oxc_parser` for the script block, then asks the structure the
questions: does untrusted data reach `v-html`? Does `innerHTML` carry
user input? Did `fetch` forget its `AbortSignal`? Taint-aware rules
report flows - source to sink - and stay silent on provably clean
bindings. The analyser that reads your components like a compiler.

| Taint ▣ | 28 rules ▣ | SARIF ▣ | No regex ▣ |
|---|---|---|---|

*P0-P3 are sealed - foundation, parser correctness, the taint engine,
and the declared categories. Autofix, integrations, and v1.0 stand
open.*

> Built with Rust, inspired by zizmor, Ruff, Clippy, Semgrep, and
> CodeQL - structure over strings, accuracy over convenience.
>
> **suradet-ps**, artifact keeper

---

## ◆ IGNITION

One command, one binary.

```
⟫ cargo install --path .
⟫ vuer src/
```

Scan a file, a directory (`.gitignore`-aware), or the whole repo:

```
⟫ vuer --rules no-v-html,no-dynamic-bind-src src/
⟫ vuer --category security --min-severity high src/
⟫ vuer --format sarif src/ > results.sarif
⟫ vuer --deny-warnings src/      # fail CI on any finding
```

<details>
<summary>Configuration</summary>

A `.vuerc.yml` at the project root sets project-wide defaults:
`disable`, `min-severity`, and `category`. CLI flags layer on top;
`--no-config` skips discovery for hermetic CI runs. Unknown keys are
rejected with a warning - a broken config never blocks the run.

Findings are suppressed with `vuer-ignore[...]` comments, or surfaced
in full with `--no-ignores`.

</details>

---

## ◆ ANATOMY

One pipeline, four disciplines, zero regex in the rules.

- **Parses** - the SFC extractor splits template, script, and style;
  the template gets a native recursive-descent parser, the script
  block gets `oxc_parser`. From then on, everything is structural.
- **Taints** - one pass annotates every expression in the file with
  data-flow: sources (`localStorage`, `fetch`, `useRoute`, props,
  events) reach sinks (`v-html`, `innerHTML`, dynamic `:src`,
  `location` writes) - and the rule reports the flow, with lines, not
  just the pattern.
- **Judges** - 28 rules across five categories - security,
  best-practice, performance, accessibility, architecture - with a
  severity model from Critical to Info and a clean SARIF 2.1.0
  mapping for GitHub Code Scanning and GitLab.
- **Reports** - rustc-style pretty output with carets and `= help:`
  remediation, plus JSON, minimal, and SARIF formats; colors that
  respect TTY and `NO_COLOR`.
- **Degrades** - a parse failure means "needs review", never "clean";
  a rule that fails to apply skips the file and reports zero
  violations; there is no `unwrap()`, `expect()`, or `panic!()` in
  production code.
- **Stays honest** - spans are absolute, rules are deterministic, and
  an offset-integrity property test re-slices the source by every
  node's span to prove the parser never lies about position.

---

## ◆ RITUALS

**The core ceremony** - the pre-merge scan:

1. Run `vuer src/` locally. The pretty output shows each finding
   rustc-style: `error[rule-id]`, the caret, the help line.
2. Read the flows: "taint from `localStorage.getItem` reaches
   `v-html` via `userInput`" - the path is the lesson.
3. Fix, or suppress with a `vuer-ignore[no-v-html]` comment and a
   reason beside it.
4. In CI, run `--deny-warnings` - and `--no-ignores` when the raw
   signal must be seen.

**The ceremony of the flow** - a rule that names the source and the
sink is worth more than a rule that names the pattern. Taint-aware
rules cut false positives without losing the unsafe path.

**The ceremony of the clean page** - provably clean bindings are
silent. The analyser's restraint is a feature: when Vuer does not
complain, the structure has been read, not just matched.

---

## ◆ ECHOES

**Where this artifact is heading**

```
P0-P1 ▸ foundation, parser conformance + offset integrity ──────────── ▸ sealed
P2    ▸ taint engine: sources, propagation, flows ───────────────────── ▸ sealed
P3    ▸ declared categories: security, perf, a11y, architecture ─────── ▸ sealed
P4-P5 ▸ autofix, editor + CI integrations ────────────────────────────── ▸ open
P6-P9 ▸ cross-file analysis, config depth, hardening, budgets ────────── ▸ open
P10-P11 ▸ release engineering, v1.0.0 ────────────────────────────────── ▸ open
```

**Raising the artifact** - the rule audit trail lives in
`docs/audits.md`; installation and editor notes in `docs/installation.md`;
the `oxc` bump and MSRV discipline in `docs/upgrading.md`. Adding a
rule follows the documented ritual: rule module, registration, SARIF
meta, fixtures, tests. Open an issue first to discuss a change.

**Status** - CI gates fmt, clippy with `-D warnings`, tests, and the
parser's no-panic discipline on every push.
[Watch the gates](.github/workflows).

---

```
  ─────────────────────────────────────────
   A linter that reads structure
   sees what a regex can only guess.
  ─────────────────────────────────────────
```

MIT.