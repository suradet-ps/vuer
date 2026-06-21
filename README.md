# Vuer

A security-focused, AST-based static analyser for Vue.js Single File Components,
written in Rust. Inspired by `zizmor`, `Ruff`, `Clippy`, `Semgrep`, and `CodeQL`.

Vuer is **not** an ESLint plugin. It parses each `.vue` file with its own
template parser and `oxc_parser` for the script block, then runs every enabled
rule against the resulting AST.

## Goals

1. **Accuracy over convenience** - low false positives, low false negatives,
   actionable remediation.
2. **AST analysis over string matching** - rules consume structure, not text.
3. **Performance over abstraction** - arena allocation, borrowed data, zero-copy
   parsing where possible.
4. **Developer experience over cleverness** - clear diagnostics, stable rule
   ids, and SARIF output for CI integration.

## Features

- **Security rules**: `v-html`, `innerHTML`, `document.write`, `eval`,
  `new Function`, dangerous URL schemes, open-redirect, `localStorage`
  token storage, missing `sandbox` on `iframe`, `postMessage` with
  wildcard `targetOrigin`, `window.open` with `_blank` and no `noopener`,
  `fetch` without an `AbortSignal`.
- **Vue best practices**: missing `:key` on `v-for`, inline styles,
  `watch` callbacks that may leak.
- **Severity model**: `Critical` / `High` / `Medium` / `Low` / `Info`,
  with a clean SARIF mapping.
- **Output formats**: pretty, JSON, minimal, **SARIF 2.1.0**
  (GitHub Code Scanning / GitLab Security Reports ready).
- **Category and severity filters** to scope runs to one area or to
  only fail the build on high-severity findings.
- **Fast**: Rust-powered, no runtime overhead, `.gitignore` aware.

## Installation

```bash
cargo install --path .
```

Or build from source:

```bash
cargo build --release
```

The binary is at `target/release/vuer`.

## Usage

### Scan a single file

```bash
vuer src/components/MyComponent.vue
```

### Scan a directory

```bash
vuer src/
```

This recursively scans all `.vue` files (respecting `.gitignore`).

### List available rules

```bash
vuer --list
```

### Run specific rules

```bash
vuer --rules no-v-html,no-dynamic-bind-src src/
vuer --rules vue/security/no-v-html src/
```

You can mix short names and stable ids.

### Filter by category or severity

```bash
vuer --category security src/
vuer --min-severity high src/
```

### Output formats

```bash
# Pretty (default) - coloured diagnostics
vuer src/

# JSON - one structured record per finding
vuer --format json src/

# SARIF 2.1.0 - GitHub Code Scanning / GitLab
vuer --format sarif src/ > results.sarif

# Minimal - one line per violation
vuer --format minimal src/
```

### CI integration

Fail with exit code 1 if any violation is found:

```bash
vuer --deny-warnings src/
```

Or only on at least `high` severity:

```bash
vuer --min-severity high --deny-warnings src/
```

### Suppressing individual findings

Use a `vuer-ignore[...]` comment on the same line (or the line above) the
finding to silence it. Both the short rule name (`no-v-html`) and the full
stable id (`vue/security/no-v-html`) are accepted. The colon form
(`vuer: ignore[...]`) is also recognised.

```vue
<template>
  <div v-html="trusted">accepted</div>
  <!-- vuer-ignore[no-v-html] -->
  <div v-html="trusted">silenced by the previous-line comment</div>
</template>

<script setup>
el.innerHTML = userInput  // vuer-ignore[no-inner-html]
</script>
```

Use `--no-ignores` to disable every inline suppression and report what
the linter would otherwise silence. This is the right flag for CI runs
that want to see the *raw* signal.

## Output

The pretty output is rustc-style: each finding is a coloured
`error[rule-id]` block with an `--> file:line:col` header, a snippet with
carets under the violation, and a `= help:` line with the remediation
advice. The summary at the bottom counts findings by severity, each
coloured to match the finding (critical = magenta, high = red, medium =
yellow, low = cyan, info = green).

```text
error[vue/security/no-v-html]: Unsafe `v-html` directive renders untrusted HTML
 --> src/components/Post.vue:8:10
  |
8 |     <div v-html="user.bio">Bio</div>
  |          ^^^^^^^^^^^^^^^^^^^ here
  |
  = help: Rendering untrusted HTML can execute arbitrary JavaScript. Sanitise the input
          with DOMPurify (or an equivalent library), or use `v-text` / `{{ }}` interpolation.

13 violations: 3 critical, 7 high, 2 medium, 1 low
```

Colours are auto-detected from the terminal. They are stripped when
output is piped to a file, when stdout is not a TTY, or when
`NO_COLOR=1` is set in the environment. Set `FORCE_COLOR=1` to force
them on for CI logs.

## Configuration

Drop a `.vuerc.yml` (or `vuer.yml`) at the project root to set
project-wide defaults. The first one found walking up from the scan
path is loaded.

```yaml
# .vuerc.yml — every field is optional.

# Disable rules by short name or full stable id.
disable:
  - no-v-html
  - vue/security/no-eval

# Only show findings at this severity or higher.
# Allowed: info, low, medium, high, critical
min-severity: medium

# Only show findings whose category is in this list.
# Allowed: security, best-practice, performance, accessibility, architecture
category:
  - security
  - best-practice
```

CLI flags layer on top of the config: `--rules` is an enable-list
that further narrows the result, `--min-severity` and `--category`
override the config when set, and `--no-config` skips discovery
entirely (handy for hermetic CI runs).

Unknown keys are rejected (`deny_unknown_fields`), so a typo like
`min-sev: high` will print a parse warning and fall back to the
default config. The run is never blocked by a broken config file.

## Performance

`vuer` walks the directory tree single-threaded (the work is just path
filtering + `.gitignore` checks) and then fans out the per-file
parsing across the rayon thread pool. On a large Vue monorepo this
gives a near-linear speedup with the number of cores.

## Documentation

Full reference documentation lives under `docs/`:

* [Installation](docs/installation.md) — install via crates.io, GitHub,
  pre-built binaries, or from source; editor and CI integration.
* [Usage](docs/usage.md) — every CLI flag, output format, suppression
  mechanism, and recommended workflows.
* [Audits](docs/audits.md) — one section per rule, with vulnerable
  and safe examples plus remediation advice.

## Available rules

| Rule id | Severity | Category | Description |
|---------|----------|----------|-------------|
| `vue/security/no-v-html` | Critical | security | Disallow `v-html` directive |
| `vue/security/no-inner-html` | Critical | security | Disallow `el.innerHTML = ...` |
| `vue/security/no-document-write` | High | security | Disallow `document.write` / `writeln` |
| `vue/security/no-eval` | Critical | security | Disallow `eval`, `new Function`, string `setTimeout` |
| `vue/security/no-dangerous-url` | Critical | security | Disallow `javascript:` / `data:text/html` / `vbscript:` URLs |
| `vue/security/no-open-redirect` | High | security | Disallow `location.*` writes to dynamic values |
| `vue/security/no-unsafe-localstorage` | High | security | Disallow auth-looking values in `localStorage` |
| `vue/security/no-unsafe-iframe` | Medium | security | Disallow `<iframe>` without `sandbox` |
| `vue/security/no-dynamic-bind-src` | High | security | Disallow dynamic `:src` bindings |
| `vue/security/no-postmessage-wildcard` | High | security | Disallow `postMessage(..., '*')` |
| `vue/security/no-window-open-blank-noopener` | High | security | Require `noopener` on `window.open(..., '_blank', ...)` |
| `vue/security/no-fetch-without-timeout` | High | security | Require an `AbortSignal` on `fetch` |
| `vue/best-practice/no-inline-style` | Low | best-practice | Disallow inline `style` |
| `vue/best-practice/no-watch-with-callback` | Low | best-practice | Warn on `watch(src, cb)` without disposal |
| `vue/best-practice/v-for-missing-key` | Medium | best-practice | Require `:key` on `v-for` |

## Architecture

```
.vue file
    |
    v
SFC extraction (template / script / style)
    |
    +-- template  -> native recursive-descent parser -> TemplateRoot
    |                                                          |
    |                                                          v
    |                                                    visitor + rules
    |
    +-- script    -> oxc_parser (oxc_ast) -> Program
                                                            |
                                                            v
                                                      visitor + rules
```

Key design decisions:

- **No regex in any rule.** The only place strings are read is the SFC
  block extractor; from then on everything is structural.
- **No `unwrap()`, `expect()`, or `panic!()` in production code.** Errors
  in the SFC extractor and the parsers are surfaced alongside the parsed
  AST; rules that fail to apply skip the file and report zero violations.
- **All rules are independent and deterministic.** They take an
  immutable `ScanContext` and return a `Vec<Box<dyn Diagnostic>>`.
  Running the same file twice produces the same output.
- **Spans are absolute** - rules produce diagnostics pointing at the
  original file, not at the trimmed template body.

### Layout

```
src/
  main.rs               # CLI (clap)
  lib.rs                # module root
  context.rs            # ScanContext, ScriptLang
  scanner.rs            # file walking, Violation
  severity.rs           # Critical/High/Medium/Low/Info
  rule_id.rs            # stable string id
  parser/
    mod.rs              # SFC extraction
    template/
      ast.rs            # TemplateRoot data model
      parser.rs         # recursive-descent template parser
      mod.rs            # public re-exports
    script.rs           # oxc_parser wrapper + callee_path / is_call_named helpers
  rules/
    mod.rs              # Rule trait, Category, RuleRegistry
    no_v_html.rs
    no_inner_html.rs
    no_document_write.rs
    no_eval.rs
    no_dangerous_url.rs
    no_open_redirect.rs
    no_unsafe_localstorage.rs
    no_unsafe_iframe.rs
    no_dynamic_bind.rs
    no_inline_styles.rs
    no_watch_with_callback.rs
    v_for_missing_key.rs
  visitor/
    mod.rs              # walk / for_each_element
  report/
    mod.rs              # output formats
    sarif.rs            # SARIF 2.1.0 serializer
tests/
  integration.rs        # end-to-end tests against fixture files
  fixtures/             # clean / vulnerable Vue files
```

## Adding a new rule

1. Create `src/rules/your_rule.rs` with a diagnostic struct and a
   `Rule` impl.
2. Pick the `Category` and `Severity`.
3. Register the rule in `src/rules/mod.rs`.
4. Add the rule id to `rule_meta` in `src/report/sarif.rs` so the
   SARIF output picks up the description.
5. Add a clean, vulnerable, and edge-case fixture (or extend an
   existing one).
6. Add a unit test and, where useful, an integration test.

## Development

```bash
cargo build              # debug build
cargo build --release    # release build
cargo test               # unit + integration
cargo run -- --list      # see all rules
cargo run -- tests/      # scan the fixture files
```

## License

MIT
