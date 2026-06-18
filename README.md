# Vue Scanner

A security-focused, AST-based static analyser for Vue.js Single File Components,
written in Rust. Inspired by `zizmor`, `Ruff`, `Clippy`, `Semgrep`, and `CodeQL`.

Vue Scanner is **not** an ESLint plugin. It parses each `.vue` file with its own
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
  token storage, missing `sandbox` on `iframe`.
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

The binary is at `target/release/vue-scanner`.

## Usage

### Scan a single file

```bash
vue-scanner src/components/MyComponent.vue
```

### Scan a directory

```bash
vue-scanner src/
```

This recursively scans all `.vue` files (respecting `.gitignore`).

### List available rules

```bash
vue-scanner --list
```

### Run specific rules

```bash
vue-scanner --rules no-v-html,no-dynamic-bind-src src/
vue-scanner --rules vue/security/no-v-html src/
```

You can mix short names and stable ids.

### Filter by category or severity

```bash
vue-scanner --category security src/
vue-scanner --min-severity high src/
```

### Output formats

```bash
# Pretty (default) - coloured diagnostics
vue-scanner src/

# JSON - one structured record per finding
vue-scanner --format json src/

# SARIF 2.1.0 - GitHub Code Scanning / GitLab
vue-scanner --format sarif src/ > results.sarif

# Minimal - one line per violation
vue-scanner --format minimal src/
```

### CI integration

Fail with exit code 1 if any violation is found:

```bash
vue-scanner --deny-warnings src/
```

Or only on at least `high` severity:

```bash
vue-scanner --min-severity high --deny-warnings src/
```

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
