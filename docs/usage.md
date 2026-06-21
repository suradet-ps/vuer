# Usage

This page covers every CLI flag `vuer` accepts and shows the
recommended workflows for common tasks.

## Synopsis

```text
vuer [OPTIONS] [PATHS]...
```

`vuer` requires at least one path (file or directory) unless
`--list` is passed. When a directory is given, `vuer` walks it
recursively, honouring `.gitignore` and `.git/exclude`.

## Quick start

Scan a single file:

```bash
vuer src/components/Post.vue
```

Scan a directory:

```bash
vuer src/
```

List the registered rules:

```bash
vuer --list
```

Pretty output is the default. For machine-readable output use
`--format json`, `--format sarif`, or `--format minimal`.

## CLI reference

### Input

| Flag | Effect |
|---|---|
| `[PATHS]...` | One or more `.vue` files or directories to scan. At least one is required unless `--list` is given. |
| `--list` | Print the list of registered rules and exit. No path is required. |
| `--no-ignores` | Disable every inline `// vuer-ignore[...]` / `<!-- vuer-ignore[...] -->` comment. Use this in CI to see what is currently being silenced. |
| `--no-config` | Skip discovery of `.vuerc.yml` / `vuer.yml`. The CLI flags alone drive the run. |
| `-r, --rules <LIST>` | Comma-separated list of rule ids (short name or full id) to run. When unset, every registered rule runs. |
| `-c, --category <LIST>` | Comma-separated list of categories to include. Allowed: `security`, `best-practice`, `performance`, `accessibility`, `architecture`. |

### Filtering

| Flag | Effect |
|---|---|
| `--min-severity <LEVEL>` | Only show findings at this severity or higher. Allowed: `info`, `low`, `medium`, `high`, `critical`. |
| `--deny-warnings` | Exit with code 1 when at least one *actionable* finding is produced (suppressed findings do not count). |

### Output

| Flag | Effect |
|---|---|
| `-f, --format <FORMAT>` | One of `pretty` (default), `json`, `sarif`, `minimal`. |
| `--color <MODE>` | Reserved for future use. Colours are auto-detected from the terminal today. |
| `--no-progress` | Reserved for future use. |
| `--render-links <MODE>` | Reserved for future use. |

### Diagnostics

| Flag | Effect |
|---|---|
| `-v, --verbose` | Reserved for future use. |
| `-q, --quiet` | Reserved for future use. |

### General

| Flag | Effect |
|---|---|
| `-V, --version` | Print version and exit. |
| `-h, --help` | Print the help text and exit. |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean run. No findings, or every finding was suppressed by an inline `vuer-ignore` comment, or `--deny-warnings` was not set. |
| 1 | `--deny-warnings` is set and there is at least one actionable finding, or the scanner hit a fatal I/O error. |
| 2 | `clap` could not parse the command line. |
| 64 | Reserved for usage errors. |

## Output formats

### Pretty (default)

Rustc-style diagnostics with colour. Each finding is a coloured
`error[rule-id]` block followed by the source snippet, carets under
the violation, and a `= help:` line with the remediation advice. A
summary at the bottom counts findings by severity.

```text
error[vue/security/no-v-html]: Unsafe `v-html` directive renders untrusted HTML
 --> src/components/Post.vue:8:10
  |
8 |     <div v-html="user.bio">Bio</div>
  |          ^^^^^^^^^^^^^^^^^^^ here
  |
  = help: Rendering untrusted HTML can execute arbitrary JavaScript. Sanitise the input
          with DOMPurify (or an equivalent library), or use `v-text` / `{{ }}` interpolation.

13 violations: 3 critical, 7 high, 2 medium, 1 low (2 ignored)
```

Colours are auto-detected: they appear on a TTY, are stripped when
output is piped to a file, and obey the `NO_COLOR=1` and
`FORCE_COLOR=1` environment variables. The pretty format always
writes to **stderr**, so `vuer --format pretty src/ > file` only
captures any accidental stdout noise.

### JSON

One structured record per finding on stdout. Use this for ad-hoc
post-processing in `jq`.

```bash
vuer --format json src/ | jq '.[] | select(.severity == "high")'
```

```json
{
  "file": "src/components/Post.vue",
  "rule_id": "vue/security/no-v-html",
  "rule_name": "no-v-html",
  "severity": "critical",
  "category": "security",
  "message": "Unsafe `v-html` directive renders untrusted HTML",
  "help": "Rendering untrusted HTML can execute arbitrary JavaScript. ...",
  "byte_offset": 1234,
  "byte_length": 25,
  "ignored": false
}
```

`ignored` is true when the finding sits under a `// vuer-ignore`
comment. Use it to distinguish "the linter found a real problem"
from "the linter is reporting a suppressed known issue".

### SARIF 2.1.0

SARIF for direct upload to GitHub Code Scanning, GitLab Security
Reports, or any other SARIF-aware dashboard. The `suppressions`
array is populated for ignored findings, so the dashboard's
"suppressed" / "won't fix" annotations work out of the box.

```bash
vuer --format sarif src/ > results.sarif
```

### Minimal

One line per finding on stderr in the format
`file: severity: message`. Useful for `grep` and `awk` pipelines.

```bash
vuer --format minimal src/ 2>&1 | grep critical
```

## Suppression

Three layered mechanisms, in order of decreasing locality:

### 1. Inline comments

```vue
<template>
  <div v-html="trusted">silenced</div>
  <!-- vuer-ignore[no-v-html] -->
  <div v-html="trusted">silenced by previous-line comment</div>
</template>

<script setup>
el.innerHTML = userInput  // vuer-ignore[no-inner-html]
</script>
```

Accepted on the violation's primary line or the line immediately
above. Both the short rule name (`no-v-html`) and the full stable id
(`vue/security/no-v-html`) are accepted. The colon form
(`vuer: ignore[...]`) is also recognised.

### 2. Project config

```yaml
# .vuerc.yml
disable:
  - no-v-html
min-severity: high
```

See the [Configuration section](#configuration) for the full schema.

### 3. `--deny-warnings` and `--no-ignores`

* `--deny-warnings` only counts **actionable** findings (total minus
  suppressed). A fully-suppressed run is treated as clean.
* `--no-ignores` re-surfaces every suppressed finding as actionable
  so you can audit the linter's "blind spots". This is the right
  flag for CI runs that want the raw signal.

## Configuration

Drop a `.vuerc.yml` (or `vuer.yml`) at the project root. The first
file found walking up from the scan path is loaded.

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

CLI flags layer on top: `--rules` is an enable-list (further
narrows the result), `--min-severity` and `--category` override the
config when set, and `--no-config` skips discovery entirely.

Unknown keys are rejected (`deny_unknown_fields`), so a typo like
`min-sev: high` will print a parse warning and fall back to the
default config. The run is never blocked by a broken config file.

## Performance

`vuer` walks the directory tree single-threaded (the work is just
path filtering + `.gitignore` checks, so it is cheap) and then fans
out the per-file parsing across the rayon thread pool. On a large
Vue monorepo this gives a near-linear speedup with the number of
cores — typical results are 3-4x on a 4-core machine compared to the
single-threaded scan.

## Workflows

### One-shot scan in a CI job

```bash
vuer --deny-warnings --min-severity high src/
```

Exit non-zero when any high (or worse) finding is actionable.

### Run as a SARIF producer for the GitHub Security tab

```yaml
- run: vuer --format sarif src/ > results.sarif
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Audit what's currently being silenced

```bash
vuer --no-ignores --list   # show every rule
vuer --no-ignores src/     # see the full raw signal
```

`--no-ignores` undoes every inline `vuer-ignore` comment. The diff
between the default run and the `--no-ignores` run is the set of
suppressions currently in place.

### Watch for regressions on a single rule

```bash
vuer --rules no-inner-html --deny-warnings src/
```

Use this in a pre-merge check to make sure a single rule never
silently regresses.
