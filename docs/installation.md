# Installation

`vuer` is a Rust binary. The recommended install path is `cargo install`,
but pre-built binaries and a Docker image are also available.

## From crates.io

Once the crate is published:

```bash
cargo install vuer
```

This compiles from source and drops the `vuer` binary in
`~/.cargo/bin/`. Make sure that directory is on your `PATH`.

## From GitHub

To install the latest commit on the default branch:

```bash
cargo install --git https://github.com/suradet-ps/vuer --locked
```

`--locked` is recommended: it pins the `Cargo.lock` so the build
reproducibly matches CI.

## From a release binary

Download a pre-built binary for your platform from the
[GitHub Releases page](https://github.com/suradet-ps/vuer/releases).
Each release attaches:

* `vuer-x86_64-unknown-linux-gnu.tar.xz`
* `vuer-x86_64-apple-darwin.tar.xz`
* `vuer-aarch64-apple-darwin.tar.xz`
* `vuer-x86_64-pc-windows-msvc.zip`

Extract the archive and place the `vuer` (or `vuer.exe`) binary
somewhere on your `PATH`. No runtime dependencies.

Verify the install:

```bash
vuer --version
```

## From source (development)

```bash
git clone https://github.com/suradet-ps/vuer
cd vuer
cargo build --release
./target/release/vuer --version
```

The release build is in `target/release/vuer`. Use `cargo run` during
development; the dev binary lives at `target/debug/vuer`.

## Editor integration

`vuer` is a single binary that reads from disk and prints to stdout
or stderr. Any tool that can run an external command can drive it:

* **VS Code** — the [ESLint](https://marketplace.visualstudio.com/items?itemName=dbaeumer.vscode-eslint)
  extension supports a custom problem matcher that points at a SARIF
  output file.
* **Neovim / Vim** — `vuer --format sarif` integrates with the built-in
  ALE and `:CocList` via any SARIF plugin.
* **JetBrains IDEs** — the [SARIF plugin](https://plugins.jetbrains.com/plugin/17409-sarif)
  reads the SARIF output and surfaces the findings inline.

## CI integration

Every CI provider can run `vuer` as a normal step. The exit code is
non-zero when `--deny-warnings` is set and at least one *actionable*
finding is produced (suppressed findings do not count), or when the
scanner hits an I/O error. Otherwise it is zero.

```yaml
# GitHub Actions
- name: vuer
  run: |
    cargo install --git https://github.com/suradet-ps/vuer --locked
    vuer --deny-warnings src/
```

```yaml
# GitLab CI
vuer:
  image: rust:1.85
  before_script: cargo install --git https://github.com/suradet-ps/vuer --locked
  script: vuer --deny-warnings src/
```

For SARIF output, write to a file and point your CI provider's
security dashboard at it:

```bash
vuer --format sarif src/ > results.sarif
```

GitHub Actions: upload with `github/codeql-action/upload-sarif`.
GitLab: use the [`artifacts:reports:sarif`](https://docs.gitlab.com/ee/ci/testing/code_quality.html)
keyword.
