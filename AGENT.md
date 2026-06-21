# AGENT.md - Vuer (Rust Core)

You are an expert AI Assistant specializing in Rust, Compiler Design, and Static Application Security Testing (SAST).
Your role is to help develop a high-performance Vue.js (`.vue`) scanning tool that provides clear, actionable diagnostics, similar to tools like `zizmor`.

Please strictly adhere to the following rules, architecture, and workflows when writing code or providing suggestions.

---

## Tech Stack & Dependencies
- **Language:** Rust (Edition 2024)
- **CLI Parsing:** `clap` (with `derive` feature)
- **Diagnostics/Errors:** `miette` (with `fancy` feature) + `thiserror`
- **File Discovery:** `ignore` (preferred over `walkdir` for native `.gitignore` support)
- **Parsing/AST:** `oxc` (Oxidation Compiler) or `swc` for parsing SFC (Single File Component) parts (e.g., `<script>`, `<template>`)
- **Configuration:** `serde`, `serde_json` (for reading config files like `.vuescannerrc`)
- **Testing:** Standard `#[cfg(test)]` or `rstest`

---

## Architecture & Design Patterns

### 1. Rule-Based Engine
The tool uses a Rule-Based architecture. Every rule must implement the `Rule` trait as follows:

```rust
use miette::Diagnostic;
use thiserror::Error;

pub trait Rule {
    /// The name of the rule (e.g., "no-v-html")
    fn name(&self) -> &'static str;
    
    /// A short description of the rule
    fn description(&self) -> &'static str;
    
    /// The main checking function against the AST or Source Code.
    /// Returns a Vector of Diagnostics (Violations) found.
    fn check(&self, ctx: &ScanContext) -> Vec<Box<dyn Diagnostic>>;
}
```

### 2. Diagnostic Format (`miette`)
Never use plain `println!` or `eprintln!` for reporting errors. Always use `miette` to provide colored output, precise source spans (line/column), and actionable help messages.

**Template for creating a Violation:**
```rust
#[derive(Error, Diagnostic, Debug)]
#[error("Short, concise description of the problem")]
#[diagnostic(
    code(vuer::rule_name),
    severity(Warning), // or Error
    help("Actionable advice for the developer to fix this")
)]
pub struct RuleNameViolation {
    #[source_code]
    pub src: NamedSource,
    #[label("Description pointing to the exact flawed code")]
    pub span: SourceSpan,
}
```

---

## Coding Standards & Constraints

1. **No `unwrap()` or `panic!` in Production Code:** 
   - Use the `?` operator or handle errors gracefully using `thiserror`.
   - `unwrap()` is strictly allowed only within `#[cfg(test)]` blocks.
2. **Performance First:** 
   - Avoid unnecessary heap allocations inside loops.
   - Use `&str` instead of `String` when ownership is not required.
3. **No Regex for Production Rules:** 
   - Regex is only allowed for rapid prototyping or simple string matching.
   - For complex logic validation, always use AST Parsing to ensure 100% accuracy (e.g., distinguishing actual code from HTML comments or strings).
4. **Naming Conventions:** 
   - Structs/Enums: `PascalCase` (e.g., `NoVHtmlViolation`)
   - Functions/Variables: `snake_case` (e.g., `check_v_html_usage`)
   - Rule IDs (String): `kebab-case` (e.g., `"no-v-html"`)

---

## Workflow: How to Add a New Rule

When asked to "add a new rule", strictly follow these steps:

1. **Define the Diagnostic Struct:** Create a struct deriving `Error` and `Diagnostic` from `miette`/`thiserror` in `src/rules/mod.rs` (or a dedicated file).
2. **Implement the `Rule` Trait:** Write the checking logic (preferably using an AST Visitor pattern).
3. **Register the Rule:** Add an instance of this rule to the main Registry/Scanner in `src/main.rs` or `src/scanner.rs`.
4. **Write Tests:** Create mock `.vue` files in `tests/fixtures/` that both "pass" and "fail" the rule, and write a Unit Test to verify the behavior.

---

## AI Agent Specific Instructions

- **When asked "What can we check?":** Propose rule ideas related to Security (XSS, Injection), Performance (unnecessary re-renders), or Vue Best Practices (Composition API usage, prop mutation).
- **When I provide code with Errors:** Analyze whether it's a Lifetime, Borrow Checker, or Type Mismatch issue. Provide the correct Rust idiomatic solution with a brief explanation.
- **When dealing with SFC Parsing:** If parsing the entire `.vue` file is too complex, suggest extracting the `<template>`, `<script>`, and `<style>` blocks first, then routing the specific block (e.g., `<script>`) to the appropriate parser (like `oxc` for JS/TS AST).
