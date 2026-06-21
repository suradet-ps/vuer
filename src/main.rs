use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process;

use annotate_snippets::{AnnotationKind, Level, Renderer, Snippet};
use anstream::eprintln;
use clap::{Parser, ValueEnum};
use owo_colors::OwoColorize;
use serde::Serialize;

use vuer::report::sarif;
use vuer::rules::RuleRegistry;
use vuer::scanner::{ScanOptions, Scanner};

#[derive(Parser)]
#[command(
  name = "vuer",
  about = "A security-focused AST-based static analyser for Vue.js SFCs",
  version,
  long_about = None
)]
struct Cli {
  #[arg(required_unless_present = "list")]
  paths: Vec<PathBuf>,

  #[arg(short, long, value_delimiter = ',')]
  rules: Option<Vec<String>>,

  #[arg(short, long, value_enum, default_value_t = OutputFormat::Pretty)]
  format: OutputFormat,

  #[arg(short, long)]
  list: bool,

  #[arg(long)]
  deny_warnings: bool,

  /// Treat every `// vuer-ignore[...]` / `<!-- vuer-ignore[...] -->` comment
  /// as a no-op and report everything the linter would otherwise suppress.
  /// Useful in CI to see what is currently being silenced.
  #[arg(long)]
  no_ignores: bool,

  /// Filter rules by category (security, best-practice, performance, accessibility, architecture).
  #[arg(long, value_delimiter = ',')]
  category: Option<Vec<String>>,

  /// Only fail on these severities or higher. Defaults to medium.
  #[arg(long, value_enum)]
  min_severity: Option<MinSeverity>,
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
  Pretty,
  Json,
  Minimal,
  Sarif,
}

#[derive(Clone, ValueEnum, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum MinSeverity {
  Info,
  Low,
  Medium,
  High,
  Critical,
}

impl MinSeverity {
  fn as_vuer_severity(self) -> vuer::severity::Severity {
    use vuer::severity::Severity;
    match self {
      Self::Info => Severity::Info,
      Self::Low => Severity::Low,
      Self::Medium => Severity::Medium,
      Self::High => Severity::High,
      Self::Critical => Severity::Critical,
    }
  }
}

fn list_rules(registry: &RuleRegistry) {
  println!("Available rules:\n");
  for rule in registry.get_all() {
    println!(
      "  {:<40} [{:<7}] {:<5} {}",
      rule.id().as_str(),
      format!("{:?}", rule.category()).to_lowercase(),
      format!("{:?}", rule.severity()).to_lowercase(),
      rule.description()
    );
  }
  println!("\nUse --rules <rule1,rule2> to run specific rules.");
  println!("Use --category <cat1,cat2> to filter by category.");
  println!("Use --min-severity <level> to fail only on at least this severity.");
  println!("Use --no-ignores to disable inline `vuer-ignore[...]` comments.");
}

fn severity_level(sev: vuer::severity::Severity) -> Level<'static> {
  // Mirror rustc's own colour choice: error red, warning yellow, note cyan.
  match sev {
    vuer::severity::Severity::Critical | vuer::severity::Severity::High => Level::ERROR,
    vuer::severity::Severity::Medium => Level::WARNING,
    vuer::severity::Severity::Low => Level::NOTE,
    vuer::severity::Severity::Info => Level::INFO,
  }
}

fn print_pretty(violations: &[vuer::scanner::Violation]) {
  let renderer = Renderer::styled();
  let mut by_file: BTreeMap<&PathBuf, Vec<&vuer::scanner::Violation>> = BTreeMap::new();
  for v in violations {
    by_file.entry(&v.file).or_default().push(v);
  }

  for (file, file_violations) in &by_file {
    eprintln!();
    eprintln!("{}", file.display().to_string().bright_cyan().bold());

    let content = match std::fs::read_to_string(file) {
      Ok(c) => c,
      Err(_) => continue,
    };

    for v in file_violations {
      let mut group = annotate_snippets::Group::with_title(
        severity_level(v.severity)
          .primary_title(v.diagnostic_message())
          .id(v.rule_id.clone()),
      );

      if v.span_offset() != 0 || v.span_len() != 0 {
        let start = v.span_offset();
        let end = start + v.span_len();
        let label = if v.ignored { "(ignored)" } else { "here" };
        let snippet = Snippet::source(&content)
          .line_start(1)
          .path(file.display().to_string())
          .annotation(
            AnnotationKind::Primary
              .span(start..end)
              .label(label.to_string()),
          );
        group = group.element(snippet);
      }

      if let Some(help) = v.diagnostic.help() {
        group = group.element(Level::HELP.message(help.to_string()));
      }

      eprintln!("{}", renderer.render(&[group]).to_string());
    }
  }
}

#[derive(Serialize)]
struct JsonViolation<'a> {
  file: String,
  rule_id: &'a str,
  rule_name: &'a str,
  severity: &'a str,
  category: &'a str,
  message: String,
  help: Option<String>,
  byte_offset: usize,
  byte_length: usize,
  ignored: bool,
}

fn print_json(violations: &[vuer::scanner::Violation]) {
  let json: Vec<JsonViolation<'_>> = violations
    .iter()
    .map(|v| JsonViolation {
      file: v.file.display().to_string(),
      rule_id: &v.rule_id,
      rule_name: &v.rule_name,
      severity: v.severity.as_str(),
      category: match v.category {
        vuer::rules::Category::Security => "security",
        vuer::rules::Category::BestPractice => "best-practice",
        vuer::rules::Category::Performance => "performance",
        vuer::rules::Category::Accessibility => "accessibility",
        vuer::rules::Category::Architecture => "architecture",
      },
      message: v.diagnostic_message(),
      help: v.diagnostic.help().map(|h| h.to_string()),
      byte_offset: v.span_offset(),
      byte_length: v.span_len(),
      ignored: v.ignored,
    })
    .collect();
  println!("{}", serde_json::to_string_pretty(&json).unwrap());
}

fn print_sarif(violations: &[vuer::scanner::Violation]) {
  // SARIF needs source bytes for line/column. We read each unique file
  // once and hand the (path, source) map to the SARIF builder.
  let mut sources: std::collections::BTreeMap<PathBuf, String> = Default::default();
  for v in violations {
    if !sources.contains_key(&v.file) {
      if let Ok(content) = std::fs::read_to_string(&v.file) {
        sources.insert(v.file.clone(), content);
      }
    }
  }
  let log = sarif::build_sarif(violations, &sources);
  println!("{}", serde_json::to_string_pretty(&log).unwrap());
}

fn print_minimal(violations: &[vuer::scanner::Violation]) {
  for v in violations {
    eprintln!(
      "{}: {}: {}",
      v.file.display(),
      v.severity,
      v.diagnostic_message()
    );
  }
}

fn main() {
  let cli = Cli::parse();
  let scanner = Scanner::new();

  if cli.list {
    list_rules(scanner.registry());
    return;
  }

  let enabled_rules = cli.rules.unwrap_or_default();
  let options = ScanOptions {
    no_ignores: cli.no_ignores,
  };
  let mut has_errors = false;
  let mut all_violations: Vec<vuer::scanner::Violation> = Vec::new();

  for path in &cli.paths {
    if !path.exists() {
      eprintln!("Error: path '{}' does not exist", path.display());
      has_errors = true;
      continue;
    }

    match scanner.scan_path(path, &enabled_rules, &options) {
      Ok(violations) => {
        all_violations.extend(violations);
      }
      Err(e) => {
        eprintln!("Error scanning {}: {}", path.display(), e);
        has_errors = true;
      }
    }
  }

  // Filter by category / min severity after the fact, so users can combine
  // the filters.
  let all_violations: Vec<vuer::scanner::Violation> = all_violations
    .into_iter()
    .filter(|v| {
      if let Some(cats) = &cli.category {
        let cat = match v.category {
          vuer::rules::Category::Security => "security",
          vuer::rules::Category::BestPractice => "best-practice",
          vuer::rules::Category::Performance => "performance",
          vuer::rules::Category::Accessibility => "accessibility",
          vuer::rules::Category::Architecture => "architecture",
        };
        if !cats.iter().any(|c| c == cat) {
          return false;
        }
      }
      if let Some(min) = cli.min_severity {
        if v.severity < min.as_vuer_severity() {
          return false;
        }
      }
      true
    })
    .collect();

  match cli.format {
    OutputFormat::Pretty => print_pretty(&all_violations),
    OutputFormat::Json => print_json(&all_violations),
    OutputFormat::Sarif => print_sarif(&all_violations),
    OutputFormat::Minimal => print_minimal(&all_violations),
  }
  let total_violations = all_violations.len();
  let ignored_count = all_violations.iter().filter(|v| v.ignored).count();

  // `deny_warnings` should never cause a clean run to fail, so a violation
  // suppressed by `// vuer-ignore` is not a real warning.
  let actionable_violations = total_violations - ignored_count;
  if cli.deny_warnings && actionable_violations > 0 {
    process::exit(1);
  }

  if has_errors {
    process::exit(1);
  }

  if total_violations == 0 {
    eprintln!();
    eprintln!("{}", "No violations found.".green().bold());
    return;
  }

  // Severity breakdown of *actionable* findings, ordered worst-first.
  let mut by_sev: BTreeMap<vuer::severity::Severity, usize> = BTreeMap::new();
  for v in &all_violations {
    if !v.ignored {
      *by_sev.entry(v.severity).or_insert(0) += 1;
    }
  }

  eprintln!();
  eprint!(
    "{n} violation{s}: ",
    n = total_violations.green(),
    s = if total_violations == 1 { "" } else { "s" },
  );

  // Print in worst-first order: Critical, High, Medium, Low, Info.
  let order = [
    vuer::severity::Severity::Critical,
    vuer::severity::Severity::High,
    vuer::severity::Severity::Medium,
    vuer::severity::Severity::Low,
    vuer::severity::Severity::Info,
  ];
  let mut parts = Vec::new();
  for sev in order {
    if let Some(n) = by_sev.get(&sev) {
      let count = match sev {
        vuer::severity::Severity::Critical => n.bright_magenta().to_string(),
        vuer::severity::Severity::High => n.red().to_string(),
        vuer::severity::Severity::Medium => n.yellow().to_string(),
        vuer::severity::Severity::Low => n.cyan().to_string(),
        vuer::severity::Severity::Info => n.green().to_string(),
      };
      parts.push(format!("{count} {}", sev.as_str()));
    }
  }
  eprint!("{}", parts.join(", "));

  if ignored_count > 0 {
    eprint!(" ({n} ignored)", n = ignored_count.bright_black());
  }
  eprintln!();
}
