use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process;

use clap::{Parser, ValueEnum};
use serde::Serialize;

use vuer::report::sarif;
use vuer::rules::RuleRegistry;
use vuer::scanner::Scanner;

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
}

fn print_pretty(violations: &[vuer::scanner::Violation]) {
  let mut by_file: BTreeMap<PathBuf, Vec<&vuer::scanner::Violation>> = BTreeMap::new();
  for v in violations {
    by_file.entry(v.file.clone()).or_default().push(v);
  }

  for (file, file_violations) in &by_file {
    eprintln!("\n\x1b[1;36m{}\x1b[0m", file.display());

    let content = match std::fs::read_to_string(file) {
      Ok(c) => c,
      Err(_) => continue,
    };
    let lines: Vec<&str> = content.lines().collect();

    for v in file_violations {
      let message = v.diagnostic_message();
      let help = v.diagnostic.help().map(|h| h.to_string());

      let severity_str = match v.severity {
        vuer::severity::Severity::Critical => "\x1b[1;35mcritical\x1b[0m",
        vuer::severity::Severity::High => "\x1b[1;31mhigh\x1b[0m",
        vuer::severity::Severity::Medium => "\x1b[1;33mmedium\x1b[0m",
        vuer::severity::Severity::Low => "\x1b[1;34mlow\x1b[0m",
        vuer::severity::Severity::Info => "\x1b[1;32minfo\x1b[0m",
      };

      let (line_no, col) = if v.span_offset() == 0 && v.span_len() == 0 {
        (0, 0)
      } else {
        let offset = v.span_offset();
        let before = &content[..offset.min(content.len())];
        let ln = before.matches('\n').count() + 1;
        let line_start = before.rfind('\n').map(|p| p + 1).unwrap_or(0);
        let c = offset - line_start + 1;
        (ln, c)
      };

      let loc = if line_no > 0 {
        format!(":{}", line_no)
      } else {
        String::new()
      };

      eprintln!("  {} [{}] {}{}", severity_str, v.rule_id, message, loc);

      if line_no > 0 && line_no <= lines.len() {
        let line_text = lines[line_no - 1];
        eprintln!("  \x1b[90m{} |\x1b[0m {}", line_no, line_text);
        if col > 0 && col <= line_text.len() {
          let padding: String = " ".repeat(col.saturating_sub(1));
          eprintln!("  \x1b[90m{} |\x1b[0m {}^", line_no, padding);
        }
      }

      if let Some(help_text) = help {
        eprintln!("    \x1b[90mhelp: {}\x1b[0m", help_text);
      }
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
  let mut has_errors = false;
  let mut all_violations: Vec<vuer::scanner::Violation> = Vec::new();

  for path in &cli.paths {
    if !path.exists() {
      eprintln!("Error: path '{}' does not exist", path.display());
      has_errors = true;
      continue;
    }

    match scanner.scan_path(path, &enabled_rules) {
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

  if cli.deny_warnings && total_violations > 0 {
    process::exit(1);
  }

  if has_errors {
    process::exit(1);
  }

  if total_violations == 0 {
    eprintln!("\x1b[32mNo violations found.\x1b[0m");
  } else {
    eprintln!(
      "\n\x1b[1;33m{} violation(s) found.\x1b[0m",
      total_violations
    );
  }
}
