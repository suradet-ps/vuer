//! Project-level configuration loaded from `.vuerc.yml` / `vuer.yml`.
//!
//! Mirrors zizmor's directory-walk-up discovery (`config/mod.rs:583-619`):
//! from the current working directory we walk up looking for the first
//! `.vuerc.yml`, `.vuerc.yaml`, `vuer.yml`, or `vuer.yaml` we can read.
//! The search stops at the filesystem root.
//!
//! ## Precedence
//!
//! Every field is optional in the YAML. The CLI flags are layered on
//! top of the config:
//!
//! * `disable` (config) -> additional rules disabled
//! * `--rules` (CLI)    -> enable-list, narrows what runs at all
//! * `min-severity`     -> the higher of config and CLI wins
//! * `category`         -> config sets default, CLI replaces if set
//!
//! The combination is computed in `main.rs` after both `Config::load`
//! and `Cli::parse` have run.
//!
//! ## Failure modes
//!
//! A missing file is normal and yields `Config::default()`. A *broken*
//! file (invalid YAML or unrecognised key) is logged once to stderr
//! and the run continues with `Config::default()` so the linter stays
//! usable. A config typo is never allowed to break the build.

use std::path::{Path, PathBuf};

use serde::Deserialize;

const CONFIG_FILENAMES: &[&str] = &[".vuerc.yml", ".vuerc.yaml", "vuer.yml", "vuer.yaml"];

#[derive(Debug, Default, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Config {
  /// Rule ids (short name or full stable id) to disable for this run.
  /// Disabled rules still execute internally so the report can mention
  /// them when `--list` is used, but they never produce findings.
  #[serde(default)]
  pub disable: Vec<String>,

  /// Only show findings at this severity or higher. Allowed values:
  /// `info`, `low`, `medium`, `high`, `critical`. Unknown values are
  /// logged to stderr and the field is treated as unset.
  #[serde(default, rename = "min-severity")]
  pub min_severity: Option<String>,

  /// Only show findings whose category is in this list. Allowed values:
  /// `security`, `best-practice`, `performance`, `accessibility`,
  /// `architecture`. Unknown values are logged to stderr.
  #[serde(default)]
  pub category: Option<Vec<String>>,
}

#[derive(Debug)]
pub struct LoadOutcome {
  pub config: Config,
  /// Absolute path of the file the config was loaded from, if any.
  pub source: Option<PathBuf>,
  /// Non-fatal parse warning that the caller may want to surface.
  pub warning: Option<String>,
}

impl Config {
  /// Look up and parse the project's config file. Returns a structured
  /// `LoadOutcome` so the caller can decide whether to print the
  /// `source` and `warning` fields.
  pub fn load_from(start: &Path) -> LoadOutcome {
    let Some(path) = discover(start) else {
      return LoadOutcome {
        config: Config::default(),
        source: None,
        warning: None,
      };
    };
    match std::fs::read_to_string(&path) {
      Ok(raw) => match serde_yaml::from_str::<Config>(&raw) {
        Ok(config) => LoadOutcome {
          config,
          source: Some(path.clone()),
          warning: None,
        },
        Err(err) => LoadOutcome {
          config: Config::default(),
          source: Some(path.clone()),
          warning: Some(format!("could not parse {}: {err}", path.display())),
        },
      },
      Err(err) => LoadOutcome {
        config: Config::default(),
        source: Some(path.clone()),
        warning: Some(format!("could not read {}: {err}", path.display())),
      },
    }
  }

  /// True when the rule id (short name or full id) is in `disable`.
  #[must_use]
  pub fn is_disabled(&self, rule_name: &str, rule_id: &str) -> bool {
    self.disable.iter().any(|d| d == rule_name || d == rule_id)
  }
}

fn discover(start: &Path) -> Option<PathBuf> {
  let mut dir = if start.is_dir() {
    start
  } else {
    start.parent()?
  };
  loop {
    for name in CONFIG_FILENAMES {
      let candidate = dir.join(name);
      if candidate.is_file() {
        return Some(candidate);
      }
    }
    match dir.parent() {
      Some(parent) => dir = parent,
      None => return None,
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn empty_config_parses() {
    let yaml = "";
    let cfg: Config = serde_yaml::from_str(yaml).unwrap();
    assert!(cfg.disable.is_empty());
    assert!(cfg.min_severity.is_none());
    assert!(cfg.category.is_none());
  }

  #[test]
  fn full_config_parses() {
    let yaml = r#"
disable:
  - no-v-html
  - vue/security/no-eval
min-severity: high
category:
  - security
  - best-practice
"#;
    let cfg: Config = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(cfg.disable, vec!["no-v-html", "vue/security/no-eval"]);
    assert_eq!(cfg.min_severity.as_deref(), Some("high"));
    assert_eq!(
      cfg.category,
      Some(vec!["security".to_string(), "best-practice".to_string()])
    );
  }

  #[test]
  fn unknown_fields_rejected() {
    let yaml = "typo: 1\n";
    assert!(serde_yaml::from_str::<Config>(yaml).is_err());
  }

  #[test]
  fn is_disabled_matches_short_and_full_id() {
    let cfg = Config {
      disable: vec!["no-v-html".to_string()],
      ..Config::default()
    };
    assert!(cfg.is_disabled("no-v-html", "vue/security/no-v-html"));
    assert!(!cfg.is_disabled("no-eval", "vue/security/no-eval"));
  }

  #[test]
  fn discover_finds_vuer_yml_in_cwd() {
    let dir = tempdir();
    std::fs::write(dir.join("vuer.yml"), "min-severity: high\n").unwrap();
    let found = discover(&dir).unwrap();
    assert!(found.ends_with("vuer.yml"));
  }

  #[test]
  fn discover_walks_up_to_parent() {
    let dir = tempdir();
    std::fs::write(dir.join(".vuerc.yml"), "min-severity: critical\n").unwrap();
    let child = dir.join("src");
    std::fs::create_dir_all(&child).unwrap();
    let found = discover(&child).unwrap();
    assert!(found.ends_with(".vuerc.yml"));
  }

  #[test]
  fn discover_returns_none_when_no_config_exists() {
    let dir = tempdir();
    assert!(discover(&dir).is_none());
  }

  fn tempdir() -> PathBuf {
    let nanos = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .unwrap()
      .as_nanos();
    let pid = std::process::id() as u128;
    let p = std::env::temp_dir().join(format!("vuer-config-test-{pid}-{nanos}"));
    std::fs::create_dir_all(&p).unwrap();
    p
  }
}
