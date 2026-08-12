use miette::NamedSource;
use std::path::PathBuf;

use crate::parser::template::{TemplateError, TemplateRoot};

#[derive(Debug, Clone)]
pub struct ScanContext {
  pub file_path: PathBuf,
  pub source: String,
  pub named_source: NamedSource<String>,
  pub template: Option<String>,
  pub script: Option<String>,
  pub lang: ScriptLang,
  pub template_offset: usize,
  pub script_offset: usize,
  /// The parsed template AST, when a `<template>` block exists and was
  /// successfully parsed. This is the source of truth for template-level
  /// rules; the string `template` is kept only for backwards compatibility
  /// and source-offset calculations.
  pub template_ast: Option<TemplateRoot>,
  /// Non-fatal parse errors encountered while parsing the template. Rules
  /// may inspect or ignore them.
  pub template_errors: Vec<TemplateError>,
  /// The content of every `<style>` block, in source order. Style analysis
  /// itself is out of scope for v1 (see README); the blocks are extracted
  /// so future rules can inspect them without re-reading the source.
  pub style_blocks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScriptLang {
  JavaScript,
  TypeScript,
  Unknown,
}

impl ScanContext {
  pub fn new(file_path: PathBuf, source: String) -> Self {
    let named_source = NamedSource::new(file_path.display().to_string(), source.clone());
    Self {
      file_path,
      source,
      named_source,
      template: None,
      script: None,
      lang: ScriptLang::Unknown,
      template_offset: 0,
      script_offset: 0,
      template_ast: None,
      template_errors: Vec::new(),
      style_blocks: Vec::new(),
    }
  }
}
