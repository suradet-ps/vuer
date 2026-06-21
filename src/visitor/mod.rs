//! Depth-first walk over a [`TemplateRoot`](super::parser::template::TemplateRoot).
//!
//! The visitor is intentionally non-mutating and intentionally small. It exists
//! so that rules can express "for every element, do X" without re-implementing
//! recursion and without depending on the concrete node shape (which may grow
//! in the future).

use crate::parser::template::{Element, TemplateNode, TemplateRoot};

pub fn walk(root: &TemplateRoot) {
  for child in &root.children {
    walk_node(child);
  }
}

pub fn walk_node(node: &TemplateNode) {
  match node {
    TemplateNode::Element(el) => walk_element(el),
    TemplateNode::Text(_) | TemplateNode::Interpolation(_) | TemplateNode::Comment(_) => {}
  }
}

pub fn walk_element(el: &Element) {
  for child in &el.children {
    walk_node(child);
  }
}

pub fn for_each_element<F: FnMut(&Element)>(root: &TemplateRoot, mut f: F) {
  for_each_element_in(&root.children, &mut f);
}

pub fn for_each_element_in<F: FnMut(&Element)>(nodes: &[TemplateNode], f: &mut F) {
  for node in nodes {
    match node {
      TemplateNode::Element(el) => {
        f(el);
        for_each_element_in(&el.children, f);
      }
      TemplateNode::Text(_) | TemplateNode::Interpolation(_) | TemplateNode::Comment(_) => {}
    }
  }
}
