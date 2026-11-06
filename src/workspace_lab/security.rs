//! Shared path checks for local overlay operations.
use super::core::no_symlink_components;
use anyhow::{Context, Result};
use std::path::Path;

pub(crate) fn check_overlay_parent(root: &Path, rel: &Path) -> Result<()> {
    no_symlink_components(root.join(rel).parent().context("missing overlay parent")?)
}
