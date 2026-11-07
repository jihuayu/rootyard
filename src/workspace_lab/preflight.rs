//! Read-only admission preflight for `init`.
//!
//! The workspace lab previously opened (and thereby created) the store before it
//! validated the `init` arguments and the source repository. A rejected source must
//! not be able to create a store directory, a lock file, staging debris or a
//! destination UUID directory. Everything here runs before `Store::open` and is
//! restricted to bounded, read-only observation:
//!
//! * no directory, lock, staging or destination creation;
//! * no index write, no index/stat refresh, no `git add`/`update-index`;
//! * no configuration includes, hooks, external attribute files or filters;
//! * no symlink following while reading attribute contents or link targets.
//!
//! The Git-state and repository-structure checks are *not* re-implemented here: they
//! are the same shared `validate_repo_with` used by `Store::validate_repo` and by the
//! later post-open re-validation. This module only adds the two worktree checks that
//! previously happened much later, inside `capture`:
//!
//! * managed `.gitattributes` files requesting a filter/LFS attribute;
//! * managed symlinks that are absolute, escape the repository, point into `.git`
//!   or reach such a target indirectly.
//!
//! The candidate set mirrors `ignore::classify_workspace` without needing an open
//! store: HEAD tree paths, index paths and untracked paths that Git does not ignore
//! and `.rootyardignore` does not ignore. A path ignored by `.rootyardignore` is
//! therefore *not* preflight-rejected, matching the capture semantics that treat it
//! as unmanaged.
//!
//! This is an early-rejection boundary only. It does not add SHA-256 support, does
//! not implement submodule, LFS or linked-worktree support, and does not replace the
//! later `Store::validate_repo` and capture re-checks, which stay in place because the
//! source can change between the preflight and the copy.

use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};

use super::{core, ignore::IgnoreMatcher};

/// Bound on a single Git path listing, so a hostile tree cannot drive unbounded work.
const MAX_LISTING_BYTES: usize = 64 * 1024 * 1024;

/// Check managed worktree `.gitattributes` filters and managed symlink targets.
pub fn worktree_checks(git: &OsStr, repo: &Path) -> Result<()> {
    let managed = managed_candidates(git, repo)?;
    attribute_filters(repo, &managed)?;
    symlink_targets(repo, &managed)
}

/// Approximate `classify_workspace().managed_paths` without an open store.
fn managed_candidates(git: &OsStr, repo: &Path) -> Result<BTreeSet<PathBuf>> {
    let mut candidates = BTreeSet::new();
    collect(&mut candidates, &core::git_bytes(git, repo, &["ls-files", "-z", "--cached"])?)?;
    let head = core::git_bytes(git, repo, &["ls-tree", "-r", "-z", "--name-only", "HEAD"])?;
    ensure!(head.len() <= MAX_LISTING_BYTES, "tracked path listing exceeds the init preflight limit");
    collect(&mut candidates, &head)?;
    let untracked = core::git_bytes(git, repo, &["ls-files", "-z", "--others", "--exclude-standard"])?;
    ensure!(untracked.len() <= MAX_LISTING_BYTES, "untracked path listing exceeds the init preflight limit");
    let rootyard = IgnoreMatcher::from_worktree(repo)?;
    for record in untracked.split(|byte| *byte == 0).filter(|record| !record.is_empty()) {
        let path = core::relative_path(record)?;
        // `classify_workspace` only manages untracked paths that `.rootyardignore`
        // does not exclude; anything else must not become a new preflight rejection.
        if !rootyard.is_ignored(&path, false) {
            candidates.insert(path);
        }
    }
    ensure!(candidates.len() <= core::MAX_ENTRIES, "managed path count exceeds the init preflight limit");
    Ok(candidates)
}

fn collect(candidates: &mut BTreeSet<PathBuf>, listing: &[u8]) -> Result<()> {
    for record in listing.split(|byte| *byte == 0).filter(|record| !record.is_empty()) {
        candidates.insert(core::relative_path(record)?);
        ensure!(candidates.len() <= core::MAX_ENTRIES, "managed path count exceeds the init preflight limit");
    }
    Ok(())
}

/// Reject managed `.gitattributes` files requesting a filter, using the same
/// conservative contract as `capture` (`filter` is refused, never interpreted).
fn attribute_filters(repo: &Path, managed: &BTreeSet<PathBuf>) -> Result<()> {
    for relative in managed {
        if relative.file_name() != Some(OsStr::new(".gitattributes")) {
            continue;
        }
        if !real_directories(repo, relative)? {
            // capture never descends through a symlinked or non-directory ancestor,
            // so the same path cannot become a managed attribute file.
            continue;
        }
        let full = repo.join(relative);
        let metadata = match fs::symlink_metadata(&full) {
            Ok(metadata) => metadata,
            // A tracked file deleted from the worktree is absent from a capture too.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        ensure!(!metadata.file_type().is_symlink(), "symlinked .gitattributes is unsupported; refusing to follow it");
        ensure!(metadata.is_file(), "non-regular .gitattributes is unsupported");
        core::ensure_no_filter_attributes(&core::read_regular(&full, core::MAX_MANIFEST)?)?;
    }
    Ok(())
}

/// Reject managed symlinks that `capture` would refuse later, reusing the existing
/// `validate_symlink` rule (relative only, no escape, no `.git` target, chain-aware).
/// Link targets are read with `read_link`; no target content is ever opened.
fn symlink_targets(repo: &Path, managed: &BTreeSet<PathBuf>) -> Result<()> {
    for relative in managed {
        if relative.starts_with(".git") || !real_directories(repo, relative)? {
            continue;
        }
        let full = repo.join(relative);
        let metadata = match fs::symlink_metadata(&full) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if !metadata.file_type().is_symlink() {
            continue;
        }
        let target = fs::read_link(&full).context("unreadable worktree symlink")?;
        core::validate_symlink(repo, relative, &target)?;
    }
    Ok(())
}

/// True when every ancestor of `relative` under `repo` is a real directory, checked
/// with `symlink_metadata` so nothing is resolved or read through a symlink.
fn real_directories(repo: &Path, relative: &Path) -> Result<bool> {
    let mut current = repo.to_path_buf();
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    for component in parent.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => return Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(true)
}
