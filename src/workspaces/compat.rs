//! Git-state compatibility admission and pre-mutation validation for hosted workspaces.
//!
//! Enforces the frozen compatibility contract across workspace creation, file writes,
//! Git staging/reset, checkpoint capture, restore/fork, remote recovery, and handoff:
//! - Supported: committed SHA-1 repositories, detached HEAD, index v2/v3 with `TREE`
//!   and `REUC`, merge conflicts, `intent-to-add`, safe relative internal symlinks,
//!   non-filter `.gitattributes`, and inert `filter=lfs` declarations without local
//!   filter drivers.
//! - Rejected (`409 Conflict`): submodules/gitlinks (`160000`, `.git/modules/*`, nested
//!   `.git`), linked worktrees (`.git` pointer file, `commondir`, `gitdir`,
//!   `.git/worktrees/*`), active clean/smudge/diff/merge drivers in `.git/config`,
//!   custom `filter=` attributes or `.git/info/attributes` filters, split/sparse
//!   indexes (`link`, `sdir`, `FSMN`, `UNTR`, `skip-worktree`, `sharedindex.*`,
//!   `info/sparse-checkout`), unborn HEAD, SHA-256 object format, external alternates,
//!   shallow clones, grafts, replacement refs, custom hooks, locks, and symlinks inside `.git`.

#[path = "compat_config.rs"]
mod config;

use crate::{Error, workspace_lab::core};
use axum::http::StatusCode;
use std::{collections::BTreeSet, ffi::OsStr, fs, os::unix::ffi::OsStrExt, path::Path};

#[cfg(test)]
pub(super) use config::validate_config_bytes;

pub(super) const CONFLICT_SUBMODULE: &str =
    "submodules, nested repositories, and gitlinks are unsupported in workspaces";
const CONFLICT_WORKTREE: &str = "linked worktrees are unsupported in workspaces";
pub(super) const CONFLICT_FILTERS: &str =
    "clean/smudge drivers and custom Git filter attributes are unsupported in workspaces";
pub(super) const CONFLICT_INDEX: &str =
    "split, sparse, gitlink, or unsupported Git index states are unsupported in workspaces";
pub(super) const CONFLICT_CONFIG: &str = "unsupported workspace Git configuration";
const CONFLICT_STORAGE: &str =
    "external Git storage, shallow clones, grafts, replace refs, and custom hooks are unsupported";
pub(super) const CONFLICT_HEAD: &str =
    "only committed SHA-1 repositories (branch or detached HEAD) are supported in workspaces";
const CONFLICT_BUSY: &str = "workspace checkpoint busy: Git lock exists";
const CONFLICT_SYMLINK: &str = "symlinks inside .git or .gitattributes are unsupported in workspaces";

pub(super) fn is_gitattributes_path(rel: &str) -> bool {
    Path::new(rel).file_name() == Some(OsStr::new(".gitattributes"))
}

/// Validate `.gitattributes` or `.git/info/attributes` contents.
/// Hosted worktree `.gitattributes` allows inert `filter=lfs` pointer markers
/// when `allow_lfs` is true (because local `.git/config` filter drivers are rejected);
/// `.git/info/attributes` always forbids any `filter` attribute (`allow_lfs = false`).
pub(super) fn validate_gitattributes_bytes(bytes: &[u8], allow_lfs: bool) -> Result<(), Error> {
    core::check_gitattributes(bytes, allow_lfs).map_err(|_| Error(StatusCode::CONFLICT, CONFLICT_FILTERS))
}

/// Reject `160000` gitlink entries from a NUL-delimited `git ls-tree -r -z` listing.
pub(super) fn validate_tree_listing_no_gitlinks(listing: &[u8]) -> Result<(), Error> {
    for record in listing.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        if record.starts_with(b"160000 ") {
            return Err(Error(StatusCode::CONFLICT, CONFLICT_SUBMODULE));
        }
    }
    Ok(())
}

/// Validate a live on-disk hosted workspace or materialized checkpoint directory.
pub(super) fn validate_repo(repo: &Path) -> Result<(), Error> {
    core::require_directory(repo).map_err(|_| Error(StatusCode::CONFLICT, CONFLICT_STORAGE))?;
    let dot_git = repo.join(".git");
    let dot_git_meta = fs::symlink_metadata(&dot_git).map_err(|_| Error(StatusCode::CONFLICT, CONFLICT_WORKTREE))?;
    if dot_git_meta.file_type().is_symlink() {
        return Err(Error(StatusCode::CONFLICT, CONFLICT_SYMLINK));
    }
    if dot_git_meta.is_file() {
        return Err(Error(StatusCode::CONFLICT, CONFLICT_WORKTREE));
    }
    if !dot_git_meta.is_dir() {
        return Err(Error(StatusCode::CONFLICT, CONFLICT_WORKTREE));
    }
    for dir in ["worktrees", "modules"] {
        if dot_git.join(dir).try_exists().map_err(Error::internal)? {
            let msg = if dir == "worktrees" { CONFLICT_WORKTREE } else { CONFLICT_SUBMODULE };
            return Err(Error(StatusCode::CONFLICT, msg));
        }
    }

    let git_files = core::walk(&dot_git).map_err(map_walk_error)?;
    let mut git_paths = BTreeSet::new();
    for (rel, meta) in &git_files {
        if meta.file_type().is_symlink() {
            return Err(Error(StatusCode::CONFLICT, CONFLICT_SYMLINK));
        }
        if !meta.is_file() {
            return Err(Error(StatusCode::CONFLICT, CONFLICT_STORAGE));
        }
        classify_git_admin_path(rel)?;
        git_paths.insert(rel.clone());
    }

    let head = read_required_git_file(&dot_git, Path::new("HEAD"))?;
    let cfg = read_required_git_file(&dot_git, Path::new("config"))?;
    config::validate_config_bytes(&cfg)?;
    let packed = if git_paths.contains(Path::new("packed-refs")) {
        Some(core::read_regular(&dot_git.join("packed-refs"), core::MAX_MANIFEST).map_err(Error::internal)?)
    } else {
        None
    };
    validate_head_bytes(&head, |refname| resolve_disk_ref(&dot_git, packed.as_deref(), refname))?;

    if git_paths.contains(Path::new("index")) {
        let index = core::read_regular(&dot_git.join("index"), core::MAX_MANIFEST).map_err(Error::internal)?;
        core::validate_index(&index).map_err(|_| Error(StatusCode::CONFLICT, CONFLICT_INDEX))?;
    }
    if git_paths.contains(Path::new("info/attributes")) {
        let info_attr =
            core::read_regular(&dot_git.join("info/attributes"), core::MAX_MANIFEST).map_err(Error::internal)?;
        validate_gitattributes_bytes(&info_attr, false)?;
    }

    walk_worktree_compat(repo, Path::new(""), &mut 0)
}

/// Validate a frozen merged workspace snapshot (`Origin::Lower` + `Origin::Upper` - whiteouts).
/// Unhydrated `Origin::Lazy` worktree placeholders are not read from sparse zeroes; their
/// baseline content came from an already-validated remote checkpoint, while local `.git/`
/// metadata and any `Lower`/`Upper` `.gitattributes` are always validated directly.
pub(super) fn validate_raw(raw: &super::snapshot::Raw) -> Result<(), Error> {
    let mut git_paths = BTreeSet::new();
    for (origin, entry) in raw.items() {
        let rel = core::decode_path(&entry.path_base64).map_err(Error::internal)?;
        if rel == Path::new(".git") {
            let msg = if entry.kind == "symlink" { CONFLICT_SYMLINK } else { CONFLICT_WORKTREE };
            return Err(Error(StatusCode::CONFLICT, msg));
        }
        if let Ok(rel_git) = rel.strip_prefix(".git") {
            if entry.kind == "symlink" {
                return Err(Error(StatusCode::CONFLICT, CONFLICT_SYMLINK));
            }
            if entry.kind != "file" || matches!(origin, super::snapshot::Origin::Lazy) {
                return Err(Error(StatusCode::CONFLICT, CONFLICT_STORAGE));
            }
            classify_git_admin_path(rel_git)?;
            git_paths.insert(rel_git.to_path_buf());
            continue;
        }
        if has_nested_git_component(&rel) {
            return Err(Error(StatusCode::CONFLICT, CONFLICT_SUBMODULE));
        }
        if rel.file_name() == Some(OsStr::new(".gitattributes")) {
            if entry.kind == "symlink" {
                return Err(Error(StatusCode::CONFLICT, CONFLICT_SYMLINK));
            }
            if !matches!(origin, super::snapshot::Origin::Lazy) {
                let bytes = raw.raw_file(&rel)?;
                validate_gitattributes_bytes(&bytes, true)?;
            }
        }
    }

    if !git_paths.contains(Path::new("HEAD")) || !git_paths.contains(Path::new("config")) {
        return Err(Error(StatusCode::CONFLICT, CONFLICT_HEAD));
    }
    let head = raw.raw_file(Path::new(".git/HEAD"))?;
    let cfg = raw.raw_file(Path::new(".git/config"))?;
    config::validate_config_bytes(&cfg)?;
    let packed = if git_paths.contains(Path::new("packed-refs")) {
        Some(raw.raw_file(Path::new(".git/packed-refs"))?)
    } else {
        None
    };
    validate_head_bytes(&head, |refname| {
        if git_paths.contains(Path::new(refname)) {
            let raw_ref = raw.raw_file(&Path::new(".git").join(refname))?;
            return Ok(is_valid_sha1_oid_line(&raw_ref));
        }
        Ok(packed.as_deref().is_some_and(|p| packed_refs_contains(p, refname)))
    })?;

    if git_paths.contains(Path::new("index")) {
        let index = raw.raw_file(Path::new(".git/index"))?;
        core::validate_index(&index).map_err(|_| Error(StatusCode::CONFLICT, CONFLICT_INDEX))?;
    }
    if git_paths.contains(Path::new("info/attributes")) {
        let info_attr = raw.raw_file(Path::new(".git/info/attributes"))?;
        validate_gitattributes_bytes(&info_attr, false)?;
    }
    Ok(())
}

fn map_walk_error(err: anyhow::Error) -> Error {
    let text = err.to_string();
    if text.contains("nested Git repositories") {
        Error(StatusCode::CONFLICT, CONFLICT_SUBMODULE)
    } else {
        Error::internal(err)
    }
}

fn read_required_git_file(dot_git: &Path, rel: &Path) -> Result<Vec<u8>, Error> {
    let path = dot_git.join(rel);
    if !path.try_exists().map_err(Error::internal)? {
        return Err(Error(StatusCode::CONFLICT, CONFLICT_HEAD));
    }
    core::read_regular(&path, core::MAX_MANIFEST).map_err(Error::internal)
}

fn resolve_disk_ref(dot_git: &Path, packed: Option<&[u8]>, refname: &str) -> Result<bool, Error> {
    let loose = dot_git.join(refname);
    if let Ok(meta) = fs::symlink_metadata(&loose) {
        if meta.file_type().is_symlink() {
            return Err(Error(StatusCode::CONFLICT, CONFLICT_SYMLINK));
        }
        if meta.is_file() {
            let bytes = core::read_regular(&loose, core::MAX_MANIFEST).map_err(Error::internal)?;
            return Ok(is_valid_sha1_oid_line(&bytes));
        }
    }
    Ok(packed.is_some_and(|p| packed_refs_contains(p, refname)))
}

fn has_nested_git_component(rel: &Path) -> bool {
    rel.components().any(|c| c.as_os_str() == OsStr::new(".git"))
}

fn walk_worktree_compat(repo: &Path, relative: &Path, seen: &mut usize) -> Result<(), Error> {
    for entry in fs::read_dir(repo.join(relative)).map_err(Error::internal)? {
        let entry = entry.map_err(Error::internal)?;
        let name = entry.file_name();
        let path = relative.join(&name);
        if path == Path::new(".git") {
            continue;
        }
        if name == OsStr::new(".git") {
            return Err(Error(StatusCode::CONFLICT, CONFLICT_SUBMODULE));
        }
        *seen += 1;
        if *seen > core::MAX_ENTRIES {
            return Err(Error(StatusCode::CONFLICT, CONFLICT_STORAGE));
        }
        let meta = fs::symlink_metadata(entry.path()).map_err(Error::internal)?;
        if meta.file_type().is_symlink() {
            if name == OsStr::new(".gitattributes") {
                return Err(Error(StatusCode::CONFLICT, CONFLICT_SYMLINK));
            }
            continue;
        }
        if meta.is_dir() {
            walk_worktree_compat(repo, &path, seen)?;
        } else if meta.is_file() && name == OsStr::new(".gitattributes") {
            let bytes = core::read_regular(&entry.path(), core::MAX_MANIFEST).map_err(Error::internal)?;
            validate_gitattributes_bytes(&bytes, true)?;
        }
    }
    Ok(())
}

fn classify_git_admin_path(rel_git: &Path) -> Result<(), Error> {
    if rel_git.as_os_str().as_bytes().ends_with(b".lock") {
        return Err(Error(StatusCode::CONFLICT, CONFLICT_BUSY));
    }
    if rel_git == Path::new("commondir") || rel_git == Path::new("gitdir") || rel_git.starts_with("worktrees") {
        return Err(Error(StatusCode::CONFLICT, CONFLICT_WORKTREE));
    }
    if rel_git.starts_with("modules") {
        return Err(Error(StatusCode::CONFLICT, CONFLICT_SUBMODULE));
    }
    if rel_git == Path::new("objects/info/alternates")
        || rel_git == Path::new("objects/info/http-alternates")
        || rel_git == Path::new("shallow")
        || rel_git == Path::new("info/grafts")
        || rel_git.starts_with("refs/replace")
    {
        return Err(Error(StatusCode::CONFLICT, CONFLICT_STORAGE));
    }
    if rel_git == Path::new("info/sparse-checkout")
        || rel_git == Path::new("config.worktree")
        || rel_git.file_name().and_then(OsStr::to_str).is_some_and(|n| n.starts_with("sharedindex."))
    {
        return Err(Error(StatusCode::CONFLICT, CONFLICT_INDEX));
    }
    if rel_git.starts_with("hooks") && !rel_git.as_os_str().as_bytes().ends_with(b".sample") {
        return Err(Error(StatusCode::CONFLICT, CONFLICT_STORAGE));
    }
    Ok(())
}

pub(super) fn validate_head_bytes(
    head_bytes: &[u8],
    mut resolve_ref: impl FnMut(&str) -> Result<bool, Error>,
) -> Result<(), Error> {
    if head_bytes.contains(&0) {
        return Err(Error(StatusCode::CONFLICT, CONFLICT_HEAD));
    }
    let Ok(text) = std::str::from_utf8(head_bytes) else {
        return Err(Error(StatusCode::CONFLICT, CONFLICT_HEAD));
    };
    let trimmed = text.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() || trimmed.contains(['\r', '\n']) {
        return Err(Error(StatusCode::CONFLICT, CONFLICT_HEAD));
    }
    if let Some(target) = trimmed.strip_prefix("ref: ") {
        if !is_safe_head_ref(target) {
            return Err(Error(StatusCode::CONFLICT, CONFLICT_HEAD));
        }
        if !resolve_ref(target)? {
            return Err(Error(StatusCode::CONFLICT, CONFLICT_HEAD));
        }
        return Ok(());
    }
    if is_valid_sha1_oid(trimmed) {
        return Ok(());
    }
    Err(Error(StatusCode::CONFLICT, CONFLICT_HEAD))
}

fn is_safe_head_ref(target: &str) -> bool {
    target.starts_with("refs/")
        && !target.contains("..")
        && !target.contains("//")
        && !target.ends_with('/')
        && !target.ends_with(".lock")
        && !target.bytes().any(|b| b <= 32 || b == 127)
}

fn is_valid_sha1_oid_line(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).ok().is_some_and(|s| is_valid_sha1_oid(s.trim_end_matches(['\r', '\n'])))
}

fn is_valid_sha1_oid(oid: &str) -> bool {
    oid.len() == 40 && oid.bytes().all(|b| b.is_ascii_hexdigit()) && !oid.bytes().all(|b| b == b'0')
}

fn packed_refs_contains(bytes: &[u8], target_ref: &str) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else { return false };
    for raw in text.lines() {
        let line = raw.trim_end_matches('\r');
        if line.is_empty() || line.starts_with('#') || line.starts_with('^') {
            continue;
        }
        if let Some((oid, refname)) = line.split_once(' ')
            && is_valid_sha1_oid(oid)
            && refname == target_ref
        {
            return true;
        }
    }
    false
}
