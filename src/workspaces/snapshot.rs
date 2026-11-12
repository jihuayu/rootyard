//! Mount-free raw snapshots of one workspace's filesystem state.
//!
//! Capture and checkpoint used to read the FUSE mount itself (`capture.rs`
//! fingerprint, `checkpoints.rs` frozen body). After a freeze that read queues
//! behind the kernel inode lock held by a parked write: the freezer waits for
//! the scanner, the scanner waits for the writer and the writer waits for the
//! thaw, so the process sits in `D` state until it is killed. Reading an
//! independent inode from the same mount is not a counterexample; the frozen
//! path itself must not touch `/workspace-service/mounts/` at all.
//!
//! This module rebuilds the namespace the overlay exposes from service-owned
//! state only:
//!
//! * lower: `workspace-service/workspaces/<id>` (or the verified lazy manifest
//!   `workspace-service/lazy/<id>.json`, which describes the sparse baseline);
//! * upper: `workspace-service/uppers/<id>` with the overlay's whiteout file
//!   `.rootyard-whiteouts.json`;
//! * the private lazy CAS cache, reached through [`super::lazy::Reader`] only
//!   for worktree files that the checkpoint actually selects.
//!
//! The merge mirrors `workspace_lab::fuse_mount::Overlay`: upper entries override
//! lower entries of the same path, a whiteout hides its exact path and every
//! descendant, an upper file/symlink replaces the lower subtree below it and an
//! upper directory replaces a lower file/symlink of the same path. Internal
//! `.rootyard-whiteouts.*` names never enter a snapshot, paths are validated
//! with the shared `workspace_lab::core` rules (no `..`, no empty components,
//! bounded by `MAX_ENTRIES`/`MAX_BYTES`) and a path that would traverse a
//! symlink ancestor is rejected instead of followed.
//!
//! Symlink targets are resolved against the merged namespace, not per layer.
//! `core::inventory` only proves that a target stays inside the layer that
//! declares it, which is weaker than what the overlay exposes: a lower
//! `a/b/link -> ../../d` turns an upper `a/b/link/../../../outside` from a
//! harmless upper-relative path into a hop that leaves the workspace. Every
//! merged target is therefore walked here with a bounded hop count and refused
//! if it pops past the workspace root or enters native Git metadata, both when
//! the fingerprint is built and again before a copy is published.
//!
//! Fingerprints stay byte-compatible with the previous implementations: the
//! SHA-256 of the JSON encoding of the same path-ordered `core::Entry` list, so
//! an unchanged workspace keeps its stored `workspace_capture_state` baseline.
#[path = "snapshot_copy.rs"]
mod snapshot_copy;

pub(super) use self::snapshot_copy::{Published, copy, publish};
#[cfg(test)]
pub(super) use self::snapshot_copy::{copy_hydrated, copy_into, materialize};
use super::lazy;
use crate::{Error, workspace_lab::core};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    ffi::{OsStr, OsString},
    fs,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
};
use uuid::Uuid;

const WHITEOUTS: &str = ".rootyard-whiteouts.json";
const INTERNAL_PREFIX: &[u8] = b".rootyard-whiteouts.";

/// Hop bound for a merged symlink chain, matching the shared
/// `workspace_lab::core` rule so a tree that passes one namespace check also
/// passes the other.
const MAX_SYMLINK_HOPS: usize = 40;

/// Which service-owned layer one merged entry is copied from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Origin {
    Lower,
    Upper,
    /// Sparse lower file described by the verified lazy manifest.
    Lazy,
}

/// Service-owned locations behind a workspace path.
struct Layout {
    id: Uuid,
    root: PathBuf,
    lower: PathBuf,
    upper: PathBuf,
    merge_upper: bool,
}

impl Layout {
    /// Recognise `<root>/workspace-service/{mounts,workspaces}/<uuid>`.
    ///
    /// Only the service-owned lower directory is inspected to validate the
    /// path. The mount path itself is never stat'ed: under a freeze that would
    /// reintroduce the deadlock this module exists to avoid.
    fn locate(path: &Path) -> Result<Option<Self>, Error> {
        let Some(name) = path.file_name().and_then(OsStr::to_str) else { return Ok(None) };
        let Ok(id) = Uuid::parse_str(name) else { return Ok(None) };
        if id.to_string() != name {
            return Ok(None);
        }
        let Some(kind) = path.parent().and_then(Path::file_name).and_then(OsStr::to_str) else { return Ok(None) };
        if kind != "mounts" && kind != "workspaces" {
            return Ok(None);
        }
        let Some(service) = path.parent().and_then(Path::parent) else { return Ok(None) };
        if service.file_name() != Some(OsStr::new("workspace-service")) {
            return Ok(None);
        }
        let Some(root) = service.parent() else { return Ok(None) };
        let lower = service.join("workspaces").join(name);
        if !directory(&lower)? {
            return Err(Error::internal("workspace raw baseline missing"));
        }
        // `direct` mode serves the lower tree itself, so a leftover upper tree
        // from an earlier FUSE host must not change its bytes or fingerprint.
        let merge_upper = kind == "mounts" || super::mounts::enabled();
        Ok(Some(Self { id, root: root.to_path_buf(), lower, upper: service.join("uppers").join(name), merge_upper }))
    }
}

/// One raw snapshot of a workspace: the merged entry list in path order plus
/// where each entry lives, so a checkpoint can copy exactly the bytes the
/// fingerprint hashed.
pub(super) struct Raw {
    id: Uuid,
    lower: PathBuf,
    upper: PathBuf,
    merged: BTreeMap<PathBuf, (Origin, core::Entry)>,
    hydrates: bool,
    digest: String,
}

impl Raw {
    /// Build the raw snapshot for a workspace path, or `Ok(None)` when the path
    /// is not a service-owned workspace (a checkpoint tree, a test fixture, ...).
    pub(super) fn load(path: &Path) -> Result<Option<Self>, Error> {
        match Layout::locate(path)? {
            Some(layout) => Ok(Some(Self::build(layout)?)),
            None => Ok(None),
        }
    }

    fn build(layout: Layout) -> Result<Self, Error> {
        // A lazy workspace keeps worktree bytes remote: its sparse lower files
        // are placeholders of the right length whose content is all zeroes, so
        // the manifest metadata is the only truthful lower inventory.
        let baseline = lazy::manifest_entries(&layout.root, layout.id)?;
        let lazy_baseline = baseline.is_some();
        let base = match baseline {
            Some(entries) => entries,
            None => core::inventory(&layout.lower).map_err(Error::internal)?,
        };
        let mut lower = BTreeMap::new();
        for entry in base {
            let path = core::decode_path(&entry.path_base64).map_err(Error::internal)?;
            if internal(&path) {
                continue;
            }
            if lower.insert(path, entry).is_some() {
                return Err(Error::internal("duplicate workspace baseline entry"));
            }
        }
        let mut upper = BTreeMap::new();
        let mut upper_dirs = BTreeSet::new();
        if layout.merge_upper && directory(&layout.upper)? {
            for entry in core::inventory(&layout.upper).map_err(Error::internal)? {
                let path = core::decode_path(&entry.path_base64).map_err(Error::internal)?;
                if internal(&path) {
                    continue;
                }
                if upper.insert(path, entry).is_some() {
                    return Err(Error::internal("duplicate workspace upper entry"));
                }
            }
            upper_dirs = upper_directories(&layout.upper)?;
        }
        // A direct-mode workspace serves the lower tree itself; a stale upper
        // tree left by an earlier FUSE host must not hide or mask anything.
        let whiteouts = if layout.merge_upper { whiteouts(&layout.upper)? } else { Vec::new() };
        let hidden = |path: &Path| whiteouts.iter().any(|whiteout| path == whiteout || path.starts_with(whiteout));
        lower.retain(|path, _| !hidden(path));
        upper.retain(|path, _| !hidden(path));
        // An upper file or symlink replaces the complete lower subtree below the
        // same path; the overlay would never resolve those lower children again.
        for path in upper.keys() {
            let mut replaced = Vec::new();
            for (candidate, _) in lower.range(path.clone()..) {
                if candidate == path {
                    continue;
                }
                if !candidate.starts_with(path) {
                    break;
                }
                replaced.push(candidate.clone());
            }
            for candidate in replaced {
                lower.remove(&candidate);
            }
        }
        // The reverse type change: an upper directory hides a lower file or
        // symlink with the same path, including an upper directory that holds no
        // entries of its own. `upper_directories` collects every real upper
        // directory once from the service-owned tree (no mount access, no
        // symlink following), so this is one bounded tree lookup instead of a
        // stat storm for every lower leaf.
        let masked: Vec<PathBuf> = lower.keys().filter(|path| upper_dirs.contains(*path)).cloned().collect();
        for path in masked {
            lower.remove(&path);
        }
        let mut merged = BTreeMap::<PathBuf, (Origin, core::Entry)>::new();
        let lower_origin = if lazy_baseline { Origin::Lazy } else { Origin::Lower };
        for (path, entry) in lower {
            merged.insert(path, (lower_origin, entry));
        }
        for (path, entry) in upper {
            merged.insert(path, (Origin::Upper, entry));
        }
        reject_symlink_ancestors(&merged)?;
        // A target only means something in the namespace the overlay exposes,
        // so a per-layer check is not enough: resolve every target through the
        // merged entry list with a bounded hop count before the fingerprint is
        // published.
        resolve_symlink_targets(&layout.lower, &layout.upper, &merged)?;
        let entries: Vec<core::Entry> = merged.values().map(|(_, entry)| entry.clone()).collect();
        core::validate_entries(&entries).map_err(Error::internal)?;
        let mut total = 0_u64;
        for entry in &entries {
            total = total.checked_add(entry.size).ok_or_else(Error::bad_request)?;
            if total > core::MAX_BYTES {
                return Err(Error::internal("workspace snapshot exceeds the 1 GiB limit"));
            }
        }
        let digest = hash_entries(&entries)?;
        let hydrates = merged.iter().any(|(path, (origin, entry))| {
            *origin == Origin::Lazy && entry.kind == "file" && !path.starts_with(".git")
        });
        Ok(Self { id: layout.id, lower: layout.lower, upper: layout.upper, merged, hydrates, digest })
    }

    pub(super) fn digest(&self) -> &str {
        &self.digest
    }

    #[cfg(test)]
    pub(super) fn items(&self) -> Vec<(Origin, core::Entry)> {
        self.merged.values().cloned().collect()
    }

    /// Raw fixture with an explicit merged namespace, for the cases a real
    /// build already refuses (a file below a merged symlink).
    #[cfg(test)]
    pub(super) fn fixture(lower: PathBuf, upper: PathBuf, items: Vec<(Origin, core::Entry)>) -> Self {
        let merged = items
            .into_iter()
            .map(|(origin, entry)| {
                let path = core::decode_path(&entry.path_base64).expect("fixture path");
                (path, (origin, entry))
            })
            .collect();
        Self { id: Uuid::new_v4(), lower, upper, merged, hydrates: false, digest: String::new() }
    }

    /// Re-check the merged namespace before anything is published: no path
    /// traverses a merged symlink and every symlink target resolves inside it.
    pub(super) fn validate(&self) -> Result<(), Error> {
        reject_symlink_ancestors(&self.merged)?;
        resolve_symlink_targets(&self.lower, &self.upper, &self.merged)
    }

    /// Read a native Git file from the raw layer the merged namespace selects.
    ///
    /// Only a visible merged regular entry is readable. An entry hidden by a
    /// whiteout, replaced by an upper directory, stored as a symlink or reachable
    /// only through a symlink ancestor is refused instead of being read out of a
    /// layer the overlay does not expose; the bytes must still match the length
    /// and digest the fingerprint hashed. A path with no visible entry returns
    /// empty bytes, exactly like an absent file.
    pub(super) fn raw_file(&self, relative: &Path) -> Result<Vec<u8>, Error> {
        let Some((origin, entry)) = self.merged.get(relative) else { return Ok(Vec::new()) };
        if entry.kind != "file" {
            return Err(Error::internal("workspace raw file is not a regular file"));
        }
        for ancestor in relative.ancestors().skip(1).take_while(|ancestor| !ancestor.as_os_str().is_empty()) {
            if self.merged.get(ancestor).is_some_and(|(_, entry)| entry.kind == "symlink") {
                return Err(Error::internal("workspace raw file traverses a symlink"));
            }
        }
        let root = layer(&self.lower, &self.upper, *origin);
        let mut directory = root.to_path_buf();
        if let Some(parent) = relative.parent() {
            for component in parent.components() {
                directory.push(component);
                core::require_directory(&directory)
                    .map_err(|_| Error::internal("workspace raw file traverses a symlink"))?;
            }
        }
        let bytes = core::read_regular(&root.join(relative), core::MAX_MANIFEST).map_err(Error::internal)?;
        if bytes.len() as u64 != entry.size || hex::encode(Sha256::digest(&bytes)) != entry.sha256 {
            return Err(Error::internal("workspace raw file changed during capture"));
        }
        Ok(bytes)
    }
}

/// Fingerprint of a workspace path built from raw layers, or the ordinary
/// inventory hash for any other directory (a freshly written checkpoint tree).
pub(super) fn fingerprint(path: &Path) -> Result<String, Error> {
    if let Some(raw) = Raw::load(path)? {
        return Ok(raw.digest);
    }
    hash_entries(&core::inventory(path).map_err(Error::internal)?)
}

fn hash_entries(entries: &[core::Entry]) -> Result<String, Error> {
    let raw = serde_json::to_vec(entries).map_err(Error::internal)?;
    Ok(hex::encode(Sha256::digest(&raw)))
}

/// The service-owned tree an entry of `origin` is copied from.
fn layer<'a>(lower: &'a Path, upper: &'a Path, origin: Origin) -> &'a Path {
    match origin {
        Origin::Upper => upper,
        Origin::Lower | Origin::Lazy => lower,
    }
}

fn reject_symlink_ancestors(merged: &BTreeMap<PathBuf, (Origin, core::Entry)>) -> Result<(), Error> {
    let links: BTreeSet<&Path> =
        merged.iter().filter(|(_, (_, entry))| entry.kind == "symlink").map(|(path, _)| path.as_path()).collect();
    for path in merged.keys() {
        let traverses = path
            .ancestors()
            .skip(1)
            .take_while(|ancestor| !ancestor.as_os_str().is_empty())
            .any(|ancestor| links.contains(ancestor));
        if traverses {
            return Err(Error::internal("workspace snapshot path traverses a symlink"));
        }
    }
    Ok(())
}

/// Read one merged symlink's target from the layer that owns it, refusing an
/// absolute or empty target and a target that no longer matches the entry the
/// fingerprint hashed (the two views must never disagree).
fn link_target(root: &Path, path: &Path, entry: &core::Entry) -> Result<PathBuf, Error> {
    let target = fs::read_link(root.join(path)).map_err(Error::internal)?;
    if target.as_os_str().is_empty() || target.is_absolute() {
        return Err(Error::internal("workspace snapshot symlink escapes the workspace"));
    }
    let bytes = target.as_os_str().as_bytes();
    if bytes.len() as u64 != entry.size || hex::encode(Sha256::digest(bytes)) != entry.sha256 {
        return Err(Error::internal("workspace raw symlink changed during capture"));
    }
    Ok(target)
}

/// Resolve every merged symlink target inside the merged namespace.
fn resolve_symlink_targets(
    lower: &Path,
    upper: &Path,
    merged: &BTreeMap<PathBuf, (Origin, core::Entry)>,
) -> Result<(), Error> {
    for (path, (origin, entry)) in merged {
        if entry.kind != "symlink" {
            continue;
        }
        resolve_target(lower, upper, merged, path, *origin, entry)?;
    }
    Ok(())
}

/// Walk one target the way the overlay would: relative to the link's parent,
/// following merged symlinks, never popping above the workspace root and never
/// entering native Git metadata. `MAX_SYMLINK_HOPS` bounds the chain.
fn resolve_target(
    lower: &Path,
    upper: &Path,
    merged: &BTreeMap<PathBuf, (Origin, core::Entry)>,
    path: &Path,
    origin: Origin,
    entry: &core::Entry,
) -> Result<(), Error> {
    let target = link_target(layer(lower, upper, origin), path, entry)?;
    let mut resolved: Vec<OsString> = Vec::new();
    if let Some(parent) = path.parent() {
        resolved.extend(parent.components().map(|component| component.as_os_str().to_owned()));
    }
    let mut pending: VecDeque<OsString> =
        target.components().map(|component| component.as_os_str().to_owned()).collect();
    let mut hops = 0_usize;
    while let Some(component) = pending.pop_front() {
        if component.as_os_str() == OsStr::new(".") {
            continue;
        }
        if component.as_os_str() == OsStr::new("..") {
            if resolved.pop().is_none() {
                return Err(Error::internal("workspace snapshot symlink escapes the workspace"));
            }
            continue;
        }
        resolved.push(component);
        if resolved.first().is_some_and(|first| first.as_os_str() == OsStr::new(".git")) {
            return Err(Error::internal("workspace snapshot symlink into Git metadata"));
        }
        let location: PathBuf = resolved.iter().collect();
        let Some((next_origin, next)) = merged.get(&location) else { continue };
        if next.kind != "symlink" {
            continue;
        }
        hops += 1;
        if hops > MAX_SYMLINK_HOPS {
            return Err(Error::internal("workspace snapshot symlink loop or excessive chain"));
        }
        let hop = link_target(layer(lower, upper, *next_origin), &location, next)?;
        resolved.pop();
        for part in hop.components().rev() {
            pending.push_front(part.as_os_str().to_owned());
        }
    }
    Ok(())
}

/// Every real directory inside the service-owned upper tree, as repository
/// relative paths. Symlinks are never followed and never treated as
/// directories, so a lower entry below one is rejected by the ancestor rule
/// instead of being silently masked. The walk is bounded by `MAX_ENTRIES` and
/// ignores the internal whiteout bookkeeping.
fn upper_directories(root: &Path) -> Result<BTreeSet<PathBuf>, Error> {
    let mut found = BTreeSet::new();
    let mut pending = vec![PathBuf::new()];
    while let Some(relative) = pending.pop() {
        for child in fs::read_dir(root.join(&relative)).map_err(Error::internal)? {
            let child = child.map_err(Error::internal)?;
            let path = relative.join(child.file_name());
            core::relative_path(path.as_os_str().as_bytes()).map_err(Error::internal)?;
            if internal(&path) {
                continue;
            }
            if !fs::symlink_metadata(child.path()).map_err(Error::internal)?.file_type().is_dir() {
                continue;
            }
            if found.len() >= core::MAX_ENTRIES {
                return Err(Error::internal("workspace upper directory limit exceeded"));
            }
            found.insert(path.clone());
            pending.push(path);
        }
    }
    Ok(found)
}

/// `.rootyard-whiteouts.json` is `Vec<String>` of repository-relative paths.
fn whiteouts(upper: &Path) -> Result<Vec<PathBuf>, Error> {
    let path = upper.join(WHITEOUTS);
    if !present(&path)? {
        return Ok(Vec::new());
    }
    let raw = core::read_regular(&path, core::MAX_MANIFEST).map_err(Error::internal)?;
    let names: Vec<String> = serde_json::from_slice(&raw).map_err(Error::internal)?;
    names.into_iter().map(|name| core::relative_path(name.as_bytes()).map_err(Error::internal)).collect()
}

/// Internal whiteout bookkeeping never becomes part of a snapshot, at any depth.
fn internal(path: &Path) -> bool {
    path.components().any(|component| component.as_os_str().as_bytes().starts_with(INTERNAL_PREFIX))
}

fn present(path: &Path) -> Result<bool, Error> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Error::internal(error)),
    }
}

fn directory(path: &Path) -> Result<bool, Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_dir()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Error::internal(error)),
    }
}
