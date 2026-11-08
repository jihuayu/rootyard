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
//! Fingerprints stay byte-compatible with the previous implementations: the
//! SHA-256 of the JSON encoding of the same path-ordered `core::Entry` list, so
//! an unchanged workspace keeps its stored `workspace_capture_state` baseline.
use super::lazy;
use crate::{AppState, Error, workspace_lab::core};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};
use uuid::Uuid;

const WHITEOUTS: &str = ".rootyard-whiteouts.json";
const INTERNAL_PREFIX: &[u8] = b".rootyard-whiteouts.";

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

/// One raw snapshot of a workspace: the merged entry list plus where each entry
/// lives, so a checkpoint can copy exactly the bytes the fingerprint hashed.
pub(super) struct Raw {
    id: Uuid,
    lower: PathBuf,
    upper: PathBuf,
    items: Vec<(Origin, core::Entry)>,
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
        Ok(Self {
            id: layout.id,
            lower: layout.lower,
            upper: layout.upper,
            items: merged.into_values().collect(),
            hydrates,
            digest,
        })
    }

    pub(super) fn digest(&self) -> &str {
        &self.digest
    }

    #[cfg(test)]
    pub(super) fn items(&self) -> &[(Origin, core::Entry)] {
        &self.items
    }

    /// Read a native Git file from raw state: upper first, then lower. Returns
    /// empty bytes when neither layer has it, exactly like an absent file.
    pub(super) fn raw_file(&self, relative: &Path) -> Result<Vec<u8>, Error> {
        for root in [&self.upper, &self.lower] {
            let path = root.join(relative);
            if present(&path)? {
                return core::read_regular(&path, core::MAX_MANIFEST).map_err(Error::internal);
            }
        }
        Ok(Vec::new())
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

/// Copy a raw snapshot into a new private tree and publish it at `dest`.
///
/// The tree is staged next to `dest`, synced and renamed, so a failure never
/// leaves a directory that could be mistaken for a confirmed checkpoint. Only
/// lower bytes, upper bytes and verified lazy-cache bytes are read; the mount
/// is never opened.
pub(super) fn copy(state: &AppState, raw: &Raw, dest: &Path) -> Result<(), Error> {
    let reader = if raw.hydrates {
        Some(lazy::Reader::open(state, raw.id)?.ok_or_else(|| Error::internal("lazy baseline manifest missing"))?)
    } else {
        None
    };
    let parent = dest.parent().ok_or_else(Error::bad_request)?;
    fs::create_dir_all(parent).map_err(Error::internal)?;
    let staging = parent.join(format!(".snapshot-{}", Uuid::new_v4()));
    core::private_dir(&staging).map_err(Error::internal)?;
    let mut hydrate = |relative: &Path, entry: &core::Entry, total: &mut u64| match &reader {
        Some(reader) => {
            let source = reader
                .file(relative)
                .map_err(Error::internal)?
                .ok_or_else(|| Error::internal("lazy baseline entry missing"))?;
            copy_hydrated(&staging, relative, entry, source, total)
        }
        None => Err(Error::internal("lazy baseline reader missing")),
    };
    let outcome = materialize(raw, &staging, &mut hydrate).and_then(|()| publish(&staging, parent, dest));
    if outcome.is_err() {
        let _ = fs::remove_dir_all(&staging);
        let _ = fs::remove_dir_all(dest);
    }
    outcome
}

fn publish(staging: &Path, parent: &Path, dest: &Path) -> Result<(), Error> {
    core::sync_tree(staging).map_err(Error::internal)?;
    fs::rename(staging, dest).map_err(Error::internal)?;
    File::open(parent).and_then(|directory| directory.sync_all()).map_err(Error::internal)
}

/// Copy every selected entry from its origin. `hydrate` is injected so unit
/// tests can materialise lazy entries without a network or a live mount.
pub(super) fn materialize(
    raw: &Raw,
    dest: &Path,
    hydrate: &mut dyn FnMut(&Path, &core::Entry, &mut u64) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut total = 0_u64;
    for (origin, entry) in &raw.items {
        let relative = core::decode_path(&entry.path_base64).map_err(Error::internal)?;
        match origin {
            Origin::Upper => {
                core::copy_single_entry(&raw.upper, dest, &relative, &mut total).map_err(Error::internal)?
            }
            Origin::Lower => {
                core::copy_single_entry(&raw.lower, dest, &relative, &mut total).map_err(Error::internal)?
            }
            // Symlinks and native Git metadata are real bytes in the sparse
            // lower tree; only worktree files stay remote.
            Origin::Lazy if entry.kind != "file" || relative.starts_with(".git") => {
                core::copy_single_entry(&raw.lower, dest, &relative, &mut total).map_err(Error::internal)?
            }
            Origin::Lazy => hydrate(&relative, entry, &mut total)?,
        }
    }
    // Empty .git directories are legal and need not be retained, but the root must exist.
    for name in [".git", ".git/objects", ".git/refs"] {
        let dir = dest.join(name);
        if !dir.exists() {
            core::private_dir(&dir).map_err(Error::internal)?;
        }
    }
    Ok(())
}

/// Copy one hydrated lazy file with the length, digest and mode the manifest
/// promised. A mismatch fails the checkpoint instead of storing different bytes.
pub(super) fn copy_hydrated(
    dest: &Path,
    relative: &Path,
    entry: &core::Entry,
    mut source: File,
    total: &mut u64,
) -> Result<(), Error> {
    let to = prepare(dest, relative)?;
    let next = total.checked_add(entry.size).ok_or_else(Error::bad_request)?;
    if next > core::MAX_BYTES {
        return Err(Error::internal("workspace copy limit is 1 GiB"));
    }
    *total = next;
    let metadata = source.metadata().map_err(Error::internal)?;
    if !metadata.is_file() || metadata.len() != entry.size {
        return Err(Error::internal("lazy baseline size mismatch"));
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&to)
        .map_err(Error::internal)?;
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut copied = 0_u64;
    loop {
        let read = source.read(&mut buffer).map_err(Error::internal)?;
        if read == 0 {
            break;
        }
        copied = copied.checked_add(read as u64).ok_or_else(Error::bad_request)?;
        if copied > entry.size {
            return Err(Error::internal("lazy baseline grew during copy"));
        }
        hash.update(&buffer[..read]);
        output.write_all(&buffer[..read]).map_err(Error::internal)?;
    }
    if copied != entry.size || hex::encode(hash.finalize()) != entry.sha256 {
        return Err(Error::internal("lazy baseline digest mismatch"));
    }
    output.set_permissions(fs::Permissions::from_mode(entry.mode & 0o777)).map_err(Error::internal)?;
    output.sync_all().map_err(Error::internal)?;
    Ok(())
}

/// Private parent directories for `relative`, rejecting symlinked ancestors
/// instead of writing through them.
fn prepare(dest: &Path, relative: &Path) -> Result<PathBuf, Error> {
    let mut directory = dest.to_path_buf();
    if let Some(parent) = relative.parent() {
        for component in parent.components() {
            directory.push(component);
            if !directory.exists() {
                core::private_dir(&directory).map_err(Error::internal)?;
            }
            core::require_directory(&directory).map_err(Error::internal)?;
        }
    }
    let to = dest.join(relative);
    if present(&to)? {
        return Err(Error::internal("duplicate workspace snapshot path"));
    }
    Ok(to)
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
