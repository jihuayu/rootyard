//! Staging, hydration verification and no-replace publication for raw workspace
//! snapshots.
use super::{Origin, Raw, lazy, present};
use crate::{AppState, Error, workspace_lab::core};
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::{
        ffi::OsStrExt,
        fs::{OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};
use uuid::Uuid;

/// The directory one publication created, and nothing else.
///
/// Publication is no-replace, so a directory this guard owns cannot have existed
/// before the call; a pre-existing destination is never touched because it is
/// never published over. A dropped guard removes exactly that directory.
///
/// Ownership and durability are separate concerns: callers must [`keep`] the
/// tree *before* awaiting a COMMIT, not after. A dropped connection at COMMIT
/// cannot distinguish "rolled back" from "committed but the response was lost",
/// so deleting on a commit error would delete a tree the database already
/// references. A tree kept before an ambiguous COMMIT is either referenced or
/// left orphaned under the service-owned checkpoint/lower directory; orphaned
/// trees are unreferenced single-call directories and must be reconciled by
/// maintenance, never by the request path. SQL errors *before* COMMIT are a
/// definite rollback; those keep the guard armed and clean the tree up.
///
/// [`keep`]: Published::keep
pub(in crate::workspaces) struct Published {
    dest: PathBuf,
    kept: bool,
}

impl Published {
    fn new(dest: PathBuf) -> Self {
        Self { dest, kept: false }
    }

    /// Disarm the guard: retain the tree from here on. Call this immediately
    /// before the COMMIT is sent, so an ambiguous commit outcome retains a tree
    /// that may already be referenced by a committed row.
    pub(in crate::workspaces) fn keep(mut self) {
        self.kept = true;
    }

    pub(in crate::workspaces) async fn cleanup(mut self) {
        if !self.kept {
            self.kept = true;
            super::super::cleanup::cleanup_paths_async(Some(self.dest.clone()), None, true).await;
        }
    }
}

impl Drop for Published {
    fn drop(&mut self) {
        if self.kept {
            return;
        }
        super::super::cleanup::cleanup_paths_on_drop(Some(self.dest.clone()), None, true);
    }
}

/// Copy a raw snapshot into a new private tree and publish it at `dest`.
///
/// The tree is staged next to `dest`, synced and published with a no-replace
/// rename, so an existing `dest` is never overwritten, replaced or removed. On
/// failure only the staging directory and a directory this very call published
/// are cleaned up; the returned guard owns the published directory until it is
/// kept. Only lower bytes, upper bytes and verified lazy-cache bytes are read;
/// the mount is never opened.
pub(in crate::workspaces) fn copy(state: &AppState, raw: &Raw, dest: &Path) -> Result<Published, Error> {
    let reader = if raw.hydrates {
        Some(lazy::Reader::open(state, raw.id)?.ok_or_else(|| Error::internal("lazy baseline manifest missing"))?)
    } else {
        None
    };
    let mut hydrate = |dest: &Path, relative: &Path, entry: &core::Entry, total: &mut u64| match &reader {
        Some(reader) => {
            let source = reader
                .file(relative)
                .map_err(Error::internal)?
                .ok_or_else(|| Error::internal("lazy baseline entry missing"))?;
            copy_hydrated(dest, relative, entry, source, total)
        }
        None => Err(Error::internal("lazy baseline reader missing")),
    };
    copy_into(raw, dest, &mut hydrate)
}

/// Stage and publish `raw` at `dest`, returning the guard that owns the
/// directory this call created. `hydrate` is injected so unit tests can
/// materialise lazy entries without a network or a live mount.
pub(in crate::workspaces) fn copy_into(
    raw: &Raw,
    dest: &Path,
    hydrate: &mut dyn FnMut(&Path, &Path, &core::Entry, &mut u64) -> Result<(), Error>,
) -> Result<Published, Error> {
    raw.validate()?;
    let parent = dest.parent().ok_or_else(Error::bad_request)?;
    fs::create_dir_all(parent).map_err(Error::internal)?;
    let staging = parent.join(format!(".snapshot-{}", Uuid::new_v4()));
    core::private_dir(&staging).map_err(Error::internal)?;
    let outcome = materialize(raw, &staging, hydrate).and_then(|()| publish(&staging, dest));
    if outcome.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    outcome
}

/// Sync a fully staged tree and publish it at `dest` without replacing anything.
pub(in crate::workspaces) fn publish(staging: &Path, dest: &Path) -> Result<Published, Error> {
    let parent = dest.parent().ok_or_else(Error::bad_request)?;
    core::sync_tree(staging).map_err(Error::internal)?;
    rename_no_replace(staging, dest)?;
    // The guard exists as soon as the rename succeeded, so even a failing
    // parent sync removes the directory instead of leaving it behind.
    let published = Published::new(dest.to_path_buf());
    File::open(parent).and_then(|directory| directory.sync_all()).map_err(Error::internal)?;
    Ok(published)
}

/// Atomically rename `from` to `to`, failing when `to` already exists.
///
/// `RENAME_NOREPLACE` is the only way to make "publish this directory only if
/// the name is still free" atomic; a stat followed by `rename` would let another
/// publisher replace a confirmed checkpoint in between.
fn rename_no_replace(from: &Path, to: &Path) -> Result<(), Error> {
    let from_c = CString::new(from.as_os_str().as_bytes()).map_err(Error::internal)?;
    let to_c = CString::new(to.as_os_str().as_bytes()).map_err(Error::internal)?;
    let result = unsafe {
        libc::renameat2(libc::AT_FDCWD, from_c.as_ptr(), libc::AT_FDCWD, to_c.as_ptr(), libc::RENAME_NOREPLACE)
    };
    if result == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::EINVAL) | Some(libc::ENOSYS) | Some(libc::ENOTSUP) => {
            Err(Error::internal("workspace snapshot publication needs RENAME_NOREPLACE support"))
        }
        Some(libc::EEXIST) | Some(libc::ENOTEMPTY) => {
            Err(Error::internal("workspace snapshot destination already exists"))
        }
        _ => Err(Error::internal(error)),
    }
}

/// Copy every selected entry from its origin. `hydrate` is injected so unit
/// tests can materialise lazy entries without a network or a live mount.
pub(in crate::workspaces) fn materialize(
    raw: &Raw,
    dest: &Path,
    hydrate: &mut dyn FnMut(&Path, &Path, &core::Entry, &mut u64) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut total = 0_u64;
    for (relative, (origin, entry)) in &raw.merged {
        match origin {
            Origin::Upper => {
                core::copy_single_entry(&raw.upper, dest, relative, &mut total).map_err(Error::internal)?
            }
            Origin::Lower => {
                core::copy_single_entry(&raw.lower, dest, relative, &mut total).map_err(Error::internal)?
            }
            Origin::Lazy if entry.kind != "file" || relative.starts_with(".git") => {
                core::copy_single_entry(&raw.lower, dest, relative, &mut total).map_err(Error::internal)?
            }
            Origin::Lazy => hydrate(dest, relative, entry, &mut total)?,
        }
    }
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
pub(in crate::workspaces) fn copy_hydrated(
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
