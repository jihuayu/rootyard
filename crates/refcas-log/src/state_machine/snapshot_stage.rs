//! Snapshot file staging, SQLite commit coupling, and stale-file sweeping.
//!
//! Pre-commit failures remove only the staged candidate. A commit error after the SQLite commit
//! point may leave the new active metadata/file in place; callers re-read metadata instead of
//! assuming rollback.

#[cfg(unix)]
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use rusqlite::Connection;

use super::snapshot::K_ACTIVE_SNAP_FILE;
use crate::fault::{FaultController, FaultPoint};
use crate::fixture::verify_same_device;
use crate::state_machine::store::SmInner;
use crate::{E, Res, get_meta};

pub(super) struct StagingCleanupGuard {
    path: Option<PathBuf>,
}

impl StagingCleanupGuard {
    pub(super) fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for StagingCleanupGuard {
    fn drop(&mut self) {
        if let Some(p) = self.path.take() {
            let _ = std::fs::remove_file(p);
        }
    }
}

#[cfg(unix)]
pub(super) fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
pub(super) fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

pub(super) struct StageSpec<'a> {
    pub(super) snapshots_dir: &'a Path,
    pub(super) store_dir: &'a Path,
    pub(super) pending_name: &'a str,
    pub(super) final_name: &'a str,
    pub(super) write_point: FaultPoint,
    pub(super) sync_point: FaultPoint,
}

pub(super) fn stage_and_sync_file(
    spec: &StageSpec<'_>,
    bytes: &[u8],
    fault: &FaultController,
) -> Res<(PathBuf, StagingCleanupGuard)> {
    std::fs::create_dir_all(spec.snapshots_dir)?;
    let pending_path = spec.snapshots_dir.join(spec.pending_name);
    let final_path = spec.snapshots_dir.join(spec.final_name);
    let mut guard = StagingCleanupGuard { path: Some(pending_path.clone()) };

    fault.check(spec.write_point)?;
    {
        let mut f = OpenOptions::new().create(true).write(true).truncate(true).open(&pending_path)?;
        f.write_all(bytes)?;
        f.flush()?;
        fault.check(spec.sync_point)?;
        f.sync_all()?;
    }
    std::fs::rename(&pending_path, &final_path)?;
    guard.path = Some(final_path.clone());
    sync_dir(spec.snapshots_dir)?;
    verify_same_device(spec.store_dir, &final_path)?;
    Ok((final_path, guard))
}

pub(super) fn validate_safe_filename(name: &str) -> Res<()> {
    if name.is_empty() || name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(E::Refused(format!("invalid snapshot filename {name:?}")));
    }
    Ok(())
}

pub(super) fn cleanup_candidate_after_commit_err(conn: &Connection, snapshots_dir: &Path, final_name: &str) {
    // Only unlink the candidate if committed SQLite state proves another (or no) file is active.
    if let Ok(active) = get_meta(conn, K_ACTIVE_SNAP_FILE)
        && active.as_deref() != Some(final_name)
    {
        let _ = std::fs::remove_file(snapshots_dir.join(final_name));
    }
}

pub(super) fn commit_staged_snapshot(
    inner: &mut SmInner,
    snapshots_dir: &Path,
    final_name: &str,
    mut guard: StagingCleanupGuard,
    post_commit_point: Option<FaultPoint>,
    populate: impl FnOnce(&rusqlite::Transaction<'_>) -> Res<()>,
) -> Res<()> {
    let fault = inner.fault.clone();
    let tx = inner.tx()?;
    populate(&tx)?;
    // Disarm unconditional StagingCleanupGuard before SQLite COMMIT: if COMMIT fails after the
    // commit point (e.g. IOERR_DIR_FSYNC), active metadata may already reference `final_name`.
    guard.disarm();
    if let Err(err) = tx.commit() {
        cleanup_candidate_after_commit_err(&inner.conn, snapshots_dir, final_name);
        return Err(err.into());
    }
    if let Some(point) = post_commit_point {
        fault.check(point)?;
    }
    sweep_old_snapshots(snapshots_dir, final_name);
    Ok(())
}

pub(super) fn sweep_old_snapshots(snapshots_dir: &Path, keep_name: &str) {
    let Ok(entries) = std::fs::read_dir(snapshots_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name_str) = name.to_str() else { continue };
        if name_str != keep_name && (name_str.starts_with("snap-") || name_str.starts_with("pending-")) {
            let _ = std::fs::remove_file(entry.path());
        }
    }
    let _ = sync_dir(snapshots_dir);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::META_SCHEMA;
    use crate::state_machine::store::K_LAST_APPLIED;
    use crate::{meta, set_meta};

    #[test]
    fn commit_err_cleanup_only_deletes_unreferenced_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let snap_dir = dir.path().join("snapshots");
        std::fs::create_dir_all(&snap_dir).unwrap();
        let old = snap_dir.join("snap-0001-old.snap");
        let new_cand = snap_dir.join("snap-0002-new.snap");
        std::fs::write(&old, b"old").unwrap();
        std::fs::write(&new_cand, b"new").unwrap();
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(META_SCHEMA).unwrap();

        set_meta(&conn, K_ACTIVE_SNAP_FILE, Some("snap-0002-new.snap")).unwrap();
        cleanup_candidate_after_commit_err(&conn, &snap_dir, "snap-0002-new.snap");
        assert!(new_cand.exists(), "committed active candidate MUST be preserved after ambiguous commit error");

        set_meta(&conn, K_ACTIVE_SNAP_FILE, Some("snap-0001-old.snap")).unwrap();
        cleanup_candidate_after_commit_err(&conn, &snap_dir, "snap-0002-new.snap");
        assert!(!new_cand.exists(), "proven-unreferenced candidate should be removed");
        assert!(old.exists(), "prior active snapshot must stay intact");
        let _: Option<String> = meta(&conn, K_LAST_APPLIED).unwrap();
    }
}
