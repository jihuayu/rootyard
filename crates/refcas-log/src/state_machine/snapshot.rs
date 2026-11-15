use std::collections::BTreeMap;
#[cfg(unix)]
use std::fs::File;
use std::fs::OpenOptions;
use std::io::{self, Cursor, Write};
use std::path::{Path, PathBuf};

use openraft::{BasicNode, LogId, Snapshot, SnapshotMeta, StoredMembership};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::fault::{FaultController, FaultPoint};
use crate::fixture::verify_same_device;
use crate::state_machine::codec::{
    MAX_KV_KEY_BYTES, MAX_KV_VAL_BYTES, hex_encode, is_valid_sha256_hex, sm_kv_checksum, validate_digest_and_boundary,
};
use crate::state_machine::store::{
    K_APPLIED_COUNT, K_LAST_APPLIED, K_LAST_MEMBERSHIP, K_SNAP_BASE_BOUNDARY_DIGEST, K_SNAP_BASE_LOG_ID,
    K_STATE_DIGEST, SmInner, ZERO_DIGEST_HEX, read_applied_state, read_boundary_entry_digest_hex, read_kv_map,
};
use crate::{E, LogTypeConfig, Res, get_meta, idx_to_i64, je, meta, set_meta};

pub(crate) const SNAPSHOT_FORMAT: &str = "rootyard-refcas-snapshot/1";
pub(crate) const SNAPSHOTS_DIR: &str = "snapshots";
pub(crate) const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;

pub(crate) const K_ACTIVE_SNAP_FILE: &str = "active_snapshot_file";
pub(crate) const K_ACTIVE_SNAP_SHA256: &str = "active_snapshot_sha256";
pub(crate) const K_ACTIVE_SNAP_META: &str = "active_snapshot_meta";
pub(crate) const K_SNAP_GEN: &str = "snapshot_generation";

/// Self-verifying persisted snapshot payload transferred across Raft nodes and stored on disk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotEnvelope {
    pub format: String,
    pub node_id: u64,
    pub generation: u64,
    pub meta: SnapshotMeta<u64, BasicNode>,
    pub last_applied: Option<LogId<u64>>,
    pub last_membership: StoredMembership<u64, BasicNode>,
    pub state_digest_hex: String,
    pub applied_count: u64,
    pub boundary_entry_digest_hex: Option<String>,
    pub kv: BTreeMap<String, String>,
    pub payload_sha256_hex: String,
}

impl SnapshotEnvelope {
    /// Computes canonical SHA-256 digest over all payload fields (excluding `payload_sha256_hex`).
    pub fn compute_payload_sha256(&self) -> Res<String> {
        let mut copy = self.clone();
        copy.payload_sha256_hex.clear();
        let bytes = serde_json::to_vec(&copy).map_err(|e| E::Codec(format!("snapshot digest encode: {e}")))?;
        Ok(hex_encode(&Sha256::digest(&bytes)))
    }

    /// Verifies format marker, internal digest/boundary formats, embedded digest, and metadata consistency.
    pub fn verify_integrity(&self) -> Res<()> {
        if self.format != SNAPSHOT_FORMAT {
            return Err(E::Refused(format!("unknown snapshot format {:?}; expected {SNAPSHOT_FORMAT}", self.format)));
        }
        if self.last_applied != self.meta.last_log_id {
            return Err(E::Refused("snapshot envelope last_applied mismatches meta.last_log_id".into()));
        }
        if self.last_membership != self.meta.last_membership {
            return Err(E::Refused("snapshot envelope membership mismatches meta.last_membership".into()));
        }
        validate_digest_and_boundary(
            &self.state_digest_hex,
            self.last_applied.as_ref(),
            self.boundary_entry_digest_hex.as_deref(),
        )?;
        if !is_valid_sha256_hex(&self.payload_sha256_hex) {
            return Err(E::Codec("invalid snapshot payload_sha256_hex format".into()));
        }
        let expected = self.compute_payload_sha256()?;
        if expected != self.payload_sha256_hex {
            return Err(E::Codec(format!(
                "snapshot payload checksum mismatch: expected {}, got {}",
                expected, self.payload_sha256_hex
            )));
        }
        Ok(())
    }
}

struct StagingCleanupGuard {
    path: Option<PathBuf>,
}

impl StagingCleanupGuard {
    fn disarm(&mut self) {
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
fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

struct StageSpec<'a> {
    snapshots_dir: &'a Path,
    store_dir: &'a Path,
    pending_name: &'a str,
    final_name: &'a str,
    write_point: FaultPoint,
    sync_point: FaultPoint,
}

fn stage_and_sync_file(
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

fn validate_safe_filename(name: &str) -> Res<()> {
    if name.is_empty() || name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(E::Refused(format!("invalid snapshot filename {name:?}")));
    }
    Ok(())
}

fn cleanup_candidate_after_commit_err(conn: &Connection, snapshots_dir: &Path, final_name: &str) {
    // Only unlink the candidate if committed SQLite state proves another (or no) file is active.
    if let Ok(active) = get_meta(conn, K_ACTIVE_SNAP_FILE)
        && active.as_deref() != Some(final_name)
    {
        let _ = std::fs::remove_file(snapshots_dir.join(final_name));
    }
}

fn commit_staged_snapshot(
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

fn sweep_old_snapshots(snapshots_dir: &Path, keep_name: &str) {
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

pub(crate) fn verify_on_open(conn: &Connection, store_dir: &Path, _node_id: u64) -> Res<()> {
    let fname = get_meta(conn, K_ACTIVE_SNAP_FILE)?;
    let expected_sha = get_meta(conn, K_ACTIVE_SNAP_SHA256)?;
    let expected_meta: Option<SnapshotMeta<u64, BasicNode>> = meta(conn, K_ACTIVE_SNAP_META)?;

    match (fname, expected_sha, expected_meta) {
        (None, None, None) => Ok(()),
        (Some(fname), Some(sha), Some(snap_meta)) => {
            validate_safe_filename(&fname)?;
            let snap_path = store_dir.join(SNAPSHOTS_DIR).join(&fname);
            let md = std::fs::metadata(&snap_path).map_err(|e| {
                E::Refused(format!("active snapshot {} missing or unreadable: {e}", snap_path.display()))
            })?;
            if !md.is_file() {
                return Err(E::Refused(format!("active snapshot {} is not a file", snap_path.display())));
            }
            if md.len() as usize > MAX_SNAPSHOT_BYTES {
                return Err(E::Refused("active snapshot file exceeds size ceiling".into()));
            }
            verify_same_device(store_dir, &snap_path)?;
            let raw = std::fs::read(&snap_path)?;
            let actual_sha = hex_encode(&Sha256::digest(&raw));
            if actual_sha != sha {
                return Err(E::Codec(format!(
                    "active snapshot {} sha256 mismatch: expected {sha}, got {actual_sha}",
                    snap_path.display()
                )));
            }
            let envelope: SnapshotEnvelope = serde_json::from_slice(&raw)
                .map_err(|e| E::Codec(format!("corrupt active snapshot {}: {e}", snap_path.display())))?;
            envelope.verify_integrity()?;
            if envelope.meta != snap_meta {
                return Err(E::Refused("active snapshot file metadata mismatches sqlite metadata".into()));
            }
            let (last_applied, _) = read_applied_state(conn)?;
            if last_applied < snap_meta.last_log_id {
                return Err(E::Refused(format!(
                    "sqlite last_applied {last_applied:?} precedes active snapshot {:?}",
                    snap_meta.last_log_id
                )));
            }
            Ok(())
        }
        _ => Err(E::Refused("inconsistent active snapshot metadata markers in sm.sqlite3".into())),
    }
}

pub(crate) fn build_snapshot_blocking(inner: &mut SmInner) -> Res<Snapshot<LogTypeConfig>> {
    let (last_applied, last_membership) = read_applied_state(&inner.conn)?;
    let state_digest_hex = get_meta(&inner.conn, K_STATE_DIGEST)?.unwrap_or_else(|| ZERO_DIGEST_HEX.to_owned());
    let applied_count: u64 = meta(&inner.conn, K_APPLIED_COUNT)?.unwrap_or(0);
    let boundary_entry_digest_hex = read_boundary_entry_digest_hex(&inner.conn, last_applied)?;
    let kv = read_kv_map(&inner.conn)?;
    let cur_gen: u64 = meta(&inner.conn, K_SNAP_GEN)?.unwrap_or(0);
    let next_gen = cur_gen.saturating_add(1);

    let snapshot_id = match last_applied {
        Some(lid) => format!("snap-{}-{}-g{next_gen}", lid.leader_id.term, lid.index),
        None => format!("snap-empty-g{next_gen}"),
    };
    let snap_meta = SnapshotMeta { last_log_id: last_applied, last_membership: last_membership.clone(), snapshot_id };

    let mut envelope = SnapshotEnvelope {
        format: SNAPSHOT_FORMAT.to_owned(),
        node_id: inner.node_id,
        generation: next_gen,
        meta: snap_meta.clone(),
        last_applied,
        last_membership,
        state_digest_hex,
        applied_count,
        boundary_entry_digest_hex,
        kv,
        payload_sha256_hex: String::new(),
    };
    envelope.payload_sha256_hex = envelope.compute_payload_sha256()?;

    let bytes = serde_json::to_vec(&envelope).map_err(|e| E::Codec(format!("encode snapshot: {e}")))?;
    if bytes.len() > MAX_SNAPSHOT_BYTES {
        return Err(E::Refused("serialized snapshot exceeds byte ceiling".into()));
    }
    let file_sha = hex_encode(&Sha256::digest(&bytes));
    let final_name = format!("snap-{next_gen:08}-{}.snap", &file_sha[..12]);
    let snapshots_dir = inner.dir.join(SNAPSHOTS_DIR);
    let fault = inner.fault.clone();
    let store_dir = inner.dir.clone();

    let pending_name = format!("pending-build-{next_gen}.snap");
    let spec = StageSpec {
        snapshots_dir: &snapshots_dir,
        store_dir: &store_dir,
        pending_name: &pending_name,
        final_name: &final_name,
        write_point: FaultPoint::SnapshotBuildWriteEnospc,
        sync_point: FaultPoint::SnapshotBuildSync,
    };
    let (_final_path, guard) = stage_and_sync_file(&spec, &bytes, &fault)?;

    let meta_json = je(&snap_meta)?;
    commit_staged_snapshot(
        inner,
        &snapshots_dir,
        &final_name,
        guard,
        Some(FaultPoint::SnapshotBuildPostCommitSync),
        |tx| {
            set_meta(tx, K_ACTIVE_SNAP_FILE, Some(&final_name))?;
            set_meta(tx, K_ACTIVE_SNAP_SHA256, Some(&file_sha))?;
            set_meta(tx, K_ACTIVE_SNAP_META, Some(&meta_json))?;
            set_meta(tx, K_SNAP_GEN, Some(&next_gen.to_string()))?;
            Ok(())
        },
    )?;

    Ok(Snapshot { meta: snap_meta, snapshot: Box::new(Cursor::new(bytes)) })
}

pub(crate) fn install_snapshot_blocking(
    inner: &mut SmInner,
    snap_meta: SnapshotMeta<u64, BasicNode>,
    raw: Vec<u8>,
) -> Res<()> {
    if raw.len() > MAX_SNAPSHOT_BYTES {
        return Err(E::Refused("incoming snapshot exceeds byte ceiling".into()));
    }
    let envelope: SnapshotEnvelope =
        serde_json::from_slice(&raw).map_err(|e| E::Codec(format!("decode incoming snapshot: {e}")))?;
    envelope.verify_integrity()?;
    if envelope.meta != snap_meta {
        return Err(E::Refused("incoming snapshot envelope metadata does not match RPC meta".into()));
    }
    for (k, v) in &envelope.kv {
        if k.len() > MAX_KV_KEY_BYTES || v.len() > MAX_KV_VAL_BYTES {
            return Err(E::Refused("incoming snapshot KV entry exceeds byte limits".into()));
        }
    }
    let file_sha = hex_encode(&Sha256::digest(&raw));

    let (cur_applied, cur_membership) = read_applied_state(&inner.conn)?;
    let cur_state_digest = get_meta(&inner.conn, K_STATE_DIGEST)?.unwrap_or_else(|| ZERO_DIGEST_HEX.to_owned());
    let cur_applied_count: u64 = meta(&inner.conn, K_APPLIED_COUNT)?.unwrap_or(0);
    let cur_active_file = get_meta(&inner.conn, K_ACTIVE_SNAP_FILE)?;
    let cur_active_sha = get_meta(&inner.conn, K_ACTIVE_SNAP_SHA256)?;
    let cur_active_meta: Option<SnapshotMeta<u64, BasicNode>> = meta(&inner.conn, K_ACTIVE_SNAP_META)?;
    let cur_gen: u64 = meta(&inner.conn, K_SNAP_GEN)?.unwrap_or(0);

    if cur_active_meta.as_ref() == Some(&snap_meta) {
        let same_sha = cur_active_sha.as_deref() == Some(file_sha.as_str());
        let same_digest = cur_state_digest == envelope.state_digest_hex;
        let same_file = cur_active_file.as_ref().is_some_and(|f| {
            std::fs::read(inner.dir.join(SNAPSHOTS_DIR).join(f))
                .map(|b| hex_encode(&Sha256::digest(&b)) == file_sha)
                .unwrap_or(false)
        });
        if same_sha && same_digest && same_file {
            return Ok(());
        }
        return Err(E::Refused("conflicting snapshot replay for already-installed snapshot_id".into()));
    }

    if snap_meta.last_log_id < cur_applied {
        return Err(E::Refused(format!(
            "refusing regressive snapshot {:?} older than applied state {:?}",
            snap_meta.last_log_id, cur_applied
        )));
    }
    if cur_applied.is_some()
        && snap_meta.last_log_id == cur_applied
        && (envelope.state_digest_hex != cur_state_digest
            || envelope.last_membership != cur_membership
            || envelope.applied_count != cur_applied_count)
    {
        return Err(E::Refused("conflicting snapshot state at equal last_applied log id".into()));
    }

    let next_gen = cur_gen.saturating_add(1);
    let final_name = format!("snap-{next_gen:08}-{}.snap", &file_sha[..12]);
    let snapshots_dir = inner.dir.join(SNAPSHOTS_DIR);
    let store_dir = inner.dir.clone();
    let fault = inner.fault.clone();

    let pending_name = format!("pending-install-{next_gen}.snap");
    let spec = StageSpec {
        snapshots_dir: &snapshots_dir,
        store_dir: &store_dir,
        pending_name: &pending_name,
        final_name: &final_name,
        write_point: FaultPoint::SnapshotInstallWriteEnospc,
        sync_point: FaultPoint::SnapshotInstallStageSync,
    };
    let (_final_path, guard) = stage_and_sync_file(&spec, &raw, &fault)?;

    fault.pause_install_if_armed();

    let meta_json = je(&snap_meta)?;
    let last_json = snap_meta.last_log_id.as_ref().map(je).transpose()?;
    let mem_json = je(&snap_meta.last_membership)?;
    let base_idx = match snap_meta.last_log_id {
        Some(lid) => idx_to_i64(lid.index)?,
        None => 0,
    };

    let install_fault = fault.clone();
    commit_staged_snapshot(
        inner,
        &snapshots_dir,
        &final_name,
        guard,
        Some(FaultPoint::SnapshotInstallPostCommitSync),
        |tx| {
            tx.execute("DELETE FROM sm_kv", [])?;
            for (k, v) in &envelope.kv {
                let csum = sm_kv_checksum(k, v, base_idx);
                tx.execute("INSERT INTO sm_kv(k,v,last_idx,checksum) VALUES(?1,?2,?3,?4)", (k, v, base_idx, csum))?;
            }
            tx.execute("DELETE FROM sm_entries", [])?;
            set_meta(tx, K_LAST_APPLIED, last_json.as_deref())?;
            set_meta(tx, K_LAST_MEMBERSHIP, Some(&mem_json))?;
            set_meta(tx, K_STATE_DIGEST, Some(&envelope.state_digest_hex))?;
            set_meta(tx, K_APPLIED_COUNT, Some(&envelope.applied_count.to_string()))?;
            set_meta(tx, K_SNAP_BASE_LOG_ID, last_json.as_deref())?;
            set_meta(tx, K_SNAP_BASE_BOUNDARY_DIGEST, envelope.boundary_entry_digest_hex.as_deref())?;
            set_meta(tx, K_ACTIVE_SNAP_FILE, Some(&final_name))?;
            set_meta(tx, K_ACTIVE_SNAP_SHA256, Some(&file_sha))?;
            set_meta(tx, K_ACTIVE_SNAP_META, Some(&meta_json))?;
            set_meta(tx, K_SNAP_GEN, Some(&next_gen.to_string()))?;

            install_fault.check(FaultPoint::SnapshotInstallCommitSync)?;
            Ok(())
        },
    )?;

    Ok(())
}

pub(crate) fn read_current_snapshot_blocking(inner: &SmInner) -> Res<Option<Snapshot<LogTypeConfig>>> {
    let fname = get_meta(&inner.conn, K_ACTIVE_SNAP_FILE)?;
    let sha = get_meta(&inner.conn, K_ACTIVE_SNAP_SHA256)?;
    let snap_meta: Option<SnapshotMeta<u64, BasicNode>> = meta(&inner.conn, K_ACTIVE_SNAP_META)?;
    match (fname, sha, snap_meta) {
        (None, None, None) => Ok(None),
        (Some(fname), Some(expected_sha), Some(snap_meta)) => {
            validate_safe_filename(&fname)?;
            let snap_path = inner.dir.join(SNAPSHOTS_DIR).join(&fname);
            verify_same_device(&inner.dir, &snap_path)?;
            let raw = std::fs::read(&snap_path)?;
            if raw.len() > MAX_SNAPSHOT_BYTES {
                return Err(E::Refused("stored active snapshot exceeds byte ceiling".into()));
            }
            if hex_encode(&Sha256::digest(&raw)) != expected_sha {
                return Err(E::Codec("stored active snapshot sha256 mismatch on read".into()));
            }
            let envelope: SnapshotEnvelope = serde_json::from_slice(&raw)
                .map_err(|e| E::Codec(format!("corrupt stored active snapshot on read: {e}")))?;
            envelope.verify_integrity()?;
            if envelope.meta != snap_meta {
                return Err(E::Refused("stored active snapshot meta mismatch on read".into()));
            }
            Ok(Some(Snapshot { meta: snap_meta, snapshot: Box::new(Cursor::new(raw)) }))
        }
        _ => Err(E::Refused("inconsistent active snapshot metadata markers on read".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::META_SCHEMA;

    #[test]
    fn commit_err_cleanup_only_deletes_unreferenced_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let snap_dir = dir.path().join(SNAPSHOTS_DIR);
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
    }
}
