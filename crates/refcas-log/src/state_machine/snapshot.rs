use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::Path;

use openraft::{BasicNode, Snapshot, SnapshotMeta};
use rusqlite::Connection;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::fault::FaultPoint;
use crate::fixture::verify_same_device;
use crate::state_machine::app::ApplicationStateMachine;
use crate::state_machine::app_store::write_app_row;
use crate::state_machine::codec::{MAX_KV_KEY_BYTES, MAX_KV_VAL_BYTES, hex_encode, sm_kv_checksum};
use crate::state_machine::snapshot_app::{
    ApplicationSnapshotEnvelope, SNAPSHOT_FORMAT_APP, build_application_body, restore_application_body,
};
use crate::state_machine::snapshot_stage::{
    StageSpec, commit_staged_snapshot, stage_and_sync_file, validate_safe_filename,
};
use crate::state_machine::store::{
    K_APPLIED_COUNT, K_LAST_APPLIED, K_LAST_MEMBERSHIP, K_SNAP_BASE_BOUNDARY_DIGEST, K_SNAP_BASE_LOG_ID,
    K_STATE_DIGEST, SmInner, ZERO_DIGEST_HEX, read_applied_state, read_boundary_entry_digest_hex, read_kv_map,
};
use crate::{E, LogTypeConfig, Res, get_meta, idx_to_i64, je, meta, set_meta};

use crate::state_machine::snapshot_v1::SNAPSHOT_FORMAT;
pub use crate::state_machine::snapshot_v1::SnapshotEnvelope;

pub(crate) const SNAPSHOTS_DIR: &str = "snapshots";
pub(crate) const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;

pub(crate) const K_ACTIVE_SNAP_FILE: &str = "active_snapshot_file";
pub(crate) const K_ACTIVE_SNAP_SHA256: &str = "active_snapshot_sha256";
pub(crate) const K_ACTIVE_SNAP_META: &str = "active_snapshot_meta";
pub(crate) const K_SNAP_GEN: &str = "snapshot_generation";

/// Parsed snapshot format selected by the canonical `format` marker.
enum DecodedSnapshot {
    Legacy(SnapshotEnvelope),
    Application(ApplicationSnapshotEnvelope),
}

#[derive(Deserialize)]
struct FormatProbe {
    format: String,
}

fn decode_snapshot(raw: &[u8]) -> Res<DecodedSnapshot> {
    let probe: FormatProbe =
        serde_json::from_slice(raw).map_err(|e| E::Codec(format!("corrupt snapshot envelope: {e}")))?;
    match probe.format.as_str() {
        SNAPSHOT_FORMAT => {
            let envelope: SnapshotEnvelope =
                serde_json::from_slice(raw).map_err(|e| E::Codec(format!("corrupt legacy snapshot: {e}")))?;
            Ok(DecodedSnapshot::Legacy(envelope))
        }
        SNAPSHOT_FORMAT_APP => {
            let envelope: ApplicationSnapshotEnvelope =
                serde_json::from_slice(raw).map_err(|e| E::Codec(format!("corrupt application snapshot: {e}")))?;
            Ok(DecodedSnapshot::Application(envelope))
        }
        other => Err(E::Refused(format!("unknown snapshot format marker {other:?}"))),
    }
}

pub(crate) fn verify_on_open(
    conn: &Connection,
    store_dir: &Path,
    _node_id: u64,
    app: Option<&dyn ApplicationStateMachine>,
) -> Res<()> {
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
            match decode_snapshot(&raw)? {
                DecodedSnapshot::Legacy(envelope) => {
                    if app.is_some() {
                        return Err(E::Refused(
                            "active snapshot is legacy KV format but state machine is in application mode".into(),
                        ));
                    }
                    envelope.verify_integrity()?;
                    if envelope.meta != snap_meta {
                        return Err(E::Refused("active snapshot file metadata mismatches sqlite metadata".into()));
                    }
                }
                DecodedSnapshot::Application(envelope) => {
                    let Some(app) = app else {
                        return Err(E::Refused(
                            "active snapshot is application format but state machine is in KV mode".into(),
                        ));
                    };
                    envelope.verify_integrity()?;
                    if envelope.meta != snap_meta {
                        return Err(E::Refused(
                            "active application snapshot metadata mismatches sqlite metadata".into(),
                        ));
                    }
                    let mut staged = app.clone_box();
                    restore_application_body(&envelope.app, staged.as_mut(), snap_meta.last_log_id)?;
                }
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
    let cur_gen: u64 = meta(&inner.conn, K_SNAP_GEN)?.unwrap_or(0);
    let next_gen = cur_gen.saturating_add(1);

    let snapshot_id = match last_applied {
        Some(lid) => format!("snap-{}-{}-g{next_gen}", lid.leader_id.term, lid.index),
        None => format!("snap-empty-g{next_gen}"),
    };
    let snap_meta = SnapshotMeta { last_log_id: last_applied, last_membership: last_membership.clone(), snapshot_id };

    let bytes = if let Some(app) = inner.app.as_ref() {
        let body = build_application_body(app.as_ref(), last_applied)?;
        let mut envelope = ApplicationSnapshotEnvelope {
            format: SNAPSHOT_FORMAT_APP.to_owned(),
            node_id: inner.node_id,
            generation: next_gen,
            meta: snap_meta.clone(),
            last_applied,
            last_membership,
            state_digest_hex,
            applied_count,
            boundary_entry_digest_hex,
            kv: BTreeMap::new(),
            app: body,
            payload_sha256_hex: String::new(),
        };
        envelope.payload_sha256_hex = envelope.compute_payload_sha256()?;
        serde_json::to_vec(&envelope).map_err(|e| E::Codec(format!("encode application snapshot: {e}")))?
    } else {
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
            kv: read_kv_map(&inner.conn)?,
            payload_sha256_hex: String::new(),
        };
        envelope.payload_sha256_hex = envelope.compute_payload_sha256()?;
        serde_json::to_vec(&envelope).map_err(|e| E::Codec(format!("encode snapshot: {e}")))?
    };
    finish_snapshot_build(inner, snap_meta, bytes, next_gen)
}

fn finish_snapshot_build(
    inner: &mut SmInner,
    snap_meta: SnapshotMeta<u64, BasicNode>,
    bytes: Vec<u8>,
    next_gen: u64,
) -> Res<Snapshot<LogTypeConfig>> {
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
    match decode_snapshot(&raw)? {
        DecodedSnapshot::Legacy(envelope) => install_legacy_snapshot(inner, snap_meta, raw, envelope),
        DecodedSnapshot::Application(envelope) => install_application_snapshot(inner, snap_meta, raw, envelope),
    }
}

fn install_legacy_snapshot(
    inner: &mut SmInner,
    snap_meta: SnapshotMeta<u64, BasicNode>,
    raw: Vec<u8>,
    envelope: SnapshotEnvelope,
) -> Res<()> {
    if inner.app.is_some() {
        return Err(E::Refused("application mode refuses a legacy KV snapshot; no empty/KV fallback".into()));
    }
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

fn install_application_snapshot(
    inner: &mut SmInner,
    snap_meta: SnapshotMeta<u64, BasicNode>,
    raw: Vec<u8>,
    envelope: ApplicationSnapshotEnvelope,
) -> Res<()> {
    let Some(live_app) = inner.app.as_ref() else {
        return Err(E::Refused("KV mode refuses an application snapshot; no local/KV fallback".into()));
    };
    envelope.verify_integrity()?;
    if envelope.meta != snap_meta {
        return Err(E::Refused("incoming application snapshot metadata does not match RPC meta".into()));
    }
    let mut staged = live_app.clone_box();
    restore_application_body(&envelope.app, staged.as_mut(), snap_meta.last_log_id)?;
    let file_sha = hex_encode(&Sha256::digest(&raw));

    let (cur_applied, cur_membership) = read_applied_state(&inner.conn)?;
    let cur_state_digest = get_meta(&inner.conn, K_STATE_DIGEST)?.unwrap_or_else(|| ZERO_DIGEST_HEX.to_owned());
    let cur_applied_count: u64 = meta(&inner.conn, K_APPLIED_COUNT)?.unwrap_or(0);
    let cur_app_digest = crate::state_machine::app_store::read_app_row(&inner.conn)?.map(|row| row.state_digest_hex);
    let cur_active_file = get_meta(&inner.conn, K_ACTIVE_SNAP_FILE)?;
    let cur_active_sha = get_meta(&inner.conn, K_ACTIVE_SNAP_SHA256)?;
    let cur_active_meta: Option<SnapshotMeta<u64, BasicNode>> = meta(&inner.conn, K_ACTIVE_SNAP_META)?;
    let cur_gen: u64 = meta(&inner.conn, K_SNAP_GEN)?.unwrap_or(0);

    if cur_active_meta.as_ref() == Some(&snap_meta) {
        let same_sha = cur_active_sha.as_deref() == Some(file_sha.as_str());
        let same_digest = cur_state_digest == envelope.state_digest_hex
            && cur_app_digest.as_deref() == Some(envelope.app.state_digest_hex.as_str());
        let same_file = cur_active_file.as_ref().is_some_and(|f| {
            std::fs::read(inner.dir.join(SNAPSHOTS_DIR).join(f))
                .map(|b| hex_encode(&Sha256::digest(&b)) == file_sha)
                .unwrap_or(false)
        });
        if same_sha && same_digest && same_file {
            return Ok(());
        }
        return Err(E::Refused("conflicting application snapshot replay for already-installed snapshot_id".into()));
    }

    if snap_meta.last_log_id < cur_applied {
        return Err(E::Refused(format!(
            "refusing regressive application snapshot {:?} older than applied state {:?}",
            snap_meta.last_log_id, cur_applied
        )));
    }
    if cur_applied.is_some()
        && snap_meta.last_log_id == cur_applied
        && (envelope.state_digest_hex != cur_state_digest
            || envelope.last_membership != cur_membership
            || envelope.applied_count != cur_applied_count
            || cur_app_digest.as_deref() != Some(envelope.app.state_digest_hex.as_str()))
    {
        return Err(E::Refused("conflicting application snapshot state at equal last_applied log id".into()));
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
    let install_fault = fault.clone();
    commit_staged_snapshot(
        inner,
        &snapshots_dir,
        &final_name,
        guard,
        Some(FaultPoint::SnapshotInstallPostCommitSync),
        |tx| {
            tx.execute("DELETE FROM sm_kv", [])?;
            tx.execute("DELETE FROM sm_entries", [])?;
            write_app_row(tx, staged.as_ref(), snap_meta.last_log_id)?;
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
    inner.app = Some(staged);
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
            match decode_snapshot(&raw)? {
                DecodedSnapshot::Legacy(envelope) => {
                    if inner.app.is_some() {
                        return Err(E::Refused(
                            "stored active snapshot is legacy KV format but state machine is in application mode"
                                .into(),
                        ));
                    }
                    envelope.verify_integrity()?;
                    if envelope.meta != snap_meta {
                        return Err(E::Refused("stored active snapshot meta mismatch on read".into()));
                    }
                }
                DecodedSnapshot::Application(envelope) => {
                    let Some(app) = inner.app.as_ref() else {
                        return Err(E::Refused(
                            "stored active snapshot is application format but state machine is in KV mode".into(),
                        ));
                    };
                    envelope.verify_integrity()?;
                    if envelope.meta != snap_meta {
                        return Err(E::Refused("stored active application snapshot meta mismatch on read".into()));
                    }
                    let mut staged = app.clone_box();
                    restore_application_body(&envelope.app, staged.as_mut(), snap_meta.last_log_id)?;
                }
            }
            Ok(Some(Snapshot { meta: snap_meta, snapshot: Box::new(Cursor::new(raw)) }))
        }
        _ => Err(E::Refused("inconsistent active snapshot metadata markers on read".into())),
    }
}
