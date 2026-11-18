//! Standard `schema 151` / `format 30` full PostgreSQL (`pg_dump`) + OpenDAL Blob closure
//! + live 3-voter mTLS Raft paired backup and archive verification (#153).

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio_postgres::IsolationLevel;
use uuid::Uuid;

use crate::blob_store::opendal::BlobStore;
use crate::config::Config;
use crate::ref_store::GitObjectFormat;
use crate::ref_store::core::state_machine::{AppliedLogId, RefCasStateMachine};

use super::backup::{reconcile_pg_raft_repositories, stream_sha256_file};
use super::closure_bind::verify_blob_closure_against_durable_raft;
use super::durable_freeze_gate::DurableFreezeHandle;
use super::mtls_raft::MtlsLiveRaftBackend;
use super::peer_groups::{
    ExpectedGroupCursorCut, PeerGroupBackupInput, extract_peer_expected_cuts, verify_all_group_cursors,
    verify_archived_peer_groups,
};
use super::pg_cutpoint::{ExpectedRaftCut, capture_pg_cutpoint_in_tx, pg_err};
use super::pg_freeze_settings::{drop_ephemeral_backup_role, provision_ephemeral_backup_role};
use super::quorum_wal::DurableRaftBackend;
use super::raft_barrier::SealedArchiveReceipt;
use super::types::{
    BlobArtifactEntry, BlobClosureManifest, COMPLETE_MARKER, MANIFEST_FILE, MAX_MANIFEST_BYTES,
    PAIRED_BACKUP_FORMAT_V1, PairedBackupError, PgCutpointProof, RaftCutpointProof, sha256_json_tagged, validate_hex64,
};

pub use super::format30_boot::restore_and_boot_format30_new_incarnation;

pub const STANDARD_PAIRED_PG_FORMAT: u32 = 30;
pub const STANDARD_SCHEMA_HEAD: i32 = 151;
pub const FORMAT30_SUBDIR: &str = "format30";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Format30PgArchiveBinding {
    pub format: u32,
    pub inner_backup_id: Uuid,
    pub schema_head: i32,
    pub schema_contract_sha256: String,
    pub metadata_dump_sha256: String,
    pub inner_complete_sha256: String,
    pub repository_count: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Format30PairedManifest {
    pub format_version: String,
    pub backup_id: Uuid,
    pub created_unix_seconds: u64,
    pub freeze: super::types::FreezePartyStatus,
    pub format30_pg: Format30PgArchiveBinding,
    pub pg_cutpoint: PgCutpointProof,
    pub raft_cutpoint: RaftCutpointProof,
    pub blob_closure: BlobClosureManifest,
    pub paired_cut_digest: String,
}

impl Format30PairedManifest {
    pub fn seal(mut self) -> Result<Self, PairedBackupError> {
        self.paired_cut_digest.clear();
        self.paired_cut_digest = sha256_json_tagged(b"rootyard-format30-paired-manifest-v1", &self)?;
        Ok(self)
    }
}

pub struct Format30PairedBackupRequest<'a> {
    pub backup_id: Uuid,
    pub src_config: &'a Config,
    pub freeze_handle: &'a DurableFreezeHandle,
    pub raft: &'a MtlsLiveRaftBackend,
    pub peer_groups: Vec<PeerGroupBackupInput<'a>>,
    pub store: &'a BlobStore,
    pub staging_dir: &'a Path,
    pub destination: &'a Path,
}

/// Capture a complete `schema 151` / `format 30` PostgreSQL (`pg_dump`) + OpenDAL Blob closure
/// archive via `crate::backup::create` paired with live 3-voter mTLS Raft cutpoints across all groups.
pub async fn create_format30_paired_raft_backup(
    req: Format30PairedBackupRequest<'_>,
) -> Result<(Format30PairedManifest, SealedArchiveReceipt), PairedBackupError> {
    if req.backup_id.is_nil() || req.destination.exists() {
        return Err(PairedBackupError::InvalidArgument("non-nil backup_id and non-existent destination required"));
    }
    let committed_idx = req.raft.committed_quorum_index()?;
    let (snapshot, state_digest) = req.raft.durable_state()?;
    let mem_digest = req.raft.group_membership_digest();
    req.freeze_handle.active_barrier.verify_against_raft_group(
        req.raft.group_id(),
        &mem_digest,
        &snapshot,
        &state_digest,
        true,
    )?;
    if committed_idx < req.freeze_handle.active_barrier.barrier_log_id.index {
        return Err(PairedBackupError::FreezeNotHeld("active 3-voter Raft quorum_commit_index behind barrier"));
    }
    let active_cut = ExpectedGroupCursorCut::from_verified_snapshot(req.raft.group_id(), &snapshot)?;
    let (peer_cuts, peer_proofs) = extract_peer_expected_cuts(req.raft.group_id(), &req.peer_groups)?;

    let parsed_dsn: tokio_postgres::Config = req.src_config.database_url.parse().map_err(pg_err)?;
    let pg_proof = {
        let mut pg_client =
            crate::db::connect_config(parsed_dsn).await.map_err(|e| PairedBackupError::Postgres(e.to_string()))?;
        req.freeze_handle.verify_still_frozen_on(&pg_client, req.raft).await?;
        let tx = pg_client
            .build_transaction()
            .isolation_level(IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .await
            .map_err(pg_err)?;
        let expected = ExpectedRaftCut { active: active_cut.clone(), peers: peer_cuts.clone() };
        let proof = capture_pg_cutpoint_in_tx(&tx, &expected).await?;
        tx.commit().await.map_err(pg_err)?;
        proof
    };
    let applied_log_id = AppliedLogId { term: active_cut.applied_term, index: active_cut.applied_index };
    reconcile_pg_raft_repositories(
        &pg_proof,
        &snapshot,
        applied_log_id,
        &req.freeze_handle.active_barrier.close_receipts,
    )?;

    let work_dir = req.staging_dir.join(format!(".paired-fmt30-{}.partial", req.backup_id));
    if work_dir.exists() {
        fs::remove_dir_all(&work_dir)?;
    }
    fs::create_dir_all(&work_dir)?;

    // Keep `<db>` at `default_transaction_read_only = on` continuously; run `crate::backup::create`
    // via a dedicated ephemeral backup role (`ALTER ROLE ... IN DATABASE ... SET default_transaction_read_only = off`).
    let fmt30_dir = work_dir.join(FORMAT30_SUBDIR);
    let (role_cfg, role_name, db_name) = provision_ephemeral_backup_role(req.src_config).await?;
    let create_res = crate::backup::create(&role_cfg, &fmt30_dir).await;
    let cleanup_res = drop_ephemeral_backup_role(req.src_config, &role_name, &db_name).await;
    create_res.map_err(|e| PairedBackupError::Postgres(format!("format 30 backup::create failed: {e:#}")))?;
    cleanup_res?;
    crate::backup::check(&fmt30_dir).map_err(|_| PairedBackupError::IncompleteCut("inner format 30 check failed"))?;

    let (fmt30_binding, blob_closure) =
        extract_format30_binding_and_closure(&fmt30_dir, &pg_proof, req.store.backend_identity().as_hex())?;
    verify_blob_closure_against_durable_raft(
        &snapshot,
        &req.freeze_handle.active_barrier.backup_holds,
        &blob_closure.entries,
        &pg_proof.repositories,
    )?;

    let mut group_epochs = BTreeMap::from([(req.raft.group_id(), active_cut.group_epoch)]);
    for pc in &peer_cuts {
        group_epochs.insert(pc.group_id, pc.group_epoch);
    }
    let raft_cutpoint = RaftCutpointProof {
        group_id: req.raft.group_id(),
        group_epochs,
        peer_groups: peer_proofs,
        applied_log_id,
        logical_clock_floor: snapshot.body.logical_clock_floor,
        state_digest,
        group_membership_digest: mem_digest,
        snapshot_checksum: snapshot.checksum.clone(),
        snapshot,
        close_receipts: req.freeze_handle.active_barrier.close_receipts.clone(),
        backup_holds: req.freeze_handle.active_barrier.backup_holds.clone(),
    };
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| PairedBackupError::Io(std::io::Error::other(e)))?
        .as_secs();
    let manifest = Format30PairedManifest {
        format_version: PAIRED_BACKUP_FORMAT_V1.to_owned(),
        backup_id: req.backup_id,
        created_unix_seconds: now_unix,
        freeze: req.freeze_handle.active_barrier.status.clone(),
        format30_pg: fmt30_binding,
        pg_cutpoint: pg_proof,
        raft_cutpoint,
        blob_closure,
        paired_cut_digest: String::new(),
    }
    .seal()?;

    let m_bytes = serde_json::to_vec_pretty(&manifest)
        .map_err(|_| PairedBackupError::IncompleteCut("format 30 paired manifest serialize"))?;
    if m_bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(PairedBackupError::InvalidArgument("manifest exceeds MAX_MANIFEST_BYTES"));
    }
    let m_path = work_dir.join(MANIFEST_FILE);
    write_synced(&m_path, &m_bytes)?;
    let (_, m_hex) = stream_sha256_file(&m_path)?;
    write_synced(&work_dir.join(COMPLETE_MARKER), m_hex.as_bytes())?;
    fs::rename(&work_dir, req.destination)?;

    let verified = verify_format30_paired_archive(req.destination, Some(req.store.backend_identity().as_hex()))?;
    let (_, complete_marker_sha256) = stream_sha256_file(&req.destination.join(COMPLETE_MARKER))?;
    let root_ids = req.freeze_handle.active_barrier.backup_holds.iter().map(|h| h.root_id).collect();
    let hold_ids =
        req.freeze_handle.active_barrier.backup_holds.iter().flat_map(|h| h.hold_ids.iter().copied()).collect();
    let seal_receipt = SealedArchiveReceipt {
        backup_id: verified.backup_id,
        barrier_id: req.freeze_handle.active_barrier.barrier_id,
        fenced_deleter_epoch: req.freeze_handle.active_barrier.status.fenced_deleter_epoch,
        app_fence_seq: req.freeze_handle.active_barrier.status.app_fence_seq,
        barrier_log_id: req.freeze_handle.active_barrier.barrier_log_id,
        barrier_state_digest: req.freeze_handle.active_barrier.barrier_state_digest.clone(),
        paired_cut_digest: verified.paired_cut_digest.clone(),
        complete_marker_sha256,
        root_ids,
        hold_ids,
        receipt_seal: String::new(),
    }
    .mint()?;
    Ok((manifest, seal_receipt))
}

/// Independently verify both outer paired manifest/COMPLETE and inner `format 30` (`schema 151`)
/// `metadata.dump` + `blob/...` + active & peer 3-voter Raft cutpoints.
pub fn verify_format30_paired_archive(
    archive_dir: &Path,
    expected_backend_identity: Option<&str>,
) -> Result<Format30PairedManifest, PairedBackupError> {
    let m_path = archive_dir.join(MANIFEST_FILE);
    let c_path = archive_dir.join(COMPLETE_MARKER);
    let (_, actual_m_hex) =
        stream_sha256_file(&m_path).map_err(|_| PairedBackupError::IncompleteCut("missing outer manifest.json"))?;
    let marker =
        fs::read_to_string(&c_path).map_err(|_| PairedBackupError::IncompleteCut("missing outer COMPLETE marker"))?;
    if marker.trim() != actual_m_hex {
        return Err(PairedBackupError::IncompleteCut("outer COMPLETE mismatches manifest.json"));
    }
    let manifest: Format30PairedManifest = serde_json::from_slice(&fs::read(&m_path)?)
        .map_err(|_| PairedBackupError::IncompleteCut("malformed or unknown field in Format30PairedManifest"))?;
    if manifest.clone().seal()?.paired_cut_digest != manifest.paired_cut_digest {
        return Err(PairedBackupError::CorruptBlobOrDigest("paired_cut_digest mismatch".into()));
    }
    if manifest.format30_pg.format != STANDARD_PAIRED_PG_FORMAT
        || manifest.format30_pg.schema_head != STANDARD_SCHEMA_HEAD
    {
        return Err(PairedBackupError::IncompleteCut("inner PG archive is not standard format 30 / schema 151"));
    }
    let fmt30_dir = archive_dir.join(FORMAT30_SUBDIR);
    crate::backup::check(&fmt30_dir).map_err(|_| PairedBackupError::IncompleteCut("inner format 30 check failed"))?;
    let (_, dump_sha) = stream_sha256_file(&fmt30_dir.join("metadata.dump"))?;
    let (_, inner_comp_sha) = stream_sha256_file(&fmt30_dir.join(COMPLETE_MARKER))?;
    if dump_sha != manifest.format30_pg.metadata_dump_sha256
        || inner_comp_sha != manifest.format30_pg.inner_complete_sha256
    {
        return Err(PairedBackupError::CorruptBlobOrDigest(
            "inner format 30 metadata.dump or COMPLETE tampered".into(),
        ));
    }

    manifest.freeze.require_frozen()?;
    manifest.pg_cutpoint.verify()?;
    manifest.blob_closure.verify()?;
    if let Some(exp) = expected_backend_identity
        && manifest.blob_closure.backend_identity != exp
    {
        return Err(PairedBackupError::BackendIdentityMismatch {
            expected: exp.to_owned(),
            actual: manifest.blob_closure.backend_identity,
        });
    }

    let raft = &manifest.raft_cutpoint;
    raft.snapshot.verify_integrity().map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
    let rebuilt =
        RefCasStateMachine::restore(&raft.snapshot).map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
    if rebuilt.state_digest().map_err(|e| PairedBackupError::StateMachine(e.to_string()))? != raft.state_digest {
        return Err(PairedBackupError::CutpointSkew("active Raft state_digest mismatches snapshot".into()));
    }
    let active_cut = ExpectedGroupCursorCut::from_verified_snapshot(raft.group_id, &raft.snapshot)?;
    let peer_cuts =
        verify_archived_peer_groups(raft.group_id, active_cut.group_epoch, &raft.group_epochs, &raft.peer_groups)?;
    verify_all_group_cursors(&manifest.pg_cutpoint, &active_cut, &peer_cuts)?;
    reconcile_pg_raft_repositories(&manifest.pg_cutpoint, &raft.snapshot, raft.applied_log_id, &raft.close_receipts)?;
    verify_blob_closure_against_durable_raft(
        &raft.snapshot,
        &raft.backup_holds,
        &manifest.blob_closure.entries,
        &manifest.pg_cutpoint.repositories,
    )?;
    for entry in &manifest.blob_closure.entries {
        let (len, sha) = stream_sha256_file(&fmt30_dir.join(&entry.archive_rel_path))?;
        if len != entry.length || sha != entry.sha256 {
            return Err(PairedBackupError::CorruptBlobOrDigest(format!(
                "corrupted format 30 blob {}",
                entry.archive_rel_path
            )));
        }
    }
    Ok(manifest)
}

fn extract_format30_binding_and_closure(
    fmt30_dir: &Path,
    pg_proof: &PgCutpointProof,
    expected_backend_hex: &str,
) -> Result<(Format30PgArchiveBinding, BlobClosureManifest), PairedBackupError> {
    let raw: Value = serde_json::from_slice(&fs::read(fmt30_dir.join(MANIFEST_FILE))?)
        .map_err(|_| PairedBackupError::IncompleteCut("parse inner format 30 manifest"))?;
    let format = raw["format"].as_u64().unwrap_or(0) as u32;
    let schema_head =
        raw["schema_versions"].as_array().and_then(|v| v.last()).and_then(Value::as_i64).unwrap_or(0) as i32;
    if format != STANDARD_PAIRED_PG_FORMAT || schema_head != STANDARD_SCHEMA_HEAD {
        return Err(PairedBackupError::IncompleteCut(
            "crate::backup::create did not emit format 30 / schema 151 archive",
        ));
    }
    let inner_backup_id: Uuid = raw["backup_id"]
        .as_str()
        .and_then(|s| s.parse().ok())
        .ok_or(PairedBackupError::IncompleteCut("missing inner format 30 backup_id"))?;
    let schema_contract_sha256 = raw["schema_contract_sha256"]
        .as_str()
        .filter(|s| validate_hex64(s))
        .ok_or(PairedBackupError::IncompleteCut("invalid inner schema_contract_sha256"))?
        .to_owned();
    let (_, metadata_dump_sha256) = stream_sha256_file(&fmt30_dir.join("metadata.dump"))?;
    let (_, inner_complete_sha256) = stream_sha256_file(&fmt30_dir.join(COMPLETE_MARKER))?;

    let repo_formats: BTreeMap<Uuid, GitObjectFormat> =
        pg_proof.repositories.iter().map(|r| (r.repository_id, r.object_format)).collect();
    let arr = raw["blob_artifacts"]
        .as_array()
        .ok_or_else(|| PairedBackupError::BlobClosureIncomplete("format 30 archive missing blob_artifacts".into()))?;
    let mut entries = Vec::with_capacity(arr.len());
    let mut total_bytes = 0u64;
    for item in arr {
        let parse_uuid = |k: &str| {
            item[k]
                .as_str()
                .and_then(|s| s.parse::<Uuid>().ok())
                .ok_or_else(|| PairedBackupError::BlobClosureIncomplete(format!("bad artifact {k}")))
        };
        let (repository_id, pack_id, tenant_id, attempt_id) =
            (parse_uuid("repository_id")?, parse_uuid("pack_id")?, parse_uuid("tenant_id")?, parse_uuid("attempt_id")?);
        let role = item["role"].as_str().unwrap_or_default().to_owned();
        let sha256 = item["sha256"].as_str().unwrap_or_default().to_owned();
        let length = item["length"].as_u64().unwrap_or(0);
        let generation = item["generation"].as_i64().unwrap_or(0);
        let backend_identity = item["backend_identity"].as_str().unwrap_or_default().to_owned();
        if backend_identity != expected_backend_hex {
            return Err(PairedBackupError::BackendIdentityMismatch {
                expected: expected_backend_hex.to_owned(),
                actual: backend_identity,
            });
        }
        let rel = format!("blob/{repository_id}/{pack_id}/{role}.{role}");
        let (disk_len, disk_sha) = stream_sha256_file(&fmt30_dir.join(&rel))?;
        if disk_len != length || disk_sha != sha256 {
            return Err(PairedBackupError::CorruptBlobOrDigest(format!("format 30 blob {rel} mismatch")));
        }
        let object_format = repo_formats.get(&repository_id).copied().unwrap_or(GitObjectFormat::Sha256);
        total_bytes = total_bytes.saturating_add(length);
        entries.push(BlobArtifactEntry {
            repository_id,
            tenant_id,
            pack_id,
            object_format,
            role,
            locator_path: rel.clone(),
            archive_rel_path: rel,
            attempt_id,
            generation,
            length,
            sha256,
            backend_identity,
        });
    }
    let provider = raw["blob_closure"]["provider"].as_str().unwrap_or("s3").to_owned();
    let closure = BlobClosureManifest {
        backend_identity: expected_backend_hex.to_owned(),
        provider,
        total_artifacts: entries.len(),
        total_bytes,
        entries,
        closure_digest: String::new(),
    }
    .seal()?;
    closure.verify()?;
    let binding = Format30PgArchiveBinding {
        format,
        inner_backup_id,
        schema_head,
        schema_contract_sha256,
        metadata_dump_sha256,
        inner_complete_sha256,
        repository_count: pg_proof.repositories.len(),
    };
    Ok((binding, closure))
}

fn write_synced(path: &Path, bytes: &[u8]) -> Result<(), PairedBackupError> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
