//! Coordinated PG cutpoint + durable multi-group Raft barrier + OpenDAL Blob closure backup (#153).

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use tokio_postgres::{Client, IsolationLevel};
use uuid::Uuid;

use crate::blob_store::{BlobLocator, opendal::BlobStore};
use crate::ref_store::GitObjectFormat;
use crate::ref_store::core::state_machine::{AppliedLogId, RefCasSnapshot, ScopeLifecycle};

use super::closure_bind::verify_blob_closure_against_durable_raft;
use super::peer_groups::{
    ExpectedGroupCursorCut, PeerGroupBackupInput, extract_peer_expected_cuts, verify_all_group_cursors,
};
use super::pg_cutpoint::{ExpectedRaftCut, capture_pg_cutpoint_in_tx};
use super::quorum_wal::DurableRaftBackend;
use super::raft_barrier::{DurableFreezeBarrierProof, SealedArchiveReceipt};
use super::types::{
    BlobArtifactEntry, BlobClosureManifest, COMPLETE_MARKER, CloseScopeBarrierReceipt, MANIFEST_FILE, MAX_ARTIFACTS,
    MAX_MANIFEST_BYTES, MAX_REPOSITORIES, PairedBackupError, PairedBackupManifest, PgCutpointProof, RaftCutpointProof,
};

#[derive(Clone, Debug)]
pub struct PreparedBlobArtifact {
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub pack_id: Uuid,
    pub object_format: GitObjectFormat,
    pub role: String,
    pub locator: BlobLocator,
}

pub struct PairedBackupRequest<'a> {
    pub backup_id: Uuid,
    pub group_id: i64,
    pub peer_groups: Vec<PeerGroupBackupInput<'a>>,
    pub freeze_barrier: &'a DurableFreezeBarrierProof,
    pub raft: &'a dyn DurableRaftBackend,
    pub artifacts: Vec<PreparedBlobArtifact>,
    pub store: &'a BlobStore,
    pub staging_dir: &'a Path,
    pub destination: &'a Path,
    pub deadline: Instant,
}

/// Capture live PG 17 repeatable-read cutpoint + durable active & peer Raft cuts + Blob closure.
pub async fn capture_live_pg_backup(
    pg_client: &mut Client,
    req: PairedBackupRequest<'_>,
) -> Result<(PairedBackupManifest, SealedArchiveReceipt), PairedBackupError> {
    if req.raft.group_id() != req.group_id {
        return Err(PairedBackupError::CutpointSkew("active Raft backend group_id mismatches request".into()));
    }
    let committed_idx = req.raft.committed_quorum_index()?;
    let (durable_snap, durable_digest) = req.raft.durable_state()?;
    let mem_digest = req.raft.group_membership_digest();
    req.freeze_barrier.verify_against_raft_group(req.group_id, &mem_digest, &durable_snap, &durable_digest, true)?;
    if committed_idx < req.freeze_barrier.barrier_log_id.index {
        return Err(PairedBackupError::FreezeNotHeld("active Raft quorum_commit_index behind freeze barrier"));
    }
    let active_cut = ExpectedGroupCursorCut::from_verified_snapshot(req.group_id, &durable_snap)?;
    let (peer_cuts, _) = extract_peer_expected_cuts(req.group_id, &req.peer_groups)?;
    let expected_cut = ExpectedRaftCut { active: active_cut, peers: peer_cuts };

    let tx = pg_client
        .build_transaction()
        .isolation_level(IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .await
        .map_err(|e| PairedBackupError::Postgres(e.to_string()))?;
    let pg_proof = capture_pg_cutpoint_in_tx(&tx, &expected_cut).await?;
    let result = create_paired_backup(req, Some(&pg_proof)).await?;
    tx.commit().await.map_err(|e| PairedBackupError::Postgres(e.to_string()))?;
    Ok(result)
}

/// Export a sealed paired backup archive proving quorum+local freeze barriers across all Raft groups,
/// complete durable hold/root/pin Blob closure, exact PG <-> Raft cursor alignment, and verified Blobs.
pub async fn create_paired_backup(
    req: PairedBackupRequest<'_>,
    pg_proof: Option<&PgCutpointProof>,
) -> Result<(PairedBackupManifest, SealedArchiveReceipt), PairedBackupError> {
    if req.backup_id.is_nil() {
        return Err(PairedBackupError::InvalidArgument("non-nil backup_id required"));
    }
    if req.destination.exists() {
        return Err(PairedBackupError::InvalidArgument("destination already exists"));
    }
    if req.artifacts.is_empty() {
        return Err(PairedBackupError::IncompleteCut("paired backup requires non-empty Blob closure"));
    }
    if req.artifacts.len() > MAX_ARTIFACTS {
        return Err(PairedBackupError::InvalidArgument("artifact count exceeds MAX_ARTIFACTS"));
    }
    let pg = pg_proof.ok_or(PairedBackupError::IncompleteCut("PG cutpoint is mandatory for paired backup"))?;
    pg.verify()?;
    if pg.repositories.is_empty() || pg.repositories.len() > MAX_REPOSITORIES {
        return Err(PairedBackupError::IncompleteCut("PG cutpoint must cover 1..=MAX_REPOSITORIES repositories"));
    }
    if req.raft.group_id() != req.group_id {
        return Err(PairedBackupError::CutpointSkew("active Raft backend group_id mismatches request".into()));
    }

    let committed_idx = req.raft.committed_quorum_index()?;
    let (snapshot, state_digest) = req.raft.durable_state()?;
    let group_membership_digest = req.raft.group_membership_digest();
    req.freeze_barrier.verify_against_raft_group(
        req.group_id,
        &group_membership_digest,
        &snapshot,
        &state_digest,
        true,
    )?;
    if committed_idx < req.freeze_barrier.barrier_log_id.index {
        return Err(PairedBackupError::FreezeNotHeld("quorum_commit_index behind freeze barrier"));
    }
    let active_cut = ExpectedGroupCursorCut::from_verified_snapshot(req.group_id, &snapshot)?;
    let (peer_cuts, peer_proofs) = extract_peer_expected_cuts(req.group_id, &req.peer_groups)?;
    verify_all_group_cursors(pg, &active_cut, &peer_cuts)?;

    let applied_log_id = AppliedLogId { term: active_cut.applied_term, index: active_cut.applied_index };
    reconcile_pg_raft_repositories(pg, &snapshot, applied_log_id, &req.freeze_barrier.close_receipts)?;

    let mut group_epochs = BTreeMap::from([(req.group_id, active_cut.group_epoch)]);
    for pc in &peer_cuts {
        group_epochs.insert(pc.group_id, pc.group_epoch);
    }

    let work_dir = req.staging_dir.join(format!(".paired-{}.partial", req.backup_id));
    if work_dir.exists() {
        fs::remove_dir_all(&work_dir)?;
    }
    fs::create_dir_all(&work_dir)?;
    let mut partial_guard = PartialDirGuard::new(work_dir.clone());

    let backend_hex = req.store.backend_identity().as_hex().to_owned();
    let provider = req.store.provider().as_str().to_owned();
    let mut entries = Vec::with_capacity(req.artifacts.len());
    let mut seen_rel = BTreeSet::new();
    let mut total_bytes = 0u64;

    for art in &req.artifacts {
        if art.role != "pack" && art.role != "idx" {
            return Err(PairedBackupError::InvalidArgument("artifact role must be pack or idx"));
        }
        let receipt =
            req.store.verify(&art.locator, req.deadline).await.map_err(|e| PairedBackupError::Blob(e.to_string()))?;
        if receipt.backend_identity().as_hex() != backend_hex {
            return Err(PairedBackupError::BackendIdentityMismatch {
                expected: backend_hex.clone(),
                actual: receipt.backend_identity().as_hex().to_owned(),
            });
        }
        let ext = if art.role == "pack" { "pack" } else { "idx" };
        let rel = format!("blobs/{}/{}/{}.{ext}", art.repository_id, art.pack_id, receipt.verified_sha256());
        if !seen_rel.insert(rel.clone()) {
            return Err(PairedBackupError::BlobClosureIncomplete(format!("duplicate archive member {rel}")));
        }
        let local_path = work_dir.join(&rel);
        if let Some(parent) = local_path.parent() {
            fs::create_dir_all(parent)?;
        }
        req.store
            .get_to_file(&art.locator, &local_path, req.deadline)
            .await
            .map_err(|e| PairedBackupError::Blob(e.to_string()))?;
        let (actual_len, actual_sha) = stream_sha256_file(&local_path)?;
        if actual_len != art.locator.length() || actual_sha != art.locator.sha256() {
            return Err(PairedBackupError::CorruptBlobOrDigest(format!(
                "exported blob {} sha256/length mismatch",
                rel
            )));
        }
        total_bytes = total_bytes.saturating_add(actual_len);
        entries.push(BlobArtifactEntry {
            repository_id: art.repository_id,
            tenant_id: art.tenant_id,
            pack_id: art.pack_id,
            object_format: art.object_format,
            role: art.role.clone(),
            locator_path: art.locator.path().to_owned(),
            archive_rel_path: rel,
            attempt_id: art.locator.attempt_id(),
            generation: art.locator.generation(),
            length: actual_len,
            sha256: actual_sha,
            backend_identity: backend_hex.clone(),
        });
    }

    verify_blob_closure_against_durable_raft(&snapshot, &req.freeze_barrier.backup_holds, &entries, &pg.repositories)?;
    super::format30_paired::enforce_blob_closure_verifier_budget(&entries)?;

    let blob_closure = BlobClosureManifest {
        backend_identity: backend_hex.clone(),
        provider,
        total_artifacts: entries.len(),
        total_bytes,
        entries,
        closure_digest: String::new(),
    }
    .seal()?;
    blob_closure.verify()?;

    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| PairedBackupError::Io(std::io::Error::other(e)))?
        .as_secs();
    let voter_ids = req.raft.voter_ids();
    let cutpoint_attestations = req.raft.attest_group_cutpoint(active_cut.group_epoch, &snapshot, &state_digest)?;
    let raft_cutpoint = RaftCutpointProof {
        group_id: req.group_id,
        group_epochs,
        peer_groups: peer_proofs,
        applied_log_id,
        min_consensus_index: committed_idx,
        logical_clock_floor: snapshot.body.logical_clock_floor,
        state_digest,
        group_membership_digest,
        voter_ids,
        cutpoint_attestations,
        snapshot_checksum: snapshot.checksum.clone(),
        snapshot,
        close_receipts: req.freeze_barrier.close_receipts.clone(),
        backup_holds: req.freeze_barrier.backup_holds.clone(),
    };
    let manifest = PairedBackupManifest {
        format_version: super::types::PAIRED_BACKUP_FORMAT_V1.to_owned(),
        backup_id: req.backup_id,
        created_unix_seconds: now_unix,
        freeze: req.freeze_barrier.status.clone(),
        pg_cutpoint: pg.clone(),
        raft_cutpoint,
        blob_closure,
        paired_cut_digest: String::new(),
    }
    .seal()?;

    let manifest_bytes =
        serde_json::to_vec_pretty(&manifest).map_err(|_| PairedBackupError::IncompleteCut("manifest serialize"))?;
    if manifest_bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(PairedBackupError::InvalidArgument("manifest exceeds MAX_MANIFEST_BYTES"));
    }
    let manifest_path = work_dir.join(MANIFEST_FILE);
    write_synced_file(&manifest_path, &manifest_bytes)?;
    let manifest_hex = stream_sha256_file(&manifest_path)?.1;
    write_synced_file(&work_dir.join(COMPLETE_MARKER), manifest_hex.as_bytes())?;
    fs::rename(&work_dir, req.destination)?;
    partial_guard.disarm();

    let verified = super::restore::verify_backup_archive(req.destination, Some(&backend_hex))?;
    let (_, complete_marker_sha256) = stream_sha256_file(&req.destination.join(COMPLETE_MARKER))?;
    let root_ids = req.freeze_barrier.backup_holds.iter().map(|h| h.root_id).collect();
    let hold_ids = req.freeze_barrier.backup_holds.iter().flat_map(|h| h.hold_ids.iter().copied()).collect();
    let seal_receipt = SealedArchiveReceipt {
        backup_id: verified.backup_id,
        barrier_id: req.freeze_barrier.barrier_id,
        fenced_deleter_epoch: req.freeze_barrier.status.fenced_deleter_epoch,
        app_fence_seq: req.freeze_barrier.status.app_fence_seq,
        barrier_log_id: req.freeze_barrier.barrier_log_id,
        barrier_state_digest: req.freeze_barrier.barrier_state_digest.clone(),
        paired_cut_digest: verified.paired_cut_digest.clone(),
        complete_marker_sha256,
        root_ids,
        hold_ids,
        receipt_seal: String::new(),
    }
    .mint()?;

    Ok((manifest, seal_receipt))
}

pub(super) struct PartialDirGuard {
    path: Option<std::path::PathBuf>,
}

impl PartialDirGuard {
    pub(super) fn new(path: std::path::PathBuf) -> Self {
        Self { path: Some(path) }
    }

    pub(super) fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for PartialDirGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_dir_all(path);
        }
    }
}

pub(super) fn reconcile_pg_raft_repositories(
    pg: &PgCutpointProof,
    snap: &RefCasSnapshot,
    applied: AppliedLogId,
    close_receipts: &[CloseScopeBarrierReceipt],
) -> Result<(), PairedBackupError> {
    for r in close_receipts {
        r.verify()?;
        if r.raft_log_index > applied.index
            || r.raft_log_term == 0
            || r.raft_log_term > applied.term
            || r.lifecycle != ScopeLifecycle::Closed
        {
            return Err(PairedBackupError::ScopeNotClosed("close receipt log/lifecycle mismatches Raft cut".into()));
        }
    }
    for repo in &pg.repositories {
        let empty = BTreeMap::new();
        let found = snap.body.refs.iter().find(|rf| rf.repository_id == repo.repository_id);
        if found.map_or(&empty, |rf| &rf.refs) != &repo.refs {
            return Err(PairedBackupError::CutpointSkew(format!(
                "PG refs != Raft refs for repo {}",
                repo.repository_id
            )));
        }
        let gate = snap.body.gates.iter().find(|g| g.repository_id == repo.repository_id).ok_or_else(|| {
            PairedBackupError::CutpointSkew(format!("Raft gate missing for repo {}", repo.repository_id))
        })?;
        if gate.history_incarnation != repo.history_incarnation
            || gate.authority_epoch != repo.authority_epoch
            || gate.group_epoch != repo.group_epoch
        {
            return Err(PairedBackupError::CutpointSkew("PG repository realm mismatches Raft gate".into()));
        }
        if !close_receipts.iter().any(|c| c.repository_id == Some(repo.repository_id)) {
            return Err(PairedBackupError::ScopeNotClosed(format!(
                "missing close receipt for repo {}",
                repo.repository_id
            )));
        }
    }
    Ok(())
}

pub(super) fn stream_sha256_file(path: &Path) -> Result<(u64, String), PairedBackupError> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.file_type().is_file() {
        return Err(PairedBackupError::CorruptBlobOrDigest(format!("{} is not a regular file", path.display())));
    }
    let mut f = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n as u64);
        hasher.update(&buf[..n]);
    }
    Ok((total, hex::encode(hasher.finalize())))
}

fn write_synced_file(path: &Path, bytes: &[u8]) -> Result<(), PairedBackupError> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut f = opts.open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
