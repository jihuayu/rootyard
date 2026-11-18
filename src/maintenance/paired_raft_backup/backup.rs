//! Coordinated PG cutpoint + Raft index/close-receipt + OpenDAL Blob closure backup (#153).

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
use crate::ref_store::core::state_machine::{AppliedLogId, RefCasStateMachine, ScopeLifecycle};

use super::pg_cutpoint::capture_pg_cutpoint_in_tx;
use super::types::{
    BackupRetentionHoldRecord, BlobArtifactEntry, BlobClosureManifest, COMPLETE_MARKER, CloseScopeBarrierReceipt,
    FreezePartyStatus, MANIFEST_FILE, MAX_ARTIFACTS, MAX_MANIFEST_BYTES, MAX_REPOSITORIES, PairedBackupError,
    PairedBackupManifest, PgCutpointProof, RaftCutpointProof,
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
    pub group_membership_digest: &'a str,
    pub freeze: &'a FreezePartyStatus,
    pub sm: &'a RefCasStateMachine,
    pub close_receipts: Vec<CloseScopeBarrierReceipt>,
    pub backup_holds: Vec<BackupRetentionHoldRecord>,
    pub artifacts: Vec<PreparedBlobArtifact>,
    pub store: &'a BlobStore,
    pub staging_dir: &'a Path,
    pub destination: &'a Path,
    pub deadline: Instant,
}

/// Capture live PG 17 repeatable-read cutpoint + Raft cut + Blob closure into `destination`.
pub async fn capture_live_pg_backup(
    pg_client: &mut Client,
    req: PairedBackupRequest<'_>,
) -> Result<PairedBackupManifest, PairedBackupError> {
    let last =
        req.sm.last_applied().ok_or(PairedBackupError::IncompleteCut("Raft state machine has no applied index"))?;
    let snap = req.sm.snapshot().map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
    let event_seq = snap.body.next_event_seq.saturating_sub(1);
    let first_gate_hist = snap.body.gates.first().map(|g| g.history_incarnation).unwrap_or_else(Uuid::nil);

    let tx = pg_client
        .build_transaction()
        .isolation_level(IsolationLevel::RepeatableRead)
        .read_only(true)
        .start()
        .await
        .map_err(|e| PairedBackupError::Postgres(e.to_string()))?;
    let pg_proof =
        capture_pg_cutpoint_in_tx(&tx, req.group_id, first_gate_hist, last.index, last.term, event_seq).await?;
    let manifest = create_paired_backup(req, Some(&pg_proof)).await?;
    tx.commit().await.map_err(|e| PairedBackupError::Postgres(e.to_string()))?;
    Ok(manifest)
}

/// Export a sealed paired backup archive proving tri-party freeze, empty close-scope drains,
/// pre-registered backup holds, exact PG <-> Raft cutpoint reconciliation, and verified Blob bytes.
pub async fn create_paired_backup(
    req: PairedBackupRequest<'_>,
    pg_proof: Option<&PgCutpointProof>,
) -> Result<PairedBackupManifest, PairedBackupError> {
    req.freeze.require_frozen()?;
    if req.backup_id.is_nil() || req.group_membership_digest.len() != 64 {
        return Err(PairedBackupError::InvalidArgument("backup_id and 64-hex membership digest required"));
    }
    if req.destination.exists() {
        return Err(PairedBackupError::InvalidArgument("destination already exists"));
    }
    if req.backup_holds.is_empty() || req.close_receipts.is_empty() || req.artifacts.is_empty() {
        return Err(PairedBackupError::IncompleteCut(
            "paired backup requires close receipts, backup holds, and Blob closure",
        ));
    }
    if req.artifacts.len() > MAX_ARTIFACTS {
        return Err(PairedBackupError::InvalidArgument("artifact count exceeds MAX_ARTIFACTS"));
    }
    let pg = pg_proof.ok_or(PairedBackupError::IncompleteCut("PG cutpoint is mandatory for paired backup"))?;
    pg.verify()?;
    if pg.repositories.is_empty() || pg.repositories.len() > MAX_REPOSITORIES {
        return Err(PairedBackupError::IncompleteCut("PG cutpoint must cover 1..=MAX_REPOSITORIES repositories"));
    }

    let applied_log_id: AppliedLogId =
        req.sm.last_applied().ok_or(PairedBackupError::IncompleteCut("Raft state machine missing applied_log_id"))?;
    let snapshot = req.sm.snapshot().map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
    snapshot.verify_integrity().map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;
    let state_digest = req.sm.state_digest().map_err(|e| PairedBackupError::StateMachine(e.to_string()))?;

    reconcile_pg_raft_cutpoint(
        pg,
        &snapshot,
        req.sm,
        applied_log_id,
        req.group_id,
        &req.close_receipts,
        &req.backup_holds,
    )?;

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
    let mut seen_pack_roles: BTreeMap<(Uuid, Uuid), BTreeSet<String>> = BTreeMap::new();
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
        seen_pack_roles.entry((art.repository_id, art.pack_id)).or_default().insert(art.role.clone());
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

    for ((repo_id, pack_id), roles) in &seen_pack_roles {
        if !(roles.contains("pack") && roles.contains("idx")) {
            return Err(PairedBackupError::BlobClosureIncomplete(format!(
                "repo {repo_id} pack {pack_id} missing paired .pack/.idx artifact"
            )));
        }
    }
    for repo in &pg.repositories {
        if !seen_pack_roles.keys().any(|(r, _)| *r == repo.repository_id) {
            return Err(PairedBackupError::BlobClosureIncomplete(format!(
                "backed-up repository {} has zero Blob pack pairs in closure",
                repo.repository_id
            )));
        }
    }

    let blob_closure = BlobClosureManifest {
        backend_identity: backend_hex,
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
    let raft_cutpoint = RaftCutpointProof {
        group_id: req.group_id,
        applied_log_id,
        logical_clock_floor: req.sm.logical_clock_floor(),
        state_digest,
        group_membership_digest: req.group_membership_digest.to_owned(),
        snapshot_checksum: snapshot.checksum.clone(),
        snapshot,
        close_receipts: req.close_receipts,
        backup_holds: req.backup_holds,
    };
    let manifest = PairedBackupManifest {
        format_version: super::types::PAIRED_BACKUP_FORMAT_V1.to_owned(),
        backup_id: req.backup_id,
        created_unix_seconds: now_unix,
        freeze: req.freeze.clone(),
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
    Ok(manifest)
}

struct PartialDirGuard {
    path: Option<std::path::PathBuf>,
}

impl PartialDirGuard {
    fn new(path: std::path::PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(&mut self) {
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

fn reconcile_pg_raft_cutpoint(
    pg: &PgCutpointProof,
    snap: &crate::ref_store::core::state_machine::RefCasSnapshot,
    sm: &RefCasStateMachine,
    applied: AppliedLogId,
    group_id: i64,
    close_receipts: &[CloseScopeBarrierReceipt],
    backup_holds: &[BackupRetentionHoldRecord],
) -> Result<(), PairedBackupError> {
    if snap.body.last_applied != Some(applied) {
        return Err(PairedBackupError::CutpointSkew("Raft snapshot last_applied disagrees with applied_log_id".into()));
    }
    let expected_seq = snap.body.next_event_seq.saturating_sub(1) as i64;
    let cursor = pg
        .projection_cursors
        .iter()
        .find(|c| c.group_id == group_id)
        .ok_or_else(|| PairedBackupError::CutpointSkew(format!("PG cursor missing for group {group_id}")))?;
    if cursor.applied_log_index != applied.index as i64
        || cursor.applied_log_term != applied.term as i64
        || cursor.applied_event_seq != expected_seq
        || cursor.stream_state != "active"
    {
        return Err(PairedBackupError::CutpointSkew(format!(
            "PG cursor ({},{},{}) skewed from Raft ({},{},{})",
            cursor.applied_log_term,
            cursor.applied_log_index,
            cursor.applied_event_seq,
            applied.term,
            applied.index,
            expected_seq
        )));
    }
    for r in close_receipts {
        r.verify()?;
        if r.raft_log_index > applied.index || r.raft_log_term != applied.term || r.lifecycle != ScopeLifecycle::Closed
        {
            return Err(PairedBackupError::ScopeNotClosed("close receipt log/lifecycle mismatches Raft cut".into()));
        }
    }
    for repo in &pg.repositories {
        let sm_refs = sm.read_refs(repo.repository_id);
        if sm_refs != repo.refs {
            return Err(PairedBackupError::CutpointSkew(format!(
                "PG refs != Raft refs for repo {}",
                repo.repository_id
            )));
        }
        let gate = sm
            .read_gate_version(repo.repository_id)
            .map_err(|e| PairedBackupError::StateMachine(e.to_string()))?
            .ok_or_else(|| {
                PairedBackupError::CutpointSkew(format!("Raft gate missing for repo {}", repo.repository_id))
            })?;
        if gate.history_incarnation() != repo.history_incarnation
            || gate.authority_epoch() != repo.authority_epoch
            || gate.group_epoch() != repo.group_epoch
        {
            return Err(PairedBackupError::CutpointSkew("PG repository realm mismatches Raft gate".into()));
        }
        if !close_receipts.iter().any(|c| c.repository_id == Some(repo.repository_id)) {
            return Err(PairedBackupError::ScopeNotClosed(format!(
                "missing close receipt for repo {}",
                repo.repository_id
            )));
        }
        let hold = backup_holds
            .iter()
            .find(|h| h.repository_id == repo.repository_id && h.tenant_id == repo.tenant_id)
            .ok_or(PairedBackupError::IncompleteCut("missing backup retention hold before unfreeze"))?;
        if sm.read_root(hold.root_id).is_none() || sm.read_pin(hold.pin_id).is_none() {
            return Err(PairedBackupError::IncompleteCut("backup pin/root missing from Raft snapshot"));
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
