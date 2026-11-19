//! Canonical types, errors, and domain-tagged SHA-256 digests for paired backups (#153).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ref_store::GitObjectFormat;
use crate::ref_store::core::state_machine::{AppliedLogId, RefCasSnapshot, ScopeLifecycle};

use super::peer_attestation::PeerDurableAttestation;
use super::peer_groups::PeerRaftCutpointProof;

pub const PAIRED_BACKUP_FORMAT_V1: &str = "rootyard-paired-pg-raft-blob-v1";
pub const MANIFEST_FILE: &str = "manifest.json";
pub const COMPLETE_MARKER: &str = "COMPLETE";
pub const MAX_REPOSITORIES: usize = 256;
pub const MAX_ARTIFACTS: usize = 10_000;
pub const MAX_MANIFEST_BYTES: u64 = 32 * 1024 * 1024;

#[derive(Debug)]
pub enum PairedBackupError {
    InvalidArgument(&'static str),
    IncompleteCut(&'static str),
    FreezeNotHeld(&'static str),
    ScopeNotClosed(String),
    UnknownInFlightOperations(usize),
    DeleterNotFenced(&'static str),
    CutpointSkew(String),
    TenantOrRepoMismatch(String),
    BlobClosureIncomplete(String),
    CorruptBlobOrDigest(String),
    BackendIdentityMismatch { expected: String, actual: String },
    StaleIncarnation { field: &'static str, expected: String, got: String },
    StaleGrantRefused(&'static str),
    StaleDecisionRefused(Uuid),
    StaleDeleterRefused(&'static str),
    GitVerificationFailed(String),
    Postgres(String),
    StateMachine(String),
    Blob(String),
    Io(std::io::Error),
}

impl fmt::Display for PairedBackupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument(msg) => write!(f, "invalid argument: {msg}"),
            Self::IncompleteCut(msg) => write!(f, "incomplete paired backup cut: {msg}"),
            Self::FreezeNotHeld(msg) => write!(f, "tri-party write freeze required: {msg}"),
            Self::ScopeNotClosed(msg) => write!(f, "Ref-CAS scope barrier not closed: {msg}"),
            Self::UnknownInFlightOperations(n) => write!(f, "{n} unresolved or unknown in-flight operations remain"),
            Self::DeleterNotFenced(msg) => write!(f, "deleter not fenced: {msg}"),
            Self::CutpointSkew(msg) => write!(f, "PG/Raft/Blob cutpoint skew: {msg}"),
            Self::TenantOrRepoMismatch(msg) => write!(f, "tenant/repository mismatch: {msg}"),
            Self::BlobClosureIncomplete(msg) => write!(f, "incomplete Blob closure: {msg}"),
            Self::CorruptBlobOrDigest(msg) => write!(f, "corrupt Blob or SHA-256 mismatch: {msg}"),
            Self::BackendIdentityMismatch { expected, actual } => {
                write!(f, "backend identity mismatch: expected {expected}, actual {actual}")
            }
            Self::StaleIncarnation { field, expected, got } => {
                write!(f, "stale incarnation rejected ({field}): expected {expected}, got {got}")
            }
            Self::StaleGrantRefused(reason) => write!(f, "stale pre-backup grant refused: {reason}"),
            Self::StaleDecisionRefused(id) => write!(f, "stale pre-backup decision refused: {id}"),
            Self::StaleDeleterRefused(reason) => write!(f, "stale pre-backup deleter lease refused: {reason}"),
            Self::GitVerificationFailed(msg) => write!(f, "Git fsck/clone verification failed: {msg}"),
            Self::Postgres(msg) => write!(f, "PostgreSQL error: {msg}"),
            Self::StateMachine(msg) => write!(f, "Ref-CAS state-machine error: {msg}"),
            Self::Blob(msg) => write!(f, "OpenDAL Blob error: {msg}"),
            Self::Io(err) => write!(f, "I/O error: {err}"),
        }
    }
}

impl std::error::Error for PairedBackupError {}

impl From<std::io::Error> for PairedBackupError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

pub fn validate_hex64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn validate_oid_hex(format: GitObjectFormat, oid: &str) -> bool {
    let want_len = match format {
        GitObjectFormat::Sha1 => 40,
        GitObjectFormat::Sha256 => 64,
    };
    oid.len() == want_len && oid.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn sha256_json_tagged(tag: &[u8], value: &impl Serialize) -> Result<String, PairedBackupError> {
    let payload = serde_json::to_vec(value)
        .map_err(|_| PairedBackupError::IncompleteCut("canonical JSON serialization failed"))?;
    let mut hasher = Sha256::new();
    hasher.update(tag);
    hasher.update(b"\0");
    hasher.update(payload);
    Ok(hex::encode(hasher.finalize()))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FreezePartyStatus {
    pub app_paused: bool,
    pub worker_paused: bool,
    pub deleter_fenced: bool,
    pub consensus_replication_active: bool,
    pub leader_election_active: bool,
    pub fenced_deleter_epoch: u64,
    pub app_fence_seq: u64,
    pub worker_drain_settled: usize,
    pub unknown_ops_resolved: usize,
}

impl FreezePartyStatus {
    pub fn require_frozen(&self) -> Result<(), PairedBackupError> {
        if !(self.app_paused && self.worker_paused && self.deleter_fenced) {
            return Err(PairedBackupError::FreezeNotHeld("app, worker, and deleter must all be frozen"));
        }
        if !(self.consensus_replication_active && self.leader_election_active) {
            return Err(PairedBackupError::FreezeNotHeld(
                "backup must never halt Raft consensus replication or leader election",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CloseScopeBarrierReceipt {
    pub scope_kind: String,
    pub scope_id: Uuid,
    pub repository_id: Option<Uuid>,
    pub tenant_id: Option<Uuid>,
    pub lifecycle: ScopeLifecycle,
    pub authz_floor: i64,
    pub raft_log_index: u64,
    pub raft_log_term: u64,
    pub pending_operation_ids: Vec<Uuid>,
    pub open_decision_ids: Vec<Uuid>,
    pub receipt_digest: String,
}

impl CloseScopeBarrierReceipt {
    pub fn seal(mut self) -> Result<Self, PairedBackupError> {
        self.receipt_digest.clear();
        self.receipt_digest = sha256_json_tagged(b"rootyard-close-scope-barrier-v1", &self)?;
        Ok(self)
    }

    pub fn verify(&self) -> Result<(), PairedBackupError> {
        if self.scope_id.is_nil() || self.authz_floor <= 0 {
            return Err(PairedBackupError::ScopeNotClosed("invalid scope_id or non-positive authz_floor".into()));
        }
        if self.lifecycle != ScopeLifecycle::Closed {
            return Err(PairedBackupError::ScopeNotClosed(format!("scope {} not closed", self.scope_id)));
        }
        if !self.pending_operation_ids.is_empty() || !self.open_decision_ids.is_empty() {
            return Err(PairedBackupError::UnknownInFlightOperations(
                self.pending_operation_ids.len() + self.open_decision_ids.len(),
            ));
        }
        let mut clean = self.clone();
        clean.receipt_digest.clear();
        let expected = sha256_json_tagged(b"rootyard-close-scope-barrier-v1", &clean)?;
        if expected != self.receipt_digest {
            return Err(PairedBackupError::ScopeNotClosed("close barrier receipt digest mismatch".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedPackPairSpec {
    pub pack_id: Uuid,
    pub pack_sha256: String,
    pub pack_bytes: u64,
    pub idx_sha256: String,
    pub idx_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupRetentionHoldRecord {
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub snapshot_id: Uuid,
    pub pin_id: Uuid,
    pub pin_generation: i64,
    pub root_id: Uuid,
    pub hold_ids: Vec<Uuid>,
    pub pack_set_digest: String,
    pub raft_log_index: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PgProjectionCursorCut {
    pub group_id: i64,
    pub history_incarnation: Uuid,
    pub group_epoch: i64,
    pub applied_event_seq: i64,
    pub applied_log_index: i64,
    pub applied_log_term: i64,
    pub last_event_id: Option<String>,
    pub stream_state: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PgRepositoryRowProof {
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub object_format: GitObjectFormat,
    pub storage_backend: String,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
    pub group_epoch: i64,
    pub gate_revision: i64,
    pub refs_digest: String,
    pub refs: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PgCutpointProof {
    pub schema_head_version: i64,
    pub wal_lsn: String,
    pub snapshot_tx: String,
    pub postgres_major_version: String,
    pub source_cluster_incarnation: Uuid,
    pub source_storage_authority_id: Uuid,
    pub source_storage_generation: i64,
    pub remote_delete_fenced: bool,
    pub max_decision_scope_version: i64,
    pub pending_decisions_count: i64,
    pub pending_outbox_count: i64,
    pub projection_cursors: Vec<PgProjectionCursorCut>,
    pub repositories: Vec<PgRepositoryRowProof>,
    pub cutpoint_digest: String,
}

impl PgCutpointProof {
    pub fn seal(mut self) -> Result<Self, PairedBackupError> {
        self.cutpoint_digest.clear();
        self.cutpoint_digest = sha256_json_tagged(b"rootyard-pg-cutpoint-proof-v1", &self)?;
        Ok(self)
    }

    pub fn verify(&self) -> Result<(), PairedBackupError> {
        if self.wal_lsn.is_empty()
            || self.snapshot_tx.is_empty()
            || !self.remote_delete_fenced
            || self.max_decision_scope_version < 0
            || self.projection_cursors.is_empty()
        {
            return Err(PairedBackupError::IncompleteCut(
                "PG cutpoint missing LSN/snapshot/cursors, negative scope version, or unfenced deleter",
            ));
        }
        for c in &self.projection_cursors {
            if c.group_epoch <= 0 || c.history_incarnation.is_nil() || c.stream_state != "active" {
                return Err(PairedBackupError::CutpointSkew(
                    "PG projection cursor has invalid group_epoch, nil incarnation, or non-active stream".into(),
                ));
            }
        }
        if self.pending_decisions_count != 0 || self.pending_outbox_count != 0 {
            return Err(PairedBackupError::UnknownInFlightOperations(
                (self.pending_decisions_count + self.pending_outbox_count).max(1) as usize,
            ));
        }
        let mut clean = self.clone();
        clean.cutpoint_digest.clear();
        let expected = sha256_json_tagged(b"rootyard-pg-cutpoint-proof-v1", &clean)?;
        if expected != self.cutpoint_digest {
            return Err(PairedBackupError::CutpointSkew("PG cutpoint digest mismatch".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RaftCutpointProof {
    pub group_id: i64,
    pub group_epochs: BTreeMap<i64, i64>,
    pub peer_groups: Vec<PeerRaftCutpointProof>,
    pub applied_log_id: AppliedLogId,
    pub min_consensus_index: u64,
    pub logical_clock_floor: u64,
    pub state_digest: String,
    pub group_membership_digest: String,
    pub voter_ids: Vec<Uuid>,
    pub cutpoint_attestations: Vec<PeerDurableAttestation>,
    pub snapshot_checksum: String,
    pub snapshot: RefCasSnapshot,
    pub close_receipts: Vec<CloseScopeBarrierReceipt>,
    pub backup_holds: Vec<BackupRetentionHoldRecord>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlobArtifactEntry {
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub pack_id: Uuid,
    pub object_format: GitObjectFormat,
    pub role: String,
    pub locator_path: String,
    pub archive_rel_path: String,
    pub attempt_id: Uuid,
    pub generation: i64,
    pub length: u64,
    pub sha256: String,
    pub backend_identity: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlobClosureManifest {
    pub backend_identity: String,
    pub provider: String,
    pub total_artifacts: usize,
    pub total_bytes: u64,
    pub entries: Vec<BlobArtifactEntry>,
    pub closure_digest: String,
}

impl BlobClosureManifest {
    pub fn seal(mut self) -> Result<Self, PairedBackupError> {
        self.entries.sort_by(|a, b| a.archive_rel_path.cmp(&b.archive_rel_path));
        self.closure_digest.clear();
        self.closure_digest = sha256_json_tagged(b"rootyard-blob-closure-manifest-v1", &self)?;
        Ok(self)
    }

    pub fn verify(&self) -> Result<(), PairedBackupError> {
        if !validate_hex64(&self.backend_identity) || self.entries.is_empty() {
            return Err(PairedBackupError::BlobClosureIncomplete("empty closure or invalid backend identity".into()));
        }
        if self.total_artifacts != self.entries.len() {
            return Err(PairedBackupError::BlobClosureIncomplete("artifact count mismatch".into()));
        }
        let sum: u64 = self.entries.iter().map(|e| e.length).sum();
        if sum != self.total_bytes {
            return Err(PairedBackupError::BlobClosureIncomplete("byte sum mismatch".into()));
        }
        let mut clean = self.clone();
        clean.closure_digest.clear();
        let expected = sha256_json_tagged(b"rootyard-blob-closure-manifest-v1", &clean)?;
        if expected != self.closure_digest {
            return Err(PairedBackupError::CorruptBlobOrDigest("Blob closure digest mismatch".into()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PairedBackupManifest {
    pub format_version: String,
    pub backup_id: Uuid,
    pub created_unix_seconds: u64,
    pub freeze: FreezePartyStatus,
    pub pg_cutpoint: PgCutpointProof,
    pub raft_cutpoint: RaftCutpointProof,
    pub blob_closure: BlobClosureManifest,
    pub paired_cut_digest: String,
}

impl PairedBackupManifest {
    pub fn seal(mut self) -> Result<Self, PairedBackupError> {
        self.paired_cut_digest.clear();
        self.paired_cut_digest = sha256_json_tagged(b"rootyard-paired-backup-manifest-v1", &self)?;
        Ok(self)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NewIncarnationAuthority {
    pub new_cluster_incarnation: Uuid,
    pub new_storage_authority_id: Uuid,
    pub new_storage_generation: i64,
    pub new_history_incarnation: Uuid,
    pub new_authority_epoch: i64,
    pub new_group_epoch: i64,
    pub new_authz_floor: i64,
    pub new_deleter_epoch: u64,
    pub fenced_prior_incarnations: BTreeSet<Uuid>,
    pub fenced_pre_backup_decision_ids: BTreeSet<Uuid>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreOutcome {
    pub backup_id: Uuid,
    pub restored_repos: usize,
    pub restored_blobs: usize,
    pub reused_blobs: usize,
    pub git_verified_refs: usize,
    pub incarnation: NewIncarnationAuthority,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WriterGrantTicket {
    pub cluster_incarnation: Uuid,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
    pub group_epoch: i64,
    pub authz_epoch: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionExecutionTicket {
    pub decision_id: Uuid,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
    pub group_epoch: i64,
    pub authz_epoch: i64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeleterLeaseTicket {
    pub cluster_incarnation: Uuid,
    pub storage_authority_id: Uuid,
    pub storage_generation: i64,
    pub deleter_epoch: u64,
}
