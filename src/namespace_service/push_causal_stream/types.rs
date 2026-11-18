//! Contract types, strict resource bounds, auth policy, and error model (#183).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::blob_store::{BlobError, BlobLocator, closure::BlobClosureError};
use crate::ref_store::contract::{OperationIdentity, RefStoreError, RequestDigest};
use crate::ref_store::core::pack_commit::contract::VERIFIER_PIPE_BYTES;
use crate::ref_store::core::ref_version::{PackSetEntry, RefVersionRealm, VersionId};
use crate::ref_store::core::types::{GitObjectFormat, RefName};

/// 64 KiB streaming I/O buffer size keeping push RAM footprint strictly bounded.
pub const STREAM_CHUNK_BYTES: usize = 64 * 1024;
/// Default ceiling for uncompressed Smart HTTP `receive-pack` stream bytes (128 MiB).
pub const DEFAULT_MAX_STREAM_BYTES: u64 = 128 * 1024 * 1024;
/// Default ceiling for the pkt-line command section before the `PACK` header.
pub const DEFAULT_MAX_COMMAND_BYTES: usize = 128 * 1024;
/// Default max ref commands accepted in one push (`MAX_REFS_PER_COMMIT = 128`).
pub const DEFAULT_MAX_COMMANDS: usize = 128;
/// Default cap on objects carried inside one pushed pack (`VERIFIER_MAX_OBJECTS = 16,384`).
pub const DEFAULT_MAX_PACK_OBJECTS: u32 = 16_384;
/// Default max OFS/REF delta chain depth permitted during pack verification.
pub const DEFAULT_MAX_DELTA_DEPTH: u32 = 50;
/// Default max single unpacked object size (16 MiB).
pub const DEFAULT_MAX_UNPACKED_OBJECT_BYTES: u64 = 16 * 1024 * 1024;
/// Default max total unpacked object payload across the pushed pack (128 MiB).
pub const DEFAULT_MAX_INFLATED_PACK_BYTES: u64 = 128 * 1024 * 1024;
/// Default max Git LFS pointer blob size scanned during closure verification.
pub const DEFAULT_MAX_LFS_POINTER_BYTES: u64 = 1024;

/// Pipeline scheduling policy controlling upload vs. local verification overlap.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PackPipelineMode {
    /// Complete local pack indexing & closure verification strictly before Blob upload.
    Sequential,
    /// Run quarantined Blob PUT + readback concurrently with deep Git closure verification (`tokio::try_join!`).
    #[default]
    OverlappedPipeline,
}

/// Hard resource and inflation budgets enforced during streaming ingest and Git verify.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StreamIngestLimits {
    pub max_stream_bytes: u64,
    pub max_command_bytes: usize,
    pub max_commands: usize,
    pub max_pack_objects: u32,
    pub max_delta_depth: u32,
    pub max_unpacked_object_bytes: u64,
    pub max_inflated_pack_bytes: u64,
    pub max_lfs_pointer_bytes: u64,
    pub allow_shallow: bool,
    pub require_report_status: bool,
}

impl Default for StreamIngestLimits {
    fn default() -> Self {
        Self {
            max_stream_bytes: DEFAULT_MAX_STREAM_BYTES,
            max_command_bytes: DEFAULT_MAX_COMMAND_BYTES,
            max_commands: DEFAULT_MAX_COMMANDS,
            max_pack_objects: DEFAULT_MAX_PACK_OBJECTS,
            max_delta_depth: DEFAULT_MAX_DELTA_DEPTH,
            max_unpacked_object_bytes: DEFAULT_MAX_UNPACKED_OBJECT_BYTES,
            max_inflated_pack_bytes: DEFAULT_MAX_INFLATED_PACK_BYTES,
            max_lfs_pointer_bytes: DEFAULT_MAX_LFS_POINTER_BYTES,
            allow_shallow: false,
            require_report_status: false,
        }
    }
}

/// Resource bounds applied via POSIX `setrlimit` on isolated stock-Git child processes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitSubprocessLimits {
    pub cpu_seconds: u64,
    pub address_space_bytes: u64,
    pub file_size_bytes: u64,
    pub max_open_files: u64,
    pub max_pipe_bytes: usize,
}

impl Default for GitSubprocessLimits {
    fn default() -> Self {
        Self {
            cpu_seconds: 30,
            address_space_bytes: 512 * 1024 * 1024,
            file_size_bytes: 256 * 1024 * 1024,
            max_open_files: 64,
            max_pipe_bytes: VERIFIER_PIPE_BYTES,
        }
    }
}

/// Capabilities negotiated on the Git Smart HTTP `receive-pack` command stream.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReceiveCapabilities {
    pub report_status: bool,
    pub report_status_v2: bool,
    pub sideband_64k: bool,
    pub atomic: bool,
    pub ofs_delta: bool,
    pub delete_refs: bool,
    pub quiet: bool,
    pub agent: Option<String>,
    pub object_format: Option<GitObjectFormat>,
}

/// Validated per-ref command decoded from the Smart HTTP `receive-pack` prefix.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PushedRefCommand {
    pub ref_name: String,
    pub old_oid: String,
    pub new_oid: String,
}

impl PushedRefCommand {
    pub fn is_create(&self) -> bool {
        self.old_oid.bytes().all(|b| b == b'0')
    }

    pub fn is_delete(&self) -> bool {
        self.new_oid.bytes().all(|b| b == b'0')
    }

    pub fn validated_ref_name(&self) -> Result<RefName, PushCausalError> {
        RefName::new(self.ref_name.clone()).map_err(|e| PushCausalError::MalformedProtocol(e.to_string()))
    }
}

/// Live principal authorization context verified at ingest AND rechecked pre-commit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PushAuthContext {
    pub actor_id: Uuid,
    pub token_scope_id: Option<Uuid>,
    pub session_scope_id: Option<Uuid>,
    pub lease_id: Option<Uuid>,
    pub lease_expires_at_ms: Option<u64>,
    pub now_ms: u64,
    pub principal_authz_epoch: i64,
    pub min_required_authz_epoch: i64,
    pub write_authorized: bool,
    pub allow_force_push: bool,
    pub allow_branch_delete: bool,
    pub protected_branches: BTreeSet<String>,
    pub visible_refs: BTreeSet<String>,
}

impl PushAuthContext {
    pub fn check_active(&self) -> Result<(), PushCausalError> {
        if self.actor_id.is_nil() {
            return Err(PushCausalError::AuthorizationDenied("actor_id must be non-nil"));
        }
        if !self.write_authorized {
            return Err(PushCausalError::AuthorizationDenied("write permission denied or revoked"));
        }
        if self.principal_authz_epoch < self.min_required_authz_epoch {
            return Err(PushCausalError::AuthorizationDenied("principal authz epoch behind repository floor"));
        }
        if let Some(exp) = self.lease_expires_at_ms
            && self.now_ms >= exp
        {
            return Err(PushCausalError::StaleLease("caller auth lease expired before commit"));
        }
        Ok(())
    }
}

/// Branch write policy enforced before Ref-CAS commit.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BranchPolicy {
    pub fast_forward_only_prefixes: Vec<String>,
    pub require_commit_for_branches: bool,
}

/// Verified remote Blob reference for a base pack already anchored in an authorized snapshot.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BasePackRef {
    pub version_id: String,
    pub pack_id: Uuid,
    pub registration_id: Uuid,
    pub artifact_set_digest_hex: String,
    pub pack_sha256: String,
    pub pack_length: u64,
    pub idx_sha256: String,
    pub idx_length: u64,
    pub pack_locator: BlobLocator,
    pub idx_locator: BlobLocator,
    pub authorized_for_principal: bool,
}

impl BasePackRef {
    pub fn pack_set_entry(&self) -> Result<PackSetEntry, PushCausalError> {
        let digest = RequestDigest::from_str(&self.artifact_set_digest_hex)?;
        PackSetEntry::new(self.pack_id, self.registration_id, digest)
            .map_err(|e| PushCausalError::UnauthorizedBaseDependency(e.to_string()))
    }
}

/// Expected verified Blob backing a referenced Git LFS pointer (`sha256 -> locator`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LfsExpectedBlob {
    pub sha256: String,
    pub size: u64,
    pub locator: BlobLocator,
}

/// Git LFS pointer and remote byte verification policy.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub enum LfsPolicy {
    #[default]
    AllowPlainOnly,
    RequireVerifiedBlobs {
        expected_blobs: BTreeMap<String, LfsExpectedBlob>,
    },
}

/// Explicitly bound repository snapshot and `#180` version closure state for one push.
#[derive(Clone, Debug)]
pub struct AuthorizedSnapshotState {
    pub realm: RefVersionRealm,
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
    pub group_epoch: i64,
    pub expected_gate_revision: i64,
    pub object_format: GitObjectFormat,
    pub snapshot_seq: i64,
    pub root_version_id: Option<VersionId>,
    pub current_refs: BTreeMap<String, String>,
    pub authorized_base_packs: Vec<BasePackRef>,
}

/// Stable client operation ticket enabling retry convergence on crash or unknown ACK.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationTicket {
    pub issuer_id: Uuid,
    pub lane: String,
    pub sequence: i64,
    pub operation_id: Uuid,
}

impl OperationTicket {
    pub fn derive_operation_identity(
        &self,
        repository_id: Uuid,
        digest: RequestDigest,
    ) -> Result<OperationIdentity, RefStoreError> {
        let lane = crate::ref_store::contract::IssuerLane::new(&self.lane)?;
        OperationIdentity::new(repository_id, self.issuer_id, lane, self.sequence, self.operation_id, digest)
    }
}

/// Measured timing & byte telemetry across streaming ingest, Blob I/O, and Git verify.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PushStageTelemetry {
    pub pipeline_mode: PackPipelineMode,
    pub stream_wire_bytes: u64,
    pub pack_bytes: u64,
    pub idx_bytes: u64,
    pub blob_put_bytes: u64,
    pub blob_get_bytes: u64,
    pub stream_receive_ms: u64,
    pub verify_ms: u64,
    pub blob_upload_ms: u64,
    pub overlap_wall_saved_ms: u64,
    pub commit_ms: u64,
    pub quarantined_paths_swept: usize,
}

/// Fault-injection triggers for deterministic failure, revocation, and retry verification.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultInjectionHook {
    #[default]
    None,
    AbortAfterBlobQuarantineUpload,
    RevokeAuthBeforeCommit,
    SimulateUnknownAckAfterCommit,
}

/// Typed fail-closed errors returned across protocol parsing, quarantine, proof, and commit.
#[derive(Debug)]
pub enum PushCausalError {
    DeadlineExceeded,
    MalformedProtocol(String),
    ShallowRejected,
    LimitExceeded(&'static str),
    TruncatedPack(&'static str),
    CorruptPack(String),
    AuthorizationDenied(&'static str),
    StaleLease(&'static str),
    UnauthorizedBaseDependency(String),
    MissingDeltaBase(String),
    MissingCausalObject(String),
    LfsPointerInvalid(String),
    LfsObjectMissingOrCorrupt(String),
    ObjectFormatMismatch,
    ProofTampered(&'static str),
    ProofScopeMismatch,
    BranchPolicyDenied(String),
    AtomicBatchRejected { rejected_refs: Vec<String>, reason: String },
    CommitUnknown { operation_id: Uuid, detail: String },
    Blob(BlobError),
    BlobClosure(BlobClosureError),
    RefStore(RefStoreError),
    StateMachine(String),
    Io(String),
}

impl fmt::Display for PushCausalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeadlineExceeded => f.write_str("push causal stream deadline exceeded"),
            Self::MalformedProtocol(msg) => write!(f, "malformed receive-pack protocol: {msg}"),
            Self::ShallowRejected => f.write_str("shallow pushes are rejected on causal closure repositories"),
            Self::LimitExceeded(msg) => write!(f, "push stream budget exceeded: {msg}"),
            Self::TruncatedPack(msg) => write!(f, "truncated pack stream: {msg}"),
            Self::CorruptPack(msg) => write!(f, "corrupt pack stream: {msg}"),
            Self::AuthorizationDenied(msg) => write!(f, "authorization denied: {msg}"),
            Self::StaleLease(msg) => write!(f, "stale caller lease: {msg}"),
            Self::UnauthorizedBaseDependency(msg) => write!(f, "unauthorized or retired base dependency: {msg}"),
            Self::MissingDeltaBase(msg) => write!(f, "missing thin-pack delta base: {msg}"),
            Self::MissingCausalObject(msg) => write!(f, "missing causal dependency object: {msg}"),
            Self::LfsPointerInvalid(msg) => write!(f, "invalid Git LFS pointer: {msg}"),
            Self::LfsObjectMissingOrCorrupt(msg) => write!(f, "LFS object missing or digest mismatch: {msg}"),
            Self::ObjectFormatMismatch => f.write_str("repository object format mismatches push capabilities or pack"),
            Self::ProofTampered(msg) => write!(f, "causal proof verification failed: {msg}"),
            Self::ProofScopeMismatch => f.write_str("causal proof binding disagrees with repository/backend scope"),
            Self::BranchPolicyDenied(msg) => write!(f, "branch policy refused ref update: {msg}"),
            Self::AtomicBatchRejected { reason, .. } => write!(f, "atomic push batch rejected: {reason}"),
            Self::CommitUnknown { operation_id, detail } => {
                write!(f, "commit outcome unknown for operation {operation_id}: {detail}")
            }
            Self::Blob(err) => write!(f, "blob error: {err}"),
            Self::BlobClosure(err) => write!(f, "blob closure error: {err}"),
            Self::RefStore(err) => write!(f, "ref store error: {err}"),
            Self::StateMachine(msg) => write!(f, "ref-cas state machine error: {msg}"),
            Self::Io(msg) => write!(f, "push I/O error: {msg}"),
        }
    }
}

impl std::error::Error for PushCausalError {}

impl From<BlobError> for PushCausalError {
    fn from(value: BlobError) -> Self {
        Self::Blob(value)
    }
}

impl From<BlobClosureError> for PushCausalError {
    fn from(value: BlobClosureError) -> Self {
        Self::BlobClosure(value)
    }
}

impl From<RefStoreError> for PushCausalError {
    fn from(value: RefStoreError) -> Self {
        Self::RefStore(value)
    }
}
