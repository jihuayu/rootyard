//! No-delete, pack-hash-sharded Rubicon Blob compaction subsystem (#162).
//!
//! Independently delivers log-structured `open -> sealed` tiered compaction over
//! authoritative `.pack` / `.idx` Blob closures with durable lease fencing,
//! isolated maintenance concurrency/rewrite/scratch budgets, exact OID/root/delta-base
//! equivalence verification (`SHA-1` & `SHA-256`), and CAS membership
//! publication while keeping physical deletion strictly disabled (`#122`).

#[path = "rubicon_compaction/budget.rs"]
pub mod budget;
#[path = "rubicon_compaction/executor.rs"]
pub mod executor;
#[path = "rubicon_compaction/git_ops.rs"]
mod git_ops;
#[path = "rubicon_compaction/lease.rs"]
pub mod lease;
#[path = "rubicon_compaction/segment.rs"]
pub mod segment;
#[path = "rubicon_compaction/sharding.rs"]
pub mod sharding;
#[path = "rubicon_compaction/store.rs"]
pub mod store;
#[path = "rubicon_compaction/store_cas.rs"]
mod store_cas;
#[cfg(test)]
#[path = "rubicon_compaction/unit_tests.rs"]
mod unit_tests;

use std::fmt;

pub use budget::{
    CompactionBudgetConfig, CompactionBudgetMetricsSnapshot, CompactionGitPermit, CompactionJobPermit,
    CompactionResourceBudget,
};
pub use executor::{
    CompactionBlobUploader, CompactionRunOutcome, CompactionRunRequest, PublishedCompaction, UploadedPackPair,
    execute_shard_compaction, execute_shard_compaction_with_retry,
};
pub use lease::{
    CompactionAuthoritativeSnapshot, CompactionAuthorityStore, CompactionEquivalenceProof, CompactionFaultHook,
    CompactionLeaseKey, CompactionLeaseToken, CompactionPhase, CompactionPublishReceipt, CompactionPublishRequest,
    ConcurrentPushFault, PendingOperationRecord,
};
pub use segment::{
    CompactionByteAccounting, CompactionSegmentLog, IngestOutcome, PackSegment, SegmentState, SegmentTier,
    SegmentTriggerPolicy, TieredMergePlan,
};
pub use sharding::{
    CompactionPackEntry, CompactionRef, CompactionShardRouter, authoritative_refs_digest, pack_set_digest, refs_digest,
    retention_roots_digest, shard_for_pack_hash,
};
pub use store::DurableCompactionStore;

use crate::blob_store::{
    BlobError,
    disposable_view::DisposableViewError,
    envelope::EnvelopeError,
    read_accel::{ReadAccelError, ReadAccelManifestError},
};

pub const RUBICON_COMPACTION_SCHEMA: u32 = 1;
/// No-delete compaction invariant: old input packs remain retained for `#122`/`#151`/`#153`.
pub const DELETE_OLD_PACKS_BY_DEFAULT: bool = false;
pub const DEFAULT_COMPACTED_PACK_NAMESPACE: &str = "packs";
pub const DEFAULT_SHARD_COUNT: u16 = 8;

#[derive(Debug)]
pub enum CompactionError {
    InvalidInput(String),
    DeleteForbidden,
    LeaseContended { owner: String },
    LeaseLost(&'static str),
    MembershipDrift(String),
    OperationConflict(&'static str),
    EquivalenceFailed(String),
    BudgetExceeded(String),
    Blob(BlobError),
    Envelope(EnvelopeError),
    DisposableView(DisposableViewError),
    ReadAccel(ReadAccelError),
    Manifest(ReadAccelManifestError),
    GitCommandFailed { command: String, detail: String },
    DeadlineExceeded,
    Serialization(String),
    Io(String),
}

impl fmt::Display for CompactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(msg) => write!(f, "invalid compaction input: {msg}"),
            Self::DeleteForbidden => f.write_str("physical Blob deletion is disabled during #162 compaction"),
            Self::LeaseContended { owner } => write!(f, "compaction shard lease held by `{owner}`"),
            Self::LeaseLost(reason) => write!(f, "compaction lease lost: {reason}"),
            Self::MembershipDrift(detail) => write!(f, "authoritative membership drifted before CAS: {detail}"),
            Self::OperationConflict(reason) => write!(f, "compaction operation conflict: {reason}"),
            Self::EquivalenceFailed(reason) => write!(f, "compaction closure equivalence failed: {reason}"),
            Self::BudgetExceeded(reason) => write!(f, "maintenance compaction budget exceeded: {reason}"),
            Self::Blob(err) => write!(f, "{err}"),
            Self::Envelope(err) => write!(f, "{err}"),
            Self::DisposableView(err) => write!(f, "{err}"),
            Self::ReadAccel(err) => write!(f, "{err}"),
            Self::Manifest(err) => write!(f, "{err}"),
            Self::GitCommandFailed { command, detail } => write!(f, "git `{command}` failed: {detail}"),
            Self::DeadlineExceeded => f.write_str("compaction deadline exceeded"),
            Self::Serialization(msg) => write!(f, "compaction serialization error: {msg}"),
            Self::Io(msg) => write!(f, "compaction IO error: {msg}"),
        }
    }
}

impl std::error::Error for CompactionError {}

impl From<BlobError> for CompactionError {
    fn from(v: BlobError) -> Self {
        Self::Blob(v)
    }
}

impl From<EnvelopeError> for CompactionError {
    fn from(v: EnvelopeError) -> Self {
        Self::Envelope(v)
    }
}

impl From<DisposableViewError> for CompactionError {
    fn from(v: DisposableViewError) -> Self {
        Self::DisposableView(v)
    }
}

impl From<ReadAccelError> for CompactionError {
    fn from(v: ReadAccelError) -> Self {
        Self::ReadAccel(v)
    }
}

impl From<ReadAccelManifestError> for CompactionError {
    fn from(v: ReadAccelManifestError) -> Self {
        Self::Manifest(v)
    }
}
