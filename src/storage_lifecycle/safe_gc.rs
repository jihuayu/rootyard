//! Safe destructive Blob GC and two-phase read-back compaction (#122).
//!
//! Destructive physical deletion is disabled by default
//! ([`SAFE_GC_DESTRUCTIVE_ENABLED_BY_DEFAULT`] = `false` / [`GcMode::DisabledByDefault`]).
//! Enabling deletion requires explicit arming bound to a live incarnation and
//! lane ([`AuthorityLane::SingleNodePg`] or [`AuthorityLane::DistributedRefCas`]
//! with `#151` global hold bridge + `#153` remote backup root + Ref-CAS quorum),
//! plus a complete [`DeletionProof`] reconciling live refs, all 6 retention
//! producer domains, global holds, in-flight decisions, paired PG/Ref-CAS
//! cursors, and group closure receipts. Physical keys follow strict monotonic
//! anti-ABA non-reuse across generations, compaction retries, and restores.

#[path = "safe_gc/anti_aba.rs"]
pub mod anti_aba;
#[path = "safe_gc/compaction.rs"]
pub mod compaction;
#[path = "safe_gc/domain.rs"]
pub mod domain;
#[path = "safe_gc/error.rs"]
pub mod error;
#[path = "safe_gc/executor.rs"]
pub mod executor;
#[path = "safe_gc/git_ops.rs"]
pub mod git_ops;
#[path = "safe_gc/model.rs"]
pub mod model;
#[path = "safe_gc/proof.rs"]
pub mod proof;
#[path = "safe_gc/proof_digest.rs"]
mod proof_digest;
#[path = "safe_gc/store.rs"]
pub mod store;
#[path = "safe_gc/store_barrier.rs"]
mod store_barrier;
#[cfg(test)]
#[path = "safe_gc/tests.rs"]
mod tests;
#[cfg(test)]
#[path = "safe_gc/tests_concurrency.rs"]
mod tests_concurrency;

pub use anti_aba::{AntiAbaKeyRegistry, KeyLifecycleState, PhysicalBlobKey};
pub use compaction::{SafeGcCompactionRequest, SafeGcCompactionResult, execute_two_phase_compaction};
pub use domain::{
    AuthorityRecord, BlobStoreReadbackBackend, CasCompactionPublish, CompactionPublishResult,
    DeleteAuthorizationTicket, DeleteExecutionReport, GcAuditEvent, SafeGcCompactionUploader, SafeGcDeleteBackend,
    UploadedCompactionPair,
};
pub use error::SafeGcError;
pub use executor::{
    DeleteFaultHook, SafeGcSweepRequest, execute_safe_gc_sweep, reconcile_pending_delete_after_restart,
};
pub use model::{
    AuthorityLane, CandidatePackTarget, DecisionKind, DecisionState, GcMode, GlobalHoldEntry, GlobalHoldState,
    GroupClosureReceipt, InFlightDecisionRecord, LiveRefRoot, MAX_CANDIDATES_PER_SWEEP, MAX_DELETION_ROOTS,
    MAX_GLOBAL_HOLDS, MAX_GROUPS_PER_PROOF, MAX_IN_FLIGHT_DECISIONS, MAX_PACKS_PER_CLOSURE, PairedCursorReconciliation,
    ProducerReconciliationEntry, RetentionProducer, SAFE_GC_DESTRUCTIVE_ENABLED_BY_DEFAULT, SAFE_GC_SCHEMA_VERSION,
    SafeGcArmReceipt, SafeGcObjectFormat, SourceFreshness,
};
pub use proof::{DeletionProof, DeletionProofInputs, build_and_verify_deletion_proof, verify_deletion_proof};
pub use store::{DurableSafeGcAuthority, SafeGcRepoSnapshot};
