//! Safe destructive Blob GC and two-phase read-back compaction (#122).
//!
//! Destructive physical deletion is disabled by default
//! ([`SAFE_GC_DESTRUCTIVE_ENABLED_BY_DEFAULT`] = `false` / [`GcMode::DisabledByDefault`]).
//! Enabling deletion requires explicit arming, live reader quiescence, `#184`
//! `GcEligible` pack-cover retention classification, a complete [`DeletionProof`],
//! and continuous fence verification across real OpenDAL S3 provider operations.

#[path = "safe_gc/anti_aba.rs"]
pub mod anti_aba;
#[path = "safe_gc/compaction.rs"]
pub mod compaction;
#[path = "safe_gc/dist_auth.rs"]
pub mod dist_auth;
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
#[path = "safe_gc/pg_maintenance.rs"]
pub mod pg_maintenance;
#[path = "safe_gc/pg_maintenance_dist.rs"]
pub mod pg_maintenance_dist;
#[path = "safe_gc/pg_reconcile.rs"]
pub mod pg_reconcile;
#[path = "safe_gc/proof.rs"]
pub mod proof;
#[path = "safe_gc/proof_digest.rs"]
pub mod proof_digest;
#[path = "safe_gc/provider_delete.rs"]
pub mod provider_delete;
#[path = "safe_gc/quiescence.rs"]
pub mod quiescence;
#[path = "safe_gc/refcas_cut.rs"]
pub mod refcas_cut;
#[path = "safe_gc/retention_bridge.rs"]
pub mod retention_bridge;
#[path = "safe_gc/store.rs"]
pub mod store;
#[path = "safe_gc/store_barrier.rs"]
mod store_barrier;
#[path = "safe_gc/store_reconcile.rs"]
mod store_reconcile;
#[path = "safe_gc/store_verify.rs"]
mod store_verify;
#[cfg(test)]
#[path = "safe_gc/tests.rs"]
mod tests;
#[cfg(test)]
#[path = "safe_gc/tests_concurrency.rs"]
mod tests_concurrency;
#[cfg(test)]
#[path = "safe_gc/tests_reconcile.rs"]
mod tests_reconcile;

pub use anti_aba::{AntiAbaKeyRegistry, KeyLifecycleState, PhysicalBlobKey};
pub use compaction::{SafeGcCompactionRequest, SafeGcCompactionResult, execute_two_phase_compaction};
pub use dist_auth::{
    BackupRootEvidence, HoldBridgeEvidence, QuorumCommitEvidence, SafeGcEd25519Signer, SafeGcRepoTrustConfig,
};
pub use domain::{
    ActiveDeleteFence, AuthorityRecord, BlobStoreReadbackBackend, CasCompactionPublish, CompactionPublishResult,
    DeleteAuthorizationTicket, DeleteExecutionReport, GcAuditEvent, ProviderDeleteOutcome, RemotePresence,
    SafeGcCompactionUploader, SafeGcDeleteBackend, StagingCleanupReport, UploadedCompactionPair,
};
pub use error::SafeGcError;
pub use executor::{
    DeleteFaultHook, PostTicketDriftFault, SafeGcSweepRequest, execute_safe_gc_sweep,
    execute_safe_gc_sweep_with_external_fence, quarantine_abandoned_staging_without_delete,
    reclaim_abandoned_compaction_staging, reconcile_pending_delete_after_restart,
    reconcile_pending_delete_after_restart_fenced,
};
pub use model::{
    AuthorityLane, CandidatePackTarget, DecisionKind, DecisionState, GcMode, GlobalHoldEntry, GlobalHoldState,
    GroupClosureReceipt, InFlightDecisionRecord, LiveRefRoot, MAX_CANDIDATES_PER_SWEEP, MAX_DELETION_ROOTS,
    MAX_GLOBAL_HOLDS, MAX_GROUPS_PER_PROOF, MAX_IN_FLIGHT_DECISIONS, MAX_PACKS_PER_CLOSURE, PairedCursorReconciliation,
    ProducerReconciliationEntry, RetentionProducer, SAFE_GC_DESTRUCTIVE_ENABLED_BY_DEFAULT, SAFE_GC_SCHEMA_VERSION,
    SafeGcArmReceipt, SafeGcObjectFormat, SourceFreshness,
};
pub use pg_maintenance::{ENV_BLOB_SAFE_GC_DESTRUCTIVE, safe_gc_destructive_env_enabled, safe_gc_journal_path};
pub use pg_maintenance_dist::{
    FsSealedRefCasCutpointSource, InMemoryRefCasCutpointSource, PersistedRefCasCutpointEnvelope,
    ProductionRefCasAuthoritySource, RefCasCommitCutpointPublisher, RefCasCutpointSource,
    persist_refcas_cutpoint_snapshot, safe_gc_refcas_cutpoint_path,
};
pub use pg_reconcile::{reconcile_pg_refstore_authority, reconcile_refcas_quorum_into_authority};
pub use proof::{DeletionProof, DeletionProofInputs, build_and_verify_deletion_proof, verify_deletion_proof};
pub use provider_delete::{OpenDalS3GcProvider, S3OperatorCredentials};
pub use quiescence::{ActiveReaderLease, ReaderLeaseRegistry, ReaderQuiescenceObservation};
pub use refcas_cut::{RefCasReconciledCut, reconcile_refcas_cut_with_pg};
pub use store::{DurableSafeGcAuthority, SafeGcRepoSnapshot, ServingPackRecord};
