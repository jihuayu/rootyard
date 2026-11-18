//! Recoverable remote-authz PR merge coordinator, Ref-CAS receipt projector,
//! and fail-closed validation facade (`Refs #156`).
//!
//! Git Ref-CAS receipts inside the ordered Raft / `RefCasStateMachine` log are the
//! sole authoritative merge commit point; PostgreSQL `forge_pulls` and durable
//! attempt projection tables update monotonically and never fabricate ref commits.

pub mod coordinator;
pub mod git_pack;
pub mod pg_store;
pub mod projector;
pub mod types;
pub mod validation;

#[cfg(test)]
mod unit_recovery_tests;
#[cfg(test)]
mod unit_tests;

pub use coordinator::{AuthorityCommitOutcome, InProcessRefCasBackend, MergeAuthorityBackend, PullRemoteMergeProducer};
pub use git_pack::{PrepareMergeInput, PreparedMergeCandidate, prepare_merge_candidate};
pub use pg_store::{PgMergeStore, init_remote_merge_tables};
pub use projector::{
    BoxFuture, InMemoryMergeStore, MergeReceiptStore, PullMergeReceiptProjector, RecoverablePullMergeFinalizer,
    ReconcileReport,
};
pub use types::{
    CheckRunSnapshot, CommittedMergeReceipt, LiveAuthzScopeState, MergeAttemptOutcome, MergeAttemptSpec,
    MergeBindingInputs, MergeFaultInjection, MergePullSnapshot, MergeStrategy, PendingMergeRecord,
    ProjectedPullRecord, ProjectionOutcome, PullMergeState, RejectedMergeReceipt, RemoteMergeError,
    compute_merge_binding_digest, compute_observed_checks_digest, compute_required_checks_digest,
};
pub use validation::{ValidatedMergeGrant, validate_merge_inputs_and_preconditions, verify_pull_remote_authz_grant};
