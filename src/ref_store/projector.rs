//! Ref-CAS Git event replay, PostgreSQL projection, reliable job bridge,
//! truncation closure, and Raft session/dependency consistency (#117, #175).

pub mod bridge;
pub mod dependency;
pub mod identity;
pub mod jobs;
pub mod memory;
pub mod pg;
pub mod replay;
pub mod session_fence;
#[cfg(test)]
mod session_tests;
pub mod types;

pub use bridge::{run_projection_job_worker_once, sync_webhooks_bounded};
pub use dependency::{
    ProjectionDependencyError, ProjectionDependencyTarget, VerifiedProjectionWait, apply_projection_step_atomically,
    apply_projection_stream_stop_on_gap, await_projected_event, verify_projection_dependency,
};
pub use identity::{
    compute_terminal_digest, compute_truncation_closure_digest, derive_job_key, derive_operation_event_id,
    derive_ref_event_id, derive_webhook_event_id,
};
pub use jobs::{
    claim_next_projection_job, finish_projection_job, process_due_projection_jobs,
    sync_projected_ref_cas_webhooks_bounded,
};
pub use memory::{InMemoryProjectionLedger, InMemorySmEventSource, SimulatedFault};
pub use pg::{
    complete_cursor_resync_in_tx, load_cursor, load_or_init_cursor_for_update, project_event_in_tx,
    projection_tables_present, record_truncation_cutoff_in_tx, replay_page_to_pg,
    verify_projected_operation_non_authorizing,
};
pub use replay::{
    CursorTransition, assert_projection_cannot_authorize_write, check_stream_continuity, complete_cursor_resync,
    plan_operation_projection, reconcile_cutoff_on_cursor, refuse_write_from_historical_receipt, validate_cursor_step,
};
pub use session_fence::{
    AdmittedRaftRead, AuthoritySourceKind, CallerAccessState, MAX_LIFETIME_SECONDS, MAX_RAFT_TOKEN_LEN,
    MIN_LIFETIME_SECONDS, RAFT_SESSION_HEADER, RAFT_TOKEN_PREFIX, RaftProbeOutcome, RaftReadProof, RaftSessionCodec,
    RaftSessionLowerBound, RaftSessionRealm, SessionFenceError, assert_authoritative_source,
    await_raft_read_or_redirect, current_unix_seconds, evaluate_raft_read,
};
pub use types::{
    DEFAULT_REPLAY_BATCH, MAX_REPLAY_BATCH, PlannedOperationProjection, ProjectedOperationRecord, ProjectedRefDelta,
    ProjectedRefState, ProjectionCursor, ProjectionError, ProjectionJobKind, ProjectionJobRecord, ProjectionJobSpec,
    ProjectionJobState, ProjectionRealm, ProjectionStreamState, RefCasEventEnvelope, RefCasEventPage,
    ReplayBatchOutcome, SingleEventOutcome, TerminalOutcomeSummary, TruncationCutoff,
};
