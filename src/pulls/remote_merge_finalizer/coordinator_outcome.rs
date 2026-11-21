//! Deterministic mapping of Ref-CAS state-machine errors to commit outcomes.

use std::future::Future;
use std::pin::Pin;

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ref_store::contract::RefStoreError;
use crate::ref_store::core::state_machine::{
    AppliedLogId, CommitScopedRefsCommand, InstallScopedDecisionCommand, StateMachineError,
};
use crate::ref_store::core::terminal::{CommitRejectCode, CommitTerminal};

use super::RemoteMergeError;

pub type BackendFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, RemoteMergeError>> + Send + 'a>>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityCommitOutcome {
    Committed {
        log_index: u64,
        log_term: u64,
        gate_revision: i64,
        merged_oid: String,
        terminal_digest: String,
        replayed: bool,
    },
    Rejected {
        log_index: Option<u64>,
        log_term: Option<u64>,
        reject_code: CommitRejectCode,
        actual_base_oid: Option<String>,
        terminal_digest: Option<String>,
        reason: String,
    },
    Cancelled { log_index: Option<u64>, log_term: Option<u64>, reason: String },
    UnknownPending { reason: String },
}

pub trait MergeAuthorityBackend: Send + Sync {
    fn install_and_commit_scoped<'a>(
        &'a self,
        repository_id: Uuid,
        base_ref: &'a str,
        install: InstallScopedDecisionCommand,
        commit: CommitScopedRefsCommand,
    ) -> BackendFuture<'a, AuthorityCommitOutcome>;

    fn query_operation_outcome<'a>(
        &'a self,
        repository_id: Uuid,
        operation_id: Uuid,
        base_ref: &'a str,
    ) -> BackendFuture<'a, Option<AuthorityCommitOutcome>>;

    fn read_ref_oid<'a>(&'a self, repository_id: Uuid, ref_name: &'a str) -> BackendFuture<'a, Option<String>>;
}

pub(super) fn canonical_terminal_digest(terminal: &CommitTerminal) -> String {
    let bytes = serde_json::to_vec(terminal).unwrap_or_default();
    hex::encode(Sha256::digest(&bytes))
}

pub fn map_sm_error_to_outcome(
    log_id: Option<AppliedLogId>,
    err: StateMachineError,
    actual_base_oid: Option<String>,
) -> AuthorityCommitOutcome {
    let idx = log_id.map(|id| id.index);
    let term = log_id.map(|id| id.term);
    let cancellation_reason = err.to_string();
    match err {
        StateMachineError::AuthzFloorViolation { .. }
        | StateMachineError::ScopeClosingOrClosed { .. }
        | StateMachineError::DecisionExpired { .. }
        | StateMachineError::Store(RefStoreError::Cancelled { .. }) => AuthorityCommitOutcome::Cancelled {
            log_index: idx,
            log_term: term,
            reason: cancellation_reason,
        },
        StateMachineError::DecisionDigestMismatch { reason, .. } => AuthorityCommitOutcome::Rejected {
            log_index: idx,
            log_term: term,
            reject_code: CommitRejectCode::RevisionMismatch,
            actual_base_oid,
            terminal_digest: None,
            reason: reason.to_owned(),
        },
        other => AuthorityCommitOutcome::Rejected {
            log_index: idx,
            log_term: term,
            reject_code: CommitRejectCode::PolicyDenied,
            actual_base_oid,
            terminal_digest: None,
            reason: other.to_string(),
        },
    }
}
