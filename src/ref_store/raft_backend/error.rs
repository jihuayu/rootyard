//! Fail-closed backend errors without payload, token, key, or SQL text leakage.

use std::fmt;

use rootyard_refcas_log::state_machine::ApplicationLogId;

use crate::ref_store::raft_backend::proposal::ProposalId;

/// Authoritative backend refusal. Every variant is a hard failure; there is no PG/Redis/local
/// fallback path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RaftBackendError {
    /// Trusted configuration is incomplete or invalid.
    InvalidConfig(&'static str),
    /// Command repository/tenant/group/authority coordinate differs from the trusted binding.
    ScopeMismatch(&'static str),
    /// The presented realm/epoch/generation does not equal the trusted configured realm.
    StaleRealm,
    /// A proposal identity is malformed or outside the fixed protocol.
    InvalidProposal(&'static str),
    /// A proposal identity does not match the backend/view repository/tenant/realm scope.
    ProposalScopeMismatch(&'static str),
    /// A retained decision cannot be minted into a successful close requirement.
    ScopeCloseNotRecoverable(&'static str),
    /// A drain query/conversion was attempted for a different close trust/domain/coordinate.
    ScopeDrainBindingMismatch(&'static str),
    /// The applied Root gate does not match the trusted realm on the named axis.
    StaleGate(&'static str),
    /// This node is not the leader; no local or projection read was substituted.
    FollowerRedirect(Option<u64>),
    /// No actual quorum proof was obtained within the bounded deadline.
    QuorumUnavailable(&'static str),
    /// The local application apply barrier did not reach the quorum ReadIndex coordinate.
    ApplyBarrierTimeout { applied: Option<ApplicationLogId>, required: Option<ApplicationLogId> },
    /// The committed entry applied without a durable typed outcome at its exact coordinate.
    OutcomeMissing(ApplicationLogId),
    /// The stored outcome belongs to a different canonical command payload.
    OutcomeDigestMismatch(ApplicationLogId),
    /// A committed retry's exact receipt is no longer observed within its valid window.
    RecoveryNotObserved(Box<ProposalId>),
    /// Owned-node control/peer RPC failure.
    NodeControl(&'static str),
    /// The persistent state machine was not opened with the root Ref-CAS reducer.
    NotApplicationMode,
    /// The opened application reducer is not the root Ref-CAS adapter.
    WrongReducer,
    /// The owned factory could not create its real Raft node/storage pair.
    NodeStart(&'static str),
    /// The owned factory could not shut down its real Raft node.
    NodeShutdown(&'static str),
    /// Persistence/read failed; the message is intentionally fixed/bounded.
    Storage(&'static str),
    /// Command encoding or envelope bounds refused the write before Raft append.
    Encode(&'static str),
    /// Deterministic state-machine refusal. It carries no caller payload or credentials.
    Command(String),
}

impl fmt::Display for RaftBackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => write!(f, "invalid raft backend configuration: {reason}"),
            Self::ScopeMismatch(coordinate) => {
                write!(f, "command {coordinate} is outside the trusted repository/tenant/realm binding")
            }
            Self::StaleRealm => f.write_str("presented realm/epoch/storage generation is stale"),
            Self::InvalidProposal(reason) => write!(f, "invalid proposal identity: {reason}"),
            Self::ProposalScopeMismatch(axis) => write!(f, "proposal identity does not match {axis}"),
            Self::ScopeCloseNotRecoverable(reason) => {
                write!(f, "scope close requirement cannot be recovered: {reason}")
            }
            Self::ScopeDrainBindingMismatch(axis) => {
                write!(f, "scope drain observation does not match the required close binding on {axis}")
            }
            Self::RecoveryNotObserved(id) => {
                write!(f, "proposal {id:?} has no observed exact receipt within its valid window")
            }
            Self::NodeControl(operation) => write!(f, "owned Raft node control failed during {operation}"),
            Self::StaleGate(axis) => write!(f, "live Root gate does not match the trusted realm on {axis}"),
            Self::FollowerRedirect(leader) => {
                write!(f, "leader redirect required (leader {leader:?}); follower cannot serve this view")
            }
            Self::QuorumUnavailable(operation) => {
                write!(f, "raft quorum unavailable during {operation}; no fallback read was attempted")
            }
            Self::ApplyBarrierTimeout { applied, required } => {
                write!(f, "local application apply barrier {applied:?} did not reach required coordinate {required:?}")
            }
            Self::OutcomeMissing(log_id) => {
                write!(f, "committed entry {log_id:?} has no durable typed business outcome")
            }
            Self::OutcomeDigestMismatch(log_id) => {
                write!(f, "committed entry {log_id:?} typed outcome digest does not match the command payload")
            }
            Self::NotApplicationMode => {
                f.write_str("persistent state machine is not opened with the root Ref-CAS reducer")
            }
            Self::WrongReducer => f.write_str("application reducer is not the root Ref-CAS adapter"),
            Self::NodeStart(operation) => write!(f, "owned Raft node start failed during {operation}"),
            Self::NodeShutdown(operation) => write!(f, "owned Raft node shutdown failed during {operation}"),
            Self::Storage(operation) => write!(f, "state-machine storage failure during {operation}"),
            Self::Encode(reason) => write!(f, "raft command refused before append: {reason}"),
            Self::Command(message) => write!(f, "state-machine refused command: {message}"),
        }
    }
}

impl std::error::Error for RaftBackendError {}

impl From<rootyard_refcas_log::E> for RaftBackendError {
    fn from(_: rootyard_refcas_log::E) -> Self {
        Self::Storage("application state-machine access")
    }
}
