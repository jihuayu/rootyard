//! Fixed failure-phase frames for the two long Root Raft cases.
//!
//! Frames contain only a fixed case identifier, a closed phase code and a closed class code. They
//! never include panic payloads, error text, identities, paths, metrics or other runtime data. On
//! a real-case failure only, one fixed append-witness companion is written from retained listener
//! counters; it never changes the phase or class receipt.

use std::io::Write;

use rootyard::ref_store::projector::RemoteAuthzBridgeError;
use rootyard::ref_store::raft_backend::RaftBackendError;

#[path = "quorum_diagnostic.rs"]
mod quorum_diagnostic;

pub(crate) use quorum_diagnostic::{
    Operation, emit_append_witness, note_append_decoded, note_append_handled, note_append_written, observe_call,
    reset_append_witness,
};

pub(crate) const CASE_REAL: &str = "real_root_refcas_commands_through_quorum_mtls_sqlite_and_restart";
pub(crate) const CASE_SCOPE: &str =
    "scope_drain_support::privileged_scope_drain_query_is_quorum_bound_and_multirepo_complete";

pub(crate) trait PhaseLabel: Copy {
    fn code(self) -> &'static str;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Phase {
    Bootstrap,
    Provision,
    Commit,
    SemanticInputWrite,
    SemanticInputView,
    SemanticIdentityWrite,
    SemanticIdentityView,
    SemanticHealthyWrite,
    SemanticHealthyView,
    Concurrent,
    ClosingWrite,
    ClosingView,
    RefusedWrite,
    RefusedView,
    RefusalLookup,
    RefusalReplay,
    HealthyWrite,
    HealthyView,
    StandaloneProbe,
    Follower,
    Isolation,
    LiveAxes,
    Snapshot,
    Install,
    Reopen,
    Partition,
    Heal,
    FinalReopen,
}

impl PhaseLabel for Phase {
    fn code(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Provision => "provision",
            Self::Commit => "commit",
            Self::SemanticInputWrite => "semantic_input_write",
            Self::SemanticInputView => "semantic_input_view",
            Self::SemanticIdentityWrite => "semantic_identity_write",
            Self::SemanticIdentityView => "semantic_identity_view",
            Self::SemanticHealthyWrite => "semantic_healthy_write",
            Self::SemanticHealthyView => "semantic_healthy_view",
            Self::Concurrent => "concurrent",
            Self::ClosingWrite => "closing_write",
            Self::ClosingView => "closing_view",
            Self::RefusedWrite => "refused_write",
            Self::RefusedView => "refused_view",
            Self::RefusalLookup => "refusal_lookup",
            Self::RefusalReplay => "refusal_replay",
            Self::HealthyWrite => "healthy_write",
            Self::HealthyView => "healthy_view",
            Self::StandaloneProbe => "standalone_probe",
            Self::Follower => "follower",
            Self::Isolation => "isolation",
            Self::LiveAxes => "live_axes",
            Self::Snapshot => "snapshot",
            Self::Install => "install",
            Self::Reopen => "reopen",
            Self::Partition => "partition",
            Self::Heal => "heal",
            Self::FinalReopen => "final_reopen",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScopePhase {
    Bootstrap,
    Provision,
    Install,
    Close,
    Recover,
    RecoveryRejections,
    InitialDrain,
    BindingRejections,
    ForeignBootstrap,
    ForeignAdvance,
    ForeignRejection,
    PendingBridge,
    Cancel,
    SettledDrain,
    SettledEvaluate,
    SettledBridge,
    Follower,
    InvalidOptions,
    Partition,
    Heal,
    Shutdown,
}

impl PhaseLabel for ScopePhase {
    fn code(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Provision => "provision",
            Self::Install => "install",
            Self::Close => "close",
            Self::Recover => "recover",
            Self::RecoveryRejections => "recovery_rejections",
            Self::InitialDrain => "initial_drain",
            Self::BindingRejections => "binding_rejections",
            Self::ForeignBootstrap => "foreign_bootstrap",
            Self::ForeignAdvance => "foreign_advance",
            Self::ForeignRejection => "foreign_rejection",
            Self::PendingBridge => "pending_bridge",
            Self::Cancel => "cancel",
            Self::SettledDrain => "settled_drain",
            Self::SettledEvaluate => "settled_evaluate",
            Self::SettledBridge => "settled_bridge",
            Self::Follower => "follower",
            Self::InvalidOptions => "invalid_options",
            Self::Partition => "partition",
            Self::Heal => "heal",
            Self::Shutdown => "shutdown",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Class {
    AssertionPanic,
    ProposalScope,
    CommandScope,
    StaleGate,
    FollowerRedirect,
    QuorumUnavailable,
    ApplyBarrier,
    Storage,
    Encode,
    WrongReducer,
    RecoveryNotObserved,
    ScopeBinding,
    ScopeCloseRecovery,
    BridgeDatabase,
    BridgeInvalidInput,
    BridgeAuthority,
    BackendOther,
    Unclassified,
}

impl Class {
    fn code(self) -> &'static str {
        match self {
            Self::AssertionPanic => "assertion_panic",
            Self::ProposalScope => "proposal_scope",
            Self::CommandScope => "command_scope",
            Self::StaleGate => "stale_gate",
            Self::FollowerRedirect => "follower_redirect",
            Self::QuorumUnavailable => "quorum_unavailable",
            Self::ApplyBarrier => "apply_barrier",
            Self::Storage => "storage",
            Self::Encode => "encode",
            Self::WrongReducer => "wrong_reducer",
            Self::RecoveryNotObserved => "recovery_not_observed",
            Self::ScopeBinding => "scope_binding",
            Self::ScopeCloseRecovery => "scope_close_recovery",
            Self::BridgeDatabase => "bridge_database",
            Self::BridgeInvalidInput => "bridge_invalid_input",
            Self::BridgeAuthority => "bridge_authority",
            Self::BackendOther => "backend_other",
            Self::Unclassified => "unclassified",
        }
    }

    pub(crate) fn from_error(error: &anyhow::Error) -> Self {
        if let Some(error) = error.downcast_ref::<RaftBackendError>() {
            return match error {
                RaftBackendError::ProposalScopeMismatch(_) => Self::ProposalScope,
                RaftBackendError::ScopeMismatch(_) => Self::CommandScope,
                RaftBackendError::StaleGate(_) => Self::StaleGate,
                RaftBackendError::FollowerRedirect(_) => Self::FollowerRedirect,
                RaftBackendError::QuorumUnavailable(_) => Self::QuorumUnavailable,
                RaftBackendError::ApplyBarrierTimeout { .. } => Self::ApplyBarrier,
                RaftBackendError::Storage(_) => Self::Storage,
                RaftBackendError::Encode(_) => Self::Encode,
                RaftBackendError::WrongReducer => Self::WrongReducer,
                RaftBackendError::RecoveryNotObserved(_) => Self::RecoveryNotObserved,
                RaftBackendError::ScopeDrainBindingMismatch(_) => Self::ScopeBinding,
                RaftBackendError::ScopeCloseNotRecoverable(_) => Self::ScopeCloseRecovery,
                _ => Self::BackendOther,
            };
        }
        if let Some(error) = error.downcast_ref::<RemoteAuthzBridgeError>() {
            return match error {
                RemoteAuthzBridgeError::PgDatabase(_) => Self::BridgeDatabase,
                RemoteAuthzBridgeError::InvalidInput(_) => Self::BridgeInvalidInput,
                RemoteAuthzBridgeError::AuthorityViolation(_) => Self::BridgeAuthority,
            };
        }
        Self::Unclassified
    }
}

pub(crate) struct PhaseGuard<P: PhaseLabel> {
    case: &'static str,
    phase: P,
    armed: bool,
}

impl<P: PhaseLabel> PhaseGuard<P> {
    pub(crate) fn new(case: &'static str, phase: P) -> Self {
        Self { case, phase, armed: true }
    }

    pub(crate) fn set(&mut self, phase: P) {
        if self.armed {
            self.phase = phase;
        }
    }

    pub(crate) fn current(&self) -> P {
        self.phase
    }

    pub(crate) fn case(&self) -> &'static str {
        self.case
    }

    pub(crate) fn fail(mut self, class: Class) {
        self.emit(class);
        self.armed = false;
    }

    pub(crate) fn complete(mut self) {
        self.armed = false;
    }

    fn emit(&self, class: Class) {
        {
            let mut stderr = std::io::stderr().lock();
            let _ = write!(
                stderr,
                "\nROOTYARD_FAILURE_FRAME v1 case={} phase={} class={}\n",
                self.case,
                self.phase.code(),
                class.code()
            );
        }
        if self.case == CASE_REAL {
            emit_append_witness(self.case);
        }
    }
}

impl<P: PhaseLabel> Drop for PhaseGuard<P> {
    fn drop(&mut self) {
        if self.armed {
            self.emit(Class::AssertionPanic);
        }
    }
}
