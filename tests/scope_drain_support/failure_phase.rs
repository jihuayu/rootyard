//! Fixed failure-phase frames for the first real Root Raft case.
//!
//! Frames contain only the fixed case name, a closed phase code and a closed class code. They never
//! include panic payloads, error text, identities, paths, metrics or other runtime data.

use std::io::Write;

use rootyard::ref_store::raft_backend::RaftBackendError;

pub(crate) const CASE_ID: &str = "real_root_refcas_commands_through_quorum_mtls_sqlite_and_restart";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Phase {
    Bootstrap,
    Provision,
    Commit,
    Refusal,
    Concurrent,
    Transition,
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

impl Phase {
    fn code(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Provision => "provision",
            Self::Commit => "commit",
            Self::Refusal => "refusal",
            Self::Concurrent => "concurrent",
            Self::Transition => "transition",
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
            Self::BackendOther => "backend_other",
            Self::Unclassified => "unclassified",
        }
    }

    pub(crate) fn from_error(error: &anyhow::Error) -> Self {
        let Some(error) = error.downcast_ref::<RaftBackendError>() else {
            return Self::Unclassified;
        };
        match error {
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
            _ => Self::BackendOther,
        }
    }
}

pub(crate) struct PhaseGuard {
    phase: Phase,
    armed: bool,
}

impl PhaseGuard {
    pub(crate) fn new(phase: Phase) -> Self {
        Self { phase, armed: true }
    }

    pub(crate) fn set(&mut self, phase: Phase) {
        if self.armed {
            self.phase = phase;
        }
    }

    pub(crate) fn fail(mut self, class: Class) {
        self.emit(class);
        self.armed = false;
    }

    pub(crate) fn complete(mut self) {
        self.armed = false;
    }

    fn emit(&self, class: Class) {
        let mut stderr = std::io::stderr().lock();
        let _ = write!(
            stderr,
            "\nROOTYARD_FAILURE_FRAME v1 case={CASE_ID} phase={} class={}\n",
            self.phase.code(),
            class.code()
        );
    }
}

impl Drop for PhaseGuard {
    fn drop(&mut self) {
        if self.armed {
            self.emit(Class::AssertionPanic);
        }
    }
}
