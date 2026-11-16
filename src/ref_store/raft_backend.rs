//! Real openraft Ref-CAS backend adapter for Issue #175.
//!
//! This module is deliberately **not** a production HTTP/PG projection consumer. It owns:
//!
//! - a Root Ref-CAS reducer that actually applies committed `RefCasCommand` values inside the
//!   persistent state-machine callback (`RootRefCasStateMachine`);
//! - a real openraft quorum `ReadIndex` + local apply barrier that mints an owned
//!   `CommittedRefCasView` capability (no public/deserialize/raw-bytes constructor);
//! - trusted repository/tenant/realm/group/authority/storage-generation scope checks.
//!
//! Follower, no-quorum, stale-realm, wrong-reducer, and KV-mode paths fail closed. There is no
//! Redis/PG/local-unverified fallback. Full authenticated network proof, production HTTP auth,
//! and the PostgreSQL projection consumer remain later qualification tasks.

mod adapter_state;
mod backend;
mod error;
mod node;
mod outcome;
mod proposal;
mod realm;
mod reducer;
mod scope;
mod scope_close;
mod scope_close_requirement;
mod scope_drain;
mod view;

pub use backend::{BackendOptions, RootRaftRefCasBackend};
pub use error::RaftBackendError;
pub use node::{RootRaftNode, RootRaftNodeConfig};
pub use outcome::{
    GateVersionSnapshot, OperationStateSnapshot, ProposeOutcome, RootRefCasApplied, RootRefCasOutcome,
    RootRefCasRefusal, RootRefCasRefusalKind,
};
pub use proposal::{
    MAX_ADAPTER_STATE_BYTES, MAX_PROPOSAL_RECEIPT_BYTES, MAX_ROOT_STATE_BYTES, PROPOSAL_FORMAT, PROPOSAL_WINDOW,
    ProposalAttempt, ProposalAttemptKind, ProposalEnvelope, ProposalId, ProposalLookup, ProposalOutcome,
    command_digest_hex,
};
pub use realm::{NodeTrust, RealmBinding};
pub use reducer::{ROOT_REF_CAS_DOMAIN, ROOT_REF_CAS_VERSION, RootRefCasStateMachine, validate_ref_cas_command};
pub use scope_close::{MAX_SCOPE_CLOSE_ACK_BYTES, SCOPE_CLOSE_DRAIN_FORMAT, ScopeCloseDrainSummary};
pub use scope_close_requirement::ScopeCloseRequirement;
pub use scope_drain::CommittedScopeDrain;
pub use view::CommittedRefCasView;
