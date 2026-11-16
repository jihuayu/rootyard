//! Privileged, quorum-backed current scope-drain observations.
//!
//! A [`CommittedScopeDrain`] is minted only from an actual openraft `ReadIndex` plus an atomic
//! application snapshot that has applied through both that read coordinate and the caller's
//! required close coordinate. It reports the **current** committed drain, not the historical
//! vectors captured by one close receipt. The result is an owned capability with private fields
//! and no public constructor or `Deserialize` implementation.

use uuid::Uuid;

use crate::ref_store::core::state_machine::ScopeDrainSnapshot;
use crate::ref_store::projector::remote_authz_bridge::LinearizableScopeProbe;
use crate::ref_store::projector::session_fence::AuthoritySourceKind;
use crate::ref_store::raft_backend::realm::NodeTrust;

/// One quorum-confirmed current scope-drain observation from an owned node.
///
/// The complete [`ScopeDrainSnapshot`] is deliberately group-level: the core scope index is keyed
/// by `(scope_kind, scope_id)` and may contain decisions from more than one repository. Callers
/// must not present this as a repository-scoped view or silently filter entries needed by a
/// revocation drain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedScopeDrain {
    drain: ScopeDrainSnapshot,
    read_log_index: Option<u64>,
    applied_log_index: u64,
    trust: NodeTrust,
}

impl CommittedScopeDrain {
    pub(crate) fn new(
        drain: ScopeDrainSnapshot,
        read_log_index: Option<u64>,
        applied_log_index: u64,
        trust: NodeTrust,
    ) -> Self {
        Self { drain, read_log_index, applied_log_index, trust }
    }

    /// Complete current committed drain, including the settled terminal-operation map.
    pub fn drain(&self) -> &ScopeDrainSnapshot {
        &self.drain
    }

    /// Actual openraft linearizable ReadIndex log index, preserved separately from the later
    /// applied coordinate. `None` only when Raft returned no read log id.
    pub fn read_log_index(&self) -> Option<u64> {
        self.read_log_index
    }

    /// Applied index of the exact application snapshot used for this observation.
    pub fn applied_log_index(&self) -> u64 {
        self.applied_log_index
    }

    /// Trusted group/authority/storage binding of the owned node that produced this observation.
    pub fn trust(&self) -> &NodeTrust {
        &self.trust
    }

    pub fn group_id(&self) -> &str {
        self.trust.group_id()
    }

    pub fn authority_id(&self) -> Uuid {
        self.trust.authority_id()
    }

    pub fn storage_generation(&self) -> u64 {
        self.trust.storage_generation()
    }

    /// Consumes the observation and returns the complete current drain.
    pub fn into_drain(self) -> ScopeDrainSnapshot {
        self.drain
    }

    /// Converts this genuinely quorum-bound observation into the existing bridge probe shape.
    /// The source is always `RaftReadIndexQuorum`; no local-replica or PG source can be minted here.
    pub fn into_linearizable_scope_probe(self) -> LinearizableScopeProbe {
        LinearizableScopeProbe {
            source: AuthoritySourceKind::RaftReadIndexQuorum,
            read_log_index: self.read_log_index,
            applied_log_index: self.applied_log_index,
            drain: self.drain,
        }
    }
}
