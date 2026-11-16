//! Privileged, quorum-backed current scope-drain observations.
//!
//! A [`CommittedScopeDrain`] is minted only from an actual openraft `ReadIndex` plus an atomic
//! application snapshot that has applied through both that read coordinate and the bound
//! [`ScopeCloseRequirement`]'s original close coordinate. It reports the **current** committed
//! drain, not the historical vectors captured by one close receipt. The result is an owned
//! capability with private fields and no public constructor or `Deserialize` implementation.

use uuid::Uuid;

use crate::ref_store::core::state_machine::ScopeDrainSnapshot;
use crate::ref_store::projector::remote_authz_bridge::LinearizableScopeProbe;
use crate::ref_store::projector::session_fence::AuthoritySourceKind;
use crate::ref_store::raft_backend::error::RaftBackendError;
use crate::ref_store::raft_backend::realm::NodeTrust;
use crate::ref_store::raft_backend::reducer::{ROOT_REF_CAS_DOMAIN, ROOT_REF_CAS_VERSION};
use crate::ref_store::raft_backend::scope_close_requirement::ScopeCloseRequirement;

/// One quorum-confirmed current scope-drain observation for one bound close requirement.
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
    required: ScopeCloseRequirement,
}

impl CommittedScopeDrain {
    pub(crate) fn new(
        drain: ScopeDrainSnapshot,
        read_log_index: Option<u64>,
        applied_log_index: u64,
        required: ScopeCloseRequirement,
    ) -> Self {
        let trust = required.trust().clone();
        Self { drain, read_log_index, applied_log_index, trust, required }
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

    /// Exact close requirement this observation was minted for.
    pub fn requirement(&self) -> &ScopeCloseRequirement {
        &self.required
    }

    /// Consumes the observation and returns the complete current drain.
    pub fn into_drain(self) -> ScopeDrainSnapshot {
        self.drain
    }

    /// Converts this genuinely quorum-bound observation into the existing bridge probe shape.
    ///
    /// The caller must present the exact requirement used for the query. This prevents an
    /// observation for trust/scope/floor/coordinate A from being silently relabeled as B before
    /// the bridge erases the extra identity fields. It does not make the public projector probe
    /// type unforgeable by arbitrary trusted Rust.
    pub fn into_linearizable_scope_probe(
        self,
        required: &ScopeCloseRequirement,
    ) -> Result<LinearizableScopeProbe, RaftBackendError> {
        if &self.required != required {
            return Err(RaftBackendError::ScopeDrainBindingMismatch("close requirement"));
        }
        if self.trust != *required.trust() {
            return Err(RaftBackendError::ScopeDrainBindingMismatch("node trust"));
        }
        if self.required.application_domain() != ROOT_REF_CAS_DOMAIN
            || self.required.application_version() != ROOT_REF_CAS_VERSION
        {
            return Err(RaftBackendError::ScopeDrainBindingMismatch("application domain/version"));
        }
        if self.applied_log_index < required.close_log_id().index {
            return Err(RaftBackendError::ScopeDrainBindingMismatch("applied coordinate"));
        }
        Ok(LinearizableScopeProbe {
            source: AuthoritySourceKind::RaftReadIndexQuorum,
            read_log_index: self.read_log_index,
            applied_log_index: self.applied_log_index,
            drain: self.drain,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rootyard_refcas_log::state_machine::ApplicationLogId;

    use crate::ref_store::core::state_machine::ScopeLifecycle;

    fn trust(group: &str, authority: Uuid, storage_generation: u64) -> NodeTrust {
        NodeTrust::new(group, authority, storage_generation).expect("trust")
    }

    fn requirement(trust: NodeTrust, close_index: u64, scope_id: Uuid, floor: i64) -> ScopeCloseRequirement {
        ScopeCloseRequirement::from_verified_close(
            trust,
            ApplicationLogId::new(1, close_index),
            "token".into(),
            scope_id,
            ScopeLifecycle::Closing,
            floor,
        )
        .expect("requirement")
    }

    #[test]
    fn conversion_requires_exact_requirement_and_applied_coordinate() {
        let authority = Uuid::from_u128(10);
        let base_trust = trust("group-a", authority, 1);
        let required = requirement(base_trust.clone(), 7, Uuid::from_u128(20), 2);
        let drain = ScopeDrainSnapshot {
            scope: None,
            pending_operation_ids: vec![],
            open_decision_ids: vec![],
            settled_terminal_operations: Default::default(),
        };
        let matching = CommittedScopeDrain::new(drain.clone(), Some(8), 9, required.clone());
        assert!(matching.clone().into_linearizable_scope_probe(&required).is_ok());
        assert_eq!(matching.requirement(), &required);

        let same_group_wrong_scope = requirement(base_trust.clone(), 7, Uuid::from_u128(21), 2);
        assert!(matches!(
            matching.clone().into_linearizable_scope_probe(&same_group_wrong_scope),
            Err(RaftBackendError::ScopeDrainBindingMismatch("close requirement"))
        ));
        let same_group_wrong_floor = requirement(base_trust.clone(), 7, Uuid::from_u128(20), 3);
        assert!(matches!(
            matching.clone().into_linearizable_scope_probe(&same_group_wrong_floor),
            Err(RaftBackendError::ScopeDrainBindingMismatch("close requirement"))
        ));
        let same_group_wrong_coordinate = requirement(base_trust.clone(), 8, Uuid::from_u128(20), 2);
        assert!(matches!(
            matching.clone().into_linearizable_scope_probe(&same_group_wrong_coordinate),
            Err(RaftBackendError::ScopeDrainBindingMismatch("close requirement"))
        ));
        let other_trust = requirement(trust("group-b", authority, 1), 7, Uuid::from_u128(20), 2);
        assert!(matches!(
            matching.clone().into_linearizable_scope_probe(&other_trust),
            Err(RaftBackendError::ScopeDrainBindingMismatch("close requirement"))
        ));
        let early = CommittedScopeDrain::new(drain, Some(8), 6, required.clone());
        assert!(matches!(
            early.into_linearizable_scope_probe(&required),
            Err(RaftBackendError::ScopeDrainBindingMismatch("close requirement"))
        ));
    }
}
