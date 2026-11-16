//! Owned committed Ref-CAS view capability minted only after an actual quorum ReadIndex
//! plus local application apply barrier.

use std::collections::BTreeMap;

use rootyard_refcas_log::state_machine::ApplicationLogId;
use uuid::Uuid;

use crate::ref_store::contract::OperationLookup;
use crate::ref_store::core::state_machine::{RefCasStateMachine, ScopeLifecycle};
use crate::ref_store::raft_backend::error::RaftBackendError;
use crate::ref_store::raft_backend::realm::RealmBinding;
use crate::ref_store::{CoreGateVersion, VersionCheck};

/// Authoritative committed view of one repository at one exact `(term, index)` application
/// coordinate. The constructor is crate-private; there is no `Deserialize`, default, raw-bytes,
/// or caller-local-state constructor. A caller can only obtain this after the backend performs a
/// real openraft quorum ReadIndex and verifies the local application apply barrier.
#[derive(Clone)]
pub struct CommittedRefCasView {
    machine: RefCasStateMachine,
    applied: Option<ApplicationLogId>,
    repository_id: Uuid,
    tenant_id: Uuid,
    realm: RealmBinding,
}

impl CommittedRefCasView {
    pub(crate) fn mint(
        machine: RefCasStateMachine,
        applied: Option<ApplicationLogId>,
        repository_id: Uuid,
        tenant_id: Uuid,
        realm: RealmBinding,
    ) -> Self {
        Self { machine, applied, repository_id, tenant_id, realm }
    }

    /// Exact applied consensus coordinate of this view.
    pub fn last_applied(&self) -> Option<ApplicationLogId> {
        self.applied
    }

    pub fn repository_id(&self) -> Uuid {
        self.repository_id
    }

    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    pub fn realm(&self) -> &RealmBinding {
        &self.realm
    }

    /// Committed refs for the configured repository only.
    pub fn read_refs(&self) -> BTreeMap<String, String> {
        self.machine.read_refs(self.repository_id)
    }

    /// One committed ref name for the configured repository only.
    pub fn read_ref(&self, ref_name: &str) -> Option<String> {
        let mut refs = self.machine.read_refs(self.repository_id);
        refs.remove(ref_name)
    }

    pub fn read_head_ref(&self) -> Option<String> {
        self.machine.read_head_ref(self.repository_id)
    }

    pub fn read_scope_lifecycle(&self) -> Option<(ScopeLifecycle, i64)> {
        self.machine.read_scope_lifecycle(self.repository_id)
    }

    pub fn read_gate_version(&self) -> Result<Option<CoreGateVersion>, RaftBackendError> {
        self.machine
            .read_gate_version(self.repository_id)
            .map_err(|e| RaftBackendError::Command(format!("gate version query refused: {e}")))
    }

    /// Linearized gate-version check bound to the configured repository/tenant.
    pub fn check_version(&self, known: Option<&CoreGateVersion>) -> Result<VersionCheck, RaftBackendError> {
        self.machine
            .check_version(self.repository_id, self.tenant_id, known)
            .map_err(|e| RaftBackendError::Command(format!("version check refused: {e}")))
    }

    /// Durable operation lookup bound to the configured repository.
    pub fn query_operation(&self, operation_id: Uuid) -> Result<OperationLookup, RaftBackendError> {
        self.machine
            .query_operation(self.repository_id, operation_id)
            .map_err(|e| RaftBackendError::Command(format!("operation query refused: {e}")))
    }

    /// Deterministic state digest of the cloned view.
    pub fn state_digest_hex(&self) -> Result<String, RaftBackendError> {
        self.machine.state_digest().map_err(|e| RaftBackendError::Command(format!("state digest refused: {e}")))
    }
}
