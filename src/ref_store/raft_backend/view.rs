//! Owned committed Ref-CAS view capability minted only after an actual quorum ReadIndex
//! plus local application apply barrier.

use std::collections::BTreeMap;

use rootyard_refcas_log::state_machine::ApplicationLogId;
use uuid::Uuid;

use crate::ref_store::contract::OperationLookup;
use crate::ref_store::core::state_machine::ScopeLifecycle;
use crate::ref_store::raft_backend::error::RaftBackendError;
use crate::ref_store::raft_backend::outcome::{OutcomeQuery, StoredOutcome};
use crate::ref_store::raft_backend::realm::RealmBinding;
use crate::ref_store::raft_backend::reducer::RootRefCasStateMachine;
use crate::ref_store::{CoreGateVersion, VersionCheck};

/// Authoritative committed view of one repository at one exact `(term, index)` application
/// coordinate. The constructor is crate-private; there is no `Deserialize`, default, raw-bytes,
/// or caller-local-state constructor. A caller can only obtain this after the backend performs a
/// real openraft quorum ReadIndex and verifies the local application apply barrier.
#[derive(Clone)]
pub struct CommittedRefCasView {
    reducer: RootRefCasStateMachine,
    applied: Option<ApplicationLogId>,
    repository_id: Uuid,
    tenant_id: Uuid,
    realm: RealmBinding,
}

impl CommittedRefCasView {
    pub(crate) fn mint(
        reducer: RootRefCasStateMachine,
        applied: Option<ApplicationLogId>,
        repository_id: Uuid,
        tenant_id: Uuid,
        realm: RealmBinding,
    ) -> Self {
        Self { reducer, applied, repository_id, tenant_id, realm }
    }

    /// Exact applied consensus coordinate of this view.
    pub fn last_applied(&self) -> Option<ApplicationLogId> {
        self.applied
    }

    /// Deterministic logical clock floor at this view.
    pub fn logical_clock_floor(&self) -> u64 {
        self.reducer.logical_clock_floor()
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
        self.reducer.read_refs(self.repository_id)
    }

    /// One committed ref name for the configured repository only.
    pub fn read_ref(&self, ref_name: &str) -> Option<String> {
        let mut refs = self.reducer.read_refs(self.repository_id);
        refs.remove(ref_name)
    }

    pub fn read_head_ref(&self) -> Option<String> {
        self.reducer.read_head_ref(self.repository_id)
    }

    pub fn read_scope_lifecycle(&self) -> Option<(ScopeLifecycle, i64)> {
        self.reducer.machine().read_scope_lifecycle(self.repository_id)
    }

    pub fn read_gate_version(&self) -> Result<Option<CoreGateVersion>, RaftBackendError> {
        self.reducer
            .machine()
            .read_gate_version(self.repository_id)
            .map_err(|e| RaftBackendError::Command(format!("gate version query refused: {e}")))
    }

    /// Linearized gate-version check bound to the configured repository/tenant.
    pub fn check_version(&self, known: Option<&CoreGateVersion>) -> Result<VersionCheck, RaftBackendError> {
        self.reducer
            .machine()
            .check_version(self.repository_id, self.tenant_id, known)
            .map_err(|e| RaftBackendError::Command(format!("version check refused: {e}")))
    }

    /// Durable operation lookup bound to the configured repository.
    pub fn query_operation(&self, operation_id: Uuid) -> Result<OperationLookup, RaftBackendError> {
        self.reducer
            .machine()
            .query_operation(self.repository_id, operation_id)
            .map_err(|e| RaftBackendError::Command(format!("operation query refused: {e}")))
    }

    /// Deterministic state digest of the cloned view.
    /// Full adapter digest, covering Root state and the typed outcome ledger when present.
    pub fn state_digest_hex(&self) -> Result<String, RaftBackendError> {
        self.reducer
            .adapter_state_digest_hex()
            .map_err(|e| RaftBackendError::Command(format!("state digest refused: {e}")))
    }

    /// Idempotent lookup of the actual replicated typed outcome at this committed view.
    pub fn query_outcome(&self, query: &OutcomeQuery) -> Option<StoredOutcome> {
        self.reducer.query_outcome(query).cloned()
    }
}
