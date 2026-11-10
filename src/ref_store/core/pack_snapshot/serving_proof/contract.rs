//! Crate-private accessors for the native contract suite only (`cfg(test)`).
//!
//! The integration test drives the *production* builder
//! (`materialize_serving_read_sealed`) and then checks the sealed proof against
//! its own capture; it lives outside the crate, so it needs these very small
//! typed accessors instead of reaching into private fields. Nothing here
//! constructs a proof, seals one, or is compiled outside test builds.

use crate::ref_store::contract::RequestDigest;

impl super::ProvenScope {
    /// The captured tenant.
    pub(crate) fn contract_tenant_id(&self) -> uuid::Uuid {
        self.tenant_id
    }

    /// The captured repository.
    pub(crate) fn contract_repository_id(&self) -> uuid::Uuid {
        self.repository_id
    }

    /// The captured object format.
    pub(crate) fn contract_object_format(&self) -> crate::ref_store::GitObjectFormat {
        self.object_format
    }

    /// The captured history incarnation.
    pub(crate) fn contract_history_incarnation(&self) -> uuid::Uuid {
        self.history_incarnation
    }

    /// The captured authority epoch.
    pub(crate) fn contract_authority_epoch(&self) -> i64 {
        self.authority_epoch
    }

    /// The captured group epoch.
    pub(crate) fn contract_group_epoch(&self) -> i64 {
        self.group_epoch
    }
}

impl super::super::MaterializedServingRead {
    /// `(proof gate revision, proof scope, proof binding, view A5a probe)`.
    pub(crate) fn contract_parts(&self) -> (i64, super::ProvenScope, RequestDigest, RequestDigest) {
        (self.proof.gate_revision, self.proof.scope, self.proof.binding, self.proof.contract_a5a_probe())
    }
}
