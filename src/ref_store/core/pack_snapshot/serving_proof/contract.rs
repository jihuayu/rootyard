//! Crate-private read-only accessors for the sealed proof (`cfg(test)` only).
//!
//! The real-PostgreSQL contract case lives inside this crate subtree
//! (`materialize::serving_tests`) because the production builder is
//! crate-private by design. These accessors let it inspect the sealed proof and
//! the materialized view without widening any production visibility: nothing
//! here constructs a proof, seals one, mints a view, or is compiled outside test
//! builds. Integration-test binaries are separate crates, so no `pub(crate)`
//! type can ever reach them.

use super::super::materialize::MaterializedServingRead;
use crate::ref_store::contract::{RefStoreError, RequestDigest};

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

impl super::VerifiedReadViewProof {
    /// The A5b binding the proof states.
    pub(crate) fn contract_binding(&self) -> RequestDigest {
        self.binding
    }

    /// The realm the proof states.
    pub(crate) fn contract_scope(&self) -> super::ProvenScope {
        self.scope
    }
}

impl MaterializedServingRead {
    /// `(proof gate revision, proof realm, proof A5b binding)`.
    pub(crate) fn contract_parts(&self) -> (i64, super::ProvenScope, RequestDigest) {
        (self.proof.gate_revision(), self.proof.contract_scope(), self.proof.contract_binding())
    }

    /// The same factory the materializer's seal site uses, re-run over the
    /// sealed view: a contract case can therefore prove that the view and its
    /// proof bind the identical A5b materialization digest, and that the
    /// factory refuses again if the two could ever disagree.
    pub(crate) fn contract_refactory(&self) -> Result<super::VerifiedReadView, RefStoreError> {
        super::VerifiedReadView::of_materialized(self.view())
    }
}
