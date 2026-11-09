//! The unforgeable decision capability.
//!
//! `DecisionCapability` has private fields, is not `Clone`, not `Serialize`/`Deserialize` and has no
//! public constructor. Its only minting site is [`super::install::select_and_install`], reached from
//! the same module tree that owns the fields, so no request body, receipt, SQL row or caller structure
//! can be turned into a capability.
//!
//! It deliberately does **not** hold the token secret or its digest: the PG-only credential identity
//! lives in the protected decision row, and the final check re-verifies `tokens.digest` against that
//! row instead of trusting an in-memory copy.
use super::contract::{DecisionKind, DenialCode, PublicationAction};
use super::digest::DecisionDigests;
use crate::ref_store::core::pack_commit::plan::PackCommitPlan;
use crate::ref_store::core::types::GitObjectFormat;
use std::fmt;
use uuid::Uuid;

pub(crate) struct DecisionCapability {
    decision_id: Uuid,
    repository_id: Uuid,
    tenant_id: Uuid,
    owner_id: Uuid,
    actor_id: Uuid,
    token_id: Uuid,
    operation_id: Uuid,
    kind: DecisionKind,
    action: PublicationAction,
    object_format: GitObjectFormat,
    base_revision: i64,
    not_after_millis: i64,
    created_db_millis: i64,
    digests: DecisionDigests,
}

impl DecisionCapability {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn mint(
        decision_id: Uuid,
        repository_id: Uuid,
        tenant_id: Uuid,
        owner_id: Uuid,
        actor_id: Uuid,
        token_id: Uuid,
        operation_id: Uuid,
        kind: DecisionKind,
        action: PublicationAction,
        object_format: GitObjectFormat,
        base_revision: i64,
        not_after_millis: i64,
        created_db_millis: i64,
        digests: DecisionDigests,
    ) -> Self {
        Self {
            decision_id,
            repository_id,
            tenant_id,
            owner_id,
            actor_id,
            token_id,
            operation_id,
            kind,
            action,
            object_format,
            base_revision,
            not_after_millis,
            created_db_millis,
            digests,
        }
    }

    pub(crate) fn decision_id(&self) -> Uuid {
        self.decision_id
    }
    pub(crate) fn operation_id(&self) -> Uuid {
        self.operation_id
    }
    pub(crate) fn kind(&self) -> DecisionKind {
        self.kind
    }
    pub(crate) fn action(&self) -> &PublicationAction {
        &self.action
    }
    pub(super) fn ensure_actor(&self, actor: &crate::db::Identity) -> Result<(), DenialCode> {
        if self.actor_id != actor.id || self.token_id != actor.token_id {
            return Err(DenialCode::TokenInvalid);
        }
        Ok(())
    }

    /// The capability only ever authorizes the exact original plan it was minted for.
    pub(crate) fn matches_plan(&self, plan: &PackCommitPlan) -> Result<(), DenialCode> {
        if plan.repository_id() != self.repository_id
            || plan.tenant_id() != self.tenant_id
            || plan.owner_id() != self.owner_id
            || plan.identity().operation_id() != self.operation_id
            || plan.object_format() != self.object_format
        {
            return Err(DenialCode::TenantMismatch);
        }
        if *plan.parent_digest() != self.digests.command_digest {
            return Err(DenialCode::ProofMismatch);
        }
        if *plan.expected().gate_digest() != self.digests.base_gate_digest {
            return Err(DenialCode::GateDigestMismatch);
        }
        if plan.expected().revision() != self.base_revision {
            return Err(DenialCode::RevisionMismatch);
        }
        Ok(())
    }
}

impl fmt::Debug for DecisionCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DecisionCapability")
            .field("decision_id", &self.decision_id)
            .field("operation_id", &self.operation_id)
            .field("repository_id", &self.repository_id)
            .field("kind", &self.kind)
            .field("not_after_millis", &self.not_after_millis)
            .field("created_db_millis", &self.created_db_millis)
            .finish()
    }
}

/// A capability can never be re-derived from serialized data.
impl Drop for DecisionCapability {
    fn drop(&mut self) {
        // Nothing secret is held, so dropping is intentionally a no-op; the explicit `Drop` keeps the
        // type from being `Copy`-like in future refactors and documents that this value is not
        // reconstructible from persisted bytes.
    }
}
