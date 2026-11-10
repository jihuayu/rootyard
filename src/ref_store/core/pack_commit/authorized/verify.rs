//! Native closure after the durable selection, with no database connection.
use super::{AuthorizedCommitError, AuthorizedSelection, PgAuthorizedCommit, effective_deadline};
use crate::ref_store::core::pack_commit::{PackClosureContext, PackClosureProof, PackVerifier};
use tokio::time::Instant;

/// Owned final proof and its exact durable selection. No public constructor.
pub struct VerifiedAuthorizedPublication {
    selection: AuthorizedSelection,
    proof: Option<PackClosureProof>,
}

impl VerifiedAuthorizedPublication {
    pub(super) fn selection(&self) -> &AuthorizedSelection {
        &self.selection
    }
    pub(super) fn proof(&self) -> Option<&PackClosureProof> {
        self.proof.as_ref()
    }
    pub fn operation_id(&self) -> uuid::Uuid {
        self.selection.operation_id()
    }
    pub fn selection_digest(&self) -> &crate::ref_store::RequestDigest {
        self.selection.selection_digest()
    }
    pub fn is_all_rejected(&self) -> bool {
        self.selection.is_all_rejected()
    }
}

impl PgAuthorizedCommit {
    pub async fn verify(
        &self,
        selection: AuthorizedSelection,
        deadline: Instant,
    ) -> Result<VerifiedAuthorizedPublication, AuthorizedCommitError> {
        let deadline = effective_deadline(deadline)?;
        if selection.is_all_rejected() {
            return Ok(VerifiedAuthorizedPublication { selection, proof: None });
        }
        let prepared = selection.prepared();
        let context = PackClosureContext::capture_selected(
            selection.selected().selected_plan(),
            prepared.baseline(),
            prepared.new_packs().to_vec(),
        )?;
        let proof = PackVerifier::new(self.store.clone(), self.git_binary.clone())?
            .verify_selected(selection.selected().selected_plan(), &context, deadline.into_std())
            .await?;
        Ok(VerifiedAuthorizedPublication { selection, proof: Some(proof) })
    }
}
