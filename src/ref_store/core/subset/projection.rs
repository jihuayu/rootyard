//! Private projection of the ORIGINAL whole-batch plan onto its accepted subset.
//!
//! A [`SelectedPackPlan`] is an opaque capability: the only constructor is the
//! crate-private [`SelectedPackPlan::seal`], and it requires
//! [`VerifiedPublicationFacts`] (native-only, unforgeable) bound to this exact
//! plan plus one policy verdict per plan ref in original order. There is no public
//! factory, no `Default` and no caller boolean.
//!
//! What it binds:
//!
//! * the ORIGINAL operation identity and the ORIGINAL whole-batch parent digest
//!   (the A3 parent operation is never replaced by a smaller fake plan);
//! * the exact per-ref selection digest (`core-subset-selection-v1`);
//! * the exact accepted update list in original order;
//! * the exact resulting ref-name/object map digest of the full resulting ref map
//!   after the selected updates (`core-subset-selected-plan-v1`).
//!
//! Rejected refs are never part of the projection or of the final closure proof,
//! and nothing is filtered after the proof.
use super::selection::{SubsetSelection, seal_selection};
use super::verdict::PolicyVerdict;
use crate::ref_store::contract::{OperationIdentity, RequestDigest};
use crate::ref_store::core::pack_commit::VerifiedPublicationFacts;
use crate::ref_store::core::pack_commit::artifact::RegisteredPack;
use crate::ref_store::core::pack_commit::closure::PackClosureContext;
use crate::ref_store::core::pack_commit::closure::result_head_with;
use crate::ref_store::core::pack_commit::context::PackCommitBaseline;
use crate::ref_store::core::pack_commit::context::{CapturedRef, refs_digest};
use crate::ref_store::core::pack_commit::error::PackCommitError;
use crate::ref_store::core::pack_commit::plan::PackCommitPlan;
use crate::ref_store::core::pack_commit::proof::PackClosureProof;
use crate::ref_store::core::pack_commit::proof::verifier::PackVerifier;
use crate::ref_store::core::types::{RefName, RefPrecondition, RefTarget, RefUpdate};
use std::collections::BTreeMap;
use std::time::Instant;

/// Opaque selected capability derived from the original plan plus native facts.
pub struct SelectedPackPlan {
    plan: PackCommitPlan,
    selection: SubsetSelection,
    accepted: Vec<RefUpdate>,
    selection_digest: RequestDigest,
    resulting_refs_digest: RequestDigest,
}

impl SelectedPackPlan {
    /// The only constructor. Crate-private by design: decisions/integration obtain
    /// the capability from their own persisted selection flow, and no public
    /// caller can build one from unchecked data.
    pub(crate) fn seal(
        plan: PackCommitPlan,
        facts: &VerifiedPublicationFacts,
        policy: &[PolicyVerdict],
    ) -> Result<Self, PackCommitError> {
        facts.ensure_binds(&plan)?;
        let (selection, accepted) = seal_selection(&plan, facts, policy)?;
        let resulting = resulting_refs(&plan, &accepted, facts.old_refs())?;
        if !accepted.is_empty() {
            // A retarget must land on a live resulting branch; anything else is a
            // safe whole-batch refusal instead of an accidental dangling HEAD.
            let _ = result_head_with(facts.head_ref(), plan.head(), facts.old_refs(), &accepted)?;
        }
        let resulting_refs_digest = refs_digest(&resulting);
        let selection_digest = projection_digest(&plan, selection.digest(), &accepted, &resulting_refs_digest);
        Ok(Self { plan, selection, accepted, selection_digest, resulting_refs_digest })
    }

    /// The ORIGINAL whole-batch plan: same operation identity and parent digest.
    pub fn original(&self) -> &PackCommitPlan {
        &self.plan
    }

    pub fn original_identity(&self) -> &OperationIdentity {
        self.plan.identity()
    }

    pub fn original_parent_digest(&self) -> &RequestDigest {
        self.plan.parent_digest()
    }

    pub fn selection(&self) -> &SubsetSelection {
        &self.selection
    }

    /// Private projection digest: original parent + selection digest + accepted
    /// updates + exact resulting ref-map digest.
    pub fn selection_digest(&self) -> &RequestDigest {
        &self.selection_digest
    }

    pub fn accepted(&self) -> &[RefUpdate] {
        &self.accepted
    }

    pub fn is_all_rejected(&self) -> bool {
        self.accepted.is_empty()
    }

    /// False for an all-rejected selection: no proof, no ref revision mutation and
    /// no extra root hold; integration persists the durable rejected terminal.
    pub fn requires_closure(&self) -> bool {
        !self.accepted.is_empty()
    }

    /// Full resulting ref map after the selected accepted updates.
    pub fn resulting_refs(&self, old: &[CapturedRef]) -> Result<Vec<CapturedRef>, PackCommitError> {
        resulting_refs(&self.plan, &self.accepted, old)
    }

    /// Resulting HEAD after the selected accepted updates.
    pub fn resulting_head(&self, old_head: &RefName, old: &[CapturedRef]) -> Result<RefName, PackCommitError> {
        result_head_with(old_head, self.plan.head(), old, &self.accepted)
    }

    pub fn resulting_refs_digest(&self) -> &RequestDigest {
        &self.resulting_refs_digest
    }
}

/// Selected closure capture, defined here so the pack-commit slice stays
/// independent of the subset module wiring.
impl PackClosureContext {
    /// Same as `PackClosureContext::capture`, but the resulting ref map applies
    /// ONLY the accepted updates and the digest also binds the selection digest and
    /// accepted set (`core-pack-closure-context-subset-v1`).
    pub fn capture_selected(
        selected: &SelectedPackPlan,
        baseline: &PackCommitBaseline,
        new_packs: Vec<RegisteredPack>,
    ) -> Result<Self, PackCommitError> {
        Self::capture_selected_parts(
            selected.original(),
            selected.selection_digest(),
            selected.accepted(),
            baseline,
            new_packs,
        )
    }
}

/// Selected closure verification, defined here for the same reason.
impl PackVerifier {
    /// Verify the FULL resulting ref map of this selection and mint a proof that
    /// also binds the private selection digest. Rejected refs are not in the proof.
    pub async fn verify_selected(
        &self,
        selected: &SelectedPackPlan,
        context: &PackClosureContext,
        deadline: Instant,
    ) -> Result<PackClosureProof, PackCommitError> {
        self.verify_selected_parts(
            selected.original(),
            context,
            selected.selection_digest(),
            selected.accepted(),
            selected.resulting_refs_digest(),
            deadline,
        )
        .await
    }
}

impl std::fmt::Debug for SelectedPackPlan {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SelectedPackPlan")
            .field("original_parent_digest", &self.plan.parent_digest())
            .field("selection_digest", &self.selection_digest)
            .field("accepted", &self.accepted.len())
            .finish_non_exhaustive()
    }
}

/// Apply one accepted subset to a captured old ref map and return the sorted,
/// canonical resulting refs. Every accepted precondition must hold.
fn resulting_refs(
    plan: &PackCommitPlan,
    accepted: &[RefUpdate],
    old: &[CapturedRef],
) -> Result<Vec<CapturedRef>, PackCommitError> {
    let format = plan.object_format();
    let mut map: BTreeMap<String, String> =
        old.iter().map(|reference| (reference.name().to_owned(), reference.oid_hex().to_owned())).collect();
    for update in accepted {
        let actual = map.get(update.name().as_str()).cloned();
        let satisfied = match update.precondition() {
            RefPrecondition::Absent => actual.is_none(),
            RefPrecondition::Present(oid) => actual.as_deref() == Some(oid.as_hex().as_str()),
        };
        if !satisfied {
            return Err(PackCommitError::Invalid("accepted update precondition does not hold for these old refs"));
        }
        match update.target() {
            RefTarget::Delete => {
                map.remove(update.name().as_str());
            }
            RefTarget::Oid(oid) => {
                map.insert(update.name().as_str().to_owned(), oid.as_hex());
            }
        }
    }
    let mut refs = Vec::with_capacity(map.len());
    for (name, oid) in map {
        refs.push(CapturedRef::from_stored(format, name, oid)?);
    }
    refs.sort();
    Ok(refs)
}

fn projection_digest(
    plan: &PackCommitPlan,
    selection_digest: &RequestDigest,
    accepted: &[RefUpdate],
    resulting_refs_digest: &RequestDigest,
) -> RequestDigest {
    let mut fields: Vec<Vec<u8>> = vec![
        plan.identity().repository_id().as_bytes().to_vec(),
        plan.identity().operation_id().as_bytes().to_vec(),
        plan.parent_digest().as_bytes().to_vec(),
        plan.commit_mode().as_str().as_bytes().to_vec(),
        selection_digest.as_bytes().to_vec(),
        (accepted.len() as u64).to_be_bytes().to_vec(),
    ];
    for update in accepted {
        fields.push(update.name().as_str().as_bytes().to_vec());
        fields.push(update.precondition().canonical_tag().as_bytes().to_vec());
        fields.push(update.precondition().oid().map(|oid| oid.as_hex()).unwrap_or_default().into_bytes());
        fields.push(update.target().canonical_tag().as_bytes().to_vec());
        fields.push(update.target().oid().map(|oid| oid.as_hex()).unwrap_or_default().into_bytes());
    }
    fields.push(resulting_refs_digest.as_bytes().to_vec());
    let parts = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
    RequestDigest::of("core-subset-selected-plan-v1", &parts)
}
