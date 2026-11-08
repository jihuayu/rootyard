//! The sealed `PackClosureProof`.
//!
//! This module owns the proof *type* and its read-only surface. It deliberately
//! exposes **no constructor**: the type has private fields, is neither `Clone`
//! nor `Serialize`/`Deserialize`, and its only minting site is the private
//! native-verifier submodule ([`verifier`], wired here as a child so it can reach
//! the private fields while sibling modules cannot). A verifier proof is
//! therefore the only thing that can authorise a verified commit, and no
//! request/receipt/metadata value can be turned into one.
use super::artifact::packs_digest;
use super::closure::PackClosureContext;
use super::context::{CapturedRef, MembershipDigest, refs_digest};
use super::error::PackCommitError;
use super::plan::PackCommitPlan;
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::types::RefName;

/// Native closure proof. Binds one closure context digest, the plan's canonical
/// parent digest, the expected gate revision/digest, the exact resulting
/// refs/HEAD, the old membership digest and the complete old+new registered pack
/// sets (each artifact set digest covers the full physical locator identity).
pub struct PackClosureProof {
    context_digest: RequestDigest,
    parent_digest: RequestDigest,
    expected_revision: i64,
    gate_digest: RequestDigest,
    resulting_head: RefName,
    resulting_refs: Vec<CapturedRef>,
    resulting_refs_digest: RequestDigest,
    old_membership_digest: MembershipDigest,
    old_packs_digest: RequestDigest,
    new_packs_digest: RequestDigest,
    verified_pairs: usize,
    verified_bytes: u64,
}

impl PackClosureProof {
    /// The exact context this proof was minted for.
    pub fn context_digest(&self) -> &RequestDigest {
        &self.context_digest
    }

    pub fn parent_digest(&self) -> &RequestDigest {
        &self.parent_digest
    }

    pub fn expected_revision(&self) -> i64 {
        self.expected_revision
    }

    pub fn gate_digest(&self) -> &RequestDigest {
        &self.gate_digest
    }

    pub fn resulting_head(&self) -> &RefName {
        &self.resulting_head
    }

    pub fn resulting_refs(&self) -> &[CapturedRef] {
        &self.resulting_refs
    }

    pub fn resulting_refs_digest(&self) -> &RequestDigest {
        &self.resulting_refs_digest
    }

    pub fn old_membership_digest(&self) -> MembershipDigest {
        self.old_membership_digest
    }

    /// Digest over the complete old active registered pack set the verifier
    /// validated.
    pub fn old_packs_digest(&self) -> &RequestDigest {
        &self.old_packs_digest
    }

    /// Digest over the complete newly registered pack set the verifier validated.
    pub fn new_packs_digest(&self) -> &RequestDigest {
        &self.new_packs_digest
    }

    pub fn verified_pairs(&self) -> usize {
        self.verified_pairs
    }

    pub fn verified_bytes(&self) -> u64 {
        self.verified_bytes
    }

    /// True only when every bound field equals this exact plan/context pair.
    /// The commit path uses this instead of trusting a caller-supplied digest.
    pub(crate) fn binds(&self, plan: &PackCommitPlan, context: &PackClosureContext) -> bool {
        self.context_digest == *context.digest()
            && self.parent_digest == *plan.parent_digest()
            && self.expected_revision == context.expected_revision()
            && self.gate_digest == *context.gate_digest()
            && self.resulting_head == *context.resulting_head()
            && self.resulting_refs_digest == refs_digest(context.resulting_refs())
            && self.resulting_refs == context.resulting_refs()
            && self.old_membership_digest == context.old_membership_digest()
            && self.old_packs_digest == packs_digest(context.old_packs())
            && self.new_packs_digest == packs_digest(context.new_packs())
    }

    /// Internal consistency check used by the verifier after minting.
    pub(crate) fn is_coherent(&self, context: &PackClosureContext, plan: &PackCommitPlan) -> bool {
        self.binds(plan, context)
    }
}

impl std::fmt::Debug for PackClosureProof {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PackClosureProof")
            .field("context_digest", &self.context_digest)
            .field("expected_revision", &self.expected_revision)
            .field("verified_pairs", &self.verified_pairs)
            .field("verified_bytes", &self.verified_bytes)
            .finish_non_exhaustive()
    }
}

/// Native verifier subtree, owned by the verifier worker after contract freeze.
/// It is a *child* of this module so it alone can construct a proof; the file
/// lives at `pack_commit/verifier/mod.rs`.
#[path = "verifier/mod.rs"]
pub(crate) mod verifier;

/// Closed, internal refusal for a proof that cannot be used here.
pub(crate) fn refuse_unusable<'a>(
    proof: Option<&'a PackClosureProof>,
    plan: &PackCommitPlan,
    context: &PackClosureContext,
) -> Result<&'a PackClosureProof, PackCommitError> {
    let proof = proof.ok_or(PackCommitError::ProofUnavailable("no verified closure proof"))?;
    if proof.binds(plan, context) {
        Ok(proof)
    } else {
        Err(PackCommitError::ProofUnavailable("proof binds another plan/context"))
    }
}
