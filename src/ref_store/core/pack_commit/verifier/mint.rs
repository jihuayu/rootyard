//! Mint the sealed proof — and only after the native closure passed.
//!
//! This is the single construction site of [`PackClosureProof`]. It lives inside
//! the `verifier` subtree that `proof.rs` declares as a child module, so the
//! private proof fields are reachable here and nowhere else in the crate. There is
//! no public or `pub(crate)` factory: a sibling module can read a proof but cannot
//! build one, and no request, receipt or metadata value can be converted into one.
//!
//! The bound values are recomputed from the plan and the context at mint time and
//! the result is checked with `PackClosureProof::is_coherent`, so a proof can never
//! describe a different plan, context or resulting ref/HEAD/pack set than the one
//! native Git just validated.
use super::refuse;
use crate::ref_store::core::pack_commit::artifact::packs_digest;
use crate::ref_store::core::pack_commit::closure::PackClosureContext;
use crate::ref_store::core::pack_commit::context::refs_digest;
use crate::ref_store::core::pack_commit::error::PackCommitError;
use crate::ref_store::core::pack_commit::plan::PackCommitPlan;
use crate::ref_store::core::pack_commit::proof::PackClosureProof;

/// Bind one fully verified closure.
pub(super) fn mint(
    plan: &PackCommitPlan,
    context: &PackClosureContext,
    verified_pairs: usize,
    verified_bytes: u64,
) -> Result<PackClosureProof, PackCommitError> {
    let proof = PackClosureProof {
        context_digest: *context.digest(),
        parent_digest: *plan.parent_digest(),
        expected_revision: context.expected_revision(),
        gate_digest: *context.gate_digest(),
        resulting_head: context.resulting_head().clone(),
        resulting_refs: context.resulting_refs().to_vec(),
        resulting_refs_digest: refs_digest(context.resulting_refs()),
        old_membership_digest: context.old_membership_digest(),
        old_packs_digest: packs_digest(context.old_packs()),
        new_packs_digest: packs_digest(context.new_packs()),
        selection_digest: context.selection_digest().copied(),
        verified_pairs,
        verified_bytes,
    };
    if !proof.is_coherent(context, plan) {
        return Err(refuse("minted proof does not bind this plan and context"));
    }
    Ok(proof)
}
