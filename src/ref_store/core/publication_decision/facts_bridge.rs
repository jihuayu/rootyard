//! Concrete bridge from the native [`VerifiedPublicationFacts`] value to the decision checks.
//!
//! There is deliberately **one** native facts type and **one** getter surface. This module does not
//! define a second selection framework: it reads the real native facts (`RefFacts.target_present`,
//! `old_refs`, `facts_digest`, `old_membership_digest`, verified pack counters) and the sealed
//! [`SelectedPackPlan`] derived from those same facts. A caller cannot pass booleans, a fake pack plan
//! or another plan's facts: [`ensure_binds`] refuses facts bound to a different original plan/realm,
//! and every final proof is compared against the exact full resulting ref map of the sealed plan.
use super::contract::{DecisionError, DenialCode, SelectedDecision};
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::pack_commit::error::PackCommitError;
use crate::ref_store::core::pack_commit::plan::PackCommitPlan;
use crate::ref_store::core::pack_commit::proof::PackClosureProof;
use crate::ref_store::core::pack_commit::{RefFacts, VerifiedPublicationFacts};
use crate::ref_store::core::types::GitOid;
use std::collections::BTreeMap;

/// Refuse facts that were not computed for exactly this original plan and realm.
pub(super) fn ensure_binds(plan: &PackCommitPlan, facts: &VerifiedPublicationFacts) -> Result<(), DecisionError> {
    facts
        .ensure_binds(plan)
        .map_err(|_| DecisionError::Unverifiable("native facts bind another original plan/realm"))?;
    if !facts.complete() {
        return Err(DecisionError::Unverifiable("native facts are incomplete"));
    }
    if facts.repository_id() != plan.repository_id()
        || facts.tenant_id() != plan.tenant_id()
        || facts.owner_id() != plan.owner_id()
        || facts.object_format() != plan.object_format()
        || facts.history_incarnation() != plan.history_incarnation()
        || facts.authority_epoch() != plan.authority_epoch()
        || facts.group_epoch() != plan.group_epoch()
    {
        return Err(DecisionError::Unverifiable("native facts bind another realm"));
    }
    Ok(())
}

/// The exact captured old ref map the native facts were computed against.
pub(super) fn old_ref_map(facts: &VerifiedPublicationFacts) -> Result<BTreeMap<String, Option<GitOid>>, DecisionError> {
    let format = facts.object_format();
    let mut map = BTreeMap::new();
    for reference in facts.old_refs() {
        let oid = GitOid::parse(format, reference.oid_hex())
            .map_err(|_| DecisionError::Ledger("captured native ref object id is not canonical"))?;
        map.insert(reference.name().to_owned(), Some(oid));
    }
    Ok(map)
}

pub(super) fn old_oid(facts: &VerifiedPublicationFacts, name: &str) -> Result<Option<GitOid>, DecisionError> {
    let map = old_ref_map(facts)?;
    Ok(map.get(name).copied().flatten())
}

/// Per-ref native facts for a plan ref. Missing entry is unverifiable, never "absent".
pub(super) fn ref_facts<'a>(facts: &'a VerifiedPublicationFacts, name: &str) -> Result<&'a RefFacts, DecisionError> {
    facts.ref_facts(name).ok_or(DecisionError::Unverifiable("native facts are missing a plan ref"))
}

/// Native whole-fact digest. It is persisted verbatim and recomputed from the same concrete value.
pub(super) fn facts_digest(facts: &VerifiedPublicationFacts) -> RequestDigest {
    *facts.facts_digest()
}

/// Canonical digest of the captured old ref map (name + exact OID / absence).
pub(super) fn captured_oid_digest(facts: &VerifiedPublicationFacts) -> Result<RequestDigest, DecisionError> {
    let map = old_ref_map(facts)?;
    let mut fields: Vec<Vec<u8>> = vec![(map.len() as u64).to_be_bytes().to_vec()];
    for (name, oid) in map {
        fields.push(name.into_bytes());
        fields.push(oid.map(|oid| oid.as_hex()).unwrap_or_default().into_bytes());
    }
    let parts = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
    Ok(RequestDigest::of("publication-decision-captured-v1", &parts))
}

/// The optional final closure proof.
///
/// `None` is legal **only** when the sealed projection rejected every original ref (no closure, no
/// ref revision, no root/hold change). Otherwise a proof is mandatory and must bind the exact same
/// original parent, gate revision/digest, old membership, verified pack counters, full resulting ref
/// map/head and sealed selection digest.
pub(super) fn verify_final_proof(
    selected: &SelectedDecision,
    plan: &PackCommitPlan,
    facts: &VerifiedPublicationFacts,
    proof: Option<&PackClosureProof>,
) -> Result<(), DecisionError> {
    let projection = selected.selected_plan();
    if projection.is_all_rejected() {
        if proof.is_some() {
            return Err(DecisionError::Denied(DenialCode::ProofMismatch));
        }
        return Ok(());
    }
    let proof = proof.ok_or(DecisionError::Denied(DenialCode::ProofMismatch))?;
    if proof.selection_digest() != Some(projection.selection_digest()) {
        return Err(DecisionError::Denied(DenialCode::ProofMismatch));
    }
    if proof.parent_digest() != plan.parent_digest()
        || proof.expected_revision() != plan.expected().revision()
        || proof.gate_digest() != plan.expected().gate_digest()
    {
        return Err(DecisionError::Denied(DenialCode::ProofMismatch));
    }
    if proof.old_membership_digest() != facts.old_membership_digest()
        || proof.old_packs_digest() != facts.old_packs_digest()
        || proof.new_packs_digest() != facts.new_packs_digest()
        || proof.verified_pairs() != facts.verified_pairs()
        || proof.verified_bytes() != facts.verified_bytes()
    {
        return Err(DecisionError::Denied(DenialCode::ProofMismatch));
    }
    let expected_refs = projection
        .resulting_refs(facts.old_refs())
        .map_err(|_| DecisionError::Unverifiable("sealed projection cannot reproduce the full ref map"))?;
    if proof.resulting_refs() != expected_refs.as_slice() {
        return Err(DecisionError::Denied(DenialCode::ProofMismatch));
    }
    let expected_head = projection
        .resulting_head(facts.head_ref(), facts.old_refs())
        .map_err(|_| DecisionError::Unverifiable("sealed projection cannot reproduce HEAD"))?;
    if proof.resulting_head() != &expected_head {
        return Err(DecisionError::Denied(DenialCode::ProofMismatch));
    }
    if proof.resulting_refs_digest() != projection.resulting_refs_digest() {
        return Err(DecisionError::Denied(DenialCode::ProofMismatch));
    }
    Ok(())
}

/// Map a native/verifier refusal without echoing Git paths, pack locators or SQL text.
pub(super) fn native_error(error: PackCommitError) -> DecisionError {
    match error {
        PackCommitError::Capacity { .. } => {
            DecisionError::Unverifiable("native publication facts exceed a fixed bound")
        }
        PackCommitError::Invalid("selected projection requires the accepted_subset plan mode") => {
            // The subset owner is extending `seal` to the Atomic original; until that lands the
            // authorized atomic decision path is explicitly unsupported, never silently allowed.
            DecisionError::Denied(DenialCode::UnsupportedAction)
        }
        PackCommitError::Invalid(_) => {
            DecisionError::Unverifiable("native publication facts or sealed projection are invalid")
        }
        PackCommitError::Rejected(_) => DecisionError::Unverifiable("native publication facts were rejected"),
        PackCommitError::ProofUnavailable(_) => DecisionError::Denied(DenialCode::ProofMismatch),
        other => {
            let _ = other;
            DecisionError::Unverifiable("native publication facts could not be verified")
        }
    }
}
