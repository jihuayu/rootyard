//! Deterministic selection sealing and canonical selection hashing.
//!
//! The decisions owner evaluates PG auth/policy/RBAC/branch-rule/review/check/LFS
//! lock facts and supplies one [`PolicyVerdict`] per original plan ref, in original
//! order. This module then applies the deterministic, native-fact-driven outcomes
//! (CAS, missing target, bad branch target type, LFS fail-closed, prefix and HEAD
//! dependencies) and seals the exact final per-ref verdicts.
//!
//! Rules that cannot be bypassed:
//!
//! * a policy accept cannot resurrect a deterministic rejection;
//! * a rejected ref is never accepted later and never silently dropped;
//! * HEAD is never left dangling by accident: deleting the kept HEAD branch is a
//!   per-ref `head_dependency` rejection, and a retarget whose target is not in the
//!   final ref map refuses the whole selection (`HeadTargetMissing`);
//! * the final name set obeys stock Git's strict `a` vs `a/b` namespace rule;
//! * all-rejected is a valid selection (`is_all_rejected`): no proof, no ref
//!   revision and no extra root hold; integration persists `durableRejected`.
use super::verdict::{PolicyVerdict, RefRejectReason, RefVerdict};
use crate::ref_store::CommitMode;
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::pack_commit::error::{PackCommitError, PackCommitRejectCode, PackCommitRejection};
use crate::ref_store::core::pack_commit::plan::PackCommitPlan;
use crate::ref_store::core::pack_commit::{RefFacts, VerifiedPublicationFacts};
use crate::ref_store::core::types::{HeadUpdate, RefTarget, RefUpdate, is_strict_prefix};
use std::collections::BTreeMap;

/// Sealed, persistable selection in ORIGINAL plan order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubsetSelection {
    verdicts: Vec<RefVerdict>,
    accepted: Vec<RefUpdate>,
    original_parent_digest: RequestDigest,
    digest: RequestDigest,
}

impl SubsetSelection {
    pub fn verdicts(&self) -> &[RefVerdict] {
        &self.verdicts
    }

    pub fn accepted(&self) -> &[RefUpdate] {
        &self.accepted
    }

    pub fn is_all_rejected(&self) -> bool {
        self.accepted.is_empty()
    }

    /// `core-subset-selection-v1`: original parent digest, commit mode and every
    /// ordered verdict (name + accepted/reason/detail).
    pub fn digest(&self) -> &RequestDigest {
        &self.digest
    }

    pub fn original_parent_digest(&self) -> &RequestDigest {
        &self.original_parent_digest
    }

    /// `(ref_name, canonical_verdict)` rows for the durable per-ref verdict table.
    pub fn canonical_rows(&self) -> Vec<(String, String)> {
        self.verdicts.iter().map(|verdict| (verdict.name().as_str().to_owned(), verdict.canonical())).collect()
    }
}

/// Seal the final selection from native facts plus policy verdicts.
///
/// `policy` must contain exactly one verdict per plan ref, in original order.
pub(crate) fn seal_selection(
    plan: &PackCommitPlan,
    facts: &VerifiedPublicationFacts,
    policy: &[PolicyVerdict],
) -> Result<(SubsetSelection, Vec<RefUpdate>), PackCommitError> {
    facts.ensure_binds(plan)?;
    if policy.len() != plan.refs().len() {
        return Err(PackCommitError::Invalid("policy must carry exactly one verdict per plan ref"));
    }
    let mut final_map = old_map(facts);
    let head_keep = matches!(plan.head(), HeadUpdate::Keep);
    let mut verdicts = Vec::with_capacity(plan.refs().len());
    let mut accepted = Vec::new();
    for (index, update) in plan.refs().iter().enumerate() {
        let policy_verdict = &policy[index];
        if policy_verdict.name() != update.name() {
            return Err(PackCommitError::Invalid("policy verdicts are not in the original plan ref order"));
        }
        let ref_facts = facts
            .ref_facts(update.name().as_str())
            .ok_or(PackCommitError::Invalid("native facts are missing one plan ref"))?;
        let mut outcome = deterministic_outcome(update, ref_facts);
        if outcome.is_none() && policy_verdict.rejects() {
            let reason =
                policy_verdict.reason().ok_or(PackCommitError::Invalid("policy rejection has no shared reason"))?;
            let detail = policy_verdict.detail().ok_or(PackCommitError::Invalid("policy rejection has no detail"))?;
            outcome = Some((reason, detail));
        }
        if outcome.is_none()
            && head_keep
            && update.name().as_str() == facts.head_ref().as_str()
            && *update.target() == RefTarget::Delete
        {
            outcome = Some((RefRejectReason::HeadDependency, "deletes-kept-head"));
        }
        if outcome.is_none() && creates_prefix_conflict(&final_map, update) {
            outcome = Some((RefRejectReason::PrefixConflict, "final-ref-name-conflict"));
        }
        match outcome {
            Some((reason, detail)) => {
                verdicts.push(RefVerdict::rejected(update.name().clone(), reason, detail)?);
            }
            None => {
                apply(update, &mut final_map);
                accepted.push(update.clone());
                verdicts.push(RefVerdict::accepted(update.name().clone()));
            }
        }
    }
    // Authorized Atomic publications stay all-or-nothing: one deterministic or
    // policy rejection rolls the WHOLE batch to all-rejected (no effects, no
    // proof, no revision). AcceptedSubset keeps the per-ref verdicts.
    if plan.commit_mode() == CommitMode::Atomic && verdicts.iter().any(|verdict| !verdict.is_accepted()) {
        for verdict in &mut verdicts {
            if verdict.is_accepted() {
                *verdict =
                    RefVerdict::rejected(verdict.name().clone(), RefRejectReason::Policy, "atomic-batch-rejected")?;
            }
        }
        accepted.clear();
    }
    // A retarget must land on a live branch of the final map. An all-rejected
    // selection applies nothing, so the captured HEAD state is unchanged.
    if !accepted.is_empty()
        && let HeadUpdate::Retarget(target) = plan.head()
        && !final_map.contains_key(target.as_str())
    {
        return Err(PackCommitError::Rejected(PackCommitRejection::new(
            PackCommitRejectCode::HeadTargetMissing,
            "HEAD retarget target is not in the resulting ref map",
        )));
    }
    let digest = selection_digest(plan, &verdicts);
    Ok((
        SubsetSelection { verdicts, accepted: accepted.clone(), original_parent_digest: *plan.parent_digest(), digest },
        accepted,
    ))
}

/// Deterministic native-fact outcomes, independent of policy.
fn deterministic_outcome(update: &RefUpdate, facts: &RefFacts) -> Option<(RefRejectReason, &'static str)> {
    let actual = facts.old_oid_hex();
    let satisfied = match update.precondition() {
        crate::ref_store::core::types::RefPrecondition::Absent => actual.is_none(),
        crate::ref_store::core::types::RefPrecondition::Present(oid) => actual == Some(oid.as_hex().as_str()),
    };
    if !satisfied {
        return Some((RefRejectReason::Cas, "old-oid-mismatch"));
    }
    if *update.target() == RefTarget::Delete {
        return None;
    }
    match facts.target_present() {
        Some(true) => {}
        _ => return Some((RefRejectReason::MissingTarget, "new-target-missing")),
    }
    if update.name().is_branch() && facts.branch_target_is_commit() != Some(true) {
        return Some((RefRejectReason::BadObjectType, "branch-target-not-commit"));
    }
    if !facts.changed_paths_complete() {
        return Some((RefRejectReason::Policy, "lfs-path-scan-incomplete"));
    }
    if let Some(detail) = facts.lfs_failure() {
        // LFS must fail closed: no durable byte fact / unverified bytes means the
        // ref is rejected, never allowed.
        return Some((RefRejectReason::Policy, detail));
    }
    None
}

fn old_map(facts: &VerifiedPublicationFacts) -> BTreeMap<String, String> {
    facts.old_refs().iter().map(|reference| (reference.name().to_owned(), reference.oid_hex().to_owned())).collect()
}

fn apply(update: &RefUpdate, map: &mut BTreeMap<String, String>) {
    match update.target() {
        RefTarget::Delete => {
            map.remove(update.name().as_str());
        }
        RefTarget::Oid(oid) => {
            map.insert(update.name().as_str().to_owned(), oid.as_hex());
        }
    }
}

/// Would accepting this update create a strict `a` vs `a/b` relation with another
/// final name? Deletion never creates a conflict.
fn creates_prefix_conflict(map: &BTreeMap<String, String>, update: &RefUpdate) -> bool {
    if *update.target() == RefTarget::Delete {
        return false;
    }
    let name = update.name().as_str();
    map.keys()
        .filter(|other| other.as_str() != name)
        .any(|other| is_strict_prefix(name, other) || is_strict_prefix(other, name))
}

fn selection_digest(plan: &PackCommitPlan, verdicts: &[RefVerdict]) -> RequestDigest {
    let mut fields: Vec<Vec<u8>> = vec![
        plan.parent_digest().as_bytes().to_vec(),
        plan.commit_mode().as_str().as_bytes().to_vec(),
        (verdicts.len() as u64).to_be_bytes().to_vec(),
    ];
    for verdict in verdicts {
        fields.push(verdict.canonical().into_bytes());
    }
    let parts = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
    RequestDigest::of("core-subset-selection-v1", &parts)
}
