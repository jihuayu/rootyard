//! Pure per-ref policy selection over the concrete native facts.
//!
//! The pipeline is: native facts (no closure proof) -> one [`PolicyVerdict`] per ORIGINAL plan ref ->
//! `subset::SelectedPackPlan::seal(original.clone(), &facts, &policies)` -> persist the sealed verdicts
//! and digest -> derived selected plan -> native closure proof over the full selected ref map.
//!
//! This module never decides CAS, missing NEW target, branch object type, prefix or HEAD dependency:
//! those deterministic outcomes belong to the subset owner and are applied by `seal`. Policy can only
//! deny; it can never resurrect a deterministic rejection, invent a fact or widen a grant.
use super::contract::{DecisionError, DecisionRejectCode, MergeBinding, PublicationAction};
use super::facts_bridge::{old_oid, ref_facts};
use super::policy::{BranchRuleFacts, CheckRunFacts, PullFacts, RepoPolicyFacts};
use super::subset::{PolicyVerdict, RefRejectReason};
use crate::ref_store::core::pack_commit::{RefFacts, VerifiedPublicationFacts};
use crate::ref_store::core::types::{GitObjectFormat, GitOid, RefUpdate};
use uuid::Uuid;

/// Maximum LFS pointer objects one decision may evaluate (bounded fail-closed).
pub(super) const MAX_POINTER_OBJECTS: usize = 4096;

pub(super) struct SelectionInput<'a> {
    pub action: &'a PublicationAction,
    pub format: GitObjectFormat,
    pub refs: &'a [RefUpdate],
    pub actor_id: Uuid,
    pub policy: &'a RepoPolicyFacts,
    pub facts: &'a VerifiedPublicationFacts,
}

#[derive(Debug)]
pub(super) struct SelectionOutcome {
    /// Exactly one policy verdict per original plan ref, in original order.
    pub policy: Vec<PolicyVerdict>,
}

/// LFS pointer object ids introduced by the plan refs that really have a NEW target. A missing NEW
/// target is a per-ref subset outcome, not a whole-publication failure, so those refs are skipped.
pub(super) fn collect_lfs_oids(
    refs: &[RefUpdate],
    facts: &VerifiedPublicationFacts,
) -> Result<Vec<String>, DecisionError> {
    let mut oids: Vec<String> = Vec::new();
    for update in refs {
        if update.target().oid().is_none() {
            continue;
        }
        let ref_facts = ref_facts(facts, update.name().as_str())?;
        if ref_facts.target_present() != Some(true) || ref_facts.lfs_failure().is_some() {
            continue;
        }
        for pointer in ref_facts.lfs_pointers() {
            if pointer.oid_hex().len() != 64 || !pointer.oid_hex().bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(DecisionError::Unverifiable("LFS pointer object id is not canonical hex"));
            }
            oids.push(pointer.oid_hex().to_ascii_lowercase());
        }
    }
    if oids.len() > MAX_POINTER_OBJECTS {
        return Err(DecisionError::Unverifiable("too many LFS pointer objects in one publication"));
    }
    oids.sort();
    oids.dedup();
    Ok(oids)
}

fn rule_for<'a>(policy: &'a RepoPolicyFacts, name: &str) -> Option<&'a BranchRuleFacts> {
    policy.rules.iter().find(|rule| rule.branch_ref == name)
}

fn deny(
    name: &crate::ref_store::core::types::RefName,
    code: DecisionRejectCode,
) -> Result<PolicyVerdict, DecisionError> {
    PolicyVerdict::reject(name.clone(), RefRejectReason::Policy, code.as_str())
        .map_err(|_| DecisionError::Ledger("policy reject detail is not a stable literal"))
}

/// Evaluate one ref. `Ok(None)` = policy accepts (deterministic outcomes stay with `seal`).
fn evaluate(
    input: &SelectionInput<'_>,
    update: &RefUpdate,
    ref_facts: &RefFacts,
) -> Result<Option<DecisionRejectCode>, DecisionError> {
    let name = update.name().as_str();
    let deleting = update.target().oid().is_none();
    let new_target = update.target().oid();

    // Missing NEW target: the subset decision owns this deterministic per-ref outcome. Native
    // changed-path/check facts do not exist, so policy does not evaluate them here.
    if !deleting && ref_facts.target_present() != Some(true) {
        return Ok(None);
    }

    // LFS pointer metadata readiness (actual `lfs_objects(state='ready')` rows).
    if let Some(new) = &new_target {
        if ref_facts.lfs_failure().is_none() {
            for pointer in ref_facts.lfs_pointers() {
                let oid = pointer.oid_hex();
                match input.policy.lfs_objects.iter().find(|object| object.oid == oid) {
                    Some(object) if object.ready => {}
                    _ => return Ok(Some(DecisionRejectCode::PolicyDenied)),
                }
            }
        }
        let _ = new;
    }

    // Changed-path LFS locks apply to every ref, independent of a branch rule.
    if !deleting {
        if !ref_facts.changed_paths_complete() {
            return Err(DecisionError::Unverifiable("changed-path scan of a ref is incomplete"));
        }
        for path in ref_facts.changed_paths() {
            if let Some(lock) = input.policy.lfs_locks.iter().find(|lock| &lock.path == path)
                && lock.owner_user_id != input.actor_id
            {
                return Ok(Some(DecisionRejectCode::LfsLocked));
            }
        }
    }

    if !update.name().is_branch() {
        return Ok(None);
    }
    let Some(rule) = rule_for(input.policy, name) else {
        return Ok(None);
    };
    if deleting {
        if rule.prevent_deletion {
            return Ok(Some(DecisionRejectCode::ProtectedBranch));
        }
        return Ok(None);
    }
    let Some(new) = &new_target else {
        return Ok(None);
    };

    let old = old_oid(input.facts, name)?;
    let creating = old.is_none();

    // Fast-forward / force-push: the native facts own the ancestry computation; policy reads it.
    if !creating && (rule.require_fast_forward || rule.prevent_force_push) {
        match ref_facts.fast_forward() {
            Some(true) => {}
            Some(false) => return Ok(Some(DecisionRejectCode::ForcePushDenied)),
            None => return Err(DecisionError::Unverifiable("fast-forward ancestry fact is missing")),
        }
    }

    match input.action {
        PublicationAction::Push => {
            // EXACT current ContentsWrite semantics: a branch rule requiring approvals makes a
            // direct push impossible. There is no pull-request identity on a direct push, so an
            // open PR with this head can never substitute for it.
            if rule.required_approvals > 0 {
                return Ok(Some(DecisionRejectCode::MissingApprovals));
            }
            if !required_checks_pass(input, rule, new, old.as_ref(), creating)? {
                return Ok(Some(DecisionRejectCode::RequiredCheckFailed));
            }
        }
        PublicationAction::Merge(binding) => {
            if let Some(reject) = evaluate_merge(input, rule, update, binding)? {
                return Ok(Some(reject));
            }
        }
    }
    Ok(None)
}

/// Exact `trusted_check_passed` semantics for the required contexts of a rule.
fn required_checks_pass(
    input: &SelectionInput<'_>,
    rule: &BranchRuleFacts,
    commit: &GitOid,
    base: Option<&GitOid>,
    creating: bool,
) -> Result<bool, DecisionError> {
    let commit_hex = commit.as_hex();
    for context in &rule.required_checks {
        let Some(run) = input.policy.checks.iter().find(|run| run.context == *context && run.commit_oid == commit_hex)
        else {
            return Ok(false);
        };
        if !check_passes(run, base, creating) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn check_passes(run: &CheckRunFacts, base: Option<&GitOid>, creating: bool) -> bool {
    if run.status != "completed" || run.conclusion.as_deref() != Some("success") {
        return false;
    }
    if !run.binding_present {
        return true;
    }
    if creating {
        return false;
    }
    let Some(base) = base else { return false };
    if !run.binding_active || !run.webhook_active {
        return false;
    }
    if run.bound_webhook_id.is_none() || run.issuer_webhook_id != run.bound_webhook_id {
        return false;
    }
    if run.ci_base_oid.as_deref() != Some(base.as_hex().as_str()) {
        return false;
    }
    run.ci_run_valid
}

/// A merge must bind the exact live pull facts and pass its current reviews/checks. Any mismatch is a
/// policy refusal; the atomic `forge_pulls` finalizer is a separate explicit step.
fn evaluate_merge(
    input: &SelectionInput<'_>,
    rule: &BranchRuleFacts,
    update: &RefUpdate,
    binding: &MergeBinding,
) -> Result<Option<DecisionRejectCode>, DecisionError> {
    let pull = input.policy.pulls.iter().find(|pull| pull.number == binding.pull_number());
    let Some(pull) = pull else {
        return Ok(Some(DecisionRejectCode::PullFlowViolation));
    };
    if !merge_bindings_match(pull, binding, update) {
        return Ok(Some(DecisionRejectCode::PullFlowViolation));
    }
    // The merged update must advance exactly the pull's base ref from its recorded base OID.
    if update.precondition().oid().map(|oid| oid.as_hex()).as_deref() != Some(binding.base_oid()) {
        return Ok(Some(DecisionRejectCode::PullFlowViolation));
    }
    // Required checks use the verified PR head and base (stock merge policy), not the merge commit.
    let head = GitOid::parse(input.format, binding.head_oid())
        .map_err(|_| DecisionError::Denied(super::contract::DenialCode::UnsupportedAction))?;
    let base = GitOid::parse(input.format, binding.base_oid())
        .map_err(|_| DecisionError::Denied(super::contract::DenialCode::UnsupportedAction))?;
    if !required_checks_pass(input, rule, &head, Some(&base), false)? {
        return Ok(Some(DecisionRejectCode::RequiredCheckFailed));
    }

    let mut approvals: i64 = 0;
    let mut self_approved = false;
    for review in input.policy.approvals.iter().filter(|review| review.pull_number == binding.pull_number()) {
        if review.pull_version != binding.version() || review.commit_oid != binding.head_oid() {
            continue;
        }
        match review.state.as_str() {
            "changes_requested" => return Ok(Some(DecisionRejectCode::PullFlowViolation)),
            "approved" => {}
            _ => continue,
        }
        if review.author_id == input.actor_id {
            self_approved = true;
            if rule.prevent_self_approval {
                continue;
            }
        }
        approvals += 1;
    }
    if approvals >= rule.required_approvals {
        return Ok(None);
    }
    if self_approved && rule.prevent_self_approval {
        Ok(Some(DecisionRejectCode::SelfApprovalDenied))
    } else {
        Ok(Some(DecisionRejectCode::MissingApprovals))
    }
}

fn merge_bindings_match(pull: &PullFacts, binding: &MergeBinding, update: &RefUpdate) -> bool {
    pull.number == binding.pull_number()
        && pull.version == binding.version()
        && pull.head_oid == binding.head_oid()
        && pull.base_oid == binding.base_oid()
        && pull.base_ref == update.name().as_str()
}

/// One policy verdict per original plan ref. Policy never drops a ref.
pub(super) fn policy_verdicts(input: &SelectionInput<'_>) -> Result<SelectionOutcome, DecisionError> {
    let mut policy = Vec::with_capacity(input.refs.len());
    for update in input.refs {
        let ref_facts = ref_facts(input.facts, update.name().as_str())?;
        match evaluate(input, update, ref_facts)? {
            None => policy.push(PolicyVerdict::accept(update.name().clone())),
            Some(code) => policy.push(deny(update.name(), code)?),
        }
    }
    Ok(SelectionOutcome { policy })
}
