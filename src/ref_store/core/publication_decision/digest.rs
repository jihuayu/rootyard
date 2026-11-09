//! Canonical digest material for publication decisions.
//!
//! Decision-owned digests cover the live authorization/policy facts and the plan binding. The
//! selection and selected-ref digests are **not** invented here: they are the exact
//! `subset::SelectedPackPlan` projection digests persisted from the sealed projection. That makes the
//! persisted selection and the proved selection the same value, not two domains that can drift.
use super::contract::DependencyObservation;
use super::policy::{
    BranchRuleFacts, CheckRunFacts, LfsLockFacts, LfsObjectFacts, PullApprovalFacts, PullFacts, RepoPolicyFacts,
};
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::pack_commit::plan::{PackCommitPlan, PlannedPack};
use crate::ref_store::core::types::RefUpdate;
use uuid::Uuid;

const DOMAIN_REFS: &str = "publication-decision-refs-v1";
const DOMAIN_POLICY: &str = "publication-decision-policy-v1";
const DOMAIN_FACTS: &str = "publication-decision-facts-v1";
const DOMAIN_AUTHZ: &str = "publication-decision-authz-v1";
const DOMAIN_DEPENDENCIES: &str = "publication-decision-dependencies-v1";
const DOMAIN_PACKS: &str = "publication-decision-packs-v1";
const DOMAIN_HOLDS: &str = "publication-decision-holds-v1";
const DOMAIN_AUTHORITY: &str = "publication-decision-authority-v1";
const DOMAIN_SCOPE: &str = "publication-decision-scope-v1";

pub(super) fn push_field(fields: &mut Vec<Vec<u8>>, value: impl AsRef<[u8]>) {
    fields.push(value.as_ref().to_vec());
}

pub(super) fn canonical(domain: &str, fields: &[Vec<u8>]) -> RequestDigest {
    let parts = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
    RequestDigest::of(domain, &parts)
}

fn flag(value: bool) -> [u8; 1] {
    [value as u8]
}

fn push_update(fields: &mut Vec<Vec<u8>>, update: &RefUpdate) {
    push_field(fields, update.name().as_str());
    push_field(fields, update.precondition().canonical_tag());
    push_field(fields, update.precondition().oid().map(|oid| oid.as_hex()).unwrap_or_default());
    push_field(fields, update.target().canonical_tag());
    push_field(fields, update.target().oid().map(|oid| oid.as_hex()).unwrap_or_default());
}

/// Canonical digest of the exact old/new update set of a plan (stable order = plan order).
pub(super) fn refs_digest(refs: &[RefUpdate]) -> RequestDigest {
    let mut fields = Vec::new();
    push_field(&mut fields, (refs.len() as u64).to_be_bytes());
    for update in refs {
        push_update(&mut fields, update);
    }
    canonical(DOMAIN_REFS, &fields)
}

/// Canonical digest of the trusted native fact value (as produced by the native engine).
pub(super) fn native_facts_digest(facts: &RequestDigest) -> RequestDigest {
    canonical(DOMAIN_FACTS, &[facts.as_bytes().to_vec()])
}

pub(super) fn rules_digest(rules: &[BranchRuleFacts]) -> RequestDigest {
    let mut fields = Vec::new();
    push_field(&mut fields, (rules.len() as u64).to_be_bytes());
    for rule in rules {
        push_field(&mut fields, rule.branch_ref.as_bytes());
        push_field(&mut fields, rule.required_approvals.to_be_bytes());
        push_field(&mut fields, (rule.required_checks.len() as u64).to_be_bytes());
        for check in &rule.required_checks {
            push_field(&mut fields, check.as_bytes());
        }
        push_field(&mut fields, flag(rule.require_fast_forward));
        push_field(&mut fields, flag(rule.prevent_deletion));
        push_field(&mut fields, flag(rule.prevent_force_push));
        push_field(&mut fields, flag(rule.prevent_self_approval));
        push_field(&mut fields, rule.version.to_be_bytes());
    }
    canonical("publication-decision-rules-v1", &fields)
}

pub(super) fn pulls_digest(pulls: &[PullFacts]) -> RequestDigest {
    let mut fields = Vec::new();
    push_field(&mut fields, (pulls.len() as u64).to_be_bytes());
    for pull in pulls {
        push_field(&mut fields, pull.number.to_be_bytes());
        push_field(&mut fields, pull.head_ref.as_bytes());
        push_field(&mut fields, pull.base_ref.as_bytes());
        push_field(&mut fields, pull.head_oid.as_bytes());
        push_field(&mut fields, pull.base_oid.as_bytes());
        push_field(&mut fields, pull.version.to_be_bytes());
    }
    canonical("publication-decision-pulls-v1", &fields)
}

pub(super) fn approvals_digest(approvals: &[PullApprovalFacts]) -> RequestDigest {
    let mut fields = Vec::new();
    push_field(&mut fields, (approvals.len() as u64).to_be_bytes());
    for approval in approvals {
        push_field(&mut fields, approval.pull_number.to_be_bytes());
        push_field(&mut fields, approval.number.to_be_bytes());
        push_field(&mut fields, approval.author_id.as_bytes());
        push_field(&mut fields, approval.state.as_bytes());
        push_field(&mut fields, approval.commit_oid.as_bytes());
        push_field(&mut fields, approval.pull_version.to_be_bytes());
    }
    canonical("publication-decision-approvals-v1", &fields)
}

pub(super) fn checks_digest(checks: &[CheckRunFacts]) -> RequestDigest {
    let mut fields = Vec::new();
    push_field(&mut fields, (checks.len() as u64).to_be_bytes());
    for check in checks {
        push_field(&mut fields, check.commit_oid.as_bytes());
        push_field(&mut fields, check.context.as_bytes());
        push_field(&mut fields, check.status.as_bytes());
        push_field(&mut fields, check.conclusion.clone().unwrap_or_default());
        push_field(
            &mut fields,
            [
                check.binding_present as u8,
                check.binding_active as u8,
                check.webhook_active as u8,
                check.ci_run_valid as u8,
            ],
        );
        push_field(&mut fields, check.bound_webhook_id.map(|id| id.to_string()).unwrap_or_default().as_bytes());
        push_field(&mut fields, check.issuer_webhook_id.map(|id| id.to_string()).unwrap_or_default().as_bytes());
        push_field(&mut fields, check.ci_base_oid.clone().unwrap_or_default());
    }
    canonical("publication-decision-checks-v1", &fields)
}

pub(super) fn lfs_locks_digest(locks: &[LfsLockFacts]) -> RequestDigest {
    let mut fields = Vec::new();
    push_field(&mut fields, (locks.len() as u64).to_be_bytes());
    for lock in locks {
        push_field(&mut fields, lock.path.as_bytes());
        push_field(&mut fields, lock.owner_user_id.as_bytes());
        push_field(&mut fields, lock.version.to_be_bytes());
    }
    canonical("publication-decision-lfs-locks-v1", &fields)
}

pub(super) fn lfs_objects_digest(objects: &[LfsObjectFacts]) -> RequestDigest {
    let mut fields = Vec::new();
    push_field(&mut fields, (objects.len() as u64).to_be_bytes());
    for object in objects {
        push_field(&mut fields, object.oid.as_bytes());
        push_field(&mut fields, flag(object.ready));
    }
    canonical("publication-decision-lfs-objects-v1", &fields)
}

/// Canonical digest of the live policy rows that were evaluated.
pub(super) fn policy_digest(policy: &RepoPolicyFacts) -> RequestDigest {
    let fields = vec![
        rules_digest(&policy.rules).as_bytes().to_vec(),
        pulls_digest(&policy.pulls).as_bytes().to_vec(),
        approvals_digest(&policy.approvals).as_bytes().to_vec(),
        checks_digest(&policy.checks).as_bytes().to_vec(),
        lfs_locks_digest(&policy.lfs_locks).as_bytes().to_vec(),
        lfs_objects_digest(&policy.lfs_objects).as_bytes().to_vec(),
    ];
    canonical(DOMAIN_POLICY, &fields)
}

/// Canonical digest of the live authorization facts (subject, credential and repository lifecycle).
pub(super) struct AuthzFacts<'a> {
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub actor_id: Uuid,
    pub token_id: Uuid,
    pub token_kind: &'a str,
    pub token_read_only: bool,
    pub token_restricted: bool,
    pub token_scope_version: i64,
    pub token_expires_millis: Option<i64>,
    pub role: &'a str,
    pub repository_state: &'a str,
    pub storage_backend: &'a str,
    pub transition_state: &'a str,
    pub pando_authority: bool,
    pub storage_generation: i64,
    pub actions: &'a [&'static str],
    pub action: &'a str,
}

pub(super) fn authz_digest(facts: &AuthzFacts<'_>) -> RequestDigest {
    let mut fields = Vec::new();
    for id in [facts.repository_id, facts.tenant_id, facts.owner_id, facts.actor_id, facts.token_id] {
        push_field(&mut fields, id.as_bytes());
    }
    push_field(&mut fields, facts.token_kind.as_bytes());
    push_field(&mut fields, [facts.token_read_only as u8, facts.token_restricted as u8]);
    push_field(&mut fields, facts.token_scope_version.to_be_bytes());
    push_field(&mut fields, facts.token_expires_millis.unwrap_or(-1).to_be_bytes());
    push_field(&mut fields, facts.role.as_bytes());
    push_field(&mut fields, facts.repository_state.as_bytes());
    push_field(&mut fields, facts.storage_backend.as_bytes());
    push_field(&mut fields, facts.transition_state.as_bytes());
    push_field(&mut fields, flag(facts.pando_authority));
    push_field(&mut fields, facts.storage_generation.to_be_bytes());
    push_field(&mut fields, facts.action.as_bytes());
    push_field(&mut fields, (facts.actions.len() as u64).to_be_bytes());
    for action in facts.actions {
        push_field(&mut fields, action.as_bytes());
    }
    canonical(DOMAIN_AUTHZ, &fields)
}

/// Canonical digest of the observed gate/protocol realm used as the authority base.
#[allow(clippy::too_many_arguments)]
pub(super) fn authority_digest(
    tenant_id: Uuid,
    object_format: &str,
    history_incarnation: Uuid,
    authority_epoch: i64,
    group_epoch: i64,
    revision: i64,
    decision_required: bool,
    head_ref: &str,
) -> RequestDigest {
    let mut fields = Vec::new();
    push_field(&mut fields, tenant_id.as_bytes());
    push_field(&mut fields, object_format.as_bytes());
    push_field(&mut fields, history_incarnation.as_bytes());
    push_field(&mut fields, authority_epoch.to_be_bytes());
    push_field(&mut fields, group_epoch.to_be_bytes());
    push_field(&mut fields, revision.to_be_bytes());
    push_field(&mut fields, flag(decision_required));
    push_field(&mut fields, head_ref.as_bytes());
    canonical(DOMAIN_AUTHORITY, &fields)
}

/// Canonical digest over the ordered dependency observations.
pub(super) fn dependencies_digest(dependencies: &[DependencyObservation]) -> RequestDigest {
    let mut fields = Vec::new();
    push_field(&mut fields, (dependencies.len() as u64).to_be_bytes());
    for dependency in dependencies {
        push_field(&mut fields, dependency.kind.as_str());
        push_field(&mut fields, dependency.id.as_bytes());
        push_field(&mut fields, dependency.version.to_be_bytes());
        push_field(&mut fields, dependency.digest.as_bytes());
    }
    canonical(DOMAIN_DEPENDENCIES, &fields)
}

/// Canonical digest of one arbitrary scope payload (used for the "no session"/"no user row" scopes).
pub(super) fn scope_digest(tag: &str, parts: &[&[u8]]) -> RequestDigest {
    let mut fields = Vec::new();
    push_field(&mut fields, tag.as_bytes());
    for part in parts {
        push_field(&mut fields, part);
    }
    canonical(DOMAIN_SCOPE, &fields)
}

/// Canonical digest of the planned pack identities (sorted, so plan order is irrelevant).
pub(super) fn packs_digest(packs: &[PlannedPack]) -> RequestDigest {
    let mut material = packs
        .iter()
        .map(|pack| {
            (
                pack.pack_id().as_bytes().to_vec(),
                pack.registration_id().as_bytes().to_vec(),
                pack.total_bytes().to_be_bytes().to_vec(),
            )
        })
        .collect::<Vec<_>>();
    material.sort();
    let mut fields = Vec::new();
    push_field(&mut fields, (material.len() as u64).to_be_bytes());
    for (pack_id, registration_id, total_bytes) in material {
        push_field(&mut fields, pack_id);
        push_field(&mut fields, registration_id);
        push_field(&mut fields, total_bytes);
    }
    canonical(DOMAIN_PACKS, &fields)
}

/// Canonical digest of the hold/publication registrations the plan depends on.
pub(super) fn hold_receipts_digest(packs: &[PlannedPack]) -> RequestDigest {
    let mut ids = packs.iter().map(|pack| pack.registration_id().as_bytes().to_vec()).collect::<Vec<_>>();
    ids.sort();
    let mut fields = Vec::new();
    push_field(&mut fields, (ids.len() as u64).to_be_bytes());
    for id in ids {
        push_field(&mut fields, id);
    }
    canonical(DOMAIN_HOLDS, &fields)
}

/// All digests a decision binds. `selection_digest` and `selected_refs_digest` are the exact sealed
/// projection value; they are never recomputed from a decision-owned selection domain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct DecisionDigests {
    pub base_gate_digest: RequestDigest,
    pub command_digest: RequestDigest,
    pub refs_digest: RequestDigest,
    pub selected_refs_digest: RequestDigest,
    pub selection_digest: RequestDigest,
    pub policy_digest: RequestDigest,
    pub facts_digest: RequestDigest,
    pub authz_digest: RequestDigest,
    pub dependencies_digest: RequestDigest,
    pub packs_digest: RequestDigest,
    pub hold_receipts_digest: RequestDigest,
    pub captured_oid_digest: RequestDigest,
}

impl DecisionDigests {
    pub(super) fn compute(
        plan: &PackCommitPlan,
        selection_digest: RequestDigest,
        policy: &RepoPolicyFacts,
        authz: RequestDigest,
        dependencies: &[DependencyObservation],
        native_facts: RequestDigest,
        captured: RequestDigest,
    ) -> Self {
        Self {
            base_gate_digest: *plan.expected().gate_digest(),
            command_digest: *plan.parent_digest(),
            refs_digest: refs_digest(plan.refs()),
            selected_refs_digest: selection_digest,
            selection_digest,
            policy_digest: policy_digest(policy),
            facts_digest: native_facts_digest(&native_facts),
            authz_digest: authz,
            dependencies_digest: dependencies_digest(dependencies),
            packs_digest: packs_digest(plan.packs()),
            hold_receipts_digest: hold_receipts_digest(plan.packs()),
            captured_oid_digest: captured,
        }
    }
}
