//! Fail-closed pre-CAS checks and signed remote authorization grant verification (`Refs #156`).

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ref_store::contract::IssuerLane;
use crate::ref_store::core::command::CommitRefsRequest;
use crate::ref_store::core::contract::CommitMode;
use crate::ref_store::core::state_machine::{CommitScopedRefsCommand, InstallScopedDecisionCommand, ScopeLifecycle};
use crate::ref_store::core::types::{GitOid, HeadUpdate, RefName, RefUpdate};
use crate::ref_store::projector::{
    DecisionGrantKeyring, RemoteAuthzGrantError, build_scoped_commit_from_grant, verify_signed_decision_grant,
};

use super::types::{
    CheckRunSnapshot, MergeAttemptSpec, MergePullSnapshot, MergeStrategy, RemoteMergeError, oid_valid_for_format,
    sha256_hex_valid, unique_sorted_checks,
};

const MERGE_BINDING_DOMAIN: &[u8] = b"rootyard/pulls/remote-merge-binding/v1";
const REQUIRED_CHECKS_DOMAIN: &[u8] = b"rootyard/pulls/required-checks/v1";
const OBSERVED_CHECKS_DOMAIN: &[u8] = b"rootyard/pulls/observed-checks/v1";

fn feed_len_str(h: &mut Sha256, s: &str) {
    h.update((s.len() as u64).to_be_bytes());
    h.update(s.as_bytes());
}

pub fn compute_required_checks_digest(required_checks: &[String], min_sequence: i64) -> String {
    let mut unique: Vec<&str> = required_checks.iter().map(String::as_str).collect();
    unique.sort_unstable();
    unique.dedup();
    let mut h = Sha256::new();
    h.update(REQUIRED_CHECKS_DOMAIN);
    h.update([0]);
    h.update(min_sequence.to_be_bytes());
    h.update((unique.len() as u64).to_be_bytes());
    for ctx in unique {
        feed_len_str(&mut h, ctx);
    }
    hex::encode(h.finalize())
}

pub fn compute_observed_checks_digest(
    expected_head_oid: &str,
    expected_base_oid: &str,
    required_checks: &[String],
    min_sequence: i64,
    observed_checks: &[CheckRunSnapshot],
) -> String {
    let mut unique: Vec<&str> = required_checks.iter().map(String::as_str).collect();
    unique.sort_unstable();
    unique.dedup();
    let mut sorted: Vec<&CheckRunSnapshot> = observed_checks.iter().collect();
    sorted.sort_unstable_by_key(|c| {
        (
            c.context.as_str(),
            c.sequence,
            c.attempt,
            c.status.as_str(),
            c.commit_oid.as_str(),
            c.conclusion.as_deref().unwrap_or(""),
            c.base_oid.as_deref().unwrap_or(""),
            c.trusted,
        )
    });
    let mut h = Sha256::new();
    h.update(OBSERVED_CHECKS_DOMAIN);
    h.update([0]);
    feed_len_str(&mut h, expected_head_oid);
    feed_len_str(&mut h, expected_base_oid);
    h.update(min_sequence.to_be_bytes());
    h.update((unique.len() as u64).to_be_bytes());
    for ctx in unique {
        feed_len_str(&mut h, ctx);
    }
    h.update((sorted.len() as u64).to_be_bytes());
    for obs in sorted {
        for s in [&obs.context, &obs.commit_oid, &obs.status] {
            feed_len_str(&mut h, s);
        }
        for opt in [obs.base_oid.as_deref(), obs.conclusion.as_deref()] {
            h.update([u8::from(opt.is_some())]);
            feed_len_str(&mut h, opt.unwrap_or(""));
        }
        h.update(obs.sequence.to_be_bytes());
        h.update(obs.attempt.to_be_bytes());
        h.update([u8::from(obs.trusted)]);
    }
    hex::encode(h.finalize())
}

#[derive(Clone, Debug)]
pub struct MergeBindingInputs<'a> {
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub pull_number: i64,
    pub actor_id: Uuid,
    pub operation_id: Uuid,
    pub decision_id: Uuid,
    pub base_ref: &'a str,
    pub expected_head_oid: &'a str,
    pub expected_base_oid: &'a str,
    pub candidate_target_oid: &'a str,
    pub strategy: MergeStrategy,
    pub expected_version: i64,
    pub expected_storage_generation: i64,
    pub required_checks: &'a [String],
    pub min_check_sequence: i64,
    pub observed_checks: &'a [CheckRunSnapshot],
    pub authz_epoch: i64,
    pub pack_sha256: &'a str,
}

pub fn compute_merge_binding_digest(inputs: &MergeBindingInputs<'_>) -> String {
    let checks_digest = compute_required_checks_digest(inputs.required_checks, inputs.min_check_sequence);
    let observed_digest = compute_observed_checks_digest(
        inputs.expected_head_oid,
        inputs.expected_base_oid,
        inputs.required_checks,
        inputs.min_check_sequence,
        inputs.observed_checks,
    );
    let mut h = Sha256::new();
    h.update(MERGE_BINDING_DOMAIN);
    h.update([0]);
    for id in [inputs.tenant_id, inputs.repository_id, inputs.actor_id, inputs.operation_id, inputs.decision_id] {
        h.update(id.as_bytes());
    }
    for n in [
        inputs.pull_number,
        inputs.expected_version,
        inputs.expected_storage_generation,
        inputs.min_check_sequence,
        inputs.authz_epoch,
    ] {
        h.update(n.to_be_bytes());
    }
    for s in [
        inputs.base_ref,
        inputs.expected_head_oid,
        inputs.expected_base_oid,
        inputs.candidate_target_oid,
        inputs.strategy.as_str(),
        inputs.pack_sha256,
        &checks_digest,
        &observed_digest,
    ] {
        feed_len_str(&mut h, s);
    }
    hex::encode(h.finalize())
}

#[derive(Clone, Debug)]
pub struct ValidatedMergeGrant {
    pub commit_request: CommitRefsRequest,
    pub install_cmd: InstallScopedDecisionCommand,
    pub commit_cmd: CommitScopedRefsCommand,
    pub binding_digest: String,
}

/// Validates repository/PR coordinates, head/base freshness, branch-rule strategy,
/// and required check-run freshness bound to `expected_head_oid` and `expected_base_oid`.
pub fn validate_merge_inputs_and_preconditions(
    spec: &MergeAttemptSpec,
    pull: &MergePullSnapshot,
) -> Result<(), RemoteMergeError> {
    if [
        spec.attempt_id,
        spec.operation_id,
        spec.decision_id,
        spec.tenant_id,
        spec.repository_id,
        spec.actor_id,
        pull.tenant_id,
        pull.repository_id,
    ]
    .iter()
    .any(Uuid::is_nil)
    {
        return Err(RemoteMergeError::InvalidInput("all merge attempt identifiers must be non-nil".into()));
    }
    if spec.pull_number <= 0
        || spec.sequence <= 0
        || spec.expected_version <= 0
        || spec.expected_storage_generation <= 0
        || spec.expected_base_revision <= 0
        || pull.pull_number <= 0
        || pull.version <= 0
        || pull.storage_generation <= 0
    {
        return Err(RemoteMergeError::InvalidInput("numeric versions/sequences/revisions must be > 0".into()));
    }
    if pull.tenant_id != spec.tenant_id
        || pull.repository_id != spec.repository_id
        || pull.pull_number != spec.pull_number
    {
        return Err(RemoteMergeError::RemoteAuthzDenied("pull request snapshot coordinates mismatch merge spec".into()));
    }
    if pull.object_format != spec.object_format {
        return Err(RemoteMergeError::InvalidInput("pull object_format disagrees with merge spec".into()));
    }
    if !oid_valid_for_format(&spec.expected_head_oid, spec.object_format)
        || !oid_valid_for_format(&spec.expected_base_oid, spec.object_format)
        || !oid_valid_for_format(&spec.candidate_target_oid, spec.object_format)
    {
        return Err(RemoteMergeError::InvalidInput("invalid or zero OID for repository object_format".into()));
    }
    if !sha256_hex_valid(&spec.pack_sha256) {
        return Err(RemoteMergeError::InvalidInput("invalid pack_sha256 hex digest".into()));
    }
    if pull.base_ref != spec.base_ref || !spec.base_ref.starts_with("refs/heads/") {
        return Err(RemoteMergeError::InvalidInput("base_ref mismatch or invalid branch ref".into()));
    }
    if pull.state == "merged" {
        return Err(RemoteMergeError::AlreadyMerged {
            pull_number: pull.pull_number,
            committed_oid: pull.merge_commit_oid.clone().unwrap_or_default(),
            commit_log_index: 0,
        });
    }
    if pull.state != "open" {
        return Err(RemoteMergeError::InvalidInput(format!("pull request state `{}` is not open", pull.state)));
    }
    if pull.storage_generation != spec.expected_storage_generation {
        return Err(RemoteMergeError::TargetRefMoved {
            ref_name: spec.base_ref.clone(),
            expected_base_oid: spec.expected_base_oid.clone(),
            actual_base_oid: Some(pull.live_base_ref_oid.clone()),
        });
    }
    if pull.head_oid != spec.expected_head_oid {
        return Err(RemoteMergeError::StaleHeadOid {
            pull_number: pull.pull_number,
            expected_head_oid: spec.expected_head_oid.clone(),
            actual_head_oid: pull.head_oid.clone(),
        });
    }
    if pull.live_head_ref_oid != spec.expected_head_oid {
        return Err(RemoteMergeError::StaleHeadOid {
            pull_number: pull.pull_number,
            expected_head_oid: spec.expected_head_oid.clone(),
            actual_head_oid: pull.live_head_ref_oid.clone(),
        });
    }
    if pull.version != spec.expected_version {
        return Err(RemoteMergeError::StaleHeadOid {
            pull_number: pull.pull_number,
            expected_head_oid: spec.expected_head_oid.clone(),
            actual_head_oid: pull.head_oid.clone(),
        });
    }
    if pull.base_oid != spec.expected_base_oid {
        return Err(RemoteMergeError::TargetRefMoved {
            ref_name: spec.base_ref.clone(),
            expected_base_oid: spec.expected_base_oid.clone(),
            actual_base_oid: Some(pull.base_oid.clone()),
        });
    }
    if pull.live_base_ref_oid != spec.expected_base_oid {
        return Err(RemoteMergeError::TargetRefMoved {
            ref_name: spec.base_ref.clone(),
            expected_base_oid: spec.expected_base_oid.clone(),
            actual_base_oid: Some(pull.live_base_ref_oid.clone()),
        });
    }
    if pull.require_fast_forward && spec.strategy == MergeStrategy::MergeCommit {
        return Err(RemoteMergeError::FastForwardNotPossible(
            "branch protection rule requires fast-forward merge".into(),
        ));
    }

    verify_required_checks(spec, pull)
}

fn verify_required_checks(spec: &MergeAttemptSpec, pull: &MergePullSnapshot) -> Result<(), RemoteMergeError> {
    let required = unique_sorted_checks(&pull.required_checks)?;
    for ctx in &required {
        let mut saw_other_commit = false;
        let mut matching_head = Vec::new();
        for obs in &pull.observed_checks {
            if obs.context == *ctx {
                if obs.commit_oid == spec.expected_head_oid {
                    matching_head.push(obs);
                } else {
                    saw_other_commit = true;
                }
            }
        }
        let Some(latest_key) = matching_head.iter().map(|obs| (obs.sequence, obs.attempt)).max() else {
            let reason = if saw_other_commit {
                format!("required check `{ctx}` only ran on stale commit_oid")
            } else {
                format!("missing required check `{ctx}`")
            };
            return Err(RemoteMergeError::StaleRequiredChecks {
                expected_head_oid: spec.expected_head_oid.clone(),
                reason,
            });
        };
        for check in matching_head.into_iter().filter(|obs| (obs.sequence, obs.attempt) == latest_key) {
            if !check.trusted {
                return Err(RemoteMergeError::StaleRequiredChecks {
                    expected_head_oid: spec.expected_head_oid.clone(),
                    reason: format!("required check `{ctx}` is untrusted"),
                });
            }
            if check.base_oid.as_deref().is_some_and(|b| b != spec.expected_base_oid) {
                return Err(RemoteMergeError::StaleRequiredChecks {
                    expected_head_oid: spec.expected_head_oid.clone(),
                    reason: format!("required check `{ctx}` targeted stale base OID"),
                });
            }
            if check.sequence < pull.min_check_sequence || check.attempt < 1 {
                return Err(RemoteMergeError::StaleRequiredChecks {
                    expected_head_oid: spec.expected_head_oid.clone(),
                    reason: format!("required check `{ctx}` sequence {} < {}", check.sequence, pull.min_check_sequence),
                });
            }
            if check.status != "completed" || check.conclusion.as_deref() != Some("success") {
                return Err(RemoteMergeError::StaleRequiredChecks {
                    expected_head_oid: spec.expected_head_oid.clone(),
                    reason: format!("required check `{ctx}` status={}/conclusion={:?}", check.status, check.conclusion),
                });
            }
        }
    }
    Ok(())
}

/// Verifies signed remote authorization grant, non-revoked scopes/keys/tokens, and
/// exact PR-merge domain bindings before constructing Ref-CAS Raft commands.
pub fn verify_pull_remote_authz_grant(
    spec: &MergeAttemptSpec,
    pull: &MergePullSnapshot,
    keyring: &DecisionGrantKeyring,
) -> Result<ValidatedMergeGrant, RemoteMergeError> {
    if spec.cancelled_operations.contains(&spec.operation_id) {
        return Err(RemoteMergeError::RevokedAuthorization(format!(
            "operation {} already has cancellation tombstone",
            spec.operation_id
        )));
    }

    let lane = IssuerLane::new(spec.lane.as_str()).map_err(|e| RemoteMergeError::InvalidInput(e.to_string()))?;
    let pre = GitOid::precondition_value(spec.object_format, &spec.expected_base_oid)
        .map_err(|e| RemoteMergeError::InvalidInput(e.to_string()))?;
    let target = GitOid::target_value(spec.object_format, &spec.candidate_target_oid)
        .map_err(|e| RemoteMergeError::InvalidInput(e.to_string()))?;
    let ref_name = RefName::branch(spec.base_ref.as_str()).map_err(|e| RemoteMergeError::InvalidInput(e.to_string()))?;
    let update = RefUpdate::new(ref_name, pre, target);

    let commit_request = CommitRefsRequest::new(
        spec.repository_id,
        spec.tenant_id,
        spec.actor_id,
        lane,
        spec.sequence,
        spec.operation_id,
        spec.object_format,
        spec.realm.history_incarnation,
        spec.realm.authority_epoch,
        spec.realm.group_epoch,
        spec.expected_base_revision,
        HeadUpdate::Keep,
        CommitMode::Atomic,
        vec![update],
    )
    .map_err(|e| RemoteMergeError::InvalidInput(e.to_string()))?;
    commit_request.validate().map_err(|e| RemoteMergeError::InvalidInput(e.to_string()))?;

    let install_cmd = verify_signed_decision_grant(
        keyring,
        &spec.grant,
        &spec.realm,
        &spec.expected_service_san,
        spec.current_logical_tick,
    )
    .map_err(map_grant_error)?;

    let p = &spec.grant.payload;
    if p.actor_id != spec.actor_id || p.operation_id != spec.operation_id || p.decision_id != spec.decision_id {
        return Err(RemoteMergeError::RemoteAuthzDenied("grant actor/operation/decision differs from merge spec".into()));
    }
    if p.base_revision != spec.expected_base_revision {
        return Err(RemoteMergeError::TargetRefMoved {
            ref_name: spec.base_ref.clone(),
            expected_base_oid: spec.expected_base_oid.clone(),
            actual_base_oid: Some(pull.live_base_ref_oid.clone()),
        });
    }
    if p.command_digest != commit_request.digest().as_hex() {
        return Err(RemoteMergeError::RemoteAuthzDenied("grant command_digest mismatches merge CAS payload".into()));
    }

    let binding_digest = compute_merge_binding_digest(&MergeBindingInputs {
        tenant_id: spec.tenant_id,
        repository_id: spec.repository_id,
        pull_number: spec.pull_number,
        actor_id: spec.actor_id,
        operation_id: spec.operation_id,
        decision_id: spec.decision_id,
        base_ref: &spec.base_ref,
        expected_head_oid: &spec.expected_head_oid,
        expected_base_oid: &spec.expected_base_oid,
        candidate_target_oid: &spec.candidate_target_oid,
        strategy: spec.strategy,
        expected_version: spec.expected_version,
        expected_storage_generation: spec.expected_storage_generation,
        required_checks: &pull.required_checks,
        min_check_sequence: pull.min_check_sequence,
        observed_checks: &pull.observed_checks,
        authz_epoch: p.authz_epoch,
        pack_sha256: &spec.pack_sha256,
    });
    if p.facts_digest != binding_digest {
        return Err(RemoteMergeError::RemoteAuthzDenied(
            "grant facts_digest does not bind exact pull merge tuple".into(),
        ));
    }

    let accepted_target = p.verdicts.iter().any(|v| v.ref_name == spec.base_ref && v.accepted && v.reject_code.is_none());
    if !accepted_target || p.verdicts.len() != 1 {
        return Err(RemoteMergeError::RemoteAuthzDenied("grant verdicts do not authorize target base_ref merge".into()));
    }

    for dep in &p.scope_dependencies {
        if !spec.live_scopes.iter().any(|s| s.scope_kind == dep.scope_kind && s.scope_id == dep.scope_id) {
            return Err(RemoteMergeError::RevokedAuthorization(format!(
                "missing live state for dependency scope ({}, {})",
                dep.scope_kind, dep.scope_id
            )));
        }
    }
    for live in &spec.live_scopes {
        if live.lifecycle != ScopeLifecycle::Open {
            return Err(RemoteMergeError::RevokedAuthorization(format!(
                "dependency scope ({}, {}) is {:?}",
                live.scope_kind, live.scope_id, live.lifecycle
            )));
        }
        if p.authz_epoch < live.authz_floor {
            return Err(RemoteMergeError::RevokedAuthorization(format!(
                "grant authz_epoch {} < live floor {}",
                p.authz_epoch, live.authz_floor
            )));
        }
    }

    let wire_req = crate::ref_store::core::state_machine::WireCommitRefsRequest::from(&commit_request);
    let commit_cmd = build_scoped_commit_from_grant(&spec.grant, wire_req, BTreeMap::new(), spec.current_logical_tick);
    Ok(ValidatedMergeGrant { commit_request, install_cmd, commit_cmd, binding_digest })
}

fn map_grant_error(err: RemoteAuthzGrantError) -> RemoteMergeError {
    match err {
        RemoteAuthzGrantError::RetiredSigningKey(_)
        | RemoteAuthzGrantError::GrantExpired { .. }
        | RemoteAuthzGrantError::DecisionNotOpenInPg { .. }
        | RemoteAuthzGrantError::DecisionCancelledInPg(_)
        | RemoteAuthzGrantError::ScopeClosingOrMissingInPg { .. } => RemoteMergeError::RevokedAuthorization(err.to_string()),
        _ => RemoteMergeError::RemoteAuthzDenied(err.to_string()),
    }
}
