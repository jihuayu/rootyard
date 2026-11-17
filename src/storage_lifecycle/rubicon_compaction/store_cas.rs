//! Lease fencing, CAS validation, and atomic commit transitions for DurableCompactionStore (#162).

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    CompactionError,
    lease::{
        CompactionAuthoritativeSnapshot, CompactionLeaseKey, CompactionLeaseToken, CompactionPhase,
        CompactionPublishReceipt, CompactionPublishRequest, PendingOperationRecord,
    },
    segment::CompactionByteAccounting,
    sharding::pack_set_digest,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LeaseSlotState {
    pub(super) next_fence_epoch: u64,
    pub(super) active: Option<CompactionLeaseToken>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredOpEntry {
    pub(super) request_digest: String,
    pub(super) receipt: CompactionPublishReceipt,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DurableStoreState {
    pub(super) repos: BTreeMap<(Uuid, Uuid, Uuid), CompactionAuthoritativeSnapshot>,
    pub(super) leases: BTreeMap<String, LeaseSlotState>,
    pub(super) checkpoints: BTreeMap<Uuid, PendingOperationRecord>,
    pub(super) operations: BTreeMap<Uuid, StoredOpEntry>,
    pub(super) cas_conflict_count: u64,
    pub(super) double_retirement_rejections: u64,
}

pub(super) fn lease_slot_key(key: &CompactionLeaseKey) -> String {
    format!("{}:{}:{}:{}", key.tenant_id, key.repo_id, key.history_id, key.shard_id)
}

pub(super) fn validate_lease_in_state(
    state: &DurableStoreState,
    key: &CompactionLeaseKey,
    lease_id: Uuid,
    fence_epoch: u64,
    now_ms: u64,
) -> Result<(), CompactionError> {
    let slot = state.leases.get(&lease_slot_key(key)).ok_or(CompactionError::LeaseLost("lease missing"))?;
    let active = slot.active.as_ref().ok_or(CompactionError::LeaseLost("lease released"))?;
    if active.lease_id != lease_id || active.fence_epoch != fence_epoch {
        return Err(CompactionError::LeaseLost("lease fenced out by newer epoch/owner"));
    }
    if now_ms >= active.expires_at_ms {
        return Err(CompactionError::LeaseLost("lease expired"));
    }
    Ok(())
}

pub(super) fn acquire_lease_locked(
    state: &mut DurableStoreState,
    key: &CompactionLeaseKey,
    owner_id: &str,
    now_ms: u64,
    ttl_ms: u64,
) -> Result<CompactionLeaseToken, CompactionError> {
    let slot = state.leases.entry(lease_slot_key(key)).or_insert(LeaseSlotState { next_fence_epoch: 1, active: None });
    match &mut slot.active {
        Some(existing) if existing.owner_id == owner_id && now_ms < existing.expires_at_ms => {
            existing.expires_at_ms = now_ms.saturating_add(ttl_ms);
            Ok(existing.clone())
        }
        Some(existing) if now_ms < existing.expires_at_ms => {
            Err(CompactionError::LeaseContended { owner: existing.owner_id.clone() })
        }
        _ => {
            let epoch = slot.next_fence_epoch;
            slot.next_fence_epoch = slot.next_fence_epoch.saturating_add(1);
            let fresh = CompactionLeaseToken {
                key: key.clone(),
                lease_id: Uuid::new_v4(),
                owner_id: owner_id.to_owned(),
                fence_epoch: epoch,
                acquired_at_ms: now_ms,
                expires_at_ms: now_ms.saturating_add(ttl_ms),
            };
            slot.active = Some(fresh.clone());
            Ok(fresh)
        }
    }
}

pub(super) fn apply_cas_commit_locked(
    guard: &mut DurableStoreState,
    request: &CompactionPublishRequest,
    now_ms: u64,
) -> Result<CompactionPublishReceipt, CompactionError> {
    if !request.delete_disabled {
        return Err(CompactionError::DeleteForbidden);
    }
    let req_digest = request.canonical_digest();
    if let Some(existing) = guard.operations.get(&request.op_id) {
        if existing.request_digest == req_digest {
            return Ok(existing.receipt.clone());
        }
        return Err(CompactionError::OperationConflict("op_id reused with different payload digest"));
    }
    let key = CompactionLeaseKey {
        tenant_id: request.tenant_id,
        repo_id: request.repo_id,
        history_id: request.history_id,
        shard_id: request.shard_id,
    };
    validate_lease_in_state(guard, &key, request.lease_id, request.fence_epoch, now_ms)?;
    if !request.equivalence_proof.fsck_verified
        || !request.equivalence_proof.delta_bases_verified
        || request.equivalence_proof.oid_set_digest.is_empty()
        || request.equivalence_proof.canonical_digest() != request.equivalence_proof_digest
    {
        return Err(CompactionError::EquivalenceFailed("publish request lacks valid equivalence proof".into()));
    }
    let repo_key = (request.tenant_id, request.repo_id, request.history_id);
    let Some(repo) = guard.repos.get(&repo_key) else {
        return Err(CompactionError::InvalidInput("missing repository authority".into()));
    };
    if repo.authority_epoch != request.authority_epoch
        || repo.membership_generation != request.expected_membership_generation
        || repo.pack_set_digest != request.expected_pack_set_digest
        || repo.refs_digest != request.expected_refs_digest
        || repo.retention_roots_digest != request.expected_retention_roots_digest
    {
        guard.cas_conflict_count = guard.cas_conflict_count.saturating_add(1);
        return Err(CompactionError::MembershipDrift(format!(
            "expected gen={}, actual gen={}",
            request.expected_membership_generation, repo.membership_generation
        )));
    }
    let retire_set: HashSet<Uuid> = request.retired_pack_ids.iter().copied().collect();
    let plan_set: HashSet<Uuid> = request.merge_plan.input_packs.iter().map(|p| p.pack_id).collect();
    if request.retired_pack_ids.len() < 2
        || retire_set.len() != request.retired_pack_ids.len()
        || retire_set != plan_set
    {
        return Err(CompactionError::OperationConflict("retired_pack_ids must uniquely match merge_plan inputs"));
    }
    let already_retired = repo.retained_old_packs.iter().any(|p| retire_set.contains(&p.pack_id));
    let serving_ids: HashSet<Uuid> = repo.serving_packs.iter().map(|p| p.pack_id).collect();
    if already_retired || !retire_set.iter().all(|id| serving_ids.contains(id)) {
        guard.double_retirement_rejections = guard.double_retirement_rejections.saturating_add(1);
        return Err(CompactionError::OperationConflict("double retirement or missing serving input pack rejected"));
    }
    if repo.serving_packs.iter().any(|p| p.pack_id == request.replacement_pack.pack_id) {
        return Err(CompactionError::OperationConflict("replacement pack_id already in serving"));
    }
    request.replacement_pack.validate(repo.shard_count)?;

    let mut next_segments = repo.segments.clone();
    next_segments.apply_compacted_merge(&request.merge_plan, request.replacement_pack.clone(), now_ms)?;

    let repo_mut = guard.repos.get_mut(&repo_key).expect("verified repo");
    let mut next_serving = Vec::with_capacity(repo_mut.serving_packs.len() + 1);
    for pack in repo_mut.serving_packs.drain(..) {
        if retire_set.contains(&pack.pack_id) {
            repo_mut.retained_old_packs.push(pack);
        } else {
            next_serving.push(pack);
        }
    }
    next_serving.push(request.replacement_pack.clone());
    repo_mut.serving_packs = next_serving;
    let next_gen = repo_mut.membership_generation.saturating_add(1);
    repo_mut.membership_generation = next_gen;
    repo_mut.pack_set_digest = pack_set_digest(&repo_mut.serving_packs);
    repo_mut.segments = next_segments;
    repo_mut.cumulative_newly_written_bytes =
        repo_mut.cumulative_newly_written_bytes.saturating_add(request.replacement_pack.physical_pair_bytes());
    let accounting = CompactionByteAccounting::compute(
        &repo_mut.serving_packs,
        &repo_mut.retained_old_packs,
        repo_mut.cumulative_newly_written_bytes,
    );
    let receipt = CompactionPublishReceipt {
        op_id: request.op_id,
        request_digest: req_digest.clone(),
        authority_epoch: repo_mut.authority_epoch,
        history_id: repo_mut.history_id,
        previous_membership_generation: request.expected_membership_generation,
        new_membership_generation: next_gen,
        new_pack_set_digest: repo_mut.pack_set_digest.clone(),
        retired_pack_ids: request.retired_pack_ids.clone(),
        replacement_pack: request.replacement_pack.clone(),
        merge_plan: request.merge_plan.clone(),
        equivalence_proof: request.equivalence_proof.clone(),
        accounting,
        published_at_ms: now_ms,
    };
    guard.operations.insert(request.op_id, StoredOpEntry { request_digest: req_digest, receipt: receipt.clone() });
    guard.checkpoints.insert(
        request.op_id,
        PendingOperationRecord {
            op_id: request.op_id,
            key,
            fence_epoch: request.fence_epoch,
            expected_membership_generation: request.expected_membership_generation,
            phase: CompactionPhase::Published { new_membership_generation: next_gen },
        },
    );
    Ok(receipt)
}
