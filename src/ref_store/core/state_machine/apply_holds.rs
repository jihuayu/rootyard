//! Deterministic artifact-hold reference state transitions.
//!
//! No Blob I/O or PG queries run here; hold retirement refuses whenever any
//! active retention root still binds the target hold id.

use super::commands::{
    AcquireHoldBatchCommand, MarkHoldConsumedCommand, RetireHoldBatchCommand, ScopeLifecycle, SmHoldState, SmRootState,
};
use super::response::{ApplyResponse, StateMachineError};
use super::state::{
    HoldBatchRecord, HoldConsumeRecord, HoldEntry, HoldRetireRecord, QuotaCounters, RepoEntityKey, SmState,
};
use crate::ref_store::contract::{RefStoreError, RequestDigest};
use crate::ref_store::core::artifact_hold::contract::{
    ArtifactHoldPurpose, MAX_BATCH_ARTIFACTS, REPO_MAX_DECLARED_BYTES, REPO_MAX_HOLDS, REPO_MAX_RECEIPTS,
    TENANT_MAX_DECLARED_BYTES, TENANT_MAX_HOLDS, TENANT_MAX_RECEIPTS,
};
use std::collections::BTreeSet;
use std::str::FromStr;
use uuid::Uuid;

pub(super) fn acquire_hold_batch(
    state: &mut SmState,
    cmd: AcquireHoldBatchCommand,
) -> Result<ApplyResponse, StateMachineError> {
    if cmd.request_id.is_nil()
        || cmd.consume_request_id.is_nil()
        || cmd.operation_id.is_nil()
        || cmd.repository_id.is_nil()
        || cmd.tenant_id.is_nil()
        || cmd.owner_id.is_nil()
        || cmd.authority_id.is_nil()
        || cmd.authority_generation <= 0
    {
        return Err(StateMachineError::Store(RefStoreError::InvalidIdentity(
            "hold batch ids and authority generation must be valid".into(),
        )));
    }
    ArtifactHoldPurpose::parse(&cmd.purpose).map_err(|err| StateMachineError::InvalidInput(err.to_string()))?;
    RequestDigest::from_str(&cmd.backend_identity)?;
    RequestDigest::from_str(&cmd.expected_gate_digest)?;
    if cmd.artifacts.is_empty() || cmd.artifacts.len() > MAX_BATCH_ARTIFACTS {
        return Err(StateMachineError::InvalidInput("artifact hold batch size out of bounds".into()));
    }

    let digest = hold_acquire_digest(&cmd);
    if let Some(existing) = state.hold_batches.get(&cmd.request_id) {
        if existing.repository_id != cmd.repository_id
            || existing.tenant_id != cmd.tenant_id
            || existing.owner_id != cmd.owner_id
            || existing.operation_id != cmd.operation_id
            || existing.request_digest != digest
        {
            return Err(StateMachineError::Store(RefStoreError::DigestConflict));
        }
        return Ok(ApplyResponse::HoldBatchAcquired {
            request_id: existing.request_id,
            consume_request_id: existing.consume_request_id,
            hold_count: existing.artifacts.len(),
            replayed: true,
        });
    }

    let gate =
        state.gates.get(&cmd.repository_id).ok_or(StateMachineError::Store(RefStoreError::RepositoryNotFound))?;
    if gate.tenant_id != cmd.tenant_id {
        return Err(StateMachineError::InvalidInput("hold batch tenant differs from gate".into()));
    }
    if gate.lifecycle != ScopeLifecycle::Open {
        return Err(StateMachineError::ScopeClosingOrClosed {
            repository_id: cmd.repository_id,
            lifecycle: gate.lifecycle,
        });
    }
    let op_key = RepoEntityKey::new(cmd.repository_id, cmd.operation_id);
    if state.cancellations.contains_key(&op_key) {
        return Err(StateMachineError::Store(RefStoreError::Cancelled { operation_id: cmd.operation_id }));
    }

    let mut total_declared: i64 = 0;
    let mut seen_holds = BTreeSet::new();
    let mut seen_slots = BTreeSet::new();
    for spec in &cmd.artifacts {
        if spec.hold_id.is_nil() || !seen_holds.insert(spec.hold_id) || state.holds.contains_key(&spec.hold_id) {
            return Err(StateMachineError::InvalidInput("hold_id must be non-nil and globally unique".into()));
        }
        if spec.slot < 0 || !seen_slots.insert(spec.slot) {
            return Err(StateMachineError::InvalidInput("hold slot must be non-negative and unique".into()));
        }
        if spec.declared_bytes <= 0 || spec.logical_bytes <= 0 {
            return Err(StateMachineError::InvalidInput("hold bytes must be positive".into()));
        }
        RequestDigest::from_str(&spec.artifact_digest)?;
        total_declared = total_declared
            .checked_add(spec.declared_bytes)
            .ok_or(StateMachineError::QuotaExceeded("hold declared bytes overflow"))?;
    }

    charge_hold_quota(state, cmd.repository_id, cmd.tenant_id, cmd.artifacts.len() as i64, total_declared)?;

    for spec in &cmd.artifacts {
        state.holds.insert(
            spec.hold_id,
            HoldEntry {
                hold_id: spec.hold_id,
                batch_request_id: cmd.request_id,
                consume_request_id: cmd.consume_request_id,
                operation_id: cmd.operation_id,
                repository_id: cmd.repository_id,
                tenant_id: cmd.tenant_id,
                owner_id: cmd.owner_id,
                purpose: cmd.purpose.clone(),
                slot: spec.slot,
                state: SmHoldState::Active,
                generation: 1,
                artifact_digest: spec.artifact_digest.clone(),
                backend_identity: cmd.backend_identity.clone(),
                authority_id: cmd.authority_id,
                authority_generation: cmd.authority_generation,
                declared_bytes: spec.declared_bytes,
                logical_bytes: spec.logical_bytes,
            },
        );
    }
    let count = cmd.artifacts.len();
    let consume_request_id = cmd.consume_request_id;
    let request_id = cmd.request_id;
    state.hold_batches.insert(
        request_id,
        HoldBatchRecord {
            request_id,
            consume_request_id,
            operation_id: cmd.operation_id,
            repository_id: cmd.repository_id,
            tenant_id: cmd.tenant_id,
            owner_id: cmd.owner_id,
            purpose: cmd.purpose,
            backend_identity: cmd.backend_identity,
            authority_id: cmd.authority_id,
            authority_generation: cmd.authority_generation,
            expected_gate_digest: cmd.expected_gate_digest,
            artifacts: cmd.artifacts,
            request_digest: digest,
        },
    );
    Ok(ApplyResponse::HoldBatchAcquired { request_id, consume_request_id, hold_count: count, replayed: false })
}

pub(super) fn mark_hold_consumed(
    state: &mut SmState,
    cmd: MarkHoldConsumedCommand,
) -> Result<ApplyResponse, StateMachineError> {
    if cmd.consume_request_id.is_nil() || cmd.request_id.is_nil() || cmd.hold_ids.is_empty() {
        return Err(StateMachineError::Store(RefStoreError::InvalidIdentity(
            "consume hold request requires valid ids and holds".into(),
        )));
    }
    let digest = hold_consume_digest(&cmd);
    if let Some(existing) = state.hold_consumes.get(&cmd.consume_request_id) {
        if existing.request_digest != digest || existing.repository_id != cmd.repository_id {
            return Err(StateMachineError::Store(RefStoreError::DigestConflict));
        }
        return Ok(ApplyResponse::HoldsConsumed {
            consume_request_id: existing.consume_request_id,
            hold_count: existing.hold_ids.len(),
            replayed: true,
        });
    }
    let mut provided = BTreeSet::new();
    for hold_id in &cmd.hold_ids {
        if !provided.insert(*hold_id) {
            return Err(StateMachineError::InvalidInput("duplicate hold_id in consume batch".into()));
        }
        let hold = state.holds.get(hold_id).ok_or(StateMachineError::HoldNotFound { hold_id: *hold_id })?;
        if hold.repository_id != cmd.repository_id || hold.tenant_id != cmd.tenant_id {
            return Err(StateMachineError::HoldScopeMismatch { hold_id: *hold_id });
        }
        if hold.batch_request_id != cmd.request_id || hold.consume_request_id != cmd.consume_request_id {
            return Err(StateMachineError::HoldScopeMismatch { hold_id: *hold_id });
        }
        if hold.state != SmHoldState::Active {
            return Err(StateMachineError::HoldNotActive { hold_id: *hold_id, state: hold.state });
        }
    }
    let batch = state
        .hold_batches
        .get(&cmd.request_id)
        .ok_or_else(|| StateMachineError::InvalidInput("hold batch not found for consume".into()))?;
    if batch.repository_id != cmd.repository_id
        || batch.tenant_id != cmd.tenant_id
        || batch.consume_request_id != cmd.consume_request_id
    {
        return Err(StateMachineError::InvalidInput("hold batch scope or consume_request_id mismatch".into()));
    }
    let expected: BTreeSet<Uuid> = batch.artifacts.iter().map(|spec| spec.hold_id).collect();
    if provided != expected {
        return Err(StateMachineError::InvalidInput("consume hold_ids must match complete acquire batch".into()));
    }
    for hold_id in &cmd.hold_ids {
        if let Some(hold) = state.holds.get_mut(hold_id) {
            hold.state = SmHoldState::Consumed;
        }
    }
    let hold_count = cmd.hold_ids.len();
    let consume_request_id = cmd.consume_request_id;
    state.hold_consumes.insert(
        consume_request_id,
        HoldConsumeRecord {
            consume_request_id,
            request_id: cmd.request_id,
            repository_id: cmd.repository_id,
            tenant_id: cmd.tenant_id,
            hold_ids: cmd.hold_ids,
            request_digest: digest,
        },
    );
    Ok(ApplyResponse::HoldsConsumed { consume_request_id, hold_count, replayed: false })
}

pub(super) fn retire_hold_batch(
    state: &mut SmState,
    cmd: RetireHoldBatchCommand,
) -> Result<ApplyResponse, StateMachineError> {
    if cmd.request_id.is_nil() || cmd.repository_id.is_nil() || cmd.tenant_id.is_nil() || cmd.hold_ids.is_empty() {
        return Err(StateMachineError::Store(RefStoreError::InvalidIdentity(
            "retire holds requires non-nil ids".into(),
        )));
    }
    let digest = hold_retire_digest(&cmd);
    if let Some(existing) = state.hold_retires.get(&cmd.request_id) {
        if existing.repository_id != cmd.repository_id
            || existing.tenant_id != cmd.tenant_id
            || existing.request_digest != digest
        {
            return Err(StateMachineError::Store(RefStoreError::DigestConflict));
        }
        return Ok(ApplyResponse::HoldsRetired { retired_count: existing.retired_count });
    }
    for hold_id in &cmd.hold_ids {
        let hold = state.holds.get(hold_id).ok_or(StateMachineError::HoldNotFound { hold_id: *hold_id })?;
        if hold.repository_id != cmd.repository_id || hold.tenant_id != cmd.tenant_id {
            return Err(StateMachineError::HoldScopeMismatch { hold_id: *hold_id });
        }
        for root in state.roots.values() {
            if root.state == SmRootState::Active && root.bound_hold_ids.contains(hold_id) {
                return Err(StateMachineError::HoldProtectedByRoot { hold_id: *hold_id, root_id: root.root_id });
            }
        }
    }
    let mut retired = 0usize;
    for hold_id in &cmd.hold_ids {
        if let Some(hold) = state.holds.get_mut(hold_id)
            && hold.state != SmHoldState::Retired
        {
            hold.state = SmHoldState::Retired;
            retired += 1;
        }
    }
    state.hold_retires.insert(
        cmd.request_id,
        HoldRetireRecord {
            request_id: cmd.request_id,
            repository_id: cmd.repository_id,
            tenant_id: cmd.tenant_id,
            hold_ids: cmd.hold_ids,
            retired_count: retired,
            request_digest: digest,
        },
    );
    Ok(ApplyResponse::HoldsRetired { retired_count: retired })
}

fn hold_acquire_digest(cmd: &AcquireHoldBatchCommand) -> String {
    let mut fields: Vec<Vec<u8>> = vec![
        cmd.request_id.as_bytes().to_vec(),
        cmd.consume_request_id.as_bytes().to_vec(),
        cmd.operation_id.as_bytes().to_vec(),
        cmd.repository_id.as_bytes().to_vec(),
        cmd.tenant_id.as_bytes().to_vec(),
        cmd.owner_id.as_bytes().to_vec(),
        cmd.purpose.as_bytes().to_vec(),
        cmd.backend_identity.as_bytes().to_vec(),
        cmd.authority_id.as_bytes().to_vec(),
        cmd.authority_generation.to_be_bytes().to_vec(),
        cmd.expected_gate_digest.as_bytes().to_vec(),
    ];
    for art in &cmd.artifacts {
        fields.push(art.hold_id.as_bytes().to_vec());
        fields.push(art.slot.to_be_bytes().to_vec());
        fields.push(art.artifact_digest.as_bytes().to_vec());
        fields.push(art.declared_bytes.to_be_bytes().to_vec());
        fields.push(art.logical_bytes.to_be_bytes().to_vec());
    }
    let slices: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
    RequestDigest::of("raft-sm-hold-acquire-v1", &slices).as_hex()
}

fn hold_consume_digest(cmd: &MarkHoldConsumedCommand) -> String {
    let mut fields: Vec<Vec<u8>> = vec![
        cmd.consume_request_id.as_bytes().to_vec(),
        cmd.request_id.as_bytes().to_vec(),
        cmd.repository_id.as_bytes().to_vec(),
        cmd.tenant_id.as_bytes().to_vec(),
    ];
    for id in &cmd.hold_ids {
        fields.push(id.as_bytes().to_vec());
    }
    let slices: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
    RequestDigest::of("raft-sm-hold-consume-v1", &slices).as_hex()
}

fn hold_retire_digest(cmd: &RetireHoldBatchCommand) -> String {
    let mut fields: Vec<Vec<u8>> = vec![
        cmd.request_id.as_bytes().to_vec(),
        cmd.repository_id.as_bytes().to_vec(),
        cmd.tenant_id.as_bytes().to_vec(),
    ];
    for id in &cmd.hold_ids {
        fields.push(id.as_bytes().to_vec());
    }
    let slices: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
    RequestDigest::of("raft-sm-hold-retire-v1", &slices).as_hex()
}

fn charge_hold_quota(
    state: &mut SmState,
    repo_id: Uuid,
    tenant_id: Uuid,
    count: i64,
    declared_bytes: i64,
) -> Result<(), StateMachineError> {
    let apply_check = |q: QuotaCounters,
                       max_holds: i64,
                       max_bytes: i64,
                       max_receipts: i64|
     -> Result<QuotaCounters, StateMachineError> {
        let holds = q.holds.checked_add(count).ok_or(StateMachineError::QuotaExceeded("hold count overflow"))?;
        let bytes = q
            .hold_declared_bytes
            .checked_add(declared_bytes)
            .ok_or(StateMachineError::QuotaExceeded("hold declared bytes overflow"))?;
        let receipts = q.hold_receipts + 1;
        if holds > max_holds || bytes > max_bytes || receipts > max_receipts {
            return Err(StateMachineError::QuotaExceeded("artifact hold quota exceeded"));
        }
        Ok(QuotaCounters { holds, hold_declared_bytes: bytes, hold_receipts: receipts, ..q })
    };
    let new_repo = apply_check(
        state.repo_quotas.get(&repo_id).copied().unwrap_or_default(),
        REPO_MAX_HOLDS,
        REPO_MAX_DECLARED_BYTES,
        REPO_MAX_RECEIPTS,
    )?;
    let new_tenant = apply_check(
        state.tenant_quotas.get(&tenant_id).copied().unwrap_or_default(),
        TENANT_MAX_HOLDS,
        TENANT_MAX_DECLARED_BYTES,
        TENANT_MAX_RECEIPTS,
    )?;
    state.repo_quotas.insert(repo_id, new_repo);
    state.tenant_quotas.insert(tenant_id, new_tenant);
    Ok(())
}
