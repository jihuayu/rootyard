//! Deterministic metadata snapshot/pin state transitions.
//!
//! Lease expiry and renewal use only `logical_clock_floor` supplied via Raft log
//! entries (never wall clocks), preserving non-refundable snapshot quotas.

use super::commands::{CreateSnapshotPinCommand, ReleasePinCommand, RenewPinCommand, ScopeLifecycle, SmPinState};
use super::response::{ApplyResponse, StateMachineError};
use super::state::{PinReceiptRecord, PinRecord, QuotaCounters, SmState, SnapshotRecord};
use crate::ref_store::contract::{MetadataMutationAction, RefStoreError, RequestDigest};
use crate::ref_store::core::pack_commit::PackMode;
use crate::ref_store::core::snapshot_contract::{
    MAX_PIN_LEASE_SECONDS, MAX_SNAPSHOT_PACKS, MAX_SNAPSHOT_REFS, REPO_MAX_LOGICAL_BYTES, REPO_MAX_RECEIPTS,
    REPO_MAX_SNAPSHOT_REFS, REPO_MAX_SNAPSHOTS, TENANT_MAX_LOGICAL_BYTES, TENANT_MAX_RECEIPTS,
    TENANT_MAX_SNAPSHOT_REFS, TENANT_MAX_SNAPSHOTS,
};
use std::str::FromStr;
use uuid::Uuid;

pub(super) fn create_snapshot_pin(
    state: &mut SmState,
    cmd: CreateSnapshotPinCommand,
) -> Result<ApplyResponse, StateMachineError> {
    if cmd.request_id.is_nil()
        || cmd.repository_id.is_nil()
        || cmd.tenant_id.is_nil()
        || cmd.owner_id.is_nil()
        || cmd.snapshot_id.is_nil()
        || cmd.pin_id.is_nil()
        || cmd.snapshot_id == cmd.pin_id
    {
        return Err(StateMachineError::Store(RefStoreError::InvalidIdentity(
            "snapshot/pin ids must be non-nil and distinct".into(),
        )));
    }
    if cmd.lease_ticks == 0 || cmd.lease_ticks > u64::try_from(MAX_PIN_LEASE_SECONDS).unwrap_or(3600) {
        return Err(StateMachineError::InvalidInput("pin lease_ticks out of bounds".into()));
    }
    if cmd.pack_digests.len() > MAX_SNAPSHOT_PACKS {
        return Err(StateMachineError::InvalidInput("pack_digests exceeds MAX_SNAPSHOT_PACKS".into()));
    }
    RequestDigest::from_str(&cmd.expected_gate_digest)?;
    RequestDigest::from_str(&cmd.request_digest)?;

    if let Some(receipt) = state.pin_receipts.get(&cmd.request_id) {
        if receipt.action != MetadataMutationAction::Create
            || receipt.repository_id != cmd.repository_id
            || receipt.tenant_id != cmd.tenant_id
            || receipt.owner_id != cmd.owner_id
            || receipt.pin_id != cmd.pin_id
            || receipt.snapshot_id != cmd.snapshot_id
            || receipt.request_digest != cmd.request_digest
        {
            return Err(StateMachineError::Store(RefStoreError::DigestConflict));
        }
        return Ok(ApplyResponse::SnapshotPinCreated {
            snapshot_id: receipt.snapshot_id,
            pin_id: receipt.pin_id,
            generation: receipt.pin_generation,
            gate_revision: receipt.gate_revision,
            expires_at_tick: receipt.expires_at_tick,
            replayed: true,
        });
    }

    if state.pins.contains_key(&cmd.pin_id) || state.snapshots.contains_key(&cmd.snapshot_id) {
        return Err(StateMachineError::Store(RefStoreError::IdentityConflict));
    }
    let gate =
        state.gates.get(&cmd.repository_id).ok_or(StateMachineError::Store(RefStoreError::RepositoryNotFound))?;
    if gate.tenant_id != cmd.tenant_id {
        return Err(StateMachineError::InvalidInput("snapshot tenant does not match gate tenant".into()));
    }
    if gate.lifecycle != ScopeLifecycle::Open {
        return Err(StateMachineError::ScopeClosingOrClosed {
            repository_id: cmd.repository_id,
            lifecycle: gate.lifecycle,
        });
    }
    if gate.object_format != cmd.object_format
        || gate.history_incarnation != cmd.history_incarnation
        || gate.authority_epoch != cmd.authority_epoch
        || gate.group_epoch != cmd.group_epoch
    {
        return Err(StateMachineError::InvalidInput("snapshot scope realm disagrees with current gate".into()));
    }
    let gate_version = gate.version()?;
    if gate_version.digest().as_hex() != cmd.expected_gate_digest {
        return Err(StateMachineError::InvalidInput("expected_gate_digest differs from current gate".into()));
    }

    let current_refs = state.refs.get(&cmd.repository_id).cloned().unwrap_or_default();
    if current_refs.len() > MAX_SNAPSHOT_REFS {
        return Err(StateMachineError::QuotaExceeded("snapshot exceeds MAX_SNAPSHOT_REFS"));
    }
    let effective_tick = state.logical_clock_floor.max(cmd.logical_tick);
    let expires_at_tick = effective_tick
        .checked_add(cmd.lease_ticks)
        .ok_or(StateMachineError::InvalidInput("lease tick overflow".into()))?;
    let logical_bytes = (current_refs.len() as i64).saturating_mul(128).saturating_add(512);
    charge_snapshot_quota(state, cmd.repository_id, cmd.tenant_id, current_refs.len() as i64, logical_bytes)?;

    let head_oid = current_refs.get(&gate.head_ref).cloned();
    let pack_mode = if cmd.pack_digests.is_empty() { PackMode::MetadataOnly } else { gate.pack_mode };
    let gate_revision = gate.revision;
    let head_ref = gate.head_ref.clone();

    state.advance_clock(effective_tick);
    state.snapshots.insert(
        cmd.snapshot_id,
        SnapshotRecord {
            snapshot_id: cmd.snapshot_id,
            repository_id: cmd.repository_id,
            tenant_id: cmd.tenant_id,
            owner_id: cmd.owner_id,
            purpose: cmd.purpose,
            object_format: cmd.object_format,
            history_incarnation: cmd.history_incarnation,
            authority_epoch: cmd.authority_epoch,
            group_epoch: cmd.group_epoch,
            gate_revision,
            gate_digest: cmd.expected_gate_digest,
            head_ref,
            head_oid,
            refs: current_refs,
            pack_mode,
            pack_digests: cmd.pack_digests,
            created_tick: effective_tick,
            logical_bytes,
        },
    );
    state.pins.insert(
        cmd.pin_id,
        PinRecord {
            pin_id: cmd.pin_id,
            snapshot_id: cmd.snapshot_id,
            repository_id: cmd.repository_id,
            tenant_id: cmd.tenant_id,
            owner_id: cmd.owner_id,
            purpose: cmd.purpose,
            state: SmPinState::Active,
            generation: 1,
            created_tick: effective_tick,
            expires_at_tick,
            release_reason: None,
        },
    );
    state.pin_receipts.insert(
        cmd.request_id,
        PinReceiptRecord {
            request_id: cmd.request_id,
            repository_id: cmd.repository_id,
            tenant_id: cmd.tenant_id,
            owner_id: cmd.owner_id,
            action: MetadataMutationAction::Create,
            pin_id: cmd.pin_id,
            snapshot_id: cmd.snapshot_id,
            pin_generation: 1,
            expires_at_tick,
            gate_revision,
            request_digest: cmd.request_digest,
        },
    );
    Ok(ApplyResponse::SnapshotPinCreated {
        snapshot_id: cmd.snapshot_id,
        pin_id: cmd.pin_id,
        generation: 1,
        gate_revision,
        expires_at_tick,
        replayed: false,
    })
}

pub(super) fn renew_pin(state: &mut SmState, cmd: RenewPinCommand) -> Result<ApplyResponse, StateMachineError> {
    if cmd.request_id.is_nil() || cmd.pin_id.is_nil() || cmd.expected_generation <= 0 {
        return Err(StateMachineError::Store(RefStoreError::InvalidIdentity("invalid renew pin parameters".into())));
    }
    if cmd.lease_ticks == 0 || cmd.lease_ticks > u64::try_from(MAX_PIN_LEASE_SECONDS).unwrap_or(3600) {
        return Err(StateMachineError::InvalidInput("renew lease_ticks out of bounds".into()));
    }
    RequestDigest::from_str(&cmd.request_digest)?;

    if let Some(receipt) = state.pin_receipts.get(&cmd.request_id) {
        if receipt.action != MetadataMutationAction::Renew
            || receipt.repository_id != cmd.repository_id
            || receipt.pin_id != cmd.pin_id
            || receipt.request_digest != cmd.request_digest
        {
            return Err(StateMachineError::Store(RefStoreError::DigestConflict));
        }
        return Ok(ApplyResponse::PinRenewed {
            pin_id: receipt.pin_id,
            generation: receipt.pin_generation,
            expires_at_tick: receipt.expires_at_tick,
            replayed: true,
        });
    }

    let pin = state.pins.get(&cmd.pin_id).ok_or(StateMachineError::PinNotFound { pin_id: cmd.pin_id })?.clone();
    if pin.repository_id != cmd.repository_id || pin.tenant_id != cmd.tenant_id || pin.owner_id != cmd.owner_id {
        return Err(StateMachineError::InvalidInput("pin renew scope mismatch".into()));
    }
    if pin.state == SmPinState::Released {
        return Err(StateMachineError::PinReleased { pin_id: pin.pin_id });
    }
    if pin.generation != cmd.expected_generation {
        return Err(StateMachineError::PinGenerationMismatch {
            pin_id: pin.pin_id,
            expected: cmd.expected_generation,
            actual: pin.generation,
        });
    }
    let effective_tick = state.logical_clock_floor.max(cmd.logical_tick);
    if effective_tick >= pin.expires_at_tick {
        return Err(StateMachineError::PinExpired {
            pin_id: pin.pin_id,
            expires_at_tick: pin.expires_at_tick,
            current_tick: effective_tick,
        });
    }
    let next_generation = pin.generation + 1;
    let new_expiry = effective_tick
        .checked_add(cmd.lease_ticks)
        .ok_or(StateMachineError::InvalidInput("lease tick overflow".into()))?;
    charge_pin_receipt_quota(state, cmd.repository_id, cmd.tenant_id)?;
    state.advance_clock(effective_tick);
    if let Some(mut_pin) = state.pins.get_mut(&cmd.pin_id) {
        mut_pin.generation = next_generation;
        mut_pin.expires_at_tick = new_expiry;
    }
    let gate_revision = state.gates.get(&cmd.repository_id).map_or(0, |gate| gate.revision);
    state.pin_receipts.insert(
        cmd.request_id,
        PinReceiptRecord {
            request_id: cmd.request_id,
            repository_id: cmd.repository_id,
            tenant_id: cmd.tenant_id,
            owner_id: cmd.owner_id,
            action: MetadataMutationAction::Renew,
            pin_id: pin.pin_id,
            snapshot_id: pin.snapshot_id,
            pin_generation: next_generation,
            expires_at_tick: new_expiry,
            gate_revision,
            request_digest: cmd.request_digest,
        },
    );
    Ok(ApplyResponse::PinRenewed {
        pin_id: pin.pin_id,
        generation: next_generation,
        expires_at_tick: new_expiry,
        replayed: false,
    })
}

pub(super) fn release_pin(state: &mut SmState, cmd: ReleasePinCommand) -> Result<ApplyResponse, StateMachineError> {
    if cmd.request_id.is_nil() || cmd.pin_id.is_nil() || cmd.reason.trim().is_empty() {
        return Err(StateMachineError::Store(RefStoreError::InvalidIdentity("invalid pin release request".into())));
    }
    RequestDigest::from_str(&cmd.request_digest)?;
    if let Some(receipt) = state.pin_receipts.get(&cmd.request_id) {
        if receipt.action != MetadataMutationAction::Release
            || receipt.repository_id != cmd.repository_id
            || receipt.pin_id != cmd.pin_id
            || receipt.request_digest != cmd.request_digest
        {
            return Err(StateMachineError::Store(RefStoreError::DigestConflict));
        }
        return Ok(ApplyResponse::PinReleased {
            pin_id: receipt.pin_id,
            generation: receipt.pin_generation,
            replayed: true,
        });
    }
    let pin = state.pins.get(&cmd.pin_id).ok_or(StateMachineError::PinNotFound { pin_id: cmd.pin_id })?.clone();
    if pin.repository_id != cmd.repository_id || pin.tenant_id != cmd.tenant_id || pin.owner_id != cmd.owner_id {
        return Err(StateMachineError::InvalidInput("pin release scope mismatch".into()));
    }
    charge_pin_receipt_quota(state, cmd.repository_id, cmd.tenant_id)?;
    state.advance_clock(cmd.logical_tick);
    if let Some(mut_pin) = state.pins.get_mut(&cmd.pin_id)
        && mut_pin.state == SmPinState::Active
    {
        mut_pin.state = SmPinState::Released;
        mut_pin.release_reason = Some(cmd.reason);
    }
    let gate_revision = state.gates.get(&cmd.repository_id).map_or(0, |gate| gate.revision);
    state.pin_receipts.insert(
        cmd.request_id,
        PinReceiptRecord {
            request_id: cmd.request_id,
            repository_id: cmd.repository_id,
            tenant_id: cmd.tenant_id,
            owner_id: cmd.owner_id,
            action: MetadataMutationAction::Release,
            pin_id: pin.pin_id,
            snapshot_id: pin.snapshot_id,
            pin_generation: pin.generation,
            expires_at_tick: pin.expires_at_tick,
            gate_revision,
            request_digest: cmd.request_digest,
        },
    );
    Ok(ApplyResponse::PinReleased { pin_id: pin.pin_id, generation: pin.generation, replayed: false })
}

fn charge_snapshot_quota(
    state: &mut SmState,
    repo_id: Uuid,
    tenant_id: Uuid,
    refs_count: i64,
    logical_bytes: i64,
) -> Result<(), StateMachineError> {
    let check = |q: QuotaCounters, ms: i64, mr: i64, mb: i64, mrec: i64| -> Result<QuotaCounters, StateMachineError> {
        let next = QuotaCounters {
            snapshots: q.snapshots + 1,
            snapshot_refs: q.snapshot_refs + refs_count,
            snapshot_logical_bytes: q.snapshot_logical_bytes.saturating_add(logical_bytes),
            pin_receipts: q.pin_receipts + 1,
            ..q
        };
        if next.snapshots > ms
            || next.snapshot_refs > mr
            || next.snapshot_logical_bytes > mb
            || next.pin_receipts > mrec
        {
            return Err(StateMachineError::QuotaExceeded("snapshot/pin quota exceeded"));
        }
        Ok(next)
    };
    let next_repo = check(
        state.repo_quotas.get(&repo_id).copied().unwrap_or_default(),
        REPO_MAX_SNAPSHOTS,
        REPO_MAX_SNAPSHOT_REFS,
        REPO_MAX_LOGICAL_BYTES,
        REPO_MAX_RECEIPTS,
    )?;
    let next_tenant = check(
        state.tenant_quotas.get(&tenant_id).copied().unwrap_or_default(),
        TENANT_MAX_SNAPSHOTS,
        TENANT_MAX_SNAPSHOT_REFS,
        TENANT_MAX_LOGICAL_BYTES,
        TENANT_MAX_RECEIPTS,
    )?;
    state.repo_quotas.insert(repo_id, next_repo);
    state.tenant_quotas.insert(tenant_id, next_tenant);
    Ok(())
}

fn charge_pin_receipt_quota(state: &mut SmState, repo_id: Uuid, tenant_id: Uuid) -> Result<(), StateMachineError> {
    let r = state.repo_quotas.get(&repo_id).copied().unwrap_or_default().pin_receipts + 1;
    let t = state.tenant_quotas.get(&tenant_id).copied().unwrap_or_default().pin_receipts + 1;
    if r > REPO_MAX_RECEIPTS || t > TENANT_MAX_RECEIPTS {
        return Err(StateMachineError::QuotaExceeded("pin receipt quota exceeded"));
    }
    state.repo_quotas.entry(repo_id).or_default().pin_receipts = r;
    state.tenant_quotas.entry(tenant_id).or_default().pin_receipts = t;
    Ok(())
}
