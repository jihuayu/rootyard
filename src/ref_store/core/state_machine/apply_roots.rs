//! Deterministic retention-root registration and release transitions.
//!
//! Release-before-register tombstones, non-reusable `root_id` enforcement,
//! bound hold verification, and non-refundable root quotas all preserve exact PG behavior.

use super::commands::{RegisterRootCommand, ReleaseRootCommand, ScopeLifecycle, SmHoldState, SmPinState, SmRootState};
use super::response::{ApplyResponse, StateMachineError};
use super::state::{RepoEntityKey, RootReceiptRecord, RootRecordSm, RootReleaseTombstone, SmState};
use crate::ref_store::contract::{RefStoreError, RequestDigest};
use crate::ref_store::core::retention_root::{
    REPO_MAX_RECEIPTS, REPO_MAX_ROOTS, RootPurpose, RootSelectorKind, TENANT_MAX_RECEIPTS, TENANT_MAX_ROOTS,
};
use std::str::FromStr;
use uuid::Uuid;

pub(super) fn register_root(state: &mut SmState, cmd: RegisterRootCommand) -> Result<ApplyResponse, StateMachineError> {
    if cmd.request_id.is_nil()
        || cmd.root_id.is_nil()
        || cmd.operation_id.is_nil()
        || cmd.repository_id.is_nil()
        || cmd.tenant_id.is_nil()
        || cmd.owner_id.is_nil()
    {
        return Err(StateMachineError::Store(RefStoreError::InvalidIdentity(
            "root register ids must be non-nil".into(),
        )));
    }
    RootPurpose::parse(&cmd.purpose).map_err(|err| StateMachineError::InvalidInput(err.to_string()))?;
    RootSelectorKind::parse(&cmd.selector_kind).map_err(|err| StateMachineError::InvalidInput(err.to_string()))?;
    for hex_str in [
        &cmd.business_intent_digest,
        &cmd.selector_digest,
        &cmd.refs_digest,
        &cmd.pack_set_digest,
        &cmd.register_digest,
        &cmd.request_digest,
    ] {
        RequestDigest::from_str(hex_str)?;
    }

    if let Some(receipt) = state.root_receipts.get(&cmd.request_id) {
        if receipt.action != "register"
            || receipt.repository_id != cmd.repository_id
            || receipt.root_id != cmd.root_id
            || receipt.request_digest != cmd.request_digest
        {
            return Err(StateMachineError::RootDigestConflict("register request id reused with different digest"));
        }
        return Ok(ApplyResponse::RootRegistered {
            root_id: receipt.root_id,
            roots_revision: receipt.roots_revision,
            replayed: true,
        });
    }

    let tomb_key = RepoEntityKey::new(cmd.repository_id, cmd.root_id);
    if state.root_tombstones.contains_key(&tomb_key) {
        return Err(StateMachineError::RootReleased { root_id: cmd.root_id });
    }
    if state.roots.contains_key(&cmd.root_id) {
        return Err(StateMachineError::RootConflict("root_id cannot be reused"));
    }

    for hold_id in &cmd.bound_hold_ids {
        let hold = state.holds.get(hold_id).ok_or(StateMachineError::HoldNotFound { hold_id: *hold_id })?;
        if hold.repository_id != cmd.repository_id || hold.tenant_id != cmd.tenant_id {
            return Err(StateMachineError::HoldScopeMismatch { hold_id: *hold_id });
        }
        if hold.state == SmHoldState::Retired {
            return Err(StateMachineError::HoldNotActive { hold_id: *hold_id, state: hold.state });
        }
    }

    let snap = state
        .snapshots
        .get(&cmd.source_snapshot_id)
        .ok_or(StateMachineError::SnapshotNotFound { snapshot_id: cmd.source_snapshot_id })?
        .clone();
    let pin = state.pins.get(&cmd.source_pin_id).ok_or(StateMachineError::PinNotFound { pin_id: cmd.source_pin_id })?;
    if pin.state != SmPinState::Active {
        return Err(StateMachineError::PinReleased { pin_id: pin.pin_id });
    }
    if snap.repository_id != cmd.repository_id
        || snap.tenant_id != cmd.tenant_id
        || pin.repository_id != cmd.repository_id
        || pin.tenant_id != cmd.tenant_id
        || pin.snapshot_id != snap.snapshot_id
        || pin.generation != cmd.source_pin_generation
    {
        return Err(StateMachineError::RootConflict("source snapshot/pin does not match root scope"));
    }
    if snap.object_format != cmd.object_format
        || snap.history_incarnation != cmd.history_incarnation
        || snap.authority_epoch != cmd.authority_epoch
        || snap.group_epoch != cmd.group_epoch
    {
        return Err(StateMachineError::RootConflict("source snapshot realm does not match root command"));
    }

    let gate =
        state.gates.get(&cmd.repository_id).ok_or(StateMachineError::Store(RefStoreError::RepositoryNotFound))?;
    if gate.tenant_id != cmd.tenant_id
        || gate.lifecycle != ScopeLifecycle::Open
        || gate.object_format != cmd.object_format
        || gate.history_incarnation != cmd.history_incarnation
        || gate.authority_epoch != cmd.authority_epoch
        || gate.group_epoch != cmd.group_epoch
    {
        return Err(StateMachineError::RootConflict("gate missing, tenant/realm mismatched, or scope closed"));
    }
    let gate_digest = gate.version()?.digest().as_hex();
    let gate_revision = gate.revision;

    charge_root_register_quota(state, cmd.repository_id, cmd.tenant_id)?;
    let next_roots_rev = state
        .gates
        .get_mut(&cmd.repository_id)
        .map(|g| {
            g.roots_revision += 1;
            g.roots_revision
        })
        .unwrap_or(1);

    state.roots.insert(
        cmd.root_id,
        RootRecordSm {
            root_id: cmd.root_id,
            repository_id: cmd.repository_id,
            tenant_id: cmd.tenant_id,
            owner_id: cmd.owner_id,
            operation_id: cmd.operation_id,
            state: SmRootState::Active,
            generation: 1,
            purpose: cmd.purpose,
            business_intent_digest: cmd.business_intent_digest,
            object_format: cmd.object_format,
            history_incarnation: cmd.history_incarnation,
            authority_epoch: cmd.authority_epoch,
            group_epoch: cmd.group_epoch,
            source_snapshot_id: cmd.source_snapshot_id,
            source_pin_id: cmd.source_pin_id,
            source_pin_generation: cmd.source_pin_generation,
            selector_kind: cmd.selector_kind,
            selector_digest: cmd.selector_digest,
            refs_digest: cmd.refs_digest,
            pack_set_digest: cmd.pack_set_digest,
            bound_hold_ids: cmd.bound_hold_ids,
            gate_revision,
            gate_digest,
            roots_revision: next_roots_rev,
            register_digest: cmd.register_digest,
        },
    );
    state.root_receipts.insert(
        cmd.request_id,
        RootReceiptRecord {
            request_id: cmd.request_id,
            repository_id: cmd.repository_id,
            tenant_id: cmd.tenant_id,
            owner_id: cmd.owner_id,
            root_id: cmd.root_id,
            action: "register".into(),
            state: SmRootState::Active,
            generation: 1,
            roots_revision: next_roots_rev,
            request_digest: cmd.request_digest,
        },
    );
    Ok(ApplyResponse::RootRegistered { root_id: cmd.root_id, roots_revision: next_roots_rev, replayed: false })
}

pub(super) fn release_root(state: &mut SmState, cmd: ReleaseRootCommand) -> Result<ApplyResponse, StateMachineError> {
    if cmd.request_id.is_nil() || cmd.root_id.is_nil() || cmd.repository_id.is_nil() {
        return Err(StateMachineError::Store(RefStoreError::InvalidIdentity(
            "root release ids must be non-nil".into(),
        )));
    }
    RequestDigest::from_str(&cmd.expected_register_digest)?;
    RequestDigest::from_str(&cmd.intent_digest)?;

    if let Some(receipt) = state.root_receipts.get(&cmd.request_id) {
        if receipt.action != "release"
            || receipt.repository_id != cmd.repository_id
            || receipt.root_id != cmd.root_id
            || receipt.request_digest != cmd.intent_digest
        {
            return Err(StateMachineError::RootDigestConflict("release request id reused with different digest"));
        }
        return Ok(ApplyResponse::RootReleased { root_id: receipt.root_id, tombstone_created: false, replayed: true });
    }
    if let Some(gate) = state.gates.get(&cmd.repository_id)
        && gate.tenant_id != cmd.tenant_id
    {
        return Err(StateMachineError::RootConflict("release gate tenant mismatch"));
    }

    let tomb_key = RepoEntityKey::new(cmd.repository_id, cmd.root_id);
    if let Some(root) = state.roots.get(&cmd.root_id)
        && (root.repository_id != cmd.repository_id
            || root.tenant_id != cmd.tenant_id
            || root.owner_id != cmd.owner_id
            || root.register_digest != cmd.expected_register_digest)
    {
        return Err(StateMachineError::RootConflict("release scope/digest disagrees with registered root"));
    }
    charge_root_receipt_quota(state, cmd.repository_id, cmd.tenant_id)?;
    let tombstone_created = !state.root_tombstones.contains_key(&tomb_key);
    state.root_tombstones.entry(tomb_key).or_insert_with(|| RootReleaseTombstone {
        key: tomb_key,
        tenant_id: cmd.tenant_id,
        owner_id: cmd.owner_id,
        expected_register_digest: cmd.expected_register_digest,
    });
    if let Some(root) = state.roots.get_mut(&cmd.root_id) {
        root.state = SmRootState::Released;
    }
    let roots_revision = state.gates.get(&cmd.repository_id).map_or(0, |gate| gate.roots_revision);
    state.root_receipts.insert(
        cmd.request_id,
        RootReceiptRecord {
            request_id: cmd.request_id,
            repository_id: cmd.repository_id,
            tenant_id: cmd.tenant_id,
            owner_id: cmd.owner_id,
            root_id: cmd.root_id,
            action: "release".into(),
            state: SmRootState::Released,
            generation: 1,
            roots_revision,
            request_digest: cmd.intent_digest,
        },
    );
    Ok(ApplyResponse::RootReleased { root_id: cmd.root_id, tombstone_created, replayed: false })
}

fn charge_root_register_quota(state: &mut SmState, repo_id: Uuid, tenant_id: Uuid) -> Result<(), StateMachineError> {
    let r = state.repo_quotas.get(&repo_id).copied().unwrap_or_default();
    let t = state.tenant_quotas.get(&tenant_id).copied().unwrap_or_default();
    if r.roots + 1 > REPO_MAX_ROOTS
        || t.roots + 1 > TENANT_MAX_ROOTS
        || r.root_receipts + 1 > REPO_MAX_RECEIPTS
        || t.root_receipts + 1 > TENANT_MAX_RECEIPTS
    {
        return Err(StateMachineError::QuotaExceeded("retention root quota exceeded"));
    }
    let repo_entry = state.repo_quotas.entry(repo_id).or_default();
    repo_entry.roots += 1;
    repo_entry.root_receipts += 1;
    let tenant_entry = state.tenant_quotas.entry(tenant_id).or_default();
    tenant_entry.roots += 1;
    tenant_entry.root_receipts += 1;
    Ok(())
}

fn charge_root_receipt_quota(state: &mut SmState, repo_id: Uuid, tenant_id: Uuid) -> Result<(), StateMachineError> {
    let r = state.repo_quotas.get(&repo_id).copied().unwrap_or_default().root_receipts + 1;
    let t = state.tenant_quotas.get(&tenant_id).copied().unwrap_or_default().root_receipts + 1;
    if r > REPO_MAX_RECEIPTS || t > TENANT_MAX_RECEIPTS {
        return Err(StateMachineError::QuotaExceeded("root receipt quota exceeded"));
    }
    state.repo_quotas.entry(repo_id).or_default().root_receipts = r;
    state.tenant_quotas.entry(tenant_id).or_default().root_receipts = t;
    Ok(())
}
