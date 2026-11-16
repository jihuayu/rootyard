//! Recoverable reserve-before-publish bridge between global PostgreSQL artifact
//! holds (`artifact_holds*`, Migration 141) and deterministic Ref-CAS consensus
//! authorities (`RefCasStateMachine`, #151).

use super::bridge_contract::ObservedRealm;
pub use super::bridge_contract::{BridgeBinding, GlobalHoldReservation, ReservedGlobalHold, RetentionBridgeError};
use super::contract::{ArtifactHoldError, HoldScope};
use super::pg::{AcquireOutcome, PgArtifactHoldStore};
use super::receipt::AcquireLookup;
use super::request::AcquireArtifactHoldsRequest;
use crate::blob_store::opendal::BlobStore;
use crate::ref_store::contract::{
    IssuerLane, MetadataPinPurpose, OperationLookup, OperationState, RefStoreError, RequestDigest,
};
use crate::ref_store::core::contract::VersionCheck;
use crate::ref_store::core::retention_root::{RootPurpose, RootSelectorKind};
use crate::ref_store::core::state_machine::{
    AppliedLogId, ApplyResponse, BeginOperationCommand, CreateSnapshotPinCommand, QuotaCounters, RefCasCommand,
    RefCasStateMachine, RegisterRootCommand, ReleaseRootCommand, RetireHoldBatchCommand, ScopeLifecycle, SmHoldState,
};
use crate::ref_store::pg::{self as ref_pg, db_error};
use crate::ref_store::tx::begin_bounded;
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use tokio::time::Instant;
use tokio_postgres::Client;
use uuid::Uuid;

/// Bounded inputs for deterministic snapshot-pin + retention-root publication.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeRootRegistrationPlan {
    pub pin_request_id: Uuid,
    pub snapshot_id: Uuid,
    pub pin_id: Uuid,
    pub pin_purpose: MetadataPinPurpose,
    pub lease_ticks: u64,
    pub pin_logical_tick: u64,
    pub pack_digests: Vec<String>,
    pub pin_request_digest: String,
    pub root_request_id: Uuid,
    pub root_id: Uuid,
    pub root_purpose: String,
    pub business_intent_digest: String,
    pub selector_kind: String,
    pub selector_digest: String,
    pub refs_digest: String,
    pub pack_set_digest: String,
    pub register_digest: String,
    pub root_request_digest: String,
}

impl BridgeRootRegistrationPlan {
    pub fn validate(&self) -> Result<(), RetentionBridgeError> {
        let ids = [self.pin_request_id, self.snapshot_id, self.pin_id, self.root_request_id, self.root_id];
        if ids.iter().any(Uuid::is_nil) {
            return Err(RetentionBridgeError::InvalidBinding("pin/root ids must be non-nil".into()));
        }
        RootPurpose::parse(&self.root_purpose).map_err(|e| RetentionBridgeError::InvalidBinding(e.to_string()))?;
        RootSelectorKind::parse(&self.selector_kind)
            .map_err(|e| RetentionBridgeError::InvalidBinding(e.to_string()))?;
        for hex in [
            &self.pin_request_digest,
            &self.business_intent_digest,
            &self.selector_digest,
            &self.refs_digest,
            &self.pack_set_digest,
            &self.register_digest,
            &self.root_request_digest,
        ] {
            RequestDigest::from_str(hex)?;
        }
        Ok(())
    }
}

/// Phase 1 (PostgreSQL first): reserve global PG artifact holds before creating
/// any Ref-CAS pin/root or pack references.
pub async fn reserve_global_hold_first(
    client: &mut Client,
    blob: &BlobStore,
    request: &AcquireArtifactHoldsRequest,
    binding: &BridgeBinding,
    deadline: Instant,
) -> Result<ReservedGlobalHold, RetentionBridgeError> {
    binding.validate()?;
    if blob.backend_identity().as_hex() != binding.backend_identity {
        return Err(RetentionBridgeError::BackendMismatch);
    }
    let scope = request.scope();
    binding.check_realm(ObservedRealm {
        tenant_id: scope.tenant_id(),
        repository_id: scope.repository_id(),
        owner_id: scope.owner_id(),
        history_incarnation: scope.history_incarnation(),
        authority_epoch: scope.authority_epoch(),
        group_epoch: scope.group_epoch(),
        backend_identity: request.backend_identity().as_hex(),
    })?;
    if request.authority_id() != binding.authority_id {
        return Err(RetentionBridgeError::RealmMismatch("authority_id"));
    }
    if request.authority_generation() != binding.authority_generation {
        return Err(RetentionBridgeError::GenerationConflict {
            field: "authority_generation",
            expected: binding.authority_generation,
            actual: request.authority_generation(),
        });
    }
    let op = request.operation();
    if op.operation_id() != binding.operation_id
        || op.issuer_id() != binding.issuer_id
        || op.lane().as_str() != binding.lane
        || op.sequence() != binding.sequence
        || op.digest().as_hex() != binding.operation_digest
    {
        return Err(RetentionBridgeError::RealmMismatch("operation_identity"));
    }
    match PgArtifactHoldStore.acquire(client, blob, request, deadline).await? {
        AcquireOutcome::Granted { ack, grant } => {
            binding.matches_acquire_ack(&ack)?;
            let reservation = GlobalHoldReservation {
                binding: binding.clone(),
                ack,
                replayed: false,
                recovered_from_unknown_commit: false,
            };
            Ok(ReservedGlobalHold { reservation, grant: Some(grant) })
        }
        AcquireOutcome::Replayed { ack } => {
            binding.matches_acquire_ack(&ack)?;
            let reservation = GlobalHoldReservation {
                binding: binding.clone(),
                ack,
                replayed: true,
                recovered_from_unknown_commit: false,
            };
            Ok(ReservedGlobalHold { reservation, grant: None })
        }
    }
}

/// Recover a previously committed global hold receipt by known `acquire_request_id`.
pub async fn recover_global_hold_by_request(
    client: &mut Client,
    scope: &HoldScope,
    binding: &BridgeBinding,
    acquire_request_id: Uuid,
    deadline: Instant,
) -> Result<GlobalHoldReservation, RetentionBridgeError> {
    binding.validate()?;
    match PgArtifactHoldStore.acquire_receipt(client, scope, acquire_request_id, deadline).await? {
        AcquireLookup::Found(ack) => {
            binding.matches_acquire_ack(&ack)?;
            Ok(GlobalHoldReservation {
                binding: binding.clone(),
                ack,
                replayed: true,
                recovered_from_unknown_commit: true,
            })
        }
        AcquireLookup::Unknown => Err(RetentionBridgeError::MissingDurableHold { request_id: acquire_request_id }),
    }
}

/// Recover a committed global hold receipt strictly by original `OperationIdentity`
/// after failure or lost `COMMIT` ACK without minting grants or charging quota.
pub async fn recover_global_hold_by_operation(
    client: &mut Client,
    scope: &HoldScope,
    binding: &BridgeBinding,
    deadline: Instant,
) -> Result<GlobalHoldReservation, RetentionBridgeError> {
    binding.validate()?;
    let tx = begin_bounded(client, deadline).await?;
    let query_res: Result<Vec<Uuid>, RetentionBridgeError> = async {
        ref_pg::bound(&tx, deadline).await?;
        let rows = tx
            .query(
                "SELECT request_id FROM artifact_hold_requests
                 WHERE repository_id=$1 AND operation_id=$2 AND operation_digest=$3
                 ORDER BY created_at ASC, request_id ASC LIMIT 2",
                &[&binding.repository_id, &binding.operation_id, &binding.operation_digest],
            )
            .await
            .map_err(db_error)?;
        Ok(rows.into_iter().map(|r| r.get::<_, Uuid>(0)).collect())
    }
    .await;
    let _ = tx.rollback().await;
    match query_res?.as_slice() {
        [] => Err(RetentionBridgeError::MissingDurableHold { request_id: Uuid::nil() }),
        [request_id] => recover_global_hold_by_request(client, scope, binding, *request_id, deadline).await,
        _ => Err(ArtifactHoldError::LedgerIntegrity("multiple acquire requests recorded for operation").into()),
    }
}

/// Pure deterministic gate, realm, anti-ABA generation, and cancel-cutoff
/// check against `RefCasStateMachine` (zero PG or Blob I/O).
pub fn verify_state_machine_gate_for_binding(
    sm: &RefCasStateMachine,
    binding: &BridgeBinding,
) -> Result<String, RetentionBridgeError> {
    binding.validate()?;
    let (lifecycle, _floor) = sm
        .read_scope_lifecycle(binding.repository_id)
        .ok_or(RetentionBridgeError::Store(RefStoreError::RepositoryNotFound))?;
    if lifecycle != ScopeLifecycle::Open {
        return Err(RetentionBridgeError::ScopeClosingOrClosed { repository_id: binding.repository_id, lifecycle });
    }
    let version = match sm.check_version(binding.repository_id, binding.tenant_id, None)? {
        VersionCheck::Changed(v) | VersionCheck::Unchanged(v) => v,
        VersionCheck::Unknown => return Err(RetentionBridgeError::Store(RefStoreError::RepositoryNotFound)),
    };
    if version.history_incarnation() != binding.history_incarnation {
        return Err(RetentionBridgeError::RealmMismatch("history_incarnation"));
    }
    if version.authority_epoch() != binding.authority_epoch {
        return Err(RetentionBridgeError::GenerationConflict {
            field: "authority_epoch",
            expected: version.authority_epoch(),
            actual: binding.authority_epoch,
        });
    }
    if version.group_epoch() != binding.group_epoch {
        return Err(RetentionBridgeError::GenerationConflict {
            field: "group_epoch",
            expected: version.group_epoch(),
            actual: binding.group_epoch,
        });
    }
    let lane = IssuerLane::new(&binding.lane)?;
    if sm.has_cancel_tombstone(binding.repository_id, binding.operation_id)
        || binding.sequence <= sm.cancel_cutoff(binding.repository_id, binding.issuer_id, &lane)
    {
        return Err(RetentionBridgeError::CancelledBeforeRegister { operation_id: binding.operation_id });
    }
    if let OperationLookup::Known(op) = sm.query_operation(binding.repository_id, binding.operation_id)?
        && op.state() == OperationState::Cancelled
    {
        return Err(RetentionBridgeError::CancelledBeforeRegister { operation_id: binding.operation_id });
    }
    Ok(version.digest().as_hex())
}

/// Phase 2 (pure Ref-CAS): install a verified `GlobalHoldReservation` into
/// `RefCasStateMachine` with zero PG/Blob I/O; idempotent on replay.
pub fn apply_reserved_hold_to_sm(
    sm: &mut RefCasStateMachine,
    log_id: AppliedLogId,
    reservation: &GlobalHoldReservation,
    binding: &BridgeBinding,
) -> Result<ApplyResponse, RetentionBridgeError> {
    reservation.matches_binding(binding)?;
    let cmd = binding.to_hold_batch_command(&reservation.ack)?;
    let applied = cmd
        .artifacts
        .first()
        .is_some_and(|spec| sm.read_hold(spec.hold_id).is_some_and(|e| e.batch_request_id == cmd.request_id));
    if !applied {
        verify_state_machine_gate_for_binding(sm, binding)?;
    }
    Ok(sm.apply(log_id, RefCasCommand::AcquireHoldBatch(cmd))?)
}

/// Record `BeginOperation` via a bridge binding (`Cancel-before-Register` safe).
pub fn begin_operation_for_binding(
    sm: &mut RefCasStateMachine,
    log_id: AppliedLogId,
    binding: &BridgeBinding,
    logical_tick: u64,
) -> Result<ApplyResponse, RetentionBridgeError> {
    binding.validate()?;
    let cmd = BeginOperationCommand { identity: binding.to_wire_operation_identity(), logical_tick };
    Ok(sm.apply(log_id, RefCasCommand::BeginOperation(cmd))?)
}

/// Phase 3 (reserve-before-publish): register Ref-CAS pin + retention root ONLY
/// after global PG holds are installed in `RefCasStateMachine`.
pub fn publish_pin_and_root_after_hold(
    sm: &mut RefCasStateMachine,
    pin_log_id: AppliedLogId,
    root_log_id: AppliedLogId,
    reservation: &GlobalHoldReservation,
    binding: &BridgeBinding,
    plan: &BridgeRootRegistrationPlan,
) -> Result<(ApplyResponse, ApplyResponse), RetentionBridgeError> {
    plan.validate()?;
    reservation.matches_binding(binding)?;
    let hold_ids = reservation.hold_ids();
    if hold_ids.is_empty() {
        return Err(RetentionBridgeError::MissingDurableHold { request_id: reservation.ack.request_id });
    }
    for hold_id in &hold_ids {
        let Some(entry) = sm.read_hold(*hold_id) else {
            return Err(RetentionBridgeError::MissingDurableHold { request_id: reservation.ack.request_id });
        };
        if entry.repository_id != binding.repository_id
            || entry.tenant_id != binding.tenant_id
            || entry.batch_request_id != reservation.ack.request_id
            || entry.state == SmHoldState::Retired
        {
            return Err(RetentionBridgeError::MissingDurableHold { request_id: reservation.ack.request_id });
        }
    }
    let gate_digest = verify_state_machine_gate_for_binding(sm, binding)?;
    let pin_resp = sm.apply(
        pin_log_id,
        RefCasCommand::CreateSnapshotPin(CreateSnapshotPinCommand {
            request_id: plan.pin_request_id,
            repository_id: binding.repository_id,
            tenant_id: binding.tenant_id,
            owner_id: binding.owner_id,
            purpose: plan.pin_purpose,
            snapshot_id: plan.snapshot_id,
            pin_id: plan.pin_id,
            object_format: reservation.ack.object_format,
            history_incarnation: binding.history_incarnation,
            authority_epoch: binding.authority_epoch,
            group_epoch: binding.group_epoch,
            expected_gate_digest: gate_digest,
            lease_ticks: plan.lease_ticks,
            logical_tick: plan.pin_logical_tick,
            pack_digests: plan.pack_digests.clone(),
            request_digest: plan.pin_request_digest.clone(),
        }),
    )?;
    let ApplyResponse::SnapshotPinCreated { generation, .. } = pin_resp else {
        return Err(RetentionBridgeError::InvalidBinding("unexpected pin response variant".into()));
    };
    let root_resp = sm.apply(
        root_log_id,
        RefCasCommand::RegisterRoot(RegisterRootCommand {
            request_id: plan.root_request_id,
            root_id: plan.root_id,
            operation_id: binding.operation_id,
            repository_id: binding.repository_id,
            tenant_id: binding.tenant_id,
            owner_id: binding.owner_id,
            purpose: plan.root_purpose.clone(),
            business_intent_digest: plan.business_intent_digest.clone(),
            object_format: reservation.ack.object_format,
            history_incarnation: binding.history_incarnation,
            authority_epoch: binding.authority_epoch,
            group_epoch: binding.group_epoch,
            source_snapshot_id: plan.snapshot_id,
            source_pin_id: plan.pin_id,
            source_pin_generation: generation,
            selector_kind: plan.selector_kind.clone(),
            selector_digest: plan.selector_digest.clone(),
            refs_digest: plan.refs_digest.clone(),
            pack_set_digest: plan.pack_set_digest.clone(),
            bound_hold_ids: hold_ids,
            register_digest: plan.register_digest.clone(),
            request_digest: plan.root_request_digest.clone(),
        }),
    )?;
    Ok((pin_resp, root_resp))
}

/// Replay a repository root release (or release-before-register tombstone).
pub fn apply_release_root_idempotent(
    sm: &mut RefCasStateMachine,
    log_id: AppliedLogId,
    cmd: ReleaseRootCommand,
) -> Result<ApplyResponse, RetentionBridgeError> {
    Ok(sm.apply(log_id, RefCasCommand::ReleaseRoot(cmd))?)
}

/// Apply `RetireHoldBatch` idempotently on `RefCasStateMachine`.
pub fn apply_retire_hold_batch_idempotent(
    sm: &mut RefCasStateMachine,
    log_id: AppliedLogId,
    cmd: RetireHoldBatchCommand,
) -> Result<ApplyResponse, RetentionBridgeError> {
    Ok(sm.apply(log_id, RefCasCommand::RetireHoldBatch(cmd))?)
}

/// Read current non-refundable quota counters from `RefCasStateMachine` snapshot.
pub fn read_sm_quota_counters(
    sm: &RefCasStateMachine,
    repository_id: Uuid,
    tenant_id: Uuid,
) -> Result<(QuotaCounters, QuotaCounters), RetentionBridgeError> {
    let snap = sm.snapshot()?;
    let repo_q = snap
        .body
        .repo_quotas
        .iter()
        .find(|q| q.scope_id == repository_id)
        .map_or_else(QuotaCounters::default, |q| q.counters);
    let tenant_q = snap
        .body
        .tenant_quotas
        .iter()
        .find(|q| q.scope_id == tenant_id)
        .map_or_else(QuotaCounters::default, |q| q.counters);
    Ok((repo_q, tenant_q))
}
