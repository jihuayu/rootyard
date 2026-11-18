//! PostgreSQL `PackCommitPlan` builder, A3 durable hold upload, and error helpers (#183).

use std::path::Path;
use std::time::Instant as StdInstant;

use deadpool_postgres::Pool;
use sha2::{Digest, Sha256};
use tokio::time::{Instant, timeout_at};
use uuid::Uuid;

use crate::blob_store::opendal::BlobStore;
use crate::blob_store::protected::{ProtectedUploadError, ProtectedUploader, UploadSource};
use crate::db::Identity;
use crate::ref_store::artifact_hold::{
    AcquireArtifactHoldsRequest, AcquireOutcome, ArtifactHoldError, ArtifactHoldPurpose, ArtifactSpec, HoldScope,
    PgArtifactHoldStore,
};
use crate::ref_store::core::pack_commit::{
    AuthorizedCommitError, ContentDigest, PackArtifactRole, PackCommitBaseline, PackCommitExpectation, PackCommitPlan,
    PackCommitScope, PackMembershipEntry, PackRegistrationRequest, PgPackCommit, PlannedArtifact, PlannedPack,
    ensure_pack_terminal_budget,
};
use crate::ref_store::tx::{begin_bounded, commit_bounded};
use crate::ref_store::{
    CommitMode, GitOid, HeadUpdate, IssuerLane, OperationIdentity, PgRefStore, RefName, RefPrecondition, RefTarget,
    RefUpdate, RequestDigest,
};

use super::quarantine::OperationHoldGuard;
use super::receipt::CausalPushProofReceipt;
use super::reclaim::{QuarantineReclaimLedger, StagingUploadIntent, UploadReclaimState};
use super::types::{AuthorizedSnapshotState, OperationTicket, PushCausalError};

const PG_PUSH_HOLD_NAMESPACE: &str = "push-causal-pack";

pub(super) struct PendingPlanArgs<'a> {
    pub(super) pool: &'a Pool,
    pub(super) actor: &'a Identity,
    pub(super) owner_id: Uuid,
    pub(super) snapshot: &'a AuthorizedSnapshotState,
    pub(super) ticket: &'a OperationTicket,
    pub(super) receipt: &'a CausalPushProofReceipt,
    pub(super) mode: CommitMode,
    pub(super) pack_sha: &'a str,
    pub(super) pack_len: u64,
    pub(super) idx_sha: &'a str,
    pub(super) idx_len: u64,
    pub(super) baseline: &'a PackCommitBaseline,
    pub(super) producer_digest: RequestDigest,
    pub(super) deadline: Instant,
}

pub(super) struct HeldUploadArgs<'a> {
    pub(super) pool: &'a Pool,
    pub(super) store: &'a BlobStore,
    pub(super) plan: &'a PackCommitPlan,
    pub(super) pack_id: Uuid,
    pub(super) pack_path: &'a Path,
    pub(super) pack_sha: &'a str,
    pub(super) pack_len: u64,
    pub(super) idx_path: &'a Path,
    pub(super) idx_sha: &'a str,
    pub(super) idx_len: u64,
    pub(super) reclaim_ledger: Option<&'a QuarantineReclaimLedger>,
    pub(super) hold_guard: &'a mut OperationHoldGuard,
    pub(super) deadline: Instant,
}

pub(super) async fn begin_pending_pack_plan(args: PendingPlanArgs<'_>) -> Result<PackCommitPlan, PushCausalError> {
    let lane = IssuerLane::new(args.ticket.lane.as_str())?;
    let mut client = pooled_client(args.pool, args.deadline).await?;
    let tx = begin_bounded(&mut client, args.deadline).await?;
    let staged = timeout_at(args.deadline, async {
        tx.execute("SET LOCAL synchronous_commit = 'on'", &[]).await.map_err(|e| PushCausalError::Io(e.to_string()))?;
        let seq = PgRefStore
            .reserve_sequence(
                &tx,
                args.snapshot.repository_id,
                args.actor.id,
                args.ticket.operation_id,
                &lane,
                args.deadline,
            )
            .await?;
        let identity = OperationIdentity::new(
            args.snapshot.repository_id,
            args.actor.id,
            lane,
            seq.sequence(),
            args.ticket.operation_id,
            args.producer_digest,
        )?;
        let plan = build_pack_plan(&args, identity)?;
        let _token = PgPackCommit
            .begin_serving_pending_in_tx(&tx, &plan, args.producer_digest, args.deadline)
            .await
            .map_err(|e| PushCausalError::StateMachine(format!("begin_serving_pending failed: {e}")))?;
        Ok::<_, PushCausalError>(plan)
    })
    .await
    .map_err(|_| PushCausalError::DeadlineExceeded)?;
    match staged {
        Ok(plan) => {
            commit_bounded(tx, args.deadline, args.snapshot.repository_id, Some(args.ticket.operation_id)).await?;
            Ok(plan)
        }
        Err(err) => {
            let _ = timeout_at(args.deadline, tx.rollback()).await;
            Err(err)
        }
    }
}

fn build_pack_plan(args: &PendingPlanArgs<'_>, identity: OperationIdentity) -> Result<PackCommitPlan, PushCausalError> {
    let gate = args.baseline.gate();
    let format = gate.object_format();
    let mut refs = Vec::with_capacity(args.receipt.accepted_updates.len());
    for u in &args.receipt.accepted_updates {
        let name = RefName::new(u.ref_name.clone()).map_err(|e| PushCausalError::MalformedProtocol(e.to_string()))?;
        let pre = match &u.old_oid {
            Some(hex) => RefPrecondition::Present(GitOid::parse(format, hex)?),
            None => RefPrecondition::Absent,
        };
        let tgt = match &u.new_oid {
            Some(hex) => RefTarget::Oid(GitOid::parse(format, hex)?),
            None => RefTarget::Delete,
        };
        refs.push(RefUpdate::new(name, pre, tgt));
    }
    let head_exists = args.baseline.refs().iter().any(|r| r.name() == gate.head_ref().as_str());
    let head = if head_exists {
        HeadUpdate::Keep
    } else if let Some(b) =
        args.receipt.accepted_updates.iter().find(|u| u.ref_name.starts_with("refs/heads/") && u.new_oid.is_some())
    {
        HeadUpdate::retarget(b.ref_name.clone())?
    } else {
        HeadUpdate::Keep
    };
    let old_memberships = args
        .baseline
        .old_packs()
        .iter()
        .map(PackMembershipEntry::from_pack)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| PushCausalError::StateMachine(e.to_string()))?;
    let pack_id = derived_id("pg-pack-id", identity.operation_id(), args.pack_sha.as_bytes());
    let reg_id = derived_id("pg-reg-id", identity.operation_id(), args.pack_sha.as_bytes());
    let p_dig =
        ContentDigest::parse(args.pack_sha.to_owned()).map_err(|e| PushCausalError::CorruptPack(e.to_string()))?;
    let i_dig =
        ContentDigest::parse(args.idx_sha.to_owned()).map_err(|e| PushCausalError::CorruptPack(e.to_string()))?;
    let planned = vec![
        PlannedPack::new(
            pack_id,
            reg_id,
            PlannedArtifact::new(PackArtifactRole::Pack, p_dig, args.pack_len)
                .map_err(|e| PushCausalError::CorruptPack(e.to_string()))?,
            PlannedArtifact::new(PackArtifactRole::Idx, i_dig, args.idx_len)
                .map_err(|e| PushCausalError::CorruptPack(e.to_string()))?,
        )
        .map_err(|e| PushCausalError::CorruptPack(e.to_string()))?,
    ];
    let scope = PackCommitScope::new(
        args.snapshot.repository_id,
        args.snapshot.tenant_id,
        args.owner_id,
        format,
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )
    .map_err(|e| PushCausalError::StateMachine(e.to_string()))?;
    let exp = PackCommitExpectation::new(gate.revision(), *gate.digest(), args.baseline.mode())
        .map_err(|e| PushCausalError::StateMachine(e.to_string()))?;
    let plan = PackCommitPlan::new_with_mode(
        scope,
        identity,
        exp,
        head,
        refs,
        args.baseline.membership_digest(),
        old_memberships,
        planned,
        args.mode,
    )
    .map_err(|e| PushCausalError::StateMachine(e.to_string()))?;
    ensure_pack_terminal_budget(&plan).map_err(|_| PushCausalError::LimitExceeded("pack terminal budget exceeded"))?;
    Ok(plan)
}

pub(super) async fn acquire_and_upload_held_pair(args: HeldUploadArgs<'_>) -> Result<(), PushCausalError> {
    let op_id = args.plan.identity().operation_id();
    let scope = HoldScope::new(
        args.plan.repository_id(),
        args.plan.tenant_id(),
        args.plan.owner_id(),
        ArtifactHoldPurpose::RefPublication,
        args.plan.object_format(),
        args.plan.history_incarnation(),
        args.plan.authority_epoch(),
        args.plan.group_epoch(),
    )
    .map_err(|e| PushCausalError::StateMachine(format!("hold scope invalid: {e}")))?;
    let req_id = derived_id("pg-hold-req", op_id, args.pack_sha.as_bytes());
    let auth_id = derived_id("pg-hold-auth", op_id, b"");
    let specs = vec![
        ArtifactSpec::new(PG_PUSH_HOLD_NAMESPACE, args.pack_sha.to_owned(), args.pack_len)
            .map_err(|e| PushCausalError::StateMachine(e.to_string()))?,
        ArtifactSpec::new(PG_PUSH_HOLD_NAMESPACE, args.idx_sha.to_owned(), args.idx_len)
            .map_err(|e| PushCausalError::StateMachine(e.to_string()))?,
    ];
    let hold_req = AcquireArtifactHoldsRequest::new(
        scope,
        args.plan.identity().clone(),
        req_id,
        args.store.backend_identity().clone(),
        auth_id,
        1,
        *args.plan.expected().gate_digest(),
        specs,
    )
    .map_err(|e| PushCausalError::StateMachine(e.to_string()))?;

    let (ack, grant) = {
        let mut client = pooled_client(args.pool, args.deadline).await?;
        match PgArtifactHoldStore.acquire(&mut client, args.store, &hold_req, args.deadline).await {
            Ok(AcquireOutcome::Granted { ack, grant }) => (ack, grant),
            Ok(AcquireOutcome::Replayed { .. }) => {
                return Err(PushCausalError::StateMachine("artifact hold already replayed for operation".into()));
            }
            Err(ArtifactHoldError::AcquireUnknown { .. }) => {
                args.hold_guard.mark_unknown_outcome();
                return Err(PushCausalError::CommitUnknown {
                    operation_id: op_id,
                    detail: "artifact hold acquire outcome unknown".into(),
                });
            }
            Err(e) => return Err(PushCausalError::StateMachine(format!("artifact hold acquire refused: {e}"))),
        }
    };
    let mut locators = Vec::with_capacity(ack.artifacts.len());
    let mut hold_ids = Vec::with_capacity(ack.artifacts.len());
    for h in &ack.artifacts {
        hold_ids.push(h.hold_id);
        if let Ok(loc) = h.artifact.locator() {
            locators.push(loc);
        }
    }
    let locator_paths: Vec<String> = locators.iter().map(|l| l.path()).collect();
    *args.hold_guard = OperationHoldGuard::acquire(op_id, hold_ids, locators);
    if let Some(ledger) = args.reclaim_ledger {
        ledger.record_inflight(&StagingUploadIntent {
            operation_id: op_id,
            tenant_id: args.plan.tenant_id(),
            repository_id: args.plan.repository_id(),
            generation: args.plan.authority_epoch().max(1),
            backend_identity: args.store.backend_identity().as_hex(),
            pack_sha256: args.pack_sha,
            pack_bytes: args.pack_len,
            idx_sha256: args.idx_sha,
            idx_bytes: args.idx_len,
        })?;
    }

    let std_deadline = to_std_deadline(args.deadline)?;
    let sources = [UploadSource::new(args.pack_path.to_path_buf()), UploadSource::new(args.idx_path.to_path_buf())];
    let publication = match ProtectedUploader::new(args.store.clone())
        .consume_and_upload(args.pool, grant, &sources, std_deadline)
        .await
    {
        Ok(pub_out) => pub_out,
        Err(err) => {
            let is_unknown = matches!(err, ProtectedUploadError::Consume(ArtifactHoldError::ConsumeUnknown { .. }));
            let state = if is_unknown { UploadReclaimState::OutcomeUnknown } else { UploadReclaimState::PartialFailed };
            if is_unknown {
                args.hold_guard.mark_unknown_outcome();
            }
            if let Some(ledger) = args.reclaim_ledger {
                let _ = ledger.transition(op_id, state, locator_paths, 0, format!("protected upload failed: {err}"));
            }
            return Err(if is_unknown {
                PushCausalError::CommitUnknown { operation_id: op_id, detail: format!("{err}") }
            } else {
                PushCausalError::Io(format!("protected upload refused: {err}"))
            });
        }
    };
    let mut client = pooled_client(args.pool, args.deadline).await?;
    let reg = PackRegistrationRequest::new(args.plan, args.pack_id, &publication)
        .map_err(|e| PushCausalError::StateMachine(e.to_string()))?;
    PgPackCommit
        .register_publication(&mut client, reg, args.deadline)
        .await
        .map_err(|e| PushCausalError::StateMachine(format!("register_publication failed: {e}")))?;
    Ok(())
}

pub(super) fn handle_authorized_commit_err(
    err: &AuthorizedCommitError,
    op_id: Uuid,
    hold_guard: &mut OperationHoldGuard,
    reclaim_ledger: Option<&QuarantineReclaimLedger>,
) -> Result<(), PushCausalError> {
    if err.is_unknown() {
        hold_guard.mark_unknown_outcome();
        if let Some(ledger) = reclaim_ledger
            && ledger.load(op_id)?.is_some()
        {
            ledger.transition(op_id, UploadReclaimState::OutcomeUnknown, Vec::new(), 0, err.code())?;
        }
    } else {
        let _ = hold_guard.release_on_proven_abort();
        if let Some(ledger) = reclaim_ledger
            && ledger.load(op_id)?.is_some()
        {
            ledger.transition(op_id, UploadReclaimState::AbortUnpromoted, Vec::new(), 0, err.code())?;
        }
    }
    Ok(())
}

pub(super) fn map_authorized_err(err: AuthorizedCommitError, op_id: Uuid) -> PushCausalError {
    if err.is_unknown() {
        return PushCausalError::CommitUnknown { operation_id: op_id, detail: err.code().to_owned() };
    }
    match err {
        AuthorizedCommitError::Timeout => PushCausalError::DeadlineExceeded,
        AuthorizedCommitError::Denied(reason) => PushCausalError::AuthorizationDenied(reason),
        other => PushCausalError::StateMachine(format!("authorized PG commit refused: {}", other.code())),
    }
}

pub(super) async fn pooled_client(
    pool: &Pool,
    deadline: Instant,
) -> Result<deadpool_postgres::Client, PushCausalError> {
    timeout_at(deadline, pool.get())
        .await
        .map_err(|_| PushCausalError::DeadlineExceeded)?
        .map_err(|e| PushCausalError::Io(format!("PG pool checkout failed: {e}")))
}

fn to_std_deadline(deadline: Instant) -> Result<StdInstant, PushCausalError> {
    let now = Instant::now();
    if deadline <= now {
        return Err(PushCausalError::DeadlineExceeded);
    }
    Ok(StdInstant::now() + (deadline - now))
}

pub(super) fn derived_id(domain: &str, op: Uuid, extra: &[u8]) -> Uuid {
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update(b"\0");
    h.update(op.as_bytes());
    h.update(extra);
    let d = h.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&d[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}
