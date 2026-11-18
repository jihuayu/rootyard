//! Fenced physical delete executor, staging cleanup & crash-restart reconciliation (#122).

use std::time::Instant;

use uuid::Uuid;

use super::{
    SafeGcError,
    domain::{
        ActiveDeleteFence, DeleteExecutionReport, ExternalFenceCheck, ProviderDeleteOutcome, RemotePresence,
        SafeGcDeleteBackend, StagingCleanupReport,
    },
    model::{GlobalHoldEntry, GlobalHoldState, LiveRefRoot},
    proof::DeletionProof,
    store::{DurableSafeGcAuthority, PendingDeleteBatch},
};

#[derive(Clone, Debug)]
pub enum PostTicketDriftFault {
    ConcurrentNewRef(LiveRefRoot),
    AttachGlobalHold(GlobalHoldEntry),
    AcquireReaderLease(Vec<Uuid>),
    BumpLeaseEpoch,
    RotateIncarnation,
}

#[derive(Clone, Debug)]
pub enum DeleteFaultHook {
    None,
    RotateIncarnationAfterBarrier,
    ConcurrentNewRefAfterBarrier(LiveRefRoot),
    AttachHoldAfterBarrier(GlobalHoldEntry),
    ReleaseHoldWithoutCursorAdvance(Uuid, u64),
    MutateAfterTicketBeforeProviderDelete(PostTicketDriftFault),
    SimulateCrashAfterDeletes(usize),
}

#[derive(Clone, Debug)]
pub struct SafeGcSweepRequest {
    pub batch_id: Uuid,
    pub deleter_incarnation_id: Uuid,
    pub deleter_incarnation_epoch: u64,
    pub deleter_lease_epoch: u64,
    pub proof: DeletionProof,
    pub deadline: Instant,
    pub fault: DeleteFaultHook,
}

pub async fn execute_safe_gc_sweep(
    authority: &DurableSafeGcAuthority,
    backend: &dyn SafeGcDeleteBackend,
    req: SafeGcSweepRequest,
) -> Result<DeleteExecutionReport, SafeGcError> {
    execute_safe_gc_sweep_with_external_fence(authority, backend, req, None).await
}

pub async fn execute_safe_gc_sweep_with_external_fence(
    authority: &DurableSafeGcAuthority,
    backend: &dyn SafeGcDeleteBackend,
    req: SafeGcSweepRequest,
    external_check: Option<ExternalFenceCheck<'_>>,
) -> Result<DeleteExecutionReport, SafeGcError> {
    let snap = authority.snapshot();
    let _arm = snap.gc_mode.require_armed()?;
    let batch = authority.begin_delete_batch(
        req.batch_id,
        req.deleter_incarnation_id,
        req.deleter_incarnation_epoch,
        req.deleter_lease_epoch,
        req.proof,
    )?;
    drive_pending_batch_ctx(
        DriveBatchCtx {
            authority,
            backend,
            deleter: (req.deleter_incarnation_id, req.deleter_incarnation_epoch, req.deleter_lease_epoch),
            external_check,
            reconciled: false,
            deadline: req.deadline,
        },
        batch,
        req.fault,
    )
    .await
}

pub async fn reconcile_pending_delete_after_restart(
    authority: &DurableSafeGcAuthority,
    backend: &dyn SafeGcDeleteBackend,
    deleter_incarnation_id: Uuid,
    deleter_incarnation_epoch: u64,
    deleter_lease_epoch: u64,
    deadline: Instant,
) -> Result<Option<DeleteExecutionReport>, SafeGcError> {
    let snap = authority.snapshot();
    let Some(batch) = snap.pending_delete.clone() else {
        return Ok(None);
    };
    if batch.incarnation_epoch < snap.authority.incarnation_epoch
        || batch.incarnation_id != snap.authority.incarnation_id
    {
        // Stale-incarnation batch after rotation: probe remote absence without issuing new deletes,
        // roll remaining barrier keys back to RetiredPendingProof, and clear pending_delete!
        let mut confirmed_absent = Vec::new();
        for key in &batch.pending_keys {
            if let Some(loc) = find_retired_locator_for_key(&snap, key)
                && matches!(backend.probe_presence(&loc, deadline).await?, RemotePresence::Absent)
            {
                confirmed_absent.push(key.clone());
            }
        }
        let aborted = authority.abort_stale_pending_batch(batch.batch_id, &confirmed_absent)?;
        return Ok(Some(aborted));
    }
    let report = drive_pending_batch_ctx(
        DriveBatchCtx {
            authority,
            backend,
            deleter: (deleter_incarnation_id, deleter_incarnation_epoch, deleter_lease_epoch),
            external_check: None,
            reconciled: true,
            deadline,
        },
        batch,
        DeleteFaultHook::None,
    )
    .await?;
    Ok(Some(report))
}

pub async fn reclaim_abandoned_compaction_staging(
    authority: &DurableSafeGcAuthority,
    backend: &dyn SafeGcDeleteBackend,
    external_check: Option<ExternalFenceCheck<'_>>,
    deadline: Instant,
) -> Result<StagingCleanupReport, SafeGcError> {
    let tickets = authority.mint_staging_cleanup_tickets()?;
    let mut deleted_keys = Vec::new();
    let mut already_absent_keys = Vec::new();
    let mut unknown_outcome_keys = Vec::new();
    for ticket in &tickets {
        let fence = ActiveDeleteFence::new(authority, ticket, external_check);
        match backend.delete_authorized(&fence, ticket, deadline).await? {
            ProviderDeleteOutcome::ConfirmedDeleted => {
                authority.record_staging_key_cleaned(ticket.batch_id(), ticket.physical_key())?;
                deleted_keys.push(ticket.physical_key().to_owned());
            }
            ProviderDeleteOutcome::AlreadyAbsent => {
                authority.record_staging_key_cleaned(ticket.batch_id(), ticket.physical_key())?;
                already_absent_keys.push(ticket.physical_key().to_owned());
            }
            ProviderDeleteOutcome::OutcomeUnknown { .. } => {
                unknown_outcome_keys.push(ticket.physical_key().to_owned());
            }
        }
    }
    Ok(StagingCleanupReport { deleted_keys, already_absent_keys, unknown_outcome_keys })
}

struct DriveBatchCtx<'a> {
    authority: &'a DurableSafeGcAuthority,
    backend: &'a dyn SafeGcDeleteBackend,
    deleter: (Uuid, u64, u64),
    external_check: Option<ExternalFenceCheck<'a>>,
    reconciled: bool,
    deadline: Instant,
}

async fn drive_pending_batch_ctx(
    ctx: DriveBatchCtx<'_>,
    batch: PendingDeleteBatch,
    mut fault: DeleteFaultHook,
) -> Result<DeleteExecutionReport, SafeGcError> {
    let mut skipped = batch.skipped_keys.clone();
    let mut unknown = Vec::new();
    let mut failed = Vec::new();
    let mut retry_keys = Vec::new();
    let mut deleted_this_pass = 0_usize;

    for key in &batch.pending_keys {
        if Instant::now() >= ctx.deadline {
            failed.push(format!("{key}: deadline exceeded"));
            retry_keys.push(key.clone());
            continue;
        }
        apply_pre_ticket_fault(ctx.authority, &mut fault, deleted_this_pass)?;

        if let DeleteFaultHook::SimulateCrashAfterDeletes(limit) = fault
            && deleted_this_pass >= limit
        {
            return Err(SafeGcError::Io("simulated crash mid-delete batch".into()));
        }

        let ticket_opt =
            ctx.authority.mint_fenced_step_ticket(batch.batch_id, ctx.deleter.0, ctx.deleter.1, ctx.deleter.2, key)?;
        let Some(ticket) = ticket_opt else {
            skipped.push(key.clone());
            continue;
        };

        if let DeleteFaultHook::MutateAfterTicketBeforeProviderDelete(_) = fault {
            let taken = std::mem::replace(&mut fault, DeleteFaultHook::None);
            if let DeleteFaultHook::MutateAfterTicketBeforeProviderDelete(post) = taken {
                apply_post_ticket_fault(ctx.authority, post)?;
            }
        }

        let fence = ActiveDeleteFence::new(ctx.authority, &ticket, ctx.external_check);
        match ctx.backend.delete_authorized(&fence, &ticket, ctx.deadline).await {
            Ok(ProviderDeleteOutcome::ConfirmedDeleted) => {
                ctx.authority.record_key_deleted(batch.batch_id, key, false)?;
                deleted_this_pass += 1;
            }
            Ok(ProviderDeleteOutcome::AlreadyAbsent) => {
                ctx.authority.record_key_deleted(batch.batch_id, key, true)?;
                deleted_this_pass += 1;
            }
            Ok(ProviderDeleteOutcome::OutcomeUnknown { reason }) => {
                ctx.authority.record_key_outcome_unknown(batch.batch_id, key, &reason)?;
                unknown.push(format!("{key}: {reason}"));
                retry_keys.push(key.clone());
            }
            Err(err) => {
                // Fence loss / post-ticket drift / disabled backend aborts fail-closed immediately!
                if matches!(
                    err,
                    SafeGcError::StaleIncarnation(_)
                        | SafeGcError::StaleDeleterFenced(_)
                        | SafeGcError::ConcurrentRetentionRace(_)
                        | SafeGcError::MembershipOrRootDrift(_)
                        | SafeGcError::ProtectionOverlap(_)
                        | SafeGcError::ReaderQuiescenceUnverified(_)
                        | SafeGcError::DestructiveGcDisabledByDefault
                        | SafeGcError::BlobDeleteDisabled
                ) {
                    return Err(err);
                }
                failed.push(format!("{key}: {err}"));
                retry_keys.push(key.clone());
            }
        }
    }

    let report = ctx.authority.finalize_delete_batch(
        batch.batch_id,
        skipped,
        unknown.clone(),
        failed.clone(),
        retry_keys,
        ctx.reconciled,
    )?;
    if !unknown.is_empty() {
        return Err(SafeGcError::DeleteOutcomeUnknown(unknown.join("; ")));
    }
    if !failed.is_empty() {
        return Err(SafeGcError::PartialDeleteFailure(failed.join("; ")));
    }
    Ok(report)
}

fn find_retired_locator_for_key(
    snap: &super::store::SafeGcRepoSnapshot,
    physical_key: &str,
) -> Option<super::domain::BlobLocatorRecord> {
    snap.retired_packs.iter().find_map(|p| {
        if p.pack_key.object_path == physical_key {
            Some(p.pack_locator.clone())
        } else if p.idx_key.object_path == physical_key {
            Some(p.idx_locator.clone())
        } else {
            None
        }
    })
}

fn apply_pre_ticket_fault(
    authority: &DurableSafeGcAuthority,
    fault: &mut DeleteFaultHook,
    deleted_so_far: usize,
) -> Result<(), SafeGcError> {
    if matches!(
        fault,
        DeleteFaultHook::None
            | DeleteFaultHook::SimulateCrashAfterDeletes(_)
            | DeleteFaultHook::MutateAfterTicketBeforeProviderDelete(_)
    ) || deleted_so_far > 0
    {
        return Ok(());
    }
    match std::mem::replace(fault, DeleteFaultHook::None) {
        DeleteFaultHook::RotateIncarnationAfterBarrier => {
            let _ = authority.rotate_incarnation()?;
        }
        DeleteFaultHook::ConcurrentNewRefAfterBarrier(r) => authority.register_concurrent_ref(r)?,
        DeleteFaultHook::AttachHoldAfterBarrier(h) => authority.upsert_global_hold(h)?,
        DeleteFaultHook::ReleaseHoldWithoutCursorAdvance(hold_id, future_seq) => {
            let snap = authority.snapshot();
            if let Some(mut released) = snap.global_holds.into_iter().find(|x| x.hold_id == hold_id) {
                released.state = GlobalHoldState::Released { released_at_seq: future_seq };
                authority.upsert_global_hold(released)?;
            } else {
                return Err(SafeGcError::InvalidInput("fault hold_id not found".into()));
            }
        }
        DeleteFaultHook::None
        | DeleteFaultHook::SimulateCrashAfterDeletes(_)
        | DeleteFaultHook::MutateAfterTicketBeforeProviderDelete(_) => {}
    }
    Ok(())
}

fn apply_post_ticket_fault(authority: &DurableSafeGcAuthority, fault: PostTicketDriftFault) -> Result<(), SafeGcError> {
    match fault {
        PostTicketDriftFault::ConcurrentNewRef(r) => authority.register_concurrent_ref(r),
        PostTicketDriftFault::AttachGlobalHold(h) => authority.upsert_global_hold(h),
        PostTicketDriftFault::AcquireReaderLease(packs) => {
            authority.acquire_reader_lease("post-ticket-reader", packs).map(|_| ())
        }
        PostTicketDriftFault::BumpLeaseEpoch => authority.bump_lease_epoch().map(|_| ()),
        PostTicketDriftFault::RotateIncarnation => authority.rotate_incarnation().map(|_| ()),
    }
}
