//! Fenced physical delete executor, staging cleanup & crash-restart reconciliation (#122).

use std::time::{Duration, Instant};

use uuid::Uuid;

use super::{
    SafeGcError,
    domain::{
        ActiveDeleteFence, DeleteExecutionReport, ExternalFenceCheck, ProviderDeleteOutcome, RemotePresence,
        SafeGcDeleteBackend, StagingCleanupReport,
    },
    model::{AuthorityLane, GlobalHoldEntry, GlobalHoldState, LiveRefRoot},
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
    BumpLeaseEpochAfterProviderDeleteBeforeCommit,
    SimulateCrashAfterDeletes(usize),
    /// Publish a readiness marker after N confirmed deletes, then block until an
    /// external watchdog `SIGKILL`s this process (hard process-death recovery test).
    PauseAfterDeletesForExternalKill {
        after_deletes: usize,
        ready_marker_path: std::path::PathBuf,
    },
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

fn require_lane_external_fence(
    lane: &AuthorityLane,
    external_check: Option<ExternalFenceCheck<'_>>,
) -> Result<(), SafeGcError> {
    match (matches!(lane, AuthorityLane::SingleNodePg { .. }), external_check) {
        (true, None) => Err(SafeGcError::StaleDeleterFenced(
            "SingleNodePg provider delete requires live PG lease and gc_epoch fence",
        )),
        (_, Some(chk)) => chk(),
        (false, None) => Ok(()),
    }
}

pub async fn execute_safe_gc_sweep_with_external_fence(
    authority: &DurableSafeGcAuthority,
    backend: &dyn SafeGcDeleteBackend,
    req: SafeGcSweepRequest,
    external_check: Option<ExternalFenceCheck<'_>>,
) -> Result<DeleteExecutionReport, SafeGcError> {
    let snap = authority.snapshot();
    let arm = snap.gc_mode.require_armed()?;
    require_lane_external_fence(&arm.lane, external_check)?;
    require_lane_external_fence(&req.proof.lane, external_check)?;
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
    reconcile_pending_delete_after_restart_fenced(
        authority,
        backend,
        deleter_incarnation_id,
        deleter_incarnation_epoch,
        deleter_lease_epoch,
        None,
        deadline,
    )
    .await
}

pub async fn reconcile_pending_delete_after_restart_fenced(
    authority: &DurableSafeGcAuthority,
    backend: &dyn SafeGcDeleteBackend,
    deleter_incarnation_id: Uuid,
    deleter_incarnation_epoch: u64,
    deleter_lease_epoch: u64,
    external_check: Option<ExternalFenceCheck<'_>>,
    deadline: Instant,
) -> Result<Option<DeleteExecutionReport>, SafeGcError> {
    reconcile_pending_delete_after_restart_fenced_with_fault(
        authority,
        backend,
        (deleter_incarnation_id, deleter_incarnation_epoch, deleter_lease_epoch),
        external_check,
        DeleteFaultHook::None,
        deadline,
    )
    .await
}

/// Restart reconciliation that also threads one fault hook into the resumed pending batch.
pub async fn reconcile_pending_delete_after_restart_fenced_with_fault(
    authority: &DurableSafeGcAuthority,
    backend: &dyn SafeGcDeleteBackend,
    deleter: (Uuid, u64, u64),
    external_check: Option<ExternalFenceCheck<'_>>,
    fault: DeleteFaultHook,
    deadline: Instant,
) -> Result<Option<DeleteExecutionReport>, SafeGcError> {
    let (deleter_incarnation_id, deleter_incarnation_epoch, deleter_lease_epoch) = deleter;
    let snap = authority.snapshot();
    let Some(batch) = snap.pending_delete.clone() else {
        return Ok(None);
    };
    let arm = snap.gc_mode.require_armed()?;
    if deleter_incarnation_id != snap.authority.incarnation_id
        || deleter_incarnation_epoch != snap.authority.incarnation_epoch
        || deleter_lease_epoch != snap.authority.lease_epoch
    {
        return Err(SafeGcError::StaleDeleterFenced(
            "restart reconciliation deleter epochs do not exactly equal live authority",
        ));
    }
    require_lane_external_fence(&arm.lane, external_check)?;
    require_lane_external_fence(&batch.proof.lane, external_check)?;

    if batch.incarnation_epoch < snap.authority.incarnation_epoch
        || batch.incarnation_id != snap.authority.incarnation_id
    {
        // Stale-incarnation batch after rotation: probe remote absence under live fence without issuing new deletes!
        let mut confirmed_absent = Vec::new();
        for key in &batch.pending_keys {
            if let Some(chk) = external_check {
                chk()?;
            }
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
            external_check,
            reconciled: true,
            deadline,
        },
        batch,
        fault,
    )
    .await?;
    Ok(Some(report))
}

/// Default-off non-destructive staging quarantine: records audit state with ZERO provider deletes.
pub fn quarantine_abandoned_staging_without_delete(authority: &DurableSafeGcAuthority) -> Result<usize, SafeGcError> {
    authority.quarantine_abandoned_staging()
}

pub async fn reclaim_abandoned_compaction_staging(
    authority: &DurableSafeGcAuthority,
    backend: &dyn SafeGcDeleteBackend,
    external_check: Option<ExternalFenceCheck<'_>>,
    deadline: Instant,
) -> Result<StagingCleanupReport, SafeGcError> {
    let snap = authority.snapshot();
    let arm = snap.gc_mode.require_armed()?;
    require_lane_external_fence(&arm.lane, external_check)?;
    let tickets = authority.mint_staging_cleanup_tickets()?;
    let mut deleted_keys = Vec::new();
    let mut already_absent_keys = Vec::new();
    let mut unknown_outcome_keys = Vec::new();
    for ticket in &tickets {
        let fence = ActiveDeleteFence::new(authority, ticket, external_check);
        match backend.delete_authorized(&fence, ticket, deadline).await? {
            ProviderDeleteOutcome::ConfirmedDeleted => {
                fence.verify_active_for_ticket(ticket)?;
                authority.record_staging_key_cleaned(ticket.batch_id(), ticket.physical_key())?;
                deleted_keys.push(ticket.physical_key().to_owned());
            }
            ProviderDeleteOutcome::AlreadyAbsent => {
                fence.verify_active_for_ticket(ticket)?;
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

        if let DeleteFaultHook::PauseAfterDeletesForExternalKill { after_deletes, ready_marker_path } = &fault
            && deleted_this_pass >= *after_deletes
        {
            let marker = serde_json::json!({
                "pid": std::process::id(),
                "batch_id": batch.batch_id,
                "deleted_this_pass": deleted_this_pass,
            });
            write_ready_marker(ready_marker_path, &marker)?;
            tokio::time::sleep(Duration::from_secs(120)).await;
            return Err(SafeGcError::Io("external kill after deletes never arrived".into()));
        }

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
                if matches!(fault, DeleteFaultHook::BumpLeaseEpochAfterProviderDeleteBeforeCommit) {
                    fault = DeleteFaultHook::None;
                    let _ = ctx.authority.bump_lease_epoch()?;
                }
                fence.verify_active_for_ticket(&ticket)?;
                ctx.authority.record_key_deleted(batch.batch_id, key, false)?;
                deleted_this_pass += 1;
            }
            Ok(ProviderDeleteOutcome::AlreadyAbsent) => {
                fence.verify_active_for_ticket(&ticket)?;
                ctx.authority.record_key_deleted(batch.batch_id, key, true)?;
                deleted_this_pass += 1;
            }
            Ok(ProviderDeleteOutcome::OutcomeUnknown { reason }) => {
                ctx.authority.record_key_outcome_unknown(batch.batch_id, key, &reason)?;
                unknown.push(format!("{key}: {reason}"));
                retry_keys.push(key.clone());
            }
            Err(err) => {
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
                        | SafeGcError::CompactionVerificationFailed(_)
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
    for p in &snap.retired_packs {
        if p.pack_key.object_path == physical_key {
            return Some(p.pack_locator.clone());
        }
        if p.idx_key.object_path == physical_key {
            return Some(p.idx_locator.clone());
        }
    }
    None
}

fn write_ready_marker(path: &std::path::Path, marker: &serde_json::Value) -> Result<(), SafeGcError> {
    let bytes = serde_json::to_vec(marker).map_err(|e| SafeGcError::Serialization(e.to_string()))?;
    let tmp = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    std::fs::write(&tmp, &bytes).map_err(|e| SafeGcError::Io(e.to_string()))?;
    std::fs::rename(&tmp, path).map_err(|e| SafeGcError::Io(e.to_string()))
}

fn apply_post_ticket_fault(authority: &DurableSafeGcAuthority, fault: PostTicketDriftFault) -> Result<(), SafeGcError> {
    match fault {
        PostTicketDriftFault::ConcurrentNewRef(r) => authority.register_concurrent_ref(r),
        PostTicketDriftFault::AttachGlobalHold(h) => authority.upsert_global_hold(h),
        PostTicketDriftFault::AcquireReaderLease(packs) => {
            authority.acquire_reader_lease("post-ticket", packs).map(drop)
        }
        PostTicketDriftFault::BumpLeaseEpoch => authority.bump_lease_epoch().map(drop),
        PostTicketDriftFault::RotateIncarnation => authority.rotate_incarnation().map(drop),
    }
}

fn apply_pre_ticket_fault(
    authority: &DurableSafeGcAuthority,
    fault: &mut DeleteFaultHook,
    deleted_so_far: usize,
) -> Result<(), SafeGcError> {
    match fault {
        DeleteFaultHook::RotateIncarnationAfterBarrier => {
            *fault = DeleteFaultHook::None;
            let _ = authority.rotate_incarnation()?;
        }
        DeleteFaultHook::ConcurrentNewRefAfterBarrier(r) if deleted_so_far == 0 => {
            let root = r.clone();
            *fault = DeleteFaultHook::None;
            authority.register_concurrent_ref(root)?;
        }
        DeleteFaultHook::AttachHoldAfterBarrier(h) if deleted_so_far == 0 => {
            let hold = h.clone();
            *fault = DeleteFaultHook::None;
            authority.upsert_global_hold(hold)?;
        }
        DeleteFaultHook::ReleaseHoldWithoutCursorAdvance(hold_id, seq) if deleted_so_far == 0 => {
            let (id, release_seq) = (*hold_id, *seq);
            *fault = DeleteFaultHook::None;
            if let Some(mut existing) = authority.snapshot().global_holds.into_iter().find(|h| h.hold_id == id) {
                existing.state = GlobalHoldState::Released { released_at_seq: release_seq };
                authority.upsert_global_hold(existing)?;
            }
        }
        _ => {}
    }
    Ok(())
}
