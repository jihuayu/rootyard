//! Fenced physical delete executor & crash-restart reconciliation (#122).

use std::time::Instant;

use uuid::Uuid;

use super::{
    SafeGcError,
    domain::{DeleteExecutionReport, SafeGcDeleteBackend},
    model::{GlobalHoldEntry, LiveRefRoot},
    proof::DeletionProof,
    store::{DurableSafeGcAuthority, PendingDeleteBatch},
};

#[derive(Clone, Debug)]
pub enum DeleteFaultHook {
    None,
    RotateIncarnationAfterBarrier,
    ConcurrentNewRefAfterBarrier(LiveRefRoot),
    AttachHoldAfterBarrier(GlobalHoldEntry),
    ReleaseHoldWithoutCursorAdvance(Uuid, u64),
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
    let snap = authority.snapshot();
    let _arm = snap.gc_mode.require_armed()?;
    let batch = authority.begin_delete_batch(
        req.batch_id,
        req.deleter_incarnation_id,
        req.deleter_incarnation_epoch,
        req.deleter_lease_epoch,
        req.proof,
    )?;
    drive_pending_batch(
        authority,
        backend,
        batch,
        (req.deleter_incarnation_id, req.deleter_incarnation_epoch, req.deleter_lease_epoch),
        req.fault,
        false,
        req.deadline,
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
    let Some(batch) = snap.pending_delete else {
        return Ok(None);
    };
    let report = drive_pending_batch(
        authority,
        backend,
        batch,
        (deleter_incarnation_id, deleter_incarnation_epoch, deleter_lease_epoch),
        DeleteFaultHook::None,
        true,
        deadline,
    )
    .await?;
    Ok(Some(report))
}

async fn drive_pending_batch(
    authority: &DurableSafeGcAuthority,
    backend: &dyn SafeGcDeleteBackend,
    batch: PendingDeleteBatch,
    deleter: (Uuid, u64, u64),
    mut fault: DeleteFaultHook,
    reconciled: bool,
    deadline: Instant,
) -> Result<DeleteExecutionReport, SafeGcError> {
    let mut skipped = batch.skipped_keys.clone();
    let mut failed = Vec::new();
    let mut retry_keys = Vec::new();
    let mut deleted_this_pass = 0_usize;

    for key in &batch.pending_keys {
        if Instant::now() >= deadline {
            failed.push(format!("{key}: deadline exceeded"));
            retry_keys.push(key.clone());
            continue;
        }
        apply_fault_once(authority, &mut fault, deleted_this_pass)?;

        if let DeleteFaultHook::SimulateCrashAfterDeletes(limit) = fault
            && deleted_this_pass >= limit
        {
            return Err(SafeGcError::Io("simulated crash mid-delete batch".into()));
        }

        let ticket_opt = authority.mint_fenced_step_ticket(batch.batch_id, deleter.0, deleter.1, deleter.2, key)?;
        let Some(ticket) = ticket_opt else {
            skipped.push(key.clone());
            continue;
        };
        match backend.delete_authorized(&ticket, deadline).await {
            Ok(()) => {
                authority.record_key_deleted(batch.batch_id, key)?;
                deleted_this_pass += 1;
            }
            Err(err) => {
                failed.push(format!("{key}: {err}"));
                retry_keys.push(key.clone());
            }
        }
    }

    let report = authority.finalize_delete_batch(batch.batch_id, skipped, failed.clone(), retry_keys, reconciled)?;
    if !failed.is_empty() {
        return Err(SafeGcError::PartialDeleteFailure(failed.join("; ")));
    }
    Ok(report)
}

fn apply_fault_once(
    authority: &DurableSafeGcAuthority,
    fault: &mut DeleteFaultHook,
    deleted_so_far: usize,
) -> Result<(), SafeGcError> {
    if deleted_so_far > 0 && !matches!(fault, DeleteFaultHook::None | DeleteFaultHook::SimulateCrashAfterDeletes(_)) {
        return Ok(());
    }
    let taken = std::mem::replace(fault, DeleteFaultHook::None);
    match taken {
        DeleteFaultHook::None => {}
        DeleteFaultHook::SimulateCrashAfterDeletes(n) => {
            *fault = DeleteFaultHook::SimulateCrashAfterDeletes(n);
        }
        DeleteFaultHook::RotateIncarnationAfterBarrier => {
            let _ = authority.rotate_incarnation()?;
        }
        DeleteFaultHook::ConcurrentNewRefAfterBarrier(r) => {
            authority.register_concurrent_ref(r)?;
        }
        DeleteFaultHook::AttachHoldAfterBarrier(h) => {
            authority.upsert_global_hold(h)?;
        }
        DeleteFaultHook::ReleaseHoldWithoutCursorAdvance(hold_id, future_seq) => {
            let snap = authority.snapshot();
            if let Some(h) = snap.global_holds.into_iter().find(|x| x.hold_id == hold_id) {
                let mut released = h;
                released.state = super::model::GlobalHoldState::Released { released_at_seq: future_seq };
                authority.upsert_global_hold(released)?;
            } else {
                return Err(SafeGcError::InvalidInput("fault hold_id not found".into()));
            }
        }
    }
    Ok(())
}
