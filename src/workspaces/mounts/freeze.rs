//! Lease-epoch observation, background FUSE refresh, and mutation-gate freeze
//! barriers for mounted workspaces.
use super::{HELPER, enabled, helper_error, registry, registry::MountEntry};
use crate::{
    AppState, Error,
    workspace_lab::{
        fuse_helper::{HelperClient, protocol::FREEZE_DEADLINE},
        fuse_mount::{FreezeDecision, MutationGate},
    },
};
use std::{
    collections::HashMap,
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use uuid::Uuid;

/// Ordered lease observation from a periodic or page-based refresh.
pub fn update_lease(id: Uuid, db_epoch: i64, until: i64) {
    let _ = &HELPER;
    let observer = {
        let registry = registry().lock().unwrap();
        match registry.get(&id) {
            Some(MountEntry::InProcess(slot)) => {
                let _ = slot.gate.observe_lease(db_epoch, until);
                return;
            }
            Some(MountEntry::Helper(slot)) if !slot.is_pending() => slot.client.clone(),
            Some(MountEntry::Helper(_)) | None => return,
        }
    };
    super::super::blocking::spawn_observe(move || {
        let _ = observer.observe(id, db_epoch, until);
    });
}

pub async fn refresh_leases(state: &AppState) -> Result<(), Error> {
    if !enabled() {
        return Ok(());
    }
    let (in_process, helpers): (Vec<(Uuid, Arc<MutationGate>, (i64, u64))>, Vec<(Uuid, Arc<HelperClient>)>) = {
        let mounts = registry().lock().unwrap();
        let mut in_process = Vec::new();
        let mut helpers = Vec::new();
        for (id, mount) in mounts.iter() {
            match mount {
                MountEntry::InProcess(slot) => in_process.push((*id, slot.gate.clone(), slot.gate.lease_marker())),
                MountEntry::Helper(slot) if !slot.is_pending() => helpers.push((*id, slot.client.clone())),
                MountEntry::Helper(_) => {}
            }
        }
        (in_process, helpers)
    };
    if in_process.is_empty() && helpers.is_empty() {
        return Ok(());
    }
    let helpers = super::super::blocking::run_control(move || {
        Ok(helpers
            .into_iter()
            .map(|(id, client)| {
                let marker = client.marker(id).ok().map(|state| (state.epoch, state.generation));
                (id, client, marker)
            })
            .collect::<Vec<_>>())
    })
    .await?;
    let ids: Vec<Uuid> = in_process.iter().map(|(id, _, _)| *id).chain(helpers.iter().map(|(id, _, _)| *id)).collect();
    let client = state.pool.get().await.map_err(Error::internal)?;
    let rows = client
        .query(
            "SELECT id,lease_epoch,EXTRACT(EPOCH FROM lease_until)::bigint FROM workspaces \
             WHERE id=ANY($1::uuid[]) AND host_id=$2 AND state='ready'",
            &[&ids, &state.storage.volume_id],
        )
        .await
        .map_err(Error::internal)?;
    drop(client);
    let leases: HashMap<Uuid, (i64, i64)> = rows.iter().map(|r| (r.get(0), (r.get(1), r.get(2)))).collect();
    super::super::blocking::run_control(move || {
        for (id, gate, marker) in in_process {
            apply_refresh(gate, marker, leases.get(&id).copied());
        }
        for (id, client, marker) in helpers {
            match leases.get(&id).copied() {
                Some((epoch, until)) => {
                    let _ = client.observe(id, epoch, until);
                }
                None => {
                    if let Some((epoch, generation)) = marker {
                        let _ = client.fence_if_unchanged(id, epoch, generation);
                    }
                }
            }
        }
        Ok(())
    })
    .await
}

fn apply_refresh(gate: Arc<MutationGate>, marker: (i64, u64), lease: Option<(i64, i64)>) {
    match lease {
        Some((epoch, until)) => {
            let _ = gate.observe_lease(epoch, until);
        }
        None => {
            let _ = gate.fence_if_unchanged(marker);
        }
    }
}

fn freeze_grant(
    id: Uuid,
    client: &Arc<HelperClient>,
    epoch: i64,
) -> Result<crate::workspace_lab::fuse_helper::RemoteFreezeToken, Error> {
    let attempt = client.freeze_attempt(id, epoch);
    let _op_id = attempt.op_id();
    attempt.begin(FREEZE_DEADLINE).map_err(helper_error)
}

pub fn with_frozen<T>(id: Uuid, work: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
    if !enabled() {
        return work();
    }
    let (gate, client) = {
        let registry = registry().lock().unwrap();
        match registry.get(&id) {
            Some(MountEntry::InProcess(slot)) => (Some(slot.gate.clone()), None),
            Some(MountEntry::Helper(slot)) if !slot.is_pending() => (None, Some(slot.client.clone())),
            Some(MountEntry::Helper(_)) | None => (None, None),
        }
    };
    if let Some(gate) = gate {
        return gate.freeze(work);
    }
    let Some(client) = client else {
        return Err(Error::internal("workspace FUSE mount missing"));
    };
    if !client.alive() {
        return Err(Error::internal("workspace FUSE helper is unavailable"));
    }
    let epoch = client.marker(id).map_err(helper_error)?.epoch;
    let token = freeze_grant(id, &client, epoch)?;
    let outcome = work();
    token.finish(FreezeDecision::Thaw).map_err(helper_error)?;
    outcome
}

pub async fn with_frozen_async<T>(
    id: Uuid,
    commit_started: Arc<AtomicBool>,
    work: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    with_frozen_inner(id, FREEZE_DEADLINE, commit_started, None, work).await
}

pub(in crate::workspaces) async fn with_frozen_fenced<T>(
    id: Uuid,
    commit_started: Arc<AtomicBool>,
    scan_token: super::super::blocking::ScanToken,
    work: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    with_frozen_inner(id, FREEZE_DEADLINE, commit_started, Some(scan_token), work).await
}

struct PreWorkReleaseGuard {
    tx: Option<tokio::sync::oneshot::Sender<Release>>,
}

impl PreWorkReleaseGuard {
    fn disarm_for_work(&mut self) -> tokio::sync::oneshot::Sender<Release> {
        self.tx.take().expect("pre-work release sender armed")
    }
}

impl Drop for PreWorkReleaseGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            let _ = tx.send(Release::KnownRollback);
        }
    }
}

async fn with_frozen_in_process<T>(
    gate: Arc<MutationGate>,
    freeze_deadline: std::time::Duration,
    commit_started: Arc<AtomicBool>,
    scan_token: Option<super::super::blocking::ScanToken>,
    work: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    let permit = super::super::blocking::acquire_control_permit().await?;
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<Release>();
    let mut pre_work = PreWorkReleaseGuard { tx: Some(release_tx) };
    let gate_worker = gate.clone();
    let mut guard = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let _scan = scan_token;
        gate_worker.freeze_with_decision(|| {
            if ready_tx.send(()).is_err() {
                return ((), FreezeDecision::Thaw);
            }
            let decision = match release_rx.blocking_recv() {
                Ok(Release::KnownRollback) => FreezeDecision::Thaw,
                Ok(Release::Fence) | Err(_) => FreezeDecision::Fence,
            };
            ((), decision)
        });
    });

    tokio::select! {
        ready = ready_rx => {
            if ready.is_err() {
                let _ = (&mut guard).await;
                return Err(Error::internal("workspace freeze worker stopped before ready"));
            }
        }
        joined = &mut guard => {
            let _ = joined;
            return Err(Error::internal("workspace freeze worker stopped before ready"));
        }
        _ = tokio::time::sleep(freeze_deadline) => {
            drop(pre_work);
            return Err(Error::timeout());
        }
    }

    let release_tx = pre_work.disarm_for_work();
    let outcome = work.await;
    let release = release_after(&outcome, commit_started.load(Ordering::Acquire));
    let _ = release_tx.send(release);
    match (release, guard.await) {
        (Release::Fence, Err(_)) => {
            gate.fence();
            outcome
        }
        (Release::Fence, Ok(())) => outcome,
        (Release::KnownRollback, Ok(())) => outcome,
        (Release::KnownRollback, Err(_)) => {
            gate.fence();
            outcome
        }
    }
}

async fn with_frozen_inner<T>(
    id: Uuid,
    freeze_deadline: std::time::Duration,
    commit_started: Arc<AtomicBool>,
    scan_token: Option<super::super::blocking::ScanToken>,
    work: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    if !enabled() {
        return work.await;
    }
    let (gate, client) = {
        let registry = registry().lock().unwrap();
        match registry.get(&id) {
            Some(MountEntry::InProcess(slot)) => (Some(slot.gate.clone()), None),
            Some(MountEntry::Helper(slot)) if !slot.is_pending() => (None, Some(slot.client.clone())),
            Some(MountEntry::Helper(_)) | None => (None, None),
        }
    };
    if let Some(gate) = gate {
        return with_frozen_in_process(gate, freeze_deadline, commit_started, scan_token, work).await;
    }
    let _scan = scan_token;
    let Some(client) = client else {
        return Err(Error::internal("workspace FUSE mount missing"));
    };
    if !client.alive() {
        return Err(Error::internal("workspace FUSE helper is unavailable"));
    }
    let (marker_client, marker_id) = (client.clone(), id);
    let epoch =
        super::super::blocking::run_control(move || marker_client.marker(marker_id).map_err(helper_error)).await?.epoch;
    let (grant_client, grant_id) = (client.clone(), id);
    let token = super::super::blocking::run_control(move || freeze_grant(grant_id, &grant_client, epoch)).await?;
    let outcome = work.await;
    let release = release_after(&outcome, commit_started.load(Ordering::Acquire));
    let decision = match release {
        Release::KnownRollback => FreezeDecision::Thaw,
        Release::Fence => FreezeDecision::Fence,
    };
    let finish_res = super::super::blocking::run_cleanup(move || token.finish(decision).map_err(helper_error)).await;
    match (&outcome, decision) {
        (Ok(_), FreezeDecision::Fence) => {
            if let Ok(Err(err)) | Err(err) = finish_res {
                return Err(err);
            }
            outcome
        }
        _ => {
            finish_res??;
            outcome
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Release {
    KnownRollback,
    Fence,
}

fn release_after<T>(outcome: &Result<T, Error>, commit_started: bool) -> Release {
    match outcome {
        Ok(_) => Release::Fence,
        Err(_) if !commit_started => Release::KnownRollback,
        Err(_) => Release::Fence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workspace_lab::fuse_mount::GatePhase;
    use axum::http::StatusCode;
    use std::time::Duration;

    #[test]
    fn only_a_precommit_error_is_a_known_rollback() {
        let success: Result<(), Error> = Ok(());
        let error: Result<(), Error> = Err(Error::internal("conflict"));
        assert_eq!(release_after(&success, false), Release::Fence);
        assert_eq!(release_after(&error, false), Release::KnownRollback);
        assert_eq!(release_after(&error, true), Release::Fence, "a COMMIT transport error is unknown");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn in_process_freeze_acquisition_timeout_never_hangs_or_fences_unstarted_work() {
        let gate = MutationGate::new_with_lease(1, i64::MAX).unwrap();
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release_mut_tx, release_mut_rx) = std::sync::mpsc::channel();
        let gate_mut = gate.clone();
        let holder = std::thread::spawn(move || {
            let _guard = gate_mut.mutation().unwrap();
            held_tx.send(()).unwrap();
            release_mut_rx.recv().unwrap();
        });
        held_rx.recv_timeout(Duration::from_secs(2)).unwrap();

        let commit_started = Arc::new(AtomicBool::new(false));
        let work_ran = Arc::new(AtomicBool::new(false));
        let work_ran_clone = work_ran.clone();
        let err = with_frozen_in_process(gate.clone(), Duration::from_millis(60), commit_started, None, async move {
            work_ran_clone.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await
        .unwrap_err();
        assert_eq!(err.0, StatusCode::GATEWAY_TIMEOUT);
        assert!(!work_ran.load(Ordering::SeqCst));

        release_mut_tx.send(()).unwrap();
        holder.join().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while gate.phase() != GatePhase::Healthy {
            assert!(std::time::Instant::now() < deadline, "gate stayed frozen or fenced after pre-work timeout");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn in_process_freeze_preserves_slow_committed_work_past_acquisition_deadline() {
        let gate = MutationGate::new_with_lease(1, i64::MAX).unwrap();
        let commit_started = Arc::new(AtomicBool::new(false));
        let commit_flag = commit_started.clone();
        let value = with_frozen_in_process(gate.clone(), Duration::from_millis(40), commit_started, None, async move {
            tokio::time::sleep(Duration::from_millis(120)).await;
            commit_flag.store(true, Ordering::Release);
            Ok(99usize)
        })
        .await
        .expect("committed work must not be discarded by freeze acquisition deadline");
        assert_eq!(value, 99);
        assert_eq!(gate.phase(), GatePhase::Fenced);
    }
}
