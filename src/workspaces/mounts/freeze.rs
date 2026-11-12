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
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<Release>();
        let guard = tokio::spawn(super::super::blocking::run_control(move || {
            gate.freeze_with_decision(|| {
                let _ = ready_tx.send(());
                let decision = match release_rx.blocking_recv() {
                    Ok(Release::KnownRollback) => FreezeDecision::Thaw,
                    Ok(Release::Fence) | Err(_) => FreezeDecision::Fence,
                };
                ((), decision)
            });
            Ok(())
        }));
        ready_rx.await.map_err(Error::internal)?;
        let outcome = work.await;
        let release = release_after(&outcome, commit_started.load(Ordering::Acquire));
        let _ = release_tx.send(release);
        guard.await.map_err(Error::internal)??;
        return outcome;
    }
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
    super::super::blocking::run_control(move || token.finish(decision).map_err(helper_error)).await?;
    outcome
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

    #[test]
    fn only_a_precommit_error_is_a_known_rollback() {
        let success: Result<(), Error> = Ok(());
        let error: Result<(), Error> = Err(Error::internal("conflict"));
        assert_eq!(release_after(&success, false), Release::Fence);
        assert_eq!(release_after(&error, false), Release::KnownRollback);
        assert_eq!(release_after(&error, true), Release::Fence, "a COMMIT transport error is unknown");
    }
}
