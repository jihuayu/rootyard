//! Service-owned FUSE sessions for ordinary workspace filesystem access.
use super::lazy;
use crate::{
    AppState, Error,
    members::models::Role,
    workspace_lab::fuse_mount::{FreezeDecision, LazySource, MountHandle, MutationGate, Overlay},
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs,
    future::Future,
    path::PathBuf,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};
use uuid::Uuid;

struct Mounted {
    _session: MountHandle,
    gate: Arc<MutationGate>,
    lazy: Option<Arc<lazy::Reader>>,
}
static MOUNTS: OnceLock<Mutex<HashMap<Uuid, Mounted>>> = OnceLock::new();
fn registry() -> &'static Mutex<HashMap<Uuid, Mounted>> {
    MOUNTS.get_or_init(|| Mutex::new(HashMap::new()))
}

pub fn enabled() -> bool {
    std::env::var("ROOTYARD_WORKSPACE_MOUNT_MODE").as_deref() == Ok("fuse")
}
pub fn lower_path(state: &AppState, id: Uuid) -> PathBuf {
    state.storage.root.join("workspace-service/workspaces").join(id.to_string())
}
pub fn mount_path(state: &AppState, id: Uuid) -> PathBuf {
    state.storage.root.join("workspace-service/mounts").join(id.to_string())
}
pub fn mounted(id: Uuid) -> bool {
    !enabled() || registry().lock().unwrap().contains_key(&id)
}
pub fn update_lease(id: Uuid, db_epoch: i64, until: i64) {
    let gate = registry().lock().unwrap().get(&id).map(|mount| mount.gate.clone());
    if let Some(gate) = gate {
        // Epoch-ordered observe: a late SELECT result cannot fence a newer
        // handoff, shorten its deadline, or re-authorize an old epoch.
        let _ = gate.observe_lease(db_epoch, until);
    }
}
pub async fn refresh_leases(state: &AppState) -> Result<(), Error> {
    if !enabled() {
        return Ok(());
    }
    let (ids, observed): (Vec<Uuid>, Vec<(i64, u64)>) = {
        let mounts = registry().lock().unwrap();
        mounts.iter().map(|(id, mount)| (*id, mount.gate.lease_marker())).unzip()
    };
    let markers: HashMap<Uuid, (i64, u64)> = ids.iter().copied().zip(observed).collect();
    if ids.is_empty() {
        return Ok(());
    }
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
    let mounts = registry().lock().unwrap();
    for (id, mount) in mounts.iter() {
        match leases.get(id) {
            Some((epoch, until)) => {
                let _ = mount.gate.observe_lease(*epoch, *until);
            }
            None => {
                // A missing row may be an old snapshot. Only fence when this gate
                // still matches the marker captured before the query.
                if let Some(marker) = markers.get(id) {
                    let _ = mount.gate.fence_if_unchanged(*marker);
                }
            }
        }
    }
    Ok(())
}
pub fn with_frozen<T>(id: Uuid, work: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
    if !enabled() {
        return work();
    }
    let gate = registry()
        .lock()
        .unwrap()
        .get(&id)
        .map(|m| m.gate.clone())
        .ok_or_else(|| Error::internal("workspace FUSE mount missing"))?;
    gate.freeze(work)
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

pub async fn with_frozen_async<T>(
    id: Uuid,
    commit_started: Arc<AtomicBool>,
    work: impl Future<Output = Result<T, Error>>,
) -> Result<T, Error> {
    if !enabled() {
        return work.await;
    }
    let gate = registry()
        .lock()
        .unwrap()
        .get(&id)
        .map(|m| m.gate.clone())
        .ok_or_else(|| Error::internal("workspace FUSE mount missing"))?;
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<Release>();
    let guard = tokio::task::spawn_blocking(move || {
        // Hold the exclusive gate until the caller reaches a decision. Only an
        // explicit pre-COMMIT rollback thaws the old epoch; commit success,
        // transport errors, caller cancellation and a lost channel fence it.
        gate.freeze_with_decision(|| {
            let _ = ready_tx.send(());
            let decision = match release_rx.blocking_recv() {
                Ok(Release::KnownRollback) => FreezeDecision::Thaw,
                Ok(Release::Fence) | Err(_) => FreezeDecision::Fence,
            };
            ((), decision)
        });
    });
    ready_rx.await.map_err(Error::internal)?;
    let outcome = work.await;
    let release = release_after(&outcome, commit_started.load(Ordering::Acquire));
    let _ = release_tx.send(release);
    guard.await.map_err(Error::internal)?;
    outcome
}
pub fn ensure(state: &AppState, id: Uuid, db_epoch: i64, until: i64) -> Result<(), Error> {
    if !enabled() {
        return Ok(());
    }
    let mut registry = registry().lock().unwrap();
    if let Some(existing) = registry.get(&id) {
        // The lease handler commits a new database epoch before calling this.
        // A same-epoch call only renews the deadline. A new epoch is authorized
        // through the fence-then-authorize handoff, so a concurrent freeze or a
        // guard admitted under the old epoch leaves the gate fenced and surfaces
        // an error instead of keeping the superseded epoch writable.
        existing.gate.handoff(db_epoch, until).map_err(Error::internal)?;
        return Ok(());
    }
    let lower = lower_path(state, id);
    if !lower.join(".git").is_dir() {
        return Err(Error::internal("workspace lower Git state missing"));
    }
    let upper = state.storage.root.join("workspace-service/uppers").join(id.to_string());
    let mountpoint = mount_path(state, id);
    fs::create_dir_all(&upper).map_err(Error::internal)?;
    fs::create_dir_all(&mountpoint).map_err(Error::internal)?;
    let gate = MutationGate::new_with_lease(db_epoch, until).map_err(Error::internal)?;
    let lazy = lazy::Reader::open(state, id)?;
    let source: Option<Arc<dyn LazySource>> = lazy.clone().map(|reader| reader as Arc<dyn LazySource>);
    let overlay = Overlay::new_with_gate_and_lazy(lower, upper, gate.clone(), source).map_err(Error::internal)?;
    let session = crate::workspace_lab::fuse_mount::spawn(overlay, &mountpoint).map_err(Error::internal)?;
    registry.insert(id, Mounted { _session: session, gate, lazy });
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prewarm {
    paths: Vec<String>,
}
pub async fn prewarm(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<Prewarm>,
) -> Result<Json<Value>, Error> {
    let ws = super::service::authorized(&state, &headers, id, Role::Write).await?;
    if ws.host_id != state.storage.volume_id || input.paths.is_empty() || input.paths.len() > 4 {
        return Err(Error(StatusCode::CONFLICT, "workspace prewarm requires local lease and up to four paths"));
    }
    let client = state.pool.get().await.map_err(Error::internal)?;
    let live: bool = client
        .query_one("SELECT lease_until>clock_timestamp() FROM workspaces WHERE id=$1", &[&id])
        .await
        .map_err(Error::internal)?
        .get(0);
    if !live {
        return Err(super::service::conflict());
    }
    let reader = registry()
        .lock()
        .unwrap()
        .get(&id)
        .and_then(|m| m.lazy.clone())
        .ok_or(Error(StatusCode::CONFLICT, "workspace has no remote lazy baseline"))?;
    let paths: Vec<PathBuf> = input
        .paths
        .iter()
        .map(|p| crate::browse::models::normalize_rel_path(Some(p)).map(PathBuf::from))
        .collect::<Result<_, _>>()?;
    let (count, bytes) = tokio::task::spawn_blocking(move || reader.prewarm(&paths))
        .await
        .map_err(Error::internal)?
        .map_err(Error::internal)?;
    Ok(Json(json!({"hydrated_files":count,"hydrated_bytes":bytes})))
}
pub async fn ensure_from_database(state: &AppState, id: Uuid) -> Result<(), Error> {
    if !enabled() {
        return Ok(());
    }
    let client = state.pool.get().await.map_err(Error::internal)?;
    let row = client
        .query_one(
            "SELECT lease_epoch,EXTRACT(EPOCH FROM lease_until)::bigint FROM workspaces \
             WHERE id=$1 AND host_id=$2 AND state='ready'",
            &[&id, &state.storage.volume_id],
        )
        .await
        .map_err(Error::internal)?;
    ensure(state, id, row.get(0), row.get(1))
}
pub async fn reconcile_startup(state: &AppState) -> Result<(), Error> {
    let mode = std::env::var("ROOTYARD_WORKSPACE_MOUNT_MODE").unwrap_or_else(|_| "direct".into());
    if mode == "direct" {
        return Ok(());
    }
    if mode != "fuse" {
        return Err(Error::internal("invalid workspace mount mode"));
    }
    let client = state.pool.get().await.map_err(Error::internal)?;
    let rows=client.query(
        "SELECT id,lease_epoch,EXTRACT(EPOCH FROM lease_until)::bigint FROM workspaces WHERE host_id=$1 AND state='ready' ORDER BY id",
        &[&state.storage.volume_id]).await.map_err(Error::internal)?;
    for row in rows {
        ensure(state, row.get(0), row.get(1), row.get(2))?;
    }
    Ok(())
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
