//! Service-owned FUSE sessions for ordinary workspace filesystem access.
use super::lazy;
use crate::{
    AppState, Error,
    members::models::Role,
    workspace_lab::fuse_mount::{LazySource, MutationGate, Overlay},
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use fuser::{BackgroundSession, MountOption};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs,
    future::Future,
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
};
use uuid::Uuid;

struct Mounted {
    _session: BackgroundSession,
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
pub fn update_lease(id: Uuid, until: i64) {
    if let Some(mount) = registry().lock().unwrap().get(&id) {
        mount.gate.update(until);
    }
}
pub async fn refresh_leases(state: &AppState) -> Result<(), Error> {
    if !enabled() {
        return Ok(());
    }
    let ids: Vec<Uuid> = registry().lock().unwrap().keys().copied().collect();
    if ids.is_empty() {
        return Ok(());
    }
    let client = state.pool.get().await.map_err(Error::internal)?;
    let rows = client
        .query(
            "SELECT id,EXTRACT(EPOCH FROM lease_until)::bigint FROM workspaces \
             WHERE id=ANY($1::uuid[]) AND host_id=$2 AND state='ready'",
            &[&ids, &state.storage.volume_id],
        )
        .await
        .map_err(Error::internal)?;
    let deadlines: HashMap<Uuid, i64> = rows.iter().map(|r| (r.get(0), r.get(1))).collect();
    let mounts = registry().lock().unwrap();
    for (id, mount) in mounts.iter() {
        mount.gate.update(*deadlines.get(id).unwrap_or(&0));
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
pub async fn with_frozen_async<T>(id: Uuid, work: impl Future<Output = Result<T, Error>>) -> Result<T, Error> {
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
    let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
    let guard = tokio::task::spawn_blocking(move || {
        // Hold the exclusive gate until the database transaction finishes or
        // its future is cancelled; then outstanding callbacks have drained.
        gate.freeze(|| {
            let _ = ready_tx.send(());
            let _ = release_rx.blocking_recv();
        });
    });
    ready_rx.await.map_err(Error::internal)?;
    let outcome = work.await;
    drop(release_tx);
    guard.await.map_err(Error::internal)?;
    outcome
}
pub fn ensure(state: &AppState, id: Uuid, until: i64) -> Result<(), Error> {
    if !enabled() {
        return Ok(());
    }
    let mut registry = registry().lock().unwrap();
    if let Some(existing) = registry.get(&id) {
        existing.gate.update(until);
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
    let gate = MutationGate::new(until);
    let lazy = lazy::Reader::open(state, id)?;
    let source: Option<Arc<dyn LazySource>> = lazy.clone().map(|reader| reader as Arc<dyn LazySource>);
    let overlay = Overlay::new_with_gate_and_lazy(lower, upper, gate.clone(), source).map_err(Error::internal)?;
    let session = fuser::spawn_mount2(
        overlay,
        &mountpoint,
        &[MountOption::FSName("rootyard-workspace".into()), MountOption::DefaultPermissions],
    )
    .map_err(Error::internal)?;
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
    let ws = super::service::authorized(&state, &headers, id, Role::Write, crate::token_scopes::RepoAction::WorkspacesWrite).await?;
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
            "SELECT EXTRACT(EPOCH FROM lease_until)::bigint FROM workspaces WHERE id=$1 AND host_id=$2 AND state='ready'",
            &[&id, &state.storage.volume_id],
        )
        .await
        .map_err(Error::internal)?;
    ensure(state, id, row.get(0))
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
        "SELECT id,EXTRACT(EPOCH FROM lease_until)::bigint FROM workspaces WHERE host_id=$1 AND state='ready' ORDER BY id",
        &[&state.storage.volume_id]).await.map_err(Error::internal)?;
    for row in rows {
        ensure(state, row.get(0), row.get(1))?;
    }
    Ok(())
}
