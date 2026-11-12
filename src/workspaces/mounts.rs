//! Service-owned FUSE sessions for ordinary workspace filesystem access.
//!
//! Parent-side authorization and lease handling stay here: `ensure` /
//! `ensure_async` run after the lease transaction committed a new `lease_epoch`,
//! `prepare` ran with database authorization, and `with_frozen*` classifies a
//! proven pre-COMMIT rollback as the only case that may thaw the old epoch.
#[path = "mounts/freeze.rs"]
mod freeze;
#[path = "mounts/registry.rs"]
mod registry;

pub use self::freeze::{refresh_leases, update_lease, with_frozen, with_frozen_async};
use self::registry::{Admission, MountEntry, Registry};
use super::lazy;
use crate::{
    AppState, Error,
    members::models::Role,
    workspace_lab::{
        fuse_helper::{HelperClient, HelperError},
        fuse_mount::{LazySource, MountHandle, MutationGate, Overlay},
    },
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
use uuid::Uuid;

pub(super) struct InProcessSlot {
    _session: MountHandle,
    pub(super) gate: Arc<MutationGate>,
    lazy: Option<Arc<lazy::Reader>>,
}

pub(super) type MountRegistry = Registry<Arc<HelperClient>, InProcessSlot>;

static MOUNTS: OnceLock<Arc<Mutex<MountRegistry>>> = OnceLock::new();
pub(super) fn registry() -> &'static Arc<Mutex<MountRegistry>> {
    MOUNTS.get_or_init(|| Arc::new(Mutex::new(MountRegistry::new())))
}
pub(super) static HELPER: OnceLock<Mutex<Option<Arc<HelperClient>>>> = OnceLock::new();

fn helper_slot() -> &'static Mutex<Option<Arc<HelperClient>>> {
    HELPER.get_or_init(|| Mutex::new(None))
}

fn mode() -> String {
    std::env::var("ROOTYARD_WORKSPACE_MOUNT_MODE").unwrap_or_else(|_| "direct".into())
}

pub fn enabled() -> bool {
    matches!(mode().as_str(), "fuse" | "fuse-helper")
}

fn helper_mode() -> bool {
    mode() == "fuse-helper"
}

pub fn lower_path(state: &AppState, id: Uuid) -> PathBuf {
    state.storage.root.join("workspace-service/workspaces").join(id.to_string())
}
pub fn mount_path(state: &AppState, id: Uuid) -> PathBuf {
    state.storage.root.join("workspace-service/mounts").join(id.to_string())
}

pub fn mounted(id: Uuid) -> bool {
    if !enabled() {
        return true;
    }
    let registry = registry().lock().unwrap();
    match registry.get(&id) {
        Some(MountEntry::InProcess(_)) => true,
        Some(MountEntry::Helper(slot)) => !slot.is_pending() && slot.client.alive(),
        None => false,
    }
}

fn helper_client() -> Result<Arc<HelperClient>, Error> {
    let mut slot = helper_slot().lock().unwrap();
    let current = slot.clone();
    match current {
        Some(client) if client.alive() => Ok(client),
        Some(_) => {
            *slot = None;
            Err(Error::internal("workspace FUSE helper is unavailable after a control failure"))
        }
        None => {
            let client = HelperClient::spawn().map_err(Error::internal)?;
            let client = Arc::new(client);
            *slot = Some(client.clone());
            Ok(client)
        }
    }
}

pub(super) fn helper_error(error: HelperError) -> Error {
    match error.code {
        libc::EBUSY | libc::EWOULDBLOCK => {
            Error(StatusCode::CONFLICT, "workspace mount is busy with a freeze or lease handoff")
        }
        libc::ESTALE => Error(StatusCode::CONFLICT, "workspace lease epoch moved on; retry on the new epoch"),
        libc::ENOENT => Error(StatusCode::CONFLICT, "workspace is not mounted in the FUSE helper"),
        _ => Error::internal(error),
    }
}

pub fn ensure(state: &AppState, id: Uuid, db_epoch: i64, until: i64) -> Result<(), Error> {
    if !enabled() {
        return Ok(());
    }
    if helper_mode() {
        return ensure_helper(state, id, db_epoch, until);
    }
    let mut registry = registry().lock().unwrap();
    match registry.get(&id) {
        Some(MountEntry::InProcess(slot)) => {
            slot.gate.handoff(db_epoch, until).map_err(Error::internal)?;
            return Ok(());
        }
        Some(MountEntry::Helper(_)) => {
            return Err(Error(StatusCode::CONFLICT, "workspace mount is registered with another backend"));
        }
        None => {}
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
    registry.insert_in_process(id, InProcessSlot { _session: session, gate, lazy });
    Ok(())
}

/// Off-thread wrapper around [`ensure`] on the isolated control bulkhead.
pub async fn ensure_async(state: &Arc<AppState>, id: Uuid, db_epoch: i64, until: i64) -> Result<(), Error> {
    if !enabled() {
        return Ok(());
    }
    let state = state.clone();
    super::blocking::run_control(move || ensure(&state, id, db_epoch, until)).await
}

fn ensure_helper(state: &AppState, id: Uuid, db_epoch: i64, until: i64) -> Result<(), Error> {
    let client = helper_client()?;
    let generation = client.generation();
    match MountRegistry::admit(registry(), id, client.clone(), generation) {
        Admission::InProcess => {
            Err(Error(StatusCode::CONFLICT, "workspace is already mounted by the in-process backend"))
        }
        Admission::Pending => Err(Error(
            StatusCode::CONFLICT,
            "workspace mount is still being confirmed by the FUSE helper; retry on the same epoch",
        )),
        Admission::Confirmed { client, helper_generation } => {
            if client.alive() {
                return client.handoff(id, db_epoch, until).map_err(helper_error);
            }
            if registry().lock().unwrap().remove_confirmed(id, helper_generation) {
                return Err(Error::internal("workspace FUSE helper is unavailable after a control failure"));
            }
            Err(Error(StatusCode::CONFLICT, "workspace mount changed while the FUSE helper was unavailable; retry"))
        }
        Admission::Reserved(mut guard) => {
            if !lower_path(state, id).join(".git").is_dir() {
                return Err(Error::internal("workspace lower Git state missing"));
            }
            if let Err(error) = client.mount(&state.storage.root, id, db_epoch, until, true) {
                return Err(helper_error(error));
            }
            if guard.promote(client.clone()).is_err() {
                if client.unmount(id).is_err() {
                    let _ = client.shutdown(Duration::from_secs(10));
                    return Err(Error::internal("workspace helper cleanup failed after lost reservation"));
                }
                return Err(Error(
                    StatusCode::CONFLICT,
                    "workspace mount reservation changed before confirmation; retry",
                ));
            }
            Ok(())
        }
    }
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
    let ws =
        super::service::authorized(&state, &headers, id, Role::Write, crate::token_scopes::RepoAction::WorkspacesWrite)
            .await?;
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
    let server = {
        let registry = registry().lock().unwrap();
        match registry.get(&id) {
            Some(MountEntry::Helper(slot)) if !slot.is_pending() => Some(slot.client.clone()),
            _ => None,
        }
    };
    let paths: Vec<PathBuf> = input
        .paths
        .iter()
        .map(|p| crate::browse::models::normalize_rel_path(Some(p)).map(PathBuf::from))
        .collect::<Result<_, _>>()?;
    if let Some(server) = server {
        let request: Vec<String> = paths.iter().map(|p| p.to_string_lossy().into_owned()).collect();
        let (count, bytes) = super::blocking::run(move || server.prewarm(id, request).map_err(helper_error)).await?;
        return Ok(Json(json!({"hydrated_files":count,"hydrated_bytes":bytes})));
    }
    let reader = registry()
        .lock()
        .unwrap()
        .get(&id)
        .and_then(|m| match m {
            MountEntry::InProcess(slot) => slot.lazy.clone(),
            MountEntry::Helper(_) => None,
        })
        .ok_or(Error(StatusCode::CONFLICT, "workspace has no remote lazy baseline"))?;
    let (count, bytes) = super::blocking::run(move || reader.prewarm(&paths).map_err(Error::internal)).await?;
    Ok(Json(json!({"hydrated_files":count,"hydrated_bytes":bytes})))
}

pub async fn ensure_from_database(state: &Arc<AppState>, id: Uuid) -> Result<(), Error> {
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
    ensure_async(state, id, row.get(0), row.get(1)).await
}

pub async fn reconcile_startup(state: &Arc<AppState>) -> Result<(), Error> {
    let mode = mode();
    if mode == "direct" {
        return Ok(());
    }
    if mode != "fuse" && mode != "fuse-helper" {
        return Err(Error::internal("invalid workspace mount mode"));
    }
    let client = state.pool.get().await.map_err(Error::internal)?;
    let rows = client
        .query(
            "SELECT id,lease_epoch,EXTRACT(EPOCH FROM lease_until)::bigint FROM workspaces \
             WHERE host_id=$1 AND state='ready' ORDER BY id",
            &[&state.storage.volume_id],
        )
        .await
        .map_err(Error::internal)?;
    for row in rows {
        ensure_async(state, row.get(0), row.get(1), row.get(2)).await?;
    }
    Ok(())
}

pub async fn shutdown_helper() -> Result<(), Error> {
    let client = helper_slot().lock().unwrap().take();
    let entries = {
        let mut registry = registry().lock().unwrap();
        std::mem::take(&mut *registry)
    };
    let Some(client) = client else {
        super::blocking::run_control(move || {
            drop(entries);
            Ok(())
        })
        .await?;
        return Ok(());
    };
    super::blocking::run_control(move || {
        drop(entries);
        client.shutdown(Duration::from_secs(10)).map_err(Error::internal)
    })
    .await
}
