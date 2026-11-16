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

pub(super) use self::freeze::with_frozen_fenced;
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
    time::{Duration, Instant},
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

/// Existing helper fence/unmount/exit allowance. The one absolute
/// normal-shutdown deadline can only tighten this value.
const HELPER_SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

type HelperShutdown = Box<dyn FnOnce() -> Result<(), Error> + Send>;

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
    drop(client);
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
    drop(client);
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
    drop(client);
    for row in rows {
        ensure_async(state, row.get(0), row.get(1), row.get(2)).await?;
    }
    Ok(())
}

/// Compatibility entry point. If the normal signal path published one
/// absolute shutdown deadline, use it; otherwise keep the previous allowance.
pub async fn shutdown_helper() -> Result<(), Error> {
    match super::process_cleanup_deadline() {
        Some(deadline) => shutdown_helper_until(deadline).await,
        None => shutdown_helper_without_deadline().await,
    }
}

/// Merge the current helper slot with every helper client still retained by
/// the extracted mount registry, keeping one exact generation only once.
fn collect_unique<T, I, F>(current: Option<T>, entries: I, same: F) -> Vec<T>
where
    I: IntoIterator<Item = T>,
    F: Fn(&T, &T) -> bool,
{
    let mut items = Vec::new();
    if let Some(current) = current {
        items.push(current);
    }
    for entry in entries {
        if !items.iter().any(|existing| same(existing, &entry)) {
            items.push(entry);
        }
    }
    items
}

fn helper_clients(current: Option<Arc<HelperClient>>, entries: &MountRegistry) -> Vec<Arc<HelperClient>> {
    collect_unique(
        current,
        entries.iter().filter_map(|(_, mount)| match mount {
            MountEntry::Helper(slot) => Some(slot.client.clone()),
            MountEntry::InProcess(_) => None,
        }),
        |left, right| left.generation() == right.generation(),
    )
}

fn helper_teardown_error(failures: Vec<String>) -> Error {
    Error::internal(format!("workspace FUSE helper teardown incomplete: {}", failures.join("; ")))
}

/// Deadline-aware helper teardown for the normal signal path. Every helper
/// generation retained by the extracted registry (not only the current slot)
/// receives the same absolute deadline before any blocking teardown begins.
/// The existing fence/exact-unmount/exit allowance is capped by the caller's
/// remaining shared normal-shutdown deadline, never by a fresh helper grace.
pub async fn shutdown_helper_until(deadline: tokio::time::Instant) -> Result<(), Error> {
    let current = helper_slot().lock().unwrap().take();
    let entries = {
        let mut registry = registry().lock().unwrap();
        std::mem::take(&mut *registry)
    };
    let clients = helper_clients(current, &entries);
    if clients.is_empty() && entries.iter().next().is_none() {
        return Ok(());
    }
    let teardown_deadline = deadline.into_std().min(Instant::now() + HELPER_SHUTDOWN_GRACE);
    let mut effective = teardown_deadline;
    for client in &clients {
        effective = effective.min(client.publish_teardown_deadline(teardown_deadline));
    }
    let cleanup: HelperShutdown = Box::new(move || {
        let mut failures = Vec::new();
        for client in &clients {
            if let Err(error) = client.shutdown_until(effective) {
                failures.push(format!("helper generation {}: {error}", client.generation()));
            }
        }
        // Keep the registry entries alive until every retained generation has
        // had its exact-owner teardown attempt. A failed generation leaves the
        // helper stage an error; it is never converted to clean quiescence.
        drop(entries);
        if failures.is_empty() { Ok(()) } else { Err(helper_teardown_error(failures)) }
    });
    run_helper_cleanup(cleanup, tokio::time::Instant::from_std(effective)).await
}

/// Compatibility path used when no normal-shutdown deadline was published.
/// It still tears down every retained generation and keeps the previous
/// per-client helper allowance and control-bulkhead dispatch.
async fn shutdown_helper_without_deadline() -> Result<(), Error> {
    let current = helper_slot().lock().unwrap().take();
    let entries = {
        let mut registry = registry().lock().unwrap();
        std::mem::take(&mut *registry)
    };
    let clients = helper_clients(current, &entries);
    if clients.is_empty() && entries.iter().next().is_none() {
        return Ok(());
    }
    super::blocking::run_control(move || {
        let mut failures = Vec::new();
        for client in &clients {
            if let Err(error) = client.shutdown(HELPER_SHUTDOWN_GRACE) {
                failures.push(format!("helper generation {}: {error}", client.generation()));
            }
        }
        drop(entries);
        if failures.is_empty() { Ok(()) } else { Err(helper_teardown_error(failures)) }
    })
    .await
}

/// Run mandatory helper teardown on the existing control bulkhead, but never
/// wait past the helper's shared absolute deadline. If the wait expires before
/// the bulkhead dispatched the closure, launch the same owned closure on a
/// blocking task so the verified fence/exact-unmount attempt is not skipped at
/// budget zero. Either way the closure owns the helper client and registry
/// entries and uses the deadline-aware shutdown internally; a missed wait is
/// reported as a failure, never as a clean unmount.
async fn run_helper_cleanup(cleanup: HelperShutdown, deadline: tokio::time::Instant) -> Result<(), Error> {
    let cleanup = Arc::new(Mutex::new(Some(cleanup)));
    let dispatched = cleanup.clone();
    let task = super::blocking::run_control(move || {
        let cleanup = dispatched
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
            .ok_or_else(|| Error::internal("workspace FUSE helper cleanup was dispatched twice"))?;
        cleanup()
    });
    match tokio::time::timeout_at(deadline, task).await {
        Ok(result) => result,
        Err(_) => {
            let pending = cleanup.lock().unwrap_or_else(std::sync::PoisonError::into_inner).take();
            if let Some(cleanup) = pending {
                let _ = tokio::task::spawn_blocking(cleanup);
            }
            Err(Error(
                StatusCode::GATEWAY_TIMEOUT,
                "workspace FUSE helper shutdown exceeded the shared normal-shutdown deadline",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_retained_generations_are_collected_when_the_current_slot_is_known_none() {
        let collected = collect_unique(None, vec![11u64, 11, 12, 13, 12], |left, right| left == right);
        assert_eq!(collected, vec![11, 12, 13]);

        let empty = collect_unique(None, Vec::<u64>::new(), |left, right| left == right);
        assert!(empty.is_empty(), "no current client and no entries must short-circuit");
    }

    #[test]
    fn current_generation_is_merged_with_retained_entries_only_once() {
        let collected = collect_unique(Some(11u64), vec![12, 11, 13, 12], |left, right| left == right);
        assert_eq!(collected, vec![11, 12, 13]);
    }
}
