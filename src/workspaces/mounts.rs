//! Service-owned FUSE sessions for ordinary workspace filesystem access.
//!
//! Two backends share this registry:
//!
//! * `ROOTYARD_WORKSPACE_MOUNT_MODE=fuse-helper` (production, issue #91 phase 3)
//!   - the API process talks to an independent helper child over the protocol
//!   in [`crate::workspace_lab::fuse_helper`]. The registry only stores the
//!   helper client registration per workspace: no `BackgroundSession`, no
//!   `Overlay`, no `Reader` lives in the API process. The gate, the dispatcher
//!   and the lazily hydrated reader all live in the child.
//! * `ROOTYARD_WORKSPACE_MOUNT_MODE=fuse` - the older same-process prototype.
//!   It keeps a `fuser::BackgroundSession` in the API process, so an operator
//!   `SIGKILL` can still leave a blocked session owning the FUSE descriptor. It
//!   is retained for the existing in-process native tests and is *not* the
//!   phase-3 delivery; only `fuse-helper` closes that lifecycle.
//!
//! Parent-side authorization and lease handling stay here: `ensure` is called
//! after the lease transaction committed a new `lease_epoch`, `prepare` ran with
//! database authorization, and `with_frozen*` still classifies a proven
//! pre-COMMIT rollback as the only case that may thaw the old epoch.
use super::lazy;
use crate::{
    AppState, Error,
    members::models::Role,
    workspace_lab::{
        fuse_helper::{HelperClient, HelperError, protocol::FREEZE_DEADLINE},
        fuse_mount::{FreezeDecision, LazySource, MountHandle, MutationGate, Overlay},
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
    collections::HashMap,
    fs,
    future::Future,
    path::PathBuf,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use uuid::Uuid;

/// Where a mounted workspace is actually served.
enum Mounted {
    /// Same-process prototype backend; holds the live session and gate.
    InProcess { _session: MountHandle, gate: Arc<MutationGate>, lazy: Option<Arc<lazy::Reader>> },
    /// Production backend: only the helper client registration is kept.
    Helper { client: Arc<HelperClient> },
    /// A mount was admitted but not confirmed by the child. `mounted()` is
    /// false, a retry is told the mount is pending, and the guard that owns
    /// this entry removes it on every failure, cancel or panic path.
    Pending { _client: Arc<HelperClient> },
}

static MOUNTS: OnceLock<Mutex<HashMap<Uuid, Mounted>>> = OnceLock::new();
fn registry() -> &'static Mutex<HashMap<Uuid, Mounted>> {
    MOUNTS.get_or_init(|| Mutex::new(HashMap::new()))
}
static HELPER: OnceLock<Mutex<Option<Arc<HelperClient>>>> = OnceLock::new();

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

/// A workspace is mounted only while its backend is actually serving it.
pub fn mounted(id: Uuid) -> bool {
    if !enabled() {
        return true;
    }
    let registry = registry().lock().unwrap();
    match registry.get(&id) {
        Some(Mounted::InProcess { .. }) => true,
        Some(Mounted::Helper { client }) => client.alive(),
        Some(Mounted::Pending { .. }) => false,
        None => false,
    }
}

fn helper_client() -> Result<Arc<HelperClient>, Error> {
    let mut slot = helper_slot().lock().unwrap();
    // Clone the registration so the match never holds a borrow of the slot.
    let current = slot.clone();
    match current {
        Some(client) if client.alive() => Ok(client),
        Some(_) => {
            // A helper that died cannot be revived silently: every mount it held
            // is gone, and re-attaching would pretend the other workspaces
            // survived. A restart of the API generation is required.
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

fn helper_error(error: HelperError) -> Error {
    match error.code {
        libc::EBUSY | libc::EWOULDBLOCK => {
            Error(StatusCode::CONFLICT, "workspace mount is busy with a freeze or lease handoff")
        }
        libc::ESTALE => Error(StatusCode::CONFLICT, "workspace lease epoch moved on; retry on the new epoch"),
        libc::ENOENT => Error(StatusCode::CONFLICT, "workspace is not mounted in the FUSE helper"),
        _ => Error::internal(error),
    }
}

/// Ordered lease observation from a periodic or page-based refresh.
pub fn update_lease(id: Uuid, db_epoch: i64, until: i64) {
    let observer = {
        let registry = registry().lock().unwrap();
        match registry.get(&id) {
            Some(Mounted::InProcess { gate, .. }) => {
                // Epoch-ordered observe: a late SELECT result cannot fence a
                // newer handoff, shorten its deadline, or re-authorize an old epoch.
                let _ = gate.observe_lease(db_epoch, until);
                return;
            }
            Some(Mounted::Helper { client }) => client.clone(),
            Some(Mounted::Pending { .. }) | None => return,
        }
    };
    // The child orders the observation under its own gate lock; sending it from
    // a detached thread keeps the caller's runtime free of a blocking RPC.
    let _ = std::thread::Builder::new().name("fuse-helper-observe".into()).spawn(move || {
        let _ = observer.observe(id, db_epoch, until);
    });
}

pub async fn refresh_leases(state: &AppState) -> Result<(), Error> {
    if !enabled() {
        return Ok(());
    }
    // Capture the conditional-fence marker *before* the SELECT: a marker read
    // after a slow query could match a newer handoff and fence it. The marker
    // is a snapshot of (epoch, generation); the child compares it under its
    // own gate lock, so an observation/handoff that lands during the query
    // leaves the newer gate untouched.
    let (in_process, helpers): (Vec<(Uuid, Arc<MutationGate>, (i64, u64))>, Vec<(Uuid, Arc<HelperClient>)>) = {
        let mounts = registry().lock().unwrap();
        let mut in_process = Vec::new();
        let mut helpers = Vec::new();
        for (id, mount) in mounts.iter() {
            match mount {
                Mounted::InProcess { gate, .. } => in_process.push((*id, gate.clone(), gate.lease_marker())),
                Mounted::Helper { client } => helpers.push((*id, client.clone())),
                // An unconfirmed mount has no published gate to refresh.
                Mounted::Pending { .. } => {}
            }
        }
        (in_process, helpers)
    };
    if in_process.is_empty() && helpers.is_empty() {
        return Ok(());
    }
    let helpers = tokio::task::spawn_blocking(move || {
        helpers
            .into_iter()
            .map(|(id, client)| {
                let marker = client.marker(id).ok().map(|state| (state.epoch, state.generation));
                (id, client, marker)
            })
            .collect::<Vec<_>>()
    })
    .await
    .map_err(Error::internal)?;
    let ids: Vec<Uuid> = in_process.iter().map(|(id, _, _)| *id).chain(helpers.iter().map(|(id, _, _)| *id)).collect();
    let client = state.pool.get().await.map_err(Error::internal)?;
    let rows = client
        .query(
            "SELECT id,lease_epoch,EXTRACT(EPOCH FROM lease_until)::bigint FROM workspaces              WHERE id=ANY($1::uuid[]) AND host_id=$2 AND state='ready'",
            &[&ids, &state.storage.volume_id],
        )
        .await
        .map_err(Error::internal)?;
    let leases: HashMap<Uuid, (i64, i64)> = rows.iter().map(|r| (r.get(0), (r.get(1), r.get(2)))).collect();
    tokio::task::spawn_blocking(move || {
        for (id, gate, marker) in in_process {
            apply_refresh(gate, marker, leases.get(&id).copied());
        }
        for (id, client, marker) in helpers {
            match leases.get(&id).copied() {
                Some((epoch, until)) => {
                    let _ = client.observe(id, epoch, until);
                }
                None => {
                    // Only the marker read before the query may be fenced; a
                    // missing row that raced a handoff leaves the new gate alone.
                    if let Some((epoch, generation)) = marker {
                        let _ = client.fence_if_unchanged(id, epoch, generation);
                    }
                }
            }
        }
    })
    .await
    .map_err(Error::internal)?;
    Ok(())
}

fn apply_refresh(gate: Arc<MutationGate>, marker: (i64, u64), lease: Option<(i64, i64)>) {
    match lease {
        Some((epoch, until)) => {
            let _ = gate.observe_lease(epoch, until);
        }
        None => {
            // A missing row may be an old snapshot. Only fence when this gate
            // still matches the marker captured before the query.
            let _ = gate.fence_if_unchanged(marker);
        }
    }
}

fn freeze_grant(
    id: Uuid,
    client: &Arc<HelperClient>,
    epoch: i64,
) -> Result<crate::workspace_lab::fuse_helper::RemoteFreezeToken, Error> {
    // The attempt (and therefore its operation id) exists before the begin
    // frame is written. It is RAII: a begin timeout, a cancelled async caller
    // or a panic queues an `abort_freeze`, and the child's own freeze deadline
    // is the backstop.
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
            Some(Mounted::InProcess { gate, .. }) => (Some(gate.clone()), None),
            Some(Mounted::Helper { client }) => (None, Some(client.clone())),
            None => (None, None),
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
    // Capture and scan freezes never authorize a lease commit, so the old epoch
    // is still the only authority and a thaw is correct. If the gate was fenced
    // while frozen (a newer epoch was observed) the child keeps it fenced: a
    // thaw decision never revives a superseded epoch.
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
            Some(Mounted::InProcess { gate, .. }) => (Some(gate.clone()), None),
            Some(Mounted::Helper { client }) => (None, Some(client.clone())),
            None => (None, None),
        }
    };
    if let Some(gate) = gate {
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
        return outcome;
    }
    let Some(client) = client else {
        return Err(Error::internal("workspace FUSE mount missing"));
    };
    if !client.alive() {
        return Err(Error::internal("workspace FUSE helper is unavailable"));
    }
    let (marker_client, marker_id) = (client.clone(), id);
    let epoch = tokio::task::spawn_blocking(move || marker_client.marker(marker_id))
        .await
        .map_err(Error::internal)?
        .map_err(helper_error)?
        .epoch;
    let (grant_client, grant_id) = (client.clone(), id);
    let token = tokio::task::spawn_blocking(move || freeze_grant(grant_id, &grant_client, epoch))
        .await
        .map_err(Error::internal)??;
    // The token owns the one-shot finish. If the caller is cancelled here, the
    // token is dropped and the child receives an explicit fence, never a thaw.
    let outcome = work.await;
    let release = release_after(&outcome, commit_started.load(Ordering::Acquire));
    let decision = match release {
        Release::KnownRollback => FreezeDecision::Thaw,
        Release::Fence => FreezeDecision::Fence,
    };
    tokio::task::spawn_blocking(move || token.finish(decision)).await.map_err(Error::internal)?.map_err(helper_error)?;
    outcome
}

pub fn ensure(state: &AppState, id: Uuid, db_epoch: i64, until: i64) -> Result<(), Error> {
    if !enabled() {
        return Ok(());
    }
    if helper_mode() {
        return ensure_helper(state, id, db_epoch, until);
    }
    let mut registry = registry().lock().unwrap();
    if let Some(Mounted::InProcess { gate, .. }) = registry.get(&id) {
        // The lease handler commits a new database epoch before calling this.
        // A same-epoch call only renews the deadline. A new epoch is authorized
        // through the fence-then-authorize handoff, so a concurrent freeze or a
        // guard admitted under the old epoch leaves the gate fenced and surfaces
        // an error instead of keeping the superseded epoch writable.
        gate.handoff(db_epoch, until).map_err(Error::internal)?;
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
    registry.insert(id, Mounted::InProcess { _session: session, gate, lazy });
    Ok(())
}

fn ensure_helper(state: &AppState, id: Uuid, db_epoch: i64, until: i64) -> Result<(), Error> {
    let client = helper_client()?;
    enum Registered {
        Helper(Arc<HelperClient>),
        Pending,
        Missing,
    }
    let registered = {
        let registry = registry().lock().unwrap();
        match registry.get(&id) {
            Some(Mounted::Helper { client }) => Registered::Helper(client.clone()),
            Some(Mounted::Pending { .. }) => Registered::Pending,
            Some(Mounted::InProcess { .. }) | None => Registered::Missing,
        }
    };
    match registered {
        Registered::Helper(registered) => {
            // The RPC is issued with the registry lock released so one mount's
            // handoff cannot stall every other workspace.
            if registered.alive() {
                return registered.handoff(id, db_epoch, until).map_err(helper_error);
            }
            registry().lock().unwrap().remove(&id);
            return Err(Error::internal("workspace FUSE helper is unavailable after a control failure"));
        }
        Registered::Pending => {
            return Err(Error(
                StatusCode::CONFLICT,
                "workspace mount is still being confirmed by the FUSE helper; retry on the same epoch",
            ))
        }
        Registered::Missing => {}
    }
    // The lower tree was prepared by `prepare` under database authorization;
    // the helper only ever receives the root and this UUID.
    if !lower_path(state, id).join(".git").is_dir() {
        return Err(Error::internal("workspace lower Git state missing"));
    }
    // Responsibility is registered before the RPC: `mounted(id)` stays false
    // until the child confirmed the mount, and the guard removes this entry on
    // every failure path, including a panic or a cancelled caller.
    registry().lock().unwrap().insert(id, Mounted::Pending { _client: client.clone() });
    let mut guard = PendingGuard { id, armed: true };
    client.mount(&state.storage.root, id, db_epoch, until, true).map_err(helper_error)?;
    {
        let mut registry = registry().lock().unwrap();
        if matches!(registry.get(&id), Some(Mounted::Pending { .. })) {
            registry.insert(id, Mounted::Helper { client });
        }
    }
    guard.armed = false;
    Ok(())
}

/// Removes an unconfirmed mount registration unless the mount was confirmed.
struct PendingGuard {
    id: Uuid,
    armed: bool,
}

impl Drop for PendingGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut registry = registry().lock().unwrap();
        if matches!(registry.get(&self.id), Some(Mounted::Pending { .. })) {
            registry.remove(&self.id);
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
    let server = {
        let registry = registry().lock().unwrap();
        match registry.get(&id) {
            Some(Mounted::Helper { client }) => Some(client.clone()),
            _ => None,
        }
    };
    let paths: Vec<PathBuf> = input
        .paths
        .iter()
        .map(|p| crate::browse::models::normalize_rel_path(Some(p)).map(PathBuf::from))
        .collect::<Result<_, _>>()?;
    if let Some(server) = server {
        // The child runs this as a blocking job beside the FUSE actor, so a slow
        // hydration cannot delay the control loop or another mount.
        let request: Vec<String> = paths.iter().map(|p| p.to_string_lossy().into_owned()).collect();
        let (count, bytes) = tokio::task::spawn_blocking(move || server.prewarm(id, request))
            .await
            .map_err(Error::internal)?
            .map_err(helper_error)?;
        return Ok(Json(json!({"hydrated_files":count,"hydrated_bytes":bytes})));
    }
    let reader = registry()
        .lock()
        .unwrap()
        .get(&id)
        .and_then(|m| match m {
            Mounted::InProcess { lazy, .. } => lazy.clone(),
            Mounted::Helper { .. } | Mounted::Pending { .. } => None,
        })
        .ok_or(Error(StatusCode::CONFLICT, "workspace has no remote lazy baseline"))?;
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
    let mode = mode();
    if mode == "direct" {
        return Ok(());
    }
    if mode != "fuse" && mode != "fuse-helper" {
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

/// Normal shutdown: fence, unmount and reap the helper within a real deadline.
///
/// The caller must treat an error as a failed shutdown. A helper that does not
/// exit is killed by the client and reported, never silently ignored.
pub async fn shutdown_helper() -> Result<(), Error> {
    let client = helper_slot().lock().unwrap().take();
    registry().lock().unwrap().clear();
    let Some(client) = client else { return Ok(()) };
    tokio::task::spawn_blocking(move || client.shutdown(Duration::from_secs(10)))
        .await
        .map_err(Error::internal)?
        .map_err(Error::internal)
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
