//! Service-owned FUSE sessions for ordinary workspace filesystem access.
//!
//! Parent-side authorization and lease handling stay here: `ensure` /
//! `ensure_async` run after the lease transaction committed a new `lease_epoch`,
//! `prepare` ran with database authorization, and `with_frozen*` classifies a
//! proven pre-COMMIT rollback as the only case that may thaw the old epoch.
#[path = "mounts/freeze.rs"]
mod freeze;
#[path = "mounts/legacy_shutdown.rs"]
mod legacy_shutdown;
#[path = "mounts/registry.rs"]
mod registry;
#[path = "mounts/startup.rs"]
mod startup;

pub use self::startup::{StartupJoinError, StartupOutcome, StartupReconcile};

pub(super) use self::freeze::with_frozen_fenced;
pub use self::freeze::{refresh_leases, update_lease, with_frozen, with_frozen_async};
use self::legacy_shutdown::{LegacyOwner, LegacyShutdownObservation, LegacyShutdownTicket};
use self::registry::{Admission, HelperSlot, LegacyPromotion, LegacyReserveError, MountEntry, Registry};
use super::lazy;
use crate::{
    AppState, Error,
    members::models::Role,
    workspace_lab::{
        fuse_helper::{HelperClient, HelperError},
        fuse_mount::{LazySource, LegacySpawnFailure, MountHandle, MutationGate, Overlay},
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

impl LegacyOwner for InProcessSlot {
    fn fence_for_shutdown(&self) {
        self._session.request_stop();
    }

    fn teardown_owned(&mut self) -> Result<(), String> {
        self._session.teardown_owned().map_err(|error| error.to_string())
    }
}

pub(super) type MountRegistry = Registry<Arc<HelperClient>, InProcessSlot>;

static MOUNTS: OnceLock<Arc<Mutex<MountRegistry>>> = OnceLock::new();
pub(super) fn registry() -> &'static Arc<Mutex<MountRegistry>> {
    MOUNTS.get_or_init(|| Arc::new(Mutex::new(MountRegistry::new())))
}
/// One owner lock for the current helper, retired unproved generations and the
/// shutdown-closing state. A generation moves current -> retired and shutdown
/// snapshots both under this same lock, so there is no take-then-push gap.
pub(super) struct HelperOwner<C> {
    current: Option<C>,
    retired: Vec<C>,
    closing: bool,
}

impl<C> Default for HelperOwner<C> {
    fn default() -> Self {
        Self { current: None, retired: Vec::new(), closing: false }
    }
}

impl<C: Clone> HelperOwner<C> {
    /// Retire the current generation only while registration is still open.
    /// After shutdown closes the owner this returns `None`; the shutdown
    /// snapshot has already taken the current slot under the same lock.
    fn retire_current(&mut self) -> Option<C> {
        if self.closing {
            return None;
        }
        let current = self.current.take()?;
        self.retired.push(current.clone());
        Some(current)
    }

    /// Atomically close registration and take the current plus retired set.
    fn take_for_shutdown(&mut self) -> Vec<C> {
        self.closing = true;
        let mut clients = Vec::new();
        if let Some(current) = self.current.take() {
            clients.push(current);
        }
        clients.append(&mut self.retired);
        clients
    }
}

impl HelperOwner<Arc<HelperClient>> {
    /// Prune only generations whose exact child was actually reaped. An
    /// unproved retired client is retained so it remains visible to shutdown.
    fn prune_reaped(&mut self) {
        self.retired.retain(|client| !client.child_reaped());
        if self.current.as_ref().is_some_and(|client| !client.alive() && client.child_reaped()) {
            self.current = None;
        }
    }
}

pub(super) static HELPER: OnceLock<Mutex<HelperOwner<Arc<HelperClient>>>> = OnceLock::new();

fn helper_slot() -> &'static Mutex<HelperOwner<Arc<HelperClient>>> {
    HELPER.get_or_init(|| Mutex::new(HelperOwner::default()))
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
    if registry.legacy_closing() {
        return false;
    }
    match registry.get(&id) {
        Some(MountEntry::InProcess(_)) => true,
        Some(MountEntry::Helper(slot)) => !slot.is_pending() && slot.client.alive(),
        None => false,
    }
}

fn helper_client_locked(owner: &mut HelperOwner<Arc<HelperClient>>) -> Result<Arc<HelperClient>, Error> {
    if owner.closing {
        return Err(Error::internal("workspace FUSE helper is shutting down"));
    }
    owner.prune_reaped();
    if owner.current.as_ref().is_some_and(|client| client.alive()) {
        return Ok(owner.current.as_ref().expect("checked current helper").clone());
    }
    if owner.current.is_some() {
        let _ = owner.retire_current();
    }
    owner.prune_reaped();
    if !owner.retired.is_empty() {
        return Err(Error::internal("workspace FUSE helper is unavailable until the retired generation is reaped"));
    }
    // Creation is serialized by the owner lock, so shutdown either waits for
    // this spawn or observes the new generation in `current`; it can never
    // spawn an unguarded generation after the shutdown snapshot.
    let client = HelperClient::spawn().map_err(Error::internal)?;
    let client = Arc::new(client);
    owner.current = Some(client.clone());
    Ok(client)
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
    // The registry lock only covers the admission decision and token
    // reservation. Filesystem checks, lazy Reader creation and the FUSE spawn
    // happen after it is released, so a synchronous snapshot cannot block on
    // unrelated ensure IO.
    let mut admission = {
        let shared = registry();
        let mut registry = shared.lock().unwrap();
        if registry.legacy_closing() {
            return Err(Error(StatusCode::CONFLICT, "workspace FUSE mount is shutting down"));
        }
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
        match registry.reserve_legacy(id, shared) {
            Ok(admission) => admission,
            Err(LegacyReserveError::Closing) => {
                return Err(Error(StatusCode::CONFLICT, "workspace FUSE mount is shutting down"));
            }
            Err(LegacyReserveError::Pending) => {
                return Err(Error(
                    StatusCode::CONFLICT,
                    "workspace FUSE mount is still being confirmed; retry on the same epoch",
                ));
            }
            Err(LegacyReserveError::Occupied) => {
                return Err(Error(StatusCode::CONFLICT, "workspace FUSE mount changed during admission; retry"));
            }
            Err(LegacyReserveError::Unproved) => {
                return Err(Error(
                    StatusCode::CONFLICT,
                    "workspace FUSE mount has unproved ownership; retry after shutdown",
                ));
            }
        }
    };

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
    let session = match crate::workspace_lab::fuse_mount::spawn_legacy(overlay, &mountpoint) {
        Ok(session) => session,
        Err(LegacySpawnFailure::BeforeSession(error)) => return Err(Error::internal(error)),
        Err(LegacySpawnFailure::AfterSession { error, owner }) => {
            // The session already exists even though its exact identity could
            // not be captured. Transfer the owner and Reader before the
            // pending guard can resolve this admission without an owner.
            admission.retain_unproved(InProcessSlot { _session: owner, gate, lazy });
            return Err(Error::internal(error));
        }
    };
    match admission.promote(InProcessSlot { _session: session, gate, lazy }) {
        Ok(LegacyPromotion::Mounted) => Ok(()),
        Ok(LegacyPromotion::Transferred) => {
            Err(Error(StatusCode::CONFLICT, "workspace FUSE mount completed after shutdown began; ownership retained"))
        }
        Err(owner) => {
            // A stale token must never remove a newer reservation. Keep the
            // newly created owner shutdown-visible instead of dropping its live
            // session and lazy reader.
            registry().lock().unwrap().retain_legacy_owner(id, owner);
            Err(Error(StatusCode::CONFLICT, "workspace FUSE mount reservation changed; retry"))
        }
    }
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
    // Registration is admitted while the owner lock is still held, so a
    // shutdown snapshot cannot close between choosing the client and inserting
    // its registry entry.
    let (client, admission) = {
        let mut owner = helper_slot().lock().unwrap();
        let client = helper_client_locked(&mut owner)?;
        let generation = client.generation();
        let admission = MountRegistry::admit(registry(), id, client.clone(), generation);
        (client, admission)
    };
    match admission {
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

/// Compatibility entrypoint that starts and joins the owned startup producer
/// inline. Service startup retains [`StartupReconcile`] itself so a signal can
/// stop admission without dropping the producer.
pub async fn reconcile_startup(state: &Arc<AppState>) -> Result<(), Error> {
    match StartupReconcile::start(state.clone()).join().await {
        Ok(StartupOutcome::Completed(result)) => result,
        Ok(StartupOutcome::Stopped) => Err(Error::internal("workspace startup reconcile stopped")),
        Err(StartupJoinError::Panicked) => Err(Error::internal("workspace startup reconcile worker panicked")),
        Err(StartupJoinError::Cancelled) => Err(Error::internal("workspace startup reconcile worker cancelled")),
        Err(StartupJoinError::Deadline) => {
            Err(Error::internal("workspace startup reconcile deadline is not used by the compatibility entrypoint"))
        }
        Err(StartupJoinError::AlreadyJoined) => Err(Error::internal("workspace startup reconcile was already joined")),
    }
}

/// Compatibility entry point. If the normal signal path published one
/// absolute shutdown deadline, use it; otherwise keep the previous allowance.
pub async fn shutdown_helper() -> Result<(), Error> {
    match super::process_cleanup_deadline() {
        Some(deadline) => shutdown_helper_until(deadline).await,
        None => shutdown_helper_without_deadline().await,
    }
}

/// Merge the current/retired helper set with every helper client still
/// retained by the extracted mount registry, keeping one exact generation only
/// once.
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

struct ShutdownSnapshot {
    clients: Vec<Arc<HelperClient>>,
    helpers: Vec<(Uuid, HelperSlot<Arc<HelperClient>>)>,
    legacy: Option<Arc<LegacyShutdownTicket<InProcessSlot>>>,
}

/// Atomically close helper registration/creation and legacy admission, snapshot
/// the current/retired helper slots and every helper client still retained by
/// the mount registry, and extract legacy owners into one retained ticket.
/// Registration is admitted under the owner lock, so no new helper entry can
/// appear after this snapshot. The legacy ticket is stored by the registry
/// before its ordinary OS worker is spawned. This function intentionally does
/// not `mem::take` the registry: the closing flags and retained ticket stay
/// reachable for repeated observers.
fn take_shutdown_snapshot() -> ShutdownSnapshot {
    let owner_clients = {
        let mut owner = helper_slot().lock().unwrap();
        owner.prune_reaped();
        owner.take_for_shutdown()
    };
    let (helpers, legacy) = {
        let mut registry = registry().lock().unwrap();
        let shutdown = registry.begin_shutdown();
        (shutdown.helpers, shutdown.legacy)
    };
    if let Some(ticket) = legacy.as_ref() {
        // The ticket is already stored under the registry authority. A spawn
        // failure is recorded in the same ticket and retains every owner; the
        // bounded observer reports it instead of relabeling it clean.
        let _ = ticket.spawn_worker();
    }
    let clients = collect_unique(
        None,
        owner_clients.into_iter().chain(helpers.iter().map(|(_, mount)| mount.client.clone())),
        |left, right| left.generation() == right.generation(),
    );
    ShutdownSnapshot { clients, helpers, legacy }
}

fn combine_shutdown_results(helper: Result<(), Error>, legacy: Result<(), Error>) -> Result<(), Error> {
    match (helper, legacy) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

/// Minimal failsafe deadline contract for a successful legacy observation.
///
/// Success is accepted only when the observation itself happens strictly before
/// the caller's same absolute deadline. A worker that completed earlier but is
/// first observed at or after that deadline is reported as incomplete/timeout;
/// no completion time is invented retroactively and no fresh clock is started.
/// An empty/no-work legacy ticket follows the same rule: if clean completion is
/// only observable after the deadline, it is not accepted.
fn legacy_success_within_deadline(
    observation: &LegacyShutdownObservation,
    observed_at: Instant,
    deadline: Instant,
) -> bool {
    observed_at < deadline && observation.success()
}

/// Bounded observer for the retained legacy owner. A timeout or dropped future
/// never cancels the worker or releases its handles; a later shutdown/observer
/// reaps the same ticket. The deadline is checked before success is accepted.
async fn wait_legacy_until(
    ticket: Arc<LegacyShutdownTicket<InProcessSlot>>,
    deadline: tokio::time::Instant,
) -> Result<(), Error> {
    let finite_deadline = deadline.into_std();
    loop {
        let observation: LegacyShutdownObservation = ticket.observe();
        let now = Instant::now();
        if legacy_success_within_deadline(&observation, now, finite_deadline) {
            return Ok(());
        }
        if now >= finite_deadline {
            return Err(Error(
                StatusCode::GATEWAY_TIMEOUT,
                "workspace FUSE legacy mount teardown exceeded the shared normal-shutdown deadline",
            ));
        }
        if observation.is_terminal() {
            return Err(Error(StatusCode::SERVICE_UNAVAILABLE, "workspace FUSE legacy mount teardown failed"));
        }
        tokio::time::sleep((finite_deadline - now).min(Duration::from_millis(10))).await;
    }
}

fn helper_teardown_error(failures: Vec<String>) -> Error {
    Error::internal(format!("workspace FUSE helper teardown incomplete: {}", failures.join("; ")))
}

/// Bounded source-completion evidence for actual legacy owners whose actor
/// join, exact unmount and session join all completed inside one cleanup.
///
/// It is returned only after the retained ticket reports a reaped clean worker.
/// An empty/no-work ticket yields `None`, so evidence can never be interpreted
/// as proof that at least one mount existed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyShutdownEvidence {
    /// Numeric identity of the mount namespace in which the joins happened.
    pub mount_namespace: u64,
    /// Number of exact owned mounts joined in this cleanup.
    pub joined_mounts: usize,
    /// Exact workspace UUIDs, in teardown completion order. The service layer
    /// hashes these before emitting any bounded evidence line.
    pub workspaces: Vec<Uuid>,
}

fn mount_namespace_inode() -> u64 {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata("/proc/self/ns/mnt").map(|metadata| metadata.ino()).unwrap_or(0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// Deadline-aware helper teardown for the normal signal path. Every owned
/// helper generation — current, retired and registry-retained, even with an
/// empty registry — receives the same absolute deadline before any blocking
/// teardown begins. The existing fence/exact-unmount/exit allowance is capped
/// by the caller's remaining shared normal-shutdown deadline, never by a fresh
/// helper grace.
///
/// The returned bounded legacy evidence is present only when the legacy result
/// itself succeeded; a helper-only failure does not erase an already-proven
/// legacy join.
pub async fn shutdown_helper_until_with_evidence(
    deadline: tokio::time::Instant,
) -> (Result<(), Error>, Option<LegacyShutdownEvidence>) {
    let ShutdownSnapshot { clients, helpers, legacy } = take_shutdown_snapshot();
    if clients.is_empty() && helpers.is_empty() && legacy.is_none() {
        return (Ok(()), None);
    }
    let teardown_deadline = deadline.into_std().min(Instant::now() + HELPER_SHUTDOWN_GRACE);
    let mut effective = teardown_deadline;
    for client in &clients {
        effective = effective.min(client.publish_teardown_deadline(teardown_deadline));
    }
    let helper_result = if clients.is_empty() && helpers.is_empty() {
        Ok(())
    } else {
        let cleanup: HelperShutdown = Box::new(move || {
            let mut failures = Vec::new();
            for client in &clients {
                if let Err(error) = client.shutdown_until(effective) {
                    failures.push(format!("helper generation {}: {error}", client.generation()));
                }
            }
            // Keep the registry entries alive until every retained generation
            // has had its exact-owner teardown attempt. A failed generation
            // leaves the helper stage an error; it is never converted to clean
            // quiescence.
            drop(helpers);
            if failures.is_empty() { Ok(()) } else { Err(helper_teardown_error(failures)) }
        });
        run_helper_cleanup(cleanup, tokio::time::Instant::from_std(effective)).await
    };
    let (legacy_result, legacy_evidence) = match legacy {
        Some(ticket) => {
            let observer = ticket.clone();
            let result = wait_legacy_until(ticket, deadline).await;
            let evidence = if result.is_ok() {
                observer.completion_evidence().map(|(joined_mounts, workspaces)| LegacyShutdownEvidence {
                    mount_namespace: mount_namespace_inode(),
                    joined_mounts,
                    workspaces,
                })
            } else {
                None
            };
            (result, evidence)
        }
        None => (Ok(()), None),
    };
    (combine_shutdown_results(helper_result, legacy_result), legacy_evidence)
}

/// Compatibility entry point preserving the original result-only API.
pub async fn shutdown_helper_until(deadline: tokio::time::Instant) -> Result<(), Error> {
    shutdown_helper_until_with_evidence(deadline).await.0
}

/// Compatibility path used when no normal-shutdown deadline was published.
/// It still tears down every retained generation and keeps the previous
/// per-client helper allowance and control-bulkhead dispatch.
async fn shutdown_helper_without_deadline() -> Result<(), Error> {
    let ShutdownSnapshot { clients, helpers, legacy } = take_shutdown_snapshot();
    if clients.is_empty() && helpers.is_empty() && legacy.is_none() {
        return Ok(());
    }
    let legacy_deadline = tokio::time::Instant::now() + HELPER_SHUTDOWN_GRACE;
    let helper_result = if clients.is_empty() && helpers.is_empty() {
        Ok(())
    } else {
        super::blocking::run_control(move || {
            let mut failures = Vec::new();
            for client in &clients {
                if let Err(error) = client.shutdown(HELPER_SHUTDOWN_GRACE) {
                    failures.push(format!("helper generation {}: {error}", client.generation()));
                }
            }
            drop(helpers);
            if failures.is_empty() { Ok(()) } else { Err(helper_teardown_error(failures)) }
        })
        .await
    };
    let legacy_result = match legacy {
        Some(ticket) => wait_legacy_until(ticket, legacy_deadline).await,
        None => Ok(()),
    };
    combine_shutdown_results(helper_result, legacy_result)
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
                // Intentional detachment of the already bounded, owned cleanup
                // closure; the outer wait has already failed and is not retried.
                drop(tokio::task::spawn_blocking(cleanup));
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
    fn dead_current_is_retained_for_shutdown_with_an_empty_registry() {
        let mut owner = HelperOwner { current: Some(7u64), retired: Vec::new(), closing: false };
        let clients = owner.take_for_shutdown();
        assert_eq!(clients, vec![7], "a dead current generation must remain shutdown-visible");
        assert!(owner.closing);
    }

    #[test]
    fn current_retired_handoff_and_close_are_linearized_by_the_owner_lock() {
        // Handoff before close: the retired set is what shutdown takes.
        let mut before = HelperOwner { current: Some(7u64), retired: Vec::new(), closing: false };
        assert_eq!(before.retire_current(), Some(7));
        assert!(before.current.is_none());
        assert_eq!(before.take_for_shutdown(), vec![7]);

        // Close before handoff: shutdown already took current; the late handoff
        // cannot add an unguarded generation after the snapshot.
        let mut after = HelperOwner { current: Some(7u64), retired: Vec::new(), closing: false };
        assert_eq!(after.take_for_shutdown(), vec![7]);
        assert_eq!(after.retire_current(), None);
        assert!(after.retired.is_empty());
    }

    #[test]
    fn retired_generations_without_a_current_slot_are_shutdown_visible() {
        let mut owner = HelperOwner { current: None, retired: vec![8u64], closing: false };
        assert_eq!(owner.take_for_shutdown(), vec![8]);
    }

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

    fn clean_legacy_observation() -> LegacyShutdownObservation {
        LegacyShutdownObservation {
            pending: 0,
            owned: 0,
            joined: 1,
            failures: Vec::new(),
            worker_spawn_error: None,
            worker_finished: true,
            worker_reaped: true,
            reaped_result: Some(Ok(())),
        }
    }

    #[test]
    fn legacy_success_observed_at_or_after_the_absolute_deadline_is_not_clean() {
        let deadline = Instant::now();
        let clean = clean_legacy_observation();
        assert!(legacy_success_within_deadline(&clean, deadline - Duration::from_millis(1), deadline));
        assert!(
            !legacy_success_within_deadline(&clean, deadline, deadline),
            "an observation at the absolute deadline is not a success"
        );
        assert!(
            !legacy_success_within_deadline(&clean, deadline + Duration::from_millis(1), deadline),
            "a worker completed after D must not be accepted by a late observer"
        );

        let mut incomplete = clean_legacy_observation();
        incomplete.pending = 1;
        assert!(!legacy_success_within_deadline(&incomplete, deadline - Duration::from_millis(1), deadline));
    }

    #[test]
    fn empty_legacy_ticket_uses_the_same_pre_deadline_success_contract() {
        // The no-work case is represented by a clean zero-owner observation;
        // it still cannot be accepted at/after D.
        let deadline = Instant::now();
        let clean = clean_legacy_observation();
        assert!(!legacy_success_within_deadline(&clean, deadline, deadline));
        assert!(legacy_success_within_deadline(&clean, deadline - Duration::from_millis(1), deadline));
    }
}
