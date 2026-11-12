//! Cold-path LFS hydration: bounded single-flight remote fetch, atomic
//! publication of verified bytes, and deadline-aware follower waits.
//!
//! Warm reads never enter this module: they are satisfied entirely by the local
//! identity-checked verification cache. Remote health therefore cannot turn a
//! verified local read into a service error, and reads never trigger a
//! synchronous remote repair.
use super::{
    storage::{StagingFileGuard, ensure_repo_lfs_dir, object_path},
    verification,
};
use crate::storage::remote_objects::{ObjectKey, RemoteObjectStore, RemoteStoreError, StoredObject};
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{Arc, LazyLock, Mutex},
};
use tokio::{sync::watch, time::Instant};
use uuid::Uuid;

const MAX_CONCURRENT_HYDRATIONS: usize = 4;
const MAX_CONCURRENT_REPAIRS: usize = 2;

static HYDRATION_SLOTS: LazyLock<tokio::sync::Semaphore> =
    LazyLock::new(|| tokio::sync::Semaphore::new(MAX_CONCURRENT_HYDRATIONS));
static REPAIR_SLOTS: LazyLock<tokio::sync::Semaphore> =
    LazyLock::new(|| tokio::sync::Semaphore::new(MAX_CONCURRENT_REPAIRS));
static FLIGHTS: LazyLock<Mutex<HashMap<HydrationKey, FlightEntry>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

#[cfg(test)]
static HYDRATION_FOLLOWERS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct HydrationKey {
    data_root: PathBuf,
    repo_id: Uuid,
    tenant_id: Uuid,
    oid: String,
    size: u64,
}

struct FlightEntry {
    id: Uuid,
    receiver: watch::Receiver<Option<FlightOutcome>>,
}

#[derive(Clone)]
enum FlightOutcome {
    Published,
    Missing,
    /// The initiator's own short deadline expired before hydration completed.
    /// Surviving followers with remaining deadline budget re-enter `FLIGHTS`
    /// instead of inheriting the initiator's caller-specific timeout.
    InitiatorTimedOut(Arc<FlightFailure>),
    /// Carries the typed failure across the shared single-flight result without
    /// formatting it. Waiters reconstruct a source chain so the central
    /// classifier can downcast to the finite remote-store error.
    Failed(Arc<FlightFailure>),
}

impl std::fmt::Debug for FlightOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never derive over the retained error: its transport source may carry
        // request details that must not appear in diagnostic text.
        formatter.write_str(match self {
            Self::Published => "Published",
            Self::Missing => "Missing",
            Self::InitiatorTimedOut(_) => "InitiatorTimedOut",
            Self::Failed(_) => "Failed",
        })
    }
}

struct FlightFailure {
    /// Present only when the underlying cause was the bounded remote-store
    /// error. It is retained unformatted for classification.
    remote: Option<RemoteStoreError>,
}

/// Rebuilds an `anyhow` source chain for a shared flight failure. Display is a
/// fixed message; only the typed remote error is exposed as the source.
struct SharedFlightError(Arc<FlightFailure>);

impl std::fmt::Display for SharedFlightError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LFS hydration failed")
    }
}

impl std::fmt::Debug for SharedFlightError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for SharedFlightError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.remote.as_ref().map(|error| error as &(dyn std::error::Error + 'static))
    }
}

#[derive(Debug)]
struct HydrationSlotTimeout;

impl std::fmt::Display for HydrationSlotTimeout {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LFS hydration concurrency wait timed out")
    }
}

impl std::error::Error for HydrationSlotTimeout {}

struct HydrationFlightGuard {
    key: HydrationKey,
    id: Uuid,
    removed: bool,
}

impl HydrationFlightGuard {
    fn remove_now(&mut self) {
        if self.removed {
            return;
        }
        let mut flights = FLIGHTS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if flights.get(&self.key).is_some_and(|entry| entry.id == self.id) {
            flights.remove(&self.key);
        }
        self.removed = true;
    }
}

impl Drop for HydrationFlightGuard {
    fn drop(&mut self) {
        self.remove_now();
    }
}

pub(super) fn remote_store(data_root: &Path) -> Result<Option<RemoteObjectStore>> {
    if std::env::var_os("ROOTYARD_OBJECT_STORE_ENDPOINT").is_none() {
        return Ok(None);
    }
    Ok(Some(RemoteObjectStore::from_env(data_root.join("remote-objects"))?))
}

/// Returns whether verified bytes are available locally. A verified local file
/// short-circuits before any object-store configuration or request is
/// inspected. A cold miss hydrates through a single-flight leader; concurrent
/// callers wait on the same bounded operation instead of issuing parallel GETs.
pub(super) async fn ensure_readable(
    data_root: &Path,
    repo_id: Uuid,
    tenant_id: Uuid,
    oid: &str,
    size: u64,
    deadline: Instant,
) -> Result<bool> {
    let path = object_path(data_root, repo_id, oid)?;
    if verification::verify_local(path, data_root.to_path_buf(), repo_id, oid.to_owned(), size, deadline).await? {
        return Ok(true);
    }
    let Some(store) = remote_store(data_root)? else {
        return Ok(false);
    };
    ensure_readable_cold(data_root, repo_id, tenant_id, oid, size, deadline, Arc::new(store)).await
}

#[cfg(test)]
async fn ensure_readable_with_store(
    data_root: &Path,
    repo_id: Uuid,
    tenant_id: Uuid,
    oid: &str,
    size: u64,
    deadline: Instant,
    store: Arc<RemoteObjectStore>,
) -> Result<bool> {
    let path = object_path(data_root, repo_id, oid)?;
    if verification::verify_local(path, data_root.to_path_buf(), repo_id, oid.to_owned(), size, deadline).await? {
        return Ok(true);
    }
    ensure_readable_cold(data_root, repo_id, tenant_id, oid, size, deadline, store).await
}

async fn ensure_readable_cold(
    data_root: &Path,
    repo_id: Uuid,
    tenant_id: Uuid,
    oid: &str,
    size: u64,
    deadline: Instant,
    store: Arc<RemoteObjectStore>,
) -> Result<bool> {
    let outcome = hydrate_coalesced(data_root, repo_id, tenant_id, oid, size, deadline, store).await?;
    match outcome {
        FlightOutcome::Published => Ok(true),
        FlightOutcome::Missing => Ok(false),
        FlightOutcome::InitiatorTimedOut(failure) | FlightOutcome::Failed(failure) => {
            Err(anyhow::Error::new(SharedFlightError(failure)))
        }
    }
}

async fn hydrate_coalesced(
    data_root: &Path,
    repo_id: Uuid,
    tenant_id: Uuid,
    oid: &str,
    size: u64,
    deadline: Instant,
    store: Arc<RemoteObjectStore>,
) -> Result<FlightOutcome> {
    let key = HydrationKey { data_root: data_root.to_path_buf(), repo_id, tenant_id, oid: oid.to_owned(), size };
    loop {
        ensure!(Instant::now() < deadline, "LFS hydration wait timed out");
        let receiver = {
            let mut flights = FLIGHTS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(entry) = flights.get(&key) {
                #[cfg(test)]
                HYDRATION_FOLLOWERS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                entry.receiver.clone()
            } else {
                let (sender, receiver) = watch::channel(None);
                let id = Uuid::new_v4();
                flights.insert(key.clone(), FlightEntry { id, receiver: receiver.clone() });
                let key_for_task = key.clone();
                let store_for_task = store.clone();
                let initiator_deadline = deadline;
                tokio::spawn(async move {
                    let mut guard = HydrationFlightGuard { key: key_for_task, id, removed: false };
                    let outcome = run_hydration(&store_for_task, &guard.key, initiator_deadline).await;
                    // Remove the flight entry before waking followers so a surviving
                    // follower retrying after `InitiatorTimedOut` or a newly arriving
                    // caller can never re-attach to the completed flight.
                    guard.remove_now();
                    let _ = sender.send(Some(outcome));
                });
                receiver
            }
        };
        match wait_for_flight(receiver, deadline).await? {
            FlightOutcome::InitiatorTimedOut(failure) => {
                if Instant::now() >= deadline {
                    return Ok(FlightOutcome::InitiatorTimedOut(failure));
                }
                let path = object_path(data_root, repo_id, oid)?;
                if verification::verify_local(path, data_root.to_path_buf(), repo_id, oid.to_owned(), size, deadline)
                    .await?
                {
                    return Ok(FlightOutcome::Published);
                }
            }
            outcome => return Ok(outcome),
        }
    }
}

async fn wait_for_flight(
    mut receiver: watch::Receiver<Option<FlightOutcome>>,
    deadline: Instant,
) -> Result<FlightOutcome> {
    tokio::time::timeout_at(deadline, async {
        loop {
            if let Some(outcome) = receiver.borrow().clone() {
                return Ok(outcome);
            }
            if receiver.changed().await.is_err() {
                bail!("LFS hydration ended without a result");
            }
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("LFS hydration wait timed out"))?
}

fn is_initiator_timeout(error: &anyhow::Error, deadline: Instant) -> bool {
    if Instant::now() < deadline {
        return false;
    }
    if error.downcast_ref::<HydrationSlotTimeout>().is_some()
        || error.downcast_ref::<tokio::time::error::Elapsed>().is_some()
    {
        return true;
    }
    if let Some(remote) = error.downcast_ref::<RemoteStoreError>() {
        return remote.http_status().is_none() && remote.to_string().ends_with(" timed out");
    }
    false
}

async fn run_hydration(store: &RemoteObjectStore, key: &HydrationKey, deadline: Instant) -> FlightOutcome {
    match hydrate(store, key, deadline).await {
        Ok(outcome) => outcome,
        Err(error) => {
            // Keep only the bounded typed cause; never flatten error Display
            // or its transport source into text stored on the shared flight.
            if error.downcast_ref::<RemoteStoreError>().is_some() {
                super::remote_metrics::counters().record_remote_failure();
            }
            let timed_out = is_initiator_timeout(&error, deadline);
            let remote = error.downcast::<RemoteStoreError>().ok();
            let failure = Arc::new(FlightFailure { remote });
            if timed_out { FlightOutcome::InitiatorTimedOut(failure) } else { FlightOutcome::Failed(failure) }
        }
    }
}

async fn hydrate(store: &RemoteObjectStore, key: &HydrationKey, deadline: Instant) -> Result<FlightOutcome> {
    let permit = tokio::time::timeout_at(deadline, HYDRATION_SLOTS.acquire())
        .await
        .map_err(|_| anyhow::Error::new(HydrationSlotTimeout))?
        .context("LFS hydration limiter closed")?;

    let object_key = ObjectKey::new(key.tenant_id, "lfs", &key.oid)?;
    // A cold path needs one existence check so a missing remote object stays an
    // explicit 404/503 rather than being confused with a corrupt transfer.
    let Some(StoredObject { size, .. }) = store.head(&object_key, deadline).await? else {
        drop(permit);
        return Ok(FlightOutcome::Missing);
    };
    if size != key.size {
        drop(permit);
        return Ok(FlightOutcome::Missing);
    }

    let dir = ensure_repo_lfs_dir(&key.data_root, key.repo_id)?;
    let final_path = object_path(&key.data_root, key.repo_id, &key.oid)?;
    let temp_path = dir.join(format!(".tmp-{}", Uuid::new_v4()));
    let mut guard = StagingFileGuard::new(temp_path.clone());

    store.get_to_file(&object_key, &temp_path, key.size, deadline).await?;

    let staged = temp_path.clone();
    let staged_meta = tokio::task::spawn_blocking(move || -> Result<std::fs::Metadata> {
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o600))?;
        let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC).open(&staged)?;
        file.sync_all()?;
        Ok(file.metadata()?)
    })
    .await??;
    let verified_write = verification::capture_verified_write(&staged_meta, key.size)?;

    let rename_source = temp_path.clone();
    let rename_target = final_path.clone();
    let dir_for_sync = dir.clone();
    let expected = verified_write;
    let root = key.data_root.clone();
    let oid = key.oid.clone();
    let size = key.size;
    let repo_id = key.repo_id;
    tokio::task::spawn_blocking(move || -> Result<()> {
        fs::rename(&rename_source, &rename_target).context("failed to publish hydrated LFS object")?;
        File::open(&dir_for_sync)?.sync_all()?;
        verification::record_published_write(&rename_target, &expected, &root, repo_id, &oid, size)
    })
    .await??;
    guard.disarm();
    drop(permit);
    ensure!(crate::journal::exists(&final_path)?, "hydrated LFS object disappeared");
    Ok(FlightOutcome::Published)
}

/// Explicit, bounded repair workflow for an already-acknowledged upload whose
/// local bytes are still verified but whose remote copy may be missing. It is
/// deliberately never invoked from a read path.
pub(super) fn schedule_repair(
    data_root: PathBuf,
    repo_id: Uuid,
    tenant_id: Uuid,
    oid: String,
    size: u64,
    timeout: std::time::Duration,
) {
    if std::env::var_os("ROOTYARD_OBJECT_STORE_ENDPOINT").is_none() {
        return;
    }
    let Ok(permit) = REPAIR_SLOTS.try_acquire() else {
        return;
    };
    let backlog = super::remote_metrics::counters().begin_repair();
    tokio::spawn(async move {
        let _backlog = backlog;
        let _permit = permit;
        let result = async {
            let Some(store) = remote_store(&data_root)? else {
                return Ok::<(), anyhow::Error>(());
            };
            let key = ObjectKey::new(tenant_id, "lfs", &oid)?;
            let deadline = Instant::now() + timeout;
            if store.head(&key, deadline).await?.is_none_or(|head| head.size != size) {
                let path = object_path(&data_root, repo_id, &oid)?;
                store.put_file(&key, &path, size, deadline).await?;
            }
            Ok(())
        }
        .await;
        if let Err(error) = result {
            if error.downcast_ref::<RemoteStoreError>().is_some() {
                super::remote_metrics::counters().record_remote_failure();
            }
            // Observable but intentionally non-fatal: local verified bytes and
            // the paired backup remain authoritative until a later repair.
            // Fixed text only; never format the error or its source chain.
            let _ = error;
            eprintln!("rootyard: deferred LFS remote repair failed");
        }
    });
}

#[cfg(test)]
fn active_hydration_flights() -> usize {
    FLIGHTS.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).len()
}

#[cfg(test)]
fn hydration_follower_count() -> usize {
    HYDRATION_FOLLOWERS.load(std::sync::atomic::Ordering::Relaxed)
}

#[cfg(test)]
#[path = "hydration_tests.rs"]
mod tests;
