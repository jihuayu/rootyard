//! Bounded verified download, safe range read, head and policy-gated delete.
//!
//! A length-only ranged GET cannot prove global SHA-256, so v1 range reads do a
//! full bounded download into a private temp file, verify SHA-256 + length, and
//! only then seek the requested slice. This is a cold read: cost is the whole
//! object. Objects above the strict configured ceiling are rejected with
//! `RangeUnsupported` until a chunk-hash manifest/cache proof exists. No listing
//! API exists: provider LIST is not an inventory. `head` proves length only.
//! Deletion is always disabled in this profile.
//!
//! Every public read runs its entire local pipeline in an owned Tokio task carrying
//! a store clone, locator, destination and an already-acquired read lease. The
//! public wrapper only waits on the JoinHandle; on timeout or caller cancellation
//! it detaches rather than aborting, so the owned task still settles its current
//! local open/write/fsync/rename awaits and cleanup before the lease can drop.
//! Kernel-blocked IO therefore stays charged to the shared read budget. Provider
//! futures may still time out inside the task; local FS futures are never
//! cancelled mid-operation. Rename is the commit boundary: a late rename may
//! make a destination appear after a deadline error; the caller must verify the
//! bytes or use a fresh destination, and a timeout yields no receipt. The staging
//! file's `Drop` never blocks a Tokio thread: it defers the unlink to one bounded
//! `spawn_blocking` task that keeps the reader slot and staging lease charged
//! until the OS call returns.
//!
//! External ownership (the verified-read fix): [`BlobStore::get_to_file_with_owner`]
//! attaches one opaque `Arc<T: Send + Sync>` keepalive to the **actual** owned
//! transfer task, not to an outer waiter. It is cloned into the staging object and
//! moved, with the `ReadLease`, into the deferred unlink task and stays owned until
//! the OS unlink returns; a caller timeout or cancellation only detaches the
//! owned task. If a runtime abort or panic drops it while local filesystem work
//! may still run, its drop guard `mem::forget`s the keepalive: bounded capacity
//! is retained until process exit. Normal success or typed-error completion only
//! releases it after every local await returned and cleanup ownership moved. The
//! owner stays type-erased, so this module has no caller-crate dependency.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use futures_util::TryStreamExt;
use opendal::ErrorKind;
use sha2::{Digest, Sha256};
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
};
use uuid::Uuid;

use super::{
    BlobError, BlobLocator,
    budget::ReadLease,
    opendal::{BlobStore, DOWNLOAD_CHUNK_BYTES, DOWNLOAD_CONCURRENCY, MAX_RANGE_BYTES, map_provider_error},
};

/// Opaque external keepalive. Nothing in `blob_store` can interpret it; it is
/// only ever moved and dropped.
type Keepalive = Arc<dyn Send + Sync + 'static>;

/// One deferred staging unlink plus the capacity it keeps charged.
///
/// The owner is deliberately type-erased. It must stay alive until the OS
/// `unlink` has actually returned, so the blocking task takes this value by
/// value and releases the read lease and the owner only after the call returns.
struct StagingCleanup {
    path: PathBuf,
    lease: Option<ReadLease>,
    owner: Option<Keepalive>,
}

impl StagingCleanup {
    /// Run the unlink to completion, then release the read lease and the
    /// external owner. Reaching the end of this function is the only way either
    /// is released on this path.
    fn run(mut self) {
        #[cfg(test)]
        stall_cleanup(&self.path);
        let _ = std::fs::remove_file(&self.path);
        // Only after the unlink returned do the reader slot and the caller's
        // keepalive go back.
        drop(self.lease.take());
        drop(self.owner.take());
    }
}

impl Drop for StagingCleanup {
    fn drop(&mut self) {
        // This runs only when the cleanup task never ran (for example a runtime
        // abort dropped its queued closure). The unlink is unknown, so retain
        // both the read lease and the external owner for the life of the process
        // rather than reporting capacity that may still be in use.
        if self.lease.is_some() {
            std::mem::forget(self.lease.take());
        }
        if self.owner.is_some() {
            std::mem::forget(self.owner.take());
        }
    }
}

/// This call's own staging file plus the verified-read lease covering it and an
/// optional external keepalive.
///
/// The guard is created only after `create_new` succeeded, so the path it may
/// unlink is always one this call created.
struct StagingObject {
    path: Option<PathBuf>,
    lease: Option<ReadLease>,
    owner: Option<Keepalive>,
}

impl StagingObject {
    fn new(path: PathBuf, lease: ReadLease) -> Self {
        Self { path: Some(path), lease: Some(lease), owner: None }
    }

    fn with_owner(path: PathBuf, lease: ReadLease, owner: Option<Keepalive>) -> Self {
        Self { path: Some(path), lease: Some(lease), owner }
    }

    fn path(&self) -> &Path {
        self.path.as_deref().expect("staging object exposes its path until committed")
    }

    /// The temp path was renamed to its final destination: nothing to unlink and
    /// the verified-read lease and external keepalive can go back to the process.
    fn commit(mut self) {
        self.path = None;
        self.lease = None;
        self.owner = None;
    }
}

impl Drop for StagingObject {
    fn drop(&mut self) {
        let Some(path) = self.path.take() else { return };
        let cleanup = StagingCleanup { path, lease: self.lease.take(), owner: self.owner.take() };
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            // No runtime context: this only happens while the runtime itself is
            // being torn down, when a Tokio filesystem blocking operation may
            // still be running. Unlink best-effort, but retain both the read
            // lease and the caller's owner for the life of the process instead
            // of claiming capacity against an uncertain local filesystem.
            let mut cleanup = cleanup;
            let _ = std::fs::remove_file(&cleanup.path);
            if cleanup.lease.is_some() {
                std::mem::forget(cleanup.lease.take());
            }
            if cleanup.owner.is_some() {
                std::mem::forget(cleanup.owner.take());
            }
            return;
        };
        // One pending cleanup per reader slot, so at most `active_readers` are
        // ever in flight process-wide. The blocking task owns the lease and the
        // external keepalive until the unlink returned; if it never runs, its
        // `Drop` retains both fail-closed.
        drop(handle.spawn_blocking(move || cleanup.run()));
    }
}

fn tokio_deadline(deadline: Instant) -> tokio::time::Instant {
    tokio::time::Instant::from_std(deadline)
}

fn check_deadline(deadline: Instant) -> Result<(), BlobError> {
    if Instant::now() >= deadline { Err(BlobError::DeadlineExceeded) } else { Ok(()) }
}

/// Test-only deterministic gate between acquiring read capacity and opening the
/// staging file. It proves an outer timeout detaches the owned task without
/// releasing the lease while local work is still outstanding.
#[cfg(test)]
pub(crate) struct ReadbackStall {
    destination: PathBuf,
    entered: Arc<tokio::sync::Semaphore>,
    release: Arc<tokio::sync::Semaphore>,
}

#[cfg(test)]
static READBACK_STALLS: std::sync::OnceLock<std::sync::Mutex<Vec<ReadbackStall>>> = std::sync::OnceLock::new();

#[cfg(test)]
fn readback_stalls() -> &'static std::sync::Mutex<Vec<ReadbackStall>> {
    READBACK_STALLS.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

#[cfg(test)]
pub(crate) fn install_readback_stall(
    destination: PathBuf,
) -> (Arc<tokio::sync::Semaphore>, Arc<tokio::sync::Semaphore>) {
    let entered = Arc::new(tokio::sync::Semaphore::new(0));
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let stall = ReadbackStall { destination, entered: Arc::clone(&entered), release: Arc::clone(&release) };
    readback_stalls().lock().unwrap_or_else(|poisoned| poisoned.into_inner()).push(stall);
    (entered, release)
}

/// Remove only this destination's gate so parallel unit tests cannot clear each
/// other's gates.
#[cfg(test)]
pub(crate) fn clear_readback_stall(destination: &Path) {
    if let Some(slot) = READBACK_STALLS.get() {
        slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).retain(|stall| stall.destination != destination);
    }
}

#[cfg(test)]
async fn stall_before_staging(destination: &Path) {
    let gate = {
        let slot = readback_stalls().lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        slot.iter()
            .find(|stall| stall.destination == destination)
            .map(|stall| (Arc::clone(&stall.entered), Arc::clone(&stall.release)))
    };
    if let Some((entered, release)) = gate {
        entered.add_permits(1);
        let _ = release.acquire().await;
    }
}

/// Test-only gate inside the deferred `spawn_blocking(remove_file)` cleanup.
/// It proves "the transfer task returned" is not "staging cleanup finished":
/// the external keepalive and the reader slot stay owned until this gate opens
/// and the real unlink has returned.
#[cfg(test)]
pub(crate) struct CleanupStall {
    parent: PathBuf,
    entered: Arc<tokio::sync::Semaphore>,
    release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
}

#[cfg(test)]
static CLEANUP_STALLS: std::sync::OnceLock<std::sync::Mutex<Vec<CleanupStall>>> = std::sync::OnceLock::new();

#[cfg(test)]
fn cleanup_stalls() -> &'static std::sync::Mutex<Vec<CleanupStall>> {
    CLEANUP_STALLS.get_or_init(|| std::sync::Mutex::new(Vec::new()))
}

/// Gate the deferred unlink of every staging file under `parent`. The sender is
/// one-shot; the blocking cleanup thread waits on it before the real `unlink`.
#[cfg(test)]
pub(crate) fn install_cleanup_stall(parent: PathBuf) -> (Arc<tokio::sync::Semaphore>, std::sync::mpsc::SyncSender<()>) {
    let entered = Arc::new(tokio::sync::Semaphore::new(0));
    let (release, wait) = std::sync::mpsc::sync_channel(1);
    let stall = CleanupStall { parent, entered: Arc::clone(&entered), release: std::sync::Mutex::new(wait) };
    cleanup_stalls().lock().unwrap_or_else(|poisoned| poisoned.into_inner()).push(stall);
    (entered, release)
}

#[cfg(test)]
pub(crate) fn clear_cleanup_stall(parent: &Path) {
    if let Some(slot) = CLEANUP_STALLS.get() {
        slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).retain(|stall| stall.parent != parent);
    }
}

#[cfg(test)]
fn stall_cleanup(path: &Path) {
    let gate = {
        let mut slot = cleanup_stalls().lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        slot.iter().position(|stall| Some(stall.parent.as_path()) == path.parent()).map(|index| slot.remove(index))
    };
    if let Some(stall) = gate {
        stall.entered.add_permits(1);
        let wait = stall.release.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let _ = wait.recv();
    }
}

/// Owned drop guard for the caller's opaque keepalive inside the **actual**
/// transfer task.
///
/// It is settled exactly once, after the future ran to normal completion (Ok or
/// typed error) and the staging-cleanup hand-off happened. If the owned task is
/// dropped early — runtime abort or a panic while a local `tokio::fs` operation
/// may still be running — the guard deliberately `mem::forget`s the keepalive:
/// bounded capacity stays owned until process exit instead of being released
/// against a directory that may still be used. This mirrors the fail-closed
/// `Retained` reaper in the native verifier.
struct TransferGuard {
    owner: Option<Keepalive>,
    settled: bool,
}

impl TransferGuard {
    fn new(owner: Option<Keepalive>) -> Self {
        Self { owner, settled: false }
    }

    fn owner_clone(&self) -> Option<Keepalive> {
        self.owner.as_ref().map(Arc::clone)
    }

    /// Normal completion: every local await has returned and the staging object
    /// either committed or handed its owner to the deferred cleanup task.
    fn settle(&mut self) {
        self.settled = true;
        drop(self.owner.take());
    }
}

impl Drop for TransferGuard {
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        if let Some(owner) = self.owner.take() {
            std::mem::forget(owner);
        }
    }
}

impl BlobStore {
    /// Stream provider bytes into `destination`, verifying SHA-256 and length
    /// before the atomic rename. Only this call's own staging file is removed.
    pub async fn get_to_file(
        &self,
        locator: &BlobLocator,
        destination: &Path,
        deadline: Instant,
    ) -> Result<(), BlobError> {
        self.get_to_file_guarded(locator, destination, deadline, None).await
    }

    /// Crate-private retained variant of [`Self::get_to_file`].
    ///
    /// `owner` is an opaque keepalive (for example a materialized-view lease)
    /// that is moved into the **actual** owned transfer task rather than an
    /// outer waiter, cloned into the staging object, and released only after the
    /// transfer and any deferred staging unlink have finished. A caller timeout
    /// or cancellation therefore never releases the owner while local filesystem
    /// work may still run; a runtime abort retains it fail-closed.
    pub(crate) async fn get_to_file_with_owner<T: Send + Sync + 'static>(
        &self,
        locator: &BlobLocator,
        destination: &Path,
        deadline: Instant,
        owner: Arc<T>,
    ) -> Result<(), BlobError> {
        let owner: Keepalive = owner;
        self.get_to_file_guarded(locator, destination, deadline, Some(owner)).await
    }

    async fn get_to_file_guarded(
        &self,
        locator: &BlobLocator,
        destination: &Path,
        deadline: Instant,
        owner: Option<Keepalive>,
    ) -> Result<(), BlobError> {
        self.validate_locator(locator)?;
        if destination.parent().is_none() {
            return Err(BlobError::Config("blob destination parent missing".into()));
        }
        // Queueing is cancellable and happens before any task is spawned.
        let lease = self.resources().acquire_read(locator.length(), deadline).await?;
        let store = self.clone();
        let locator = locator.clone();
        let destination = destination.to_path_buf();
        let handle =
            tokio::spawn(async move { store.get_to_file_owned(&locator, &destination, lease, owner, deadline).await });
        match tokio::time::timeout_at(tokio_deadline(deadline), handle).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(BlobError::Provider("blob readback task failed".into())),
            // Dropping a JoinHandle detaches; it does not abort the owned task,
            // so the owner keepalive stays alive inside it.
            Err(_) => Err(BlobError::DeadlineExceeded),
        }
    }

    /// The whole local pipeline runs in this owned task. No individual local FS
    /// future is timed out or cancelled: after a public deadline the task still
    /// settles the current open/write/fsync/rename and keeps the read lease and
    /// the external keepalive charged until cleanup finishes.
    async fn get_to_file_owned(
        &self,
        locator: &BlobLocator,
        destination: &Path,
        lease: ReadLease,
        owner: Option<Keepalive>,
        deadline: Instant,
    ) -> Result<(), BlobError> {
        let mut guard = TransferGuard::new(owner);
        let result = self.transfer_to_destination(locator, destination, lease, &guard, deadline).await;
        // Reaching this point means the future polled to completion (Ok or a
        // typed error): every local await returned and the staging object either
        // committed or handed its keepalive to the deferred unlink task.
        guard.settle();
        result
    }

    async fn transfer_to_destination(
        &self,
        locator: &BlobLocator,
        destination: &Path,
        lease: ReadLease,
        guard: &TransferGuard,
        deadline: Instant,
    ) -> Result<(), BlobError> {
        let parent = destination.parent().ok_or_else(|| BlobError::Config("blob destination parent missing".into()))?;
        fs::create_dir_all(parent)
            .await
            .map_err(|_| BlobError::Provider("blob destination directory failed".into()))?;
        #[cfg(test)]
        stall_before_staging(destination).await;
        let temp = parent.join(format!(".rootyard-blob-{}", Uuid::new_v4()));
        check_deadline(deadline)?;
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .await
            .map_err(|_| BlobError::Provider("blob staging file creation failed".into()))?;
        // The staging object owns its own keepalive clone, so even if this task
        // is aborted mid-stream the deferred unlink keeps the caller's owner.
        let staging = StagingObject::with_owner(temp, lease, guard.owner_clone());
        self.stream_verified_to(locator, &mut output, deadline).await?;
        output.sync_all().await.map_err(|_| BlobError::Provider("blob staging fsync failed".into()))?;
        drop(output);
        check_deadline(deadline)?;
        // Rename is the commit boundary. If the deadline expires during rename,
        // the destination may still appear even though this returns a timeout;
        // there is no receipt and no attempt is made to remove a raced path.
        fs::rename(staging.path(), destination)
            .await
            .map_err(|_| BlobError::Provider("blob destination rename failed".into()))?;
        if Instant::now() >= deadline {
            return Err(BlobError::DeadlineExceeded);
        }
        File::open(parent)
            .await
            .map_err(|_| BlobError::Provider("blob destination fsync failed".into()))?
            .sync_all()
            .await
            .map_err(|_| BlobError::Provider("blob destination fsync failed".into()))?;
        check_deadline(deadline)?;
        staging.commit();
        Ok(())
    }

    /// Verified range read: full bounded download + SHA-256/length check, then
    /// seek. Never returns bytes that were not verified as part of a verified
    /// whole object. Cold-read cost is the full object size.
    pub async fn get_range(
        &self,
        locator: &BlobLocator,
        start: u64,
        len: u64,
        deadline: Instant,
    ) -> Result<Vec<u8>, BlobError> {
        self.validate_locator(locator)?;
        if len == 0 || len > MAX_RANGE_BYTES {
            return Err(BlobError::RangeExceedsLimit { requested: len, limit: MAX_RANGE_BYTES });
        }
        let end =
            start.checked_add(len).ok_or(BlobError::RangeExceedsLimit { requested: len, limit: MAX_RANGE_BYTES })?;
        if end > locator.length() {
            return Err(BlobError::LengthMismatch { expected: locator.length(), actual: end });
        }
        let ceiling = self.profile().range_full_get_max_bytes();
        if locator.length() > ceiling {
            return Err(BlobError::RangeUnsupported { length: locator.length(), limit: ceiling });
        }
        // Queueing is cancellable and happens before any task is spawned.
        let lease = self.resources().acquire_read(locator.length(), deadline).await?;
        let store = self.clone();
        let locator = locator.clone();
        let handle = tokio::spawn(async move { store.get_range_owned(&locator, start, len, lease, deadline).await });
        match tokio::time::timeout_at(tokio_deadline(deadline), handle).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(BlobError::Provider("blob readback task failed".into())),
            Err(_) => Err(BlobError::DeadlineExceeded),
        }
    }

    async fn get_range_owned(
        &self,
        locator: &BlobLocator,
        start: u64,
        len: u64,
        lease: ReadLease,
        deadline: Instant,
    ) -> Result<Vec<u8>, BlobError> {
        let temp = std::env::temp_dir().join(format!(".rootyard-range-{}", Uuid::new_v4()));
        check_deadline(deadline)?;
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)
            .await
            .map_err(|_| BlobError::Provider("blob staging file creation failed".into()))?;
        let staging = StagingObject::new(temp, lease);
        self.stream_verified_to(locator, &mut output, deadline).await?;
        drop(output);
        check_deadline(deadline)?;
        let mut file = File::open(staging.path())
            .await
            .map_err(|_| BlobError::Provider("blob range staging open failed".into()))?;
        file.seek(std::io::SeekFrom::Start(start))
            .await
            .map_err(|_| BlobError::Provider("blob range seek failed".into()))?;
        let mut bytes = vec![0u8; len as usize];
        file.read_exact(&mut bytes).await.map_err(|_| BlobError::Provider("blob range read failed".into()))?;
        check_deadline(deadline)?;
        Ok(bytes)
    }

    /// Stream the whole object into `output`, hashing and length-checking it
    /// before returning Ok. Provider awaits keep their own timeout; local
    /// staging writes are awaited fully and the absolute deadline is checked
    /// afterwards, never cancelling a local FS future mid-operation.
    async fn stream_verified_to(
        &self,
        locator: &BlobLocator,
        output: &mut File,
        deadline: Instant,
    ) -> Result<(), BlobError> {
        let path = self.object_path(locator);
        let reader = tokio::time::timeout_at(
            tokio_deadline(deadline),
            self.operator().reader_with(&path).chunk(DOWNLOAD_CHUNK_BYTES).concurrent(DOWNLOAD_CONCURRENCY),
        )
        .await
        .map_err(|_| BlobError::DeadlineExceeded)?
        .map_err(map_provider_error)?;
        let mut stream = tokio::time::timeout_at(tokio_deadline(deadline), reader.into_bytes_stream(..))
            .await
            .map_err(|_| BlobError::DeadlineExceeded)?
            .map_err(map_provider_error)?;
        let mut hasher = Sha256::new();
        let mut seen = 0u64;
        loop {
            let next = tokio::time::timeout_at(tokio_deadline(deadline), stream.try_next())
                .await
                .map_err(|_| BlobError::DeadlineExceeded)?
                .map_err(super::opendal::map_stream_error)?;
            let Some(chunk) = next else { break };
            seen = seen.saturating_add(chunk.len() as u64);
            if seen > locator.length() {
                return Err(BlobError::LengthMismatch { expected: locator.length(), actual: seen });
            }
            hasher.update(&chunk);
            output.write_all(&chunk).await.map_err(|_| BlobError::Provider("blob staging write failed".into()))?;
            check_deadline(deadline)?;
        }
        if seen != locator.length() {
            return Err(BlobError::LengthMismatch { expected: locator.length(), actual: seen });
        }
        let actual = hex::encode(hasher.finalize());
        if actual != locator.sha256() {
            return Err(BlobError::DigestMismatch { expected: locator.sha256().to_owned(), actual });
        }
        Ok(())
    }

    /// Length-only existence probe. Never returns or trusts a digest. This shares
    /// the whole-method deadline but takes no reader slot: it moves no payload.
    pub async fn head(&self, locator: &BlobLocator, deadline: Instant) -> Result<Option<u64>, BlobError> {
        let operation = async {
            self.validate_locator(locator)?;
            let path = self.object_path(locator);
            match tokio::time::timeout_at(tokio_deadline(deadline), self.operator().stat(&path)).await {
                Ok(Ok(metadata)) => Ok(Some(metadata.content_length())),
                Ok(Err(error)) if error.kind() == ErrorKind::NotFound => Ok(None),
                Ok(Err(error)) => Err(map_provider_error(error)),
                Err(_) => Err(BlobError::DeadlineExceeded),
            }
        };
        match tokio::time::timeout_at(tokio_deadline(deadline), operation).await {
            Ok(result) => result,
            Err(_) => Err(BlobError::DeadlineExceeded),
        }
    }

    /// Always disabled in the new profile. Persistent hold/root retirement
    /// claims (#113/#114) are not implemented, so no env flag may enable it.
    pub async fn delete(&self, _locator: &BlobLocator, _deadline: Instant) -> Result<(), BlobError> {
        Err(BlobError::DeleteDisabled)
    }
}

#[cfg(test)]
mod retained_tests;
