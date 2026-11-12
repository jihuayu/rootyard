//! Single-flight remote blob hydrator and verified local cache for lazy
//! workspaces.
use crate::storage::remote_objects::{ObjectKey, RemoteObjectStore};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    future::Future,
    io::{self, Read},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock},
    time::Duration,
};
use tokio::{runtime::Runtime, time::Instant};
use uuid::Uuid;

const DEFAULT_HYDRATION_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_HYDRATION_TIMEOUT_MS: u64 = 60_000;
const HYDRATION_TIMEOUT_ENV: &str = "ROOTYARD_WORKSPACE_LAZY_TIMEOUT_MS";
pub(super) const HYDRATION_PUBLICATION_GRACE: Duration = Duration::from_secs(10);

pub(super) type FetchFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

/// A single remote request shared by every concurrent reader of one blob.
pub(super) struct Flight {
    outcome: Mutex<Option<i32>>,
    done: Condvar,
    deadline: std::time::Instant,
    #[cfg(test)]
    waiters: std::sync::atomic::AtomicUsize,
}

impl Flight {
    pub(super) fn new(deadline: std::time::Instant) -> Self {
        Self {
            outcome: Mutex::new(None),
            done: Condvar::new(),
            deadline,
            #[cfg(test)]
            waiters: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub(super) fn finish(&self, code: i32) {
        *lock(&self.outcome) = Some(code);
        self.done.notify_all();
    }

    #[cfg(test)]
    pub(super) fn wait(&self) -> io::Result<()> {
        self.wait_until(self.deadline)
    }

    /// A follower waits for `min(caller_deadline, flight_deadline)`. Hitting
    /// the caller budget is `ETIMEDOUT`; hitting the leader's own deadline is
    /// the existing `EIO`. Neither case cancels the shared leader, which stays
    /// owned by the original caller that created the flight.
    pub(super) fn wait_until(&self, caller_deadline: std::time::Instant) -> io::Result<()> {
        let (limit, timeout_error): (std::time::Instant, fn() -> io::Error) =
            if caller_deadline < self.deadline { (caller_deadline, etimedout) } else { (self.deadline, eio) };
        #[cfg(test)]
        self.waiters.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let result = self.wait_bounded(limit, timeout_error);
        #[cfg(test)]
        self.waiters.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        result
    }

    fn wait_bounded(&self, limit: std::time::Instant, timeout_error: fn() -> io::Error) -> io::Result<()> {
        let mut outcome = lock(&self.outcome);
        loop {
            if let Some(code) = *outcome {
                return if code == 0 { Ok(()) } else { Err(io::Error::from_raw_os_error(code)) };
            }
            let now = std::time::Instant::now();
            if now >= limit {
                return Err(timeout_error());
            }
            let (guard, timed_out) =
                self.done.wait_timeout(outcome, limit - now).unwrap_or_else(std::sync::PoisonError::into_inner);
            outcome = guard;
            if timed_out.timed_out() && outcome.is_none() {
                return Err(timeout_error());
            }
        }
    }
}

/// Removes the leader entry and wakes its followers even if hydration panics.
struct LeaderGuard<'a> {
    hydrator: &'a Hydrator,
    digest: String,
    flight: Arc<Flight>,
    finished: bool,
}

impl<'a> LeaderGuard<'a> {
    fn new(hydrator: &'a Hydrator, digest: String, flight: Arc<Flight>) -> Self {
        Self { hydrator, digest, flight, finished: false }
    }

    fn finish(&mut self, result: &io::Result<()>) {
        self.complete(result);
        self.finished = true;
    }

    fn complete(&self, result: &io::Result<()>) {
        let code = match result {
            Ok(()) => 0,
            Err(error) => error.raw_os_error().unwrap_or(libc::EIO),
        };
        lock(&self.hydrator.flights).remove(&self.digest);
        self.flight.finish(code);
    }
}

impl Drop for LeaderGuard<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.complete(&Err(eio()));
        }
    }
}

pub(super) trait BlobFetcher: Send + Sync {
    fn fetch(&self, key: &ObjectKey, staging: PathBuf, expected_size: u64, deadline: Instant) -> FetchFuture;
}

pub(super) struct RemoteFetcher {
    pub(super) store: Arc<RemoteObjectStore>,
}

impl BlobFetcher for RemoteFetcher {
    fn fetch(&self, key: &ObjectKey, staging: PathBuf, expected_size: u64, deadline: Instant) -> FetchFuture {
        let store = self.store.clone();
        let key = key.clone();
        Box::pin(async move { store.get_to_file(&key, &staging, expected_size, deadline).await.map_err(|_| eio()) })
    }
}

pub(super) struct Hydrator {
    cache_root: PathBuf,
    fetcher: Arc<dyn BlobFetcher>,
    runtime: &'static Runtime,
    pub(super) timeout: Duration,
    verified: Mutex<HashSet<String>>,
    flights: Mutex<HashMap<String, Arc<Flight>>>,
}

impl Hydrator {
    pub(super) fn new(cache_root: PathBuf, fetcher: Arc<dyn BlobFetcher>, timeout: Duration) -> io::Result<Self> {
        fs::create_dir_all(&cache_root)?;
        Ok(Self {
            cache_root,
            fetcher,
            runtime: io_runtime()?,
            timeout,
            verified: Mutex::new(HashSet::new()),
            flights: Mutex::new(HashMap::new()),
        })
    }

    pub(super) fn ensure(&self, key: &ObjectKey, size: u64) -> io::Result<File> {
        let deadline = std::time::Instant::now() + self.timeout + HYDRATION_PUBLICATION_GRACE;
        self.ensure_until(key, size, deadline)
    }

    /// One blob hydrated inside an absolute caller deadline. A follower joins
    /// the existing single flight but bounds its own wait; it never cancels the
    /// leader. A new leader sets the flight deadline to the smaller of the
    /// caller budget and the configured publication window.
    pub(super) fn ensure_until(&self, key: &ObjectKey, size: u64, deadline: std::time::Instant) -> io::Result<File> {
        if std::time::Instant::now() >= deadline {
            return Err(etimedout());
        }
        let digest = key.sha256.as_str();
        if lock(&self.verified).contains(digest) {
            match self.open(digest) {
                Ok(file) => {
                    if file.metadata().map(|meta| meta.len()).ok() == Some(size) {
                        return Ok(file);
                    }
                    lock(&self.verified).remove(digest);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    lock(&self.verified).remove(digest);
                }
                Err(error) => return Err(error),
            }
        }
        let (flight, leader) = {
            let mut flights = lock(&self.flights);
            match flights.get(digest) {
                Some(flight) => (flight.clone(), false),
                None => {
                    let configured = std::time::Instant::now() + self.timeout + HYDRATION_PUBLICATION_GRACE;
                    let flight = Arc::new(Flight::new(configured.min(deadline)));
                    flights.insert(digest.to_owned(), flight.clone());
                    (flight, true)
                }
            }
        };
        if !leader {
            flight.wait_until(deadline)?;
            return self.open(digest);
        }
        let mut guard = LeaderGuard::new(self, digest.to_owned(), flight);
        let result = self.hydrate_until(key, size, deadline);
        guard.finish(&result);
        result?;
        self.open(digest)
    }

    fn hydrate_until(&self, key: &ObjectKey, size: u64, caller_deadline: std::time::Instant) -> io::Result<()> {
        let digest = key.sha256.as_str();
        let dest = self.cache_root.join(digest);
        if verify_file(&dest, digest, size).is_ok() {
            lock(&self.verified).insert(digest.to_owned());
            return Ok(());
        }
        let now = std::time::Instant::now();
        if now >= caller_deadline {
            return Err(etimedout());
        }
        let configured = now + self.timeout;
        let caller_bounded = caller_deadline < configured;
        let budget = if caller_bounded { caller_deadline - now } else { self.timeout };
        let timeout_error: fn() -> io::Error = if caller_bounded { etimedout } else { eio };
        let mut staging = StagingFile::new(&self.cache_root, digest);
        let deadline = Instant::now() + budget;
        let future = self.fetcher.fetch(key, staging.path().to_path_buf(), size, deadline);
        let mut handle = self.runtime.spawn(future);
        let outcome = self.runtime.block_on(async { tokio::time::timeout(budget, &mut handle).await });
        match outcome {
            Ok(Ok(result)) => result?,
            Ok(Err(_)) => return Err(eio()),
            Err(_) => {
                let cleanup = staging.path().to_path_buf();
                self.runtime.spawn(async move {
                    let _ = handle.await;
                    let _ = tokio::fs::remove_file(&cleanup).await;
                });
                return Err(timeout_error());
            }
        }
        if verify_file(staging.path(), digest, size).is_err() {
            return Err(eio());
        }
        fs::set_permissions(staging.path(), fs::Permissions::from_mode(0o600)).map_err(|_| eio())?;
        let file =
            OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(staging.path()).map_err(|_| eio())?;
        file.sync_all().map_err(|_| eio())?;
        drop(file);
        fs::rename(staging.path(), &dest).map_err(|_| eio())?;
        staging.disarm();
        File::open(&self.cache_root).and_then(|directory| directory.sync_all()).map_err(|_| eio())?;
        lock(&self.verified).insert(digest.to_owned());
        Ok(())
    }

    fn open(&self, digest: &str) -> io::Result<File> {
        OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(self.cache_root.join(digest))
    }

    #[cfg(test)]
    pub(super) fn flight_waiters(&self, digest: &str) -> usize {
        lock(&self.flights)
            .get(digest)
            .map(|flight| flight.waiters.load(std::sync::atomic::Ordering::SeqCst))
            .unwrap_or(0)
    }

    #[cfg(test)]
    pub(super) fn in_flight(&self) -> usize {
        lock(&self.flights).len()
    }
}

struct StagingFile {
    path: PathBuf,
    armed: bool,
}

impl StagingFile {
    fn new(cache_root: &Path, digest: &str) -> Self {
        Self { path: cache_root.join(format!(".hydrate-{digest}-{}.part", Uuid::new_v4())), armed: true }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StagingFile {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub(super) fn eio() -> io::Error {
    io::Error::from_raw_os_error(libc::EIO)
}

fn etimedout() -> io::Error {
    io::Error::from_raw_os_error(libc::ETIMEDOUT)
}

fn verify_file(path: &Path, digest: &str, size: u64) -> io::Result<()> {
    let meta = fs::symlink_metadata(path).map_err(|_| eio())?;
    if !meta.file_type().is_file() || meta.len() != size {
        return Err(eio());
    }
    let mut file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path).map_err(|_| eio())?;
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|_| eio())?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read as u64).ok_or_else(eio)?;
        if total > size {
            return Err(eio());
        }
        hash.update(&buffer[..read]);
    }
    if total != size || hex::encode(hash.finalize()) != digest {
        return Err(eio());
    }
    Ok(())
}

pub(super) fn configured_timeout() -> Duration {
    std::env::var(HYDRATION_TIMEOUT_ENV)
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|millis| (1..=MAX_HYDRATION_TIMEOUT_MS).contains(millis))
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_HYDRATION_TIMEOUT)
}

fn io_runtime() -> io::Result<&'static Runtime> {
    static IO: OnceLock<Result<Runtime, String>> = OnceLock::new();
    IO.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("rootyard-lazy-io")
            .enable_all()
            .build()
            .map_err(|error| error.to_string())
    })
    .as_ref()
    .map_err(|error| io::Error::other(error.clone()))
}

#[cfg(test)]
pub(super) fn reader_entries(key: ObjectKey, size: usize) -> std::collections::BTreeMap<PathBuf, (ObjectKey, u64)> {
    std::collections::BTreeMap::from([(PathBuf::from("data.bin"), (key, size as u64))])
}
