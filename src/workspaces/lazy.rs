//! Verified remote baseline objects hydrated by normal FUSE reads.
//!
//! Worktree bytes from committed remote checkpoints stay sparse in the lower
//! layer. The first FUSE read of a file hydrates its immutable blob into a
//! content-addressed local cache. Concurrent readers of one blob share a single
//! bounded CAS request, and an unreachable store fails the request with `EIO`
//! instead of blocking the FUSE session indefinitely.
//!
//! `ROOTYARD_WORKSPACE_LAZY_TIMEOUT_MS` bounds every per-blob remote request
//! (default 8 seconds, maximum 60 seconds).
use super::{mounts, remote};
use crate::{
    AppState, Error,
    storage::remote_objects::{ObjectKey, RemoteObjectStore},
    workspace_lab::core,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fs::{self, File, OpenOptions},
    future::Future,
    io::{self, Read, Write},
    os::unix::{
        ffi::OsStringExt,
        fs::{OpenOptionsExt, PermissionsExt, symlink},
    },
    path::{Path, PathBuf},
    pin::Pin,
    sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock},
    time::Duration,
};
use tokio::{runtime::Runtime, time::Instant};
use uuid::Uuid;

const DEFAULT_HYDRATION_TIMEOUT: Duration = Duration::from_secs(8);
const MAX_HYDRATION_TIMEOUT_MS: u64 = 60_000;
// Local verification and publication of one bounded remote fetch are bounded
// separately. A follower stops waiting after this grace period even if the
// leader is stuck in an uninterruptible local filesystem operation.
const HYDRATION_PUBLICATION_GRACE: Duration = Duration::from_secs(10);
const HYDRATION_TIMEOUT_ENV: &str = "ROOTYARD_WORKSPACE_LAZY_TIMEOUT_MS";

type FetchFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'static>>;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LazyManifest {
    schema: u32,
    checkpoint_id: Uuid,
    tenant_id: Uuid,
    entries: Vec<core::Entry>,
}

fn manifest_path(root: &Path, id: Uuid) -> PathBuf {
    root.join("workspace-service/lazy").join(format!("{id}.json"))
}

fn read_manifest(path: &Path) -> Result<LazyManifest, Error> {
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path).map_err(Error::internal)?;
    if !file.metadata().map_err(Error::internal)?.is_file() {
        return Err(Error::bad_request());
    }
    let mut raw = Vec::new();
    file.take(16 * 1024 * 1024 + 1).read_to_end(&mut raw).map_err(Error::internal)?;
    if raw.len() > 16 * 1024 * 1024 {
        return Err(Error::bad_request());
    }
    let manifest: LazyManifest = serde_json::from_slice(&raw).map_err(Error::internal)?;
    if manifest.schema != 1 || manifest.tenant_id.is_nil() {
        return Err(Error::bad_request());
    }
    core::validate_entries(&manifest.entries).map_err(Error::internal)?;
    Ok(manifest)
}

/// Build a sparse immutable lower tree from a verified committed manifest.
/// Native Git metadata is materialized; worktree bytes remain remote.
pub(super) async fn prepare(state: &AppState, id: Uuid, cp: Uuid, repo: Uuid, tenant: Uuid) -> Result<(), Error> {
    let dest = mounts::lower_path(state, id);
    let sidecar = manifest_path(&state.storage.root, id);
    if dest.exists() {
        let old = read_manifest(&sidecar)?;
        if old.checkpoint_id == cp && old.tenant_id == tenant && dest.join(".git").is_dir() {
            return Ok(());
        }
        return Err(Error::internal("conflicting sparse workspace baseline"));
    }
    let remote = remote::load_manifest(state, cp, repo, tenant).await?;
    if remote.entries.len() > core::MAX_ENTRIES {
        return Err(Error::bad_request());
    }
    let mut paths = BTreeSet::new();
    let mut symlinks = BTreeSet::new();
    let mut total = 0u64;
    for item in &remote.entries {
        let rel = core::decode_path(&item.path_base64).map_err(|_| Error::bad_request())?;
        if !paths.insert(rel.clone()) || item.mode > 0o777 || item.size > core::MAX_BYTES {
            return Err(Error::bad_request());
        }
        total = total.checked_add(item.size).ok_or_else(Error::bad_request)?;
        if total > core::MAX_BYTES {
            return Err(Error::bad_request());
        }
        remote::key(tenant, &item.sha256)?;
        if item.kind == "symlink" {
            symlinks.insert(rel);
        } else if item.kind != "file" || item.target_base64.is_some() {
            return Err(Error::bad_request());
        }
    }
    for path in &paths {
        if symlinks.iter().any(|link| path != link && path.starts_with(link)) {
            return Err(Error::bad_request());
        }
    }
    let parent = dest.parent().ok_or_else(Error::bad_request)?;
    fs::create_dir_all(parent).map_err(Error::internal)?;
    let stage = parent.join(format!(".lazy-{}", Uuid::new_v4()));
    fs::create_dir(&stage).map_err(Error::internal)?;
    let store = remote::remote_store(state)?;
    let result = async {
        let mut entries = Vec::with_capacity(remote.entries.len());
        for item in remote.entries {
            let rel = core::decode_path(&item.path_base64).map_err(|_| Error::bad_request())?;
            let to = stage.join(&rel);
            fs::create_dir_all(to.parent().ok_or_else(Error::bad_request)?).map_err(Error::internal)?;
            if item.kind == "symlink" {
                let target = STANDARD
                    .decode(item.target_base64.as_deref().ok_or_else(Error::bad_request)?)
                    .map_err(|_| Error::bad_request())?;
                if target.len() as u64 != item.size || hex::encode(Sha256::digest(&target)) != item.sha256 {
                    return Err(Error::bad_request());
                }
                let target = PathBuf::from(std::ffi::OsString::from_vec(target));
                core::validate_symlink(&stage, &rel, &target).map_err(Error::internal)?;
                symlink(target, &to).map_err(Error::internal)?;
            } else if rel.starts_with(".git") {
                store
                    .get_to_file(
                        &remote::key(tenant, &item.sha256)?,
                        &to,
                        item.size,
                        tokio::time::Instant::now() + Duration::from_secs(120),
                    )
                    .await
                    .map_err(Error::internal)?;
                fs::set_permissions(&to, fs::Permissions::from_mode(item.mode)).map_err(Error::internal)?;
            } else {
                let file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(item.mode)
                    .custom_flags(libc::O_NOFOLLOW)
                    .open(&to)
                    .map_err(Error::internal)?;
                file.set_len(item.size).map_err(Error::internal)?;
                file.set_permissions(fs::Permissions::from_mode(item.mode)).map_err(Error::internal)?;
                file.sync_all().map_err(Error::internal)?;
            }
            entries.push(core::Entry {
                path_base64: item.path_base64,
                kind: item.kind,
                mode: item.mode,
                size: item.size,
                sha256: item.sha256,
            });
        }
        for path in [".git", ".git/objects", ".git/refs"] {
            fs::create_dir_all(stage.join(path)).map_err(Error::internal)?;
        }
        let manifest = LazyManifest { schema: 1, checkpoint_id: cp, tenant_id: tenant, entries };
        let raw = serde_json::to_vec(&manifest).map_err(Error::internal)?;
        let sidecar_dir = sidecar.parent().ok_or_else(Error::bad_request)?;
        fs::create_dir_all(sidecar_dir).map_err(Error::internal)?;
        let temp = sidecar_dir.join(format!(".lazy-{}", Uuid::new_v4()));
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)
            .map_err(Error::internal)?;
        output.write_all(&raw).map_err(Error::internal)?;
        output.sync_all().map_err(Error::internal)?;
        core::sync_tree(&stage).map_err(Error::internal)?;
        fs::rename(&temp, &sidecar).map_err(Error::internal)?;
        fs::rename(&stage, &dest).map_err(Error::internal)?;
        File::open(parent).and_then(|file| file.sync_all()).map_err(Error::internal)?;
        Ok::<(), Error>(())
    }
    .await;
    if result.is_err() {
        let _ = fs::remove_dir_all(&stage);
    }
    result
}

fn fingerprint_manifest(root: &Path, id: Uuid) -> Result<Option<LazyManifest>, Error> {
    let path = manifest_path(root, id);
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(read_manifest(&path)?))
}

/// Merge immutable baseline metadata with confined CoW entries. This avoids
/// downloading every remote blob during the two-second capture scan.
pub(super) fn fingerprint(path: &Path) -> Result<Option<String>, Error> {
    let Some(id) = path.file_name().and_then(|name| name.to_str()).and_then(|name| Uuid::parse_str(name).ok()) else {
        return Ok(None);
    };
    let Some(kind) = path.parent().and_then(|p| p.file_name()).and_then(|s| s.to_str()) else {
        return Ok(None);
    };
    if kind != "mounts" && kind != "workspaces" {
        return Ok(None);
    }
    let root = path.parent().and_then(Path::parent).and_then(Path::parent).ok_or_else(Error::bad_request)?;
    let Some(manifest) = fingerprint_manifest(root, id)? else {
        return Ok(None);
    };
    let upper = root.join("workspace-service/uppers").join(id.to_string());
    let whiteout_file = upper.join(".rootyard-whiteouts.json");
    let whiteouts: BTreeSet<PathBuf> = if whiteout_file.exists() {
        serde_json::from_slice::<Vec<String>>(&fs::read(whiteout_file).map_err(Error::internal)?)
            .map_err(Error::internal)?
            .into_iter()
            .map(PathBuf::from)
            .collect()
    } else {
        BTreeSet::new()
    };
    let hidden = |path: &Path| whiteouts.iter().any(|w| path == w || path.starts_with(w));
    let mut entries = BTreeMap::<PathBuf, core::Entry>::new();
    for entry in manifest.entries {
        let path = core::decode_path(&entry.path_base64).map_err(Error::internal)?;
        if !hidden(&path) {
            entries.insert(path, entry);
        }
    }
    if upper.is_dir() {
        for entry in core::inventory(&upper).map_err(Error::internal)? {
            let rel = core::decode_path(&entry.path_base64).map_err(Error::internal)?;
            if !rel.as_os_str().as_encoded_bytes().starts_with(b".rootyard-whiteouts.") && !hidden(&rel) {
                entries.insert(rel, entry);
            }
        }
    }
    let raw = serde_json::to_vec(&entries.into_values().collect::<Vec<_>>()).map_err(Error::internal)?;
    Ok(Some(hex::encode(Sha256::digest(raw))))
}

/// Blocking facade used by FUSE callbacks to obtain a verified local file.
pub(crate) struct Reader {
    entries: BTreeMap<PathBuf, (ObjectKey, u64)>,
    hydrator: Hydrator,
}

impl Reader {
    pub(super) fn open(state: &AppState, id: Uuid) -> Result<Option<Arc<Self>>, Error> {
        let Some(manifest) = fingerprint_manifest(&state.storage.root, id)? else {
            return Ok(None);
        };
        let mut entries = BTreeMap::new();
        let mut sizes = HashMap::<String, u64>::new();
        for entry in manifest.entries {
            let rel = core::decode_path(&entry.path_base64).map_err(Error::internal)?;
            if entry.kind != "file" || rel.starts_with(".git") {
                continue;
            }
            let key = remote::key(manifest.tenant_id, &entry.sha256)?;
            if let Some(prior) = sizes.insert(key.sha256.clone(), entry.size) {
                if prior != entry.size {
                    return Err(Error::bad_request());
                }
            }
            entries.insert(rel, (key, entry.size));
        }
        let cache_root = state.storage.root.join("workspace-service/lazy-cache").join(id.to_string());
        let fetcher = Arc::new(RemoteFetcher { store: Arc::new(remote::remote_store(state)?) });
        let hydrator = Hydrator::new(cache_root, fetcher, configured_timeout()).map_err(Error::internal)?;
        Ok(Some(Arc::new(Self { entries, hydrator })))
    }

    pub(crate) fn file(&self, relative: &Path) -> io::Result<Option<File>> {
        let Some((key, size)) = self.entries.get(relative) else {
            return Ok(None);
        };
        self.hydrator.ensure(key, *size).map(Some)
    }

    pub(super) fn prewarm(&self, paths: &[PathBuf]) -> io::Result<(usize, u64)> {
        let mut count = 0;
        let mut bytes = 0;
        for path in paths {
            let Some((_, size)) = self.entries.get(path) else {
                return Err(io::Error::from_raw_os_error(libc::ENOENT));
            };
            self.file(path)?;
            count += 1;
            bytes += size;
        }
        Ok((count, bytes))
    }
}

impl crate::workspace_lab::fuse_mount::LazySource for Reader {
    fn file(&self, relative: &Path) -> io::Result<Option<File>> {
        Reader::file(self, relative)
    }
}

/// A single remote request shared by every concurrent reader of one blob.
struct Flight {
    outcome: Mutex<Option<i32>>,
    done: Condvar,
    deadline: std::time::Instant,
    #[cfg(test)]
    waiters: std::sync::atomic::AtomicUsize,
}

impl Flight {
    fn new(deadline: std::time::Instant) -> Self {
        Self {
            outcome: Mutex::new(None),
            done: Condvar::new(),
            deadline,
            #[cfg(test)]
            waiters: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn finish(&self, code: i32) {
        *lock(&self.outcome) = Some(code);
        self.done.notify_all();
    }

    fn wait(&self) -> io::Result<()> {
        #[cfg(test)]
        self.waiters.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let result = self.wait_bounded();
        #[cfg(test)]
        self.waiters.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
        result
    }

    fn wait_bounded(&self) -> io::Result<()> {
        let mut outcome = lock(&self.outcome);
        loop {
            if let Some(code) = *outcome {
                return if code == 0 { Ok(()) } else { Err(io::Error::from_raw_os_error(code)) };
            }
            let now = std::time::Instant::now();
            if now >= self.deadline {
                return Err(eio());
            }
            let (guard, timed_out) =
                self.done.wait_timeout(outcome, self.deadline - now).unwrap_or_else(std::sync::PoisonError::into_inner);
            outcome = guard;
            if timed_out.timed_out() && outcome.is_none() {
                return Err(eio());
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

trait BlobFetcher: Send + Sync {
    fn fetch(&self, key: &ObjectKey, staging: PathBuf, expected_size: u64, deadline: Instant) -> FetchFuture;
}

struct RemoteFetcher {
    store: Arc<RemoteObjectStore>,
}

impl BlobFetcher for RemoteFetcher {
    fn fetch(&self, key: &ObjectKey, staging: PathBuf, expected_size: u64, deadline: Instant) -> FetchFuture {
        let store = self.store.clone();
        let key = key.clone();
        Box::pin(async move {
            // The shared publisher writes a sibling temporary file, checks the
            // digest and length, fsyncs, and atomically renames into place.
            store.get_to_file(&key, &staging, expected_size, deadline).await.map_err(|_| eio())
        })
    }
}

struct Hydrator {
    cache_root: PathBuf,
    fetcher: Arc<dyn BlobFetcher>,
    runtime: &'static Runtime,
    timeout: Duration,
    verified: Mutex<HashSet<String>>,
    flights: Mutex<HashMap<String, Arc<Flight>>>,
}

impl Hydrator {
    fn new(cache_root: PathBuf, fetcher: Arc<dyn BlobFetcher>, timeout: Duration) -> io::Result<Self> {
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

    fn ensure(&self, key: &ObjectKey, size: u64) -> io::Result<File> {
        let digest = key.sha256.as_str();
        // Full digest validation happens once per process for this
        // service-owned cache; the fast path still re-checks the length.
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
                    let deadline = std::time::Instant::now() + self.timeout + HYDRATION_PUBLICATION_GRACE;
                    let flight = Arc::new(Flight::new(deadline));
                    flights.insert(digest.to_owned(), flight.clone());
                    (flight, true)
                }
            }
        };
        if !leader {
            flight.wait()?;
            return self.open(digest);
        }
        let mut guard = LeaderGuard::new(self, digest.to_owned(), flight);
        let result = self.hydrate(key, size);
        guard.finish(&result);
        result?;
        self.open(digest)
    }

    fn hydrate(&self, key: &ObjectKey, size: u64) -> io::Result<()> {
        let digest = key.sha256.as_str();
        let dest = self.cache_root.join(digest);
        if verify_file(&dest, digest, size).is_ok() {
            lock(&self.verified).insert(digest.to_owned());
            return Ok(());
        }
        let mut staging = StagingFile::new(&self.cache_root, digest);
        let deadline = Instant::now() + self.timeout;
        let future = self.fetcher.fetch(key, staging.path().to_path_buf(), size, deadline);
        let mut handle = self.runtime.spawn(future);
        let timeout = self.timeout;
        let outcome = self.runtime.block_on(async { tokio::time::timeout(timeout, &mut handle).await });
        match outcome {
            Ok(Ok(result)) => result?,
            Ok(Err(_)) => return Err(eio()),
            Err(_) => {
                // The request already failed closed. Keep the detached task's
                // completion off the staging path so a late rename cannot
                // resurrect a temporary file after this guard removes it.
                let cleanup = staging.path().to_path_buf();
                self.runtime.spawn(async move {
                    let _ = handle.await;
                    let _ = tokio::fs::remove_file(&cleanup).await;
                });
                return Err(eio());
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
    fn flight_waiters(&self, digest: &str) -> usize {
        lock(&self.flights)
            .get(digest)
            .map(|flight| flight.waiters.load(std::sync::atomic::Ordering::SeqCst))
            .unwrap_or(0)
    }

    #[cfg(test)]
    fn in_flight(&self) -> usize {
        lock(&self.flights).len()
    }
}

/// Deletes a partially fetched staging file unless publication disarms it.
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

fn eio() -> io::Error {
    io::Error::from_raw_os_error(libc::EIO)
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

fn configured_timeout() -> Duration {
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
mod tests {
    use super::*;
    use std::{
        os::unix::fs::FileExt,
        sync::atomic::{AtomicUsize, Ordering},
        thread,
        time::{Duration as StdDuration, Instant as StdInstant},
    };

    #[derive(Clone)]
    enum Behavior {
        Publish(Vec<u8>),
        Wait { bytes: Vec<u8>, release: Arc<tokio::sync::Notify> },
        Pending,
    }

    struct TestFetcher {
        calls: Arc<AtomicUsize>,
        behavior: Behavior,
    }

    impl BlobFetcher for TestFetcher {
        fn fetch(&self, _key: &ObjectKey, staging: PathBuf, _expected_size: u64, _deadline: Instant) -> FetchFuture {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let behavior = self.behavior.clone();
            Box::pin(async move {
                match behavior {
                    Behavior::Publish(bytes) => {
                        tokio::fs::write(&staging, bytes).await.map_err(|_| eio())?;
                    }
                    Behavior::Wait { bytes, release } => {
                        release.notified().await;
                        tokio::fs::write(&staging, bytes).await.map_err(|_| eio())?;
                    }
                    Behavior::Pending => std::future::pending::<()>().await,
                }
                Ok(())
            })
        }
    }

    fn key_for(bytes: &[u8]) -> ObjectKey {
        ObjectKey::new(Uuid::new_v4(), "workspace", &hex::encode(Sha256::digest(bytes))).unwrap()
    }

    fn reader_for(
        root: &Path,
        key: ObjectKey,
        size: usize,
        fetcher: Arc<dyn BlobFetcher>,
        timeout: Duration,
    ) -> Arc<Reader> {
        let entries = BTreeMap::from([(PathBuf::from("data.bin"), (key, size as u64))]);
        let hydrator = Hydrator::new(root.join("cache"), fetcher, timeout).unwrap();
        Arc::new(Reader { entries, hydrator })
    }

    fn write_object(objects: &Path, key: &ObjectKey, bytes: &[u8]) {
        let path = objects.join(key.path());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    fn names(directory: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    fn read_all(file: &File, size: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; size];
        file.read_exact_at(&mut bytes, 0).unwrap();
        bytes
    }

    #[test]
    fn remote_fetcher_publishes_verified_blob_and_cleans_staging() {
        let root = tempfile::tempdir().unwrap();
        let bytes = b"remote workspace baseline\n".repeat(4096);
        let key = key_for(&bytes);
        let objects = root.path().join("objects");
        write_object(&objects, &key, &bytes);
        let cache = root.path().join("cache");
        let hydrator = Hydrator::new(
            cache.clone(),
            Arc::new(RemoteFetcher { store: Arc::new(RemoteObjectStore::Local(objects)) }),
            Duration::from_secs(5),
        )
        .unwrap();
        // A corrupt cached copy must be replaced, not served.
        fs::write(cache.join(&key.sha256), b"corrupt").unwrap();
        let file = hydrator.ensure(&key, bytes.len() as u64).unwrap();
        assert_eq!(read_all(&file, bytes.len()), bytes);
        assert_eq!(fs::read(cache.join(&key.sha256)).unwrap(), bytes);
        assert_eq!(names(&cache), vec![key.sha256.clone()]);
        let slice = &bytes[100..200];
        let mut bytes_read = vec![0u8; slice.len()];
        file.read_exact_at(&mut bytes_read, 100).unwrap();
        assert_eq!(bytes_read, slice);
        drop(file);
        // A removed cache entry is hydrated again instead of failing forever.
        fs::remove_file(cache.join(&key.sha256)).unwrap();
        let file = hydrator.ensure(&key, bytes.len() as u64).unwrap();
        assert_eq!(read_all(&file, bytes.len()), bytes);
    }

    #[test]
    fn reader_rejects_corrupt_remote_blob_then_recovers() {
        let root = tempfile::tempdir().unwrap();
        let bytes = b"expected remote bytes\n".repeat(1024);
        let key = key_for(&bytes);
        let objects = root.path().join("objects");
        write_object(&objects, &key, &vec![b'x'; bytes.len()]);
        let fetcher = Arc::new(RemoteFetcher { store: Arc::new(RemoteObjectStore::Local(objects.clone())) });
        let reader = reader_for(root.path(), key.clone(), bytes.len(), fetcher, Duration::from_secs(5));
        let error = reader.file(Path::new("data.bin")).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        assert!(!root.path().join("cache").join(&key.sha256).exists());
        assert!(names(&root.path().join("cache")).is_empty());
        assert_eq!(reader.hydrator.in_flight(), 0);

        write_object(&objects, &key, &bytes);
        let file = reader.file(Path::new("data.bin")).unwrap().unwrap();
        assert_eq!(read_all(&file, bytes.len()), bytes);
    }

    #[test]
    fn reader_rejects_truncated_remote_blob() {
        let root = tempfile::tempdir().unwrap();
        let bytes = b"expected remote bytes\n".repeat(1024);
        let key = key_for(&bytes);
        let objects = root.path().join("objects");
        write_object(&objects, &key, &bytes[..bytes.len() - 1]);
        let fetcher = Arc::new(RemoteFetcher { store: Arc::new(RemoteObjectStore::Local(objects)) });
        let reader = reader_for(root.path(), key.clone(), bytes.len(), fetcher, Duration::from_secs(5));
        let error = reader.file(Path::new("data.bin")).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        assert!(names(&root.path().join("cache")).is_empty());
    }

    #[test]
    fn singleflight_shares_one_remote_fetch() {
        let root = tempfile::tempdir().unwrap();
        let bytes = vec![0x5au8; 256 * 1024];
        let calls = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(tokio::sync::Notify::new());
        let fetcher = Arc::new(TestFetcher {
            calls: calls.clone(),
            behavior: Behavior::Wait { bytes: bytes.clone(), release: release.clone() },
        });
        let key = key_for(&bytes);
        let digest = key.sha256.clone();
        let reader = reader_for(root.path(), key, bytes.len(), fetcher, Duration::from_secs(5));
        let expected = bytes.clone();
        thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    let reader = reader.clone();
                    let expected = expected.clone();
                    scope.spawn(move || {
                        let file = reader.file(Path::new("data.bin")).unwrap().unwrap();
                        assert_eq!(read_all(&file, expected.len()), expected);
                    })
                })
                .collect();
            let deadline = StdInstant::now() + StdDuration::from_secs(5);
            while reader.hydrator.flight_waiters(&digest) != 7 {
                if StdInstant::now() >= deadline {
                    release.notify_one();
                    panic!("concurrent readers did not join the inflight fetch");
                }
                thread::sleep(StdDuration::from_millis(5));
            }
            release.notify_one();
            for handle in handles {
                handle.join().unwrap();
            }
        });
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(names(&root.path().join("cache")), vec![digest]);
    }

    #[test]
    fn independent_blobs_hydrate_in_parallel() {
        struct DigestFetcher {
            bytes: BTreeMap<String, Vec<u8>>,
            blocked: String,
            started: Arc<std::sync::atomic::AtomicBool>,
            release: Arc<tokio::sync::Notify>,
        }

        impl BlobFetcher for DigestFetcher {
            fn fetch(&self, key: &ObjectKey, staging: PathBuf, _expected_size: u64, _deadline: Instant) -> FetchFuture {
                let bytes = self.bytes.get(&key.sha256).cloned().unwrap();
                let blocked = self.blocked == key.sha256;
                let started = self.started.clone();
                let release = self.release.clone();
                Box::pin(async move {
                    if blocked {
                        started.store(true, Ordering::SeqCst);
                        release.notified().await;
                    }
                    tokio::fs::write(&staging, bytes).await.map_err(|_| eio())?;
                    Ok(())
                })
            }
        }

        let root = tempfile::tempdir().unwrap();
        let first = b"first blob\n".repeat(2048);
        let second = b"second blob\n".repeat(2048);
        let first_key = key_for(&first);
        let second_key = key_for(&second);
        let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let release = Arc::new(tokio::sync::Notify::new());
        let fetcher = Arc::new(DigestFetcher {
            bytes: BTreeMap::from([
                (first_key.sha256.clone(), first.clone()),
                (second_key.sha256.clone(), second.clone()),
            ]),
            blocked: first_key.sha256.clone(),
            started: started.clone(),
            release: release.clone(),
        });
        let entries = BTreeMap::from([
            (PathBuf::from("first.bin"), (first_key, first.len() as u64)),
            (PathBuf::from("second.bin"), (second_key, second.len() as u64)),
        ]);
        let hydrator = Hydrator::new(root.path().join("cache"), fetcher, Duration::from_secs(5)).unwrap();
        let reader = Arc::new(Reader { entries, hydrator });
        thread::scope(|scope| {
            let first_reader = reader.clone();
            let first_thread = scope.spawn(move || first_reader.file(Path::new("first.bin")).unwrap().unwrap());
            let deadline = StdInstant::now() + StdDuration::from_secs(2);
            while !started.load(Ordering::SeqCst) {
                if StdInstant::now() >= deadline {
                    release.notify_one();
                    panic!("first blob fetch did not start");
                }
                thread::sleep(StdDuration::from_millis(5));
            }
            let (sender, receiver) = std::sync::mpsc::channel();
            let second_reader = reader.clone();
            let second_size = second.len();
            scope.spawn(move || {
                let file = second_reader.file(Path::new("second.bin")).unwrap().unwrap();
                sender.send(read_all(&file, second_size)).unwrap();
            });
            let second_bytes = match receiver.recv_timeout(StdDuration::from_secs(2)) {
                Ok(bytes) => bytes,
                Err(error) => {
                    release.notify_one();
                    panic!("independent blob was serialized behind another hydration: {error}");
                }
            };
            assert_eq!(second_bytes, second);
            release.notify_one();
            first_thread.join().unwrap();
        });
    }

    #[test]
    fn follower_wait_is_bounded_when_leader_stalls() {
        let flight = Flight::new(StdInstant::now() + StdDuration::from_millis(60));
        let started = StdInstant::now();
        let error = flight.wait().unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        assert!(started.elapsed() < StdDuration::from_secs(1));
    }

    #[test]
    fn timed_out_fetch_cannot_resurrect_staging_file() {
        let root = tempfile::tempdir().unwrap();
        let bytes = b"late published bytes
"
        .repeat(512);
        let key = key_for(&bytes);
        let release = Arc::new(tokio::sync::Notify::new());
        let calls = Arc::new(AtomicUsize::new(0));
        let fetcher = Arc::new(TestFetcher {
            calls,
            behavior: Behavior::Wait { bytes: bytes.clone(), release: release.clone() },
        });
        let reader = reader_for(root.path(), key.clone(), bytes.len(), fetcher, Duration::from_millis(100));
        let error = reader.file(Path::new("data.bin")).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        let cache = root.path().join("cache");
        release.notify_one();
        let deadline = StdInstant::now() + StdDuration::from_secs(2);
        while !names(&cache).is_empty() {
            if StdInstant::now() >= deadline {
                panic!("timed-out fetch left a staging file: {:?}", names(&cache));
            }
            thread::sleep(StdDuration::from_millis(10));
        }
        assert_eq!(reader.hydrator.in_flight(), 0);
        assert!(!cache.join(&key.sha256).exists());
    }

    #[test]
    fn offline_fetch_times_out_with_eio_and_releases_flight() {
        let root = tempfile::tempdir().unwrap();
        let bytes = b"offline blob".to_vec();
        let calls = Arc::new(AtomicUsize::new(0));
        let fetcher = Arc::new(TestFetcher { calls, behavior: Behavior::Pending });
        let key = key_for(&bytes);
        let reader = reader_for(root.path(), key.clone(), bytes.len(), fetcher, Duration::from_millis(120));
        let started = StdInstant::now();
        let error = reader.file(Path::new("data.bin")).unwrap_err();
        let elapsed = started.elapsed();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        assert!(elapsed < StdDuration::from_secs(2), "hydration blocked for {elapsed:?}");
        assert!(names(&root.path().join("cache")).is_empty());
        assert_eq!(reader.hydrator.in_flight(), 0);
        assert!(!root.path().join("cache").join(&key.sha256).exists());
    }

    #[test]
    fn staging_stays_private_until_verified_and_published() {
        struct StagingFetcher {
            cache: PathBuf,
            digest: String,
            bytes: Vec<u8>,
        }

        impl BlobFetcher for StagingFetcher {
            fn fetch(
                &self,
                _key: &ObjectKey,
                staging: PathBuf,
                _expected_size: u64,
                _deadline: Instant,
            ) -> FetchFuture {
                let cache = self.cache.clone();
                let digest = self.digest.clone();
                let bytes = self.bytes.clone();
                Box::pin(async move {
                    assert_eq!(staging.parent(), Some(cache.as_path()));
                    assert!(!cache.join(&digest).exists(), "final path was visible before publication");
                    tokio::fs::write(&staging, bytes).await.map_err(|_| eio())?;
                    Ok(())
                })
            }
        }

        let root = tempfile::tempdir().unwrap();
        let bytes = b"staged workspace bytes\n".repeat(1024);
        let key = key_for(&bytes);
        let cache = root.path().join("cache");
        let hydrator = Hydrator::new(
            cache.clone(),
            Arc::new(StagingFetcher { cache: cache.clone(), digest: key.sha256.clone(), bytes: bytes.clone() }),
            Duration::from_secs(5),
        )
        .unwrap();
        let file = hydrator.ensure(&key, bytes.len() as u64).unwrap();
        assert_eq!(read_all(&file, bytes.len()), bytes);
        assert_eq!(names(&cache), vec![key.sha256.clone()]);
    }

    #[test]
    fn failed_verification_never_publishes_final_path() {
        let root = tempfile::tempdir().unwrap();
        let bytes = b"verified workspace bytes\n".repeat(512);
        let key = key_for(&bytes);
        let calls = Arc::new(AtomicUsize::new(0));
        let fetcher =
            Arc::new(TestFetcher { calls: calls.clone(), behavior: Behavior::Publish(vec![b'y'; bytes.len()]) });
        let cache = root.path().join("cache");
        let hydrator = Hydrator::new(cache.clone(), fetcher, Duration::from_secs(5)).unwrap();
        let error = hydrator.ensure(&key, bytes.len() as u64).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(!cache.join(&key.sha256).exists());
        assert!(names(&cache).is_empty());
        assert_eq!(hydrator.in_flight(), 0);
    }
}
