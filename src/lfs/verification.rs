//! Bounded, identity-keyed verification cache for immutable LFS object bytes.
//!
//! A cache hit is only possible after opening the object with `O_NOFOLLOW` and
//! re-validating the full on-disk identity on every admission: repository and
//! promised size, device, inode, mtime/ctime nanoseconds, size, mode and link
//! count. A same-length tamper or an inode replacement therefore changes the
//! key and forces a fresh SHA-256 pass. Verification and download streaming use
//! the same open descriptor, so a path cannot be swapped between the two steps.
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashMap},
    fs::{File, Metadata, OpenOptions},
    io::{Read, Seek, SeekFrom},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Condvar, LazyLock, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;
use uuid::Uuid;

/// Upper bound for cached file identities. Entries are also time-bounded.
const MAX_CACHE_ENTRIES: usize = 4_096;
const CACHE_TTL: Duration = Duration::from_secs(15 * 60);
const MAX_CONCURRENT_VERIFICATIONS: usize = 8;

static VERIFICATION_CACHE: LazyLock<Mutex<CacheState>> = LazyLock::new(|| Mutex::new(CacheState::default()));
static VERIFICATION_SLOTS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_CONCURRENT_VERIFICATIONS)));

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct FileIdentity {
    data_root: PathBuf,
    repo_id: Uuid,
    oid: String,
    promised_size: u64,
    dev: u64,
    ino: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
    ctime_sec: i64,
    ctime_nsec: i64,
    size: u64,
    mode: u32,
    nlink: u64,
}

impl FileIdentity {
    fn new(data_root: &Path, repo_id: Uuid, oid: &str, promised_size: u64, meta: &Metadata) -> Self {
        Self {
            data_root: data_root.to_path_buf(),
            repo_id,
            oid: oid.to_owned(),
            promised_size,
            dev: meta.dev(),
            ino: meta.ino(),
            mtime_sec: meta.mtime(),
            mtime_nsec: meta.mtime_nsec(),
            ctime_sec: meta.ctime(),
            ctime_nsec: meta.ctime_nsec(),
            size: meta.len(),
            mode: meta.mode() & 0o7777,
            nlink: meta.nlink(),
        }
    }
}

#[derive(Clone, Copy)]
struct CacheRecord {
    verified_at: Instant,
    order_seq: u64,
}

/// The map and the ordering structure are one unique record set: every live
/// identity owns exactly one sequence number and therefore exactly one queue
/// slot. Reinserting or expiring removes the previous slot, so neither
/// structure can grow independently and a stale FIFO record can never evict a
/// freshly re-verified entry.
#[derive(Default)]
struct CacheState {
    entries: HashMap<FileIdentity, CacheRecord>,
    order: BTreeMap<u64, FileIdentity>,
    next_seq: u64,
}

impl CacheState {
    fn is_fresh(&mut self, identity: &FileIdentity, now: Instant) -> bool {
        let Some(record) = self.entries.get(identity).copied() else {
            return false;
        };
        if now.saturating_duration_since(record.verified_at) <= CACHE_TTL {
            return true;
        }
        self.entries.remove(identity);
        self.order.remove(&record.order_seq);
        false
    }

    fn insert(&mut self, identity: FileIdentity, now: Instant) {
        if let Some(previous) = self.entries.remove(&identity) {
            self.order.remove(&previous.order_seq);
        }
        let order_seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        self.entries.insert(identity.clone(), CacheRecord { verified_at: now, order_seq });
        self.order.insert(order_seq, identity);
        while self.entries.len() > MAX_CACHE_ENTRIES {
            let Some((_, oldest)) = self.order.pop_first() else {
                break;
            };
            self.entries.remove(&oldest);
        }
        debug_assert_eq!(self.entries.len(), self.order.len());
    }
}

fn cache() -> std::sync::MutexGuard<'static, CacheState> {
    VERIFICATION_CACHE.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Result shared by every caller that admitted the same exact file identity.
#[derive(Clone, Debug)]
enum FlightResult {
    Verified,
    Mismatch,
    Failed(String),
}

struct FlightState {
    result: Option<FlightResult>,
}

/// One digest pass per admitted identity. The leader hashes its descriptor;
/// followers wait on a deadline-bounded condition variable and never open the
/// path again, so they cannot observe a different inode. A cancelled async
/// request cannot abandon a published partial cache entry: the blocking leader
/// owns the flight and only inserts the cache after the identity re-check.
struct VerificationFlight {
    state: Mutex<FlightState>,
    finished: Condvar,
}

impl VerificationFlight {
    fn new() -> Self {
        Self { state: Mutex::new(FlightState { result: None }), finished: Condvar::new() }
    }

    fn wait(&self, deadline: Instant) -> Result<FlightResult> {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            if let Some(result) = state.result.clone() {
                return Ok(result);
            }
            let now = Instant::now();
            ensure!(now < deadline, "LFS integrity verification timed out");
            let (next, timeout) = self
                .finished
                .wait_timeout(state, deadline.saturating_duration_since(now))
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state = next;
            if timeout.timed_out() && state.result.is_none() {
                anyhow::bail!("LFS integrity verification timed out");
            }
        }
    }

    fn complete(&self, result: FlightResult) {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.result.is_none() {
            state.result = Some(result);
            self.finished.notify_all();
        }
    }
}

static VERIFICATION_FLIGHTS: LazyLock<Mutex<HashMap<FileIdentity, Arc<VerificationFlight>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn flights() -> std::sync::MutexGuard<'static, HashMap<FileIdentity, Arc<VerificationFlight>>> {
    VERIFICATION_FLIGHTS.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Leader ownership guard: even a panic inside the blocking digest pass wakes
/// followers with a failure and removes the map entry instead of wedging every
/// future reader of that identity behind a permanently incomplete flight.
struct FlightLeader {
    identity: FileIdentity,
    flight: Arc<VerificationFlight>,
    completed: bool,
}

impl FlightLeader {
    fn complete(mut self, result: FlightResult) {
        self.publish(result);
        self.completed = true;
    }

    fn publish(&self, result: FlightResult) {
        self.flight.complete(result);
        let mut flights = flights();
        if flights.get(&self.identity).is_some_and(|entry| Arc::ptr_eq(entry, &self.flight)) {
            flights.remove(&self.identity);
        }
    }
}

impl Drop for FlightLeader {
    fn drop(&mut self) {
        if !self.completed {
            self.publish(FlightResult::Failed("LFS verification worker panicked".to_owned()));
        }
    }
}

#[cfg(test)]
static FLIGHT_FOLLOWERS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
fn flight_follower_count() -> usize {
    FLIGHT_FOLLOWERS.load(std::sync::atomic::Ordering::Relaxed)
}

#[cfg(test)]
fn active_flight_count() -> usize {
    flights().len()
}

/// File metadata captured after the caller verified the bytes, before the
/// staging path is renamed to the immutable oid path. This assumes the trusted
/// service volume; it is not a defence against a hostile same-UID rewriter.
#[derive(Clone, Debug)]
pub(super) struct VerifiedWrite {
    dev: u64,
    ino: u64,
    mtime_sec: i64,
    mtime_nsec: i64,
    size: u64,
}

struct AdmittedFile {
    file: File,
    identity: FileIdentity,
}

fn layout_matches(meta: &Metadata, expected_size: u64) -> bool {
    meta.is_file() && meta.nlink() == 1 && (meta.mode() & 0o7777) == 0o600 && meta.len() == expected_size
}

fn admit(path: &Path, data_root: &Path, repo_id: Uuid, oid: &str, promised_size: u64) -> Result<Option<AdmittedFile>> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        // A symlink replacement is not an admissible object; let the cold path
        // decide whether a verified remote copy can atomically replace it.
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let meta = file.metadata()?;
    if !layout_matches(&meta, promised_size) {
        return Ok(None);
    }
    Ok(Some(AdmittedFile { file, identity: FileIdentity::new(data_root, repo_id, oid, promised_size, &meta) }))
}

#[cfg(test)]
static HASHED_BYTES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn hash_until(file: &mut File, expected_oid: &str, expected_size: u64, deadline: Instant) -> Result<bool> {
    file.seek(SeekFrom::Start(0))?;
    hash_gate_enter();
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buf = [0u8; 64 * 1024];
    loop {
        ensure!(Instant::now() < deadline, "LFS integrity verification timed out");
        let read = file.read(&mut buf)?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > expected_size {
            return Ok(false);
        }
        hasher.update(&buf[..read]);
        #[cfg(test)]
        HASHED_BYTES.fetch_add(read as u64, std::sync::atomic::Ordering::Relaxed);
    }
    if total != expected_size {
        return Ok(false);
    }
    Ok(hex::encode(hasher.finalize()) == expected_oid)
}

/// Hashes the admitted descriptor unless the exact file identity is already
/// cached. Concurrent callers that admitted the same identity share one digest
/// pass; followers wait with their own request deadline. Re-validates the
/// identity after hashing so a concurrent in-place change is never admitted
/// into the cache.
fn verify_admitted(
    admitted: &mut AdmittedFile,
    expected_oid: &str,
    expected_size: u64,
    deadline: Instant,
) -> Result<bool> {
    {
        let mut state = cache();
        if state.is_fresh(&admitted.identity, Instant::now()) {
            return Ok(true);
        }
    }
    let identity = admitted.identity.clone();
    let (flight, leader) = {
        let mut flights = flights();
        if let Some(existing) = flights.get(&identity) {
            (existing.clone(), None)
        } else {
            let flight = Arc::new(VerificationFlight::new());
            flights.insert(identity.clone(), flight.clone());
            let leader = FlightLeader { identity: identity.clone(), flight: flight.clone(), completed: false };
            (flight, Some(leader))
        }
    };
    let Some(leader) = leader else {
        #[cfg(test)]
        FLIGHT_FOLLOWERS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return match flight.wait(deadline)? {
            FlightResult::Verified => Ok(true),
            FlightResult::Mismatch => Ok(false),
            FlightResult::Failed(message) => Err(anyhow::anyhow!(message)),
        };
    };
    // A previous flight may have completed between the cache miss above and
    // the map lock. Re-check before spending a second hash pass.
    if cache().is_fresh(&identity, Instant::now()) {
        leader.complete(FlightResult::Verified);
        return Ok(true);
    }
    let result = (|| -> Result<bool> {
        let matches = hash_until(&mut admitted.file, expected_oid, expected_size, deadline)?;
        let after = FileIdentity::new(
            &identity.data_root,
            identity.repo_id,
            &identity.oid,
            identity.promised_size,
            &admitted.file.metadata()?,
        );
        if after != identity {
            // The file changed while it was read; never cache this observation.
            return Ok(false);
        }
        if matches {
            cache().insert(after, Instant::now());
        }
        Ok(matches)
    })();
    match result {
        Ok(true) => {
            leader.complete(FlightResult::Verified);
            Ok(true)
        }
        Ok(false) => {
            leader.complete(FlightResult::Mismatch);
            Ok(false)
        }
        Err(error) => {
            leader.complete(FlightResult::Failed(format!("{error:#}")));
            Err(error)
        }
    }
}

async fn acquire_verification_slot(deadline: tokio::time::Instant) -> Result<tokio::sync::OwnedSemaphorePermit> {
    let permit = tokio::time::timeout_at(deadline, VERIFICATION_SLOTS.clone().acquire_owned())
        .await
        .map_err(|_| anyhow::anyhow!("LFS verification concurrency wait timed out"))?;
    permit.context("LFS verification limiter closed")
}

#[cfg(test)]
fn available_verification_slots() -> usize {
    VERIFICATION_SLOTS.available_permits()
}

#[cfg(test)]
#[derive(Default)]
struct TestHashGateState {
    active: usize,
    hold: bool,
}

#[cfg(test)]
struct TestHashGate {
    state: Mutex<TestHashGateState>,
    changed: std::sync::Condvar,
}

#[cfg(test)]
impl TestHashGate {
    fn enter(&self) {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.hold {
            return;
        }
        state.active += 1;
        self.changed.notify_all();
        while state.hold {
            state = self.changed.wait(state).unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        state.active -= 1;
        self.changed.notify_all();
    }

    fn set_hold(&self, hold: bool) {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        state.hold = hold;
        self.changed.notify_all();
    }

    fn active(&self) -> usize {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).active
    }
}

#[cfg(test)]
static HASH_GATE: LazyLock<TestHashGate> = LazyLock::new(|| TestHashGate {
    state: Mutex::new(TestHashGateState::default()),
    changed: std::sync::Condvar::new(),
});

fn hash_gate_enter() {
    #[cfg(test)]
    HASH_GATE.enter();
}

/// Synchronous verification used by backup and checkout inventory code.
pub(super) fn verify_path_blocking(
    path: &Path,
    data_root: &Path,
    repo_id: Uuid,
    oid: &str,
    expected_size: u64,
    deadline: Instant,
) -> Result<bool> {
    match admit(path, data_root, repo_id, oid, expected_size)? {
        Some(mut admitted) => verify_admitted(&mut admitted, oid, expected_size, deadline),
        None => Ok(false),
    }
}

/// Bounded asynchronous local verification. Callers pass a path resolved by
/// the LFS storage facade; the same identity checks run inside the blocking
/// pool.
pub(crate) async fn verify_local(
    path: PathBuf,
    data_root: PathBuf,
    repo_id: Uuid,
    oid: String,
    expected_size: u64,
    deadline: tokio::time::Instant,
) -> Result<bool> {
    let permit = acquire_verification_slot(deadline).await?;
    let std_deadline = deadline.into_std();
    // The owned permit moves into the blocking closure. Cancelling the caller
    // drops the JoinHandle but not the running closure, so the concurrency
    // bound tracks actual work rather than the async request lifetime.
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        verify_path_blocking(&path, &data_root, repo_id, &oid, expected_size, std_deadline)
    })
    .await?
}

/// Opens and verifies the object once, then rewinds and returns the same
/// descriptor so the HTTP body cannot observe a different path target.
pub(crate) async fn open_verified_file(
    path: PathBuf,
    data_root: PathBuf,
    repo_id: Uuid,
    oid: String,
    expected_size: u64,
    deadline: tokio::time::Instant,
) -> Result<Option<File>> {
    let permit = acquire_verification_slot(deadline).await?;
    let std_deadline = deadline.into_std();
    tokio::task::spawn_blocking(move || -> Result<Option<File>> {
        let _permit = permit;
        let Some(mut admitted) = admit(&path, &data_root, repo_id, &oid, expected_size)? else {
            return Ok(None);
        };
        if !verify_admitted(&mut admitted, &oid, expected_size, std_deadline)? {
            return Ok(None);
        }
        // verify_admitted always rewinds before hashing; seek once more so the
        // caller streams from offset zero on this exact descriptor.
        admitted.file.seek(SeekFrom::Start(0))?;
        Ok(Some(admitted.file))
    })
    .await?
}

/// Captures the identity of a fully written, digest-verified staging file.
pub(super) fn capture_verified_write(meta: &Metadata, expected_size: u64) -> Result<VerifiedWrite> {
    ensure!(layout_matches(meta, expected_size), "LFS staging file failed layout validation");
    Ok(VerifiedWrite {
        dev: meta.dev(),
        ino: meta.ino(),
        mtime_sec: meta.mtime(),
        mtime_nsec: meta.mtime_nsec(),
        size: meta.len(),
    })
}

/// Records a verified write after rename. The destination must still be the
/// same inode with the same size and mtime that was hashed, which detects a
/// replace or in-place rewrite racing the publication rename on the trusted
/// service volume (not a hostile same-UID rewriter). Only then is the
/// new identity admitted to the cache; subsequent readers still re-validate it.
pub(super) fn record_published_write(
    path: &Path,
    expected: &VerifiedWrite,
    data_root: &Path,
    repo_id: Uuid,
    oid: &str,
    promised_size: u64,
) -> Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .context("published LFS object is not readable")?;
    let meta = file.metadata()?;
    ensure!(layout_matches(&meta, promised_size), "published LFS object failed layout validation");
    let unchanged = meta.dev() == expected.dev
        && meta.ino() == expected.ino
        && meta.len() == expected.size
        && meta.mtime() == expected.mtime_sec
        && meta.mtime_nsec() == expected.mtime_nsec;
    if !unchanged {
        // A concurrent publisher of the same immutable oid may have renamed an
        // equivalent verified file over the destination. Fall back to a full
        // digest pass; a same-content race succeeds, a tamper fails closed.
        return if verify_path_blocking(
            path,
            data_root,
            repo_id,
            oid,
            promised_size,
            Instant::now() + Duration::from_secs(60),
        )? {
            Ok(())
        } else {
            anyhow::bail!("published LFS object changed during publication")
        };
    }
    let identity = FileIdentity::new(data_root, repo_id, oid, promised_size, &meta);
    cache().insert(identity, Instant::now());
    Ok(())
}

#[cfg(test)]
#[path = "verification_tests.rs"]
mod tests;
