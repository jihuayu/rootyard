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
mod tests {
    use super::*;
    use std::{fs, os::unix::fs::PermissionsExt, sync::atomic::Ordering};

    static TEST_SERIAL: Mutex<()> = Mutex::new(());

    fn serial() -> std::sync::MutexGuard<'static, ()> {
        TEST_SERIAL.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn fixture(payload: &[u8]) -> (PathBuf, PathBuf, String) {
        let root = std::env::temp_dir().join(format!("rootyard-lfs-verify-{}", Uuid::new_v4()));
        let dir = root.join("lfs").join(Uuid::new_v4().to_string());
        fs::create_dir_all(&dir).unwrap();
        let oid = hex::encode(Sha256::digest(payload));
        let path = dir.join(&oid);
        fs::write(&path, payload).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        (root, path, oid)
    }

    fn record(path: &Path, root: &Path, oid: &str, size: u64) {
        let file = File::open(path).unwrap();
        let meta = file.metadata().unwrap();
        let write = capture_verified_write(&meta, size).unwrap();
        let repo = Uuid::nil();
        record_published_write(path, &write, root, repo, oid, size).unwrap();
    }

    fn verify(path: &Path, root: &Path, oid: &str, size: u64) -> bool {
        verify_path_blocking(path, root, Uuid::nil(), oid, size, Instant::now() + Duration::from_secs(30)).unwrap()
    }

    fn identity_record(number: u64) -> FileIdentity {
        FileIdentity {
            data_root: PathBuf::from("/data"),
            repo_id: Uuid::nil(),
            oid: "a".repeat(64),
            promised_size: 1,
            dev: 1,
            ino: number,
            mtime_sec: 1,
            mtime_nsec: 1,
            ctime_sec: 1,
            ctime_nsec: 1,
            size: 1,
            mode: 0o600,
            nlink: 1,
        }
    }

    #[test]
    fn cache_is_jointly_bounded_across_expiry_reinsert_and_pressure() {
        let _serial = serial();
        let mut state = CacheState::default();
        let base = Instant::now();
        let identity = identity_record(1);
        // Repeated expiry/reinsert of one identity must not accumulate stale
        // ordering records for the live key.
        for cycle in 0..(MAX_CACHE_ENTRIES * 3) {
            let now = base + Duration::from_millis(cycle as u64);
            state.insert(identity.clone(), now);
            assert_eq!(state.entries.len(), 1);
            assert_eq!(state.order.len(), 1);
            assert!(state.is_fresh(&identity, now));
            assert!(!state.is_fresh(&identity, now + CACHE_TTL + Duration::from_secs(1)));
            assert_eq!(state.entries.len(), 0);
            assert_eq!(state.order.len(), 0);
        }
        let total = (MAX_CACHE_ENTRIES * 3) as u64;
        for number in 0..total {
            state.insert(identity_record(number), base);
            assert_eq!(state.entries.len(), state.order.len());
            assert!(state.entries.len() <= MAX_CACHE_ENTRIES);
        }
        assert_eq!(state.entries.len(), MAX_CACHE_ENTRIES);
        assert_eq!(state.order.len(), MAX_CACHE_ENTRIES);
        assert!(state.is_fresh(&identity_record(total - 1), base));
        assert!(!state.is_fresh(&identity_record(0), base));
        for (sequence, key) in &state.order {
            assert_eq!(state.entries[key].order_seq, *sequence);
        }
    }

    struct HeldHashGate;

    impl Drop for HeldHashGate {
        fn drop(&mut self) {
            HASH_GATE.set_hold(false);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_verification_keeps_slots_until_blocking_work_finishes() {
        let _serial = serial();
        // Distinct identities: same-identity callers now coalesce onto one hash
        // pass, and this test needs three independently running hash workers.
        let fixtures: Vec<_> = (0..3u8).map(|n| fixture(&vec![3u8 + n; 128 * 1024])).collect();
        HASH_GATE.set_hold(true);
        let _released = HeldHashGate;
        let mut handles = Vec::new();
        for (root, path, oid) in &fixtures {
            handles.push(tokio::spawn(verify_local(
                path.clone(),
                root.clone(),
                Uuid::nil(),
                oid.clone(),
                128 * 1024,
                tokio::time::Instant::now() + Duration::from_secs(30),
            )));
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while HASH_GATE.active() < 3 {
            assert!(tokio::time::Instant::now() < deadline, "hash workers never entered the gate");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            available_verification_slots() <= MAX_CONCURRENT_VERIFICATIONS - 3,
            "permits were released before the blocking work started"
        );
        for handle in &handles {
            handle.abort();
        }
        for handle in handles {
            let _ = handle.await;
        }
        // Canceled request futures must not free slots while the blocking hash
        // workers are still alive.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(HASH_GATE.active(), 3);
        assert!(
            available_verification_slots() <= MAX_CONCURRENT_VERIFICATIONS - 3,
            "canceled callers returned permits owned by running work"
        );
        HASH_GATE.set_hold(false);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while HASH_GATE.active() != 0 || available_verification_slots() != MAX_CONCURRENT_VERIFICATIONS {
            assert!(tokio::time::Instant::now() < deadline, "released work never returned its slot");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        for (root, _, _) in fixtures {
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn identity_cache_avoids_rehash_but_detects_tamper_truncate_and_replace() {
        let _serial = serial();
        let payload = vec![7u8; 256 * 1024];
        let (root, path, oid) = fixture(&payload);
        let size = payload.len() as u64;
        record(&path, &root, &oid, size);

        let before = HASHED_BYTES.load(Ordering::Relaxed);
        assert!(verify(&path, &root, &oid, size));
        assert_eq!(HASHED_BYTES.load(Ordering::Relaxed), before, "a warm verified identity must not be rehashed");

        // Same inode, same length, different bytes: ctime/mtime change and the
        // cached identity no longer matches, so the digest pass fails closed.
        std::thread::sleep(Duration::from_millis(2));
        let mut tampered = payload.clone();
        tampered[17] ^= 0x55;
        fs::write(&path, &tampered).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!verify(&path, &root, &oid, size));

        // Wrong length is rejected by admission before any hash.
        fs::write(&path, &payload[..size as usize - 1]).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(!verify(&path, &root, &oid, size));

        // Restore correct bytes, then replace the inode with bad same-size
        // content. The inode change forces a fresh digest and fails.
        fs::write(&path, &payload).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(verify(&path, &root, &oid, size));
        let replacement = path.with_extension("replacement");
        fs::write(&replacement, vec![9u8; payload.len()]).unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&replacement, &path).unwrap();
        assert!(!verify(&path, &root, &oid, size));

        fs::write(&path, &payload).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(verify(&path, &root, &oid, size));
        fs::remove_dir_all(root).unwrap();
    }

    async fn wait_until(what: &str, mut predicate: impl FnMut() -> bool) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        while !predicate() {
            assert!(tokio::time::Instant::now() < deadline, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Deterministic gated native test: four readers of the same already-local
    /// file (empty cache, e.g. immediately after a restart) must share one hash
    /// pass. This is local verification coalescing, not cold hydration: the
    /// final path exists throughout and no object-store configuration or remote
    /// request can participate. A genuinely missing path stays a distinct miss.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_cache_empty_existing_file_shares_one_hash_pass() {
        let _serial = serial();
        let payload = vec![13u8; 1024 * 1024];
        let (root, path, oid) = fixture(&payload);
        let size = payload.len() as u64;
        assert!(path.is_file());
        let hashed_before = HASHED_BYTES.load(Ordering::Relaxed);
        let followers_before = flight_follower_count();
        assert_eq!(active_flight_count(), 0);

        HASH_GATE.set_hold(true);
        let _released = HeldHashGate;
        let mut handles = Vec::new();
        for _ in 0..4 {
            handles.push(tokio::spawn(verify_local(
                path.clone(),
                root.clone(),
                Uuid::nil(),
                oid.clone(),
                size,
                tokio::time::Instant::now() + Duration::from_secs(30),
            )));
        }
        wait_until("one leader to enter the hash gate", || HASH_GATE.active() == 1).await;
        wait_until("all other readers to join the flight", || flight_follower_count() == followers_before + 3).await;
        // Followers are blocked before reading any bytes; only the leader has
        // entered the gate and no reader has hashed the object yet.
        assert_eq!(HASH_GATE.active(), 1);
        assert_eq!(HASHED_BYTES.load(Ordering::Relaxed), hashed_before);
        HASH_GATE.set_hold(false);
        for handle in handles {
            assert!(handle.await.unwrap().unwrap());
        }
        assert_eq!(HASHED_BYTES.load(Ordering::Relaxed) - hashed_before, size);
        wait_until("the completed flight to leave the map", || active_flight_count() == 0).await;

        // Once verified, concurrent warm readers reuse the bounded identity
        // cache with no further bytes hashed.
        let hashed_after = HASHED_BYTES.load(Ordering::Relaxed);
        let mut warm = Vec::new();
        for _ in 0..4 {
            warm.push(tokio::spawn(verify_local(
                path.clone(),
                root.clone(),
                Uuid::nil(),
                oid.clone(),
                size,
                tokio::time::Instant::now() + Duration::from_secs(30),
            )));
        }
        for handle in warm {
            assert!(handle.await.unwrap().unwrap());
        }
        assert_eq!(HASHED_BYTES.load(Ordering::Relaxed), hashed_after);

        // Missing file is a different outcome: no flight, no hash, explicit
        // false so the caller can decide whether cold hydration is permitted.
        let missing = root.join("lfs").join(Uuid::new_v4().to_string()).join("b".repeat(64));
        assert!(
            !verify_path_blocking(
                &missing,
                &root,
                Uuid::nil(),
                &"b".repeat(64),
                size,
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap()
        );
        assert_eq!(HASHED_BYTES.load(Ordering::Relaxed), hashed_after);
        assert_eq!(active_flight_count(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    /// A follower that cannot observe a result before its own deadline fails
    /// explicitly and cannot free or steal the leader's work.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn follower_wait_is_deadline_bounded() {
        let _serial = serial();
        let payload = vec![17u8; 512 * 1024];
        let (root, path, oid) = fixture(&payload);
        let size = payload.len() as u64;
        HASH_GATE.set_hold(true);
        let _released = HeldHashGate;
        let leader = tokio::spawn(verify_local(
            path.clone(),
            root.clone(),
            Uuid::nil(),
            oid.clone(),
            size,
            tokio::time::Instant::now() + Duration::from_secs(30),
        ));
        wait_until("the leader to enter the hash gate", || HASH_GATE.active() == 1).await;
        let followers_before = flight_follower_count();
        let error = verify_local(
            path.clone(),
            root.clone(),
            Uuid::nil(),
            oid.clone(),
            size,
            tokio::time::Instant::now() + Duration::from_millis(150),
        )
        .await
        .expect_err("a follower with an expired deadline must fail explicitly");
        assert!(format!("{error:#}").contains("timed out"), "{error:#}");
        assert_eq!(flight_follower_count(), followers_before + 1);
        assert_eq!(HASH_GATE.active(), 1, "a follower must not start its own hash pass");
        HASH_GATE.set_hold(false);
        assert!(leader.await.unwrap().unwrap());
        wait_until("the leader to leave the flight map", || active_flight_count() == 0).await;
        fs::remove_dir_all(root).unwrap();
    }
}
