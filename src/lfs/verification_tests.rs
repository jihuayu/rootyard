
use super::*;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    sync::{Arc, atomic::Ordering},
};

static TEST_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn serial() -> tokio::sync::MutexGuard<'static, ()> {
    TEST_SERIAL.lock().await
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

#[tokio::test]
async fn cache_is_jointly_bounded_across_expiry_reinsert_and_pressure() {
    let _serial = serial().await;
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
    let _serial = serial().await;
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

#[tokio::test]
async fn identity_cache_avoids_rehash_but_detects_tamper_truncate_and_replace() {
    let _serial = serial().await;
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

    let symlink_target = path.with_extension("symlink-target");
    fs::write(&symlink_target, &payload).unwrap();
    fs::set_permissions(&symlink_target, fs::Permissions::from_mode(0o600)).unwrap();
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(&symlink_target, &path).unwrap();
    assert!(!verify(&path, &root, &oid, size));
    assert!(
        open_verified_file(
            path.clone(),
            root.clone(),
            Uuid::nil(),
            oid.clone(),
            size,
            tokio::time::Instant::now() + Duration::from_secs(5),
        )
        .await
        .unwrap()
        .is_none()
    );
    fs::remove_file(&path).unwrap();
    fs::remove_file(&symlink_target).unwrap();

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

fn spawn_verify_local(entry: &(PathBuf, PathBuf, String), size: u64) -> tokio::task::JoinHandle<Result<bool>> {
    let (root, path, oid) = entry.clone();
    tokio::spawn(verify_local(path, root, Uuid::nil(), oid, size, tokio::time::Instant::now() + Duration::from_secs(30)))
}

fn spawn_open_verified(entry: &(PathBuf, PathBuf, String), size: u64) -> tokio::task::JoinHandle<Result<Option<File>>> {
    let (root, path, oid) = entry.clone();
    tokio::spawn(open_verified_file(
        path,
        root,
        Uuid::nil(),
        oid,
        size,
        tokio::time::Instant::now() + Duration::from_secs(30),
    ))
}

fn spawn_sync_verify(entry: &(PathBuf, PathBuf, String), size: u64) -> std::thread::JoinHandle<Result<bool>> {
    let (root, path, oid) = entry.clone();
    std::thread::spawn(move || {
        verify_path_blocking(&path, &root, Uuid::nil(), &oid, size, Instant::now() + Duration::from_secs(30))
    })
}

/// Deterministic gated native test: four readers of the same already-local
/// file (empty cache, e.g. immediately after a restart) must share one hash
/// pass. This is local verification coalescing, not cold hydration: the
/// final path exists throughout and no object-store configuration or remote
/// request can participate. A genuinely missing path stays a distinct miss.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_cache_empty_existing_file_shares_one_hash_pass() {
    let _serial = serial().await;
    let payload = vec![13u8; 1024 * 1024];
    let item = fixture(&payload);
    let (root, path, _) = &item;
    let size = payload.len() as u64;
    assert!(path.is_file());
    let hashed_before = HASHED_BYTES.load(Ordering::Relaxed);
    let followers_before = flight_follower_count();
    assert_eq!(active_flight_count(), 0);

    HASH_GATE.set_hold(true);
    let _released = HeldHashGate;
    let handles: Vec<_> = (0..4).map(|_| spawn_verify_local(&item, size)).collect();
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
    let warm: Vec<_> = (0..4).map(|_| spawn_verify_local(&item, size)).collect();
    for handle in warm {
        assert!(handle.await.unwrap().unwrap());
    }
    assert_eq!(HASHED_BYTES.load(Ordering::Relaxed), hashed_after);

    // Missing file is a different outcome: no flight, no hash, explicit
    // false so the caller can decide whether cold hydration is permitted.
    let missing = root.join("lfs").join(Uuid::new_v4().to_string()).join("b".repeat(64));
    assert!(
        !verify_path_blocking(&missing, root, Uuid::nil(), &"b".repeat(64), size, Instant::now() + Duration::from_secs(5))
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
    let _serial = serial().await;
    let payload = vec![17u8; 512 * 1024];
    let item = fixture(&payload);
    let (root, path, oid) = &item;
    let size = payload.len() as u64;
    HASH_GATE.set_hold(true);
    let _released = HeldHashGate;
    let leader = spawn_verify_local(&item, size);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sync_and_async_callers_share_eight_slot_verification_limit() {
    let _serial = serial().await;
    let size = 128 * 1024u64;
    let fixtures: Vec<_> = (0..10u8).map(|n| fixture(&vec![31u8 + n; size as usize])).collect();
    HASH_GATE.set_hold(true);
    let _released = HeldHashGate;

    let async_bool: Vec<_> = fixtures[0..3].iter().map(|entry| spawn_verify_local(entry, size)).collect();
    let async_files: Vec<_> = fixtures[3..5].iter().map(|entry| spawn_open_verified(entry, size)).collect();
    let sync_holders: Vec<_> = fixtures[5..8].iter().map(|entry| spawn_sync_verify(entry, size)).collect();

    wait_until("all eight shared verification slots to enter the gate", || {
        HASH_GATE.active() == MAX_CONCURRENT_VERIFICATIONS
    })
    .await;
    assert_eq!(available_verification_slots(), 0);

    let (r9, p9, o9) = fixtures[8].clone();
    let sync_timeout = std::thread::spawn(move || {
        verify_path_blocking(&p9, &r9, Uuid::nil(), &o9, size, Instant::now() + Duration::from_millis(120))
    })
    .join()
    .unwrap()
    .expect_err("9th sync caller must time out while 8 shared slots remain held");
    assert!(format!("{sync_timeout:#}").contains("concurrency wait timed out"), "{sync_timeout:#}");
    assert_eq!(HASH_GATE.active(), MAX_CONCURRENT_VERIFICATIONS);

    let (r9, p9, o9) = fixtures[8].clone();
    let async_timeout =
        verify_local(p9, r9, Uuid::nil(), o9, size, tokio::time::Instant::now() + Duration::from_millis(120))
            .await
            .expect_err("9th async caller must time out while sync+async slots remain held");
    assert!(format!("{async_timeout:#}").contains("concurrency wait timed out"), "{async_timeout:#}");

    let (r9, p9, o9) = fixtures[8].clone();
    let queued_sync_done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let queued_sync_flag = queued_sync_done.clone();
    let queued_sync = std::thread::spawn(move || {
        let res = verify_path_blocking(&p9, &r9, Uuid::nil(), &o9, size, Instant::now() + Duration::from_secs(30));
        queued_sync_flag.store(true, Ordering::SeqCst);
        res
    });
    let queued_async = spawn_open_verified(&fixtures[9], size);
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert!(!queued_sync_done.load(Ordering::SeqCst), "9th sync caller bypassed full 8-slot limiter");
    assert!(!queued_async.is_finished(), "10th async caller bypassed full 8-slot limiter");
    assert_eq!(HASH_GATE.active(), MAX_CONCURRENT_VERIFICATIONS);

    HASH_GATE.set_hold(false);
    for handle in async_bool {
        assert!(handle.await.unwrap().unwrap());
    }
    for handle in async_files {
        assert!(handle.await.unwrap().unwrap().is_some());
    }
    for handle in sync_holders {
        assert!(handle.join().unwrap().unwrap());
    }
    assert!(queued_sync.join().unwrap().unwrap());
    assert!(queued_async.await.unwrap().unwrap().is_some());
    wait_until("all slots to return", || available_verification_slots() == MAX_CONCURRENT_VERIFICATIONS).await;
    for (root, _, _) in fixtures {
        fs::remove_dir_all(root).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mixed_sync_and_async_singleflight_coalesces_beyond_slot_limit() {
    let _serial = serial().await;
    let payload = vec![43u8; 512 * 1024];
    let item = fixture(&payload);
    let size = payload.len() as u64;
    let hashed_before = HASHED_BYTES.load(Ordering::Relaxed);
    let followers_before = flight_follower_count();

    HASH_GATE.set_hold(true);
    let _released = HeldHashGate;
    let async_bool: Vec<_> = (0..4).map(|_| spawn_verify_local(&item, size)).collect();
    let async_files: Vec<_> = (0..2).map(|_| spawn_open_verified(&item, size)).collect();
    let sync_callers: Vec<_> = (0..6).map(|_| spawn_sync_verify(&item, size)).collect();

    wait_until("single leader to enter the hash gate", || HASH_GATE.active() == 1).await;
    wait_until("seven admitted followers to join the flight", || {
        flight_follower_count() >= followers_before + (MAX_CONCURRENT_VERIFICATIONS - 1)
    })
    .await;
    assert_eq!(available_verification_slots(), 0);
    assert_eq!(HASH_GATE.active(), 1);
    assert_eq!(HASHED_BYTES.load(Ordering::Relaxed), hashed_before);

    HASH_GATE.set_hold(false);
    for handle in async_bool {
        assert!(handle.await.unwrap().unwrap());
    }
    for handle in async_files {
        let mut file = handle.await.unwrap().unwrap().expect("verified descriptor");
        let mut out = Vec::new();
        file.read_to_end(&mut out).unwrap();
        assert_eq!(out, payload);
    }
    for handle in sync_callers {
        assert!(handle.join().unwrap().unwrap());
    }
    assert_eq!(HASHED_BYTES.load(Ordering::Relaxed) - hashed_before, size);
    wait_until("flight map and limiter to drain", || {
        active_flight_count() == 0 && available_verification_slots() == MAX_CONCURRENT_VERIFICATIONS
    })
    .await;
    fs::remove_dir_all(&item.0).unwrap();
}
