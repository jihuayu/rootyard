//! Unit coverage for single-flight lazy VFS hydration, verification, deadlines,
//! and private staging cleanup.
use super::{
    Reader,
    hydrator::{BlobFetcher, FetchFuture, Flight, Hydrator, RemoteFetcher, eio, reader_entries},
};
use crate::storage::remote_objects::{ObjectKey, RemoteObjectStore};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    os::unix::fs::FileExt,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Duration as StdDuration, Instant as StdInstant},
};
use tokio::time::Instant;
use uuid::Uuid;

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
    let entries = reader_entries(key, size);
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
        bytes: BTreeMap::from([(first_key.sha256.clone(), first.clone()), (second_key.sha256.clone(), second.clone())]),
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
fn prewarm_until_returns_etimedout_before_starting_work() {
    let root = tempfile::tempdir().unwrap();
    let bytes = b"budgeted prewarm\n".repeat(16);
    let key = key_for(&bytes);
    let calls = Arc::new(AtomicUsize::new(0));
    let fetcher = Arc::new(TestFetcher { calls: calls.clone(), behavior: Behavior::Publish(bytes.clone()) });
    let reader = reader_for(root.path(), key, bytes.len(), fetcher, Duration::from_secs(5));
    let expired = StdInstant::now() - StdDuration::from_millis(1);
    let error = reader.prewarm_until(&[PathBuf::from("data.bin")], expired).unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::ETIMEDOUT));
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no fetch may start without budget");
}

#[test]
fn prewarm_until_uses_remaining_budget_not_the_configured_timeout() {
    let root = tempfile::tempdir().unwrap();
    let bytes = b"pending prewarm\n".repeat(16);
    let key = key_for(&bytes);
    let calls = Arc::new(AtomicUsize::new(0));
    let fetcher = Arc::new(TestFetcher { calls, behavior: Behavior::Pending });
    let reader = reader_for(root.path(), key, bytes.len(), fetcher, Duration::from_secs(30));
    let started = StdInstant::now();
    let deadline = StdInstant::now() + StdDuration::from_millis(80);
    let error = reader.prewarm_until(&[PathBuf::from("data.bin")], deadline).unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::ETIMEDOUT));
    assert!(
        started.elapsed() < StdDuration::from_secs(2),
        "prewarm ignored the caller budget: {:?}",
        started.elapsed()
    );
}

#[test]
fn follower_caller_deadline_does_not_cancel_the_shared_leader() {
    let flight = Flight::new(StdInstant::now() + StdDuration::from_secs(30));
    let started = StdInstant::now();
    let error = flight.wait_until(StdInstant::now() + StdDuration::from_millis(40)).unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::ETIMEDOUT));
    assert!(started.elapsed() < StdDuration::from_secs(1));
    flight.finish(0);
    assert!(flight.wait().is_ok());
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
    let bytes = b"late published bytes\n".repeat(512);
    let key = key_for(&bytes);
    let release = Arc::new(tokio::sync::Notify::new());
    let calls = Arc::new(AtomicUsize::new(0));
    let fetcher =
        Arc::new(TestFetcher { calls, behavior: Behavior::Wait { bytes: bytes.clone(), release: release.clone() } });
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
        fn fetch(&self, _key: &ObjectKey, staging: PathBuf, _expected_size: u64, _deadline: Instant) -> FetchFuture {
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
    let fetcher = Arc::new(TestFetcher { calls: calls.clone(), behavior: Behavior::Publish(vec![b'y'; bytes.len()]) });
    let cache = root.path().join("cache");
    let hydrator = Hydrator::new(cache.clone(), fetcher, Duration::from_secs(5)).unwrap();
    let error = hydrator.ensure(&key, bytes.len() as u64).unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::EIO));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(!cache.join(&key.sha256).exists());
    assert!(names(&root.path().join("cache")).is_empty());
    assert_eq!(hydrator.in_flight(), 0);
}
