use super::*;
use crate::lfs::verification::{hashed_bytes, open_verified_file, test_serial, verify_local};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{Arc, Barrier, Mutex},
    time::{Duration, Instant},
};
use uuid::Uuid;

struct HeldHashGate;

impl Drop for HeldHashGate {
    fn drop(&mut self) {
        HASH_GATE.set_hold(false);
    }
}

fn fixture(payload: &[u8]) -> (PathBuf, PathBuf, String) {
    let root = std::env::temp_dir().join(format!("rootyard-lfs-limiter-{}", Uuid::new_v4()));
    let dir = root.join("lfs").join(Uuid::new_v4().to_string());
    fs::create_dir_all(&dir).unwrap();
    let oid = hex::encode(Sha256::digest(payload));
    let path = dir.join(&oid);
    fs::write(&path, payload).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    (root, path, oid)
}

async fn wait_until(what: &str, mut predicate: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !predicate() {
        assert!(tokio::time::Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn short_deadline_flight_leader_times_out_in_hash_gate_and_follower_takes_over() {
    let _serial = test_serial().await;
    let payload = vec![0x5Au8; 512 * 1024];
    let (root, path, oid) = fixture(&payload);
    let size = payload.len() as u64;
    let hashed_before = hashed_bytes();
    let followers_before = flight_follower_count();
    assert_eq!(active_flight_count(), 0);

    HASH_GATE.set_hold(true);
    let _released = HeldHashGate;

    // Leader 1 enters HASH_GATE with a short 180ms deadline.
    let short_leader = tokio::spawn(verify_local(
        path.clone(),
        root.clone(),
        Uuid::nil(),
        oid.clone(),
        size,
        tokio::time::Instant::now() + Duration::from_millis(180),
    ));
    wait_until("short-deadline leader to enter HASH_GATE", || HASH_GATE.active() == 1).await;

    // Two long-deadline followers join the active singleflight while Leader 1 is still gated.
    let follower_verify = tokio::spawn(verify_local(
        path.clone(),
        root.clone(),
        Uuid::nil(),
        oid.clone(),
        size,
        tokio::time::Instant::now() + Duration::from_secs(30),
    ));
    let follower_open = tokio::spawn(open_verified_file(
        path.clone(),
        root.clone(),
        Uuid::nil(),
        oid.clone(),
        size,
        tokio::time::Instant::now() + Duration::from_secs(30),
    ));
    wait_until("both followers to attach to Leader 1's flight", || flight_follower_count() == followers_before + 2)
        .await;

    // Leader 1 times out inside HASH_GATE while the gate remains held.
    let leader_err = short_leader.await.unwrap().expect_err("short-deadline leader must time out in HASH_GATE");
    assert!(format!("{leader_err:#}").contains("timed out"), "{leader_err:#}");

    // One surviving follower promotes to the new FlightLeader on its already-open
    // descriptor and enters HASH_GATE; the other follower coalesces onto the new flight.
    wait_until("promoted follower to enter HASH_GATE as new leader", || HASH_GATE.active() == 1).await;
    wait_until("remaining follower to coalesce onto promoted leader", || {
        flight_follower_count() == followers_before + 3
    })
    .await;
    assert_eq!(hashed_bytes(), hashed_before, "no bytes should be hashed before HASH_GATE releases");

    HASH_GATE.set_hold(false);
    assert!(follower_verify.await.unwrap().unwrap());
    let mut verified_file = follower_open.await.unwrap().unwrap().expect("verified open descriptor");
    let mut read_back = Vec::new();
    verified_file.read_to_end(&mut read_back).unwrap();
    assert_eq!(read_back, payload);

    assert_eq!(hashed_bytes() - hashed_before, size, "promoted leader must hash the object exactly once");
    wait_until("flights and slots to drain cleanly", || {
        active_flight_count() == 0 && available_verification_slots() == MAX_CONCURRENT_VERIFICATIONS
    })
    .await;
    fs::remove_dir_all(root).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fifo_ticket_queue_prevents_sync_barging_and_cascades_cancelled_front_waiter() {
    let _serial = test_serial().await;
    assert_eq!(available_verification_slots(), MAX_CONCURRENT_VERIFICATIONS);
    assert_eq!(queued_verification_waiters(), 0);

    // Saturate all 8 verification slots.
    let mut held = Vec::with_capacity(MAX_CONCURRENT_VERIFICATIONS);
    for _ in 0..MAX_CONCURRENT_VERIFICATIONS {
        held.push(acquire_verification_slot(tokio::time::Instant::now() + Duration::from_secs(30)).await.unwrap());
    }
    assert_eq!(available_verification_slots(), 0);

    let order: Arc<Mutex<Vec<&'static str>>> = Arc::new(Mutex::new(Vec::new()));
    let release_async = Arc::new(tokio::sync::Notify::new());
    let release_sync1 = Arc::new(Barrier::new(2));
    let release_sync2 = Arc::new(Barrier::new(2));

    // Ticket 0: queued async waiter.
    let order_async = order.clone();
    let hold_async = release_async.clone();
    let async_waiter = tokio::spawn(async move {
        let permit = acquire_verification_slot(tokio::time::Instant::now() + Duration::from_secs(30)).await.unwrap();
        order_async.lock().unwrap().push("async");
        hold_async.notified().await;
        drop(permit);
    });
    wait_until("async waiter to enqueue first", || queued_verification_waiters() == 1).await;

    // Ticket 1: queued sync waiter arriving after async waiter.
    let order_s1 = order.clone();
    let hold_s1 = release_sync1.clone();
    let sync_waiter_1 = std::thread::spawn(move || {
        let permit = acquire_verification_slot_blocking(Instant::now() + Duration::from_secs(30)).unwrap();
        order_s1.lock().unwrap().push("sync1");
        hold_s1.wait();
        drop(permit);
    });
    wait_until("first sync waiter to enqueue behind async waiter", || queued_verification_waiters() == 2).await;

    // Drop exactly one slot while launching a barging sync caller (Ticket 2).
    let order_s2 = order.clone();
    let hold_s2 = release_sync2.clone();
    held.pop().expect("drop one permit");
    let sync_waiter_2 = std::thread::spawn(move || {
        let permit = acquire_verification_slot_blocking(Instant::now() + Duration::from_secs(30)).unwrap();
        order_s2.lock().unwrap().push("sync2");
        hold_s2.wait();
        drop(permit);
    });

    // Only the front async waiter may acquire the single freed slot.
    wait_until("queued async waiter to acquire first", || order.lock().unwrap().as_slice() == ["async"]).await;
    wait_until("both sync waiters to remain queued", || queued_verification_waiters() == 2).await;
    assert_eq!(available_verification_slots(), 0);

    // Release a second slot: sync1 must acquire ahead of sync2.
    held.pop().expect("drop second permit");
    wait_until("sync1 to acquire second", || order.lock().unwrap().as_slice() == ["async", "sync1"]).await;
    assert_eq!(queued_verification_waiters(), 1);
    assert_eq!(available_verification_slots(), 0);

    // Release a third slot: sync2 acquires third.
    held.pop().expect("drop third permit");
    wait_until("sync2 to acquire third", || order.lock().unwrap().as_slice() == ["async", "sync1", "sync2"]).await;
    assert_eq!(queued_verification_waiters(), 0);

    // Now all 8 slots are busy again (5 in `held` + async + sync1 + sync2).
    // Verify cancelling a front async waiter cascades wakeup when a slot frees.
    let cancelled_front =
        tokio::spawn(acquire_verification_slot(tokio::time::Instant::now() + Duration::from_secs(30)));
    wait_until("cancellable async waiter at front of queue", || queued_verification_waiters() == 1).await;
    let tail_sync =
        std::thread::spawn(|| acquire_verification_slot_blocking(Instant::now() + Duration::from_secs(30)).unwrap());
    wait_until("tail sync waiter behind cancellable front", || queued_verification_waiters() == 2).await;

    cancelled_front.abort();
    let _ = cancelled_front.await;
    wait_until("cancelled front ticket removed", || queued_verification_waiters() == 1).await;
    held.pop().expect("free one permit for tail sync waiter");
    let tail_permit = tail_sync.join().unwrap();
    drop(tail_permit);

    release_async.notify_one();
    release_sync1.wait();
    release_sync2.wait();
    async_waiter.await.unwrap();
    sync_waiter_1.join().unwrap();
    sync_waiter_2.join().unwrap();
    drop(held);
    wait_until("all verification slots restored", || {
        available_verification_slots() == MAX_CONCURRENT_VERIFICATIONS && queued_verification_waiters() == 0
    })
    .await;
}
