//! Real kernel FUSE acceptance for the bounded per-mount dispatcher.
//!
//! These tests execute only on a host (or user namespace) with a working
//! `/dev/fuse`:
//!
//! ```text
//! ROOTYARD_FUSE_NATIVE=1 cargo test --test fuse_freeze_queue -- --ignored --test-threads=1
//! ```
//!
//! Every test is `#[ignore = "requires ROOTYARD_FUSE_NATIVE=1 ..."]`. A default
//! run therefore does not execute it, and an explicit `--ignored` run without
//! `ROOTYARD_FUSE_NATIVE=1` fails its first assertion instead of silently
//! passing. The environment variable is a strict native entry gate, not a skip
//! notice.
//!
//! The FIFO fixture is owned and artificial: two private-upper paths are
//! hardlinked to one host inode on purpose, while the overlay allocates a
//! different FUSE inode per path. It exercises same-host-offset ordering without
//! the VFS serializing the two aliases on one inode lock. It does not claim that
//! production hardlink semantics are complete.
use rootyard::workspace_lab::fuse_mount::{
    DispatchQueueUsage, MountHandle, MutationGate, Overlay, spawn,
};
use std::{
    fs::{self, OpenOptions},
    os::unix::fs::{FileExt, MetadataExt},
    path::{Path, PathBuf},
    sync::{Mutex, PoisonError, mpsc},
    time::{Duration, Instant},
};

const WAIT: Duration = Duration::from_secs(5);
/// The helper budget and the read pool are process-wide, so these native mounts
/// never run concurrently with each other. This keeps the zero-budget checks
/// deterministic without weakening them.
static NATIVE_TESTS: Mutex<()> = Mutex::new(());

fn native() -> bool {
    std::env::var_os("ROOTYARD_FUSE_NATIVE").as_deref() == Some(std::ffi::OsStr::new("1"))
}

fn enter_native() -> std::sync::MutexGuard<'static, ()> {
    assert!(
        native(),
        "set ROOTYARD_FUSE_NATIVE=1 to run this ignored native FUSE test"
    );
    NATIVE_TESTS.lock().unwrap_or_else(PoisonError::into_inner)
}

fn wait_until(mut predicate: impl FnMut() -> bool, label: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if predicate() {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("timed out waiting for {label}");
}

/// Per-mount work only. The process-wide helper counters may still be charged by
/// another deliberately frozen mount in the same test.
fn mount_drained(usage: DispatchQueueUsage) -> bool {
    usage.mount_ops == 0
        && usage.mount_bytes == 0
        && usage.ready == 0
        && usage.frozen == 0
        && usage.pending_reads == 0
}

/// Every queue/budget counter, but not the cumulative diagnostics: an observed
/// fence is not a leaked operation.
fn queue_drained(usage: DispatchQueueUsage) -> bool {
    mount_drained(usage) && usage.global_ops == 0 && usage.global_bytes == 0
}

fn wait_until_mount_drained(handle: &MountHandle, label: &str) {
    wait_until(|| mount_drained(handle.queue_usage()), label);
}

fn wait_until_queue_drained(handle: &MountHandle, label: &str) {
    wait_until(|| queue_drained(handle.queue_usage()), label);
}

fn layout(root: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let lower = root.join("lower");
    let upper = root.join("upper");
    let mount = root.join("mount");
    fs::create_dir_all(&lower).unwrap();
    fs::create_dir_all(&upper).unwrap();
    fs::create_dir_all(&mount).unwrap();
    (lower, upper, mount)
}

#[test]
#[ignore = "requires ROOTYARD_FUSE_NATIVE=1 and a working /dev/fuse"]
fn frozen_readwrite_aliases_drain_in_fifo_order_and_other_mount_stays_live() {
    let _serial = enter_native();
    let root = tempfile::tempdir().unwrap();
    let (lower, upper, mount) = layout(root.path());
    let upper = upper.canonicalize().unwrap();

    // Reads of an inode with a blocked pwrite can serialize inside the kernel.
    // Use an independent inode to test this mount's read availability.
    fs::write(lower.join("read-probe.txt"), b"readable").unwrap();
    let gate = MutationGate::new_with_lease(1, i64::MAX).unwrap();
    let overlay = Overlay::new_with_gate(lower, upper.clone(), gate.clone()).unwrap();
    let handle = spawn(overlay, &mount).expect("kernel FUSE mount");
    wait_until_queue_drained(&handle, "fresh mount to start with empty queue budgets");

    // Owned artificial fixture: a six-byte private-upper file and a second path
    // hardlinked to the same host inode. Both entries already exist in the
    // upper layer, so a write-open's `prepare` does not CoW either alias.
    let first_path = upper.join("first.txt");
    let second_path = upper.join("second.txt");
    fs::write(&first_path, b"origin").unwrap();
    fs::hard_link(&first_path, &second_path).unwrap();
    let first_meta = fs::metadata(&first_path).unwrap();
    let second_meta = fs::metadata(&second_path).unwrap();
    assert_eq!(first_meta.ino(), second_meta.ino(), "fixture aliases must share one host inode");
    assert!(first_meta.nlink() >= 2, "fixture must be a real hardlink pair");

    // Both read-write descriptions are opened before the freeze, so no Open
    // request can park and the FIFO contains only the two Write requests.
    let first = OpenOptions::new().read(true).write(true).open(mount.join("first.txt")).unwrap();
    let second = OpenOptions::new().read(true).write(true).open(mount.join("second.txt")).unwrap();
    assert_ne!(
        first.metadata().unwrap().ino(),
        second.metadata().unwrap().ino(),
        "the overlay must allocate a different FUSE inode per path for the aliases"
    );

    let (entered_tx, entered_rx) = mpsc::channel();
    let (thaw_tx, thaw_rx) = mpsc::channel::<()>();
    std::thread::scope(|scope| {
        let freeze_gate = gate.clone();
        let freezer = scope.spawn(move || {
            freeze_gate.freeze(|| {
                entered_tx.send(()).unwrap();
                thaw_rx.recv_timeout(WAIT).expect("bounded thaw or panic release");
            });
        });
        entered_rx.recv_timeout(WAIT).expect("freeze entered");
        assert!(gate.is_frozen());

        let (first_tx, first_rx) = mpsc::channel();
        scope.spawn(move || {
            first_tx.send(first.write_at(b"first!", 0)).unwrap();
        });
        wait_until(|| handle.queue_usage().frozen >= 1, "first frozen write to park");
        assert!(
            first_rx.recv_timeout(Duration::from_millis(300)).is_err(),
            "a frozen write must block, not return EAGAIN"
        );

        // A read through the same frozen mount still returns the pre-freeze byte.
        assert_eq!(fs::read(mount.join("read-probe.txt")).unwrap(), b"readable");

        let (second_tx, second_rx) = mpsc::channel();
        scope.spawn(move || {
            second_tx.send(second.write_at(b"second", 0)).unwrap();
        });
        wait_until(|| handle.queue_usage().frozen >= 2, "second frozen write to park");
        assert!(
            second_rx.recv_timeout(Duration::from_millis(300)).is_err(),
            "the second frozen write must also block"
        );

        // A second real mount owns a different gate, actor and queue. It must
        // create/write/read while the first mount is frozen.
        let b_root = root.path().join("second-mount");
        let (lower_b, upper_b, mount_b) = layout(&b_root);
        let upper_b = upper_b.canonicalize().unwrap();
        fs::write(lower_b.join("base.txt"), b"b-base").unwrap();
        let gate_b = MutationGate::new_with_lease(1, i64::MAX).unwrap();
        let overlay_b = Overlay::new_with_gate(lower_b, upper_b.clone(), gate_b).unwrap();
        let handle_b = spawn(overlay_b, &mount_b).expect("second kernel FUSE mount");
        wait_until_mount_drained(&handle_b, "second mount to start with an empty queue");
        fs::write(mount_b.join("live.txt"), b"mount-b").unwrap();
        assert_eq!(fs::read(mount_b.join("live.txt")).unwrap(), b"mount-b");
        assert_eq!(fs::read(mount_b.join("base.txt")).unwrap(), b"b-base");
        assert_eq!(fs::read(upper_b.join("live.txt")).unwrap(), b"mount-b");
        wait_until_mount_drained(&handle_b, "second mount queue to drain");
        drop(handle_b);

        thaw_tx.send(()).unwrap();
        freezer.join().unwrap();
        assert_eq!(
            first_rx.recv_timeout(WAIT).unwrap().unwrap(),
            6,
            "the first alias write must complete after thaw"
        );
        assert_eq!(
            second_rx.recv_timeout(WAIT).unwrap().unwrap(),
            6,
            "the second alias write must complete after thaw"
        );
    });

    // Both writes overwrite the same host offset. Only FIFO drain order makes
    // the second payload win; a reversed drain would leave "first!" here.
    assert_eq!(fs::read(&first_path).unwrap(), b"second");
    assert_eq!(fs::read(&second_path).unwrap(), b"second");
    wait_until_queue_drained(&handle, "first mount queue budgets to return to zero");
}

#[test]
#[ignore = "requires ROOTYARD_FUSE_NATIVE=1 and a working /dev/fuse"]
fn fenced_mount_rejects_new_mutations_and_keeps_reads() {
    let _serial = enter_native();
    let root = tempfile::tempdir().unwrap();
    let (lower, upper, mount) = layout(root.path());
    fs::write(lower.join("base.txt"), b"base").unwrap();

    let gate = MutationGate::new_with_lease(1, i64::MAX).unwrap();
    let overlay = Overlay::new_with_gate(lower, upper.clone(), gate.clone()).unwrap();
    let handle = spawn(overlay, &mount).expect("kernel FUSE mount");
    wait_until_queue_drained(&handle, "fresh mount to start with empty queue budgets");
    assert_eq!(fs::read(mount.join("base.txt")).unwrap(), b"base");

    gate.fence();
    let error = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(mount.join("fenced.txt"))
        .expect_err("fenced mount must reject a create");
    assert_eq!(error.raw_os_error(), Some(libc::EROFS));
    assert!(!upper.join("fenced.txt").exists());
    assert_eq!(fs::read(mount.join("base.txt")).unwrap(), b"base");
    assert!(
        handle.queue_usage().fence_observations >= 1,
        "the actor must have observed the direct fence branch while rejecting the create"
    );
    wait_until_queue_drained(&handle, "fenced mount queue budgets to return to zero");
}

#[test]
#[ignore = "requires ROOTYARD_FUSE_NATIVE=1 and a working /dev/fuse"]
fn rapid_freeze_fence_handoff_cannot_replay_the_old_epoch_when_fenced_is_missed() {
    let _serial = enter_native();
    let root = tempfile::tempdir().unwrap();
    let (lower, upper, mount) = layout(root.path());
    let upper = upper.canonicalize().unwrap();
    fs::write(lower.join("base.txt"), b"base").unwrap();

    let gate = MutationGate::new_with_lease(1, i64::MAX).unwrap();
    let overlay = Overlay::new_with_gate(lower, upper.clone(), gate.clone()).unwrap();
    let handle = spawn(overlay, &mount).expect("kernel FUSE mount");
    wait_until_queue_drained(&handle, "fresh mount to start with empty queue budgets");

    let mut epoch = 1i64;
    let mut covered_missed_fence = false;
    for round in 0..32 {
        let name = format!("rapid-{round}.txt");
        let path = upper.join(&name);
        fs::write(&path, b"origin").unwrap();
        // Open the write description while this epoch is healthy, so only the
        // Write request itself can be parked by the freeze.
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(mount.join(&name))
            .expect("pre-freeze write-open");
        wait_until_queue_drained(&handle, "pre-freeze open to drain");
        let before = handle.queue_usage();
        let next = epoch + 1;

        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (handoff_tx, handoff_rx) = mpsc::channel();
        let (write_tx, write_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let freezer_gate = gate.clone();
            scope.spawn(move || {
                freezer_gate.freeze_then_fence(|| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv_timeout(WAIT).expect("bounded freeze release");
                });
                // `freeze_then_fence` returned, so the old epoch is fenced. The
                // same thread hands off the next epoch immediately; the actor's
                // 10 ms poll may therefore observe only the new Healthy epoch.
                handoff_tx.send(freezer_gate.handoff(next, i64::MAX)).unwrap();
            });
            entered_rx.recv_timeout(WAIT).expect("freeze entered");

            scope.spawn(move || {
                write_tx.send(file.write_at(b"stale!", 0)).unwrap();
            });
            wait_until(|| handle.queue_usage().frozen >= 1, "old-epoch write to park");
            release_tx.send(()).unwrap();
            handoff_rx
                .recv_timeout(WAIT)
                .expect("handoff thread result")
                .expect("handoff must authorize the next epoch");
            match write_rx.recv_timeout(WAIT).expect("writer result") {
                Ok(count) => panic!("the old parked write executed {count} bytes after handoff"),
                Err(error) => assert_eq!(
                    error.raw_os_error(),
                    Some(libc::EROFS),
                    "the old parked write must fail EROFS"
                ),
            }
        });

        let after = handle.queue_usage();
        let fenced = after.fence_observations.saturating_sub(before.fence_observations);
        let rejected = after.epoch_mismatch_rejections.saturating_sub(before.epoch_mismatch_rejections);
        assert_eq!(
            fs::read(&path).unwrap(),
            b"origin",
            "a rejected old-epoch write must leave the upper file unchanged"
        );

        if fenced == 0 {
            // The actor never saw Fenced. The only acceptable reason the write
            // failed is the enqueue-era epoch stamp rejecting it after handoff.
            assert!(
                rejected > 0,
                "a zero fence-observation round must be explained by an epoch-mismatch rejection"
            );
            covered_missed_fence = true;
            // The new epoch must accept a normal write.
            let current = OpenOptions::new()
                .read(true)
                .write(true)
                .open(mount.join(&name))
                .expect("new-epoch write-open");
            assert_eq!(current.write_at(b"fresh!", 0).unwrap(), 6);
            assert_eq!(fs::read(mount.join(&name)).unwrap(), b"fresh!");
            assert_eq!(fs::read(&path).unwrap(), b"fresh!");
            wait_until_queue_drained(&handle, "new-epoch write to drain");
            break;
        }

        // This round only proves the actor saw Fenced. Verify the EROFS result
        // above, advance the epoch and try again; it is not missed-fence proof.
        epoch = next;
        wait_until_queue_drained(&handle, "post-fence round to drain");
    }
    assert!(
        covered_missed_fence,
        "32 rounds never produced a zero fence-observation round; the epoch-mismatch window was not exercised"
    );
}
