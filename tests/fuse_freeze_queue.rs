//! Real kernel FUSE acceptance for the bounded per-mount dispatcher.
//!
//! Run only on a host (or user namespace) with a working `/dev/fuse`:
//!
//! ```text
//! ROOTYARD_FUSE_NATIVE=1 cargo test --test fuse_freeze_queue
//! ```
//!
//! The test uses a real mount and real blocking syscalls; it does not mirror the
//! dispatcher implementation. It asserts:
//!
//! * while the gate is frozen, a write and a create park in the per-mount FIFO,
//!   while an independent read completes;
//! * after the thaw the parked operations drain in FIFO order and land in the
//!   upper CoW layer;
//! * after a fence, a new create fails with `EROFS`, reads still succeed, and
//!   the per-mount/global queue budgets return to zero.
use rootyard::workspace_lab::fuse_mount::{MutationGate, Overlay, spawn};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::mpsc,
    time::{Duration, Instant},
};

fn gated() -> bool {
    std::env::var_os("ROOTYARD_FUSE_NATIVE").as_deref() == Some(std::ffi::OsStr::new("1"))
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

fn write_new(path: PathBuf) -> std::io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(&path)?;
    file.write_all(b"payload")?;
    Ok(())
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
fn frozen_writes_queue_reads_pass_thaw_drains_fifo_and_fence_erofs() {
    if !gated() {
        eprintln!("skipping native FUSE dispatch test: set ROOTYARD_FUSE_NATIVE=1");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let (lower, upper, mount) = layout(root.path());
    fs::write(lower.join("base.txt"), b"base").unwrap();

    let gate = MutationGate::new_with_lease(1, i64::MAX).unwrap();
    let overlay = Overlay::new_with_gate(lower.clone(), upper.clone(), gate.clone()).unwrap();
    let handle = spawn(overlay, &mount).expect("kernel FUSE mount");
    assert_eq!(handle.queue_usage(), Default::default(), "fresh mount must start with empty budgets");

    // Sanity: reads work before the freeze.
    assert_eq!(fs::read(mount.join("base.txt")).unwrap(), b"base");

    // Freeze on a dedicated thread; the gate closure spans the whole scenario.
    let (entered_tx, entered_rx) = mpsc::channel();
    let (thaw_tx, thaw_rx) = mpsc::channel::<()>();
    let freeze_gate = gate.clone();
    let freezer = std::thread::spawn(move || {
        freeze_gate.freeze(|| {
            entered_tx.send(()).unwrap();
            thaw_rx.recv().expect("test thaw");
        })
    });
    entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(gate.is_frozen());

    // Frozen write A: the kernel open/create request parks in the FIFO and its
    // userspace caller stays blocked.
    let (a_done_tx, a_done_rx) = mpsc::channel();
    let a_path = mount.join("first.txt");
    let a = std::thread::spawn(move || {
        let result = write_new(a_path);
        a_done_tx.send(result).unwrap();
    });
    wait_until(|| handle.queue_usage().frozen >= 1, "frozen create to park");
    assert!(a_done_rx.recv_timeout(Duration::from_millis(300)).is_err(), "frozen create must wait, not EAGAIN");

    // A read must not be blocked by the parked mutation, and B's write must also
    // be admitted into the FIFO instead of erroring.
    assert_eq!(fs::read(mount.join("base.txt")).unwrap(), b"base");
    let (b_done_tx, b_done_rx) = mpsc::channel();
    let b_path = mount.join("second.txt");
    let b = std::thread::spawn(move || {
        let result = write_new(b_path);
        b_done_tx.send(result).unwrap();
    });
    wait_until(|| handle.queue_usage().frozen >= 2, "second frozen create to park");
    assert!(b_done_rx.recv_timeout(Duration::from_millis(300)).is_err(), "second frozen create must wait");

    // Thaw: the actor must notice without any new kernel request and drain FIFO.
    thaw_tx.send(()).unwrap();
    freezer.join().unwrap();
    a.join().unwrap();
    b.join().unwrap();
    assert!(a_done_rx.recv_timeout(Duration::from_secs(5)).unwrap().is_ok(), "first frozen create must succeed");
    assert!(b_done_rx.recv_timeout(Duration::from_secs(5)).unwrap().is_ok(), "second frozen create must succeed");
    assert_eq!(fs::read(upper.join("first.txt")).unwrap(), b"payload");
    assert_eq!(fs::read(upper.join("second.txt")).unwrap(), b"payload");

    // Fence: parked/new mutations fail EROFS, reads keep working.
    gate.fence();
    let error = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(mount.join("fenced.txt"))
        .expect_err("fenced mount must reject create");
    assert_eq!(error.raw_os_error(), Some(libc::EROFS));
    assert!(!upper.join("fenced.txt").exists());
    assert_eq!(fs::read(mount.join("base.txt")).unwrap(), b"base");

    // Every queued/delayed reply has finished and both budgets are returned.
    wait_until(|| handle.queue_usage() == Default::default(), "budgets to return to zero");
}
