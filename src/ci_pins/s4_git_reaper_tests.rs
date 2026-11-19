use super::*;
use crate::ci_pins::s4_git_runner::DisposableCiView;
use std::{path::{Path, PathBuf}, process::Stdio, sync::atomic::{AtomicBool, Ordering}};

const FINAL_SCRIPT: &str = r#"#!/bin/sh
exec >/dev/null
sh -c 'trap "" TERM; while :; do sleep 1; done' &
echo $$ $! > "$0.pids"
trap "" TERM
while :; do sleep 1; done"#;

const QUIET: OwnerPolicy = OwnerPolicy { signal_on_handoff: false, signal_on_sweep: false, ..PROD_OWNER_POLICY };

fn gone(pid: i32) -> bool {
    !PathBuf::from(format!("/proc/{pid}")).exists()
}

fn retained_contains_pid(registry: &UnresolvedRegistry, pid: i32) -> bool {
    registry.state.lock().unwrap_or_else(|e| e.into_inner()).retained.iter().any(|entry| entry.pid == pid)
}

fn unverified_scratch_len(registry: &UnresolvedRegistry) -> usize {
    registry.state.lock().unwrap_or_else(|e| e.into_inner()).unverified_scratch.len()
}

fn clear_unverified_scratch(registry: &UnresolvedRegistry) {
    registry.state.lock().unwrap_or_else(|e| e.into_inner()).unverified_scratch.clear();
}

fn assert_retained(registry: &UnresolvedRegistry, root: &Path, pid: i32, leader: i32) {
    assert!(retained_contains_pid(registry, pid), "live child was dropped by the continuing owner");
    assert!(!gone(leader), "leader was reaped before the owner swept it");
    assert!(root.exists(), "retained scratch vanished with the unresolved child");
}

async fn spawn_test_group() -> (DisposableCiView, PathBuf, Child, i32, i32, i32) {
    let view = DisposableCiView::create().expect("disposable view");
    let root = view.path().to_path_buf();
    let mut cmd = tokio::process::Command::new("/bin/sh");
    cmd.args(["-c", FINAL_SCRIPT, root.join("owner").to_str().unwrap()]);
    cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null()).kill_on_drop(true).process_group(0);
    let child = cmd.spawn().expect("spawn test group");
    let pid = i32::try_from(child.id().unwrap()).unwrap();
    let pids = root.join("owner.pids");
    for _ in 0..200 {
        if let Ok(text) = std::fs::read_to_string(&pids) {
            let mut values = text.split_whitespace().filter_map(|value| value.parse::<i32>().ok());
            if let (Some(leader), Some(grandchild)) = (values.next(), values.next()) {
                return (view, root, child, pid, leader, grandchild);
            }
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    panic!("test Git wrapper did not publish its process group");
}

async fn sweep_finish_released(registry: &UnresolvedRegistry, root: &Path, pid: i32, leader: i32, grandchild: i32) {
    for _ in 0..300 {
        registry.sweep_retained_once(true);
        if !retained_contains_pid(registry, pid) && gone(leader) && gone(grandchild) && !root.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!retained_contains_pid(registry, pid), "the continuing owner dropped a live child");
    assert!(gone(leader), "leader was left as a zombie");
    assert!(gone(grandchild), "grandchild survived cleanup");
    assert!(!root.exists(), "confirmed scratch was retained after the group was reaped");
}

#[tokio::test]
async fn unresolved_owner_retains_child_and_scratch_when_runtime_unavailable() {
    let (view, root, child, pid, leader, grandchild) = spawn_test_group().await;
    let holds = vec![view.hold()];
    drop(view);
    let registry = Arc::new(UnresolvedRegistry::default());
    let started = std::time::Instant::now();
    let worker = Arc::clone(&registry);
    let handoff = std::thread::spawn(move || {
        assert!(tokio::runtime::Handle::try_current().is_err());
        let entry = UnresolvedEntry::new(child, pid, holds, default_probe());
        let policy = OwnerPolicy { allow_thread_owner: false, ..QUIET };
        let _ = worker.handoff_with(entry, None, policy);
    });
    handoff.join().expect("handoff thread");
    assert!(started.elapsed() < Duration::from_millis(200), "handoff blocked the caller");
    assert_retained(&registry, &root, pid, leader);
    sweep_finish_released(&registry, &root, pid, leader, grandchild).await;
}

#[tokio::test]
async fn unresolved_owner_retains_child_and_scratch_when_queue_full() {
    let (view, root, child, pid, leader, grandchild) = spawn_test_group().await;
    let holds = vec![view.hold()];
    drop(view);
    let registry = Arc::new(UnresolvedRegistry::default());
    let entry = UnresolvedEntry::new(child, pid, holds, default_probe());
    let policy = OwnerPolicy { queue_cap: 0, ..QUIET };
    let _ = registry.handoff_with(entry, Some(tokio::runtime::Handle::current()), policy);
    assert_retained(&registry, &root, pid, leader);
    sweep_finish_released(&registry, &root, pid, leader, grandchild).await;
}

fn failing_wait(_child: &mut Child) -> WaitFuture<'_> {
    Box::pin(std::future::ready(Err(std::io::Error::other("simulated owner wait failure"))))
}

#[tokio::test]
async fn unresolved_owner_retains_child_and_scratch_when_owner_wait_fails() {
    let (view, root, child, pid, leader, grandchild) = spawn_test_group().await;
    let holds = vec![view.hold()];
    drop(view);
    let registry = Arc::new(UnresolvedRegistry::default());
    let entry = UnresolvedEntry::new(child, pid, holds, |_| Ok(true));
    let policy = OwnerPolicy { wait_child: failing_wait, wait_budget: Duration::from_millis(20), ..QUIET };
    let _ = registry.handoff_with(entry, Some(tokio::runtime::Handle::current()), policy);
    for _ in 0..100 {
        if retained_contains_pid(&registry, pid) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_retained(&registry, &root, pid, leader);
    sweep_finish_released(&registry, &root, pid, leader, grandchild).await;
}

static WAIT_ENTERED: AtomicBool = AtomicBool::new(false);

fn pending_wait(_child: &mut Child) -> WaitFuture<'_> {
    WAIT_ENTERED.store(true, Ordering::Release);
    Box::pin(std::future::pending())
}

#[tokio::test]
async fn unresolved_owner_retains_child_and_scratch_when_owner_task_cancelled() {
    WAIT_ENTERED.store(false, Ordering::Release);
    let (view, root, child, pid, leader, grandchild) = spawn_test_group().await;
    let holds = vec![view.hold()];
    drop(view);
    let registry = Arc::new(UnresolvedRegistry::default());
    let entry = UnresolvedEntry::new(child, pid, holds, |_| Ok(true));
    let policy = OwnerPolicy { wait_child: pending_wait, wait_budget: Duration::from_secs(60), ..QUIET };
    let task = registry
        .handoff_with(entry, Some(tokio::runtime::Handle::current()), policy)
        .expect("spawned owner task");
    for _ in 0..500 {
        if WAIT_ENTERED.load(Ordering::Acquire) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert!(WAIT_ENTERED.load(Ordering::Acquire), "owner task never parked inside its wait");
    assert!(!retained_contains_pid(&registry, pid), "in-flight entry must leave the retained queue");
    assert!(root.exists(), "in-flight entry lost scratch before the reap proof");
    task.abort();
    let _ = task.await;
    assert!(retained_contains_pid(&registry, pid), "cancelling owner task dropped the in-flight child");
    assert!(!gone(leader), "leader died unexpectedly during quiet cancellation");
    assert!(root.exists(), "cancelling owner task dropped scratch before reap");
    sweep_finish_released(&registry, &root, pid, leader, grandchild).await;
}

#[tokio::test]
async fn unresolved_owner_standby_sweeper_reaps_without_runtime_or_new_thread() {
    let registry = Arc::new(UnresolvedRegistry::default());
    registry.ensure_standby_sweeper();
    let (view, root, child, pid, leader, grandchild) = spawn_test_group().await;
    let holds = vec![view.hold()];
    drop(view);
    let worker = Arc::clone(&registry);
    let handoff = std::thread::spawn(move || {
        assert!(tokio::runtime::Handle::try_current().is_err());
        let entry = UnresolvedEntry::new(child, pid, holds, default_probe());
        let policy = OwnerPolicy { allow_thread_owner: false, ..PROD_OWNER_POLICY };
        let _ = worker.handoff_with(entry, None, policy);
    });
    handoff.join().expect("handoff thread");
    for _ in 0..300 {
        if !retained_contains_pid(&registry, pid) && gone(leader) && gone(grandchild) && !root.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!retained_contains_pid(&registry, pid), "pre-warmed standby sweeper left a live entry retained");
    assert!(gone(leader), "leader was left as a zombie");
    assert!(gone(grandchild), "grandchild survived cleanup");
    assert!(!root.exists(), "pre-warmed standby sweeper did not release confirmed scratch");
    let mut state = registry.state.lock().unwrap_or_else(|e| e.into_inner());
    state.standby_stop = true;
    drop(state);
    registry.wake.notify_all();
}

fn unknown_probe(_pid: i32) -> std::io::Result<bool> {
    Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "unknown group"))
}

#[tokio::test]
async fn unresolved_owner_preserves_scratch_only_when_group_outcome_is_unknown() {
    let (view, root, child, pid, leader, grandchild) = spawn_test_group().await;
    let holds = vec![view.hold()];
    drop(view);
    let registry = Arc::new(UnresolvedRegistry::default());
    let entry = UnresolvedEntry::new(child, pid, holds, unknown_probe);
    let _ = registry.handoff_with(entry, Some(tokio::runtime::Handle::current()), PROD_OWNER_POLICY);
    for _ in 0..300 {
        if !retained_contains_pid(&registry, pid) && gone(leader) && gone(grandchild) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(root.exists(), "unknown group outcome must preserve scratch");
    assert_eq!(unverified_scratch_len(&registry), 1, "uncertain scratch must be retained as unverified");
    clear_unverified_scratch(&registry);
    let _ = std::fs::remove_dir_all(&root);
}
