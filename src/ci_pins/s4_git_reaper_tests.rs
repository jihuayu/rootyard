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

fn proc_is_zombie(pid: i32) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    stat.rsplit_once(") ")
        .and_then(|(_, rest)| rest.split_whitespace().next())
        .is_some_and(|state| state == "Z" || state == "X")
}

fn queue_len(registry: &UnresolvedRegistry) -> usize {
    registry.state.lock().unwrap_or_else(|e| e.into_inner()).queue.len()
}

fn is_active_task(registry: &UnresolvedRegistry) -> bool {
    registry.state.lock().unwrap_or_else(|e| e.into_inner()).active_task
}

fn stop_standby(registry: &UnresolvedRegistry) {
    let mut state = registry.state.lock().unwrap_or_else(|e| e.into_inner());
    state.standby_stop = true;
    drop(state);
    registry.wake.notify_all();
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
static QUEUE_WAIT_ENTERED: AtomicBool = AtomicBool::new(false);

fn pending_wait(_child: &mut Child) -> WaitFuture<'_> {
    WAIT_ENTERED.store(true, Ordering::Release);
    Box::pin(std::future::pending())
}

fn queue_pending_wait(_child: &mut Child) -> WaitFuture<'_> {
    QUEUE_WAIT_ENTERED.store(true, Ordering::Release);
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
    stop_standby(&registry);
}

static ALLOW_REAPER_PROBE: AtomicBool = AtomicBool::new(false);

fn gated_probe(pid: i32) -> std::io::Result<bool> {
    if ALLOW_REAPER_PROBE.load(Ordering::Acquire) {
        default_probe()(pid)
    } else {
        Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "unknown group"))
    }
}

#[tokio::test]
async fn unresolved_owner_preserves_scratch_only_when_group_outcome_is_unknown() {
    ALLOW_REAPER_PROBE.store(false, Ordering::Release);
    let (view, root, child, pid, leader, grandchild) = spawn_test_group().await;
    let holds = vec![view.hold()];
    drop(view);
    let registry = Arc::new(UnresolvedRegistry::default());
    let entry = UnresolvedEntry::new(child, pid, holds, gated_probe);
    let _ = registry.handoff_with(entry, Some(tokio::runtime::Handle::current()), PROD_OWNER_POLICY);
    for _ in 0..300 {
        if gone(grandchild) && proc_is_zombie(leader) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(120)).await;
    for _ in 0..300 {
        if retained_contains_pid(&registry, pid) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(retained_contains_pid(&registry, pid), "unknown-group entry was dropped before quiescence");
    assert!(proc_is_zombie(leader), "leader was reaped prematurely on probe error, releasing PGID");
    assert!(gone(grandchild), "grandchild survived SIGKILL");
    assert!(root.exists(), "uncertain scratch vanished while group probe errored");
    ALLOW_REAPER_PROBE.store(true, Ordering::Release);
    for _ in 0..300 {
        if !retained_contains_pid(&registry, pid) && gone(leader) && !root.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!retained_contains_pid(&registry, pid), "confirmed entry was not released");
    assert!(gone(leader), "leader was not reaped after the group probe recovered");
    assert!(!root.exists(), "uncertain scratch outlived the confirmed group");
}

#[tokio::test]
async fn unresolved_owner_cancellation_drains_pending_queue_and_clears_active_task() {
    QUEUE_WAIT_ENTERED.store(false, Ordering::Release);
    let (view1, root1, child1, pid1, leader1, grandchild1) = spawn_test_group().await;
    let (view2, root2, child2, pid2, leader2, grandchild2) = spawn_test_group().await;
    let registry = Arc::new(UnresolvedRegistry::default());
    let policy = OwnerPolicy { wait_child: queue_pending_wait, wait_budget: Duration::from_secs(60), ..QUIET };
    let entry1 = UnresolvedEntry::new(child1, pid1, vec![view1.hold()], |_| Ok(true));
    let entry2 = UnresolvedEntry::new(child2, pid2, vec![view2.hold()], default_probe());
    drop(view1);
    drop(view2);
    let handle = tokio::runtime::Handle::current();
    let task = registry.handoff_with(entry1, Some(handle.clone()), policy).expect("spawned owner task");
    assert!(registry.handoff_with(entry2, Some(handle), policy).is_none(), "second entry must reuse the owner task");
    for _ in 0..500 {
        if QUEUE_WAIT_ENTERED.load(Ordering::Acquire) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    assert!(QUEUE_WAIT_ENTERED.load(Ordering::Acquire), "owner task never parked inside its wait");
    assert_eq!(queue_len(&registry), 1, "second entry must sit in the shared owner queue");
    task.abort();
    let _ = task.await;
    assert!(!is_active_task(&registry), "active_task remained set after owner cancellation");
    assert_eq!(queue_len(&registry), 0, "pending queue was not drained into retained on cancellation");
    assert!(
        retained_contains_pid(&registry, pid1) && retained_contains_pid(&registry, pid2),
        "both entries must be retained"
    );
    assert!(root1.exists() && root2.exists(), "scratch vanished during cancellation");
    registry.ensure_standby_sweeper();
    registry.wake.notify_all();
    for _ in 0..300 {
        let cleared = !retained_contains_pid(&registry, pid1)
            && !retained_contains_pid(&registry, pid2)
            && gone(leader1)
            && gone(grandchild1)
            && gone(leader2)
            && gone(grandchild2)
            && !root1.exists()
            && !root2.exists();
        if cleared {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        !retained_contains_pid(&registry, pid1) && !retained_contains_pid(&registry, pid2),
        "standby did not release retained children"
    );
    assert!(gone(leader1) && gone(grandchild1) && gone(leader2) && gone(grandchild2), "standby left a live process");
    assert!(!root1.exists() && !root2.exists(), "standby did not release confirmed scratch");
    stop_standby(&registry);
}

#[tokio::test]
async fn unresolved_owner_failed_start_and_runtime_shutdown_retain_child_and_scratch() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("temp rt");
    let dead_handle = rt.handle().clone();
    drop(rt);
    let registry = Arc::new(UnresolvedRegistry::default());
    let (view1, root1, child1, pid1, leader1, grandchild1) = spawn_test_group().await;
    let entry1 = UnresolvedEntry::new(child1, pid1, vec![view1.hold()], default_probe());
    drop(view1);
    if let Some(handle) = registry.handoff_with(entry1, Some(dead_handle.clone()), QUIET) {
        let _ = handle.await;
    }
    assert!(!is_active_task(&registry), "failed owner start left active_task set");
    assert_eq!(queue_len(&registry), 0, "failed owner start left the queue undrained");
    assert!(retained_contains_pid(&registry, pid1), "failed owner start dropped the child");
    assert!(!gone(leader1), "failed owner start reaped the leader");
    assert!(root1.exists(), "failed owner start dropped scratch");
    let (view2, root2, child2, pid2, leader2, grandchild2) = spawn_test_group().await;
    let entry2 = UnresolvedEntry::new(child2, pid2, vec![view2.hold()], default_probe());
    drop(view2);
    let _ = spawn_fallback_on_handle(Arc::clone(&registry), entry2, &dead_handle, default_wait_child, QUIET).await;
    assert!(retained_contains_pid(&registry, pid2), "shutdown fallback dropped the child");
    assert!(!gone(leader2), "shutdown fallback reaped the leader");
    assert!(root2.exists(), "shutdown fallback dropped scratch");
    registry.ensure_standby_sweeper();
    registry.wake.notify_all();
    for _ in 0..300 {
        let cleared = !retained_contains_pid(&registry, pid1)
            && !retained_contains_pid(&registry, pid2)
            && gone(leader1)
            && gone(grandchild1)
            && gone(leader2)
            && gone(grandchild2)
            && !root1.exists()
            && !root2.exists();
        if cleared {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        !retained_contains_pid(&registry, pid1) && !retained_contains_pid(&registry, pid2),
        "standby did not release shutdown-retained children"
    );
    assert!(gone(leader1) && gone(grandchild1) && gone(leader2) && gone(grandchild2), "standby left a live process");
    assert!(!root1.exists() && !root2.exists(), "standby did not release shutdown-retained scratch");
    stop_standby(&registry);
}
