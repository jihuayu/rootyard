//! Continuing process-group reaper and unresolved-child owner for S4 and Git View.
#[cfg(unix)]
use crate::git_http::group_quiescent;
use super::s4_git_runner::{ScratchHold, child_gone, signal_group};
use std::{collections::VecDeque, process::ExitStatus, sync::{Arc, Mutex, OnceLock}, time::Duration};
use tokio::process::Child;

const FALLBACK_ASYNC_BUDGET: Duration = Duration::from_millis(250);
const UNRESOLVED_OWNER_CAP: usize = 256;
const OWNER_WAIT_BUDGET: Duration = Duration::from_secs(2);
const RETAINED_SWEEP_INTERVAL: Duration = Duration::from_millis(50);

pub(crate) type ReaperTask = Box<dyn FnOnce() + Send + 'static>;
pub(crate) type GroupProbe = fn(i32) -> std::io::Result<bool>;
pub(super) type WaitFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<ExitStatus>> + Send + 'a>>;
pub(super) type WaitChildFn = for<'a> fn(&'a mut Child) -> WaitFuture<'a>;
fn default_wait_child(child: &mut Child) -> WaitFuture<'_> {
    Box::pin(child.wait())
}
#[derive(Clone, Copy)]
struct OwnerPolicy {
    queue_cap: usize,
    wait_child: WaitChildFn,
    wait_budget: Duration,
    signal_on_handoff: bool,
    signal_on_sweep: bool,
    allow_thread_owner: bool,
}
const PROD_OWNER_POLICY: OwnerPolicy = OwnerPolicy {
    queue_cap: UNRESOLVED_OWNER_CAP,
    wait_child: default_wait_child,
    wait_budget: OWNER_WAIT_BUDGET,
    signal_on_handoff: true,
    signal_on_sweep: true,
    allow_thread_owner: true,
};

struct UnresolvedEntry {
    child: Child,
    pid: i32,
}

#[derive(Default)]
struct UnresolvedState {
    queue: VecDeque<UnresolvedEntry>,
    retained: Vec<UnresolvedEntry>,
    active_task: bool,
    active_thread: bool,
}
#[derive(Default)]
struct UnresolvedRegistry {
    state: Mutex<UnresolvedState>,
    scratch: Mutex<Vec<Vec<ScratchHold>>>,
}

static RETAINED_REGISTRY: OnceLock<Arc<UnresolvedRegistry>> = OnceLock::new();
fn global_registry() -> &'static Arc<UnresolvedRegistry> {
    RETAINED_REGISTRY.get_or_init(|| Arc::new(UnresolvedRegistry::new()))
}

struct TaskActiveGuard {
    registry: Arc<UnresolvedRegistry>,
    armed: bool,
}
impl Drop for TaskActiveGuard {
    fn drop(&mut self) {
        if self.armed {
            let mut state = self.registry.state.lock().unwrap_or_else(|e| e.into_inner());
            state.active_task = false;
        }
    }
}
struct ThreadActiveGuard {
    registry: Arc<UnresolvedRegistry>,
    armed: bool,
}
impl Drop for ThreadActiveGuard {
    fn drop(&mut self) {
        if self.armed {
            let mut state = self.registry.state.lock().unwrap_or_else(|e| e.into_inner());
            state.active_thread = false;
        }
    }
}

impl UnresolvedRegistry {
    fn new() -> Self {
        Self::default()
    }

    fn retain_scratch(&self, holds: Vec<ScratchHold>) {
        if !holds.is_empty() {
            self.scratch.lock().unwrap_or_else(|e| e.into_inner()).push(holds);
        }
    }

    fn sweep_retained_once(&self, signal: bool) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.retained.retain_mut(|entry| {
            if signal {
                signal_group(&mut entry.child, entry.pid);
            }
            !child_gone(&mut entry.child)
        });
    }

    fn handoff_with(
        self: &Arc<Self>,
        mut child: Child,
        pid: i32,
        holds: Vec<ScratchHold>,
        runtime: Option<tokio::runtime::Handle>,
        policy: OwnerPolicy,
    ) {
        self.retain_scratch(holds);
        if child_gone(&mut child) {
            return;
        }
        if policy.signal_on_handoff {
            signal_group(&mut child, pid);
            if child_gone(&mut child) {
                return;
            }
        }
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.retained.retain_mut(|entry| !child_gone(&mut entry.child));
        let Some(handle) = runtime else {
            state.retained.push(UnresolvedEntry { child, pid });
            let spawn_thread = policy.allow_thread_owner && !state.active_thread;
            state.active_thread |= spawn_thread;
            drop(state);
            if spawn_thread {
                let reg = Arc::clone(self);
                let spawned = std::thread::Builder::new()
                    .name("s4-git-retained".into())
                    .spawn(move || run_retained_thread_owner(reg));
                if spawned.is_err() {
                    let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
                    guard.active_thread = false;
                }
            }
            return;
        };
        state.queue.retain_mut(|entry| !child_gone(&mut entry.child));
        if state.queue.len() < policy.queue_cap {
            state.queue.push_back(UnresolvedEntry { child, pid });
        } else {
            state.retained.push(UnresolvedEntry { child, pid });
        }
        let spawn_task = !state.active_task;
        state.active_task |= spawn_task;
        drop(state);
        if spawn_task {
            let reg = Arc::clone(self);
            handle.spawn(async move {
                run_unresolved_owner_task(reg, policy).await;
            });
        }
    }
}

async fn run_unresolved_owner_task(registry: Arc<UnresolvedRegistry>, policy: OwnerPolicy) {
    let mut guard = TaskActiveGuard { registry: Arc::clone(&registry), armed: true };
    loop {
        let next = registry.state.lock().unwrap_or_else(|e| e.into_inner()).queue.pop_front();
        if let Some(mut entry) = next {
            if policy.signal_on_sweep {
                signal_group(&mut entry.child, entry.pid);
            }
            let waited = tokio::time::timeout(policy.wait_budget, (policy.wait_child)(&mut entry.child)).await;
            if !matches!(waited, Ok(Ok(_))) && !child_gone(&mut entry.child) {
                let mut state = registry.state.lock().unwrap_or_else(|e| e.into_inner());
                state.retained.push(entry);
            }
            continue;
        }
        registry.sweep_retained_once(policy.signal_on_sweep);
        let done = {
            let mut state = registry.state.lock().unwrap_or_else(|e| e.into_inner());
            let empty = state.queue.is_empty() && state.retained.is_empty();
            if empty {
                state.active_task = false;
                guard.armed = false;
            }
            empty
        };
        if done {
            return;
        }
        tokio::time::sleep(RETAINED_SWEEP_INTERVAL).await;
    }
}

fn run_retained_thread_owner(registry: Arc<UnresolvedRegistry>) {
    let mut guard = ThreadActiveGuard { registry: Arc::clone(&registry), armed: true };
    loop {
        registry.sweep_retained_once(true);
        let done = {
            let mut state = registry.state.lock().unwrap_or_else(|e| e.into_inner());
            let empty = state.retained.is_empty();
            if empty {
                state.active_thread = false;
                guard.armed = false;
            }
            empty
        };
        if done {
            return;
        }
        std::thread::sleep(RETAINED_SWEEP_INTERVAL);
    }
}

pub(crate) fn spawn_reaper_with<F>(child: Child, pid: i32, holds: Vec<ScratchHold>, spawn_fn: F)
where
    F: FnOnce(ReaperTask) -> std::io::Result<()>,
{
    #[cfg(unix)]
    let probe: GroupProbe = group_quiescent;
    #[cfg(not(unix))]
    let probe: GroupProbe = |_| Ok(true);
    spawn_reaper_with_probe(child, pid, holds, spawn_fn, probe);
}

pub(crate) fn spawn_reaper_with_probe<F>(
    child: Child,
    pid: i32,
    holds: Vec<ScratchHold>,
    spawn_fn: F,
    probe: GroupProbe,
) where
    F: FnOnce(ReaperTask) -> std::io::Result<()>,
{
    let mut fallback = SpawnFallback { state: Some((child, pid, holds, probe)) };
    let spawned = spawn_fn(Box::new(move || {
        if let Some((child, pid, holds, probe)) = fallback.state.take() {
            reap_until_confirmed(child, pid, holds, probe);
        }
    }));
    drop(spawned);
}

struct SpawnFallback {
    state: Option<(Child, i32, Vec<ScratchHold>, GroupProbe)>,
}

impl Drop for SpawnFallback {
    fn drop(&mut self) {
        let Some((mut child, pid, holds, probe)) = self.state.take() else {
            return;
        };
        signal_group(&mut child, pid);
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(reap_fallback_bounded(child, pid, holds, probe));
            return;
        }
        #[cfg(unix)]
        let quiescent = pid <= 1 || matches!(probe(pid), Ok(true));
        #[cfg(not(unix))]
        let quiescent = {
            let _ = probe;
            true
        };
        if quiescent && child_gone(&mut child) {
            drop(child);
            drop(holds);
            return;
        }
        eprintln!("rootyard: Git reaper fallback timed out or group probe failed; preserving unverified scratch");
        handoff_unresolved_child(child, pid, holds);
    }
}

async fn reap_fallback_bounded(child: Child, pid: i32, holds: Vec<ScratchHold>, probe: GroupProbe) {
    reap_fallback_with_wait(child, pid, holds, probe, default_wait_child).await;
}

pub(super) async fn reap_fallback_with_wait(
    mut child: Child,
    pid: i32,
    holds: Vec<ScratchHold>,
    probe: GroupProbe,
    wait_child: WaitChildFn,
) {
    signal_group(&mut child, pid);
    let confirmed = pid <= 1
        || child.id().is_none()
        || tokio::time::timeout(FALLBACK_ASYNC_BUDGET, async {
            while !matches!(probe(pid), Ok(true)) {
                signal_group(&mut child, pid);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .is_ok();
    let reaped = confirmed
        && (matches!(tokio::time::timeout(Duration::from_secs(1), wait_child(&mut child)).await, Ok(Ok(_)))
            || child.id().is_none());
    if !reaped {
        eprintln!("rootyard: Git reaper fallback timed out or group probe failed; preserving unverified scratch");
        handoff_unresolved_child(child, pid, holds);
        return;
    }
    drop(child);
    drop(holds);
}

fn handoff_unresolved_child(child: Child, pid: i32, holds: Vec<ScratchHold>) {
    global_registry().handoff_with(child, pid, holds, tokio::runtime::Handle::try_current().ok(), PROD_OWNER_POLICY);
}

fn reap_until_confirmed(mut child: Child, pid: i32, holds: Vec<ScratchHold>, probe: GroupProbe) {
    if pid > 1 {
        let started = std::time::Instant::now();
        let mut reported = false;
        while !matches!(probe(pid), Ok(true)) {
            signal_group(&mut child, pid);
            if !reported && started.elapsed() > Duration::from_secs(5) {
                eprintln!("rootyard: cancelled Git process group cleanup blocked; retaining scratch hold");
                reported = true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    while !child_gone(&mut child) {
        std::thread::sleep(Duration::from_millis(5));
    }
    drop(holds);
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::*;
    use crate::ci_pins::s4_git_runner::DisposableCiView;
    use std::{path::{Path, PathBuf}, process::Stdio};

    const FINAL_SCRIPT: &str = r#"#!/bin/sh
exec >/dev/null
sh -c 'trap "" TERM; while :; do sleep 1; done' &
echo $$ $! > "$0.pids"
trap "" TERM
while :; do sleep 1; done"#;

    const QUIET: OwnerPolicy = OwnerPolicy {
        signal_on_handoff: false,
        signal_on_sweep: false,
        ..PROD_OWNER_POLICY
    };

    fn gone(pid: i32) -> bool {
        !PathBuf::from(format!("/proc/{pid}")).exists()
    }

    fn retained_contains_pid(registry: &UnresolvedRegistry, pid: i32) -> bool {
        registry.state.lock().unwrap_or_else(|e| e.into_inner()).retained.iter().any(|entry| entry.pid == pid)
    }

    fn assert_retained(registry: &UnresolvedRegistry, root: &Path, pid: i32, leader: i32) {
        assert!(retained_contains_pid(registry, pid), "live child was dropped by the continuing owner");
        assert!(!gone(leader), "leader was reaped before the owner swept it");
        assert!(root.exists(), "retained scratch vanished with the unresolved child");
    }

    fn clear_scratch(registry: &UnresolvedRegistry) {
        registry.scratch.lock().unwrap_or_else(|e| e.into_inner()).clear();
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

    async fn sweep_finish(registry: &UnresolvedRegistry, root: &Path, pid: i32, leader: i32, grandchild: i32) {
        for _ in 0..300 {
            registry.sweep_retained_once(true);
            if !retained_contains_pid(registry, pid) && gone(leader) && gone(grandchild) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(!retained_contains_pid(registry, pid), "the continuing owner dropped a live child");
        assert!(gone(leader), "leader was left as a zombie");
        assert!(gone(grandchild), "grandchild survived cleanup");
        assert!(root.exists(), "retained scratch vanished with the unresolved child");
        clear_scratch(registry);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn unresolved_owner_retains_child_and_scratch_when_runtime_unavailable() {
        let (view, root, child, pid, leader, grandchild) = spawn_test_group().await;
        let holds = vec![view.hold()];
        drop(view);
        let registry = Arc::new(UnresolvedRegistry::new());
        let started = std::time::Instant::now();
        let worker = Arc::clone(&registry);
        let handoff = std::thread::spawn(move || {
            assert!(tokio::runtime::Handle::try_current().is_err());
            let policy = OwnerPolicy { allow_thread_owner: false, ..QUIET };
            worker.handoff_with(child, pid, holds, None, policy);
        });
        handoff.join().expect("handoff thread");
        assert!(started.elapsed() < Duration::from_millis(200), "handoff blocked the caller");
        assert_retained(&registry, &root, pid, leader);
        sweep_finish(&registry, &root, pid, leader, grandchild).await;
    }

    #[tokio::test]
    async fn unresolved_owner_retains_child_and_scratch_when_queue_full() {
        let (view, root, child, pid, leader, grandchild) = spawn_test_group().await;
        let holds = vec![view.hold()];
        drop(view);
        let registry = Arc::new(UnresolvedRegistry::new());
        let policy = OwnerPolicy { queue_cap: 0, ..QUIET };
        registry.handoff_with(child, pid, holds, Some(tokio::runtime::Handle::current()), policy);
        assert_retained(&registry, &root, pid, leader);
        sweep_finish(&registry, &root, pid, leader, grandchild).await;
    }

    fn failing_wait(_child: &mut Child) -> WaitFuture<'_> {
        Box::pin(std::future::ready(Err(std::io::Error::other("simulated owner wait failure"))))
    }

    #[tokio::test]
    async fn unresolved_owner_retains_child_and_scratch_when_owner_wait_fails() {
        let (view, root, child, pid, leader, grandchild) = spawn_test_group().await;
        let holds = vec![view.hold()];
        drop(view);
        let registry = Arc::new(UnresolvedRegistry::new());
        let policy = OwnerPolicy { wait_child: failing_wait, wait_budget: Duration::from_millis(20), ..QUIET };
        registry.handoff_with(child, pid, holds, Some(tokio::runtime::Handle::current()), policy);
        for _ in 0..100 {
            if retained_contains_pid(&registry, pid) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_retained(&registry, &root, pid, leader);
        sweep_finish(&registry, &root, pid, leader, grandchild).await;
    }
}
