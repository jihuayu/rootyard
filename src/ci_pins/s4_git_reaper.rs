//! Continuing process-group reaper and unresolved-child owner for S4 and Git View.
#[cfg(unix)]
use crate::git_http::group_quiescent;
use super::s4_git_runner::{ScratchHold, child_gone, signal_group};
use std::{
    collections::VecDeque,
    process::ExitStatus,
    sync::{Arc, Condvar, Mutex, OnceLock},
    time::Duration,
};
use tokio::process::Child;

const FALLBACK_ASYNC_BUDGET: Duration = Duration::from_millis(250);
const UNRESOLVED_OWNER_CAP: usize = 256;
const OWNER_WAIT_BUDGET: Duration = Duration::from_secs(2);
const RETAINED_SWEEP_INTERVAL: Duration = Duration::from_millis(50);
const FALLBACK_DIAGNOSTIC: &str =
    "rootyard: Git reaper fallback timed out or group probe failed; handing off unresolved child\n";
const BLOCKED_DIAGNOSTIC: &str =
    "rootyard: cancelled Git process group cleanup blocked; retaining scratch hold\n";
fn write_reaper_diagnostic(msg: &str) {
    let _ = std::io::Write::write_all(&mut std::io::stderr(), msg.as_bytes());
}
pub(crate) type ReaperTask = Box<dyn FnOnce() + Send + 'static>;
pub(crate) type GroupProbe = fn(i32) -> std::io::Result<bool>;
pub(super) type WaitFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<ExitStatus>> + Send + 'a>>;
pub(super) type WaitChildFn = for<'a> fn(&'a mut Child) -> WaitFuture<'a>;
fn default_wait_child(child: &mut Child) -> WaitFuture<'_> {
    Box::pin(child.wait())
}
#[cfg(unix)]
pub(crate) fn default_probe() -> GroupProbe {
    group_quiescent
}
#[cfg(not(unix))]
pub(crate) fn default_probe() -> GroupProbe {
    |_| Ok(true)
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
    holds: Vec<ScratchHold>,
    probe: GroupProbe,
    group_confirmed: bool,
    reaped: bool,
}
impl UnresolvedEntry {
    fn new(child: Child, pid: i32, holds: Vec<ScratchHold>, probe: GroupProbe) -> Self {
        Self { group_confirmed: pid <= 1 || child.id().is_none(), child, pid, holds, probe, reaped: false }
    }
}
/// Keeps the leader unreaped until `(entry.probe)(entry.pid)` returns `Ok(true)`
/// (preserving PGID ownership on both `Ok(false)` and `Err(_)`) and releases
/// `entry.holds` only after both group quiescence and leader reap are proved.
fn try_resolve_entry(entry: &mut UnresolvedEntry, signal: bool) -> bool {
    if !entry.group_confirmed {
        if signal && !entry.reaped {
            signal_group(&mut entry.child, entry.pid);
        }
        if !matches!((entry.probe)(entry.pid), Ok(true)) {
            return false;
        }
        entry.group_confirmed = true;
    }
    if signal && !entry.reaped {
        signal_group(&mut entry.child, entry.pid);
    }
    entry.reaped |= child_gone(&mut entry.child);
    if entry.reaped {
        entry.holds.clear();
    }
    entry.reaped
}
#[derive(Default)]
struct UnresolvedState {
    queue: VecDeque<UnresolvedEntry>,
    retained: Vec<UnresolvedEntry>,
    active_task: bool,
    standby_started: bool,
    standby_stop: bool,
}
#[derive(Default)]
struct UnresolvedRegistry {
    state: Mutex<UnresolvedState>,
    standby_init: Mutex<()>,
    wake: Condvar,
}
static RETAINED_REGISTRY: OnceLock<Arc<UnresolvedRegistry>> = OnceLock::new();
fn global_registry() -> &'static Arc<UnresolvedRegistry> {
    RETAINED_REGISTRY.get_or_init(|| Arc::new(UnresolvedRegistry::default()))
}
/// Pre-warms the standby OS sweeper so a runtime-less or cancelled handoff sweeps via `Condvar`.
pub(crate) fn warm_standby_reaper() -> std::io::Result<()> {
    global_registry().ensure_standby_sweeper()
}
struct FlagGuard {
    registry: Arc<UnresolvedRegistry>,
    standby: bool,
    armed: bool,
}
impl Drop for FlagGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let should_wake = {
            let mut state = self.registry.state.lock().unwrap_or_else(|e| e.into_inner());
            if self.standby {
                state.standby_started = false;
                false
            } else {
                state.active_task = false;
                while let Some(queued) = state.queue.pop_front() {
                    state.retained.push(queued);
                }
                !state.retained.is_empty()
            }
        };
        if should_wake {
            self.registry.wake.notify_all();
        }
    }
}
/// Retains ownership of an `UnresolvedEntry` across task startup, `.await` points,
/// and runtime shutdown; `Drop` returns any uncompleted entry to `state.retained`.
struct InFlightEntryGuard {
    registry: Arc<UnresolvedRegistry>,
    entry: Option<UnresolvedEntry>,
}
impl Drop for InFlightEntryGuard {
    fn drop(&mut self) {
        if let Some(entry) = self.entry.take() {
            self.registry.requeue_retained(entry);
        }
    }
}
impl UnresolvedRegistry {
    fn ensure_standby_sweeper(self: &Arc<Self>) -> std::io::Result<()> {
        let spawn = |task| std::thread::Builder::new().name("s4-git-standby".into()).spawn(task).map(|_| ());
        self.ensure_standby_sweeper_with(spawn)
    }
    fn ensure_standby_sweeper_with<F>(self: &Arc<Self>, spawn_standby: F) -> std::io::Result<()>
    where
        F: FnOnce(ReaperTask) -> std::io::Result<()>,
    {
        let _init = self.standby_init.lock().unwrap_or_else(|e| e.into_inner());
        {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.standby_started {
                return Ok(());
            }
            state.standby_started = true;
            state.standby_stop = false;
        }
        let reg = Arc::clone(self);
        let guard = FlagGuard { registry: Arc::clone(self), standby: true, armed: true };
        spawn_standby(Box::new(move || run_standby_sweeper(reg, guard)))
    }
    fn requeue_retained(&self, entry: UnresolvedEntry) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.retained.push(entry);
        drop(state);
        self.wake.notify_all();
    }
    fn settle_or_retain(&self, mut entry: UnresolvedEntry, signal: bool) {
        if !try_resolve_entry(&mut entry, signal) {
            self.requeue_retained(entry);
        }
    }
    fn pop_queued(&self) -> Option<UnresolvedEntry> {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).queue.pop_front()
    }
    fn finish_owner_cycle(&self, guard: &mut FlagGuard) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let empty = state.queue.is_empty() && state.retained.is_empty();
        if empty {
            state.active_task = false;
            guard.armed = false;
        }
        empty
    }
    fn sweep_retained_once(&self, signal: bool) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.retained.retain_mut(|entry| !try_resolve_entry(entry, signal));
    }
    fn opportunistic_sweep(&self, include_queue: bool) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.retained.retain_mut(|item| !try_resolve_entry(item, false));
        if include_queue {
            state.queue.retain_mut(|item| !try_resolve_entry(item, false));
        }
    }
    fn handoff_guarded(
        self: &Arc<Self>,
        mut guard: InFlightEntryGuard,
        runtime: Option<tokio::runtime::Handle>,
        policy: OwnerPolicy,
    ) -> Option<tokio::task::JoinHandle<()>> {
        if try_resolve_entry(guard.entry.as_mut().expect("guarded entry present"), policy.signal_on_handoff) {
            let _ = guard.entry.take();
            return None;
        }
        self.opportunistic_sweep(runtime.is_some());
        let entry = guard.entry.take().expect("guarded entry present");
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let Some(handle) = runtime else {
            state.retained.push(entry);
            let need_standby = policy.allow_thread_owner && !state.standby_started;
            drop(state);
            self.wake.notify_all();
            if need_standby {
                let _ = self.ensure_standby_sweeper();
                self.wake.notify_all();
            }
            return None;
        };
        if state.queue.len() < policy.queue_cap {
            state.queue.push_back(entry);
        } else {
            state.retained.push(entry);
            self.wake.notify_all();
        }
        let spawn_task = !std::mem::replace(&mut state.active_task, true);
        drop(state);
        if spawn_task {
            let task_guard = FlagGuard { registry: Arc::clone(self), standby: false, armed: true };
            return Some(handle.spawn(run_unresolved_owner_task(Arc::clone(self), task_guard, policy)));
        }
        None
    }
    #[cfg(test)]
    fn handoff_with(
        self: &Arc<Self>,
        entry: UnresolvedEntry,
        runtime: Option<tokio::runtime::Handle>,
        policy: OwnerPolicy,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let guard = InFlightEntryGuard { registry: Arc::clone(self), entry: Some(entry) };
        self.handoff_guarded(guard, runtime, policy)
    }
}
async fn run_unresolved_owner_task(registry: Arc<UnresolvedRegistry>, mut guard: FlagGuard, policy: OwnerPolicy) {
    loop {
        if let Some(entry) = registry.pop_queued() {
            let mut in_flight = InFlightEntryGuard { registry: Arc::clone(&registry), entry: Some(entry) };
            let ready_for_wait = {
                let current = in_flight.entry.as_mut().expect("in-flight entry present");
                if policy.signal_on_sweep && !current.reaped {
                    signal_group(&mut current.child, current.pid);
                }
                if !current.group_confirmed {
                    current.group_confirmed = matches!((current.probe)(current.pid), Ok(true));
                }
                current.group_confirmed
            };
            let waited = if ready_for_wait {
                let current = in_flight.entry.as_mut().expect("in-flight entry present");
                Some(tokio::time::timeout(policy.wait_budget, (policy.wait_child)(&mut current.child)).await)
            } else {
                None
            };
            let mut entry = in_flight.entry.take().expect("in-flight entry present");
            entry.reaped |= matches!(waited, Some(Ok(Ok(_))));
            registry.settle_or_retain(entry, policy.signal_on_sweep);
            continue;
        }
        registry.sweep_retained_once(policy.signal_on_sweep);
        if registry.finish_owner_cycle(&mut guard) {
            return;
        }
        tokio::time::sleep(RETAINED_SWEEP_INTERVAL).await;
    }
}
fn run_standby_sweeper(registry: Arc<UnresolvedRegistry>, _guard: FlagGuard) {
    loop {
        {
            let state = registry.state.lock().unwrap_or_else(|e| e.into_inner());
            let state = registry.wake.wait_while(state, |s| s.retained.is_empty() && !s.standby_stop);
            let state = state.unwrap_or_else(|e| e.into_inner());
            if state.standby_stop && state.retained.is_empty() {
                return;
            }
        }
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| registry.sweep_retained_once(true)));
        if !registry.state.lock().unwrap_or_else(|e| e.into_inner()).retained.is_empty() {
            std::thread::sleep(RETAINED_SWEEP_INTERVAL);
        }
    }
}
pub(crate) fn spawn_reaper_with<F>(child: Child, pid: i32, holds: Vec<ScratchHold>, spawn_fn: F)
where
    F: FnOnce(ReaperTask) -> std::io::Result<()>,
{
    spawn_reaper_with_probe(child, pid, holds, spawn_fn, default_probe());
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
    let _ = warm_standby_reaper();
    let mut fallback = SpawnFallback { state: Some((child, pid, holds, probe)) };
    let _ = spawn_fn(Box::new(move || {
        if let Some((child, pid, holds, probe)) = fallback.state.take() {
            reap_until_confirmed(child, pid, holds, probe);
        }
    }));
}

struct SpawnFallback {
    state: Option<(Child, i32, Vec<ScratchHold>, GroupProbe)>,
}
impl Drop for SpawnFallback {
    fn drop(&mut self) {
        let Some((child, pid, holds, probe)) = self.state.take() else {
            return;
        };
        let entry = UnresolvedEntry::new(child, pid, holds, probe);
        drop_fallback_with_diag(Arc::clone(global_registry()), entry, PROD_OWNER_POLICY, write_reaper_diagnostic);
    }
}
fn drop_fallback_with_diag<D>(
    registry: Arc<UnresolvedRegistry>,
    entry: UnresolvedEntry,
    policy: OwnerPolicy,
    diag: D,
) where
    D: FnOnce(&str),
{
    let mut guard = InFlightEntryGuard { registry: Arc::clone(&registry), entry: Some(entry) };
    if policy.signal_on_handoff {
        let current = guard.entry.as_mut().expect("guarded entry present");
        signal_group(&mut current.child, current.pid);
    }
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        drop(spawn_fallback_guarded_on_handle(guard, &handle, default_wait_child, policy));
        return;
    }
    if try_resolve_entry(guard.entry.as_mut().expect("guarded entry present"), false) {
        let _ = guard.entry.take();
        return;
    }
    drop(registry.handoff_guarded(guard, None, policy));
    diag(FALLBACK_DIAGNOSTIC);
}
fn spawn_fallback_guarded_on_handle(
    guard: InFlightEntryGuard,
    handle: &tokio::runtime::Handle,
    wait_child: WaitChildFn,
    policy: OwnerPolicy,
) -> tokio::task::JoinHandle<()> {
    handle.spawn(reap_fallback_guarded(guard, wait_child, policy))
}
#[cfg(test)]
fn spawn_fallback_on_handle(
    registry: Arc<UnresolvedRegistry>,
    entry: UnresolvedEntry,
    handle: &tokio::runtime::Handle,
    wait_child: WaitChildFn,
    policy: OwnerPolicy,
) -> tokio::task::JoinHandle<()> {
    let guard = InFlightEntryGuard { registry, entry: Some(entry) };
    spawn_fallback_guarded_on_handle(guard, handle, wait_child, policy)
}
async fn reap_fallback_guarded(guard: InFlightEntryGuard, wait_child: WaitChildFn, policy: OwnerPolicy) {
    reap_fallback_guarded_with_diag(guard, wait_child, policy, write_reaper_diagnostic).await;
}

async fn reap_fallback_guarded_with_diag<D>(
    mut guard: InFlightEntryGuard,
    wait_child: WaitChildFn,
    policy: OwnerPolicy,
    diag: D,
) where
    D: FnOnce(&str) + Send,
{
    let confirmed = {
        let current = guard.entry.as_mut().expect("guarded entry present");
        if policy.signal_on_handoff {
            signal_group(&mut current.child, current.pid);
        }
        current.group_confirmed
            || tokio::time::timeout(FALLBACK_ASYNC_BUDGET, async {
                while !matches!((current.probe)(current.pid), Ok(true)) {
                    if policy.signal_on_sweep {
                        signal_group(&mut current.child, current.pid);
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .is_ok()
    };
    let reaped = if confirmed {
        let current = guard.entry.as_mut().expect("guarded entry present");
        current.group_confirmed = true;
        matches!(tokio::time::timeout(Duration::from_secs(1), wait_child(&mut current.child)).await, Ok(Ok(_)))
            || current.child.id().is_none()
    } else {
        false
    };
    {
        let current = guard.entry.as_mut().expect("guarded entry present");
        current.group_confirmed |= confirmed;
        current.reaped |= reaped;
        if current.group_confirmed && current.reaped {
            current.holds.clear();
            let _ = guard.entry.take();
            return;
        }
    }
    let runtime = tokio::runtime::Handle::try_current().ok();
    let registry = Arc::clone(&guard.registry);
    drop(registry.handoff_guarded(guard, runtime, policy));
    diag(FALLBACK_DIAGNOSTIC);
}

#[cfg(test)]
pub(super) async fn reap_fallback_with_wait(
    child: Child,
    pid: i32,
    holds: Vec<ScratchHold>,
    probe: GroupProbe,
    wait_child: WaitChildFn,
) {
    let entry = UnresolvedEntry::new(child, pid, holds, probe);
    let guard = InFlightEntryGuard { registry: Arc::clone(global_registry()), entry: Some(entry) };
    reap_fallback_guarded(guard, wait_child, PROD_OWNER_POLICY).await;
}

fn reap_until_confirmed(mut child: Child, pid: i32, holds: Vec<ScratchHold>, probe: GroupProbe) {
    if pid > 1 {
        let started = std::time::Instant::now();
        let mut reported = false;
        while !matches!(probe(pid), Ok(true)) {
            signal_group(&mut child, pid);
            if !reported && started.elapsed() > Duration::from_secs(5) {
                write_reaper_diagnostic(BLOCKED_DIAGNOSTIC);
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
#[path = "s4_git_reaper_tests.rs"]
mod tests;
