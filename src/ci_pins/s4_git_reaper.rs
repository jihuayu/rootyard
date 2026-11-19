//! Continuing process-group reaper and unresolved-child owner for S4 and Git View.
#[cfg(unix)]
use crate::git_http::group_quiescent;
use super::s4_git_runner::{ScratchHold, child_gone, signal_group};
use std::{collections::VecDeque, process::ExitStatus, sync::{Arc, Condvar, Mutex, OnceLock}, time::Duration};
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
enum ResolveOutcome {
    StillPending,
    ConfirmedRelease,
    ReapedUnknownGroup,
}
/// Keeps the leader unreaped until group quiescence and releases scratch only on `ConfirmedRelease`.
fn try_resolve_entry(entry: &mut UnresolvedEntry, signal: bool) -> ResolveOutcome {
    if !entry.group_confirmed {
        if signal && !entry.reaped {
            signal_group(&mut entry.child, entry.pid);
        }
        match (entry.probe)(entry.pid) {
            Ok(true) => entry.group_confirmed = true,
            Ok(false) => return ResolveOutcome::StillPending,
            Err(_) => {
                entry.reaped |= child_gone(&mut entry.child);
                return if entry.reaped {
                    ResolveOutcome::ReapedUnknownGroup
                } else {
                    ResolveOutcome::StillPending
                };
            }
        }
    }
    if signal && !entry.reaped {
        signal_group(&mut entry.child, entry.pid);
    }
    entry.reaped |= child_gone(&mut entry.child);
    if entry.reaped {
        ResolveOutcome::ConfirmedRelease
    } else {
        ResolveOutcome::StillPending
    }
}
#[derive(Default)]
struct UnresolvedState {
    queue: VecDeque<UnresolvedEntry>,
    retained: Vec<UnresolvedEntry>,
    unverified_scratch: Vec<Vec<ScratchHold>>,
    active_task: bool,
    standby_started: bool,
    standby_stop: bool,
}
#[derive(Default)]
struct UnresolvedRegistry {
    state: Mutex<UnresolvedState>,
    wake: Condvar,
}
static RETAINED_REGISTRY: OnceLock<Arc<UnresolvedRegistry>> = OnceLock::new();
fn global_registry() -> &'static Arc<UnresolvedRegistry> {
    RETAINED_REGISTRY.get_or_init(|| Arc::new(UnresolvedRegistry::default()))
}
/// Pre-warms the standby OS sweeper so a runtime-less handoff still sweeps via `Condvar`.
pub(crate) fn warm_standby_reaper() {
    global_registry().ensure_standby_sweeper();
}
struct FlagGuard {
    registry: Arc<UnresolvedRegistry>,
    standby: bool,
    armed: bool,
}
impl Drop for FlagGuard {
    fn drop(&mut self) {
        if self.armed {
            let mut state = self.registry.state.lock().unwrap_or_else(|e| e.into_inner());
            if self.standby {
                state.standby_started = false;
            }
            state.active_task &= !self.standby;
        }
    }
}
/// Returns a popped entry to `retained` when the owner task is cancelled mid-wait.
struct InFlightEntryGuard<'a> {
    registry: &'a UnresolvedRegistry,
    entry: Option<UnresolvedEntry>,
}
impl Drop for InFlightEntryGuard<'_> {
    fn drop(&mut self) {
        if let Some(entry) = self.entry.take() {
            self.registry.requeue_retained(entry);
        }
    }
}
fn absorb_and_drop(entry: &mut UnresolvedEntry, unverified: &mut Vec<Vec<ScratchHold>>) -> bool {
    if !entry.holds.is_empty() {
        unverified.push(std::mem::take(&mut entry.holds));
    }
    false
}
impl UnresolvedRegistry {
    fn ensure_standby_sweeper(self: &Arc<Self>) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.standby_started {
            return;
        }
        state.standby_started = true;
        state.standby_stop = false;
        drop(state);
        let reg = Arc::clone(self);
        let spawned =
            std::thread::Builder::new().name("s4-git-standby".into()).spawn(move || run_standby_sweeper(reg));
        if spawned.is_err() {
            self.state.lock().unwrap_or_else(|e| e.into_inner()).standby_started = false;
        }
    }
    fn requeue_retained(&self, entry: UnresolvedEntry) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.retained.push(entry);
        self.wake.notify_all();
    }
    fn preserve_holds(&self, entry: &mut UnresolvedEntry) {
        if !entry.holds.is_empty() {
            let holds = std::mem::take(&mut entry.holds);
            self.state.lock().unwrap_or_else(|e| e.into_inner()).unverified_scratch.push(holds);
        }
    }
    fn settle_or_retain(&self, mut entry: UnresolvedEntry, signal: bool) {
        match try_resolve_entry(&mut entry, signal) {
            ResolveOutcome::StillPending => self.requeue_retained(entry),
            ResolveOutcome::ConfirmedRelease => {}
            ResolveOutcome::ReapedUnknownGroup => self.preserve_holds(&mut entry),
        }
    }
    fn sweep_vec(state: &mut UnresolvedState, signal: bool) {
        let UnresolvedState { retained, unverified_scratch, .. } = state;
        retained.retain_mut(|entry| match try_resolve_entry(entry, signal) {
            ResolveOutcome::StillPending => true,
            ResolveOutcome::ConfirmedRelease => false,
            ResolveOutcome::ReapedUnknownGroup => absorb_and_drop(entry, unverified_scratch),
        });
    }
    fn sweep_retained_once(&self, signal: bool) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        Self::sweep_vec(&mut state, signal);
    }
    fn handoff_with(
        self: &Arc<Self>,
        mut entry: UnresolvedEntry,
        runtime: Option<tokio::runtime::Handle>,
        policy: OwnerPolicy,
    ) -> Option<tokio::task::JoinHandle<()>> {
        if matches!(try_resolve_entry(&mut entry, policy.signal_on_handoff), ResolveOutcome::ConfirmedRelease) {
            return None;
        }
        if entry.reaped {
            self.preserve_holds(&mut entry);
            return None;
        }
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        Self::sweep_vec(&mut state, false);
        let Some(handle) = runtime else {
            state.retained.push(entry);
            let need_standby = policy.allow_thread_owner && !state.standby_started;
            self.wake.notify_all();
            drop(state);
            if need_standby {
                self.ensure_standby_sweeper();
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
            return Some(handle.spawn(run_unresolved_owner_task(Arc::clone(self), policy)));
        }
        None
    }
}
async fn run_unresolved_owner_task(registry: Arc<UnresolvedRegistry>, policy: OwnerPolicy) {
    let mut guard = FlagGuard { registry: Arc::clone(&registry), standby: false, armed: true };
    loop {
        let next = registry.state.lock().unwrap_or_else(|e| e.into_inner()).queue.pop_front();
        if let Some(entry) = next {
            let mut in_flight = InFlightEntryGuard { registry: &registry, entry: Some(entry) };
            let mut wait_now = true;
            {
                let current = in_flight.entry.as_mut().expect("in-flight entry present");
                if policy.signal_on_sweep && !current.reaped {
                    signal_group(&mut current.child, current.pid);
                }
                if !current.group_confirmed && current.pid > 1 {
                    match (current.probe)(current.pid) {
                        Ok(true) => current.group_confirmed = true,
                        Ok(false) => wait_now = false,
                        Err(_) => {}
                    }
                }
            }
            let mut waited = None;
            if wait_now {
                let current = in_flight.entry.as_mut().expect("in-flight entry present");
                waited = Some(tokio::time::timeout(policy.wait_budget, (policy.wait_child)(&mut current.child)).await);
            }
            let mut entry = in_flight.entry.take().expect("in-flight entry present");
            entry.reaped |= matches!(waited, Some(Ok(Ok(_))));
            registry.settle_or_retain(entry, policy.signal_on_sweep);
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
fn run_standby_sweeper(registry: Arc<UnresolvedRegistry>) {
    let _guard = FlagGuard { registry: Arc::clone(&registry), standby: true, armed: true };
    loop {
        {
            let state = registry.state.lock().unwrap_or_else(|e| e.into_inner());
            let state = registry.wake.wait_while(state, |s| s.retained.is_empty() && !s.standby_stop);
            let state = state.unwrap_or_else(|e| e.into_inner());
            if state.standby_stop && state.retained.is_empty() {
                return;
            }
        }
        registry.sweep_retained_once(true);
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
    warm_standby_reaper();
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
        let Some((mut child, pid, holds, probe)) = self.state.take() else {
            return;
        };
        signal_group(&mut child, pid);
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(reap_fallback_bounded(child, pid, holds, probe));
            return;
        }
        let mut entry = UnresolvedEntry::new(child, pid, holds, probe);
        if matches!(try_resolve_entry(&mut entry, false), ResolveOutcome::ConfirmedRelease) {
            return;
        }
        eprintln!("rootyard: Git reaper fallback timed out or group probe failed; handing off unresolved child");
        let _ = global_registry().handoff_with(entry, None, PROD_OWNER_POLICY);
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
        eprintln!("rootyard: Git reaper fallback timed out or group probe failed; handing off unresolved child");
        let mut entry = UnresolvedEntry::new(child, pid, holds, probe);
        entry.group_confirmed = confirmed;
        let _ = global_registry().handoff_with(entry, tokio::runtime::Handle::try_current().ok(), PROD_OWNER_POLICY);
        return;
    }
    drop(child);
    drop(holds);
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
#[path = "s4_git_reaper_tests.rs"]
mod tests;
