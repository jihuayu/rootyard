//! `cfg(test)`-only deterministic publication barriers and bounded fault seams.

use std::{
    sync::{Condvar, Mutex, MutexGuard},
    time::{Duration, Instant},
};

use crate::ci_checkouts::clonekit::manifest::CloneKitError;

const BARRIER_DEADLINE: Duration = Duration::from_secs(60);

struct SeamState {
    pause_all: Vec<&'static str>,
    pause_once: Vec<&'static str>,
    failures: Vec<(&'static str, &'static str)>,
    arrivals: Vec<(&'static str, Instant)>,
    releases: Vec<(&'static str, Instant)>,
    deadline: Option<Instant>,
    abandoned: bool,
}

static STATE: Mutex<SeamState> = Mutex::new(SeamState {
    pause_all: Vec::new(),
    pause_once: Vec::new(),
    failures: Vec::new(),
    arrivals: Vec::new(),
    releases: Vec::new(),
    deadline: None,
    abandoned: false,
});
static CHANGED: Condvar = Condvar::new();
static SERIAL: Mutex<()> = Mutex::new(());

fn lock() -> MutexGuard<'static, SeamState> {
    STATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Serialize tests that configure the process-global seam.
pub(super) fn serial() -> SerialGuard {
    serial_with_deadline(BARRIER_DEADLINE)
}

/// Serialize seam tests with a test-scoped absolute deadline.
pub(super) fn serial_with_deadline(deadline: Duration) -> SerialGuard {
    let serial = SERIAL.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    {
        let mut state = lock();
        state.deadline = Some(Instant::now() + deadline);
        state.abandoned = false;
        CHANGED.notify_all();
    }
    SerialGuard { _serial: serial }
}

/// Dropping the test serialization guard abandons any still-waiting observer so it unwinds.
pub(super) struct SerialGuard {
    _serial: MutexGuard<'static, ()>,
}

impl Drop for SerialGuard {
    fn drop(&mut self) {
        abandon();
    }
}

/// Simulate an abandoned observer so paused publishers unwind and release owned resources.
pub(super) fn abandon() {
    let mut state = lock();
    state.abandoned = true;
    CHANGED.notify_all();
}

/// Clear every configured pause, failure, arrival, release, and prior abandonment.
pub(super) fn reset() {
    let mut state = lock();
    state.pause_all.clear();
    state.pause_once.clear();
    state.failures.clear();
    state.arrivals.clear();
    state.releases.clear();
    state.abandoned = false;
    CHANGED.notify_all();
}

/// Pause every publisher that reaches `name` until the test releases it.
pub(super) fn pause_all_at(name: &'static str) {
    lock().pause_all.push(name);
}

/// Pause only the first publisher that reaches `name` until the test releases it.
pub(super) fn pause_once_at(name: &'static str) {
    lock().pause_once.push(name);
}

/// Fail only the first publisher that reaches `name`, with the given fixed message.
pub(super) fn fail_once_at(name: &'static str, message: &'static str) {
    lock().failures.push((name, message));
}

/// Record the current test-scoped absolute deadline.
pub(super) fn test_deadline() -> Instant {
    let state = lock();
    wait_deadline(&state)
}

/// Compare a recorded signal against the test deadline. Equality is timely.
pub(super) fn is_timely_signal(signal: Instant, deadline: Instant) -> bool {
    signal <= deadline
}

/// Test-only deterministic arrival injection at an explicit timestamp.
pub(super) fn record_arrival_at(name: &'static str, at: Instant) {
    let mut state = lock();
    state.arrivals.push((name, at));
    CHANGED.notify_all();
}

/// Test-only deterministic release injection at an explicit timestamp.
pub(super) fn record_release_at(name: &'static str, at: Instant) {
    let mut state = lock();
    state.releases.push((name, at));
    CHANGED.notify_all();
}

fn timely_arrivals(state: &SeamState, name: &'static str, deadline: Instant) -> usize {
    let mut count = 0;
    for (arrived_name, at) in &state.arrivals {
        if *arrived_name == name && is_timely_signal(*at, deadline) {
            count += 1;
        }
    }
    count
}

fn has_timely_release(state: &SeamState, name: &'static str, deadline: Instant) -> bool {
    for (released_name, at) in &state.releases {
        if *released_name == name && is_timely_signal(*at, deadline) {
            return true;
        }
    }
    false
}

fn has_late_release(state: &SeamState, name: &'static str, deadline: Instant) -> bool {
    for (released_name, at) in &state.releases {
        if *released_name == name && !is_timely_signal(*at, deadline) {
            return true;
        }
    }
    false
}

fn wait_deadline(state: &SeamState) -> Instant {
    state.deadline.unwrap_or_else(|| Instant::now() + BARRIER_DEADLINE)
}

fn deadline_message(name: &'static str, expected: usize, observed: usize) -> String {
    format!(
        "publication test barrier deadline exceeded: checkpoint {name:?} expected {expected} timely arrival(s), observed {observed}"
    )
}

fn fail_barrier(state: &mut SeamState, message: String) -> ! {
    state.abandoned = true;
    CHANGED.notify_all();
    panic!("{message}");
}

fn fail_checkpoint(state: &mut SeamState, message: String) -> CloneKitError {
    state.abandoned = true;
    CHANGED.notify_all();
    CloneKitError::GitFailed(message)
}

/// Block until `count` timely arrivals have reached `name`, bounded by the test deadline.
pub(super) fn wait_until(name: &'static str, count: usize) {
    let mut state = lock();
    if state.abandoned {
        fail_barrier(&mut state, format!("publication test barrier abandoned before waiting for checkpoint {name:?}"));
    }
    let deadline = wait_deadline(&state);
    let mut observed = timely_arrivals(&state, name, deadline);
    while observed < count {
        if state.abandoned {
            fail_barrier(
                &mut state,
                format!(
                    "publication test barrier abandoned while waiting for checkpoint {name:?}; expected {count}, observed {observed}"
                ),
            );
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            fail_barrier(&mut state, deadline_message(name, count, observed));
        }
        let (next, timeout) = CHANGED.wait_timeout(state, remaining).unwrap_or_else(|poisoned| poisoned.into_inner());
        state = next;
        observed = timely_arrivals(&state, name, deadline);
        if state.abandoned {
            fail_barrier(
                &mut state,
                format!(
                    "publication test barrier abandoned while waiting for checkpoint {name:?}; expected {count}, observed {observed}"
                ),
            );
        }
        if observed >= count {
            break;
        }
        if timeout.timed_out() {
            fail_barrier(&mut state, deadline_message(name, count, observed));
        }
    }
    if state.abandoned {
        fail_barrier(&mut state, format!("publication test barrier abandoned after checkpoint {name:?} arrived"));
    }
}

/// Release every publisher paused at `name`, recording the release timestamp.
pub(super) fn release(name: &'static str) {
    let mut state = lock();
    let at = Instant::now();
    state.releases.push((name, at));
    CHANGED.notify_all();
}

pub(super) fn checkpoint(name: &'static str) -> Result<(), CloneKitError> {
    let mut state = lock();
    if state.abandoned {
        return Err(fail_checkpoint(&mut state, format!("publication test barrier abandoned at checkpoint {name:?}")));
    }
    let deadline = wait_deadline(&state);
    let arrived_at = Instant::now();
    state.arrivals.push((name, arrived_at));
    CHANGED.notify_all();
    if !is_timely_signal(arrived_at, deadline) {
        return Err(fail_checkpoint(
            &mut state,
            format!("publication test barrier deadline exceeded: checkpoint {name:?} arrived after the deadline"),
        ));
    }
    let mut failure = None;
    for index in 0..state.failures.len() {
        if state.failures[index].0 == name {
            failure = Some(index);
            break;
        }
    }
    if let Some(index) = failure {
        let (_, message) = state.failures.remove(index);
        return Err(CloneKitError::GitFailed(message.into()));
    }
    let mut pause_once = None;
    for index in 0..state.pause_once.len() {
        if state.pause_once[index] == name {
            pause_once = Some(index);
            break;
        }
    }
    let paused = if let Some(index) = pause_once {
        state.pause_once.remove(index);
        true
    } else {
        state.pause_all.contains(&name)
    };
    if paused {
        loop {
            if state.abandoned {
                return Err(fail_checkpoint(
                    &mut state,
                    format!("publication test barrier abandoned while waiting to release checkpoint {name:?}"),
                ));
            }
            if has_timely_release(&state, name, deadline) {
                break;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                let suffix = if has_late_release(&state, name, deadline) {
                    "released only after the deadline"
                } else {
                    "was reached but never released"
                };
                return Err(fail_checkpoint(
                    &mut state,
                    format!("publication test barrier deadline exceeded: checkpoint {name:?} {suffix}"),
                ));
            }
            let (next, timeout) =
                CHANGED.wait_timeout(state, remaining).unwrap_or_else(|poisoned| poisoned.into_inner());
            state = next;
            if has_timely_release(&state, name, deadline) {
                break;
            }
            if state.abandoned {
                return Err(fail_checkpoint(
                    &mut state,
                    format!("publication test barrier abandoned while waiting to release checkpoint {name:?}"),
                ));
            }
            if timeout.timed_out() {
                let suffix = if has_late_release(&state, name, deadline) {
                    "released only after the deadline"
                } else {
                    "was reached but never released"
                };
                return Err(fail_checkpoint(
                    &mut state,
                    format!("publication test barrier deadline exceeded: checkpoint {name:?} {suffix}"),
                ));
            }
        }
    }
    Ok(())
}
