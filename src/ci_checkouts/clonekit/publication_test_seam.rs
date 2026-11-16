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
    arrived: Vec<&'static str>,
    released: Vec<&'static str>,
    deadline: Option<Instant>,
    abandoned: bool,
}

static STATE: Mutex<SeamState> = Mutex::new(SeamState {
    pause_all: Vec::new(),
    pause_once: Vec::new(),
    failures: Vec::new(),
    arrived: Vec::new(),
    released: Vec::new(),
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
    state.arrived.clear();
    state.released.clear();
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

fn arrivals(state: &SeamState, name: &'static str) -> usize {
    state.arrived.iter().copied().filter(|arrived| *arrived == name).count()
}

fn wait_deadline(state: &SeamState) -> Instant {
    state.deadline.unwrap_or_else(|| Instant::now() + BARRIER_DEADLINE)
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

/// Block until `count` publishers have reached `name`, bounded by the test deadline.
pub(super) fn wait_until(name: &'static str, count: usize) {
    let mut state = lock();
    if state.abandoned {
        fail_barrier(&mut state, format!("publication test barrier abandoned before waiting for checkpoint {name:?}"));
    }
    let deadline = wait_deadline(&state);
    let mut observed = arrivals(&state, name);
    while observed < count {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            fail_barrier(
                &mut state,
                format!(
                    "publication test barrier deadline exceeded: checkpoint {name:?} expected {count} arrival(s), observed {observed}"
                ),
            );
        }
        let (next, timeout) =
            CHANGED.wait_timeout(state, remaining).unwrap_or_else(|poisoned| poisoned.into_inner());
        state = next;
        observed = arrivals(&state, name);
        if state.abandoned {
            fail_barrier(
                &mut state,
                format!(
                    "publication test barrier abandoned while waiting for checkpoint {name:?}; expected {count}, observed {observed}"
                ),
            );
        }
        if timeout.timed_out() && observed < count {
            fail_barrier(
                &mut state,
                format!(
                    "publication test barrier deadline exceeded: checkpoint {name:?} expected {count} arrival(s), observed {observed}"
                ),
            );
        }
    }
    if state.abandoned {
        fail_barrier(&mut state, format!("publication test barrier abandoned after checkpoint {name:?} arrived"));
    }
}

/// Release every publisher paused at `name`.
pub(super) fn release(name: &'static str) {
    let mut state = lock();
    if !state.released.contains(&name) {
        state.released.push(name);
    }
    CHANGED.notify_all();
}

pub(super) fn checkpoint(name: &'static str) -> Result<(), CloneKitError> {
    let mut state = lock();
    if state.abandoned {
        return Err(fail_checkpoint(&mut state, format!("publication test barrier abandoned at checkpoint {name:?}")));
    }
    state.arrived.push(name);
    CHANGED.notify_all();
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
        let deadline = wait_deadline(&state);
        while !state.released.contains(&name) {
            if state.abandoned {
                return Err(fail_checkpoint(
                    &mut state,
                    format!("publication test barrier abandoned while waiting to release checkpoint {name:?}"),
                ));
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(fail_checkpoint(
                    &mut state,
                    format!("publication test barrier deadline exceeded: checkpoint {name:?} was reached but never released"),
                ));
            }
            let (next, timeout) =
                CHANGED.wait_timeout(state, remaining).unwrap_or_else(|poisoned| poisoned.into_inner());
            state = next;
            if timeout.timed_out() && !state.released.contains(&name) {
                return Err(fail_checkpoint(
                    &mut state,
                    format!("publication test barrier deadline exceeded: checkpoint {name:?} was reached but never released"),
                ));
            }
        }
    }
    Ok(())
}
