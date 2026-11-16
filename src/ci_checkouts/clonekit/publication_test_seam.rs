//! `cfg(test)`-only deterministic publication barriers and fault seams.

use std::sync::{Condvar, Mutex, MutexGuard};

use crate::ci_checkouts::clonekit::manifest::CloneKitError;

struct SeamState {
    pause_all: Vec<&'static str>,
    pause_once: Vec<&'static str>,
    failures: Vec<(&'static str, &'static str)>,
    arrived: Vec<&'static str>,
    released: Vec<&'static str>,
}

static STATE: Mutex<SeamState> = Mutex::new(SeamState {
    pause_all: Vec::new(),
    pause_once: Vec::new(),
    failures: Vec::new(),
    arrived: Vec::new(),
    released: Vec::new(),
});
static CHANGED: Condvar = Condvar::new();
static SERIAL: Mutex<()> = Mutex::new(());

fn lock() -> MutexGuard<'static, SeamState> {
    STATE.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Serialize tests that configure the process-global seam.
pub(super) fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Clear every configured pause, failure, arrival, and release.
pub(super) fn reset() {
    let mut state = lock();
    state.pause_all.clear();
    state.pause_once.clear();
    state.failures.clear();
    state.arrived.clear();
    state.released.clear();
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

/// Block until `count` publishers have reached `name`.
pub(super) fn wait_until(name: &'static str, count: usize) {
    let mut state = lock();
    while state.arrived.iter().copied().filter(|arrived| *arrived == name).count() < count {
        state = CHANGED.wait(state).unwrap_or_else(|poisoned| poisoned.into_inner());
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
    if let Some(index) = pause_once {
        state.pause_once.remove(index);
        while !state.released.contains(&name) {
            state = CHANGED.wait(state).unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    } else if state.pause_all.contains(&name) {
        while !state.released.contains(&name) {
            state = CHANGED.wait(state).unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }
    Ok(())
}
