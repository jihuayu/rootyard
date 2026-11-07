//! Queue-budget accounting and its RAII permit.
//!
//! Extracted verbatim from the dispatcher module so the actor and queue code
//! stay readable; admission and reply semantics do not live here.

use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use super::{GLOBAL_QUEUE_BYTES, GLOBAL_QUEUE_OPS};

pub(super) struct Budget {
    limit_ops: usize,
    limit_bytes: usize,
    used: Mutex<(usize, usize)>,
}

impl Budget {
    pub(super) fn new(limit_ops: usize, limit_bytes: usize) -> Self {
        Self { limit_ops, limit_bytes, used: Mutex::new((0, 0)) }
    }

    fn lock(&self) -> MutexGuard<'_, (usize, usize)> {
        self.used.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(super) fn try_acquire(&self, bytes: usize) -> bool {
        let mut used = self.lock();
        let Some(ops) = used.0.checked_add(1) else { return false };
        let Some(total) = used.1.checked_add(bytes) else { return false };
        if ops > self.limit_ops || total > self.limit_bytes {
            return false;
        }
        *used = (ops, total);
        true
    }

    pub(super) fn release(&self, bytes: usize) {
        let mut used = self.lock();
        used.0 = used.0.saturating_sub(1);
        used.1 = used.1.saturating_sub(bytes);
    }

    pub(super) fn used(&self) -> (usize, usize) {
        *self.lock()
    }
}

pub(super) fn global_budget() -> Arc<Budget> {
    static GLOBAL: OnceLock<Arc<Budget>> = OnceLock::new();
    GLOBAL.get_or_init(|| Arc::new(Budget::new(GLOBAL_QUEUE_OPS, GLOBAL_QUEUE_BYTES))).clone()
}

/// RAII charge against the per-mount budget and the process-wide helper budget.
/// Released exactly once, on every path, when the operation's reply is sent.
pub(super) struct Permit {
    mount: Arc<Budget>,
    global: Arc<Budget>,
    bytes: usize,
}

impl Permit {
    pub(super) fn acquire(mount: &Arc<Budget>, global: &Arc<Budget>, bytes: usize) -> Option<Self> {
        if !mount.try_acquire(bytes) {
            return None;
        }
        if !global.try_acquire(bytes) {
            mount.release(bytes);
            return None;
        }
        Some(Self { mount: mount.clone(), global: global.clone(), bytes })
    }
}

impl Drop for Permit {
    fn drop(&mut self) {
        self.global.release(self.bytes);
        self.mount.release(self.bytes);
    }
}
