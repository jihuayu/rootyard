//! Bounded conservative retired-operation floor.
//!
//! A cancellation may never be forgotten while a delayed begin/mount frame can
//! still arrive. Request and operation IDs are allocated monotonically, so the
//! highest cancelled ID is an O(1) retired floor: every ID at or below it is
//! rejected forever. Control frames are allotted IDs before the socket write
//! lock, so wire order is not guaranteed to be monotonic; the floor can reject
//! a legitimate reordered request. That is deliberately fail-closed rather
//! than letting an evicted cancellation revive an old operation.
use std::sync::{Mutex, MutexGuard, PoisonError};

#[derive(Default)]
pub(super) struct RetiredIds {
    floor: Mutex<Option<u64>>,
}

impl RetiredIds {
    pub(super) fn new() -> Self {
        Self { floor: Mutex::new(None) }
    }

    fn lock(&self) -> MutexGuard<'_, Option<u64>> {
        self.floor.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Record a cancellation. The floor only ever moves forward, and ID `0`
    /// is never a frame identity, so it cannot make every operation retired.
    pub(super) fn retire(&self, id: u64) {
        if id == 0 {
            return;
        }
        let mut floor = self.lock();
        *floor = Some(floor.map_or(id, |current| current.max(id)));
    }

    /// An ID at or below the floor was cancelled, or precedes a cancellation
    /// whose frame order cannot be proven. It must not begin or take ownership.
    pub(super) fn is_retired(&self, id: u64) -> bool {
        id != 0 && self.lock().is_some_and(|floor| id <= floor)
    }

    #[cfg(test)]
    pub(super) fn floor(&self) -> Option<u64> {
        *self.lock()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn far_more_than_the_old_tombstone_bound_keeps_the_oldest_id_retired() {
        let retired = RetiredIds::new();
        for id in 1..=96 {
            retired.retire(id);
        }
        assert_eq!(retired.floor(), Some(96));
        assert!(retired.is_retired(1), "the oldest cancellation is never evicted");
        assert!(retired.is_retired(96));
        assert!(!retired.is_retired(97));
    }

    #[test]
    fn retire_cannot_lower_the_floor_or_retire_id_zero() {
        let retired = RetiredIds::new();
        retired.retire(40);
        retired.retire(9);
        retired.retire(0);
        assert_eq!(retired.floor(), Some(40));
        assert!(!retired.is_retired(0));
        assert!(!retired.is_retired(41));
    }
}
