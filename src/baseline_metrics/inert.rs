//! Zero-cost stand-ins for a default build: no atomics, no allocation, no
//! formatting, and the awaited future is polled exactly as before.
use super::{Outcome, Phase};
use std::future::Future;

/// Records nothing; exists only so call sites read identically in both builds.
pub struct Timer;

impl Timer {
    #[inline]
    pub fn start(_phase: Phase) -> Self {
        Self
    }

    #[inline]
    pub fn finish(self, _outcome: Outcome) {}

    #[inline]
    pub fn finish_with_bytes(self, _outcome: Outcome, _bytes: u64) {}
}

#[inline]
pub async fn timed<F: Future>(_phase: Phase, future: F) -> F::Output {
    future.await
}

#[inline]
pub async fn timed_result<T, E, F: Future<Output = Result<T, E>>>(_phase: Phase, future: F) -> Result<T, E> {
    future.await
}

/// Nothing is exported when the feature is off, not even zero-valued series.
pub fn render(_out: &mut String) {}
