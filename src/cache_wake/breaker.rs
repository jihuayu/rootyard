//! Advisory-only half-open circuit breaker for cache backend operations.
//!
//! When a cache backend (such as Redis) suffers repeated errors or timeouts,
//! callers bypass backend calls during the cooldown window and serve directly
//! from origin instead of paying backend timeouts on every request.
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

#[derive(Default)]
struct AdvisoryBreakerState {
    failures: u32,
    open_until: Option<Instant>,
    probing: bool,
}

pub(super) struct AdvisoryBreaker {
    state: Mutex<AdvisoryBreakerState>,
    threshold: u32,
    cooldown: Duration,
}

pub(super) struct ProbePermit<'a> {
    breaker: &'a AdvisoryBreaker,
    half_open_probe: bool,
    settled: bool,
}

impl Drop for ProbePermit<'_> {
    fn drop(&mut self) {
        if !self.settled && self.half_open_probe {
            let mut state = self.breaker.state.lock().unwrap_or_else(|poison| poison.into_inner());
            state.probing = false;
        }
    }
}

impl ProbePermit<'_> {
    pub(super) fn record_ok(mut self) {
        self.settled = true;
        let mut state = self.breaker.state.lock().unwrap_or_else(|poison| poison.into_inner());
        state.failures = 0;
        state.open_until = None;
        state.probing = false;
    }

    pub(super) fn record_err(mut self) {
        self.settled = true;
        let mut state = self.breaker.state.lock().unwrap_or_else(|poison| poison.into_inner());
        let was_open = state.open_until.is_some();
        state.probing = false;
        state.failures = state.failures.saturating_add(1);
        if was_open || state.failures >= self.threshold {
            state.open_until = Instant::now().checked_add(self.cooldown);
        }
    }
}

impl AdvisoryBreaker {
    pub(super) fn new(threshold: u32, cooldown: Duration) -> Self {
        Self { state: Mutex::new(AdvisoryBreakerState::default()), threshold, cooldown }
    }

    pub(super) fn try_begin(&self) -> Option<ProbePermit<'_>> {
        let now = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
        match state.open_until {
            None => Some(ProbePermit { breaker: self, half_open_probe: false, settled: false }),
            Some(until) if now < until => None,
            Some(_) if state.probing => None,
            Some(_) => {
                state.probing = true;
                Some(ProbePermit { breaker: self, half_open_probe: true, settled: false })
            }
        }
    }

    pub(super) fn is_open(&self) -> bool {
        let now = Instant::now();
        let state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
        state.open_until.is_some_and(|until| now < until)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn half_open_probe_releases_when_dropped_and_closes_on_success() {
        let breaker = AdvisoryBreaker::new(2, Duration::from_millis(5));
        breaker.try_begin().unwrap().record_err();
        assert!(!breaker.is_open());
        breaker.try_begin().unwrap().record_err();
        assert!(breaker.is_open());
        assert!(breaker.try_begin().is_none());
        std::thread::sleep(Duration::from_millis(10));
        let canceled_probe = breaker.try_begin().expect("first probe after cooldown");
        assert!(breaker.try_begin().is_none());
        drop(canceled_probe);
        breaker.try_begin().expect("canceled probe must unlock next attempt").record_ok();
        assert!(!breaker.is_open());
    }
}
