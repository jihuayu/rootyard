//! Narrow retry window for typed `MatchedIdBusy` during explicit helper
//! shutdown.
//!
//! The helper already owns one absolute shutdown deadline. This policy never
//! moves that deadline: it spends at most a short shared window, starts only
//! after every owned mount had its first exact-unmount attempt, and stops
//! before a terminal reserve. The remaining time therefore stays available for
//! the other mounts, the pending-owner barrier and the final typed fail-stop.

use std::time::{Duration, Instant};

/// One short pause between exact-unmount retry rounds.
const RETRY_DELAY: Duration = Duration::from_millis(25);
/// Shared extra window for all busy mounts in one explicit shutdown.
const RETRY_BUDGET: Duration = Duration::from_millis(100);
/// Maximum retry rounds. Each round re-attempts every still-busy mount.
const RETRY_ROUNDS: u8 = 3;
/// Time kept outside the retry window for the remaining teardown work and the
/// terminal classification. This is a reserve inside the existing deadline,
/// not an extension of it.
const TERMINAL_RESERVE: Duration = Duration::from_millis(50);

/// Bounded decision state for retries after `MountTeardownClass::MatchedIdBusy`.
#[derive(Debug, Clone, Copy)]
pub(super) struct BusyRetry {
    retry_until: Instant,
    rounds_left: u8,
}

impl BusyRetry {
    /// Build the one shared retry window from the already-published absolute
    /// shutdown deadline. Without a published deadline the ordinary fail-stop
    /// behavior is kept unchanged.
    pub(super) fn new(now: Instant, shutdown_deadline: Option<Instant>) -> Self {
        let Some(deadline) = shutdown_deadline else {
            return Self { retry_until: now, rounds_left: 0 };
        };
        let Some(terminal_at) = deadline.checked_sub(TERMINAL_RESERVE) else {
            return Self { retry_until: now, rounds_left: 0 };
        };
        let budget_end = now.checked_add(RETRY_BUDGET).unwrap_or(terminal_at);
        let retry_until = budget_end.min(terminal_at);
        let rounds_left = if retry_until > now { RETRY_ROUNDS } else { 0 };
        Self { retry_until, rounds_left }
    }

    /// A delay for one retry round, or `None` once the round cap, retry window
    /// or terminal reserve leaves no room for another attempt.
    pub(super) fn next_delay(&mut self, now: Instant) -> Option<Duration> {
        if self.rounds_left == 0 {
            return None;
        }
        let Some(remaining) = self.retry_until.checked_duration_since(now) else {
            self.rounds_left = 0;
            return None;
        };
        if remaining <= RETRY_DELAY {
            self.rounds_left = 0;
            return None;
        }
        self.rounds_left -= 1;
        Some(RETRY_DELAY)
    }

    /// True while the same absolute retry boundary still permits another exact
    /// repeat. Callers recheck this after sleeping and immediately before each
    /// repeat, because either the sleep or an earlier mount can consume the
    /// remaining window.
    pub(super) fn within_window(&self, now: Instant) -> bool {
        now < self.retry_until
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_published_deadline_keeps_immediate_failstop_behavior() {
        let now = Instant::now();
        let mut retry = BusyRetry::new(now, None);
        assert_eq!(retry.next_delay(now), None);
    }

    #[test]
    fn retry_window_never_exceeds_the_existing_deadline() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(5);
        let retry = BusyRetry::new(now, Some(deadline));
        assert_eq!(retry.retry_until, now + RETRY_BUDGET);
        assert!(retry.retry_until <= deadline.checked_sub(TERMINAL_RESERVE).unwrap());
    }

    #[test]
    fn a_tight_deadline_tightens_the_window_instead_of_extending_it() {
        let now = Instant::now();
        let deadline = now + Duration::from_millis(120);
        let retry = BusyRetry::new(now, Some(deadline));
        assert_eq!(retry.retry_until, deadline - TERMINAL_RESERVE);
        assert!(retry.retry_until < now + RETRY_BUDGET);
    }

    #[test]
    fn no_retry_starts_when_the_terminal_reserve_or_delay_does_not_fit() {
        let now = Instant::now();
        let mut at_reserve = BusyRetry::new(now, Some(now + TERMINAL_RESERVE));
        assert_eq!(at_reserve.next_delay(now), None);

        let mut inside_delay = BusyRetry::new(now, Some(now + TERMINAL_RESERVE + RETRY_DELAY / 2));
        assert_eq!(inside_delay.next_delay(now), None);
    }

    #[test]
    fn retries_are_capped_and_stay_inside_the_window() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(5);
        let mut retry = BusyRetry::new(now, Some(deadline));
        let mut attempts = 0;
        let mut at = now;
        while let Some(delay) = retry.next_delay(at) {
            assert_eq!(delay, RETRY_DELAY);
            at += delay;
            attempts += 1;
            assert!(at < retry.retry_until);
            assert!(at < deadline.checked_sub(TERMINAL_RESERVE).unwrap());
        }
        assert_eq!(attempts, RETRY_ROUNDS as usize);
        assert_eq!(retry.next_delay(at), None, "an exhausted policy cannot restart the window");
    }

    #[test]
    fn an_expired_window_cannot_restart() {
        let now = Instant::now();
        let mut retry = BusyRetry::new(now, Some(now + Duration::from_secs(5)));
        assert_eq!(retry.next_delay(now + RETRY_BUDGET + Duration::from_millis(1)), None);
        assert_eq!(retry.next_delay(now), None);
    }

    #[test]
    fn boundary_recheck_rejects_a_sleep_overshoot_and_a_consumed_window() {
        let now = Instant::now();
        let mut retry = BusyRetry::new(now, Some(now + Duration::from_secs(5)));
        let delay = retry.next_delay(now).expect("the first retry is inside the window");

        assert!(retry.within_window(now + delay));
        assert!(!retry.within_window(now + RETRY_BUDGET));
        assert!(!retry.within_window(now + RETRY_BUDGET + Duration::from_millis(1)));
    }
}
