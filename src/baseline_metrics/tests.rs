//! Behavioural tests for the opt-in recorder.
//!
//! Every assertion uses a private `Registry`: other library tests instrument real
//! operations concurrently against the process-global registry, so exact values
//! there are racy by construction. The private registry is driven through the
//! same helpers and RAII timer used in production, never through a reimplementation.
use super::enabled::{timed_in, timed_result_in};
use super::{BUCKET_LABELS, BUCKETS, Outcome, Phase, Registry, Timer, render_registry};
use std::{collections::BTreeSet, time::Duration};

fn rendered(registry: &Registry) -> String {
    let mut out = String::new();
    render_registry(registry, &mut out);
    out
}

fn series(text: &str) -> Vec<(&str, &str)> {
    text.lines()
        .filter(|line| !line.starts_with('#'))
        .map(|line| line.split_once(' ').expect("sample line has a value"))
        .collect()
}

#[test]
fn success_error_and_abandonment_are_distinct() {
    let registry = Registry::default();
    Timer::start_in(&registry, Phase::RemotePut).finish(Outcome::Ok);
    Timer::start_in(&registry, Phase::RemotePut).finish(Outcome::Error);
    drop(Timer::start_in(&registry, Phase::RemotePut));
    assert_eq!(registry.observations(Phase::RemotePut), 3);
    assert_eq!(registry.outcome_count(Phase::RemotePut, Outcome::Ok), 1);
    assert_eq!(registry.outcome_count(Phase::RemotePut, Outcome::Error), 1);
    assert_eq!(registry.outcome_count(Phase::RemotePut, Outcome::Cancelled), 1);
    // Nothing leaks into a phase that was never observed.
    assert_eq!(registry.observations(Phase::RemoteGet), 0);
}

#[test]
fn finishing_then_dropping_records_exactly_once() {
    let registry = Registry::default();
    let timer = Timer::start_in(&registry, Phase::StateRow);
    timer.finish(Outcome::Ok);
    assert_eq!(registry.observations(Phase::StateRow), 1);
    assert_eq!(registry.outcome_count(Phase::StateRow, Outcome::Cancelled), 0);
    assert!(registry.nanos(Phase::StateRow) > 0, "the completed span recorded a duration");
}

#[tokio::test]
async fn helper_records_success_once_and_returns_the_value() {
    let registry = Registry::default();
    let value = timed_result_in(&registry, Phase::PoolCheckout, async { Ok::<u8, &'static str>(7) }).await;
    assert_eq!(value, Ok(7));
    assert_eq!(registry.observations(Phase::PoolCheckout), 1);
    assert_eq!(registry.outcome_count(Phase::PoolCheckout, Outcome::Ok), 1);
}

#[tokio::test]
async fn returned_elapsed_is_an_explicit_error_not_a_cancellation() {
    let registry = Registry::default();
    let expired = timed_result_in(
        &registry,
        Phase::PublicationSlot,
        tokio::time::timeout(Duration::from_millis(1), std::future::pending::<()>()),
    )
    .await;
    assert!(expired.is_err(), "an inner deadline must surface as Err");
    assert_eq!(registry.observations(Phase::PublicationSlot), 1);
    assert_eq!(registry.outcome_count(Phase::PublicationSlot, Outcome::Error), 1);
    assert_eq!(registry.outcome_count(Phase::PublicationSlot, Outcome::Cancelled), 0);
}

#[tokio::test]
async fn dropping_the_instrumented_future_is_the_only_cancellation() {
    let registry = Registry::default();
    let abandoned = tokio::time::timeout(
        Duration::from_millis(1),
        timed_in(&registry, Phase::RemoteGet, std::future::pending::<()>()),
    )
    .await;
    assert!(abandoned.is_err(), "outer deadline must drop the instrumented future");
    assert_eq!(registry.observations(Phase::RemoteGet), 1);
    assert_eq!(registry.outcome_count(Phase::RemoteGet, Outcome::Cancelled), 1);
    assert_eq!(registry.outcome_count(Phase::RemoteGet, Outcome::Ok), 0);
    assert_eq!(registry.outcome_count(Phase::RemoteGet, Outcome::Error), 0);
}

#[tokio::test]
async fn an_never_polled_future_records_nothing() {
    let registry = Registry::default();
    drop(timed_in(&registry, Phase::StateRow, std::future::ready(())));
    assert_eq!(registry.observations(Phase::StateRow), 0);
}

#[test]
fn concurrent_recording_is_exact() {
    let registry = Registry::default();
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                for _ in 0..250 {
                    Timer::start_in(&registry, Phase::NativeGitHydration).finish_with_bytes(Outcome::Ok, 7);
                }
            });
        }
    });
    assert_eq!(registry.observations(Phase::NativeGitHydration), 2_000);
    assert_eq!(registry.outcome_count(Phase::NativeGitHydration, Outcome::Ok), 2_000);
    assert_eq!(registry.bytes(Phase::NativeGitHydration), 14_000);
}

#[test]
fn histogram_buckets_are_cumulative_and_bounded() {
    let registry = Registry::default();
    // Same recording path the timer uses, with exact durations so bucket edges are
    // deterministic rather than dependent on scheduler jitter.
    registry.record(Phase::RefAdvisory, Outcome::Ok, Duration::from_micros(1_000), 0);
    registry.record(Phase::RefAdvisory, Outcome::Error, Duration::from_millis(60), 0);
    registry.record(Phase::RefAdvisory, Outcome::Cancelled, Duration::from_secs(300), 0);
    let raw = registry.buckets(Phase::RefAdvisory);
    assert_eq!(raw.len(), BUCKETS.len() + 1);
    // 1ms -> first bound, 60ms -> 0.1s bound, 300s -> overflow bucket outside every bound.
    assert_eq!(raw.iter().sum::<u64>(), 3);
    assert_eq!(raw[0], 1);
    assert_eq!(raw[4], 1);
    assert_eq!(raw[BUCKETS.len()], 1, "over-30s observations land in the overflow bucket");
    let text = rendered(&registry);
    // Rendered buckets are cumulative, and +Inf always equals the observation count.
    assert!(text.contains("rootyard_baseline_phase_duration_seconds_bucket{phase=\"ref_advisory\",le=\"0.005\"} 1\n"));
    assert!(text.contains("rootyard_baseline_phase_duration_seconds_bucket{phase=\"ref_advisory\",le=\"0.1\"} 2\n"));
    assert!(text.contains("rootyard_baseline_phase_duration_seconds_bucket{phase=\"ref_advisory\",le=\"30\"} 2\n"));
    assert!(text.contains("rootyard_baseline_phase_duration_seconds_bucket{phase=\"ref_advisory\",le=\"+Inf\"} 3\n"));
    assert!(text.contains("rootyard_baseline_phase_duration_seconds_count{phase=\"ref_advisory\"} 3\n"));
    assert_eq!(registry.nanos(Phase::RefAdvisory), 1_000_000 + 60_000_000 + 300_000_000_000);
}

#[test]
fn labels_are_fixed_and_series_cardinality_never_grows() {
    let fresh = rendered(&Registry::default());
    let registry = Registry::default();
    for phase in Phase::ALL {
        registry.record(phase, Outcome::Ok, Duration::from_millis(3), 11);
        registry.record(phase, Outcome::Error, Duration::from_secs(1), 0);
    }
    let used = rendered(&registry);
    assert_eq!(series(&fresh).len(), series(&used).len());

    let mut allowed: BTreeSet<String> = Phase::ALL.iter().map(|phase| phase.label().to_string()).collect();
    allowed.extend(["ok", "error", "cancelled"].map(str::to_string));
    allowed.extend(BUCKET_LABELS.iter().map(|label| label.to_string()));
    for (name, value) in series(&used) {
        assert!(name.starts_with("rootyard_baseline_"), "unexpected series {name}");
        assert!(value.parse::<f64>().is_ok_and(f64::is_finite), "non-finite sample {name}");
        if let Some((_, labels)) = name.split_once('{') {
            for pair in labels.trim_end_matches('}').split(',') {
                let (key, value) = pair.split_once('=').expect("label pair");
                assert!(matches!(key, "phase" | "outcome" | "le"), "unexpected label key {key}");
                assert!(allowed.contains(value.trim_matches('"')), "unexpected label value {value}");
            }
        }
    }
    // Fixed series count: 12 observations + 36 outcomes + 12*13 histogram + 12 bytes.
    assert_eq!(series(&fresh).len(), 12 + 36 + 12 * (BUCKETS.len() + 3) + 12);
}

#[test]
fn bytes_count_only_what_a_completed_transfer_reported() {
    let registry = Registry::default();
    Timer::start_in(&registry, Phase::RemotePut).finish_with_bytes(Outcome::Ok, 4_096);
    drop(Timer::start_in(&registry, Phase::RemotePut));
    assert_eq!(registry.bytes(Phase::RemotePut), 4_096);
    assert_eq!(registry.outcome_count(Phase::RemotePut, Outcome::Cancelled), 1);
    let text = rendered(&registry);
    assert!(text.contains("rootyard_baseline_phase_bytes_total{phase=\"remote_put\"} 4096\n"));
    assert!(text.contains("rootyard_baseline_phase_bytes_total{phase=\"remote_get\"} 0\n"));
}
