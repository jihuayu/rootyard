//! Recording implementation, compiled only with `--features state-baseline-metrics`.
use super::{BUCKET_LABELS, BUCKETS, OUTCOMES, Outcome, Phase, WIDTH};
use std::{
    fmt::Write,
    future::Future,
    sync::{
        LazyLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

fn add(value: &AtomicU64, amount: u64) {
    let mut current = value.load(Ordering::Relaxed);
    loop {
        match value.compare_exchange_weak(current, current.saturating_add(amount), Ordering::Relaxed, Ordering::Relaxed)
        {
            Ok(_) => break,
            Err(actual) => current = actual,
        }
    }
}

/// Per-phase atomics. Every field is bounded: three outcome counters, a fixed
/// bucket array and two saturating scalars, so memory never grows with load.
struct PhaseStats {
    observations: AtomicU64,
    outcomes: [AtomicU64; OUTCOMES],
    buckets: [AtomicU64; BUCKETS.len() + 1],
    nanos: AtomicU64,
    bytes: AtomicU64,
}

impl PhaseStats {
    const fn new() -> Self {
        Self {
            observations: AtomicU64::new(0),
            outcomes: [const { AtomicU64::new(0) }; OUTCOMES],
            buckets: [const { AtomicU64::new(0) }; BUCKETS.len() + 1],
            nanos: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
        }
    }
}

/// Recording target. Production uses one process-global instance; tests build
/// their own so assertions never depend on which other test ran first.
pub struct Registry {
    phases: [PhaseStats; WIDTH],
}

impl Default for Registry {
    fn default() -> Self {
        Self { phases: std::array::from_fn(|_| PhaseStats::new()) }
    }
}

static GLOBAL: LazyLock<Registry> = LazyLock::new(Registry::default);

impl Registry {
    /// The single recording path shared by the RAII timer and the timed helpers.
    pub(super) fn record(&self, phase: Phase, outcome: Outcome, elapsed: Duration, bytes: u64) {
        let stats = &self.phases[phase.index()];
        add(&stats.observations, 1);
        add(&stats.outcomes[outcome.index()], 1);
        add(&stats.nanos, u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX));
        add(&stats.bytes, bytes);
        let seconds = elapsed.as_secs_f64();
        let bucket = BUCKETS.iter().position(|bound| seconds <= *bound).unwrap_or(BUCKETS.len());
        add(&stats.buckets[bucket], 1);
    }
}

/// RAII observation. Finishing explicitly records `ok`/`error`; dropping without
/// finishing records `cancelled`, so an abandoned await is never silently lost
/// and never counted as success or as an application error.
pub struct Timer<'a> {
    registry: &'a Registry,
    phase: Phase,
    started: Instant,
    recorded: bool,
}

impl<'a> Timer<'a> {
    pub fn start(phase: Phase) -> Timer<'static> {
        Timer::<'static>::start_in(&GLOBAL, phase)
    }

    pub fn start_in(registry: &'a Registry, phase: Phase) -> Self {
        Self { registry, phase, started: Instant::now(), recorded: false }
    }

    pub fn finish(mut self, outcome: Outcome) {
        self.record(outcome, 0);
    }

    pub fn finish_with_bytes(mut self, outcome: Outcome, bytes: u64) {
        self.record(outcome, bytes);
    }

    fn record(&mut self, outcome: Outcome, bytes: u64) {
        if !self.recorded {
            self.recorded = true;
            self.registry.record(self.phase, outcome, self.started.elapsed(), bytes);
        }
    }
}

impl Drop for Timer<'_> {
    fn drop(&mut self) {
        self.record(Outcome::Cancelled, 0);
    }
}

/// Time an awaited operation that has no error channel; if this future is
/// dropped before it completes, the timer records `cancelled`.
pub async fn timed<F: Future>(phase: Phase, future: F) -> F::Output {
    timed_in(&GLOBAL, phase, future).await
}

/// Time an awaited operation whose `Result` distinguishes success from failure.
/// An `Err` returned by the awaited operation is an explicit `error` completion,
/// including a nested `tokio::time::timeout_at` that expired; only dropping this
/// future before it resumes counts as `cancelled`.
pub async fn timed_result<T, E, F: Future<Output = Result<T, E>>>(phase: Phase, future: F) -> Result<T, E> {
    timed_result_in(&GLOBAL, phase, future).await
}

/// Registry-parameterised form of [`timed`]; the only difference is the target, so
/// tests measure the same recording path without touching process-global state.
pub(super) async fn timed_in<F: Future>(registry: &Registry, phase: Phase, future: F) -> F::Output {
    let timer = Timer::start_in(registry, phase);
    let output = future.await;
    timer.finish(Outcome::Ok);
    output
}

/// Registry-parameterised form of [`timed_result`].
pub(super) async fn timed_result_in<T, E, F: Future<Output = Result<T, E>>>(
    registry: &Registry,
    phase: Phase,
    future: F,
) -> Result<T, E> {
    let timer = Timer::start_in(registry, phase);
    match future.await {
        Ok(value) => {
            timer.finish(Outcome::Ok);
            Ok(value)
        }
        Err(error) => {
            timer.finish(Outcome::Error);
            Err(error)
        }
    }
}

/// Append every fixed series of the process-global registry.
pub fn render(out: &mut String) {
    render_registry(&GLOBAL, out);
}

pub fn render_registry(registry: &Registry, out: &mut String) {
    out.push_str(
        "# HELP rootyard_baseline_phase_observations_total Completed observations by fixed phase; nested spans are not additive.\n# TYPE rootyard_baseline_phase_observations_total counter\n",
    );
    for phase in Phase::ALL {
        let _ = writeln!(
            out,
            "rootyard_baseline_phase_observations_total{{phase=\"{}\"}} {}",
            phase.label(),
            registry.phases[phase.index()].observations.load(Ordering::Relaxed)
        );
    }
    out.push_str(
        "# HELP rootyard_baseline_phase_outcomes_total Phase outcomes; cancelled means dropped before completion.\n# TYPE rootyard_baseline_phase_outcomes_total counter\n",
    );
    for phase in Phase::ALL {
        for outcome in [Outcome::Ok, Outcome::Error, Outcome::Cancelled] {
            let _ = writeln!(
                out,
                "rootyard_baseline_phase_outcomes_total{{phase=\"{}\",outcome=\"{}\"}} {}",
                phase.label(),
                outcome.label(),
                registry.phases[phase.index()].outcomes[outcome.index()].load(Ordering::Relaxed)
            );
        }
    }
    out.push_str(
        "# HELP rootyard_baseline_phase_duration_seconds Wall-clock wait of the awaited operation; buckets mix outcomes; nested spans are not additive.\n# TYPE rootyard_baseline_phase_duration_seconds histogram\n",
    );
    for phase in Phase::ALL {
        let stats = &registry.phases[phase.index()];
        let mut cumulative = 0u64;
        for (index, bound) in BUCKET_LABELS.iter().enumerate().take(BUCKETS.len()) {
            cumulative = cumulative.saturating_add(stats.buckets[index].load(Ordering::Relaxed));
            let _ = writeln!(
                out,
                "rootyard_baseline_phase_duration_seconds_bucket{{phase=\"{}\",le=\"{bound}\"}} {cumulative}",
                phase.label()
            );
        }
        let total = stats.observations.load(Ordering::Relaxed);
        let nanos = stats.nanos.load(Ordering::Relaxed);
        let _ = writeln!(
            out,
            "rootyard_baseline_phase_duration_seconds_bucket{{phase=\"{}\",le=\"+Inf\"}} {total}\n\
             rootyard_baseline_phase_duration_seconds_sum{{phase=\"{}\"}} {}.{:09}\n\
             rootyard_baseline_phase_duration_seconds_count{{phase=\"{}\"}} {total}",
            phase.label(),
            phase.label(),
            nanos / 1_000_000_000,
            nanos % 1_000_000_000,
            phase.label()
        );
    }
    out.push_str(
        "# HELP rootyard_baseline_phase_bytes_total Successful transfer bytes moved by this process; retried or re-sent bytes are unknown, so this is not an exact network count.\n# TYPE rootyard_baseline_phase_bytes_total counter\n",
    );
    for phase in Phase::ALL {
        let _ = writeln!(
            out,
            "rootyard_baseline_phase_bytes_total{{phase=\"{}\"}} {}",
            phase.label(),
            registry.phases[phase.index()].bytes.load(Ordering::Relaxed)
        );
    }
}

#[cfg(test)]
impl Registry {
    pub(super) fn observations(&self, phase: Phase) -> u64 {
        self.phases[phase.index()].observations.load(Ordering::Relaxed)
    }
    pub(super) fn outcome_count(&self, phase: Phase, outcome: Outcome) -> u64 {
        self.phases[phase.index()].outcomes[outcome.index()].load(Ordering::Relaxed)
    }
    pub(super) fn buckets(&self, phase: Phase) -> [u64; BUCKETS.len() + 1] {
        std::array::from_fn(|index| self.phases[phase.index()].buckets[index].load(Ordering::Relaxed))
    }
    pub(super) fn nanos(&self, phase: Phase) -> u64 {
        self.phases[phase.index()].nanos.load(Ordering::Relaxed)
    }
    pub(super) fn bytes(&self, phase: Phase) -> u64 {
        self.phases[phase.index()].bytes.load(Ordering::Relaxed)
    }
}
