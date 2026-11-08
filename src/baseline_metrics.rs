//! Default-OFF phase instrumentation for the #106 state-services baseline.
//!
//! Build with `--features state-baseline-metrics` to record fixed-cardinality
//! wait/byte observations at real await boundaries; a default build compiles an
//! inert zero-sized timer with no atomics, allocation or formatting. Observations
//! are exported only by the existing loopback-only listener in `crate::metrics`
//! and never by the application router.
//!
//! Semantics that callers and the baseline runner must respect:
//!
//! * Durations are wall-clock spans of `await`ed operations, not CPU time and
//!   not a substitute for measuring a whole push/cold or warm run. Instrumented
//!   spans are nested (for example `remote_verified_readback` contains an inner
//!   object GET, and `native_git_hydration` contains remote GET plus decrypt), so
//!   values are **not additive** and must never be summed into a total.
//! * `ok` and `error` are explicit completions of the awaited operation.
//!   `cancelled` means the timer was dropped before completion: the future was
//!   abandoned because a deadline elapsed, the caller/task was cancelled, or the
//!   surrounding future was dropped. It is not an application error.
//! * Bytes are counted only after a successful transfer and only from the byte
//!   stream this process moved (known source or stream length). They are not
//!   object metadata sizes. Retries or re-sent request bodies inside the HTTP or
//!   filesystem layer can duplicate bytes on the wire; those duplicates are
//!   unknown here, so byte counters are lower-bound accounting of this process's
//!   transfers and never an exact network byte count.
//! * Not observable by these phases: native Git subprocess CPU inside
//!   receive-pack or fsck beyond the coarse `native_git_*` spans, in-process
//!   transient disk/worst-case GC temp peaks, PostgreSQL server CPU, kernel
//!   socket time, and DNS. Waits on in-process mutexes are excluded as well.
//! * Truth boundary: measurements come from one process on one physical host.
//!   They say nothing about another host, a replica, or the client.
//!
//! Labels are fixed and contain no repository, user, ref, key, token, database
//! URL or error-message text. Counters saturate at `u64::MAX` instead of wrapping.

/// Number of fixed phase labels.
pub const WIDTH: usize = 12;
/// Fixed outcome label count: ok, error, cancelled.
pub const OUTCOMES: usize = 3;
/// Upper bounds of the fixed duration histogram, in seconds.
pub const BUCKETS: [f64; 10] = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 5.0, 30.0];
/// Rendering labels for the same bounds plus the mandatory `+Inf` bucket.
pub const BUCKET_LABELS: [&str; 11] = ["0.005", "0.01", "0.025", "0.05", "0.1", "0.25", "0.5", "1", "5", "30", "+Inf"];

/// Closed set of instrumented phases. Every variant is always exported, so a
/// scrape has a stable number of series even before any observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Waiting for one of the fixed publication guard slots.
    PublicationSlot,
    /// Waiting for the sorted exact-ref advisory locks and their owner session.
    RefAdvisory,
    /// Waiting for a pooled PostgreSQL connection inside the Pando publish path.
    PoolCheckout,
    /// Waiting for the repository-wide publication window grant.
    RepoPublicationWindow,
    /// Waiting for the authoritative Pando state row lock (`FOR UPDATE`).
    StateRow,
    /// Waiting for the singleton storage-authority row lock that serializes
    /// remote artifact reservations.
    AuthorityLock,
    /// Native Git prepare work: bare init, ref writes, symbolic HEAD.
    NativeGitPrepare,
    /// Native Git `fsck --full --strict` over a reconstructed snapshot.
    NativeGitFsck,
    /// Recovering pack/index bytes into the disposable snapshot (cache hit copy
    /// or remote recovery, including decryption).
    NativeGitHydration,
    /// Streaming object upload of a known source length.
    RemotePut,
    /// Post-upload read-back verification of a known object length.
    RemoteVerifiedReadback,
    /// Whole-object GET into a local destination.
    RemoteGet,
}

impl Phase {
    pub const ALL: [Phase; WIDTH] = [
        Phase::PublicationSlot,
        Phase::RefAdvisory,
        Phase::PoolCheckout,
        Phase::RepoPublicationWindow,
        Phase::StateRow,
        Phase::AuthorityLock,
        Phase::NativeGitPrepare,
        Phase::NativeGitFsck,
        Phase::NativeGitHydration,
        Phase::RemotePut,
        Phase::RemoteVerifiedReadback,
        Phase::RemoteGet,
    ];
    pub const fn index(self) -> usize {
        self as usize
    }
    pub const fn label(self) -> &'static str {
        match self {
            Phase::PublicationSlot => "publication_slot",
            Phase::RefAdvisory => "ref_advisory",
            Phase::PoolCheckout => "pool_checkout",
            Phase::RepoPublicationWindow => "repo_publication_window",
            Phase::StateRow => "state_row",
            Phase::AuthorityLock => "authority_lock",
            Phase::NativeGitPrepare => "native_git_prepare",
            Phase::NativeGitFsck => "native_git_fsck",
            Phase::NativeGitHydration => "native_git_hydration",
            Phase::RemotePut => "remote_put",
            Phase::RemoteVerifiedReadback => "remote_verified_readback",
            Phase::RemoteGet => "remote_get",
        }
    }
}

/// How an instrumented operation ended. See the module docs for `Cancelled`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    Error,
    Cancelled,
}

impl Outcome {
    pub const fn index(self) -> usize {
        self as usize
    }
    pub const fn label(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Error => "error",
            Outcome::Cancelled => "cancelled",
        }
    }
}

const _: () = assert!(Phase::ALL.len() == WIDTH && OUTCOMES == 3 && BUCKETS.len() + 1 == BUCKET_LABELS.len());

#[cfg(feature = "state-baseline-metrics")]
mod enabled;
#[cfg(all(test, feature = "state-baseline-metrics"))]
mod tests;
#[cfg(feature = "state-baseline-metrics")]
pub use enabled::{Registry, Timer, render, render_registry, timed, timed_result};

#[cfg(not(feature = "state-baseline-metrics"))]
mod inert;
#[cfg(not(feature = "state-baseline-metrics"))]
pub use inert::{Timer, render, timed, timed_result};
