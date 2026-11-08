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
//! * Durations are wall-clock spans of `await`ed client operations, not CPU time
//!   and not a substitute for measuring a whole push/cold or warm run. The spans
//!   below nest: `native_git_hydration` contains any remote GET and decryption
//!   inside it, and `ref_advisory` contains an unmetered owner-session pool
//!   checkout. `remote_verified_readback` is its own phase and is *not* also
//!   recorded as `remote_get` for the same transfer. Values are therefore **not
//!   additive** and must never be summed into a total.
//! * `ok` and `error` are explicit completions of the awaited operation. An `Err`
//!   handed back to the instrumented future is `error`, including a nested
//!   `tokio::time::timeout(_at)` that expired and returned `Elapsed`.
//!   `cancelled` is narrower: the instrumented future or its timer was dropped
//!   before it could complete (caller aborted, enclosing future dropped, task
//!   ended), so no completion was observed. It is not an application error, and a
//!   deadline that fired normally is not by itself `cancelled`.
//! * Bytes are counted only after a successful S3-backed transfer and only from
//!   the known source or stream length. The local-filesystem object store never
//!   produces `remote_*` series. Counts are not object-metadata sizes and not wire
//!   sizes: HTTP headers, TLS overhead and bytes re-sent by client retries are
//!   unknown here, so these are lower-bound logical-payload counts.
//! * Only the fixed call sites named on each phase are measured. This is not full
//!   coverage of every lock, pool checkout or byte path in the process.
//! * Not observable by these phases: native Git subprocess CPU inside
//!   receive-pack or fsck beyond the coarse `native_git_*` spans, in-process
//!   transient disk/worst-case GC temp peaks, PostgreSQL server execution time
//!   separated from the client round trip, kernel socket time, and DNS. Waits on
//!   in-process mutexes are excluded as well.
//! * Scraping `/metrics` acquires a pool connection and runs one SQL snapshot
//!   statement per scrape. That observer work is outside every instrumented span
//!   but adds load to the same database and pool being measured, so a
//!   before/after scrape perturbs the case slightly. Zero values never prove an
//!   uncontended lock or an uncontended database.
//! * Truth boundary: measurements come from one process on one physical host.
//!   They say nothing about another host, a replica, or the client.
//!
//! These are wait and byte counters only: no authority decision reads them, and no
//! lock, CAS, lease, deadline or liveness behaviour depends on the feature. Labels
//! are fixed and contain no repository, user, ref, key, token, database URL or
//! error-message text. Counters saturate at `u64::MAX` instead of wrapping.

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
    /// Waiting for the sorted exact-ref advisory locks and the owner session that
    /// holds them. Includes that owner session's unmetered pool checkout and the
    /// bounded retry sleeps between lock attempts.
    RefAdvisory,
    /// Waiting for a pooled PostgreSQL connection at the instrumented Pando call
    /// sites only: `pando_gateway::publish`, `snapshot::materialize` and the
    /// `pack_store` publish/load/recover paths. Admission, read-lease, auth and
    /// metrics-scrape checkouts are **not** measured.
    PoolCheckout,
    /// Waiting for the repository-wide publication window grant; the grant is
    /// served on the existing owner session, so this adds no pool checkout.
    RepoPublicationWindow,
    /// Full client round trip of the authoritative `pando_repository_states`
    /// `SELECT ... FOR UPDATE OF s`: statement submission, PostgreSQL execution
    /// and row-lock wait, and the row being returned. Not pure lock wait.
    StateRow,
    /// Full client round trip of the singleton storage-authority
    /// `SELECT ... FOR UPDATE` that serialises remote artifact reservations:
    /// statement submission, execution, row-lock wait and row return. Not pure
    /// lock wait.
    AuthorityLock,
    /// Native Git prepare work: bare init, ref writes, symbolic HEAD.
    NativeGitPrepare,
    /// Native Git `fsck --full --strict` over a reconstructed snapshot.
    NativeGitFsck,
    /// Recovering pack/index bytes into the disposable snapshot (cache hit copy
    /// or remote recovery, including decryption).
    NativeGitHydration,
    /// S3-backed object upload of a known source length. The local-filesystem
    /// object store fallback is never counted here.
    RemotePut,
    /// S3-backed post-upload read-back verification of a known object length.
    /// Recorded instead of `RemoteGet` for that transfer, never both.
    RemoteVerifiedReadback,
    /// S3-backed whole-object GET into a local destination. Local-filesystem
    /// reads and ranged GETs are not counted.
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
