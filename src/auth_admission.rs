//! Bounded, process-local admission for authentication and credential exchange.
//!
//! This is a deliberately partial implementation of issue #84. It bounds the
//! login/token-exchange path and the explicit `/api/auth/whoami` identity lookup
//! before either of them may acquire a PostgreSQL connection. It does **not**
//! implement MFA, OIDC, an external identity provider, e-mail binding, account
//! recovery, per-username lockout, or a distributed rate limiter.
//!
//! Design rules:
//! * A source is the real TCP peer address supplied by Axum `ConnectInfo`.
//!   `X-Forwarded-For`, `Forwarded` and every other request header are ignored.
//! * Rate limits are keyed by peer address only. There is no username key, so an
//!   attacker cannot lock a victim account out by failing authentication.
//! * A small process-wide semaphore bounds concurrent authentication work before
//!   the first database query, leaving connection-pool capacity for ordinary
//!   requests. Permits are RAII (`OwnedSemaphorePermit`), so cancellation or a
//!   dropped request releases capacity immediately.
//! * The source table is bounded by entry count and TTL, and is pruned/evicted
//!   without unbounded growth or an unbounded per-request scan: hot sources are
//!   repositioned in an ordered index in `O(log n)`, and at most a fixed number
//!   of expired entries is removed per admission check.
//! * Rejections use a fixed generic body and a fixed `Retry-After`; neither the
//!   body nor a metric label contains a token, username, address or digest.
//!
//! The budget is per process. A multi-replica deployment gets one budget per
//! replica; this module does not coordinate replicas.

use crate::{AppState, auth};
use anyhow::{Context, Result, ensure};
use axum::{
    Json, Router,
    body::Body,
    extract::{Extension, State, connect_info::ConnectInfo},
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::json;
use std::{
    collections::{BTreeSet, HashMap},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, LazyLock, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

/// Conservative default concurrent authentication budget. It caps how much
/// pool pressure this module can add (at most four concurrent lookups against a
/// 16-connection pool); it does not reserve connections, because other,
/// unbounded API routes can consume the pool concurrently.
pub const DEFAULT_MAX_INFLIGHT: usize = 4;
/// Maximum admitted concurrent authentication lookups. Keeping this well below
/// the pool size limits this module's contribution to pool saturation.
pub const MAX_INFLIGHT_CAP: usize = 8;
pub const DEFAULT_ATTEMPTS_PER_SOURCE: u32 = 10;
pub const DEFAULT_SOURCE_WINDOW_SECONDS: u64 = 60;
pub const DEFAULT_MAX_SOURCES: usize = 4096;
pub const DEFAULT_SOURCE_TTL_SECONDS: u64 = 300;
/// Fixed, source-independent retry hint. It is deliberately not derived from a
/// per-source bucket state, so it cannot become an identity/timing oracle.
pub const RETRY_AFTER_SECONDS: u64 = 60;
const RETRY_AFTER_HEADER: &str = "60";
/// Hard per-request bound on expired source entries evicted in one admission
/// check. TTL cleanup is amortised: a large cold table drains over several
/// requests instead of scanning the whole map under the mutex.
const MAX_EXPIRY_POPS_PER_ACCESS: usize = 64;

/// Validated, startup-loaded authentication admission settings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionConfig {
    pub max_inflight: usize,
    pub attempts_per_source: u32,
    pub source_window: Duration,
    pub max_sources: usize,
    pub source_ttl: Duration,
}

impl Default for AdmissionConfig {
    fn default() -> Self {
        Self {
            max_inflight: DEFAULT_MAX_INFLIGHT,
            attempts_per_source: DEFAULT_ATTEMPTS_PER_SOURCE,
            source_window: Duration::from_secs(DEFAULT_SOURCE_WINDOW_SECONDS),
            max_sources: DEFAULT_MAX_SOURCES,
            source_ttl: Duration::from_secs(DEFAULT_SOURCE_TTL_SECONDS),
        }
    }
}

impl AdmissionConfig {
    /// Load settings from the trusted runtime environment. Invalid values fail
    /// startup instead of silently weakening the bound.
    pub fn from_env() -> Result<Self> {
        let max_inflight = env_number("ROOTYARD_AUTH_ADMISSION_MAX_INFLIGHT", DEFAULT_MAX_INFLIGHT as u64)?;
        let attempts_per_source =
            env_number("ROOTYARD_AUTH_ADMISSION_ATTEMPTS_PER_SOURCE", DEFAULT_ATTEMPTS_PER_SOURCE as u64)?;
        let source_window_seconds =
            env_number("ROOTYARD_AUTH_ADMISSION_SOURCE_WINDOW_SECONDS", DEFAULT_SOURCE_WINDOW_SECONDS)?;
        let max_sources = env_number("ROOTYARD_AUTH_ADMISSION_MAX_SOURCES", DEFAULT_MAX_SOURCES as u64)?;
        let source_ttl_seconds = env_number("ROOTYARD_AUTH_ADMISSION_SOURCE_TTL_SECONDS", DEFAULT_SOURCE_TTL_SECONDS)?;
        Self::try_new(
            max_inflight.try_into().context("ROOTYARD_AUTH_ADMISSION_MAX_INFLIGHT is too large")?,
            attempts_per_source.try_into().context("ROOTYARD_AUTH_ADMISSION_ATTEMPTS_PER_SOURCE is too large")?,
            source_window_seconds,
            max_sources.try_into().context("ROOTYARD_AUTH_ADMISSION_MAX_SOURCES is too large")?,
            source_ttl_seconds,
        )
    }

    pub fn try_new(
        max_inflight: usize,
        attempts_per_source: u32,
        source_window_seconds: u64,
        max_sources: usize,
        source_ttl_seconds: u64,
    ) -> Result<Self> {
        ensure!(
            (1..=MAX_INFLIGHT_CAP).contains(&max_inflight),
            "ROOTYARD_AUTH_ADMISSION_MAX_INFLIGHT must be in 1..={MAX_INFLIGHT_CAP}"
        );
        ensure!(
            (1..=1000).contains(&attempts_per_source),
            "ROOTYARD_AUTH_ADMISSION_ATTEMPTS_PER_SOURCE must be in 1..=1000"
        );
        ensure!(
            (1..=3600).contains(&source_window_seconds),
            "ROOTYARD_AUTH_ADMISSION_SOURCE_WINDOW_SECONDS must be in 1..=3600"
        );
        ensure!((1..=1_000_000).contains(&max_sources), "ROOTYARD_AUTH_ADMISSION_MAX_SOURCES must be in 1..=1000000");
        ensure!(
            (1..=86_400).contains(&source_ttl_seconds),
            "ROOTYARD_AUTH_ADMISSION_SOURCE_TTL_SECONDS must be in 1..=86400"
        );
        ensure!(
            source_ttl_seconds >= source_window_seconds,
            "ROOTYARD_AUTH_ADMISSION_SOURCE_TTL_SECONDS must be >= ROOTYARD_AUTH_ADMISSION_SOURCE_WINDOW_SECONDS"
        );
        Ok(Self {
            max_inflight,
            attempts_per_source,
            source_window: Duration::from_secs(source_window_seconds),
            max_sources,
            source_ttl: Duration::from_secs(source_ttl_seconds),
        })
    }
}

fn env_number(name: &str, default: u64) -> Result<u64> {
    match std::env::var(name) {
        Ok(value) => value.parse().with_context(|| format!("invalid {name}")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => anyhow::bail!("{name} must be ASCII digits"),
    }
}

/// Aggregate process counters. They have no labels and are not exported through
/// Prometheus; no peer address, username or credential is retained.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AdmissionCounters {
    pub admitted: u64,
    pub rejected_rate: u64,
    pub rejected_capacity: u64,
    pub rejected_missing_peer: u64,
}

#[derive(Debug)]
struct SourceEntry {
    window_start: Instant,
    attempts: u32,
    last_seen: Instant,
}

#[derive(Debug, Default)]
struct SourceTable {
    entries: HashMap<IpAddr, SourceEntry>,
    /// Access counter used only to schedule amortised TTL cleanup.
    admissions: u64,
    /// `(last_seen, source)` for every live entry, so the oldest and the most
    /// stale buckets are found in `O(log n)` without scanning the map.
    by_last_seen: BTreeSet<(Instant, IpAddr)>,
}

impl SourceTable {
    /// Reposition a live entry after its `last_seen` changes. Removes the old
    /// order tuple first so the index never accumulates stale duplicates.
    fn touch(&mut self, source: IpAddr, entry: &mut SourceEntry, now: Instant) {
        self.by_last_seen.remove(&(entry.last_seen, source));
        entry.last_seen = entry.last_seen.max(now);
        self.by_last_seen.insert((entry.last_seen, source));
    }

    /// Evict at most `budget` expired entries. Work per admission check stays
    /// constant even when a cold table holds up to `max_sources` entries.
    fn expire_oldest(&mut self, now: Instant, ttl: Duration, budget: usize) -> usize {
        let mut expired = 0;
        while expired < budget {
            let Some(&(last_seen, source)) = self.by_last_seen.first() else {
                break;
            };
            if now.saturating_duration_since(last_seen) < ttl {
                break;
            }
            self.by_last_seen.pop_first();
            if self.entries.get(&source).is_some_and(|entry| entry.last_seen == last_seen) {
                self.entries.remove(&source);
                expired += 1;
            }
        }
        expired
    }

    /// Drop the least-recently-seen live bucket, if any. `O(log n)`.
    fn evict_oldest(&mut self) {
        while let Some((_, source)) = self.by_last_seen.pop_first() {
            if self.entries.remove(&source).is_some() {
                return;
            }
        }
    }
}

/// RAII admission permit. Dropping it, including when a request future is
/// cancelled, returns the concurrent authentication slot to the process.
#[derive(Debug)]
pub struct AdmissionPermit {
    _permit: OwnedSemaphorePermit,
}

/// Why admission refused an attempt. Deliberately small so
/// `Result<AdmissionPermit, _>` stays cheap; it becomes a fixed HTTP response
/// only at the middleware/route boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionRejection {
    /// Per-source window or in-flight capacity exhausted (fixed `429`).
    Overloaded,
    /// No trusted transport peer for this route (fixed `503`, fail closed).
    MissingPeer,
}

impl IntoResponse for AdmissionRejection {
    fn into_response(self) -> Response {
        match self {
            Self::Overloaded => overloaded_response(),
            Self::MissingPeer => missing_peer_response(),
        }
    }
}

/// Process-local bounded authentication admission state.
pub struct AuthAdmission {
    config: AdmissionConfig,
    inflight: Arc<Semaphore>,
    sources: Mutex<SourceTable>,
    admitted: AtomicU64,
    rejected_rate: AtomicU64,
    rejected_capacity: AtomicU64,
    rejected_missing_peer: AtomicU64,
}

impl AuthAdmission {
    pub fn new(config: AdmissionConfig) -> Self {
        let inflight = Arc::new(Semaphore::new(config.max_inflight));
        Self {
            config,
            inflight,
            sources: Mutex::new(SourceTable::default()),
            admitted: AtomicU64::new(0),
            rejected_rate: AtomicU64::new(0),
            rejected_capacity: AtomicU64::new(0),
            rejected_missing_peer: AtomicU64::new(0),
        }
    }

    pub fn config(&self) -> &AdmissionConfig {
        &self.config
    }

    pub fn counters(&self) -> AdmissionCounters {
        AdmissionCounters {
            admitted: self.admitted.load(Ordering::Relaxed),
            rejected_rate: self.rejected_rate.load(Ordering::Relaxed),
            rejected_capacity: self.rejected_capacity.load(Ordering::Relaxed),
            rejected_missing_peer: self.rejected_missing_peer.load(Ordering::Relaxed),
        }
    }

    fn source_table(&self) -> MutexGuard<'_, SourceTable> {
        self.sources.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Consume one per-source attempt. Returns `false` when this source has used
    /// its fixed-window budget. No username or credential participates.
    ///
    /// Every access, admitted or rate-denied, refreshes the source's last-seen
    /// position in both indexes. Work is `O(log n)` plus the fixed TTL-cleanup
    /// budget, independent of how many sources the table holds.
    fn consume_source(&self, source: IpAddr, now: Instant) -> bool {
        let mut table = self.source_table();
        table.admissions = table.admissions.wrapping_add(1);
        // Amortised, bounded cleanup: every 64th admission and whenever the
        // table is at its hard capacity bound. Never a full-map scan.
        if table.admissions.is_multiple_of(64) || table.entries.len() >= self.config.max_sources {
            table.expire_oldest(now, self.config.source_ttl, MAX_EXPIRY_POPS_PER_ACCESS);
        }
        if let Some(mut entry) = table.entries.remove(&source) {
            if now.saturating_duration_since(entry.window_start) >= self.config.source_window {
                entry.window_start = now;
                entry.attempts = 0;
            }
            let admitted = entry.attempts < self.config.attempts_per_source;
            if admitted {
                entry.attempts += 1;
            }
            table.touch(source, &mut entry, now);
            table.entries.insert(source, entry);
            return admitted;
        }
        if table.entries.len() >= self.config.max_sources {
            table.evict_oldest();
            // A clock anomaly or a zero-capacity construction must still never
            // grow the table past the configured bound.
            if table.entries.len() >= self.config.max_sources {
                return false;
            }
        }
        table.by_last_seen.insert((now, source));
        table.entries.insert(source, SourceEntry { window_start: now, attempts: 1, last_seen: now });
        true
    }

    /// Admit one authentication attempt for a known peer. The returned permit
    /// must be held until the database work and response construction finish.
    pub(crate) fn try_admit(&self, source: IpAddr) -> Result<AdmissionPermit, AdmissionRejection> {
        self.try_admit_at(source, Instant::now())
    }

    pub(crate) fn try_admit_at(&self, source: IpAddr, now: Instant) -> Result<AdmissionPermit, AdmissionRejection> {
        if !self.consume_source(source, now) {
            self.rejected_rate.fetch_add(1, Ordering::Relaxed);
            return Err(AdmissionRejection::Overloaded);
        }
        match self.inflight.clone().try_acquire_owned() {
            Ok(permit) => {
                self.admitted.fetch_add(1, Ordering::Relaxed);
                Ok(AdmissionPermit { _permit: permit })
            }
            Err(_) => {
                // Queueing here would let a login flood consume memory and then
                // hit the database in a burst; fail fast before any query.
                self.rejected_capacity.fetch_add(1, Ordering::Relaxed);
                Err(AdmissionRejection::Overloaded)
            }
        }
    }

    /// Admit an attempt that requires a transport peer. Used by the explicit
    /// auth lookup route: missing `ConnectInfo` is refused instead of silently
    /// trusting a caller-supplied header or invented identity.
    pub(crate) fn try_admit_required(&self, source: Option<IpAddr>) -> Result<AdmissionPermit, AdmissionRejection> {
        let Some(source) = source else {
            self.rejected_missing_peer.fetch_add(1, Ordering::Relaxed);
            return Err(AdmissionRejection::MissingPeer);
        };
        self.try_admit(source)
    }
}

/// Read the peer address from Axum `ConnectInfo` only. Headers are never
/// consulted; proxying headers are untrusted caller input.
pub(crate) fn request_peer(request: &Request<Body>) -> Option<IpAddr> {
    request.extensions().get::<ConnectInfo<SocketAddr>>().map(|connect_info| connect_info.0.ip())
}

fn extension_peer(peer: Option<Extension<ConnectInfo<SocketAddr>>>) -> Option<IpAddr> {
    peer.map(|Extension(ConnectInfo(address))| address.ip())
}

fn fixed_response(status: StatusCode, message: &'static str) -> Response {
    let mut response = (status, Json(json!({ "error": message }))).into_response();
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn overloaded_response() -> Response {
    let mut response = fixed_response(StatusCode::TOO_MANY_REQUESTS, "authentication temporarily unavailable");
    response.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from_static(RETRY_AFTER_HEADER));
    response
}

fn missing_peer_response() -> Response {
    fixed_response(StatusCode::SERVICE_UNAVAILABLE, "authentication admission unavailable")
}

/// Whether this request is the browser login/token-exchange POST guarded by the
/// login middleware.
fn is_login_attempt(request: &Request<Body>) -> bool {
    request.method() == Method::POST && request.uri().path() == "/web/login"
}

/// Admission gate for a confirmed login POST. A request without a transport
/// peer is rejected (fail closed); otherwise the same bounded budget as
/// `whoami` applies.
///
/// It is separated from [`login_middleware`] so the route's peer behaviour can
/// be unit-tested without a database-backed `AppState` or an axum `Next` value;
/// the full middleware path also runs in the native harness.
pub(crate) fn admit_login_attempt(
    admission: &AuthAdmission,
    request: &Request<Body>,
) -> Result<AdmissionPermit, AdmissionRejection> {
    admission.try_admit_required(request_peer(request))
}

/// Route-level admission for the browser login/token-exchange POST.
///
/// The middleware runs outside the web session middleware so a rejected attempt
/// never reaches the session/credential database lookups. Missing `ConnectInfo`
/// is refused with a fixed `503` (fail closed), including when an embedding
/// server forgets to supply it. The main listener installs transport-derived
/// `ConnectInfo` for every request.
pub async fn login_middleware(State(state): State<Arc<AppState>>, request: Request<Body>, next: Next) -> Response {
    if !is_login_attempt(&request) {
        return next.run(request).await;
    }
    let admission = for_state(&state);
    let permit = match admit_login_attempt(&admission, &request) {
        Ok(permit) => permit,
        Err(rejection) => return rejection.into_response(),
    };
    let response = next.run(request).await;
    drop(permit);
    response
}

/// Authenticated identity probe used by the bounded-admission slice and its
/// native harness. It returns only the caller's own non-secret identity fields.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/api/auth/whoami", get(whoami))
}

async fn whoami(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
) -> Response {
    let admission = for_state(&state);
    let permit = match admission.try_admit_required(extension_peer(peer)) {
        Ok(permit) => permit,
        Err(rejection) => return rejection.into_response(),
    };
    let identity = match auth::authenticate(&state.pool, &headers).await {
        Ok(identity) => identity,
        Err(error) => return error.into_response(),
    };
    drop(permit);
    let mut response = (
        StatusCode::OK,
        Json(json!({
            "id": identity.id,
            "username": identity.username,
            "read_only": identity.read_only,
        })),
    )
        .into_response();
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

static REGISTRY: LazyLock<Mutex<HashMap<Uuid, Arc<AuthAdmission>>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn registry() -> MutexGuard<'static, HashMap<Uuid, Arc<AuthAdmission>>> {
    REGISTRY.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Validate and install the process admission policy before the listener starts.
pub fn init_for_state(state: &AppState) -> Result<Arc<AuthAdmission>> {
    let admission = Arc::new(AuthAdmission::new(AdmissionConfig::from_env()?));
    registry().insert(state.storage.volume_id, admission.clone());
    Ok(admission)
}

/// Return this volume's admission state, installing conservative defaults if a
/// caller did not run `init_for_state` (for example an in-process unit router).
pub fn for_state(state: &AppState) -> Arc<AuthAdmission> {
    if let Some(admission) = registry().get(&state.storage.volume_id).cloned() {
        return admission;
    }
    let admission = Arc::new(AuthAdmission::new(AdmissionConfig::from_env().unwrap_or_default()));
    registry().entry(state.storage.volume_id).or_insert_with(|| admission.clone()).clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(max_inflight: usize, attempts: u32, max_sources: usize) -> AdmissionConfig {
        AdmissionConfig::try_new(max_inflight, attempts, 60, max_sources, 300).unwrap()
    }

    fn peer(last: u8) -> IpAddr {
        IpAddr::from([127, 0, 0, last])
    }

    #[test]
    fn config_rejects_zero_and_unsafe_values() {
        assert!(AdmissionConfig::try_new(0, 10, 60, 16, 300).is_err());
        assert!(AdmissionConfig::try_new(MAX_INFLIGHT_CAP + 1, 10, 60, 16, 300).is_err());
        assert!(AdmissionConfig::try_new(4, 0, 60, 16, 300).is_err());
        assert!(AdmissionConfig::try_new(4, 10, 0, 16, 300).is_err());
        assert!(AdmissionConfig::try_new(4, 10, 60, 0, 300).is_err());
        assert!(AdmissionConfig::try_new(4, 10, 60, 16, 59).is_err());
        assert!(AdmissionConfig::try_new(4, 10, 60, 16, 300).is_ok());
    }

    #[tokio::test]
    async fn source_limit_has_fixed_retry_after_and_no_identity_leak() {
        let admission = AuthAdmission::new(config(4, 2, 16));
        let now = Instant::now();
        assert!(admission.try_admit_at(peer(1), now).is_ok());
        assert!(admission.try_admit_at(peer(1), now).is_ok());
        let Err(rejection) = admission.try_admit_at(peer(1), now) else {
            panic!("third attempt was admitted");
        };
        assert_eq!(rejection, AdmissionRejection::Overloaded);
        let response = rejection.into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers().get(header::RETRY_AFTER).unwrap().to_str().unwrap(), RETRY_AFTER_HEADER);
        assert_eq!(response.headers().get(header::CACHE_CONTROL).unwrap().to_str().unwrap(), "no-store");
        let body = axum::body::to_bytes(response.into_body(), 8192).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(!text.contains("127.0.0.1"));
        assert!(!text.contains("alice"));
        assert!(!text.contains("ryt_"));
    }

    #[test]
    fn unrelated_source_is_isolated_from_a_limited_source() {
        let admission = AuthAdmission::new(config(4, 1, 16));
        let now = Instant::now();
        assert!(admission.try_admit_at(peer(1), now).is_ok());
        assert!(admission.try_admit_at(peer(1), now).is_err());
        // The second source has its own bucket: no global username/account lock.
        assert!(admission.try_admit_at(peer(2), now).is_ok());
    }

    #[test]
    fn window_expiry_resets_only_the_elapsed_source() {
        let admission = AuthAdmission::new(config(4, 1, 16));
        let start = Instant::now();
        assert!(admission.try_admit_at(peer(1), start).is_ok());
        assert!(admission.try_admit_at(peer(1), start).is_err());
        let later = start + Duration::from_secs(61);
        assert!(admission.try_admit_at(peer(1), later).is_ok());
    }

    #[test]
    fn dropping_permit_releases_capacity_without_waiting() {
        let admission = AuthAdmission::new(config(1, 10, 16));
        let now = Instant::now();
        let first = admission.try_admit_at(peer(1), now).expect("first permit");
        let Err(overloaded) = admission.try_admit_at(peer(1), now) else {
            panic!("capacity bound did not reject the second attempt");
        };
        assert_eq!(overloaded.into_response().status(), StatusCode::TOO_MANY_REQUESTS);
        drop(first);
        // Cancellation and explicit drop both run the same RAII release.
        assert!(admission.try_admit_at(peer(1), now).is_ok());
        assert_eq!(admission.counters().rejected_capacity, 1);
    }

    #[test]
    fn source_table_is_bounded_by_count_and_ttl() {
        let admission = AuthAdmission::new(config(8, 10, 2));
        let start = Instant::now();
        assert!(admission.try_admit_at(peer(1), start).is_ok());
        assert!(admission.try_admit_at(peer(2), start).is_ok());
        // A third live source evicts the oldest entry instead of growing.
        assert!(admission.try_admit_at(peer(3), start).is_ok());
        assert_eq!(admission.source_table().entries.len(), 2);
        // TTL pruning removes stale buckets before a new insert.
        let later = start + Duration::from_secs(301);
        assert!(admission.try_admit_at(peer(4), later).is_ok());
        assert_eq!(admission.source_table().entries.len(), 1);
    }

    #[test]
    fn forwarded_and_authorization_headers_never_change_the_peer() {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/auth/whoami")
            .header("x-forwarded-for", "203.0.113.7, 198.51.100.9")
            .header("forwarded", "for=203.0.113.7")
            .header(header::AUTHORIZATION, "Basic YWxpY2U6Zm9yZ2Vk")
            .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4242))))
            .body(Body::empty())
            .unwrap();
        assert_eq!(request_peer(&request), Some(peer(1)));
        let request = Request::builder().uri("/api/auth/whoami").body(Body::empty()).unwrap();
        assert_eq!(request_peer(&request), None);
    }

    #[tokio::test]
    async fn missing_peer_is_refused_on_the_new_auth_route() {
        let admission = AuthAdmission::new(config(4, 10, 16));
        let Err(rejection) = admission.try_admit_required(None) else {
            panic!("missing peer was admitted");
        };
        assert_eq!(rejection, AdmissionRejection::MissingPeer);
        let response = rejection.into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(response.headers().get(header::RETRY_AFTER).is_none());
        let body = axum::body::to_bytes(response.into_body(), 8192).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("authentication admission unavailable"));
        assert!(admission.try_admit_required(Some(peer(3))).is_ok());
        assert_eq!(admission.counters().rejected_missing_peer, 1);
    }

    #[tokio::test]
    async fn aborting_a_spawned_request_releases_the_permit() {
        let admission = Arc::new(AuthAdmission::new(config(1, 10, 16)));
        let now = Instant::now();
        let (holding_tx, holding_rx) = tokio::sync::oneshot::channel();
        let task = {
            let admission = Arc::clone(&admission);
            tokio::spawn(async move {
                let _permit = admission.try_admit_at(peer(1), now).expect("spawned permit");
                let _ = holding_tx.send(());
                std::future::pending::<()>().await;
            })
        };
        holding_rx.await.expect("task should acquire the only permit");
        // The held permit is still live inside the spawned (pending) future.
        assert_eq!(admission.try_admit_at(peer(1), now).err(), Some(AdmissionRejection::Overloaded));
        task.abort();
        let error = task.await.expect_err("aborted task must not complete");
        assert!(error.is_cancelled());
        // No explicit drop ran: aborting the future is what released the slot.
        assert!(admission.try_admit_at(peer(1), now).is_ok());
        assert_eq!(admission.counters().rejected_capacity, 1);
    }

    #[tokio::test]
    async fn login_route_requires_a_transport_peer() {
        let admission = AuthAdmission::new(config(4, 10, 16));
        let login = Request::builder().method(Method::POST).uri("/web/login").body(Body::empty()).unwrap();
        assert!(is_login_attempt(&login));
        // No ConnectInfo: the login gate fails closed instead of admitting.
        let Err(rejection) = admit_login_attempt(&admission, &login) else {
            panic!("login without a transport peer was admitted");
        };
        assert_eq!(rejection, AdmissionRejection::MissingPeer);
        let response = rejection.into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(response.headers().get(header::RETRY_AFTER).is_none());
        assert_eq!(admission.counters().rejected_missing_peer, 1);
        // The same route is admitted when a real transport peer is present.
        let login_with_peer = Request::builder()
            .method(Method::POST)
            .uri("/web/login")
            .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4100))))
            .body(Body::empty())
            .unwrap();
        assert!(admit_login_attempt(&admission, &login_with_peer).is_ok());
        // Other routes and methods do not enter the login gate.
        let whoami = Request::builder().method(Method::GET).uri("/api/auth/whoami").body(Body::empty()).unwrap();
        assert!(!is_login_attempt(&whoami));
        let other_post = Request::builder().method(Method::POST).uri("/api/repos").body(Body::empty()).unwrap();
        assert!(!is_login_attempt(&other_post));
    }

    #[test]
    fn hot_updates_and_rotation_keep_both_indexes_bounded() {
        let admission = AuthAdmission::new(config(8, 10, 4));
        let start = Instant::now();
        // Repeated access to one hot source, including rate-denied attempts,
        // must keep exactly one order tuple rather than growing the index.
        for step in 0..500u64 {
            let now = start + Duration::from_millis(step);
            let _ = admission.try_admit_at(peer(1), now);
        }
        {
            let table = admission.source_table();
            assert_eq!(table.entries.len(), 1);
            assert_eq!(table.by_last_seen.len(), 1);
        }
        // Source rotation with a hard cap never exceeds capacity and never
        // desynchronises the order index from the entry map.
        for last in 2..=200u8 {
            let now = start + Duration::from_secs(1) + Duration::from_millis(u64::from(last));
            assert!(admission.try_admit_at(IpAddr::from([127, 0, 0, last]), now).is_ok());
            let table = admission.source_table();
            assert!(table.entries.len() <= 4);
            assert!(table.by_last_seen.len() <= 4);
            assert_eq!(table.entries.len(), table.by_last_seen.len());
        }
    }

    #[test]
    fn expiration_cleanup_is_bounded_per_access() {
        // Fill the table to its hard cap with entries that all expire together.
        let admission = AuthAdmission::new(config(8, 10, 200));
        let start = Instant::now();
        for last in 1..=200u8 {
            assert!(admission.try_admit_at(peer(last), start).is_ok());
        }
        assert_eq!(admission.source_table().entries.len(), 200);
        let later = start + Duration::from_secs(301);
        // Capacity-triggered cleanup removes at most the fixed budget of
        // expired entries, then the new bucket is inserted: no full-table scan.
        assert!(admission.try_admit_at(peer(250), later).is_ok());
        let table = admission.source_table();
        assert_eq!(table.entries.len(), 200 - MAX_EXPIRY_POPS_PER_ACCESS + 1);
        assert_eq!(table.entries.len(), table.by_last_seen.len());
    }
}
