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
//!   without unbounded growth.
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
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, LazyLock, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

/// Conservative default concurrent authentication budget. The PostgreSQL pool
/// is 16 connections, so four admitted authentication lookups leave at least
/// twelve connections available for normal repository traffic.
pub const DEFAULT_MAX_INFLIGHT: usize = 4;
/// Maximum admitted concurrent authentication lookups. Keeping this well below
/// the pool size is what reserves database capacity for unrelated requests.
pub const MAX_INFLIGHT_CAP: usize = 8;
pub const DEFAULT_ATTEMPTS_PER_SOURCE: u32 = 10;
pub const DEFAULT_SOURCE_WINDOW_SECONDS: u64 = 60;
pub const DEFAULT_MAX_SOURCES: usize = 4096;
pub const DEFAULT_SOURCE_TTL_SECONDS: u64 = 300;
/// Fixed, source-independent retry hint. It is deliberately not derived from a
/// per-source bucket state, so it cannot become an identity/timing oracle.
pub const RETRY_AFTER_SECONDS: u64 = 60;
const RETRY_AFTER_HEADER: &str = "60";

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
    admissions: u64,
}

impl SourceTable {
    fn prune_expired(&mut self, now: Instant, ttl: Duration) {
        self.entries.retain(|_, entry| now.saturating_duration_since(entry.last_seen) < ttl);
    }

    fn evict_oldest(&mut self) {
        if let Some(source) = self.entries.iter().min_by_key(|(_, entry)| entry.last_seen).map(|(source, _)| *source) {
            self.entries.remove(&source);
        }
    }
}

/// RAII admission permit. Dropping it, including when a request future is
/// cancelled, returns the concurrent authentication slot to the process.
#[derive(Debug)]
pub struct AdmissionPermit {
    _permit: OwnedSemaphorePermit,
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
    fn consume_source(&self, source: IpAddr, now: Instant) -> bool {
        let mut table = self.source_table();
        table.admissions = table.admissions.wrapping_add(1);
        if table.entries.len() >= self.config.max_sources || table.admissions % 64 == 0 {
            table.prune_expired(now, self.config.source_ttl);
        }
        if let Some(entry) = table.entries.get_mut(&source) {
            if now.saturating_duration_since(entry.window_start) >= self.config.source_window {
                entry.window_start = now;
                entry.attempts = 0;
            }
            entry.last_seen = now;
            if entry.attempts >= self.config.attempts_per_source {
                return false;
            }
            entry.attempts += 1;
            return true;
        }
        if table.entries.len() >= self.config.max_sources {
            table.evict_oldest();
            // A clock anomaly or a zero-capacity construction must still never
            // grow the table past the configured bound.
            if table.entries.len() >= self.config.max_sources {
                return false;
            }
        }
        table.entries.insert(source, SourceEntry { window_start: now, attempts: 1, last_seen: now });
        true
    }

    /// Admit one authentication attempt for a known peer. The returned permit
    /// must be held until the database work and response construction finish.
    pub(crate) fn try_admit(&self, source: IpAddr) -> Result<AdmissionPermit, Response> {
        self.try_admit_at(source, Instant::now())
    }

    pub(crate) fn try_admit_at(&self, source: IpAddr, now: Instant) -> Result<AdmissionPermit, Response> {
        if !self.consume_source(source, now) {
            self.rejected_rate.fetch_add(1, Ordering::Relaxed);
            return Err(overloaded_response());
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
                Err(overloaded_response())
            }
        }
    }

    /// Admit an attempt that requires a transport peer. Used by the explicit
    /// auth lookup route: missing `ConnectInfo` is refused instead of silently
    /// trusting a caller-supplied header or invented identity.
    pub(crate) fn try_admit_required(&self, source: Option<IpAddr>) -> Result<AdmissionPermit, Response> {
        let Some(source) = source else {
            self.rejected_missing_peer.fetch_add(1, Ordering::Relaxed);
            return Err(missing_peer_response());
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

/// Route-level admission for the browser login/token-exchange POST.
///
/// The middleware runs outside the web session middleware so a rejected attempt
/// never reaches the session/credential database lookups. Missing `ConnectInfo`
/// is refused, including when an embedding server forgets to supply it. The
/// main listener installs transport-derived `ConnectInfo` for every request.
pub async fn login_middleware(State(state): State<Arc<AppState>>, request: Request<Body>, next: Next) -> Response {
    if request.method() == Method::POST && request.uri().path() == "/web/login" {
        let Some(source) = request_peer(&request) else {
            return missing_peer_response();
        };
        let admission = for_state(&state);
        let permit = match admission.try_admit(source) {
            Ok(permit) => permit,
            Err(response) => return response,
        };
        let response = next.run(request).await;
        drop(permit);
        return response;
    }
    next.run(request).await
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
        Err(response) => return response,
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
        let Err(response) = admission.try_admit_at(peer(1), now) else {
            panic!("third attempt was admitted");
        };
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
        let first = admission.try_admit_at(peer(1), now).ok().expect("first permit");
        let Err(overloaded) = admission.try_admit_at(peer(1), now) else {
            panic!("capacity bound did not reject the second attempt");
        };
        assert_eq!(overloaded.status(), StatusCode::TOO_MANY_REQUESTS);
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
        let Err(response) = admission.try_admit_required(None) else {
            panic!("missing peer was admitted");
        };
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(response.headers().get(header::RETRY_AFTER).is_none());
        let body = axum::body::to_bytes(response.into_body(), 8192).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("authentication admission unavailable"));
        assert!(admission.try_admit_required(Some(peer(3))).is_ok());
        assert_eq!(admission.counters().rejected_missing_peer, 1);
    }
}
