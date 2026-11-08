//! Central, privacy-preserving internal-error classification and request correlation.
//!
//! Only fixed classifications, a validated SQLSTATE, a server-generated UUID and
//! the router's matched path pattern are emitted. Error Display/Debug text, URLs,
//! headers, query strings, user content and source strings are never formatted.
use crate::storage::remote_objects::RemoteStoreError;
use axum::{
    extract::{MatchedPath, Request},
    http::{HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};
use serde_json::{Value, json};
use std::any::Any;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::task_local;
use uuid::Uuid;

/// Bounded fixed-class rate limit for error events: one fixed global window.
const LOG_LIMIT_PER_SECOND: u64 = 100;
/// Fixed capacity of the stderr writer queue. Once full, new records are
/// discarded instead of blocking a request or growing memory.
const LOG_QUEUE_CAPACITY: usize = 128;
static LOG_LIMITER: OnceLock<Mutex<LogLimiter>> = OnceLock::new();
static LOG_SENDER: OnceLock<Option<SyncSender<String>>> = OnceLock::new();
static LOG_DROPPED: AtomicU64 = AtomicU64::new(0);

struct LogLimiter {
    start: Instant,
    count: u64,
}

impl LogLimiter {
    fn allow(&mut self, now: Instant) -> bool {
        if now.saturating_duration_since(self.start) >= Duration::from_secs(1) {
            self.start = now;
            self.count = 0;
        }
        if self.count >= LOG_LIMIT_PER_SECOND {
            return false;
        }
        self.count += 1;
        true
    }
}

/// Number of accepted error events discarded because the bounded queue was full,
/// the writer thread was gone, output was disabled, or a record could not be
/// completely written. Rate-limited faults and queued records at exit are excluded.
pub(crate) fn dropped_event_count() -> u64 {
    LOG_DROPPED.load(Ordering::Relaxed)
}

fn saturating_increment(counter: &AtomicU64) {
    let mut current = counter.load(Ordering::Relaxed);
    while current != u64::MAX {
        match counter.compare_exchange_weak(current, current + 1, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

fn record_dropped() {
    saturating_increment(&LOG_DROPPED);
}

/// Writes exactly one record plus its line terminator. The error is returned so
/// the writer thread discards it best-effort; nothing here panics.
fn write_record<W: std::io::Write>(writer: &mut W, record: &str) -> std::io::Result<()> {
    writer.write_all(record.as_bytes())?;
    writer.write_all(b"\n")
}

fn deliver_record<W: std::io::Write>(writer: &mut W, record: &str, dropped: &AtomicU64) {
    if write_record(writer, record).is_err() {
        saturating_increment(dropped);
    }
}

/// Dedicated writer thread body: takes the stderr lock for one complete record at
/// a time, performs no other I/O and treats every write failure as best-effort.
fn writer_loop(receiver: Receiver<String>) {
    for record in receiver {
        deliver_record(&mut std::io::stderr().lock(), &record, &LOG_DROPPED);
    }
}

/// Lazily starts the single named writer thread. A spawn failure disables output
/// safely (records then count as dropped) instead of panicking.
fn log_sender() -> Option<&'static SyncSender<String>> {
    LOG_SENDER
        .get_or_init(|| {
            let (sender, receiver) = mpsc::sync_channel::<String>(LOG_QUEUE_CAPACITY);
            let builder = std::thread::Builder::new().name("rootyard-error-log".to_owned());
            let spawned = builder.spawn(move || writer_loop(receiver));
            match spawned {
                Ok(_worker) => Some(sender),
                Err(_) => None,
            }
        })
        .as_ref()
}

/// Non-blocking handoff. A full or disconnected queue discards the record.
fn offer_to(sender: &SyncSender<String>, record: String) -> bool {
    match sender.try_send(record) {
        Ok(()) => true,
        Err(mpsc::TrySendError::Full(_)) | Err(mpsc::TrySendError::Disconnected(_)) => false,
    }
}

#[derive(Clone)]
struct RequestScope {
    request_id: Uuid,
    route: Option<String>,
}
task_local! {
    static REQUEST_SCOPE: RequestScope;
}

/// Wraps every routed request future and stamps the response with our own
/// correlation ID. Incoming IDs are ignored; the outer layer preserves status,
/// body, security headers and all downstream middleware behavior.
pub async fn middleware(request: Request, next: Next) -> Response {
    let route = request.extensions().get::<MatchedPath>().map(|path| path.as_str().to_owned());
    let scope = RequestScope { request_id: Uuid::new_v4(), route };
    let request_id = scope.request_id;
    let mut response = REQUEST_SCOPE.scope(scope, next.run(request)).await;
    if let Ok(value) = HeaderValue::from_str(&request_id.to_string()) {
        response.headers_mut().insert(HeaderName::from_static("x-request-id"), value);
    }
    response
}

struct Classification {
    kind: &'static str,
    sqlstate: Option<String>,
    remote_op: Option<&'static str>,
    remote_status: Option<u16>,
}
impl Classification {
    fn kind(kind: &'static str) -> Self {
        Self { kind, sqlstate: None, remote_op: None, remote_status: None }
    }

    fn database(sqlstate: Option<String>) -> Self {
        Self { kind: "database", sqlstate, remote_op: None, remote_status: None }
    }

    /// Finite remote-store classification: a fixed operation label and, when
    /// a response completed, its bounded numeric status. No URL, key, header,
    /// query or transport text is copied.
    fn remote(error: &RemoteStoreError) -> Self {
        Self {
            kind: "remote_store",
            sqlstate: None,
            remote_op: Some(error.op().as_str()),
            remote_status: error.http_status(),
        }
    }

    fn http(error: &reqwest::Error) -> Self {
        Self {
            kind: if error.is_timeout() { "timeout" } else { "http" },
            sqlstate: None,
            remote_op: None,
            remote_status: error.status().map(|status| status.as_u16()),
        }
    }
}

fn valid_sqlstate(code: &str) -> bool {
    code.len() == 5 && code.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

fn pg_classification(error: &tokio_postgres::Error) -> Classification {
    match error.code() {
        Some(code) if valid_sqlstate(code.code()) => Classification::database(Some(code.code().to_owned())),
        _ => Classification::database(None),
    }
}

fn pool_classification(error: &deadpool_postgres::PoolError) -> Classification {
    if let deadpool_postgres::PoolError::Backend(pg) = error {
        return pg_classification(pg);
    }
    Classification::kind("database_pool")
}

fn anyhow_classification(error: &anyhow::Error) -> Classification {
    for cause in error.chain() {
        if let Some(remote) = cause.downcast_ref::<RemoteStoreError>() {
            return Classification::remote(remote);
        }
        if let Some(pg) = cause.downcast_ref::<tokio_postgres::Error>() {
            return pg_classification(pg);
        }
        if cause.downcast_ref::<std::io::Error>().is_some() {
            return Classification::kind("io");
        }
        if let Some(http) = cause.downcast_ref::<reqwest::Error>() {
            return Classification::http(http);
        }
        if let Some(pool) = cause.downcast_ref::<deadpool_postgres::PoolError>() {
            return pool_classification(pool);
        }
        if cause.downcast_ref::<tokio::time::error::Elapsed>().is_some() {
            return Classification::kind("timeout");
        }
        if cause.downcast_ref::<tokio::task::JoinError>().is_some() {
            return Classification::kind("join");
        }
    }
    Classification::kind("internal")
}

/// Finite type-based classification only. No type name or error text is used.
fn classify(error: &dyn Any) -> Classification {
    if let Some(remote) = error.downcast_ref::<RemoteStoreError>() {
        return Classification::remote(remote);
    }
    if let Some(pg) = error.downcast_ref::<tokio_postgres::Error>() {
        return pg_classification(pg);
    }
    if let Some(error) = error.downcast_ref::<anyhow::Error>() {
        return anyhow_classification(error);
    }
    if error.downcast_ref::<std::io::Error>().is_some() {
        return Classification::kind("io");
    }
    if let Some(error) = error.downcast_ref::<reqwest::Error>() {
        return Classification::http(error);
    }
    if let Some(pool) = error.downcast_ref::<deadpool_postgres::PoolError>() {
        return pool_classification(pool);
    }
    if error.downcast_ref::<tokio::time::error::Elapsed>().is_some() {
        return Classification::kind("timeout");
    }
    if error.downcast_ref::<tokio::task::JoinError>().is_some() {
        return Classification::kind("join");
    }
    if error.downcast_ref::<&'static str>().is_some() || error.downcast_ref::<String>().is_some() {
        return Classification::kind("internal");
    }
    // Unrecognized concrete types always receive the same fixed label.
    Classification::kind("unknown")
}

fn scope_snapshot() -> Option<(Uuid, Option<String>)> {
    REQUEST_SCOPE.try_with(|scope| (scope.request_id, scope.route.clone())).ok()
}

fn event_json(error: &dyn Any) -> String {
    let classification = classify(error);
    let scope = scope_snapshot();
    let mut event = serde_json::Map::new();
    event.insert("event".to_owned(), json!("rootyard_error"));
    event.insert("event_id".to_owned(), json!(Uuid::new_v4().to_string()));
    event.insert("kind".to_owned(), json!(classification.kind));
    event.insert("status".to_owned(), json!(503));
    if let Some((request_id, route)) = scope {
        event.insert("scope".to_owned(), json!("request"));
        event.insert("request_id".to_owned(), json!(request_id.to_string()));
        if let Some(route) = route {
            event.insert("route".to_owned(), json!(route));
        }
    } else {
        // Detached work (for example a `tokio::spawn`ed handler future) does not
        // inherit task-local request scope; it gets a fresh event UUID and no route.
        event.insert("scope".to_owned(), json!("detached"));
    }
    if let Some(sqlstate) = classification.sqlstate {
        event.insert("sqlstate".to_owned(), json!(sqlstate));
    }
    if let Some(remote_op) = classification.remote_op {
        event.insert("remote_op".to_owned(), json!(remote_op));
    }
    if let Some(remote_status) = classification.remote_status {
        event.insert("remote_status".to_owned(), json!(remote_status));
    }
    serde_json::to_string(&Value::Object(event))
        .unwrap_or_else(|_| r#"{"event":"rootyard_error","scope":"detached","kind":"unknown","status":503}"#.to_owned())
}

fn allow_event() -> bool {
    let limiter = LOG_LIMITER.get_or_init(|| Mutex::new(LogLimiter { start: Instant::now(), count: 0 }));
    let mut limiter = limiter.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    limiter.allow(Instant::now())
}

pub(crate) fn observe_internal(error: &dyn Any) {
    if !allow_event() {
        return;
    }
    // The request path never awaits and never touches stderr: a full queue, a
    // closed queue or disabled output drops the record and counts it.
    let delivered = match log_sender() {
        Some(sender) => offer_to(sender, event_json(error)),
        None => false,
    };
    if !delivered {
        record_dropped();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::remote_objects::RemoteOp;
    use std::sync::atomic::AtomicBool;

    const SENTINEL: &str = "SECRET-sqlstate-23503-token-https://user:pass@example.invalid/?q=leak";
    static FORMATTED: AtomicBool = AtomicBool::new(false);

    struct Hostile;
    impl std::fmt::Display for Hostile {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            FORMATTED.store(true, Ordering::SeqCst);
            formatter.write_str(SENTINEL)
        }
    }
    impl std::fmt::Debug for Hostile {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            FORMATTED.store(true, Ordering::SeqCst);
            formatter.write_str(SENTINEL)
        }
    }

    #[test]
    fn hostile_display_and_debug_are_never_formatted() {
        FORMATTED.store(false, Ordering::SeqCst);
        let text = event_json(&Hostile as &dyn Any);
        assert!(!FORMATTED.load(Ordering::SeqCst), "classifier formatted the hostile value");
        assert!(!text.contains("SECRET"));
        assert!(!text.contains("23503"));
        assert!(!text.contains("example.invalid"));
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["kind"].as_str(), Some("unknown"));
        assert_eq!(value["scope"].as_str(), Some("detached"));
        assert!(value.get("route").is_none());
        assert!(value.get("request_id").is_none());
        assert!(value.get("sqlstate").is_none());
        assert!(value["event_id"].as_str().is_some_and(|id| Uuid::parse_str(id).is_ok()));
    }

    #[test]
    fn typed_io_and_anyhow_chain_keep_finite_kinds_without_text() {
        let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, SENTINEL);
        let text = event_json(&io as &dyn Any);
        assert!(!text.contains("SECRET"));
        assert_eq!(serde_json::from_str::<Value>(&text).unwrap()["kind"].as_str(), Some("io"));
        let chained = anyhow::Error::new(std::io::Error::other(SENTINEL)).context(SENTINEL);
        let text = event_json(&chained as &dyn Any);
        assert!(!text.contains("SECRET"));
        assert_eq!(serde_json::from_str::<Value>(&text).unwrap()["kind"].as_str(), Some("io"));
    }

    #[test]
    fn sqlstate_must_be_exactly_five_ascii_units() {
        assert!(valid_sqlstate("23503"));
        for invalid in ["", "2350", "235030", "2350\n", "2350é", "23-03"] {
            assert!(!valid_sqlstate(invalid), "accepted invalid SQLSTATE {invalid:?}");
        }
    }

    #[test]
    fn concurrent_error_storm_has_one_bounded_monotonic_window() {
        let now = Instant::now();
        let limiter = Mutex::new(LogLimiter { start: now, count: 0 });
        let accepted = std::sync::atomic::AtomicU64::new(0);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for _ in 0..100 {
                        if limiter.lock().unwrap().allow(now) {
                            accepted.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
            }
        });
        assert_eq!(accepted.load(Ordering::Relaxed), LOG_LIMIT_PER_SECOND);
        let mut limiter = limiter.into_inner().unwrap();
        assert!(!limiter.allow(now + Duration::from_millis(999)));
        assert!(limiter.allow(now + Duration::from_secs(1)));
        assert_eq!(limiter.count, 1);
    }

    #[tokio::test]
    async fn request_scope_supplies_middleware_id_and_matched_route() {
        let request_id = Uuid::new_v4();
        let scope = RequestScope { request_id, route: Some("/api/repos/{owner}/{name}".to_owned()) };
        let text = REQUEST_SCOPE.scope(scope, async { event_json(&std::io::Error::other(SENTINEL) as &dyn Any) }).await;
        assert!(!text.contains("SECRET"));
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["scope"].as_str(), Some("request"));
        let expected = request_id.to_string();
        assert_eq!(value["request_id"].as_str(), Some(expected.as_str()));
        assert_eq!(value["route"].as_str(), Some("/api/repos/{owner}/{name}"));
    }

    #[test]
    fn bounded_writer_queue_discards_immediately_when_full_or_closed() {
        assert_eq!(LOG_QUEUE_CAPACITY, 128);
        let (sender, receiver) = mpsc::sync_channel::<String>(LOG_QUEUE_CAPACITY);
        for index in 0..LOG_QUEUE_CAPACITY {
            assert!(offer_to(&sender, format!("record-{index}")));
        }
        let started = Instant::now();
        assert!(!offer_to(&sender, "overflow".to_owned()), "full queue must discard the record");
        assert!(started.elapsed() < Duration::from_secs(1), "full queue blocked the request path");
        assert_eq!(receiver.try_recv().unwrap(), "record-0");
        drop(sender);
        let (sender, receiver) = mpsc::sync_channel::<String>(LOG_QUEUE_CAPACITY);
        drop(receiver);
        assert!(!offer_to(&sender, "closed".to_owned()), "closed queue must discard the record");
    }

    struct FailingSink;
    impl std::io::Write for FailingSink {
        fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, SENTINEL))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, SENTINEL))
        }
    }

    #[test]
    fn failing_stderr_sink_is_reported_and_never_panics() {
        let dropped = AtomicU64::new(0);
        deliver_record(&mut FailingSink, "record", &dropped);
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
        let mut buffer = Vec::new();
        deliver_record(&mut buffer, "record", &dropped);
        assert_eq!(buffer, b"record\n".to_vec());
        assert_eq!(dropped.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn dropped_counter_saturates_at_u64_max() {
        let counter = AtomicU64::new(u64::MAX - 1);
        saturating_increment(&counter);
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
        saturating_increment(&counter);
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }

    #[test]
    fn typed_remote_status_is_classified_without_error_text() {
        let remote = RemoteStoreError::http(RemoteOp::Get, 502);
        let text = event_json(&remote as &dyn Any);
        assert!(!text.contains("SECRET"));
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["kind"].as_str(), Some("remote_store"));
        assert_eq!(value["remote_op"].as_str(), Some("get"));
        assert_eq!(value["remote_status"].as_u64(), Some(502));
        assert!(value.get("sqlstate").is_none());
    }

    #[test]
    fn remote_chain_keeps_typed_status_and_never_formats_context() {
        let chained = anyhow::Error::new(RemoteStoreError::http(RemoteOp::Put, 503)).context(SENTINEL);
        let text = event_json(&chained as &dyn Any);
        assert!(!text.contains("SECRET"));
        assert!(!text.contains("https://"));
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["kind"].as_str(), Some("remote_store"));
        assert_eq!(value["remote_op"].as_str(), Some("put"));
        assert_eq!(value["remote_status"].as_u64(), Some(503));
    }

    #[test]
    fn reqwest_transport_chain_stays_remote_and_never_formats_display() {
        let client = reqwest::Client::new();
        let transport = client.request(reqwest::Method::GET, "http://[").build().unwrap_err();
        let chained =
            anyhow::Error::new(RemoteStoreError::transport(RemoteOp::Head, Box::new(transport))).context(SENTINEL);
        let text = event_json(&chained as &dyn Any);
        assert!(!text.contains("SECRET"));
        assert!(!text.contains("http://"));
        assert!(!text.contains("://"));
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["kind"].as_str(), Some("remote_store"));
        assert_eq!(value["remote_op"].as_str(), Some("head"));
        assert!(value.get("remote_status").is_none());
    }

    #[test]
    fn bare_reqwest_error_uses_fixed_http_kind_without_status_or_text() {
        let client = reqwest::Client::new();
        let error = client.request(reqwest::Method::GET, "http://[").build().unwrap_err();
        let text = event_json(&error as &dyn Any);
        assert!(!text.contains("://"));
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["kind"].as_str(), Some("http"));
        assert!(value.get("remote_op").is_none());
        assert!(value.get("remote_status").is_none());
    }
}
