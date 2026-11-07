//! Central, privacy-preserving internal-error classification and request correlation.
//!
//! Only fixed classifications, a validated SQLSTATE, a server-generated UUID and
//! the router's matched path pattern are emitted. Error Display/Debug text, URLs,
//! headers, query strings, user content and source strings are never formatted.
use axum::{
    extract::{MatchedPath, Request},
    http::{HeaderName, HeaderValue},
    middleware::Next,
    response::Response,
};
use serde_json::{Value, json};
use std::any::Any;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::task_local;
use uuid::Uuid;

/// Bounded fixed-class rate limit for error events: one fixed global window.
const LOG_LIMIT_PER_SECOND: u64 = 100;
static LOG_WINDOW: AtomicU64 = AtomicU64::new(0);
static LOG_COUNT: AtomicU64 = AtomicU64::new(0);

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
}
impl Classification {
    fn kind(kind: &'static str) -> Self {
        Self { kind, sqlstate: None }
    }
}

fn valid_sqlstate(code: &str) -> bool {
    code.len() == 5 && code.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

fn pg_classification(error: &tokio_postgres::Error) -> Classification {
    match error.code() {
        Some(code) if valid_sqlstate(code.code()) => {
            Classification { kind: "database", sqlstate: Some(code.code().to_owned()) }
        }
        _ => Classification::kind("database"),
    }
}

fn anyhow_classification(error: &anyhow::Error) -> Classification {
    for cause in error.chain() {
        if let Some(pg) = cause.downcast_ref::<tokio_postgres::Error>() {
            return pg_classification(pg);
        }
        if cause.downcast_ref::<std::io::Error>().is_some() {
            return Classification::kind("io");
        }
        if let Some(http) = cause.downcast_ref::<reqwest::Error>() {
            return Classification::kind(if http.is_timeout() { "timeout" } else { "http" });
        }
        if cause.downcast_ref::<deadpool_postgres::PoolError>().is_some() {
            return Classification::kind("database_pool");
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
        return Classification::kind(if error.is_timeout() { "timeout" } else { "http" });
    }
    if error.downcast_ref::<deadpool_postgres::PoolError>().is_some() {
        return Classification::kind("database_pool");
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
    serde_json::to_string(&Value::Object(event))
        .unwrap_or_else(|_| r#"{"event":"rootyard_error","scope":"detached","kind":"unknown","status":503}"#.to_owned())
}

fn allow_event() -> bool {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|elapsed| elapsed.as_secs()).unwrap_or(0);
    let window = LOG_WINDOW.load(Ordering::Relaxed);
    // A backwards clock never advances the window, so the fixed cap still applies.
    if now > window && LOG_WINDOW.compare_exchange(window, now, Ordering::Relaxed, Ordering::Relaxed).is_ok() {
        LOG_COUNT.store(0, Ordering::Relaxed);
    }
    LOG_COUNT.fetch_add(1, Ordering::Relaxed) < LOG_LIMIT_PER_SECOND
}

pub(crate) fn observe_internal(error: &dyn Any) {
    if !allow_event() {
        return;
    }
    eprintln!("{}", event_json(error));
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
