//! Loopback HTTP observation helpers for the `#174` acceptance cases.
//!
//! Every answer is parsed exactly as a network client sees it; session headers
//! are inspected only in memory and never printed.
use std::sync::{Arc, Mutex, PoisonError};

use anyhow::{Context, Result, anyhow, ensure};
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderMap, Method, Request},
    middleware::{self, Next},
    response::Response,
};
use serde_json::Value;

/// Request header carrying the session token.
pub(crate) const SESSION_HEADER: &str = "x-rootyard-session";
/// Response header naming the exact gate revision served.
pub(crate) const REVISION_HEADER: &str = "x-rootyard-session-revision";
/// A syntactically invalid session header value: never a framed token.
pub(crate) const MALFORMED_SESSION: &str = "not-a-session-token";

/// The session headers exactly as one response carried them, before admission.
pub(crate) struct RawSession {
    pub(crate) token: Option<String>,
    pub(crate) revision: Option<String>,
}

impl RawSession {
    pub(crate) fn from_headers(headers: &HeaderMap) -> Self {
        Self { token: header_text(headers, SESSION_HEADER), revision: header_text(headers, REVISION_HEADER) }
    }

    /// The first bound: nonempty token, positive revision.
    pub(crate) fn admit(self) -> Result<Bound> {
        let token = nonempty(self.token.as_deref(), "push response carried no session token")?.to_owned();
        let revision = parse_revision(self.revision.as_deref())?;
        Ok(Bound { token, revision })
    }

    /// Admit this response's headers against the bound the read presented:
    /// nonempty token, positive revision, never behind it.
    pub(crate) fn admit_at_least(self, previous: &Bound) -> Result<Bound> {
        let token = nonempty(self.token.as_deref(), "a read response carried no session token")?.to_owned();
        let revision = parse_revision(self.revision.as_deref())?;
        ensure!(revision >= previous.revision, "a read response revision regressed below its presented bound");
        Ok(Bound { token, revision })
    }
}

/// One admitted session lower bound, presented to the next read.
pub(crate) struct Bound {
    pub token: String,
    pub revision: i64,
}

fn header_text(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get(name).map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
}

fn parse_revision(value: Option<&str>) -> Result<i64> {
    let revision = nonempty(value, "a response carried no session revision")?
        .parse::<i64>()
        .map_err(|_| anyhow!("a response carried an unparseable session revision"))?;
    ensure!(revision > 0, "a response carried a non-positive session revision");
    Ok(revision)
}

fn nonempty<'a>(value: Option<&'a str>, message: &'static str) -> Result<&'a str> {
    let value = value.ok_or_else(|| anyhow!(message))?;
    ensure!(!value.is_empty(), "{message}");
    Ok(value)
}

pub(crate) fn contains(body: &str, needle: &str) -> bool {
    body.contains(needle)
}

pub(crate) fn json_string(value: &str) -> String {
    Value::String(value.to_owned()).to_string()
}

pub(crate) fn status_succeeds(status: u16) -> bool {
    (200..300).contains(&status)
}

pub(crate) fn is_denial(status: u16) -> bool {
    matches!(status, 401 | 403 | 404)
}

/// A body of a successful refs answer names refs; a refusal body must not.
pub(crate) fn looks_like_refs(body: &str) -> bool {
    body.contains("refs/") || body.contains("\"refs\"")
}

pub(crate) fn ensure_no_disclosure(body: &str, needles: &[&str], what: &str) -> Result<()> {
    for needle in needles {
        ensure!(!needle.is_empty() && !contains(body, needle), "{what} disclosed a repository or actor detail");
    }
    Ok(())
}

pub(crate) struct JsonAnswer {
    pub body: String,
    pub session: RawSession,
}

/// One real GET's raw answer: status code, complete body and the session
/// headers it carried, whether or not it succeeded.
pub(crate) struct RawAnswer {
    pub status: u16,
    pub body: String,
    pub session: RawSession,
}

/// One real GET over TCP with the bearer token of `bearer`, presenting
/// `session` as the session header when given (even a malformed value).
pub(crate) async fn raw_get(
    client: &reqwest::Client,
    url: &str,
    bearer: &str,
    session: Option<&str>,
) -> Result<RawAnswer> {
    // The bearer and the session header are sent as header values only, never
    // in the URL, and are never printed here.
    let mut request = client.get(url).bearer_auth(bearer);
    if let Some(session) = session {
        request = request.header(SESSION_HEADER, session);
    }
    let response = request.send().await.context("real gateway TCP request failed")?;
    let status = response.status().as_u16();
    let session = RawSession::from_headers(response.headers());
    let bytes = response.bytes().await.context("real gateway response body failed")?;
    Ok(RawAnswer { status, body: String::from_utf8_lossy(&bytes).into_owned(), session })
}

/// One successful real JSON read with the bearer token, presenting `session`
/// when given, returning the complete body with the session headers.
pub(crate) async fn json_read(
    client: &reqwest::Client,
    url: &str,
    bearer: &str,
    session: Option<&str>,
) -> Result<JsonAnswer> {
    let RawAnswer { status, body, session } = raw_get(client, url, bearer, session).await?;
    ensure!(status_succeeds(status), "gateway read returned {status}");
    ensure!(!body.is_empty(), "gateway read returned an empty body");
    Ok(JsonAnswer { body, session })
}

/// The push response's session headers, captured in memory only.
#[derive(Default)]
pub(crate) struct PushSession {
    token: Option<String>,
    revision: Option<String>,
}

impl Drop for PushSession {
    fn drop(&mut self) {
        // Best effort: clear the buffered bearer-equivalent value, never print it.
        if let Some(token) = self.token.as_mut() {
            token.clear();
        }
    }
}

/// Test-only middleware: capture only the push response's session headers into
/// memory. Nothing is logged and no other request is recorded.
pub(crate) fn observe_push_session(router: Router, push: Arc<Mutex<PushSession>>) -> Router {
    router.layer(middleware::from_fn_with_state(push, capture_push_session))
}

async fn capture_push_session(
    State(push): State<Arc<Mutex<PushSession>>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let is_push = request.method() == Method::POST
        && request.uri().path().starts_with("/git/")
        && request.uri().path().ends_with("/git-receive-pack");
    let response = next.run(request).await;
    if is_push {
        let captured = RawSession::from_headers(response.headers());
        let mut slot = push.lock().unwrap_or_else(PoisonError::into_inner);
        *slot = PushSession::default();
        slot.token = captured.token;
        slot.revision = captured.revision;
    }
    response
}

/// Abort-on-drop guard for the real `axum::serve` task.
pub(crate) struct ServerGuard {
    task: tokio::task::JoinHandle<Result<(), std::io::Error>>,
}

impl ServerGuard {
    pub(crate) fn start(listener: tokio::net::TcpListener, app: Router) -> Self {
        Self { task: tokio::spawn(async move { axum::serve(listener, app).await }) }
    }
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl PushSession {
    pub(crate) fn snapshot(&self) -> RawSession {
        RawSession { token: self.token.clone(), revision: self.revision.clone() }
    }
}
