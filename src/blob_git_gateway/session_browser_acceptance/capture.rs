//! Same-origin capture adapter in front of the child.
//!
//! Every request the page issues to its own origin reaches this adapter, which
//! records the redacted facts the Rust attestation needs and then forwards the
//! request to the real child: method, path and query, a bounded body and the
//! end-to-end request headers are copied; the real upstream status and the
//! safe end-to-end response headers (`Content-Type`, CSP, `Set-Cookie`,
//! `Location`, security and session headers) are passed back unchanged.
//!
//! The adapter is a different loopback port from the child, so the browser's
//! `Origin` names the adapter while the child's `Host` names the child. The
//! child's own same-origin checks compare the two and would refuse every
//! mutation (the real sign-in form), so `Origin` is rewritten to the configured
//! upstream origin, exactly as a reverse proxy on the child's host would see
//! it. Only the connection-scoped (hop-by-hop) headers are dropped in either
//! direction; `Host` is the one request header not copied, because the HTTP
//! client derives it from the upstream target.
//!
//! Cookie values, bodies and query strings never enter a record: only presence
//! flags, integer statuses and the presence-only fixture markers below are
//! retained. The request token and the answered pair are separate fields: the
//! gateway receives only the token request header, while token and revision
//! are the answer's pair. Token strings live in a record only for in-memory
//! equality checks and never reach a message.
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex, PoisonError},
};

use anyhow::Result;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderName, HeaderValue, StatusCode, header},
    response::Response,
    routing::any,
};
use serde_json::Value;

use crate::blob_git_gateway::repo_session::{REVISION_HEADER, SESSION_HEADER};

use super::http_client;

/// Upper bound on one proxied request body (the page sends only reads and its
/// bounded form; a receive pack never travels through it).
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
/// The icon path a browser requests on its own; it is named so that request is
/// attested rather than mistaken for a repository read.
const FAVICON: &str = "/favicon.ico";

/// Every route the assertions name. Each request keeps the narrowest matching
/// route, so a misrouted read is caught on the route it was expected on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Route {
    WebBlob,
    WebLogin,
    WebAppJs,
    Favicon,
    /// Exactly `/web/blob/api/repos`: the index list, which is headerless.
    WebList,
    /// `/web/blob/api/repos/{owner}/{name}/{refs|tree|commits}`.
    WebRefs,
    WebTree,
    WebCommits,
    /// Another read below `/web/blob/api`.
    WebApiOther,
    ApiRepos,
    Git,
    Other,
}

impl Route {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::WebBlob => "web_blob",
            Self::WebLogin => "web_login",
            Self::WebAppJs => "web_app_js",
            Self::Favicon => "favicon",
            Self::WebList => "web_list",
            Self::WebRefs => "web_refs",
            Self::WebTree => "web_tree",
            Self::WebCommits => "web_commits",
            Self::WebApiOther => "web_api_other",
            Self::ApiRepos => "api_repos",
            Self::Git => "git",
            Self::Other => "other",
        }
    }
}

/// One page request, redacted to what the assertions need.
pub(super) struct Recorded {
    pub route: Route,
    pub status: u16,
    pub has_cookie: bool,
    pub has_authorization: bool,
    /// The session token the request presented, if any.
    pub request_token: Option<String>,
    /// A revision the request presented. The session contract never sends it;
    /// it is recorded so any presentation is caught.
    pub request_revision: Option<String>,
    /// The session token the answer carried.
    pub response_token: Option<String>,
    /// The revision the answer named.
    pub response_revision: Option<String>,
    /// The tree query when it is exactly `?oid=HEAD`.
    pub oid_head: bool,
    pub location: Option<String>,
    pub csp: Option<String>,
    /// The list answer named the fixture repository exactly once.
    pub list_names_repository: bool,
    /// The tree answer listed the pushed file's exact path.
    pub tree_names_file: bool,
    /// The commits answer listed the pushed OID.
    pub commits_names_oid: bool,
}

/// The configured fixture identity and upstream origin of one run. Values are
/// compared, never recorded or printed.
#[derive(Clone)]
pub(super) struct Fixture {
    pub owner: String,
    pub name: String,
    pub oid: String,
    pub file: String,
    /// The child's origin, `http://<child address>`.
    pub upstream: String,
}

impl Fixture {
    /// The prefix every named nested read of this repository starts with.
    fn alias_prefix(&self) -> String {
        format!("/web/blob/api/repos/{}/{}/", self.owner, self.name)
    }

    /// The exact path of one nested read of this repository.
    fn read_path(&self, tail: &str) -> String {
        format!("{}{tail}", self.alias_prefix())
    }
}

/// The captured records of one run.
#[derive(Clone, Default)]
pub(super) struct Capture(Arc<Mutex<Vec<Recorded>>>);

impl Capture {
    pub(super) fn snapshot(&self) -> Vec<Recorded> {
        std::mem::take(&mut *self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }

    fn push(&self, record: Recorded) {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).push(record);
    }
}

#[derive(Clone)]
struct Adapter {
    capture: Capture,
    fixture: Fixture,
}

/// Serve the adapter on a fresh loopback port in front of the fixture's
/// upstream origin.
pub(super) async fn serve_adapter(capture: Capture, fixture: Fixture) -> Result<SocketAddr> {
    let adapter = Arc::new(Adapter { capture, fixture });
    let app = Router::new().fallback(any(forward)).with_state(adapter);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(address)
}

/// Forward one request, then pass the child's answer back unchanged, its real
/// status included, so a browser observes exactly what the upstream answered.
async fn forward(State(adapter): State<Arc<Adapter>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let route = route_of(&adapter.fixture.alias_prefix(), parts.uri.path());
    if route == Route::Other {
        // A page request no route names is refused here and recorded as
        // `other`, never silently forwarded.
        adapter.capture.push(record(&adapter.fixture, &parts, route, 400, None));
        return failure(StatusCode::BAD_REQUEST, "unclassified page request");
    }
    match relay(&adapter, parts, body, route).await {
        Ok(response) => response,
        Err(_) => failure(StatusCode::BAD_GATEWAY, "upstream unavailable"),
    }
}

async fn relay(adapter: &Adapter, parts: axum::http::request::Parts, body: Body, route: Route) -> Result<Response, ()> {
    let body = to_bytes(body, MAX_BODY_BYTES).await.map_err(|_| ())?;
    let upstream_origin = adapter.fixture.upstream.as_str();
    let target = format!("{upstream_origin}{}", parts.uri.path_and_query().map_or("/", |target| target.as_str()));
    let client = http_client().map_err(|_| ())?;
    let mut outbound = client.request(parts.method.clone(), target).body(body.to_vec());
    let origins: Vec<&HeaderValue> = parts.headers.get_all(header::ORIGIN).iter().collect();
    for (name, value) in parts.headers.iter() {
        if !is_hop_by_hop(name) && name != header::HOST && name != header::ORIGIN {
            outbound = outbound.header(name, value);
        }
    }
    // Every browser-facing `Origin` names the adapter; the child compares it
    // with its own `Host`, so it must see the upstream origin instead.
    if !origins.is_empty() {
        outbound = outbound.header(header::ORIGIN, upstream_origin);
    }
    let upstream = outbound.send().await.map_err(|_| ())?;
    let status = upstream.status();
    let headers = upstream.headers().clone();
    let bytes = upstream.bytes().await.map_err(|_| ())?;
    let mut captured = record(&adapter.fixture, &parts, route, status.as_u16(), Some(&headers));
    marker(&adapter.fixture, &bytes, route, &mut captured);
    adapter.capture.push(captured);

    let mut answer = Response::new(Body::from(bytes));
    *answer.status_mut() = status;
    for (name, value) in headers.iter() {
        if !is_hop_by_hop(name)
            && let Ok(value) = HeaderValue::from_bytes(value.as_bytes())
        {
            answer.headers_mut().append(name.clone(), value);
        }
    }
    Ok(answer)
}

/// The redacted record of one request and, for a relayed one, its answer.
fn record(
    fixture: &Fixture,
    request: &axum::http::request::Parts,
    route: Route,
    status: u16,
    answer: Option<&axum::http::HeaderMap>,
) -> Recorded {
    let headers = &request.headers;
    Recorded {
        route,
        status,
        has_cookie: headers.contains_key(header::COOKIE),
        has_authorization: headers.contains_key(header::AUTHORIZATION),
        request_token: text(headers.get(SESSION_HEADER)),
        request_revision: text(headers.get(REVISION_HEADER)),
        response_token: answer.and_then(|answer| text(answer.get(SESSION_HEADER))),
        response_revision: answer.and_then(|answer| text(answer.get(REVISION_HEADER))),
        oid_head: route == Route::WebTree
            && request.uri.path() == fixture.read_path("tree")
            && tree_oid_is_head(request.uri.query()),
        location: answer.and_then(|answer| text(answer.get(header::LOCATION))),
        csp: answer.and_then(|answer| text(answer.get(header::CONTENT_SECURITY_POLICY))),
        list_names_repository: false,
        tree_names_file: false,
        commits_names_oid: false,
    }
}

/// A tree query names `HEAD` exactly when it is the single parameter
/// `oid=HEAD`.
fn tree_oid_is_head(query: Option<&str>) -> bool {
    query.is_some_and(|query| query.split('&').eq(["oid=HEAD"]))
}

/// Presence-only markers of one list/tree/commits JSON body. No body value is
/// retained; each field is a boolean naming the exact configured fixture.
///
/// The body is parsed once and its shape is chosen by route: the list is the
/// bare `RepositoryView` array, the tree and commits are objects whose `items`
/// arrays name a `path` and an `oid`. A body that does not have the route's
/// shape leaves every marker false.
fn marker(fixture: &Fixture, bytes: &[u8], route: Route, record: &mut Recorded) {
    if !matches!(route, Route::WebList | Route::WebTree | Route::WebCommits) {
        return;
    }
    let Ok(value) = serde_json::from_slice::<Value>(bytes) else {
        return;
    };
    match route {
        Route::WebList => {
            let Some(rows) = value.as_array() else {
                return;
            };
            let named = |row: &Value| {
                row["owner"].as_str() == Some(fixture.owner.as_str())
                    && row["name"].as_str() == Some(fixture.name.as_str())
            };
            record.list_names_repository = rows.iter().filter(|row| named(row)).count() == 1
                && rows.iter().filter(|row| row["name"].as_str() == Some(fixture.name.as_str())).count() == 1;
        }
        Route::WebTree | Route::WebCommits => {
            let Some(rows) = value["items"].as_array() else {
                return;
            };
            if route == Route::WebTree {
                record.tree_names_file = rows.iter().any(|entry| entry["path"].as_str() == Some(fixture.file.as_str()));
            } else {
                record.commits_names_oid = rows.iter().any(|entry| entry["oid"].as_str() == Some(fixture.oid.as_str()));
            }
        }
        _ => {}
    }
}

fn failure(status: StatusCode, reason: &'static str) -> Response {
    let mut answer = Response::new(Body::from(reason));
    *answer.status_mut() = status;
    answer
}

fn text(value: Option<&HeaderValue>) -> Option<String> {
    value.and_then(|value| value.to_str().ok()).map(str::to_owned)
}

/// Connection-scoped headers, never forwarded in either direction.
fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// The route of one request path, path-only (a query never changes a route).
///
/// The list alias is exact. Below `/web/blob/api/repos/`, the only named routes
/// are this fixture's own `/{owner}/{name}/{refs|tree|commits}`; any other
/// repository API read is `web_api_other`, never mistaken for the list.
pub(super) fn route_of(fixture_prefix: &str, path: &str) -> Route {
    for (exact, route) in
        [("/web/blob/api/repos", Route::WebList), ("/web/app.js", Route::WebAppJs), (FAVICON, Route::Favicon)]
    {
        if path == exact {
            return route;
        }
    }
    for (tail, route) in [("refs", Route::WebRefs), ("tree", Route::WebTree), ("commits", Route::WebCommits)] {
        if path == format!("{fixture_prefix}{tail}") {
            return route;
        }
    }
    for (prefix, route) in [
        ("/web/login", Route::WebLogin),
        ("/web/blob/api/", Route::WebApiOther),
        ("/api/repos", Route::ApiRepos),
        ("/git/", Route::Git),
    ] {
        let descendant = format!("{}/", prefix.trim_end_matches('/'));
        if path == prefix || path.starts_with(&descendant) {
            return route;
        }
    }
    if path.trim_end_matches('/') == "/web/blob" || path.starts_with("/web/blob/repos/") {
        Route::WebBlob
    } else {
        Route::Other
    }
}

#[cfg(test)]
mod tests {
    use super::{Fixture, Route, route_of, tree_oid_is_head};

    fn fixture() -> Fixture {
        Fixture {
            owner: "owner".into(),
            name: "repo".into(),
            oid: "0".repeat(40),
            file: "afile.txt".into(),
            upstream: "http://127.0.0.1:1".into(),
        }
    }

    #[test]
    fn the_list_is_exact_and_nested_reads_are_distinct() {
        let prefix = fixture().alias_prefix();
        assert_eq!(prefix, "/web/blob/api/repos/owner/repo/");
        assert_eq!(route_of(&prefix, "/web/blob/api/repos"), Route::WebList);
        assert_eq!(route_of(&prefix, "/web/blob/api/repos/"), Route::WebApiOther);
        assert_eq!(route_of(&prefix, "/web/blob/api/repos/owner/repo/refs"), Route::WebRefs);
        assert_eq!(route_of(&prefix, "/web/blob/api/repos/owner/repo/tree"), Route::WebTree);
        assert_eq!(route_of(&prefix, "/web/blob/api/repos/owner/repo/commits"), Route::WebCommits);
        // Another repository's reads are never the list.
        assert_eq!(route_of(&prefix, "/web/blob/api/repos/other/repo/refs"), Route::WebApiOther);
        assert_eq!(route_of(&prefix, "/web/blob/api/repos/owner/repo/blob"), Route::WebApiOther);
        assert_eq!(route_of(&prefix, "/web/blob/api/repos/owner/repo_extra/refs"), Route::WebApiOther);
        // The shipped SPA adds `?oid=HEAD` to the tree URL; the route is
        // path-only, so the query never changes it.
        assert_eq!(route_of(&prefix, "/web/blob/api/repos/owner/repo/tree"), Route::WebTree);
        assert!(tree_oid_is_head(Some("oid=HEAD")));
        assert!(!tree_oid_is_head(Some("oid=HEAD&path=a")));
        assert!(!tree_oid_is_head(Some("oid=HEAD&oid=HEAD")));
        assert!(!tree_oid_is_head(None));
        assert_eq!(fixture().read_path("tree"), "/web/blob/api/repos/owner/repo/tree");
        for (path, route) in [
            ("/web/blob", Route::WebBlob),
            ("/web/blob/repos/owner/repo", Route::WebBlob),
            ("/web/login", Route::WebLogin),
            ("/web/app.js", Route::WebAppJs),
            ("/favicon.ico", Route::Favicon),
            ("/api/repos", Route::ApiRepos),
            ("/api/repos/owner/repo/refs", Route::ApiRepos),
            ("/git/owner/repo.git/info/refs", Route::Git),
            ("/", Route::Other),
        ] {
            assert_eq!(route_of(&prefix, path), route, "{path}");
        }
    }
}
