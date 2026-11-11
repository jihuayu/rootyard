//! Same-origin capture adapter in front of the child.
//!
//! Every request the page issues to its own origin reaches this adapter, which
//! records the redacted facts the Rust attestation needs and then forwards the
//! request to the real child: method, path and query, a bounded body and the
//! end-to-end request headers are copied; the child's real status, body and
//! every end-to-end response header (`WWW-Authenticate` included, every value
//! of it) are passed back unchanged, so Chromium observes exactly the child's
//! own answer and any challenge behaviour is the child's, never rewritten here.
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
//! Cookie values, bodies, query strings, header values and the paths that are
//! not fixed are never retained as text: only presence flags, integer statuses,
//! fixed classifications (the route, a challenge scheme, a path shape) and the
//! presence-only fixture markers below are. A denial record names the fixed
//! shape of its request path ([`DenialPath`]), never the path itself.
//!
//! A [`Recorded`] entry exists only for a request the child answered, with
//! exactly the status it answered. A request the adapter cannot classify or
//! relay (an unreadable body, a client build error, no connection, an
//! interrupted body) is answered locally and captures nothing: the local answer
//! is never recorded as an upstream response, so the attestation can never read
//! an adapter-made status as the child's (in particular, no `401` is
//! synthesized here), and a forwarding failure for a denial read leaves a
//! visible non-denial record ([`Recorded::forwarding_failure`]) instead. The
//! request token and the answered pair are separate fields: the gateway receives
//! only the token request header, while token and revision are the answer's
//! pair. Token strings live in a record only for in-memory equality checks and
//! never reach a message.
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
use bytes::Bytes;
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

/// A named denial read a page request may be: the fixed shape of its path and
/// query, never the path itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum DenialPath {
    /// `GET /api/repos`.
    ApiRepos,
    /// `GET /git/{owner}/{name}.git/info/refs?service=git-upload-pack`.
    GitInfoRefs,
}

impl DenialPath {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::ApiRepos => "api_repos",
            Self::GitInfoRefs => "git_info_refs",
        }
    }

    /// The denial shape of one exact page request, judged by method, path and
    /// query together. Every other request on the same route is `None`.
    fn of(fixture: &Fixture, method: &str, path: &str, query: Option<&str>) -> Option<Self> {
        if method != "GET" {
            return None;
        }
        if path == "/api/repos" {
            return match query {
                None | Some("") => Some(Self::ApiRepos),
                Some(_) => None,
            };
        }
        let git = fixture.git_info_refs();
        if path == git {
            return match query {
                Some(query) if fixture.requests_git_info_refs(query) => Some(Self::GitInfoRefs),
                _ => None,
            };
        }
        None
    }
}

/// The challenge scheme of the first `WWW-Authenticate` value, reduced to a
/// fixed word. Every further value is recorded only as present, never parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Challenge {
    None,
    Basic,
    Bearer,
    Other,
}

impl Challenge {
    fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Basic => "basic",
            Self::Bearer => "bearer",
            Self::Other => "other",
        }
    }

    /// The scheme word of the first challenge value. Only the scheme is read;
    /// parameters, realm and any later value are never recorded.
    fn of(answer: Option<&axum::http::HeaderMap>) -> Self {
        let Some(value) = answer.and_then(|answer| answer.get(header::WWW_AUTHENTICATE)) else {
            return Self::None;
        };
        let scheme = value.to_str().map(str::trim_start).unwrap_or("").split([' ', ',']).next().unwrap_or("");
        if scheme.eq_ignore_ascii_case("basic") {
            Self::Basic
        } else if scheme.eq_ignore_ascii_case("bearer") {
            Self::Bearer
        } else {
            Self::Other
        }
    }
}

/// One page request, redacted to what the assertions need.
pub(super) struct Recorded {
    pub route: Route,
    pub status: u16,
    pub has_cookie: bool,
    pub has_authorization: bool,
    /// A fixed scheme word of the answer's first `WWW-Authenticate` value.
    pub challenge: &'static str,
    /// The exact denial read this request was, if any.
    pub denial_path: Option<DenialPath>,
    /// The request the adapter could not relay. Its `route` stays the route the
    /// path names, so the attestation sees the missing denial answer, but it
    /// carries no answer facts and is never an upstream response.
    pub forwarding_failure: bool,
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
    /// The tree answer listed both pushes, each at its exact configured path.
    pub tree_names_files: bool,
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
    /// The second pushed file the HEAD tree must also name.
    pub second_file: String,
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

    /// The exact Smart HTTP `info/refs` path of this repository. The handler's
    /// `repository_name` requires the `.git` suffix, so it is part of the path.
    fn git_info_refs(&self) -> String {
        format!("/git/{}/{}.git/info/refs", self.owner, self.name)
    }

    /// Whether one `info/refs` query is exactly `service=git-upload-pack`.
    fn requests_git_info_refs(&self, query: &str) -> bool {
        query == "service=git-upload-pack"
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
/// status, body and every end-to-end header included, so a browser observes
/// exactly what the upstream answered.
async fn forward(State(adapter): State<Arc<Adapter>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let route = route_of(&adapter.fixture.alias_prefix(), parts.uri.path());
    if route == Route::Other {
        // A page request no route names is refused here and recorded as
        // `other`, never silently forwarded.
        let mut captured = record(&adapter.fixture, &parts, route, 400, None);
        captured.forwarding_failure = true;
        adapter.capture.push(captured);
        return failure(StatusCode::BAD_REQUEST, "unclassified page request");
    }
    match relay(&adapter, &parts, body).await {
        Ok(Ok((status, headers, bytes))) => {
            let mut captured = record(&adapter.fixture, &parts, route, status.as_u16(), Some(&headers));
            marker(&adapter.fixture, &bytes, route, &mut captured);
            adapter.capture.push(captured);
            answered(status, &headers, bytes)
        }
        Ok(Err(())) => {
            // The child answered but its body could not be read whole: no
            // status, header or body of that answer reaches the browser, so
            // nothing of it may be recorded as an upstream answer either.
            failed(&adapter, &parts, route)
        }
        // No answer was captured for this request: a `401` is only ever the
        // child's own answer, never one built here.
        Err(()) => failed(&adapter, &parts, route),
    }
}

/// One request the adapter could not relay end to end. A denial read keeps a
/// visible non-denial record, so a forwarding failure can never satisfy or
/// silently replace the denial assertion; every other request records nothing.
fn failed(adapter: &Adapter, parts: &axum::http::request::Parts, route: Route) -> Response {
    if let Some(denial) = denial_of(&adapter.fixture, parts) {
        let mut captured = record(&adapter.fixture, parts, route, StatusCode::BAD_GATEWAY.as_u16(), None);
        captured.denial_path = Some(denial);
        captured.forwarding_failure = true;
        adapter.capture.push(captured);
    }
    failure(StatusCode::BAD_GATEWAY, "upstream unavailable")
}

/// The denial shape of one page request, or `None` for every other request.
fn denial_of(fixture: &Fixture, parts: &axum::http::request::Parts) -> Option<DenialPath> {
    DenialPath::of(fixture, parts.method.as_str(), parts.uri.path(), parts.uri.query())
}

/// Forward one request and return the child's own answer parts. The outer
/// error is a local failure before any request was sent; the inner one is a
/// sent request whose answer body could not be read whole.
async fn relay(
    adapter: &Adapter,
    parts: &axum::http::request::Parts,
    body: Body,
) -> Result<Result<(StatusCode, axum::http::HeaderMap, Bytes), ()>, ()> {
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
    Ok(Ok((status, headers, bytes)))
}

/// The child's answer exactly as it came: its status, its body and every
/// end-to-end header in its own order, a repeated `WWW-Authenticate` included.
/// Only connection-scoped headers are dropped; nothing is added, replaced or
/// omitted, and no header is rewritten here.
fn answered(status: StatusCode, headers: &axum::http::HeaderMap, bytes: Bytes) -> Response {
    let mut answer = Response::new(Body::from(bytes));
    *answer.status_mut() = status;
    for (name, value) in headers.iter() {
        if !is_hop_by_hop(name) {
            answer.headers_mut().append(name.clone(), value.clone());
        }
    }
    answer
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
        challenge: Challenge::of(answer).name(),
        denial_path: denial_of(fixture, request),
        forwarding_failure: false,
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
        tree_names_files: false,
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
                // Both real pushes must be named at their exact paths: one
                // entry each, never one entry standing in for both.
                let named = |file: &str| rows.iter().any(|entry| entry["path"].as_str() == Some(file));
                record.tree_names_files = named(&fixture.file) && named(&fixture.second_file);
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
    use axum::http::{HeaderMap, HeaderValue, header};

    use super::{Challenge, DenialPath, Fixture, Route, denial_of, marker, record, route_of, tree_oid_is_head};

    fn fixture() -> Fixture {
        Fixture {
            owner: "owner".into(),
            name: "repo".into(),
            oid: "0".repeat(40),
            file: "afile.txt".into(),
            second_file: "other file.txt".into(),
            upstream: "http://127.0.0.1:1".into(),
        }
    }

    fn request(method: &str, uri: &str) -> axum::http::request::Parts {
        axum::http::Request::builder().method(method).uri(uri).body(()).unwrap().into_parts().0
    }

    fn answer(challenges: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for challenge in challenges {
            headers.append(header::WWW_AUTHENTICATE, HeaderValue::from_str(challenge).unwrap());
        }
        headers
    }

    #[test]
    fn the_tree_names_both_pushed_files_at_their_exact_paths() {
        let fixture = fixture();
        let first = fixture.file.clone();
        let second = fixture.second_file.clone();
        // The exact production tree URL the shipped SPA issues, query included.
        let tree = format!("{}?oid=HEAD", fixture.read_path("tree"));
        // The real `marker()` over a tree answer naming both pushes.
        let mark = |entries: &[(&str, &str)]| {
            let items: Vec<serde_json::Value> =
                entries.iter().map(|(name, path)| serde_json::json!({"name": name, "path": path})).collect();
            let body = serde_json::to_vec(&serde_json::json!({"items": items})).unwrap();
            let mut recorded = record(&fixture, &request("GET", &tree), Route::WebTree, 200, None);
            marker(&fixture, &body, Route::WebTree, &mut recorded);
            recorded
        };
        let both = mark(&[(&first, &first), (&second, &second)]);
        assert!(both.tree_names_files, "a tree naming both pushes at their exact paths");
        assert!(both.oid_head, "the test tree request is the shipped `?oid=HEAD` read");
        // The second push missing leaves the marker false, as does a near miss.
        assert!(!mark(&[(&first, &first)]).tree_names_files, "the second push was never named");
        let near = format!("prefix/{second}");
        assert!(!mark(&[(&first, &first), (&second, &near)]).tree_names_files, "the second path was not exact");
        assert!(!mark(&[(&first, &first), (&second, &first)]).tree_names_files, "one path cannot name two pushes");
    }

    #[test]
    fn only_the_two_exact_denial_reads_classify() {
        let fixture = fixture();
        assert_eq!(
            denial_of(&fixture, &request("GET", "/api/repos")),
            Some(DenialPath::ApiRepos),
            "the exact cookie-only API read is the API denial"
        );
        let git = "/git/owner/repo.git/info/refs?service=git-upload-pack";
        assert_eq!(denial_of(&fixture, &request("GET", git)), Some(DenialPath::GitInfoRefs));
        // Another route, repository, method, query or VCS service is no denial.
        for uri in [
            "/api/repos/owner/repo",
            "/api/repos?page=2",
            "/web/blob/api/repos",
            "/git/other/repo.git/info/refs?service=git-upload-pack",
            "/git/owner/repo/info/refs?service=git-upload-pack",
            "/git/owner/repo.git/info/refs?service=git-receive-pack",
            "/git/owner/repo.git/info/refs",
        ] {
            assert_eq!(denial_of(&fixture, &request("GET", uri)), None, "{uri}");
        }
        assert_eq!(denial_of(&fixture, &request("POST", "/api/repos")), None);
        assert_eq!(denial_of(&fixture, &request("HEAD", git)), None);
    }

    #[test]
    fn the_challenge_is_one_fixed_scheme_word() {
        assert_eq!(Challenge::of(None), Challenge::None);
        assert_eq!(Challenge::of(Some(&answer(&[]))), Challenge::None);
        assert_eq!(Challenge::of(Some(&answer(&["Basic realm=\"Rootyard\", charset=\"UTF-8\""]))), Challenge::Basic);
        assert_eq!(Challenge::of(Some(&answer(&["bearer realm=\"Rootyard\""]))), Challenge::Bearer);
        // Only the first value names the scheme; later ones are never parsed.
        assert_eq!(
            Challenge::of(Some(&answer(&["Bearer realm=\"Rootyard\"", "Basic realm=\"Rootyard\""]))),
            Challenge::Bearer
        );
        assert_eq!(Challenge::of(Some(&answer(&["Negotiate"]))), Challenge::Other);
        let mut binary = HeaderMap::new();
        binary.append(header::WWW_AUTHENTICATE, HeaderValue::from_bytes(b"\xff\xfe").unwrap());
        assert_eq!(Challenge::of(Some(&binary)), Challenge::Other);
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
