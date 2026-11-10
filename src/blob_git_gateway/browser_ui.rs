//! Small authenticated, read-only browser UI for the Blob-only gateway (#174).
//!
//! This module adds routes only. Every repository read is answered by the
//! existing Blob gateway handlers (`api`, `browse`, `history`) through GET-only
//! `/web/blob/api/...` aliases, so the serving lookup, ref capture, Blob
//! closure, session issuance and revision fences stay in exactly one place and
//! no client-supplied revision is ever accepted.
//!
//! Mounted below `/web` only:
//!
//! * `GET /web/login` and `POST /web/login` reuse the shared
//!   [`crate::web::session`] page, now also below the Blob gateway whose
//!   standalone service merges no other `/web` tree; `POST /web/logout` and
//!   `GET /web/app.js` are the same paths the shared Web UI registers;
//! * `GET /web/blob` and `GET /web/blob/repos/{owner}/{name}` serve one static
//!   SPA shell that carries no credential, repository name, list or content;
//! * `GET /web/blob/api/...` are the read aliases. They first receive the
//!   narrowest header translation ([`normalize_session_headers`]), which runs
//!   only after the outer Web session middleware validated the HttpOnly browser
//!   cookie. It translates that cookie to `Authorization` and is scoped to this
//!   GET-only alias subtree; `/api` and `/git` never observe it.
//!
//! The ordinary `/api` and Smart HTTP routes keep their bearer-only behaviour
//! and are neither merged, wrapped nor changed here. No mutation, push or
//! content-write route exists in the browser subtree.
use std::sync::Arc;

use axum::{
    Form, Router,
    extract::{Path, Query, Request, State, rejection::PathRejection},
    http::{HeaderMap, Uri, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::Value;

use super::{api, browse, error::GatewayError, history, session::authenticate, state::BlobGitState};
use crate::{
    application::MetadataState,
    browse::models::{BlobByOidQuery, BlobQuery, CommitsQuery, CompareQuery, RefsQuery, TreeByOidQuery, TreeQuery},
    web::{
        session::{self, LoginForm, normalize_web_headers},
        templates::html_response,
    },
};

/// Request header carrying the opaque repository session token.
const SESSION_HEADER: &str = "x-rootyard-session";
/// Response header naming the exact core gate revision served.
const REVISION_HEADER: &str = "x-rootyard-session-revision";
const STATIC_CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; \
                           base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

/// The Web subrouter: the shared sign-in pages, the read-only Blob SPA and its
/// GET-only read aliases. The caller applies [`crate::web::session::middleware`]
/// over this complete router exactly once.
pub(super) fn router() -> Router<Arc<BlobGitState>> {
    let aliases = Router::new()
        .route("/repos", get(list_repos))
        .route("/repos/{owner}/{name}", get(get_repo))
        .route("/repos/{owner}/{name}/refs", get(alias_refs))
        .route("/repos/{owner}/{name}/commits", get(alias_commits))
        .route("/repos/{owner}/{name}/tree", get(alias_tree))
        .route("/repos/{owner}/{name}/tree/{oid}", get(alias_tree_by_oid))
        .route("/repos/{owner}/{name}/blob", get(alias_blob))
        .route("/repos/{owner}/{name}/blob/{oid}", get(alias_blob_by_oid))
        .route("/repos/{owner}/{name}/compare", get(alias_compare))
        .layer(middleware::from_fn(normalize_session_headers));
    Router::new()
        .route("/login", get(login_page).post(login))
        .route("/logout", post(logout))
        .route("/app.js", get(app_js))
        .route("/blob", get(spa_shell))
        .route("/blob/", get(spa_shell))
        .route("/blob/repos/{owner}/{name}", get(spa_shell))
        .nest("/blob/api", aliases)
}

/// Translate the already-validated HttpOnly browser session cookie into the
/// `Authorization` header the gateway handlers expect.
///
/// Only cookie-to-header normalisation is applied and only here. A request that
/// already carries any `Authorization` value is left untouched (the shared
/// normaliser's rule) and no other header is rewritten. The public `/api` and
/// Smart HTTP routes are outside this subtree and stay bearer-only.
async fn normalize_session_headers(request: Request, next: Next) -> Response {
    let (mut parts, body) = request.into_parts();
    parts.headers = normalize_web_headers(&parts.headers);
    next.run(Request::from_parts(parts, body)).await
}

/// The shared sign-in pages, mounted on this router's own state. The shared
/// handlers take `MetadataState`, which the state provides via `FromRef`.
async fn login_page(State(state): State<MetadataState>, Query(query): Query<session::ReturnTo>) -> Response {
    session::login_page(State(state), Query(query)).await
}

async fn login(
    State(state): State<MetadataState>,
    headers: HeaderMap,
    form: Result<Form<LoginForm>, axum::extract::rejection::FormRejection>,
) -> Response {
    // A missing or rejected form is the same generic unauthorized answer the
    // shared handler gives for a missing field; no framework text is echoed.
    match form {
        Ok(form) => session::login(State(state), headers, form).await.into_response(),
        Err(_) => crate::Error::unauthorized().into_response(),
    }
}

async fn logout(State(state): State<MetadataState>, headers: HeaderMap) -> Response {
    match session::logout(State(state), headers).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn app_js() -> Response {
    static_asset("application/javascript; charset=utf-8", inline::SCRIPT)
}

fn static_asset(content_type: &'static str, body: &'static str) -> Response {
    let mut response = (axum::http::StatusCode::OK, body).into_response();
    let headers = response.headers_mut();
    headers.insert(header::CONTENT_TYPE, header::HeaderValue::from_static(content_type));
    headers.insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
    headers.insert(header::CONTENT_SECURITY_POLICY, header::HeaderValue::from_static(STATIC_CSP));
    headers.insert(header::X_CONTENT_TYPE_OPTIONS, header::HeaderValue::from_static("nosniff"));
    headers.insert(header::X_FRAME_OPTIONS, header::HeaderValue::from_static("DENY"));
    headers.insert(header::REFERRER_POLICY, header::HeaderValue::from_static("no-referrer"));
    response
}

/// The SPA shell. It is identical for every page and carries no repository
/// name, list, session bound or content: the script derives the page scope from
/// its own URL and every repository read is a same-origin `/web/blob/api`
/// request authenticated by the browser session cookie. A page navigation
/// without a live cookie is a 401 here, so the outer session middleware applies
/// its shared login redirect with a safe `return_to` instead of delivering a
/// shell that could never read data.
async fn spa_shell(State(state): State<Arc<BlobGitState>>, headers: HeaderMap) -> Response {
    if authenticate(&state, &headers).await.is_err() {
        return GatewayError::Unauthorized.into_response();
    }
    let mut response = html_response(axum::http::StatusCode::OK, inline::shell());
    if let Ok(value) = axum::http::HeaderValue::from_str(inline::CSP) {
        response.headers_mut().insert(header::CONTENT_SECURITY_POLICY, value);
    }
    response
}

// ---------------------------------------------------------------------------
// Read aliases. Each one parses only the framework-level query/path types and
// calls the unchanged gateway handler. Query decoding failures are the same
// generic input refusal as on `/api`, never a framework echo.
// ---------------------------------------------------------------------------

async fn list_repos(
    State(state): State<Arc<BlobGitState>>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let query: api::ListQuery = optional_query(&uri)?;
    api::list_repos(State(state), Query(query), uri, headers).await
}

async fn get_repo(
    State(state): State<Arc<BlobGitState>>,
    path: Result<Path<(String, String)>, PathRejection>,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let Path((owner, name)) = path.map_err(|_| GatewayError::NotFound)?;
    api::get_repo(State(state), Path((owner, name)), headers).await
}

/// The bound a browser presented, also guarding the cookie-only list read.
fn presented_bound(headers: &HeaderMap) -> Option<&HeaderValue> {
    headers.get(SESSION_HEADER)
}

/// Admit a whole repository read against the browser's bound before any body
/// byte is forwarded.
///
/// * No presented header is the token-free compatibility read: it is forwarded
///   unchanged. A keyless gateway stays usable and issues no session headers;
///   a keyed one answers with the pair the browser then adopts.
/// * With a presented bound, a `Behind` refusal is returned as-is (its body is
///   the framework's generic refusal), and a successful answer must carry a
///   complete pair with a positive, non-regressing revision; anything else
///   becomes a generic refusal, so a malformed answer never renders data.
///
/// The framework stays the only admission decision point. This wrapper only
/// checks the shape of a whole-body answer (complete pair, positive revision,
/// never below the presented frame's own bound), which neither parses a token
/// for authentication nor compares a bound with a live store revision.
async fn admit_bound(
    response: Result<Response, GatewayError>,
    presented: Option<&HeaderValue>,
) -> Result<Response, GatewayError> {
    let mut response = response?;
    let Some(presented) = presented else { return Ok(response) };
    if !response.status().is_success() {
        return Ok(response);
    }
    let served = response
        .headers()
        .get(REVISION_HEADER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<i64>().ok())
        .filter(|revision| *revision > 0);
    let complete = response.headers().get(SESSION_HEADER).is_some_and(|token| !token.is_empty());
    // A frame the framework already admitted at revision R is only extended by
    // an answer that names revision >= R. An unreadable bound was refused as an
    // explicit input error, so it never reaches this successful branch.
    let fresh = match (presented.to_str(), served) {
        (Ok(token), Some(served)) => super::repo_session::presented_bound(token).is_some_and(|bound| served >= bound),
        _ => false,
    };
    if complete && fresh {
        return Ok(response);
    }
    let refusal = GatewayError::Unavailable("repository read was refused").into_response();
    *response.status_mut() = refusal.status();
    *response.headers_mut() = refusal.headers().clone();
    Ok(response)
}

async fn alias_refs(
    State(state): State<Arc<BlobGitState>>,
    path: Result<Path<(String, String)>, PathRejection>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let presented = presented_bound(&headers);
    let Path((owner, name)) = path.map_err(|_| GatewayError::NotFound)?;
    let query: RefsQuery = optional_query(&uri)?;
    let answer = history::refs(State(state), Path((owner, name)), Query(query), headers).await;
    admit_bound(answer, presented).await
}

async fn alias_commits(
    State(state): State<Arc<BlobGitState>>,
    path: Result<Path<(String, String)>, PathRejection>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let presented = presented_bound(&headers);
    let Path((owner, name)) = path.map_err(|_| GatewayError::NotFound)?;
    let query: CommitsQuery = optional_query(&uri)?;
    let answer = history::commits(State(state), Path((owner, name)), Query(query), headers).await;
    admit_bound(answer, presented).await
}

async fn alias_compare(
    State(state): State<Arc<BlobGitState>>,
    path: Result<Path<(String, String)>, PathRejection>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let presented = presented_bound(&headers);
    let Path((owner, name)) = path.map_err(|_| GatewayError::NotFound)?;
    // `base` and `head` are required; a missing pair is the same generic input
    // refusal the handler gives for an invalid revision.
    let query: CompareQuery = optional_query(&uri)?;
    let answer = history::compare(State(state), Path((owner, name)), Query(query), headers).await;
    admit_bound(answer, presented).await
}

async fn alias_tree(
    State(state): State<Arc<BlobGitState>>,
    path: Result<Path<(String, String)>, PathRejection>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let presented = presented_bound(&headers);
    let Path((owner, name)) = path.map_err(|_| GatewayError::NotFound)?;
    let query: TreeQuery = optional_query(&uri)?;
    let answer = browse::tree(State(state), Path((owner, name)), Query(query), headers).await;
    admit_bound(answer, presented).await
}

async fn alias_tree_by_oid(
    State(state): State<Arc<BlobGitState>>,
    path: Result<Path<(String, String, String)>, PathRejection>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let presented = presented_bound(&headers);
    let Path((owner, name, oid)) = path.map_err(|_| GatewayError::NotFound)?;
    let query: TreeByOidQuery = optional_query(&uri)?;
    let answer = browse::tree_by_oid(State(state), Path((owner, name, oid)), Query(query), headers).await;
    admit_bound(answer, presented).await
}

async fn alias_blob(
    State(state): State<Arc<BlobGitState>>,
    path: Result<Path<(String, String)>, PathRejection>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let presented = presented_bound(&headers);
    let Path((owner, name)) = path.map_err(|_| GatewayError::NotFound)?;
    let query: BlobQuery = optional_query(&uri)?;
    let answer = browse::blob(State(state), Path((owner, name)), Query(query), headers).await;
    admit_bound(answer, presented).await
}

async fn alias_blob_by_oid(
    State(state): State<Arc<BlobGitState>>,
    path: Result<Path<(String, String, String)>, PathRejection>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let presented = presented_bound(&headers);
    let Path((owner, name, oid)) = path.map_err(|_| GatewayError::NotFound)?;
    let query: BlobByOidQuery = optional_query(&uri)?;
    let answer = browse::blob_by_oid(State(state), Path((owner, name, oid)), Query(query), headers).await;
    admit_bound(answer, presented).await
}

fn optional_query<T: serde::de::DeserializeOwned>(uri: &Uri) -> Result<T, GatewayError> {
    // No query is the same as an empty query, so every optional field keeps its
    // default. Decoding follows the same form rules as `Query` on `/api` (a
    // repeated parameter keeps its last value); a failure is the generic input
    // refusal, never a framework echo.
    let pairs = Query::<Vec<(String, String)>>::try_from_uri(uri)
        .map_err(|_| GatewayError::BadRequest("invalid repository browse parameters"))?;
    let fields = pairs.0.into_iter().map(|(key, value)| (key, Value::String(value))).collect();
    serde_json::from_value(Value::Object(fields))
        .map_err(|_| GatewayError::BadRequest("invalid repository browse parameters"))
}

#[path = "browser_ui/assets.rs"]
mod inline;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_decoding_is_optional_and_errsafe() {
        let uri: Uri = "/x?oid=HEAD&path=a%2Fb".parse().unwrap();
        let query: TreeQuery = optional_query(&uri).expect("valid query");
        assert_eq!(query.oid.as_deref(), Some("HEAD"));
        assert_eq!(query.path.as_deref(), Some("a/b"));
        let empty: Uri = "/x".parse().unwrap();
        let query: RefsQuery = optional_query(&empty).expect("empty query");
        assert!(query.prefix.is_none() && query.limit.is_none());
        let unknown: Uri = "/x?surprise=1".parse().unwrap();
        assert_eq!(
            optional_query::<TreeQuery>(&unknown).err(),
            Some(GatewayError::BadRequest("invalid repository browse parameters"))
        );
    }

    #[test]
    fn the_assets_carry_no_data_or_credentials() {
        let shell = inline::shell();
        for marker in ["x-rootyard-session", "rs1.", "/web/blob/api/repos/", "<script>", "__STYLE__"] {
            assert!(!shell.contains(marker), "the shell carries {marker}");
        }
        // The shell loads the script from the route this router actually registers.
        assert!(shell.contains(r#"<script src="/web/app.js" defer>"#));
        assert!(!inline::SCRIPT.contains("innerHTML"), "repository data must never reach innerHTML");
        assert!(!inline::SCRIPT.contains("currentScript"), "there is no out-of-band bound producer");
        for storage in ["localStorage", "sessionStorage", "document.cookie", "location.search"] {
            assert!(!inline::SCRIPT.contains(storage), "the bound must not reach {storage}");
        }
        assert!(inline::SCRIPT.contains("credentials: 'same-origin'"));
        assert!(inline::SCRIPT.contains("textContent"));
        // Whole-body wire objects nest their rows under `items`.
        assert!(inline::SCRIPT.contains("Array.isArray(data.items)"));
        assert!(!inline::SCRIPT.contains("data.page"));
    }

    #[test]
    fn a_presented_bound_requires_a_complete_non_regressing_answer() {
        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let answer = |status: u16, token: Option<&'static str>, revision: Option<&'static str>| {
            let mut builder = axum::http::Response::builder().status(status);
            for (name, value) in [(SESSION_HEADER, token), (REVISION_HEADER, revision)] {
                if let Some(value) = value {
                    builder = builder.header(name, value);
                }
            }
            builder.body(axum::body::Body::empty()).unwrap()
        };
        let run = |response: axum::http::Response<axum::body::Body>, presented: Option<&HeaderValue>| {
            runtime
                .block_on(async move { admit_bound(Ok(response), presented).await })
                .map(|response| response.status().as_u16())
        };
        // The framework admitted this minimal frame at revision 3; this module
        // only compares the whole answer against that same reported bound.
        let bound = super::super::repo_session::presented_bound("rs1.test").unwrap_or(3);
        let fresh = HeaderValue::from_str(&format!("rs1.at{bound}")).unwrap();
        let stale = HeaderValue::from_str(&format!("rs1.at{}", bound.saturating_add(1))).unwrap();
        let high = (bound.saturating_add(1)).to_string();
        // Token-free compatibility reads are passed through unchanged.
        assert_eq!(run(answer(200, None, None), None).unwrap(), 200);
        // Every refusal, including Behind, passes as the framework's generic
        // refusal without being rewritten.
        for status in [503, 401, 403, 404, 400, 422] {
            assert_eq!(run(answer(status, None, None), Some(&fresh)).unwrap(), status);
        }
        // A successful but incomplete or malformed answer is refused.
        let empty = Some("");
        let incomplete = [
            (None, Some("3")),
            (Some("rs1.next"), None),
            (Some("rs1.next"), Some("0")),
            (empty, Some("3")),
        ];
        for (token, revision) in incomplete {
            assert_eq!(run(answer(200, token, revision), Some(&fresh)).unwrap(), 503, "{token:?} {revision:?}");
        }
        // An answer that would move the browser backwards is refused.
        assert_eq!(run(answer(200, Some("rs1.next"), Some(&high)), Some(&fresh)).unwrap(), 503);
        // A complete, non-regressing pair is admitted for the script to adopt.
        assert_eq!(run(answer(200, Some("rs1.next"), Some("3")), Some(&fresh)).unwrap(), 200);
        assert_eq!(run(answer(200, Some("rs1.next"), Some("3")), Some(&stale)).unwrap(), 503);
    }
}
