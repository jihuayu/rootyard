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

#[path = "browser_ui/assets.rs"]
mod inline;

use axum::{
    Form, Router,
    extract::{Path, Query, Request, State, rejection::PathRejection},
    http::{HeaderMap, HeaderValue, Uri, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::Value;

use super::{api, browse, error::GatewayError, history, state::BlobGitState};
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

/// The shared sign-in page, mounted on this router's own state. The shared
/// page handler takes no state at all; only the sign-in mutation below needs
/// the `MetadataState` the gateway provides via `FromRef`.
async fn login_page(Query(query): Query<session::ReturnTo>) -> Response {
    session::login_page(Query(query)).await
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
///
/// The check goes through the shared Web cookie-aware helper: this handler sees
/// the raw request headers (the session middleware validates the cookie but does
/// not rewrite them), so only that helper turns the HttpOnly browser cookie into
/// the credential `auth::authenticate` reads. A cookie never rescues an explicit
/// bad credential (`normalize_web_headers` keeps an existing `Authorization`
/// untouched).
///
/// A helper failure is converted through [`GatewayError::from`], which keeps
/// only its status class and is opaque (no provider or SQL text), so only
/// invalid credentials become the `401` the middleware turns into its shared
/// login redirect; a database or other failure is never answered as a sign-in
/// redirect, and an expired deadline is the gateway [`GatewayError::Timeout`].
async fn spa_shell(State(state): State<Arc<BlobGitState>>, headers: HeaderMap) -> Response {
    let deadline = state.deadline();
    let admitted = tokio::time::timeout_at(deadline, crate::web::session::authenticate_web(state.pool(), &headers));
    match admitted.await {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => return GatewayError::from(error).into_response(),
        Err(_) => return GatewayError::Timeout.into_response(),
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
///   complete pair with a positive, non-regressing revision. Anything else is
///   dropped whole — the success response and its repository JSON body — and
///   replaced by a fresh generic [`GatewayError::Unavailable`], so a malformed
///   answer never renders data.
///
/// The framework stays the only admission decision point. This wrapper only
/// checks the shape of a whole-body answer (complete pair, positive revision,
/// never below the presented frame's own bound), which neither parses a token
/// for authentication nor compares a bound with a live store revision.
async fn admit_bound(
    response: Result<Response, GatewayError>,
    presented: Option<&HeaderValue>,
) -> Result<Response, GatewayError> {
    let response = response?;
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
    // Drop the whole success answer (status, headers and repository JSON body)
    // and answer with a fresh generic refusal instead of patching it in place.
    drop(response);
    Err(bound_refusal())
}

/// The generic refusal for an incomplete or regressing successful answer.
fn bound_refusal() -> GatewayError {
    GatewayError::Unavailable("repository read was refused")
}

async fn alias_refs(
    State(state): State<Arc<BlobGitState>>,
    path: Result<Path<(String, String)>, PathRejection>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let presented = presented_bound(&headers).cloned();
    let Path((owner, name)) = path.map_err(|_| GatewayError::NotFound)?;
    let query: RefsQuery = optional_query(&uri)?;
    let answer = history::refs(State(state), Path((owner, name)), Query(query), headers).await;
    admit_bound(answer, presented.as_ref()).await
}

async fn alias_commits(
    State(state): State<Arc<BlobGitState>>,
    path: Result<Path<(String, String)>, PathRejection>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let presented = presented_bound(&headers).cloned();
    let Path((owner, name)) = path.map_err(|_| GatewayError::NotFound)?;
    let query: CommitsQuery = optional_query(&uri)?;
    let answer = history::commits(State(state), Path((owner, name)), Query(query), headers).await;
    admit_bound(answer, presented.as_ref()).await
}

async fn alias_compare(
    State(state): State<Arc<BlobGitState>>,
    path: Result<Path<(String, String)>, PathRejection>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let presented = presented_bound(&headers).cloned();
    let Path((owner, name)) = path.map_err(|_| GatewayError::NotFound)?;
    // `base` and `head` are required; a missing pair is the same generic input
    // refusal the handler gives for an invalid revision.
    let query: CompareQuery = optional_query(&uri)?;
    let answer = history::compare(State(state), Path((owner, name)), Query(query), headers).await;
    admit_bound(answer, presented.as_ref()).await
}

async fn alias_tree(
    State(state): State<Arc<BlobGitState>>,
    path: Result<Path<(String, String)>, PathRejection>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let presented = presented_bound(&headers).cloned();
    let Path((owner, name)) = path.map_err(|_| GatewayError::NotFound)?;
    let query: TreeQuery = optional_query(&uri)?;
    let answer = browse::tree(State(state), Path((owner, name)), Query(query), headers).await;
    admit_bound(answer, presented.as_ref()).await
}

async fn alias_tree_by_oid(
    State(state): State<Arc<BlobGitState>>,
    path: Result<Path<(String, String, String)>, PathRejection>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let presented = presented_bound(&headers).cloned();
    let Path((owner, name, oid)) = path.map_err(|_| GatewayError::NotFound)?;
    let query: TreeByOidQuery = optional_query(&uri)?;
    let answer = browse::tree_by_oid(State(state), Path((owner, name, oid)), Query(query), headers).await;
    admit_bound(answer, presented.as_ref()).await
}

async fn alias_blob(
    State(state): State<Arc<BlobGitState>>,
    path: Result<Path<(String, String)>, PathRejection>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let presented = presented_bound(&headers).cloned();
    let Path((owner, name)) = path.map_err(|_| GatewayError::NotFound)?;
    let query: BlobQuery = optional_query(&uri)?;
    let answer = browse::blob(State(state), Path((owner, name)), Query(query), headers).await;
    admit_bound(answer, presented.as_ref()).await
}

async fn alias_blob_by_oid(
    State(state): State<Arc<BlobGitState>>,
    path: Result<Path<(String, String, String)>, PathRejection>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let presented = presented_bound(&headers).cloned();
    let Path((owner, name, oid)) = path.map_err(|_| GatewayError::NotFound)?;
    let query: BlobByOidQuery = optional_query(&uri)?;
    let answer = browse::blob_by_oid(State(state), Path((owner, name, oid)), Query(query), headers).await;
    admit_bound(answer, presented.as_ref()).await
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
        // Whole-body wire objects nest their rows under `items`; the page list
        // handler itself issues no session, so it reads plain arrays.
        assert!(inline::SCRIPT.contains("Array.isArray(data.items)"));
        assert!(!inline::SCRIPT.contains("data.page"));
        // A boundless read is still cookie-authenticated and RBAC-checked; only
        // the repository consistency bound may be missing.
        assert!(inline::SCRIPT.contains("This server did not provide a bounded session."));
        assert!(!inline::SCRIPT.contains("reads are anonymous"));
    }

    /// A valid signed frame of revision `revision`, minted only by the cfg(test)
    /// codec helper for this isolated unit fixture.
    fn framed_token(revision: i64) -> String {
        let backend = crate::blob_store::test_support::blob_backend_identity("browser-ui-tests");
        let codec = super::super::repo_session::SessionTokenCodec::new(
            [(0_u8, zeroize::Zeroizing::new([0x5a; 32]))],
            0,
            &backend,
            120,
        )
        .expect("test codec");
        let realm = super::super::repo_session::SessionRealm::new(
            uuid::Uuid::from_bytes([1; 16]),
            uuid::Uuid::from_bytes([2; 16]),
            crate::ref_store::GitObjectFormat::Sha1,
            uuid::Uuid::from_bytes([3; 16]),
            1,
            1,
            uuid::Uuid::from_bytes([4; 16]),
        )
        .expect("test realm");
        super::super::repo_session::SessionTokens::new(codec)
            .issue_for_test(&realm, revision)
            .expect("test token")
            .token()
            .to_owned()
    }

    /// One answer with only the named session headers; `None` means absent.
    fn answer(status: u16, token: Option<&str>, revision: Option<&str>) -> axum::http::Response<axum::body::Body> {
        let mut builder = axum::http::Response::builder().status(status);
        for (name, value) in [(SESSION_HEADER, token), (REVISION_HEADER, revision)] {
            if let Some(value) = value {
                builder = builder.header(name, value);
            }
        }
        builder.body(axum::body::Body::empty()).unwrap()
    }

    /// The presented bound exactly as a request header carries it.
    fn presented(token: &str) -> HeaderValue {
        HeaderValue::from_str(token).expect("a framed token is a valid header value")
    }

    #[test]
    fn a_presented_bound_requires_a_complete_non_regressing_answer() {
        // Revision 3 of the fixture frame: a valid frame, as the framework's
        // own admission would have required before this wrapper saw an answer.
        let presented_token = framed_token(3);
        assert_eq!(super::super::repo_session::presented_bound(&presented_token), Some(3));
        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        // Returns the status plus the whole answer body of an admitted answer.
        let run = |response: axum::http::Response<axum::body::Body>, bound: Option<HeaderValue>| {
            runtime.block_on(async move {
                match admit_bound(Ok(response), bound.as_ref()).await {
                    Ok(response) => {
                        let status = response.status().as_u16();
                        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap_or_default();
                        Ok((status, String::from_utf8_lossy(&bytes).into_owned()))
                    }
                    Err(error) => Err(error),
                }
            })
        };
        let status = |response: axum::http::Response<axum::body::Body>, bound: Option<HeaderValue>| {
            run(response, bound).map(|(status, _)| status)
        };
        // Token-free compatibility reads are passed through unchanged.
        assert_eq!(status(answer(200, None, None), None).unwrap(), 200);
        // Every refusal, including Behind, passes as the framework's generic
        // refusal without being rewritten.
        for code in [503, 401, 403, 404, 400, 422] {
            assert_eq!(status(answer(code, None, None), Some(presented(&presented_token))).unwrap(), code);
        }
        // A successful but incomplete or malformed answer is refused. A fresh
        // refusal carries no part of the refused answer, in particular no
        // byte of its distinctive repository JSON body.
        const MARKER: &str = "REPO-DATA-MARKER-7f3a";
        let with_body = |token: Option<&str>, revision: Option<&str>| {
            let repository = format!(r#"{{"items":[{{"name":"{}"}}]}}"#, MARKER);
            let mut response = answer(200, token, revision).map(|_| axum::body::Body::from(repository));
            response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
            response
        };
        let partial: [(&str, Option<&str>, Option<&str>); 2] =
            [("a revision without a token", None, Some("3")), ("a token without a revision", Some("rs1.next"), None)];
        let malformed: [(&str, Option<&str>, Option<&str>); 2] =
            [("a non-positive revision", Some("rs1.next"), Some("0")), ("an empty token", Some(""), Some("3"))];
        for (what, token, revision) in partial.into_iter().chain(malformed) {
            let refused = run(with_body(token, revision), Some(presented(&presented_token)));
            assert_eq!(refused.err(), Some(bound_refusal()), "{what} was admitted");
        }
        // An answer below its newer presented bound is refused the same way,
        // with its body dropped, and the rendering carries no marker: the
        // browser presents revision 4 while the answer completes revision 3,
        // an internally consistent pair that still moves the browser backwards.
        let newer_bound = framed_token(4);
        assert_eq!(super::super::repo_session::presented_bound(&newer_bound), Some(4));
        let refused = run(with_body(Some(&presented_token), Some("3")), Some(presented(&newer_bound)));
        let rendered = match refused {
            Err(error) => {
                assert_eq!(error, bound_refusal());
                error.into_response()
            }
            // A fresh success answer reaches the client unchanged; render it
            // as-is, so the marker assertions below would catch any leak.
            Ok((_status, body)) => axum::http::Response::builder()
                .status(axum::http::StatusCode::OK)
                .body(axum::body::Body::from(body))
                .expect("a fresh rendering"),
        };
        assert_eq!(rendered.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
        let bytes = runtime.block_on(axum::body::to_bytes(rendered.into_body(), usize::MAX)).unwrap();
        let rendered = String::from_utf8_lossy(&bytes);
        assert!(!rendered.contains(MARKER), "the refused answer retained its repository body");
        assert!(!rendered.contains(r#""items""#), "the refused answer retained its repository shape");
        // A complete, non-regressing pair is admitted for the script to adopt,
        // and the same complete pair is refused against its newer presented bound.
        assert_eq!(status(answer(200, Some("rs1.next"), Some("3")), Some(presented(&presented_token))).unwrap(), 200);
        assert_eq!(
            status(answer(200, Some("rs1.next"), Some("3")), Some(presented(&newer_bound))).err(),
            Some(bound_refusal())
        );
    }

    #[test]
    fn a_boundless_answer_is_passed_through_and_only_a_presented_bound_is_checked() {
        // The first answer, whether it is the index list (no session headers)
        // or a bounded repository read, has no bound to check against and is
        // passed through unchanged; only a presented bound is ever checked.
        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let admit = |response: axum::http::Response<axum::body::Body>, bound: Option<HeaderValue>| {
            runtime.block_on(async move {
                match admit_bound(Ok(response), bound.as_ref()).await {
                    Ok(response) => Ok((response.status().as_u16(), response.headers().len())),
                    Err(error) => Err(error),
                }
            })
        };
        assert_eq!(admit(answer(200, None, None), None), Ok((200, 0)));
        assert_eq!(admit(answer(200, Some("rs1.next"), Some("3")), None), Ok((200, 2)));
        // With a presented bound the answer is checked; a complete pair at or
        // above it passes and a headerless answer does not.
        let bound = presented(&framed_token(3));
        assert_eq!(admit(answer(200, Some("rs1.next"), Some("3")), Some(bound.clone())).err(), None);
        assert_eq!(admit(answer(200, None, None), Some(bound)).err(), Some(bound_refusal()));
        // Only the script knows whether a bound was adopted: a whole-body
        // answer with no session header at all is accepted while nothing was
        // adopted, a half pair never is, and a headerless answer after an
        // adopted pair is refused. These are the exact script rules.
        let script = inline::SCRIPT;
        assert!(
            script.contains(
                "const hasToken = response.headers.has(TOKEN), hasRevision = response.headers.has(REVISION);"
            )
        );
        assert!(script.contains("const headerless = !hasToken && !hasRevision;"));
        assert!(script.contains("if (headerless) return bound === null && revision === null ? NO_BOUND : null;"));
        assert!(
            script
                .contains("if (!hasToken || !hasRevision || !token || raw === null || raw.trim() === '') return null;")
        );
        assert!(!script.contains("const headerless = !token && (raw === null || raw.trim() === '');"));
    }

    /// The page admission uses the shared cookie-aware helper, not the raw
    /// bearer-only gateway check on unnormalised request headers, and it keeps
    /// a missing credential (401) apart from a failure and an expired deadline.
    #[test]
    fn the_shell_authenticates_through_the_shared_cookie_helper() {
        let source = include_str!("browser_ui.rs");
        let shell = body_of(source, "async fn spa_shell(", "// Read aliases", "the shell handler");
        assert!(shell.contains("crate::web::session::authenticate_web(state.pool(), &headers)"));
        assert!(shell.contains("tokio::time::timeout_at(deadline,"), "the page check is deadline-bounded");
        assert!(shell.contains("Ok(Err(error)) => return GatewayError::from(error).into_response()"));
        assert!(shell.contains("Err(_) => return GatewayError::Timeout.into_response()"));
        assert!(!shell.contains("super::session::authenticate("), "the shell must not read raw bearer headers");
        // Invalid credentials are no longer collapsed into a 401 here: the
        // helper's own answer is already one.
        assert_eq!(shell.matches("GatewayError::Unauthorized").count(), 0, "no failure may collapse into a 401");
    }

    /// The source text of one item: from `from` up to the next `to` marker.
    fn body_of<'a>(source: &'a str, from: &str, to: &str, what: &str) -> &'a str {
        let start = source.find(from).unwrap_or_else(|| panic!("missing {what}"));
        let rest = &source[start..];
        let end = rest.find(to).unwrap_or_else(|| panic!("missing the end of the source"));
        &rest[..end]
    }

    /// The script's single `adopt` updates the closure's `bound` and `revision`
    /// from its own parameters (never shadowing the revision it replaces), and
    /// bound adoption happens only after the headers were admitted and the
    /// whole body was read and parsed into the expected `{items: [...]}` shape.
    #[test]
    fn the_script_parses_the_whole_body_before_adopting_a_bound() {
        let script = inline::SCRIPT;
        let adopt = body_of(script, "function adopt(", "// Validate response headers", "the adopt function");
        assert!(adopt.contains("function adopt(nextToken, nextRevision)"), "the revision parameter must not shadow");
        assert!(adopt.contains("bound = nextToken;"), "the token is adopted");
        assert!(adopt.contains("revision = nextRevision;"), "the outer revision is updated");
        let read = body_of(script, "async function read(scope, url)", "async function repository(", "the read path");
        let headers = read.find("const next = admit(response);").expect("headers are admitted");
        let body = read.find("await response.json()").expect("the whole body is parsed");
        let shape = read.find("Array.isArray(data.items)").expect("the body shape is checked");
        let adopt = read.find("adopt(next.token, next.revision);").expect("the pair is adopted together");
        assert!(headers < body && body < shape && shape < adopt, "admission and parsing must precede adoption");
        assert!(read.contains("if (next !== NO_BOUND)"), "a headerless answer must keep the browser boundless");
        assert_eq!(read.matches("adopt(").count(), 1, "the read path adopts at exactly one site");
        assert!(!script.contains("currentScript"));
    }

    /// A repository read that fails after showing its refusal stops the
    /// sequence, so no later read or the closing success status overwrites it.
    #[test]
    fn a_failed_repository_read_stops_the_sequence() {
        let repository = body_of(inline::SCRIPT, "async function repository(", "async function index(", "the repository page");
        let refs = repository.find("const refs = await read(").expect("refs are read");
        let tree = repository.find("const tree = await read(").expect("the tree is read");
        let commits = repository.find("const commits = await read(").expect("the commits are read");
        let status = repository.find("show(bound ? READ : NO_SESSION, false);").expect("the success status");
        let stop = |at: usize, value: &str| {
            repository[at..].find(&format!("if (!{value}) return;")).map(|offset| at + offset)
                .unwrap_or_else(|| panic!("a failed {value} read must stop the sequence"))
        };
        assert!(stop(refs, "refs") < tree, "a failed refs read must not start the tree read");
        assert!(tree < stop(tree, "tree") && stop(tree, "tree") < commits, "a failed tree read must not start the commits read");
        assert!(commits < stop(commits, "commits") && stop(commits, "commits") < status, "a failed commits read must precede the success status");
        assert_eq!(repository.matches("show(bound ? READ : NO_SESSION, false);").count(), 1, "one closing success status");
        assert_eq!(repository.matches("show(").count(), 1, "the page itself shows no failure status of its own");
    }
}
