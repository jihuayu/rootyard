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
//!
//! The 401 challenge of a relayed read is not decided in this module: every
//! JSON handler the aliases call renders an unauthorized answer with
//! [`GatewayError::api`] (`Bearer realm="Rootyard"`), so the alias and the
//! top-level `/api` route answer one identical refusal and a cookie-only
//! browser `fetch` resolves promptly instead of entering a Basic auth exchange.
//! A refusal already challenged by another authority passes through untouched.
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
        .route("/repos/{owner}/{name}/commits/{oid}", get(alias_commit))
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
async fn normalize_session_headers(request: Request, next: Next) -> Response {
    let (mut parts, body) = request.into_parts();
    parts.headers = normalize_web_headers(&parts.headers);
    next.run(Request::from_parts(parts, body)).await
}

async fn login_page(Query(query): Query<session::ReturnTo>) -> Response {
    session::login_page(Query(query)).await
}

async fn login(
    State(state): State<MetadataState>,
    headers: HeaderMap,
    form: Result<Form<LoginForm>, axum::extract::rejection::FormRejection>,
) -> Response {
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
// Read aliases.
// ---------------------------------------------------------------------------

async fn list_repos(
    State(state): State<Arc<BlobGitState>>,
    uri: Uri,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let query: api::ListQuery = optional_query(&uri)?;
    Ok(api::list_repos(State(state), Query(query), uri, headers).await)
}

async fn get_repo(
    State(state): State<Arc<BlobGitState>>,
    path: Result<Path<(String, String)>, PathRejection>,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let Path((owner, name)) = path.map_err(|_| GatewayError::NotFound)?;
    Ok(api::get_repo(State(state), Path((owner, name)), headers).await)
}

fn presented_bound(headers: &HeaderMap) -> Option<&HeaderValue> {
    headers.get(SESSION_HEADER)
}

/// Admit a whole repository read against the browser's bound before any body
/// byte is forwarded.
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
    let fresh = match (presented.to_str(), served) {
        (Ok(token), Some(served)) => super::repo_session::presented_bound(token).is_some_and(|bound| served >= bound),
        _ => false,
    };
    if complete && fresh {
        return Ok(response);
    }
    drop(response);
    Err(bound_refusal())
}

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
    let answer = Ok(history::refs(State(state), Path((owner, name)), Query(query), headers).await);
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
    let answer = Ok(history::commits(State(state), Path((owner, name)), Query(query), headers).await);
    admit_bound(answer, presented.as_ref()).await
}

async fn alias_commit(
    State(state): State<Arc<BlobGitState>>,
    path: Result<Path<(String, String, String)>, PathRejection>,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let presented = presented_bound(&headers).cloned();
    let Path((owner, name, oid)) = path.map_err(|_| GatewayError::NotFound)?;
    let answer = Ok(history::commit(State(state), Path((owner, name, oid)), headers).await);
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
    let query: CompareQuery = optional_query(&uri)?;
    let answer = Ok(history::compare(State(state), Path((owner, name)), Query(query), headers).await);
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
    let answer = Ok(browse::tree(State(state), Path((owner, name)), Query(query), headers).await);
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
    let answer = Ok(browse::tree_by_oid(State(state), Path((owner, name, oid)), Query(query), headers).await);
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
    let answer = Ok(browse::blob(State(state), Path((owner, name)), Query(query), headers).await);
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
    let answer = Ok(browse::blob_by_oid(State(state), Path((owner, name, oid)), Query(query), headers).await);
    admit_bound(answer, presented.as_ref()).await
}

fn optional_query<T: serde::de::DeserializeOwned>(uri: &Uri) -> Result<T, GatewayError> {
    let pairs = Query::<Vec<(String, String)>>::try_from_uri(uri)
        .map_err(|_| GatewayError::BadRequest("invalid repository browse parameters"))?;
    let fields = pairs.0.into_iter().map(|(key, value)| (key, Value::String(value))).collect();
    serde_json::from_value(Value::Object(fields))
        .map_err(|_| GatewayError::BadRequest("invalid repository browse parameters"))
}

#[cfg(test)]
mod tests;
