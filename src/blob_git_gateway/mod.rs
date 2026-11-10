//! Blob-only Git gateway (#144/#109): a real Smart-HTTP vertical over the
//! PostgreSQL RefStore core and protected OpenDAL Blob bytes.
//!
//! What this module owns:
//!
//! * a small create/list/get JSON API, where creation goes through the shared
//!   `ref_store::serving` provision authority (never legacy Pando/GitFS);
//! * `GET .../info/refs?service=git-upload-pack|git-receive-pack`;
//! * `POST .../git-upload-pack` (bounded native streaming);
//! * `POST .../git-receive-pack` (quarantine spool -> real native ingestion ->
//!   A3 protected Blob upload -> A4 registration -> decision-gated
//!   prepare/select/verify/commit -> a real `report-status` from the durable
//!   terminal).
//!
//! What it deliberately does not own: a permanent bare repository, a legacy
//! data-directory authority, an LFS media service or a merge producer.
//! Those routes refuse explicitly (`501`) instead of
//! pretending success.
//!
//! Local bare Git exists only as a per-request computed view. Durable refs live
//! in the core and durable bytes in Blob, so the RAII deletion of a compute view
//! can never lose an already acknowledged ref or byte.
mod api;
mod browse;
mod browser_ui;
mod config;
mod error;
mod history;
mod metadata;
mod native;
mod operation;
mod process_guard;
mod protocol;
mod publish;
mod read_session;
mod receive;
pub(crate) mod repo_session;
mod resource;
mod serving;
mod session;
mod smart_http;
mod snapshot;
mod state;

#[cfg(test)]
mod session_http_acceptance;

use std::sync::Arc;

use axum::{
    Router,
    routing::{any, get, post},
};

pub use config::{BlobGitConfig, BlobGitConfigError, BlobGitLimits, BlobGitNativeLimits};
pub use error::GatewayError;
pub use repo_session::SessionTokens;
pub use state::BlobGitState;

/// The browser-only `/web` subtree: the shared sign-in/session pages and the
/// read-only Blob SPA with its GET-only read aliases, all behind the existing
/// `web::session` middleware (cookie validation, Origin/CSRF for mutations and
/// navigation handling) with the [`BlobGitState`] metadata extraction.
///
/// It is merged once here and never wraps `/api` or `/git`, so those keep their
/// bearer-only behaviour unchanged. Cookie authentication is added only for the
/// GET-only `/web/blob/api/...` reads, where the validated session cookie is
/// translated into the `Authorization` header the gateway handlers read.
fn web_router(state: Arc<BlobGitState>) -> Router<Arc<BlobGitState>> {
    Router::new()
        .nest("/web", browser_ui::router())
        .layer(axum::middleware::from_fn_with_state(state, crate::web::session::middleware))
}

/// Mount the Blob Git gateway. The caller owns the listener and the real Blob
/// store; no `AppState`, legacy `Storage` authority or permanent bare repo is
/// consulted.
///
/// Token/session routes are merged here from the shared token module. They see
/// only the PostgreSQL pool (`MetadataState` via `FromRef<Arc<BlobGitState>>`);
/// the real token/session service and its token-scoped authorization are reused
/// unchanged. The broad request deadline below covers their handler awaits too.
pub fn router(state: Arc<BlobGitState>) -> Router {
    Router::new()
        .route("/health/live", get(|| async { "ok" }))
        .route("/health/ready", get(metadata_ready))
        .route("/api/repos", post(api::create_repo).get(api::list_repos))
        .route("/api/repos/{owner}/{name}", get(api::get_repo))
        .route("/api/repos/{owner}/{name}/operations/{operation}", get(api::get_operation))
        .route("/api/repos/{owner}/{name}/merges", post(api::unsupported_merge))
        .route("/api/repos/{owner}/{name}/tree", get(browse::tree))
        .route("/api/repos/{owner}/{name}/tree/{oid}", get(browse::tree_by_oid))
        .route("/api/repos/{owner}/{name}/blob", get(browse::blob))
        .route("/api/repos/{owner}/{name}/blob/{oid}", get(browse::blob_by_oid))
        .route("/api/repos/{owner}/{name}/refs", get(history::refs))
        .route("/api/repos/{owner}/{name}/commits", get(history::commits))
        .route("/api/repos/{owner}/{name}/commits/{oid}", get(history::commit))
        .route("/api/repos/{owner}/{name}/compare", get(history::compare))
        .route("/git/{owner}/{name}/info/refs", get(smart_http::info_refs))
        .route("/git/{owner}/{name}/git-upload-pack", post(smart_http::upload_pack))
        .route("/git/{owner}/{name}/git-receive-pack", post(receive::receive_pack))
        .route("/git/{owner}/{name}/info/lfs/{*rest}", any(api::unsupported_lfs))
        // The browser subtree is merged before the shared token routes, so a
        // path both would register keeps the established token API handler.
        .merge(web_router(state.clone()))
        .merge(crate::token_management::routes())
        .layer(axum::middleware::from_fn_with_state(state.clone(), request_deadline))
        .with_state(state)
}

// One deadline starts before authentication and capacity admission. Every local
// stage reads that same task-scoped value; streaming producers receive it by value.
async fn request_deadline(
    axum::extract::State(state): axum::extract::State<Arc<BlobGitState>>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let deadline = state.deadline();
    let operation = if request.method() == axum::http::Method::POST
        && request.uri().path().starts_with("/git/")
        && request.uri().path().ends_with("/git-receive-pack")
    {
        match session::operation_id(request.headers(), request.uri()) {
            Ok(id) => {
                let value = match axum::http::HeaderValue::from_str(&id.to_string()) {
                    Ok(value) => value,
                    Err(_) => return GatewayError::BadRequest("invalid operation identifier").into_response(),
                };
                request.headers_mut().insert("x-rootyard-operation", value.clone());
                Some(value)
            }
            Err(error) => return error.into_response(),
        }
    } else {
        None
    };
    let mut response =
        match tokio::time::timeout_at(deadline, state::REQUEST_DEADLINE.scope(deadline, next.run(request))).await {
            Ok(response) => response,
            Err(_) => GatewayError::Timeout.into_response(),
        };
    if let Some(operation) = operation {
        response.headers_mut().insert("x-rootyard-operation", operation);
    }
    response
}

// Metadata readiness only: Blob availability/closure is verified on actual
// operations. This endpoint makes no bucket integrity or durability claim.
async fn metadata_ready(
    axum::extract::State(state): axum::extract::State<Arc<BlobGitState>>,
) -> Result<&'static str, GatewayError> {
    if !process_guard::healthy() {
        return Err(GatewayError::Unavailable("native process cleanup requires service restart"));
    }
    let deadline = state.deadline().min(tokio::time::Instant::now() + std::time::Duration::from_secs(2));
    tokio::time::timeout_at(deadline, async {
        state
            .pooled(deadline)
            .await?
            .simple_query("SELECT 1")
            .await
            .map_err(|_| GatewayError::Unavailable("metadata is unavailable"))?;
        Ok("ready")
    })
    .await
    .map_err(|_| GatewayError::Timeout)?
}
