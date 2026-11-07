//! Personal access token and browser session management.
//!
//! Shared data model, service and handlers for:
//!
//! * `GET|POST /api/tokens`
//! * `GET|PATCH|DELETE /api/tokens/{id}`
//! * `POST /api/tokens/{id}/rotate`
//! * `GET /api/sessions`, `DELETE /api/sessions/{session_token_id}`
//!
//! The API accepts only `Authorization`; the browser UI
//! (`/web/settings/tokens`, `/web/settings/sessions`) is authenticated by the
//! existing cookie/Origin/CSRF middleware and then calls the same service.
//! New tokens are always restricted with an explicit grant set (an empty set is
//! deny-all), owned by the acting user, and bounded to 128 grants. Lists are
//! keyset-paginated with a default of 50 and a hard maximum of 100.
//!
//! Release state: the CAS parent-token lock for Git publication and the
//! restricted browser-child inheritance are tracked on a separate branch. This
//! module is a private implementation branch; it does not claim those pieces
//! are released.

pub mod grants;
pub mod handlers;
pub mod models;
pub mod service;

use crate::AppState;
use axum::{
    Json, Router,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
};
use std::sync::Arc;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/tokens", get(handlers::list_tokens).post(handlers::create_token))
        .route(
            "/api/tokens/{id}",
            get(handlers::get_token).patch(handlers::update_token).delete(handlers::revoke_token),
        )
        .route("/api/tokens/{id}/rotate", post(handlers::rotate_token))
        .route("/api/sessions", get(handlers::list_sessions))
        .route("/api/sessions/{session_token_id}", delete(handlers::revoke_session))
}

/// JSON response that is never cacheable and never content-sniffed. Secret
/// material appears only in a create/rotate response body, never in a header.
pub fn json_response<T: serde::Serialize>(status: StatusCode, body: T) -> Response {
    (status, [(header::CACHE_CONTROL, "no-store"), (header::X_CONTENT_TYPE_OPTIONS, "nosniff")], Json(body))
        .into_response()
}

/// Empty response with the same no-store/nosniff policy.
pub fn empty_response(status: StatusCode) -> Response {
    (status, [(header::CACHE_CONTROL, "no-store"), (header::X_CONTENT_TYPE_OPTIONS, "nosniff")]).into_response()
}
