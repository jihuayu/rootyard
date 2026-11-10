//! Session and account navigation pages of the Web UI.
//!
//! These routes serve the login/app/logout shell, the repository listing and
//! the personal access token / browser session management pages under
//! `/web/settings/*`. They are mounted below the same cookie/Origin/CSRF
//! middleware as every other `/web` page; this module only owns their paths.

use crate::{application::MetadataState, web};

use axum::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;

pub fn routes() -> Router<MetadataState> {
    Router::new()
        .route("/web/login", get(web::session::login_page).post(web::session::login))
        .route("/web/app.js", get(web::session::app_js))
        .route("/web/logout", post(web::session::logout))
        .route("/web/repos", get(web::repository_listing::discover))
        .route("/web/settings/tokens", get(web::tokens::tokens_page).post(web::tokens::create_token_web))
        .route("/web/settings/tokens/{id}/rotate", post(web::tokens::rotate_token_web))
        .route("/web/settings/tokens/{id}/revoke", post(web::tokens::revoke_token_web))
        .route("/web/settings/tokens/{id}/scope", post(web::tokens::update_token_web))
        .route("/web/settings/sessions", get(web::tokens::sessions_page))
        .route("/web/settings/sessions/{id}/revoke", post(web::tokens::revoke_session_web))
}
