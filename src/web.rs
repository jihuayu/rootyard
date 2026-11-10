//! Part II Track 1: Web UI & Frontend Security Rendering Layer (`F33` & `F34`).
//! Provides HTML views for repository overview, file tree, bounded blob preview,
//! commit history, commit diffs, branch comparison, Issues, Pull Requests, Reviews,
//! Check Run status panels, atomic Pull Request merge, and RBAC audit logs under
//! `/web/repos/{owner}/{name}...` and `/ui/repos/{owner}/{name}...`.
//!
//! Composition: [`navigation`] owns the login/app/logout, repository listing
//! and the `/web/settings/...` token/session pages, [`repository_pages`] owns the
//! repository pages for both the `/web` and legacy `/ui` prefixes, and
//! [`org_admin`] owns organization administration. [`routes`] merges them and
//! applies one session/Origin/CSRF middleware layer over the final router.
pub mod detail_pagination;
pub mod handlers;
pub mod models;
pub mod native_reads;
pub mod navigation;
pub mod org_admin;
pub mod org_admin_actions;
pub mod org_admin_views;
pub mod repository_listing;
pub mod repository_pages;
pub mod sanitize;
pub mod session;
pub mod session_gc;
pub mod templates;
pub mod tokens;

use crate::AppState;
use axum::Router;
use std::sync::Arc;

/// The Web UI router merged into the default application router.
///
/// Every page is authorized by one `session::middleware` layer (cookie plus
/// Origin/CSRF checks) that is applied over the complete, final router:
/// shared pages, repository Web/UI pages and organization administration. The
/// layer stays outermost of the whole merge (navigation, repository pages and
/// organization administration), exactly once, so no route can bypass it.
pub fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .merge(navigation::routes())
        .merge(repository_pages::router())
        .merge(org_admin::routes())
        .layer(axum::middleware::from_fn_with_state(state, session::middleware))
}
