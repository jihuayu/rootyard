//! Part II Track 1: Web UI & Frontend Security Rendering Layer (`F33` & `F34`).
//! Provides HTML views for repository overview, file tree, bounded blob preview,
//! commit history, commit diffs, branch comparison, Issues, Pull Requests, Reviews,
//! Check Run status panels, atomic Pull Request merge, and RBAC audit logs under
//! `/web/repos/{owner}/{name}...` and `/ui/repos/{owner}/{name}...`.
pub mod handlers;
pub mod models;
pub mod native_reads;
pub mod repository_listing;
pub mod sanitize;
pub mod session;
pub mod session_gc;
pub mod templates;
pub mod tokens;

use crate::AppState;
use axum::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;

pub fn routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/web/login", get(session::login_page).post(session::login))
        .route("/web/app.js", get(session::app_js))
        .route("/web/logout", post(session::logout))
        .route("/web/repos", get(repository_listing::discover))
        .route("/web/repos/{owner}/{name}", get(handlers::repo_overview))
        .route("/web/repos/{owner}/{name}/tree", get(handlers::tree_view))
        .route("/web/repos/{owner}/{name}/tree/{oid}", get(handlers::tree_by_oid_view))
        .route("/web/repos/{owner}/{name}/blob", get(handlers::blob_view))
        .route("/web/repos/{owner}/{name}/blob/{oid}", get(handlers::blob_by_oid_view))
        .route("/web/repos/{owner}/{name}/commits", get(handlers::commits_view))
        .route("/web/repos/{owner}/{name}/commits/{oid}", get(handlers::commit_detail_view))
        .route("/web/repos/{owner}/{name}/commits/{oid}/checks", get(handlers::commit_checks_view))
        .route("/web/repos/{owner}/{name}/compare", get(handlers::compare_view))
        .route("/web/repos/{owner}/{name}/issues", get(handlers::issues_list_view).post(handlers::create_issue_web))
        .route(
            "/web/repos/{owner}/{name}/issues/{number}",
            get(handlers::issue_detail_view).post(handlers::update_issue_web).patch(handlers::update_issue_web),
        )
        .route("/web/repos/{owner}/{name}/issues/{number}/comments", post(handlers::create_issue_comment_web))
        .route("/web/repos/{owner}/{name}/pulls", get(handlers::pulls_list_view).post(handlers::create_pull_web))
        .route(
            "/web/repos/{owner}/{name}/pulls/{number}",
            get(handlers::pull_detail_view).post(handlers::update_pull_web).patch(handlers::update_pull_web),
        )
        .route("/web/repos/{owner}/{name}/pulls/{number}/diff", get(handlers::pull_diff_view))
        .route(
            "/web/repos/{owner}/{name}/pulls/{number}/reviews",
            get(handlers::pull_reviews_view).post(handlers::create_review_web),
        )
        .route("/web/repos/{owner}/{name}/pulls/{number}/checks", get(handlers::pull_checks_view))
        .route("/web/repos/{owner}/{name}/pulls/{number}/merge", post(handlers::merge_pull_web))
        .route("/web/repos/{owner}/{name}/audit", get(handlers::audit_view))
        .route("/ui/repos/{owner}/{name}", get(handlers::repo_overview))
        .route("/ui/repos/{owner}/{name}/tree", get(handlers::tree_view))
        .route("/ui/repos/{owner}/{name}/tree/{oid}", get(handlers::tree_by_oid_view))
        .route("/ui/repos/{owner}/{name}/blob", get(handlers::blob_view))
        .route("/ui/repos/{owner}/{name}/blob/{oid}", get(handlers::blob_by_oid_view))
        .route("/ui/repos/{owner}/{name}/commits", get(handlers::commits_view))
        .route("/ui/repos/{owner}/{name}/commits/{oid}", get(handlers::commit_detail_view))
        .route("/ui/repos/{owner}/{name}/commits/{oid}/checks", get(handlers::commit_checks_view))
        .route("/ui/repos/{owner}/{name}/compare", get(handlers::compare_view))
        .route("/ui/repos/{owner}/{name}/issues", get(handlers::issues_list_view).post(handlers::create_issue_web))
        .route(
            "/ui/repos/{owner}/{name}/issues/{number}",
            get(handlers::issue_detail_view).post(handlers::update_issue_web).patch(handlers::update_issue_web),
        )
        .route("/ui/repos/{owner}/{name}/issues/{number}/comments", post(handlers::create_issue_comment_web))
        .route("/ui/repos/{owner}/{name}/pulls", get(handlers::pulls_list_view).post(handlers::create_pull_web))
        .route(
            "/ui/repos/{owner}/{name}/pulls/{number}",
            get(handlers::pull_detail_view).post(handlers::update_pull_web).patch(handlers::update_pull_web),
        )
        .route("/ui/repos/{owner}/{name}/pulls/{number}/diff", get(handlers::pull_diff_view))
        .route(
            "/ui/repos/{owner}/{name}/pulls/{number}/reviews",
            get(handlers::pull_reviews_view).post(handlers::create_review_web),
        )
        .route("/ui/repos/{owner}/{name}/pulls/{number}/checks", get(handlers::pull_checks_view))
        .route("/ui/repos/{owner}/{name}/pulls/{number}/merge", post(handlers::merge_pull_web))
        .route("/ui/repos/{owner}/{name}/audit", get(handlers::audit_view))
        .route("/web/settings/tokens", get(tokens::tokens_page).post(tokens::create_token_web))
        .route("/web/settings/tokens/{id}/rotate", post(tokens::rotate_token_web))
        .route("/web/settings/tokens/{id}/revoke", post(tokens::revoke_token_web))
        .route("/web/settings/tokens/{id}/scope", post(tokens::update_token_web))
        .route("/web/settings/sessions", get(tokens::sessions_page))
        .route("/web/settings/sessions/{id}/revoke", post(tokens::revoke_session_web))
        .layer(axum::middleware::from_fn_with_state(state, session::middleware))
}
