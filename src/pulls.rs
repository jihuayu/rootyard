//! Track 1 extension boundary: Pull Requests, Reviews, Check Runs and Branch Rules.
//! Add routes to [`routes`] without modifying `src/lib.rs`.
pub mod checks;
pub mod handlers;
pub mod merge;
pub mod models;
pub mod rules;

use crate::AppState;
use axum::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/repos/{owner}/{name}/pulls",
            get(handlers::list_pulls).post(handlers::create_pull),
        )
        .route(
            "/api/repos/{owner}/{name}/pulls/{number}",
            get(handlers::get_pull).patch(handlers::update_pull),
        )
        .route(
            "/api/repos/{owner}/{name}/pulls/{number}/diff",
            get(handlers::get_pull_diff),
        )
        .route(
            "/api/repos/{owner}/{name}/pulls/{number}/reviews",
            get(handlers::list_reviews).post(handlers::create_review),
        )
        .route(
            "/api/repos/{owner}/{name}/pulls/{number}/checks",
            get(checks::list_pull_checks),
        )
        .route(
            "/api/repos/{owner}/{name}/pulls/{number}/merge",
            post(merge::merge_pull),
        )
        .route(
            "/api/repos/{owner}/{name}/checks",
            post(checks::upsert_check_run),
        )
        .route(
            "/api/repos/{owner}/{name}/commits/{oid}/checks",
            get(checks::list_commit_checks).post(checks::upsert_commit_check_run),
        )
        .route(
            "/api/repos/{owner}/{name}/commits/{oid}/check-runs",
            get(checks::list_commit_checks).post(checks::upsert_commit_check_run),
        )
        .route(
            "/api/repos/{owner}/{name}/branch-rules",
            get(rules::list_branch_rules)
                .post(rules::upsert_branch_rule)
                .put(rules::upsert_branch_rule),
        )
        .route(
            "/api/repos/{owner}/{name}/branch-rules/{*branch}",
            get(rules::get_branch_rule)
                .put(rules::put_branch_rule_by_path)
                .delete(rules::delete_branch_rule),
        )
}
