//! Track 1 extension boundary: Pull Requests, Reviews, Line Review Comments, Check Runs and Branch Rules.
//! Add routes to [`routes`] without modifying `src/lib.rs`.
pub mod checks;
pub mod handlers;
pub mod merge;
pub mod models;
pub mod remote_merge_finalizer;
pub mod review_comment_actions;
pub mod review_comments;
pub mod rules;

use crate::{AppState, forge};
use axum::{Router, routing::{delete, get, post}};
use std::sync::Arc;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/repos/{owner}/{name}/pulls", get(handlers::list_pulls).post(handlers::create_pull))
        .route("/api/repos/{owner}/{name}/pulls/{number}", get(handlers::get_pull).patch(handlers::update_pull))
        .route("/api/repos/{owner}/{name}/pulls/{number}/diff", get(handlers::get_pull_diff))
        .route("/api/repos/{owner}/{name}/pulls/{number}/reviews", get(handlers::list_reviews).post(handlers::create_review))
        .route("/api/repos/{owner}/{name}/pulls/{number}/review-comments", get(review_comments::list_review_comments).post(review_comments::create_review_comment))
        .route("/api/repos/{owner}/{name}/pulls/{number}/review-comments/{comment_number}", get(review_comments::get_review_comment).patch(review_comment_actions::update_review_comment).delete(review_comment_actions::delete_review_comment))
        .route("/api/repos/{owner}/{name}/pulls/{number}/review-comments/{comment_number}/moderate", post(review_comment_actions::moderate_review_comment))
        .route("/api/repos/{owner}/{name}/pulls/{number}/review-comments/{comment_number}/revisions", get(review_comment_actions::list_review_comment_revisions))
        .route("/api/repos/{owner}/{name}/pulls/{number}/labels", get(forge::label_targets::list_pull_labels).put(forge::label_targets::set_pull_labels).post(forge::label_targets::add_pull_labels))
        .route("/api/repos/{owner}/{name}/pulls/{number}/labels/{label}", delete(forge::label_targets::remove_pull_label))
        .route("/api/repos/{owner}/{name}/pulls/{number}/assignees", get(forge::assignees::list_pull_assignees).put(forge::assignees::set_pull_assignees).post(forge::assignees::add_pull_assignees))
        .route("/api/repos/{owner}/{name}/pulls/{number}/assignees/{username}", delete(forge::assignees::remove_pull_assignee))
        .route("/api/repos/{owner}/{name}/pulls/{number}/subscription", get(forge::subscriptions::get_pull_subscription).put(forge::subscriptions::put_pull_subscription).delete(forge::subscriptions::delete_pull_subscription))
        .route("/api/repos/{owner}/{name}/pulls/{number}/checks", get(checks::list_pull_checks))
        .route("/api/repos/{owner}/{name}/pulls/{number}/merge", post(merge::merge_pull))
        .route("/api/repos/{owner}/{name}/checks", post(checks::upsert_check_run))
        .route("/api/repos/{owner}/{name}/commits/{oid}/checks", get(checks::list_commit_checks).post(checks::upsert_commit_check_run))
        .route("/api/repos/{owner}/{name}/commits/{oid}/check-runs", get(checks::list_commit_checks).post(checks::upsert_commit_check_run))
        .route("/api/repos/{owner}/{name}/branch-rules", get(rules::list_branch_rules).post(rules::upsert_branch_rule).put(rules::upsert_branch_rule))
        .route("/api/repos/{owner}/{name}/branch-rules/{*branch}", get(rules::get_branch_rule).put(rules::put_branch_rule_by_path).delete(rules::delete_branch_rule))
}
