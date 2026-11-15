//! Repository Issue, Search, Collaboration, Subscription, and Notification HTTP API.
#[path = "forge/assignees.rs"]
pub(crate) mod assignees;
#[path = "forge/backend.rs"]
mod backend;
#[path = "forge/comments.rs"]
mod comments;
#[path = "forge/handlers.rs"]
pub(crate) mod handlers;
#[path = "forge/label_targets.rs"]
pub(crate) mod label_targets;
#[path = "forge/labels.rs"]
pub(crate) mod labels;
#[path = "forge/moderation.rs"]
pub(crate) mod moderation;
#[path = "forge/notifications.rs"]
pub(crate) mod notifications;
#[path = "forge/search.rs"]
pub(crate) mod search;
#[path = "forge/subscriptions.rs"]
pub(crate) mod subscriptions;
pub(crate) use backend::build_backend_status;

use crate::AppState;
use axum::{Router, routing::{delete, get, post}};
use std::sync::Arc;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/api/search", get(search::search_global))
        .route("/api/notifications", get(notifications::list_notifications))
        .route("/api/notifications/read-all", post(notifications::mark_all_notifications_read))
        .route("/api/notifications/prune", post(notifications::prune_expired_notifications))
        .route("/api/notifications/{id}/read", post(notifications::mark_notification_read))
        .route("/api/repos/{owner}/{name}/search", get(search::search_repo))
        .route("/api/repos/{owner}/{name}/subscription", get(subscriptions::get_repo_subscription).put(subscriptions::put_repo_subscription).delete(subscriptions::delete_repo_subscription))
        .route("/api/repos/{owner}/{name}/labels", get(labels::list_labels).post(labels::create_label))
        .route("/api/repos/{owner}/{name}/labels/{label}", get(labels::get_label).patch(labels::update_label).delete(labels::delete_label))
        .route("/api/repos/{owner}/{name}/issues", get(handlers::list_issues).post(handlers::create_issue))
        .route("/api/repos/{owner}/{name}/issues/{number}", get(handlers::get_issue).patch(handlers::update_issue))
        .route("/api/repos/{owner}/{name}/issues/{number}/subscription", get(subscriptions::get_issue_subscription).put(subscriptions::put_issue_subscription).delete(subscriptions::delete_issue_subscription))
        .route("/api/repos/{owner}/{name}/issues/{number}/labels", get(label_targets::list_issue_labels).put(label_targets::set_issue_labels).post(label_targets::add_issue_labels))
        .route("/api/repos/{owner}/{name}/issues/{number}/labels/{label}", delete(label_targets::remove_issue_label))
        .route("/api/repos/{owner}/{name}/issues/{number}/assignees", get(assignees::list_issue_assignees).put(assignees::set_issue_assignees).post(assignees::add_issue_assignees))
        .route("/api/repos/{owner}/{name}/issues/{number}/assignees/{username}", delete(assignees::remove_issue_assignee))
        .route("/api/repos/{owner}/{name}/issues/{number}/comments", get(comments::list_comments).post(comments::create_comment))
        .route("/api/repos/{owner}/{name}/issues/{number}/comments/{comment_number}", get(comments::get_comment).patch(comments::update_comment).delete(moderation::delete_issue_comment))
        .route("/api/repos/{owner}/{name}/issues/{number}/comments/{comment_number}/moderate", post(moderation::moderate_issue_comment))
        .route("/api/repos/{owner}/{name}/issues/{number}/comments/{comment_number}/revisions", get(moderation::list_issue_comment_revisions))
        .route("/api/repos/{owner}/{name}/backend", get(backend::get_backend).patch(backend::set_backend))
}

#[cfg(test)]
#[path = "forge/collab_tests.rs"]
mod collab_tests;
#[cfg(test)]
#[path = "forge/tests.rs"]
mod tests;
