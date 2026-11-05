//! Track B extension boundary: Collaborator & Team 5-Role RBAC Hierarchy,
//! Multi-Reviewer PR Self-Approval Policy, and Paginated Repository Audit Query API.
pub mod audit;
pub mod models;
pub mod rbac;

use crate::AppState;
use axum::{
    Router,
    routing::{get, put},
};
use std::sync::Arc;

pub const MIGRATION_050_SQL: &str = include_str!("members/050_members_rbac.sql");

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/repos/{owner}/{name}/collaborators",
            get(rbac::list_collaborators).post(rbac::upsert_collaborator),
        )
        .route(
            "/api/repos/{owner}/{name}/collaborators/{username}",
            get(rbac::get_collaborator)
                .put(rbac::put_collaborator)
                .patch(rbac::put_collaborator)
                .delete(rbac::remove_collaborator),
        )
        .route(
            "/api/repos/{owner}/{name}/teams",
            get(rbac::list_teams).post(rbac::create_team),
        )
        .route(
            "/api/repos/{owner}/{name}/teams/{team_slug}",
            get(rbac::get_team)
                .patch(rbac::update_team)
                .delete(rbac::delete_team),
        )
        .route(
            "/api/repos/{owner}/{name}/teams/{team_slug}/members",
            get(rbac::list_team_members).post(rbac::add_team_member),
        )
        .route(
            "/api/repos/{owner}/{name}/teams/{team_slug}/members/{username}",
            put(rbac::put_team_member).delete(rbac::remove_team_member),
        )
        .route(
            "/api/repos/{owner}/{name}/permissions/{username}",
            get(rbac::get_effective_permission),
        )
        .route(
            "/api/repos/{owner}/{name}/audit",
            get(audit::list_audit_events),
        )
}
