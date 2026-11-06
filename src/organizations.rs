//! Durable organization namespaces and inherited repository roles.
pub mod handlers;

use crate::{
    Error, auth,
    db::{self, Identity},
    members::models::Role,
};
use axum::{
    Router,
    routing::{get, post, put},
};
use deadpool_postgres::Transaction;
use std::sync::Arc;
use uuid::Uuid;

pub fn routes() -> Router<Arc<crate::AppState>> {
    Router::new()
        .route("/api/orgs", post(handlers::create_organization))
        .route("/api/orgs/{slug}", get(handlers::get_organization))
        .route("/api/repos/{owner}/{name}/transfer", post(handlers::transfer_ownership))
        .route("/api/orgs/{slug}/members", get(handlers::list_members))
        .route(
            "/api/orgs/{slug}/members/{username}",
            put(handlers::put_member).delete(handlers::delete_member),
        )
        .route(
            "/api/orgs/{slug}/teams",
            get(handlers::list_teams).post(handlers::create_team),
        )
        .route(
            "/api/orgs/{slug}/teams/{team_slug}/members/{username}",
            put(handlers::put_team_member).delete(handlers::delete_team_member),
        )
}

pub async fn authorize_namespace_create(
    tx: &Transaction<'_>,
    actor: &Identity,
    slug: &str,
) -> Result<Uuid, Error> {
    if !db::valid_name(slug) {
        return Err(Error::not_found());
    }
    auth::writable(actor)?;
    auth::verify_token(tx, actor, true).await?;
    let row = tx
        .query_opt(
            "SELECT id, kind, user_id FROM namespaces WHERE slug=$1 FOR SHARE",
            &[&slug],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let id: Uuid = row.get("id");
    let kind: &str = row.get("kind");
    if kind == "user" {
        if row.get::<_, Option<Uuid>>("user_id") == Some(actor.id) {
            return Ok(id);
        }
        return Err(Error::not_found());
    }
    let role = tx
        .query_opt(
            "SELECT role FROM organization_memberships WHERE organization_id=$1 AND user_id=$2",
            &[&id, &actor.id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    if Role::parse(role.get::<_, &str>(0))? < Role::Maintain {
        return Err(Error(
            axum::http::StatusCode::FORBIDDEN,
            "organization maintain role required",
        ));
    }
    Ok(id)
}
