//! Grant loading, writing and current-role validation helpers.
//!
//! Kept separate from `service.rs` so the transaction/lock protocol and the
//! grant SQL stay individually reviewable. Nothing here inserts a grant that
//! the actor's current role could not hold, and nothing widens an existing
//! grant set.

use crate::{
    Error,
    db::Identity,
    members::{models::Role, rbac},
    token_management::models,
    token_scopes::{NamespaceAction, RepoAction},
};
use axum::http::StatusCode;
use deadpool_postgres::Transaction;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub type RepositoryGrants = BTreeMap<Uuid, BTreeSet<RepoAction>>;
pub type NamespaceGrants = BTreeMap<Uuid, BTreeSet<NamespaceAction>>;

fn conflict(message: &'static str) -> Error {
    Error(StatusCode::CONFLICT, message)
}

pub async fn load_grants(
    tx: &Transaction<'_>,
    token_id: Uuid,
) -> Result<(RepositoryGrants, NamespaceGrants), Error> {
    let mut repositories: RepositoryGrants = BTreeMap::new();
    let rows = tx
        .query("SELECT repository_id, action FROM token_repository_scopes WHERE token_id = $1", &[&token_id])
        .await
        .map_err(Error::internal)?;
    for row in rows {
        let repository_id: Uuid = row.get(0);
        let action = RepoAction::parse(row.get::<_, &str>(1))
            .ok_or_else(|| Error::internal("token scope store unavailable"))?;
        repositories.entry(repository_id).or_default().insert(action);
    }
    let mut namespaces: NamespaceGrants = BTreeMap::new();
    let rows = tx
        .query("SELECT organization_id, action FROM token_namespace_scopes WHERE token_id = $1", &[&token_id])
        .await
        .map_err(Error::internal)?;
    for row in rows {
        let organization_id: Uuid = row.get(0);
        let action = NamespaceAction::parse(row.get::<_, &str>(1))
            .ok_or_else(|| Error::internal("token scope store unavailable"))?;
        namespaces.entry(organization_id).or_default().insert(action);
    }
    Ok((repositories, namespaces))
}

pub async fn insert_grants(
    tx: &Transaction<'_>,
    token_id: Uuid,
    repositories: &RepositoryGrants,
    namespaces: &NamespaceGrants,
) -> Result<(), Error> {
    for (repository_id, actions) in repositories {
        for action in actions {
            let name = action.as_str();
            tx.execute(
                "INSERT INTO token_repository_scopes(token_id, repository_id, action) VALUES ($1, $2, $3)",
                &[&token_id, repository_id, &name],
            )
            .await
            .map_err(Error::internal)?;
        }
    }
    for (organization_id, actions) in namespaces {
        for action in actions {
            let name = action.as_str();
            tx.execute(
                "INSERT INTO token_namespace_scopes(token_id, organization_id, action) VALUES ($1, $2, $3)",
                &[&token_id, organization_id, &name],
            )
            .await
            .map_err(Error::internal)?;
        }
    }
    Ok(())
}

pub async fn replace_grants(
    tx: &Transaction<'_>,
    token_id: Uuid,
    repositories: &RepositoryGrants,
    namespaces: &NamespaceGrants,
) -> Result<(), Error> {
    tx.execute("DELETE FROM token_repository_scopes WHERE token_id = $1", &[&token_id])
        .await
        .map_err(Error::internal)?;
    tx.execute("DELETE FROM token_namespace_scopes WHERE token_id = $1", &[&token_id])
        .await
        .map_err(Error::internal)?;
    insert_grants(tx, token_id, repositories, namespaces).await
}

/// Validate one repository grant against the actor's *current* role.
///
/// A grant can only narrow the RBAC decision, never widen it, and a repository
/// the actor cannot see is reported as not found instead of leaking its
/// existence through a different status code.
pub async fn validate_repository_grant(
    tx: &Transaction<'_>,
    actor: &Identity,
    repository_id: Uuid,
    actions: &BTreeSet<RepoAction>,
) -> Result<(), Error> {
    let row = tx
        .query_opt("SELECT owner_id, state FROM repositories WHERE id = $1", &[&repository_id])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let owner_id: Uuid = row.get(0);
    let state: String = row.get(1);
    let Some(role) = rbac::resolve_effective_role(&**tx, repository_id, owner_id, actor.id).await? else {
        return Err(Error::not_found());
    };
    for action in actions {
        if role < models::repository_min_role(*action) {
            return Err(Error(
                StatusCode::FORBIDDEN,
                "current repository role is insufficient for a granted action",
            ));
        }
    }
    if state != "ready" {
        return Err(conflict("repository is not ready"));
    }
    Ok(())
}

/// Validate one organisation grant against current membership. Organisation
/// grants live in their own table and can never turn into repository grants or
/// account-wide administration.
pub async fn validate_namespace_grant(
    tx: &Transaction<'_>,
    actor: &Identity,
    organization_id: Uuid,
    actions: &BTreeSet<NamespaceAction>,
) -> Result<(), Error> {
    tx.query_opt("SELECT id FROM organizations WHERE id = $1", &[&organization_id])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let row = tx
        .query_opt(
            "SELECT role FROM organization_memberships WHERE organization_id = $1 AND user_id = $2",
            &[&organization_id, &actor.id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let role = Role::parse(row.get::<_, &str>(0))?;
    for action in actions {
        if role < models::namespace_min_role(*action) {
            return Err(Error(
                StatusCode::FORBIDDEN,
                "current organisation role is insufficient for a granted action",
            ));
        }
    }
    Ok(())
}
