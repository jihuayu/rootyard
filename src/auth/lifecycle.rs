//! Repository lifecycle availability enforcement (`deleted_at`, `archived_at`,
//! backend transitions, and active ownership transfers).
use super::{Role, authorize_repo_scope, verify_token};
use crate::{Error, db, members::models::RepoAccess, token_scopes::RepoAction};
use axum::http::StatusCode;
use deadpool_postgres::Transaction;
use tokio_postgres::GenericClient;
use uuid::Uuid;

pub(super) async fn authorize_repo_lifecycle_inner(
    tx: &Transaction<'_>,
    actor: &db::Identity,
    owner: &str,
    name: &str,
    min_role: Role,
    action: RepoAction,
    allow_deleted: bool,
    enforce_lifecycle_fence: bool,
) -> Result<RepoAccess, Error> {
    if !db::valid_name(owner) || !db::valid_name(name) {
        return Err(Error::not_found());
    }
    tx.query_opt(
        "SELECT t.id FROM tokens t JOIN users u ON u.id=t.user_id WHERE t.id=$1 AND t.user_id=$2 AND u.username=$3 FOR SHARE OF t,u",
        &[&actor.token_id, &actor.id, &actor.username],
    )
    .await
    .map_err(Error::internal)?
    .ok_or_else(Error::unauthorized)?;
    verify_token(tx, actor, action.is_mutating()).await?;

    let row = tx
        .query_opt(
            "SELECT r.id, r.owner_id, r.state, r.transition_state, r.archived_at IS NOT NULL AS archived, r.deleted_at IS NOT NULL AS deleted \
             FROM repositories r JOIN namespaces ns ON ns.id = r.owner_id WHERE ns.slug = $1 AND r.name = $2 FOR SHARE OF r",
            &[&owner, &name],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let repo_id: Uuid = row.get("id");
    let owner_id: Uuid = row.get("owner_id");
    let state: String = row.get("state");
    let transition_state: String = row.get("transition_state");
    let archived: bool = row.get("archived");
    let deleted: bool = row.get("deleted");
    if deleted && !allow_deleted {
        return Err(Error::not_found());
    }
    let Some((effective_role, _, _)) =
        crate::members::rbac::resolve_effective_role(&**tx, repo_id, owner_id, actor.id).await?
    else {
        return Err(Error::not_found());
    };
    if deleted && effective_role < min_role {
        return Err(Error::not_found());
    }
    if effective_role < min_role {
        return Err(Error(StatusCode::FORBIDDEN, "insufficient repository role"));
    }
    if state != "ready" {
        return Err(Error(StatusCode::CONFLICT, "repository is not ready"));
    }
    if enforce_lifecycle_fence {
        enforce_availability(&**tx, repo_id, deleted, archived, &transition_state, action.is_mutating()).await?;
    }
    authorize_repo_scope(tx, actor, repo_id, action).await?;
    Ok(RepoAccess { repo_id, owner_id, role: effective_role })
}

pub(crate) async fn has_active_transfer<C: GenericClient + Sync>(
    client: &C,
    repo_id: Uuid,
) -> Result<bool, Error> {
    let row = client
        .query_one(
            "SELECT EXISTS ( \
                SELECT 1 FROM repository_transfers \
                WHERE repository_id = $1 \
                  AND state IN ('draining', 'copying_remote', 'rekeying_db', 'revoking_legacy', 'rolling_back') \
            )",
            &[&repo_id],
        )
        .await
        .map_err(Error::internal)?;
    Ok(row.get(0))
}

pub(crate) async fn enforce_availability<C: GenericClient + Sync>(
    client: &C,
    repo_id: Uuid,
    deleted: bool,
    archived: bool,
    transition_state: &str,
    mutating: bool,
) -> Result<(), Error> {
    if deleted {
        return Err(Error::not_found());
    }
    if mutating {
        if archived {
            return Err(Error(StatusCode::FORBIDDEN, "repository is archived and read-only"));
        }
        if transition_state != "stable" {
            return Err(Error(StatusCode::CONFLICT, "repository backend transition in progress"));
        }
        if has_active_transfer(client, repo_id).await? {
            return Err(Error(StatusCode::CONFLICT, "repository ownership transfer in progress"));
        }
    }
    Ok(())
}

pub(super) async fn check_repo_availability_by_id<C: GenericClient + Sync>(
    client: &C,
    repo_id: Uuid,
    mutating: bool,
) -> Result<(), Error> {
    let row = client
        .query_opt(
            "SELECT deleted_at IS NOT NULL, archived_at IS NOT NULL, transition_state \
             FROM repositories WHERE id = $1",
            &[&repo_id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    enforce_availability(client, repo_id, row.get(0), row.get(1), row.get::<_, &str>(2), mutating).await
}
