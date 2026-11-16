//! HTTP handlers for repository lifecycle inspection, archive, unarchive, rename,
//! and transfer status.
use super::{
    lifecycle::{
        ArchiveRepoInput, LifecycleAction, RenameRepoInput, RepositoryAliasView, RepositoryLifecycleView,
        UnarchiveRepoInput, check_cas_version, enforce_mutating_availability, request_sha256,
        validate_expected_version, validate_rename_input,
    },
    lifecycle_ops::{decide_idempotent_cas, json_no_store, lifecycle_action_audit_name, require_idempotency_key_valid},
    transfer_db::load_transfer_status,
};
use crate::{AppState, Error, auth, db::Identity, members::models::Role, token_scopes::RepoAction};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use deadpool_postgres::Transaction;
use serde::Serialize;
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;

pub(super) type Res = Result<Response, Error>;

pub(super) struct LockedRepo {
    pub(super) id: Uuid,
    pub(super) owner_id: Uuid,
    pub(super) owner: String,
    pub(super) name: String,
    pub(super) version: i64,
    pub(super) storage_backend: String,
    pub(super) transition_state: String,
    pub(super) archived: bool,
    pub(super) deleted: bool,
    pub(super) gc_fenced: bool,
    pub(super) transfer_in_progress: bool,
}

pub(super) async fn load_lifecycle_view(tx: &Transaction<'_>, repo_id: Uuid) -> Result<RepositoryLifecycleView, Error> {
    let row = tx
        .query_opt(
            "SELECT r.id, r.owner_id, n.slug, r.name, r.version, r.state, r.storage_backend, \
                    r.storage_generation, r.object_format, r.archived_at IS NOT NULL, r.archived_at::text, \
                    r.deleted_at IS NOT NULL, r.deleted_at::text, r.purge_after::text \
             FROM repositories r JOIN namespaces n ON n.id = r.owner_id WHERE r.id = $1",
            &[&repo_id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;

    let alias_rows = tx
        .query(
            "SELECT n.slug, a.alias_name, a.created_at::text \
             FROM repository_aliases a JOIN namespaces n ON n.id = a.alias_owner_id \
             WHERE a.repository_id = $1 ORDER BY a.created_at ASC",
            &[&repo_id],
        )
        .await
        .map_err(Error::internal)?;

    let aliases = alias_rows
        .into_iter()
        .map(|a| RepositoryAliasView { owner: a.get(0), name: a.get(1), created_at: a.get(2) })
        .collect();

    Ok(RepositoryLifecycleView {
        id: row.get(0),
        owner_id: row.get(1),
        owner: row.get(2),
        name: row.get(3),
        version: row.get(4),
        state: row.get(5),
        storage_backend: row.get(6),
        storage_generation: row.get(7),
        object_format: row.get(8),
        archived: row.get(9),
        archived_at: row.get(10),
        deleted: row.get(11),
        deleted_at: row.get(12),
        purge_after: row.get(13),
        aliases,
    })
}

pub(super) async fn lock_repo_for_lifecycle(
    tx: &Transaction<'_>,
    repo_id: Uuid,
    actor: &Identity,
    action: LifecycleAction,
    idem_key: Option<&str>,
    req_hash: &str,
    expected_version: i64,
) -> Result<Result<LockedRepo, (StatusCode, Value)>, Error> {
    let row = tx
        .query_opt(
            "SELECT r.id, r.owner_id, n.slug, r.name, r.version, r.storage_backend, r.transition_state, \
                    r.archived_at IS NOT NULL, r.deleted_at IS NOT NULL, \
                    (r.gc_owner IS NOT NULL AND r.gc_lease_until IS NOT NULL AND r.gc_lease_until > clock_timestamp()), \
                    EXISTS (SELECT 1 FROM repository_transfers t WHERE t.repository_id = r.id AND t.state NOT IN ('completed','rolled_back','failed')) \
             FROM repositories r JOIN namespaces n ON n.id = r.owner_id WHERE r.id = $1 FOR UPDATE OF r",
            &[&repo_id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;

    let locked = LockedRepo {
        id: row.get(0),
        owner_id: row.get(1),
        owner: row.get(2),
        name: row.get(3),
        version: row.get(4),
        storage_backend: row.get(5),
        transition_state: row.get(6),
        archived: row.get(7),
        deleted: row.get(8),
        gc_fenced: row.get(9),
        transfer_in_progress: row.get(10),
    };

    if let Some(key) = idem_key {
        let existing = tx
            .query_opt(
                "SELECT request_sha256, response_status, response_body FROM repository_lifecycle_idempotency \
                 WHERE repository_id = $1 AND actor_id = $2 AND action = $3 AND idempotency_key = $4",
                &[&repo_id, &actor.id, &action.as_str(), &key],
            )
            .await
            .map_err(Error::internal)?;
        let stored_row = existing.as_ref().and_then(|r| {
            let hash: &str = r.get(0);
            let status: i32 = r.get(1);
            let body: Value = r.get(2);
            i16::try_from(status).ok().map(|s| (hash, s, body))
        });
        let stored_ref = stored_row.as_ref().map(|(h, s, b)| (*h, *s, b));
        if let Some(replay) = decide_idempotent_cas(stored_ref, req_hash, locked.version, expected_version)? {
            return Ok(Err(replay));
        }
    }

    check_cas_version(locked.version, expected_version)?;
    Ok(Ok(locked))
}

pub(super) async fn store_idempotency<T: Serialize>(
    tx: &Transaction<'_>,
    repo_id: Uuid,
    actor_id: Uuid,
    action: LifecycleAction,
    idem_key: Option<&str>,
    req_hash: &str,
    status: StatusCode,
    payload: &T,
) -> Result<(), Error> {
    let Some(key) = idem_key else {
        return Ok(());
    };
    let val = serde_json::to_value(payload).map_err(Error::internal)?;
    tx.execute(
        "INSERT INTO repository_lifecycle_idempotency \
         (repository_id, actor_id, action, idempotency_key, request_sha256, response_status, response_body) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT DO NOTHING",
        &[&repo_id, &actor_id, &action.as_str(), &key, &req_hash, &i32::from(status.as_u16()), &val],
    )
    .await
    .map_err(Error::internal)?;
    Ok(())
}

pub async fn get_lifecycle(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Res {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access =
        auth::authorize_repo_lifecycle(&tx, &actor, &owner, &name, Role::Admin, RepoAction::RepoAdmin, true).await?;
    let view = load_lifecycle_view(&tx, access.repo_id).await?;
    auth::finish_tx(tx, &actor, false).await?;
    json_no_store(StatusCode::OK, &view)
}

pub async fn get_transfer(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Res {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access =
        auth::authorize_repo_lifecycle(&tx, &actor, &owner, &name, Role::Admin, RepoAction::RepoAdmin, false).await?;
    let transfer = load_transfer_status(&tx, access.repo_id).await?.ok_or_else(Error::not_found)?;
    auth::finish_tx(tx, &actor, false).await?;
    json_no_store(StatusCode::OK, &transfer)
}

pub async fn archive(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<ArchiveRepoInput>,
) -> Res {
    toggle_archive(&state, &owner, &name, &headers, input.expected_version, true, &input).await
}

pub async fn unarchive(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<UnarchiveRepoInput>,
) -> Res {
    toggle_archive(&state, &owner, &name, &headers, input.expected_version, false, &input).await
}

async fn toggle_archive<T: Serialize>(
    state: &Arc<AppState>,
    owner: &str,
    name: &str,
    headers: &HeaderMap,
    expected_version: i64,
    target_archived: bool,
    raw_input: &T,
) -> Res {
    validate_expected_version(expected_version)?;
    let actor = auth::authenticate(&state.pool, headers).await?;
    let idem_key = require_idempotency_key_valid(headers)?;
    let req_hash = request_sha256(raw_input)?;
    let action = if target_archived { LifecycleAction::Archive } else { LifecycleAction::Unarchive };

    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access =
        auth::authorize_repo_lifecycle(&tx, &actor, owner, name, Role::Admin, RepoAction::RepoAdmin, false).await?;

    let locked = match lock_repo_for_lifecycle(
        &tx,
        access.repo_id,
        &actor,
        action,
        idem_key.as_deref(),
        &req_hash,
        expected_version,
    )
    .await?
    {
        Ok(repo) => repo,
        Err((status, body)) => {
            auth::finish_tx(tx, &actor, false).await?;
            return json_no_store(status, &body);
        }
    };
    enforce_mutating_availability(
        locked.deleted,
        false,
        locked.transfer_in_progress || locked.transition_state != "stable" || locked.gc_fenced,
    )?;
    if target_archived && locked.archived {
        return Err(Error(StatusCode::CONFLICT, "repository is already archived"));
    }
    if !target_archived && !locked.archived {
        return Err(Error(StatusCode::CONFLICT, "repository is not archived"));
    }

    if target_archived {
        tx.execute(
            "UPDATE repositories SET archived_at = clock_timestamp(), archived_by = $2, version = version + 1 WHERE id = $1",
            &[&locked.id, &actor.id],
        )
        .await
        .map_err(Error::internal)?;
    } else {
        tx.execute(
            "UPDATE repositories SET archived_at = NULL, archived_by = NULL, version = version + 1 WHERE id = $1",
            &[&locked.id],
        )
        .await
        .map_err(Error::internal)?;
    }

    crate::members::audit::record_audit_event(
        &tx,
        locked.owner_id,
        locked.id,
        &actor,
        lifecycle_action_audit_name(action),
        "repository",
        &locked.name,
        json!({"version": locked.version + 1}),
    )
    .await?;

    let view = load_lifecycle_view(&tx, locked.id).await?;
    store_idempotency(&tx, locked.id, actor.id, action, idem_key.as_deref(), &req_hash, StatusCode::OK, &view).await?;
    auth::finish_tx(tx, &actor, true).await?;
    json_no_store(StatusCode::OK, &view)
}

pub async fn rename(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<RenameRepoInput>,
) -> Res {
    validate_expected_version(input.expected_version)?;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let idem_key = require_idempotency_key_valid(&headers)?;
    let req_hash = request_sha256(&input)?;

    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access =
        auth::authorize_repo_lifecycle(&tx, &actor, &owner, &name, Role::Admin, RepoAction::RepoAdmin, false).await?;

    let locked = match lock_repo_for_lifecycle(
        &tx,
        access.repo_id,
        &actor,
        LifecycleAction::Rename,
        idem_key.as_deref(),
        &req_hash,
        input.expected_version,
    )
    .await?
    {
        Ok(repo) => repo,
        Err((status, body)) => {
            auth::finish_tx(tx, &actor, false).await?;
            return json_no_store(status, &body);
        }
    };
    enforce_mutating_availability(
        locked.deleted,
        locked.archived,
        locked.transfer_in_progress || locked.transition_state != "stable" || locked.gc_fenced,
    )?;
    if locked.storage_backend == "pg_refstore" {
        return Err(Error(StatusCode::CONFLICT, "pg_refstore repositories cannot be renamed"));
    }
    validate_rename_input(&locked.name, &input)?;

    let collision = tx
        .query_opt(
            "SELECT 1 FROM repositories WHERE owner_id = $1 AND name = $2 AND id <> $3 \
             UNION ALL \
             SELECT 1 FROM repository_aliases WHERE alias_owner_id = $1 AND alias_name = $2 AND repository_id <> $3 \
             LIMIT 1",
            &[&locked.owner_id, &input.new_name, &locked.id],
        )
        .await
        .map_err(Error::internal)?
        .is_some();
    if collision {
        return Err(Error(StatusCode::CONFLICT, "target repository name or alias is already taken"));
    }

    tx.execute(
        "DELETE FROM repository_aliases WHERE alias_owner_id = $1 AND alias_name = $2 AND repository_id = $3",
        &[&locked.owner_id, &input.new_name, &locked.id],
    )
    .await
    .map_err(Error::internal)?;
    tx.execute(
        "UPDATE repositories SET name = $2, version = version + 1 WHERE id = $1",
        &[&locked.id, &input.new_name],
    )
    .await
    .map_err(Error::internal)?;
    tx.execute("UPDATE workspaces SET repository_name = $2 WHERE repository_id = $1", &[&locked.id, &input.new_name])
        .await
        .map_err(Error::internal)?;
    tx.execute(
        "UPDATE workspace_namespace_mounts SET repository_name = $2 WHERE repository_id = $1",
        &[&locked.id, &input.new_name],
    )
    .await
    .map_err(Error::internal)?;
    tx.execute(
        "UPDATE workspace_changeset_steps SET repository_name = $2 WHERE repository_id = $1",
        &[&locked.id, &input.new_name],
    )
    .await
    .map_err(Error::internal)?;

    let alias_id = Uuid::new_v4();
    tx.execute(
        "INSERT INTO repository_aliases (id, alias_owner_id, alias_name, repository_id, created_by, reason) \
         VALUES ($1, $2, $3, $4, $5, 'rename') ON CONFLICT (alias_owner_id, alias_name) DO NOTHING",
        &[&alias_id, &locked.owner_id, &locked.name, &locked.id, &actor.id],
    )
    .await
    .map_err(Error::internal)?;

    crate::members::audit::record_audit_event(
        &tx,
        locked.owner_id,
        locked.id,
        &actor,
        lifecycle_action_audit_name(LifecycleAction::Rename),
        "repository",
        &input.new_name,
        json!({"owner": locked.owner, "old_name": locked.name, "new_name": input.new_name}),
    )
    .await?;

    let view = load_lifecycle_view(&tx, locked.id).await?;
    store_idempotency(
        &tx,
        locked.id,
        actor.id,
        LifecycleAction::Rename,
        idem_key.as_deref(),
        &req_hash,
        StatusCode::OK,
        &view,
    )
    .await?;
    auth::finish_tx(tx, &actor, true).await?;
    json_no_store(StatusCode::OK, &view)
}
