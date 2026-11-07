//! Repository audit log recording and cursor-paginated query API (`/api/repos/{owner}/{name}/audit`).
use crate::{
    AppState, Error,
    auth::{self, finish_tx as finish},
    db::Identity,
    members::models::{
        self, AUDIT_FIELDS, AuditEntry, AuditPage, AuditQuery, Role, json, valid_audit_token,
    },
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use deadpool_postgres::Transaction;
use serde_json::Value;
use std::sync::Arc;
use uuid::Uuid;

pub async fn audit_table_installed(tx: &Transaction<'_>) -> Result<bool, Error> {
    let row = tx
        .query_one(
            "SELECT to_regclass('repository_audit_log') IS NOT NULL",
            &[],
        )
        .await
        .map_err(Error::internal)?;
    Ok(row.get(0))
}

pub async fn insert_audit_event(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repository_id: Uuid,
    actor: &Identity,
    action: &str,
    target_type: &str,
    target_name: &str,
    details: Value,
) -> Result<AuditEntry, Error> {
    if !valid_audit_token(action)
        || !valid_audit_token(target_type)
        || target_name.len() > 256
        || target_name.chars().any(char::is_control)
    {
        return Err(Error::bad_request());
    }
    let row = tx
        .query_one(
            &format!(
                "INSERT INTO repository_audit_log \
                 (tenant_id, repository_id, actor_id, actor_name, action, target_type, target_name, details, created_unix) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, (extract(epoch FROM clock_timestamp()))::bigint) \
                 RETURNING {AUDIT_FIELDS}"
            ),
            &[
                &tenant_id,
                &repository_id,
                &actor.id,
                &actor.username,
                &action,
                &target_type,
                &target_name,
                &details,
            ],
        )
        .await
        .map_err(Error::internal)?;
    Ok(AuditEntry::row(&row))
}

pub async fn record_audit_event(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repository_id: Uuid,
    actor: &Identity,
    action: &str,
    target_type: &str,
    target_name: &str,
    details: Value,
) -> Result<Option<AuditEntry>, Error> {
    if !audit_table_installed(tx).await? {
        return Ok(None);
    }
    let entry = insert_audit_event(
        tx,
        tenant_id,
        repository_id,
        actor,
        action,
        target_type,
        target_name,
        details,
    )
    .await?;
    Ok(Some(entry))
}

pub async fn list_audit_events(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    Query(query): Query<AuditQuery>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    models::ensure_schema(&state.pool).await?;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let (after, limit) = query.validate()?;

    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Maintain, crate::token_scopes::RepoAction::MembersRead).await?;

    let rows = tx
        .query(
            &format!(
                "SELECT {AUDIT_FIELDS} FROM repository_audit_log \
                 WHERE tenant_id = $1 \
                   AND repository_id = $2 \
                   AND id > $3 \
                   AND ($4::text IS NULL OR actor_name = $4) \
                   AND ($5::text IS NULL OR action = $5) \
                   AND ($6::bigint IS NULL OR created_unix >= $6) \
                   AND ($7::bigint IS NULL OR created_unix <= $7) \
                 ORDER BY id ASC \
                 LIMIT $8"
            ),
            &[
                &access.owner_id,
                &access.repo_id,
                &after,
                &query.actor,
                &query.action,
                &query.since,
                &query.until,
                &(limit + 1),
            ],
        )
        .await
        .map_err(Error::internal)?;

    let more = rows.len() > limit as usize;
    let items: Vec<AuditEntry> = rows
        .iter()
        .take(limit as usize)
        .map(AuditEntry::row)
        .collect();
    let next_after = if more {
        items.last().map(|e| e.id)
    } else {
        None
    };

    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, AuditPage { items, next_after }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_action_and_target_token_validation() {
        for good in [
            "collaborator.added",
            "collaborator.updated",
            "collaborator.removed",
            "team.created",
            "team.updated",
            "team.deleted",
            "team_member.added",
            "team_member.removed",
            "pull_review.submitted",
            "branch_rule.upserted",
        ] {
            assert!(valid_audit_token(good));
        }
        for bad in [
            "",
            "spaces not allowed",
            "slash/not/allowed",
            &"x".repeat(65),
        ] {
            assert!(!valid_audit_token(bad));
        }
    }
}
