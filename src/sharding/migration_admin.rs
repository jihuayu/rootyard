//! Operator-facing migration administration: abort a drained operation
//! without promoting it, and list durable operations for resumption.
use super::AbortInput;
use crate::{
    AppState, Error,
    auth::{self, Role, finish_tx as finish},
    members::audit::record_audit_event,
    sharding::{
        locks,
        models::{REPO_ROUTE_FIELDS, RepoShardRoute, VolumeFenceMarker, conflict, json, unix_now},
        replication::{self},
        router::load_or_init_repo_route,
        security::require_operator,
        transitions,
        transport::{self},
    },
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde_json::json as sjson;
use std::sync::Arc;
use uuid::Uuid;

pub async fn abort_migration(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<AbortInput>,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Admin).await?;
    require_operator(&tx, &actor).await?;
    let route = load_or_init_repo_route(&tx, access.owner_id, access.repo_id).await?;
    finish(tx, &actor, false).await?;
    if transport::node_id()?.as_deref() != Some(route.primary_node_id.as_str()) {
        return Err(conflict("migration abort must run on the source storage node"));
    }
    let _migration = locks::migration(&state, access.repo_id).await?;
    let mutation = locks::exclusive(&state, access.repo_id).await?;
    mutation.ensure_active()?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, true).await?;
    require_operator(&tx, &actor).await?;
    let generation: i64 = tx
        .query_one("SELECT storage_generation FROM repositories WHERE id=$1 FOR UPDATE", &[&access.repo_id])
        .await
        .map_err(Error::internal)?
        .get(0);
    let route_sql =
        format!("SELECT {REPO_ROUTE_FIELDS} FROM repository_shard_routes WHERE repository_id=$1 FOR UPDATE");
    let route = RepoShardRoute::row(&tx.query_one(&route_sql, &[&access.repo_id]).await.map_err(Error::internal)?);
    if input.expected_route_epoch.is_some_and(|epoch| epoch != route.route_epoch) {
        return Err(conflict("migration abort route epoch mismatch"));
    }
    let op = tx
        .query_opt(
            "SELECT source_node_id,state,source_route_epoch FROM shard_replication_operations \
             WHERE id=$1 AND repository_id=$2 FOR UPDATE",
            &[&input.operation_id, &access.repo_id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let source: String = op.get(0);
    let op_state: String = op.get(1);
    let op_epoch: i64 = op.get(2);
    if source != route.primary_node_id {
        return Err(conflict("migration abort source mismatch"));
    }
    if op_state == "aborted" {
        finish(tx, &actor, false).await?;
        return Ok(json(
            StatusCode::OK,
            sjson!({
                "operation_id": input.operation_id,
                "repository_id": access.repo_id,
                "state": "aborted",
            }),
        ));
    }
    if op_state == "completed" {
        return Err(conflict("migration operation is already terminal"));
    }
    if route.draining && op_epoch != route.route_epoch {
        return Err(conflict("migration operation epoch differs from the drained route"));
    }
    if route.draining {
        let new_epoch = route.route_epoch + 1;
        let new_token = route.fencing_token.max(new_epoch) + 1;
        let upd = format!(
            "UPDATE repository_shard_routes SET route_epoch=$2, fencing_token=$3, fenced_epoch=$4, \
             required_generation=$5, draining=false, read_only_degraded=false, degraded_reason='', \
             version=version+1, updated_at=clock_timestamp() WHERE repository_id=$1 \
             RETURNING {REPO_ROUTE_FIELDS}"
        );
        let updated = RepoShardRoute::row(
            &tx.query_one(&upd, &[&access.repo_id, &new_epoch, &new_token, &route.route_epoch, &generation])
                .await
                .map_err(Error::internal)?,
        );
        crate::storage::ref_admission::fence_epoch(&tx, access.repo_id, route.route_epoch, std::time::Duration::ZERO)
            .await?;
        let marker = VolumeFenceMarker::from_route(&updated, generation, None, unix_now());
        tx.execute(
            "UPDATE shard_replication_operations SET state='aborted', updated_at=clock_timestamp() WHERE id=$1",
            &[&input.operation_id],
        )
        .await
        .map_err(Error::internal)?;
        record_audit_event(
            &tx,
            access.owner_id,
            access.repo_id,
            &actor,
            "shard.migration_aborted",
            "shard_replication",
            &route.primary_node_id,
            sjson!({"operation_id": input.operation_id, "released_drain": true, "route_epoch": new_epoch}),
        )
        .await?;
        let transition_id = transitions::stage(&tx, &state, &marker).await?;
        mutation.ensure_active()?;
        transitions::commit_and_publish(&state, tx, &actor, &marker, transition_id).await?;
        let _ = replication::clean_staging(&replication::base_path(&state, input.operation_id)?);
        return Ok(json(
            StatusCode::OK,
            sjson!({
                "operation_id": input.operation_id,
                "repository_id": access.repo_id,
                "state": "aborted",
                "route_epoch": new_epoch,
            }),
        ));
    }
    tx.execute(
        "UPDATE shard_replication_operations SET state='aborted', updated_at=clock_timestamp() WHERE id=$1",
        &[&input.operation_id],
    )
    .await
    .map_err(Error::internal)?;
    record_audit_event(
        &tx,
        access.owner_id,
        access.repo_id,
        &actor,
        "shard.migration_aborted",
        "shard_replication",
        &route.primary_node_id,
        sjson!({"operation_id": input.operation_id, "released_drain": false}),
    )
    .await?;
    finish(tx, &actor, true).await?;
    let _ = replication::clean_staging(&replication::base_path(&state, input.operation_id)?);
    Ok(json(
        StatusCode::OK,
        sjson!({
            "operation_id": input.operation_id,
            "repository_id": access.repo_id,
            "state": "aborted",
            "route_epoch": route.route_epoch,
        }),
    ))
}

/// List durable migration operations so an operator can resume a
/// server-generated operation id or abort a drained transfer after a crash.
/// Listing never resumes or promotes on its own.
pub async fn list_migrations(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Read).await?;
    require_operator(&tx, &actor).await?;
    let rows = tx
        .query(
            "SELECT id,target_node_id,state,source_route_epoch,source_generation, \
             refs_sha256,journal_sequence,created_at::text,updated_at::text \
             FROM shard_replication_operations WHERE repository_id=$1 \
             ORDER BY created_at DESC, id DESC LIMIT 100",
            &[&access.repo_id],
        )
        .await
        .map_err(Error::internal)?;
    let items: Vec<serde_json::Value> = rows
        .iter()
        .map(|row| {
            let state_name: String = row.get(2);
            sjson!({
                "operation_id": row.get::<_, Uuid>(0),
                "target_node_id": row.get::<_, String>(1),
                "state": state_name,
                "source_route_epoch": row.get::<_, i64>(3),
                "source_generation": row.get::<_, i64>(4),
                "refs_sha256": row.get::<_, Option<String>>(5),
                "journal_sequence": row.get::<_, Option<i64>>(6),
                "created_at": row.get::<_, String>(7),
                "updated_at": row.get::<_, String>(8),
                "resumable": matches!(state_name.as_str(), "copying" | "verified"),
            })
        })
        .collect();
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, sjson!({"items": items})))
}
