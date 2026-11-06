//! Durable orphan cleanup for tenant-scoped remote checkpoint objects.
use super::{remote, service};
use crate::{AppState, Error, members::models::Role};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub(super) async fn lock_key(tx: &deadpool_postgres::Transaction<'_>, tenant: Uuid, digest: &str) -> Result<(), Error> {
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1::uuid::text || ':' || $2::text, 702))",
        &[&tenant, &digest],
    )
    .await
    .map_err(Error::internal)?;
    Ok(())
}

pub async fn abandon(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(cp): Path<Uuid>,
) -> Result<(StatusCode, Json<Value>), Error> {
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let row = tx
        .query_opt("SELECT workspace_id,state FROM workspace_checkpoints WHERE id=$1", &[&cp])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let workspace_id: Uuid = row.get(0);
    let status: String = row.get(1);
    service::authorized(&state, &headers, workspace_id, Role::Write).await?;
    if status == "committed" {
        return Err(Error(StatusCode::CONFLICT, "committed checkpoint is a retention root"));
    }
    if status != "failed" {
        let changed = tx
            .execute(
                "UPDATE workspace_checkpoints SET state='failed' WHERE id=$1 AND state='local_complete' AND NOT EXISTS (SELECT 1 FROM workspaces WHERE parent_checkpoint_id=$1)",
                &[&cp],
            )
            .await
            .map_err(Error::internal)?;
        if changed != 1 {
            return Err(service::conflict());
        }
        tx.execute(
            "UPDATE workspaces SET last_checkpoint_id=NULL WHERE id=$1 AND last_checkpoint_id=$2",
            &[&workspace_id, &cp],
        )
        .await
        .map_err(Error::internal)?;
    }
    tx.commit().await.map_err(Error::internal)?;
    // A transport failure leaves the staging rows as the retryable tombstone.
    let removed = collect_once(&state).await.unwrap_or(0);
    Ok((StatusCode::OK, Json(json!({"checkpoint_id":cp,"state":"failed","objects_collected":removed}))))
}

pub async fn collect_once(state: &AppState) -> Result<usize, Error> {
    let store = remote::remote_store(state)?;
    let client = state.pool.get().await.map_err(Error::internal)?;
    let rows = client
        .query(
            "SELECT DISTINCT s.tenant_id,s.digest FROM workspace_remote_staging_objects s JOIN workspace_checkpoints c ON c.id=s.checkpoint_id WHERE c.state='failed' ORDER BY s.tenant_id,s.digest LIMIT 100",
            &[],
        )
        .await
        .map_err(Error::internal)?;
    drop(client);
    let mut removed = 0;
    for row in rows {
        let tenant: Uuid = row.get(0);
        let digest: String = row.get(1);
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        lock_key(&tx, tenant, &digest).await?;
        let active: bool = tx
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM workspace_remote_staging_objects s JOIN workspace_checkpoints c ON c.id=s.checkpoint_id WHERE s.tenant_id=$1 AND s.digest=$2 AND c.state<>'failed')",
                &[&tenant, &digest],
            )
            .await
            .map_err(Error::internal)?
            .get(0);
        if active {
            // A committed or resumable checkpoint owns this immutable key.
            // Retire only the failed checkpoint's staging references.
            tx.execute(
                "DELETE FROM workspace_remote_staging_objects s USING workspace_checkpoints c WHERE s.checkpoint_id=c.id AND s.tenant_id=$1 AND s.digest=$2 AND c.state='failed'",
                &[&tenant, &digest],
            )
            .await
            .map_err(Error::internal)?;
            tx.commit().await.map_err(Error::internal)?;
            continue;
        }
        let key = remote::key(tenant, &digest)?;
        store.delete(&key, tokio::time::Instant::now() + Duration::from_secs(30)).await.map_err(Error::internal)?;
        tx.execute(
            "DELETE FROM workspace_remote_staging_objects s USING workspace_checkpoints c WHERE s.checkpoint_id=c.id AND s.tenant_id=$1 AND s.digest=$2 AND c.state='failed'",
            &[&tenant, &digest],
        )
        .await
        .map_err(Error::internal)?;
        tx.commit().await.map_err(Error::internal)?;
        removed += 1;
    }
    Ok(removed)
}

pub async fn run(state: Arc<AppState>, stop: CancellationToken) {
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        tokio::select! { _=stop.cancelled()=>break, _=interval.tick()=>{} }
        let _ = collect_once(&state).await;
    }
}
