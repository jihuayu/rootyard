//! Guarded workspace remote staging and checkpoint commit helpers (#85).
//!
//! Coordinates durable write admissions (`storage_write_admissions`), per-key delete
//! claims (`remote_object_delete_claims`), and active transfer fencing before publishing
//! or committing workspace remote objects.
use super::service;
use crate::{
    AppState, Error, auth,
    db::Identity,
    storage::{
        admission::Admission,
        remote_key_claims::{has_active_delete_claim, lock_object_key, wait_or_clear_delete_claim},
        remote_objects::RemoteObjectStore,
    },
    token_scopes::RepoAction,
};
use axum::http::StatusCode;
use deadpool_postgres::Transaction;
use std::time::Duration;
use tokio::time::{Instant, sleep};
use uuid::Uuid;

const MAX_STAGE_CLAIM_RETRIES: usize = 8;

/// Ensure the repository still belongs to `tenant`, is not soft-deleted, and is not
/// in an ownership-transfer phase that has moved beyond drain.
pub(super) async fn verify_publish_repo_state(tx: &Transaction<'_>, repo_id: Uuid, tenant: Uuid) -> Result<(), Error> {
    let row = tx
        .query_opt(
            "SELECT r.owner_id, (r.deleted_at IS NOT NULL), \
                    EXISTS ( \
                        SELECT 1 FROM repository_transfers t \
                        WHERE t.repository_id = r.id \
                          AND t.state IN ('copying_remote', 'rekeying_db', 'revoking_legacy', 'rolling_back') \
                    ) \
             FROM repositories r WHERE r.id = $1 FOR SHARE OF r",
            &[&repo_id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let owner_id: Uuid = row.get(0);
    let deleted: bool = row.get(1);
    let transfer_fenced: bool = row.get(2);
    if deleted {
        return Err(Error::not_found());
    }
    if owner_id != tenant || transfer_fenced {
        return Err(Error(StatusCode::CONFLICT, "repository identity or transfer state changed"));
    }
    Ok(())
}

pub(super) struct StageKeyTarget<'a> {
    pub checkpoint_id: Uuid,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub digest: &'a str,
    pub size: u64,
    pub kind: &'a str,
}

/// Wait out or flush any delete claim on `(tenant, "workspace", digest)`, then under
/// `lock_object_key` verify ownership, absence of active delete claims, and record staging.
pub(super) async fn stage_key_guarded(
    state: &AppState,
    store: &RemoteObjectStore,
    target: StageKeyTarget<'_>,
    admission: &Admission,
    deadline: Instant,
) -> Result<(), Error> {
    for attempt in 0..MAX_STAGE_CLAIM_RETRIES {
        admission.ensure_active()?;
        wait_or_clear_delete_claim(&state.pool, Some(store), target.tenant_id, "workspace", target.digest, deadline)
            .await?;
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        lock_object_key(&tx, target.tenant_id, "workspace", target.digest).await?;
        verify_publish_repo_state(&tx, target.repository_id, target.tenant_id).await?;
        if has_active_delete_claim(&tx, target.tenant_id, "workspace", target.digest).await? {
            tx.rollback().await.map_err(Error::internal)?;
            drop(client);
            if attempt + 1 >= MAX_STAGE_CLAIM_RETRIES || Instant::now() >= deadline {
                return Err(Error(StatusCode::CONFLICT, "remote object delete claim in progress"));
            }
            sleep(Duration::from_millis(25)).await;
            continue;
        }
        tx.execute(
            "INSERT INTO workspace_remote_staging_objects(checkpoint_id,tenant_id,digest,size,kind) \
             VALUES($1,$2,$3,$4,$5) ON CONFLICT(checkpoint_id,digest) DO NOTHING",
            &[&target.checkpoint_id, &target.tenant_id, &target.digest, &(target.size as i64), &target.kind],
        )
        .await
        .map_err(Error::internal)?;
        admission.ensure_active()?;
        tx.commit().await.map_err(Error::internal)?;
        return Ok(());
    }
    Err(Error(StatusCode::CONFLICT, "remote object delete claim in progress"))
}

/// Re-verify live token/repo write authority, ownership, transfer state, and write admission
/// inside the final checkpoint commit transaction before making `committed` durable.
pub(super) async fn commit_checkpoint_guarded(
    state: &AppState,
    cp: Uuid,
    repo_id: Uuid,
    tenant: Uuid,
    actor: &Identity,
    digest: &str,
    raw_len: i64,
    admission: &Admission,
) -> Result<(), Error> {
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_repo_write_access_with_parent(
        &*tx,
        actor.id,
        actor.token_id,
        actor.parent_token_id,
        repo_id,
        auth::web_scope_enabled(),
        RepoAction::WorkspacesWrite,
    )
    .await?;
    verify_publish_repo_state(&tx, repo_id, tenant).await?;
    let changed = tx
        .execute(
            "UPDATE workspace_checkpoints c SET state='committed',manifest_digest=$2,manifest_size=$3,committed_at=clock_timestamp() \
             FROM workspaces w WHERE c.id=$1 AND c.workspace_id=w.id AND c.state='local_complete' \
             AND c.lease_epoch=w.lease_epoch AND w.host_id=$4 AND w.lease_until>clock_timestamp()",
            &[&cp, &digest, &raw_len, &state.storage.volume_id],
        )
        .await
        .map_err(Error::internal)?;
    if changed != 1 {
        let row = tx
            .query_opt("SELECT state,manifest_digest,manifest_size FROM workspace_checkpoints WHERE id=$1", &[&cp])
            .await
            .map_err(Error::internal)?
            .ok_or_else(Error::not_found)?;
        if row.get::<_, String>(0) != "committed" || row.get::<_, Option<String>>(1).as_deref() != Some(digest) {
            return Err(service::conflict());
        }
    }
    admission.ensure_active()?;
    tx.commit().await.map_err(Error::internal)?;
    Ok(())
}
