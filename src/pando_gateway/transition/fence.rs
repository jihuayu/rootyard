//! Durable transition fence transitions and publication-window arbitration.
use super::MAX_ERROR;
use crate::{AppState, Error, db::Repository, journal, pando_gateway::pack_store::PackManifest};
use anyhow::{Result, ensure};
use axum::http::StatusCode;
use deadpool_postgres::{Client, Pool};
use std::{collections::BTreeMap, time::Duration};
use tokio::time::Instant;
use uuid::Uuid;

pub(super) struct Fence {
    pub(super) id: Uuid,
    pub(super) epoch: i64,
    pub(super) generation: i64,
    pub(super) backend: String,
}

fn conflict() -> Error {
    Error(StatusCode::CONFLICT, "repository storage transition in progress; retry")
}

pub(super) async fn begin(state: &AppState, repo_id: Uuid, direction: super::Direction) -> Result<Fence, Error> {
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let row = tx
        .query_opt(
            "SELECT storage_backend,state,storage_generation,backend_transition_epoch,transition_state \
        FROM repositories WHERE id=$1 FOR UPDATE",
            &[&repo_id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let backend: String = row.get("storage_backend");
    let repo_state: String = row.get("state");
    let generation: i64 = row.get("storage_generation");
    let epoch: i64 = row.get("backend_transition_epoch");
    let transition_state: String = row.get("transition_state");
    if repo_state != "ready" || !matches!(transition_state.as_str(), "stable" | "failed") {
        return Err(conflict());
    }
    let expected = match direction {
        super::Direction::Cutover => "gitfs",
        super::Direction::Rollback => "pando",
    };
    if backend != expected {
        return Err(Error(StatusCode::CONFLICT, "repository is not in the required source backend"));
    }
    let id = Uuid::new_v4();
    let next = epoch.checked_add(1).ok_or_else(conflict)?;
    tx.execute(
        "UPDATE repositories SET transition_state='draining',backend_transition_epoch=$2, \
        transition_id=$3,transition_started_at=clock_timestamp(),transition_error=NULL WHERE id=$1",
        &[&repo_id, &next, &id],
    )
    .await
    .map_err(Error::internal)?;
    tx.commit().await.map_err(Error::internal)?;
    Ok(Fence { id, epoch: next, generation, backend })
}

/// Record a failed transition without reopening ordinary writes. The fence
/// remains `failed` (not `stable`) so an interrupted or uncertain outcome can
/// never be mistaken for committed authority. Recovery is an explicit retry of
/// the same direction after repairing the cause: `begin` accepts `failed`, but
/// only the transition's own fenced/durable checks may run until it succeeds.
pub(super) async fn fail(state: &AppState, repo_id: Uuid, fence: &Fence, error: &anyhow::Error) {
    let message = format!("{error:#}");
    let message: String = message.chars().take(MAX_ERROR).collect();
    let Ok(client) = state.pool.get().await else { return };
    let _ = client
        .execute(
            "UPDATE repositories SET transition_state='failed',transition_error=$3 \
        WHERE id=$1 AND transition_id=$2 AND transition_state='draining'",
            &[&repo_id, &fence.id, &message],
        )
        .await;
}

async fn ensure_fence(tx: &tokio_postgres::Transaction<'_>, repo_id: Uuid, fence: &Fence) -> Result<()> {
    let row = tx
        .query_opt(
            "SELECT storage_backend,state,storage_generation,transition_state,transition_id \
        FROM repositories WHERE id=$1 FOR UPDATE",
            &[&repo_id],
        )
        .await?;
    let row = row.ok_or_else(|| anyhow::anyhow!("repository disappeared during transition"))?;
    ensure!(
        row.get::<_, String>("storage_backend") == fence.backend
            && row.get::<_, String>("state") == "ready"
            && row.get::<_, i64>("storage_generation") == fence.generation
            && row.get::<_, String>("transition_state") == "draining"
            && row.get::<_, Option<Uuid>>("transition_id") == Some(fence.id),
        "transition fence changed before commit"
    );
    Ok(())
}

pub(crate) async fn acquire_publication_lock(pool: &Pool, repo_id: Uuid, deadline: Instant) -> Result<Client, Error> {
    let client = pool.get().await.map_err(Error::internal)?;
    loop {
        let granted: bool = client
            .query_one(
                "SELECT pg_try_advisory_lock(hashtextextended('rootyard-publication-v1:' || $1::uuid::text, 0))",
                &[&repo_id],
            )
            .await
            .map_err(Error::internal)?
            .get(0);
        if granted {
            return Ok(client);
        }
        if Instant::now() >= deadline {
            return Err(conflict());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub(crate) async fn release_publication_lock(client: &Client, repo_id: Uuid) {
    let _ = client
        .query_one(
            "SELECT pg_advisory_unlock(hashtextextended('rootyard-publication-v1:' || $1::uuid::text, 0))",
            &[&repo_id],
        )
        .await;
}

/// Write admission for every mutating route. A repository under transition
/// rejects new writes even though its public backend field may still name the
/// old authority until the switch commits.
pub async fn admit_write(pool: &Pool, repository_id: Uuid, expected_backend: &str) -> Result<(), Error> {
    let client = pool.get().await.map_err(Error::internal)?;
    let row = client
        .query_opt(
            "SELECT transition_state,storage_backend,state,storage_generation FROM repositories WHERE id=$1",
            &[&repository_id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    if row.get::<_, String>("transition_state") != "stable" {
        return Err(conflict());
    }
    if row.get::<_, String>("storage_backend") != expected_backend
        || row.get::<_, String>("state") != "ready"
        || row.get::<_, i64>("storage_generation") <= 0
    {
        return Err(Error(StatusCode::CONFLICT, "repository backend changed; retry"));
    }
    Ok(())
}

pub(super) async fn complete_cutover(
    state: &AppState,
    repo: &Repository,
    fence: &Fence,
    tenant_id: Uuid,
    refs: &BTreeMap<String, String>,
    head_ref: &str,
    pack: &PackManifest,
) -> Result<(), Error> {
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    ensure_fence(&tx, repo.id, fence).await.map_err(Error::internal)?;
    if pack.repository_id != repo.id
        || pack.tenant_id != tenant_id
        || pack.storage_generation != fence.generation
        || pack.object_format != repo.object_format
    {
        return Err(conflict());
    }
    // GitFS and Pando share `git_operations` uniqueness per generation. Carry
    // the durable high-water mark forward instead of restarting at zero, or
    // the first Pando push after cutover would collide with GitFS history.
    let operation_sequence: i64 = tx
        .query_one(
            "SELECT COALESCE(max(sequence),0) FROM git_operations WHERE repository_id=$1 AND storage_generation=$2",
            &[&repo.id, &fence.generation],
        )
        .await
        .map_err(Error::internal)?
        .get(0);
    let journal_floor: i64 = tx
        .query_one("SELECT COALESCE(max(sequence),0) FROM git_operations WHERE repository_id=$1", &[&repo.id])
        .await
        .map_err(Error::internal)?
        .get(0);
    journal::ensure_sequence_at_least(&state.storage.root, repo.id, journal_floor).map_err(Error::internal)?;
    let names: Vec<String> = refs.keys().cloned().collect();
    tx.execute(
        "INSERT INTO pando_repository_states         (repository_id,tenant_id,storage_generation,ref_generation,object_format,state,pack_ids,head_ref,operation_sequence)         VALUES($1,$2,$3,1,$4,'serving',ARRAY[$5]::uuid[],$6,$7)         ON CONFLICT(repository_id) DO UPDATE SET tenant_id=EXCLUDED.tenant_id,         storage_generation=EXCLUDED.storage_generation,ref_generation=1,         object_format=EXCLUDED.object_format,state='serving',pack_ids=EXCLUDED.pack_ids,         head_ref=EXCLUDED.head_ref,operation_sequence=EXCLUDED.operation_sequence,         updated_at=clock_timestamp()",
        &[&repo.id, &tenant_id, &fence.generation, &repo.object_format, &pack.id, &head_ref, &operation_sequence],
    )
    .await
    .map_err(Error::internal)?;
    tx.execute("DELETE FROM pando_publication_fences WHERE manifest_id=$1", &[&pack.id])
        .await
        .map_err(Error::internal)?;
    tx.execute("DELETE FROM pando_refs WHERE repository_id=$1 AND NOT (ref_name = ANY($2))", &[&repo.id, &names])
        .await
        .map_err(Error::internal)?;
    for (name, oid) in refs {
        tx.execute(
            "INSERT INTO pando_refs(repository_id,ref_name,oid,updated_generation) VALUES($1,$2,$3,1) \
            ON CONFLICT(repository_id,ref_name) DO UPDATE SET oid=EXCLUDED.oid,updated_generation=EXCLUDED.updated_generation",
            &[&repo.id, name, oid],
        )
        .await
        .map_err(Error::internal)?;
    }
    let changed = tx
        .execute(
            "UPDATE repositories SET storage_backend='pando',transition_state='stable', \
        transition_id=NULL,transition_started_at=NULL,transition_error=NULL \
        WHERE id=$1 AND transition_id=$2 AND transition_state='draining'",
            &[&repo.id, &fence.id],
        )
        .await
        .map_err(Error::internal)?;
    if changed != 1 {
        return Err(conflict());
    }
    tx.commit().await.map_err(Error::internal)?;
    Ok(())
}

pub(super) async fn complete_rollback(state: &AppState, repo: &Repository, fence: &Fence) -> Result<(), Error> {
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    ensure_fence(&tx, repo.id, fence).await.map_err(Error::internal)?;
    // Pando-era operations advanced the shared `git_operations` namespace but
    // not the local journal counter. Reset the local counter to the durable
    // high-water mark before restoring GitFS authority, while the transition
    // still holds the repository write lock.
    let journal_floor: i64 = tx
        .query_one("SELECT COALESCE(max(sequence),0) FROM git_operations WHERE repository_id=$1", &[&repo.id])
        .await
        .map_err(Error::internal)?
        .get(0);
    journal::ensure_sequence_at_least(&state.storage.root, repo.id, journal_floor).map_err(Error::internal)?;
    tx.execute(
        "UPDATE pando_repository_states SET state='rollback',updated_at=clock_timestamp() WHERE repository_id=$1",
        &[&repo.id],
    )
    .await
    .map_err(Error::internal)?;
    let changed = tx
        .execute(
            "UPDATE repositories SET storage_backend='gitfs',transition_state='stable', \
        transition_id=NULL,transition_started_at=NULL,transition_error=NULL \
        WHERE id=$1 AND transition_id=$2 AND transition_state='draining'",
            &[&repo.id, &fence.id],
        )
        .await
        .map_err(Error::internal)?;
    if changed != 1 {
        return Err(conflict());
    }
    tx.commit().await.map_err(Error::internal)?;
    Ok(())
}
