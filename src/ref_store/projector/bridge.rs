//! Runtime worker bridges connecting Ref-CAS projection, reliable jobs, and
//! webhook backfill with `events`, `dispatch`, and `webhooks::background` (#117).

use super::jobs::{process_due_projection_jobs, sync_projected_ref_cas_webhooks_bounded};
use super::pg::projection_tables_present;
use crate::Error;
use deadpool_postgres::Pool;
use tokio::time::Instant;
use uuid::Uuid;

/// Claims and executes a bounded batch of due `ref_cas_projection_jobs` for the
/// dispatch / event worker. Returns `Ok(0)` without failing standalone GitFS
/// deployments before migration `149` is applied.
pub async fn run_projection_job_worker_once(
    pool: &Pool,
    owner: Uuid,
    batch: usize,
    lease_seconds: i64,
) -> anyhow::Result<usize> {
    let client = pool.get().await?;
    if !projection_tables_present(&**client).await? {
        return Ok(0);
    }
    drop(client);
    Ok(process_due_projection_jobs(pool, owner, batch, lease_seconds).await?)
}

/// Bounded backfill for any active push hooks on Ref-CAS projected repositories.
/// Called alongside legacy outbox backfill from the background webhook worker.
pub async fn sync_webhooks_bounded(
    pool: &Pool,
    tenant_id: Uuid,
    repository_id: Uuid,
    pair_limit: i64,
    deadline: Instant,
) -> Result<usize, Error> {
    sync_projected_ref_cas_webhooks_bounded(pool, tenant_id, repository_id, pair_limit, deadline)
        .await
        .map_err(map_proj_err)
}

fn map_proj_err(err: super::types::ProjectionError) -> Error {
    Error::internal(err)
}
