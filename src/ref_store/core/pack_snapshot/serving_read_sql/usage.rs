//! Transient serving-read usage counters and bounded expiry reclaim.
//!
//! Extracted from `serving_read_sql` so every SQL-only adapter stays inside the
//! project's submodule line cap. All functions run inside the caller's short
//! transaction and only lock/read/update the three transient usage/read tables.

use super::super::serving_read_request::{MAX_EXPIRED_SERVING_READ_RECLAIM, ServingReadUsage};
use crate::ref_store::contract::RefStoreError;
use crate::ref_store::pg;
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

/// Decode one transient usage `(active_count,logical_bytes)` pair.
///
/// Both columns are `BIGINT`; a missing/typed-wrong column is a typed row-shape
/// failure instead of a panic (an indexing or decode panic would escape the
/// request task). The column order is `SELECT active_count,logical_bytes`.
fn usage_row(row: &Row, what: &'static str) -> Result<ServingReadUsage, RefStoreError> {
    let active = row
        .try_get::<_, i64>(0)
        .map_err(|_| RefStoreError::Database(format!("serving read {what} usage row has no bigint active_count")))?;
    let logical_bytes = row
        .try_get::<_, i64>(1)
        .map_err(|_| RefStoreError::Database(format!("serving read {what} usage row has no bigint logical_bytes")))?;
    Ok(ServingReadUsage::new(active, logical_bytes))
}

/// Lock (or create) and read both transient usage counter/mutex rows.
///
/// Order is tenant then repository, matching every other A5 write path. The
/// repository row's stored tenant is compared after the lock, so a re-created
/// repository id can never inherit another tenant's transient budget.
pub(crate) async fn lock_usage(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repository_id: Uuid,
) -> Result<(ServingReadUsage, ServingReadUsage), RefStoreError> {
    tx.execute(
        "INSERT INTO ref_store_core_serving_read_tenant_usage(tenant_id) VALUES($1)
         ON CONFLICT(tenant_id) DO NOTHING",
        &[&tenant_id],
    )
    .await
    .map_err(pg::db_error)?;
    tx.execute(
        "INSERT INTO ref_store_core_serving_read_repo_usage(repository_id,tenant_id) VALUES($1,$2)
         ON CONFLICT(repository_id) DO NOTHING",
        &[&repository_id, &tenant_id],
    )
    .await
    .map_err(pg::db_error)?;
    let tenant = tx
        .query_one(
            "SELECT active_count,logical_bytes FROM ref_store_core_serving_read_tenant_usage
             WHERE tenant_id=$1 FOR UPDATE",
            &[&tenant_id],
        )
        .await
        .map_err(pg::db_error)?;
    let repository = tx
        .query_one(
            "SELECT tenant_id,active_count,logical_bytes FROM ref_store_core_serving_read_repo_usage
             WHERE repository_id=$1 FOR UPDATE",
            &[&repository_id],
        )
        .await
        .map_err(pg::db_error)?;
    let stored_tenant: Uuid = repository
        .try_get(0)
        .map_err(|_| RefStoreError::Database("serving read repository usage row has no uuid tenant_id".into()))?;
    if stored_tenant != tenant_id {
        return Err(RefStoreError::IdentityConflict);
    }
    // The repository row is `tenant_id,active_count,logical_bytes`.
    let repository_usage = ServingReadUsage::new(
        repository.try_get::<_, i64>(1).map_err(|_| {
            RefStoreError::Database("serving read repository usage row has no bigint active_count".into())
        })?,
        repository.try_get::<_, i64>(2).map_err(|_| {
            RefStoreError::Database("serving read repository usage row has no bigint logical_bytes".into())
        })?,
    );
    // The tenant row is exactly `active_count,logical_bytes`.
    Ok((usage_row(&tenant, "tenant")?, repository_usage))
}

/// Delete at most [`MAX_EXPIRED_SERVING_READ_RECLAIM`] expired transient reads of
/// one tenant. Bounded, ordered by expiry and serialized by the tenant usage row
/// lock the caller already holds.
pub(crate) async fn reclaim_expired(tx: &Transaction<'_>, tenant_id: Uuid) -> Result<u64, RefStoreError> {
    let rows = tx
        .query(
            "DELETE FROM ref_store_core_serving_reads
             WHERE pin_id IN (
                 SELECT pin_id FROM ref_store_core_serving_reads
                 WHERE tenant_id=$1 AND expires_at <= clock_timestamp()
                 ORDER BY expires_at
                 LIMIT $2
             )
             RETURNING pin_id",
            &[&tenant_id, &MAX_EXPIRED_SERVING_READ_RECLAIM],
        )
        .await
        .map_err(pg::db_error)?;
    Ok(rows.len() as u64)
}

/// Cheap tenant-scoped probe: is there at least one expired transient row?
///
/// Used by the separately committed bounded cleanup so a scope with nothing to
/// reclaim does not take the usage locks and writes no row at all. The probe and
/// the `DELETE` that follows it are both index probes on
/// `(tenant_id, expires_at)`; the `DELETE` re-evaluates `clock_timestamp()`
/// itself, so a stale `true` can only produce an empty (still committed) batch.
pub(crate) async fn has_expired(tx: &Transaction<'_>, tenant_id: Uuid) -> Result<bool, RefStoreError> {
    let row = tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM ref_store_core_serving_reads
             WHERE tenant_id=$1 AND expires_at <= clock_timestamp())",
            &[&tenant_id],
        )
        .await
        .map_err(pg::db_error)?;
    Ok(row.get(0))
}

/// Read the locked transient usage counters without taking the locks again.
/// The caller must already hold both `FOR UPDATE` rows (via [`lock_usage`]).
pub(crate) async fn read_usage(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repository_id: Uuid,
) -> Result<(ServingReadUsage, ServingReadUsage), RefStoreError> {
    let tenant = tx
        .query_one(
            "SELECT active_count,logical_bytes FROM ref_store_core_serving_read_tenant_usage WHERE tenant_id=$1",
            &[&tenant_id],
        )
        .await
        .map_err(pg::db_error)?;
    let repository = tx
        .query_one(
            "SELECT active_count,logical_bytes FROM ref_store_core_serving_read_repo_usage WHERE repository_id=$1",
            &[&repository_id],
        )
        .await
        .map_err(pg::db_error)?;
    // Both queries select `active_count,logical_bytes` only.
    Ok((usage_row(&tenant, "tenant")?, usage_row(&repository, "repository")?))
}

/// Recompute both transient counters from the actual rows of this scope.
///
/// Recomputation (instead of a blind increment) keeps the bounds honest even
/// when a legitimate repository delete cascades transient rows away without
/// touching these counter rows, and it can only ever *under*-count a concurrent
/// writer because every writer holds the same tenant usage row.
pub(crate) async fn recompute_usage(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repository_id: Uuid,
) -> Result<(), RefStoreError> {
    tx.execute(
        "UPDATE ref_store_core_serving_read_tenant_usage u
         SET active_count=s.active_count,logical_bytes=s.logical_bytes
         FROM (
             SELECT (count(*) FILTER (WHERE expires_at > clock_timestamp()))::bigint AS active_count,
                    COALESCE(sum(logical_bytes),0)::bigint AS logical_bytes
             FROM ref_store_core_serving_reads WHERE tenant_id=$1
         ) s
         WHERE u.tenant_id=$1",
        &[&tenant_id],
    )
    .await
    .map_err(pg::db_error)?;
    tx.execute(
        "UPDATE ref_store_core_serving_read_repo_usage u
         SET active_count=s.active_count,logical_bytes=s.logical_bytes
         FROM (
             SELECT (count(*) FILTER (WHERE expires_at > clock_timestamp()))::bigint AS active_count,
                    COALESCE(sum(logical_bytes),0)::bigint AS logical_bytes
             FROM ref_store_core_serving_reads WHERE repository_id=$1
         ) s
         WHERE u.repository_id=$1",
        &[&repository_id],
    )
    .await
    .map_err(pg::db_error)?;
    Ok(())
}
