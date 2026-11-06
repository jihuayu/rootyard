//! Active checkout leases used by retention and mirror eviction.
use super::*;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveLease {
    pub job_id: Uuid,
    pub storage_generation: i64,
    pub target_oid: String,
    pub expires_unix: i64,
}

/// Pure predicate for whether a checkout job row represents an active lease at `now_unix`.
pub fn is_lease_active(
    cancelled: bool,
    revoked: bool,
    expires_unix: Option<i64>,
    now_unix: i64,
) -> bool {
    !cancelled && !revoked && expires_unix.is_some_and(|exp| exp > now_unix)
}

/// Check on an existing SQL client/transaction whether `job_id` has an active checkout lease.
pub async fn has_active_lease_on(
    client: &(impl tokio_postgres::GenericClient + Sync),
    repository_id: Uuid,
    job_id: Uuid,
) -> anyhow::Result<bool> {
    let row = client
        .query_opt(
            "SELECT 1 FROM ci_checkout_jobs \
             WHERE repository_id = $1 AND job_id = $2 \
               AND plan IS NOT NULL \
               AND NOT cancelled AND NOT revoked \
               AND expires_unix > extract(epoch FROM clock_timestamp())",
            &[&repository_id, &job_id],
        )
        .await?;
    Ok(row.is_some())
}

/// Check using the connection pool whether `job_id` has an active checkout lease.
pub async fn has_active_lease(
    pool: &deadpool_postgres::Pool,
    repository_id: Uuid,
    job_id: Uuid,
) -> anyhow::Result<bool> {
    let client = pool.get().await?;
    has_active_lease_on(&**client, repository_id, job_id).await
}

/// List all active (non-cancelled, non-revoked, unexpired) checkout leases for `repository_id`.
pub async fn active_leases_on(
    client: &(impl tokio_postgres::GenericClient + Sync),
    repository_id: Uuid,
) -> anyhow::Result<Vec<ActiveLease>> {
    let rows = client
        .query(
            "SELECT job_id, (plan->>'storage_generation')::bigint, plan->>'target_oid', expires_unix \
             FROM ci_checkout_jobs \
             WHERE repository_id = $1 \
               AND plan IS NOT NULL \
               AND NOT cancelled AND NOT revoked \
               AND expires_unix > extract(epoch FROM clock_timestamp()) \
             ORDER BY job_id",
            &[&repository_id],
        )
        .await?;
    let mut leases = Vec::with_capacity(rows.len());
    for row in rows {
        leases.push(ActiveLease {
            job_id: row.get(0),
            storage_generation: row.get(1),
            target_oid: row.get(2),
            expires_unix: row.get(3),
        });
    }
    Ok(leases)
}

pub async fn active_leases(
    pool: &deadpool_postgres::Pool,
    repository_id: Uuid,
) -> anyhow::Result<Vec<ActiveLease>> {
    let client = pool.get().await?;
    active_leases_on(&**client, repository_id).await
}

/// Return the set of `job_id`s with active checkout leases for `repository_id`.
pub async fn active_job_ids(
    pool: &deadpool_postgres::Pool,
    repository_id: Uuid,
) -> anyhow::Result<std::collections::BTreeSet<Uuid>> {
    Ok(active_leases(pool, repository_id)
        .await?
        .into_iter()
        .map(|lease| lease.job_id)
        .collect())
}

/// Return the set of `target_oid`s protected by active checkout leases for `repository_id`.
pub async fn active_pinned_oids(
    pool: &deadpool_postgres::Pool,
    repository_id: Uuid,
) -> anyhow::Result<std::collections::BTreeSet<String>> {
    Ok(active_leases(pool, repository_id)
        .await?
        .into_iter()
        .map(|lease| lease.target_oid)
        .collect())
}

/// Return the set of `(storage_generation, target_oid)` pairs protected by active checkout leases.
pub async fn active_pinned_targets(
    pool: &deadpool_postgres::Pool,
    repository_id: Uuid,
) -> anyhow::Result<std::collections::BTreeSet<(i64, String)>> {
    Ok(active_leases(pool, repository_id)
        .await?
        .into_iter()
        .map(|lease| (lease.storage_generation, lease.target_oid))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_lease_predicate_enforces_expiry_and_terminal_flags() {
        let now = 1_700_000_000;
        assert!(is_lease_active(false, false, Some(now + 60), now));
        assert!(!is_lease_active(true, false, Some(now + 60), now));
        assert!(!is_lease_active(false, true, Some(now + 60), now));
        assert!(!is_lease_active(false, false, Some(now), now));
        assert!(!is_lease_active(false, false, Some(now - 1), now));
        assert!(!is_lease_active(false, false, None, now));
    }
}

