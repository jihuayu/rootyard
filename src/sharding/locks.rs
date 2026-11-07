//! One lock order for shard metadata changes that publish or replace native data.
use crate::{AppState, Error, storage::{read_leases, ref_publication}};
use tokio::{sync::{OwnedMutexGuard, OwnedRwLockWriteGuard}, time::Instant};
use uuid::Uuid;

pub(crate) struct MutationGuard {
    _writer: OwnedMutexGuard<()>,
    _publication: ref_publication::RepositoryFence,
    _local_gate: OwnedRwLockWriteGuard<()>,
    pub(crate) lease: read_leases::Lease,
}

impl MutationGuard {
    pub(crate) fn ensure_active(&self) -> Result<(), Error> {
        self.lease.ensure_active()?;
        self._publication.ensure_active()
    }
}

/// Serialize migration handlers for one repository without blocking ordinary
/// writes. A dedicated session connection is dropped (and the advisory lock is
/// released) when the handler returns or the process exits.
pub(crate) struct MigrationLock {
    _client: tokio_postgres::Client,
}

pub(crate) async fn migration(state: &AppState, repo: Uuid) -> Result<MigrationLock, Error> {
    let client = crate::db::connect_url(&state.config.database_url).await.map_err(Error::internal)?;
    let key = format!("rootyard-migration-v1:{repo}");
    let acquired: bool = client
        .query_one("SELECT pg_try_advisory_lock(hashtextextended($1,0))", &[&key])
        .await
        .map_err(Error::internal)?
        .get(0);
    if !acquired {
        return Err(crate::sharding::models::conflict("repository already has an active migration"));
    }
    Ok(MigrationLock { _client: client })
}

/// PostgreSQL exclusive data barrier -> local maintenance gate -> cross-process
/// publication fence -> local writer mutex. Callers keep all four until their
/// native-data/route mutation is finished.
pub(crate) async fn exclusive(state: &AppState, repo: Uuid) -> Result<MutationGuard, Error> {
    let deadline = Instant::now() + state.config.git_timeout;
    let lease = read_leases::exclusive(&state.pool, repo, deadline).await?;
    let gate = tokio::time::timeout_at(deadline, state.storage.maintenance_exclusive(repo))
        .await.map_err(|_| Error::timeout())?;
    let publication = ref_publication::acquire_repository_fence(&state.pool, repo, deadline).await?;
    let writer = tokio::time::timeout_at(deadline, state.storage.write_lock(repo))
        .await.map_err(|_| Error::timeout())?;
    lease.ensure_active()?;
    publication.ensure_active()?;
    Ok(MutationGuard { _writer: writer, _publication: publication, _local_gate: gate, lease })
}
