//! One lock order for shard metadata changes that publish or replace native data.
use crate::{AppState, Error, storage::read_leases};
use tokio::{sync::{OwnedMutexGuard, OwnedRwLockWriteGuard}, time::Instant};
use uuid::Uuid;

pub(crate) struct MutationGuard {
    pub(crate) lease: read_leases::Lease,
    _local_gate: OwnedRwLockWriteGuard<()>,
    _writer: OwnedMutexGuard<()>,
}

impl MutationGuard {
    pub(crate) fn ensure_active(&self) -> Result<(), Error> { self.lease.ensure_active() }
}

/// PostgreSQL exclusive data barrier -> local maintenance gate -> publication
/// writer mutex. Every later caller must take these in this exact order.
pub(crate) async fn exclusive(state: &AppState, repo: Uuid) -> Result<MutationGuard, Error> {
    let deadline = Instant::now() + state.config.git_timeout;
    let lease = read_leases::exclusive(&state.pool, repo, deadline).await?;
    let gate = tokio::time::timeout_at(deadline, state.storage.maintenance_exclusive(repo))
        .await.map_err(|_| Error::timeout())?;
    let writer = tokio::time::timeout_at(deadline, state.storage.write_lock(repo))
        .await.map_err(|_| Error::timeout())?;
    lease.ensure_active()?;
    Ok(MutationGuard { lease, _local_gate: gate, _writer: writer })
}
