//! Authorized internal serving CheckVersion boundary.
//!
//! One owned read-only PostgreSQL transaction first resolves the real serving
//! repository through [`lookup_in_tx`]: authenticated owner/name selector,
//! current Role::Read + ContentsRead, live API-token kind/revocation/expiry/
//! read-only semantics, ready binding, actual opened Blob backend, current
//! gate/realm and cluster-incarnation `NOWAIT`. The same transaction then calls
//! the owning-core [`PgRefStoreCore::check_version_in_tx`], so `Unknown`,
//! `Unchanged` and `Changed` and the canonical gate proof keep their existing
//! semantics.
//!
//! `known` is only a comparison selector; it grants no write, tenant,
//! repository or scope authority. The caller's owner/name strings are route
//! selectors resolved by the authorized lookup, never authority.
//!
//! The observation is returned only after a bounded rollback. Cleanup failure,
//! timeout or unavailability returns an opaque error instead of an observation.
//! No REST route, legacy/local/PG fallback, mutation, quota, pin, Blob/native IO
//! or session/byte-closure proof is part of this facade.
use super::{acquire, begin_owned, deadline_error, lookup_in_tx, map_refstore};
use crate::{
    Error,
    blob_store::BlobBackendIdentity,
    db::Identity,
    ref_store::{CoreGateVersion, PgRefStoreCore, VersionCheck},
};
use axum::http::StatusCode;
use deadpool_postgres::Pool;
use std::time::Duration;
use tokio::time::{Instant, timeout_at};

/// Fixed cleanup budget after the observation's absolute deadline. This bounds
/// rollback only; it never refreshes or extends the authorization/observation
/// deadline.
const CLEANUP_BUDGET: Duration = Duration::from_secs(1);

/// Authorized repository-scoped CheckVersion observation over the real
/// `pg_refstore` serving authority.
///
/// The authorization lookup and owning-core observation share the caller's one
/// absolute deadline; rollback has a separate fixed short cleanup budget. The
/// returned gate proof belongs to the owning core and mints no #174
/// token/HWM/byte-closure proof.
pub async fn check_version(
    pool: &Pool,
    actor: &Identity,
    owner: &str,
    name: &str,
    known: Option<&CoreGateVersion>,
    backend: &BlobBackendIdentity,
    deadline: Instant,
) -> Result<VersionCheck, Error> {
    let mut client = acquire(pool, deadline).await?;
    let tx = begin_owned(&mut client, deadline).await?;
    // One absolute timeout covers the *entire* same-transaction authorization
    // lookup and owning-core observation. lookup_in_tx's initial statement/lock
    // timeout is only a per-statement PostgreSQL bound; this wrapper stops a
    // later sequential auth query from inheriting that larger bound and running
    // past the caller deadline. No second transaction or refreshed auth
    // deadline is introduced.
    let observation = match timeout_at(deadline, async {
        // Same transaction: authorized serving lookup first (including the
        // cluster NOWAIT anchor), then the owning-core observation. No
        // public lookup transaction is opened and no PG lease is re-acquired.
        let serving = lookup_in_tx(&tx, actor, owner, name, false, backend, deadline).await?;
        let repository_id = serving.repository.id;
        let tenant_id = serving.gate.tenant_id();
        PgRefStoreCore.check_version_in_tx(&tx, repository_id, tenant_id, known, deadline).await.map_err(map_refstore)
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(deadline_error()),
    };
    // Observation and authorization use the absolute deadline above. Cleanup
    // gets only a fixed short budget after cancellation/expiry, so a blocked
    // auth query cannot also consume an already-expired cleanup deadline.
    let cleanup = timeout_at(Instant::now() + CLEANUP_BUDGET, tx.rollback()).await;
    let result = match (cleanup, observation) {
        (Ok(Ok(())), observation) => observation,
        _ => Err(Error(StatusCode::SERVICE_UNAVAILABLE, "ref-store version check cleanup failed")),
    };
    // A future that completed just after the absolute deadline is not an
    // observation either. Errors stay mapped as before; only an actual
    // VersionCheck is suppressed once time is up.
    if result.is_ok() && Instant::now() >= deadline {
        return Err(deadline_error());
    }
    result
}
