//! Serving authority lookup and cluster-incarnation fence (#143/#174).
//!
//! This submodule keeps the live authority read (`lookup`) and every helper it
//! needs apart from the provisioning transaction in the parent module. The
//! cluster anchor is read under `FOR SHARE NOWAIT` as the first row lock after
//! authorization, so a restore rotation is the only conflicting writer.
use super::{acquire, begin_owned, map_refstore, map_scope_refusal};
use crate::{
    Error, auth,
    db::{self, Identity, Repository},
    members::models::Role,
    ref_store::{
        core::{PgRefStoreCore, serving_scope::LockedScope},
        pg::bound,
    },
    token_scopes::RepoAction,
};
use axum::http::StatusCode;
use deadpool_postgres::{Pool, Transaction};
use tokio::time::Instant;
use uuid::Uuid;

/// The authority family a serving read is bound to. The two wire values are one
/// stable byte each and are signed into the session frame; unknown bytes are
/// rejected instead of being treated as a wildcard.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AuthorityKind {
    PgRefStore,
    RaftRefStore,
}

impl AuthorityKind {
    pub(crate) const fn wire(self) -> u8 {
        match self {
            Self::PgRefStore => 1,
            Self::RaftRefStore => 2,
        }
    }

    pub(crate) fn from_wire(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::PgRefStore),
            2 => Some(Self::RaftRefStore),
            _ => None,
        }
    }
}

/// Resolve one already served `pg_refstore` repository after current
/// authorization.
///
/// `writable` selects the required role/scope (`write` vs `read`) and refuses a
/// read-only token. Authorization runs first (token, RBAC, token scope,
/// repository `ready`); only then is the durable binding, the live gate and the
/// concrete Blob backend identity checked, so an unauthorized caller cannot
/// probe serving state.
///
/// After authorization and before any repository/scope/gate read, the same
/// bounded transaction also reads the cluster authority incarnation. The
/// lookup rolls back and returns no client or transaction. A later serving read
/// capture must prove the identical incarnation before it may materialize
/// (#174).
pub async fn lookup(
    pool: &Pool,
    actor: &Identity,
    owner: &str,
    name: &str,
    writable: bool,
    backend: &crate::blob_store::BlobBackendIdentity,
    deadline: Instant,
) -> Result<super::ServingRepository, Error> {
    if !db::valid_name(owner) || !db::valid_name(name) {
        return Err(Error::not_found());
    }
    if writable {
        auth::writable(actor)?;
    }
    let mut client = acquire(pool, deadline).await?;
    let tx = begin_owned(&mut client, deadline).await?;
    let result = lookup_in_tx(&tx, actor, owner, name, writable, backend, deadline).await;
    let _ = tx.rollback().await;
    result
}

pub(crate) async fn lookup_in_tx(
    tx: &Transaction<'_>,
    actor: &Identity,
    owner: &str,
    name: &str,
    writable: bool,
    backend: &crate::blob_store::BlobBackendIdentity,
    deadline: Instant,
) -> Result<super::ServingRepository, Error> {
    bound(tx, deadline).await.map_err(map_refstore)?;
    let (min_role, action) =
        if writable { (Role::Write, RepoAction::ContentsWrite) } else { (Role::Read, RepoAction::ContentsRead) };
    let access = auth::authorize_repo_with_role(tx, actor, owner, name, min_role, action).await?;
    // Only an authorized caller reads the restore incarnation, as the first
    // shared-lock statement after auth and inside this same read-only `tx`
    // (every later read, including `LockedScope::lock`, reuses it; none opens
    // another transaction). `NOWAIT` is required: auth already holds
    // tokens/users/repository `FOR SHARE` and `backup::authority::fence` updates
    // the cluster row before its token rows, so a *blocking* cluster
    // `FOR SHARE` here could deadlock (token->cluster vs cluster->token). Only
    // this one read maps a contended lock locally; every other failure (and
    // every other DB read) keeps the shared deadline policy.
    let cluster_incarnation = map_cluster_incarnation(read_cluster_incarnation_nowait(tx).await)?;
    // The tenant identity is the owner namespace resolved by that
    // authorization, never the actor id.
    let scope =
        LockedScope::lock(tx, access.repo_id, false).await.map_err(map_refstore)?.ok_or_else(Error::not_found)?;
    let binding = scope.require_serving(access.owner_id, backend.as_hex()).map_err(map_scope_refusal)?;
    let gate = PgRefStoreCore
        .read_gate_in_tx(tx, access.repo_id, false)
        .await
        .map_err(map_refstore)?
        .ok_or_else(Error::not_found)?;
    // Durable binding realm must equal the live gate realm; a gate that moved
    // under another realm is a durable inconsistency, never a request verdict.
    scope.require_binding_matches_gate(&gate).map_err(|refusal| Error::internal(refusal.reason()))?;
    if gate.tenant_id() != access.owner_id
        || gate.object_format() != binding.object_format()
        || gate.repository_id() != access.repo_id
    {
        return Err(Error::internal("durable gate/binding realm mismatch"));
    }
    let repository = read_repository_in_tx(tx, access.repo_id).await?;
    Ok(super::ServingRepository { repository, gate, cluster_incarnation })
}

/// The generic, retryable refusal for a cluster-anchor lock that `NOWAIT`
/// could not take. It names no SQLSTATE, detail or incarnation.
const NOWAIT_CONTENDED: &str = "ref-store authority is busy; retry the same request";

/// Outcome of the cluster anchor `FOR SHARE NOWAIT`: either the incarnation was
/// read, or the lock was held by another transaction. Any other failure is
/// returned unchanged (and therefore mapped by the caller's shared mapper).
enum ClusterIncarnation {
    Read(Uuid),
    LockNotAvailable,
}

/// Lock and read the global restore incarnation (migration 085) `FOR SHARE NOWAIT`
/// in the caller's already-authorized transaction. Exactly one non-nil
/// singleton row is required; anything else is a typed store failure, never an
/// empty anchor.
async fn read_cluster_incarnation_nowait(
    tx: &Transaction<'_>,
) -> Result<ClusterIncarnation, crate::ref_store::contract::RefStoreError> {
    let rows = match tx
        .query("SELECT incarnation FROM public.cluster_authority WHERE singleton=true FOR SHARE NOWAIT", &[])
        .await
    {
        Ok(rows) => rows,
        Err(error) if nowait_contended(&error) => return Ok(ClusterIncarnation::LockNotAvailable),
        Err(error) => return Err(crate::ref_store::pg::db_error(error)),
    };
    let [row] = rows.as_slice() else {
        return Err(crate::ref_store::contract::RefStoreError::Database(format!(
            "cluster authority has {} singleton incarnation rows, expected exactly one",
            rows.len()
        )));
    };
    let incarnation: Uuid = row.try_get(0).map_err(|_| {
        crate::ref_store::contract::RefStoreError::Database("cluster authority row has no uuid incarnation".into())
    })?;
    if incarnation.is_nil() {
        return Err(crate::ref_store::contract::RefStoreError::Database("cluster authority incarnation is nil".into()));
    }
    Ok(ClusterIncarnation::Read(incarnation))
}

/// `SQLSTATE 55P03` (`lock_not_available`): the `NOWAIT` share lock was not
/// taken, nothing was written, and retrying the same statement is the remedy.
fn nowait_contended(error: &tokio_postgres::Error) -> bool {
    error.code() == Some(&tokio_postgres::error::SqlState::LOCK_NOT_AVAILABLE)
}

/// Map the cluster anchor outcome: only this lookup's contended `NOWAIT` becomes
/// the generic retryable service error; everything else keeps the shared mapper.
fn map_cluster_incarnation(
    outcome: Result<ClusterIncarnation, crate::ref_store::contract::RefStoreError>,
) -> Result<Uuid, Error> {
    match outcome {
        Ok(ClusterIncarnation::Read(incarnation)) => Ok(incarnation),
        Ok(ClusterIncarnation::LockNotAvailable) => Err(Error(StatusCode::SERVICE_UNAVAILABLE, NOWAIT_CONTENDED)),
        Err(error) => Err(map_refstore(error)),
    }
}

async fn read_repository_in_tx(tx: &Transaction<'_>, repository_id: Uuid) -> Result<Repository, Error> {
    let row = tx
        .query_opt(&format!("{} WHERE r.id=$1", db::REPO_SELECT), &[&repository_id])
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    Ok(Repository::from_row(&row))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authority_kind_wire_values_are_stable_and_unknown_is_rejected() {
        assert_eq!(AuthorityKind::PgRefStore.wire(), 1);
        assert_eq!(AuthorityKind::RaftRefStore.wire(), 2);
        assert_eq!(AuthorityKind::from_wire(1), Some(AuthorityKind::PgRefStore));
        assert_eq!(AuthorityKind::from_wire(2), Some(AuthorityKind::RaftRefStore));
        for byte in [0u8, 3, 9, u8::MAX] {
            assert_eq!(AuthorityKind::from_wire(byte), None, "{byte}");
        }
    }

    #[test]
    fn only_the_cluster_nowait_contention_is_a_generic_retryable_503() {
        let incarnation = Uuid::new_v4();
        assert_eq!(map_cluster_incarnation(Ok(ClusterIncarnation::Read(incarnation))).expect("read"), incarnation);
        let contended = map_cluster_incarnation(Ok(ClusterIncarnation::LockNotAvailable)).expect_err("503");
        assert_eq!(contended.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(contended.1, NOWAIT_CONTENDED);
        // Every other failure keeps the shared mapper: a deadline is still the
        // provisioning GATEWAY_TIMEOUT and an internal store failure is never
        // disclosed.
        let timed_out =
            map_cluster_incarnation(Err(crate::ref_store::contract::RefStoreError::Timeout)).expect_err("deadline");
        assert_eq!(timed_out.0, StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(timed_out.1, super::super::deadline_error().1);
        let missing =
            crate::ref_store::contract::RefStoreError::Database("cluster authority incarnation is nil".into());
        let internal = map_cluster_incarnation(Err(missing)).expect_err("internal");
        assert_eq!(internal.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(internal.1, "service temporarily unavailable");
    }
}
