//! SQL-only row helpers for the bounded TRANSIENT serving read pin (migration
//! 146).
//!
//! Every function here runs inside the one owned short transaction that
//! `super::serving_read` starts. Nothing opens a connection, commits, rolls back,
//! performs Blob/Git IO or mints a proof; rows in, data out.
//!
//! Lock order of the serving read write path (shared with every other A5 write
//! so the two families cannot deadlock):
//!
//! cluster authority `FOR SHARE` -> serving tenant usage -> serving repository
//! usage -> repository row `FOR SHARE` -> durable serving binding `FOR SHARE` ->
//! core gate `FOR UPDATE`
//!
//! The read/T2 path takes the cluster authority (capture anchor / T2 comparison)
//! -> repository -> binding -> gate `FOR SHARE` -> transient pin `FOR SHARE`;
//! release takes usage rows then the pin `FOR UPDATE`. No path locks a durable
//! `ref_store_core_pins` row or writes migration-140/143/144/145 rows.
mod insert;
mod rows;
mod sealed;
mod usage;

pub(super) use insert::{ServingReadInsert, insert_read};
pub(crate) use rows::ServingReadRow;
pub(super) use rows::{check_capture_digest, delete_read, load_read, read_packs, read_refs};
pub(super) use sealed::lock_cluster_incarnation;
pub(super) use usage::{has_expired, lock_usage, read_usage, reclaim_expired, recompute_usage};

use super::super::pack_commit::PackMode;
use super::super::serving_scope::{LockedScope, ScopeRefusal};
use super::super::snapshot_contract::MetadataSnapshotScope;
use super::super::snapshot_sql;
use crate::ref_store::contract::RefStoreError;
use crate::ref_store::pg;
use tokio_postgres::Transaction;
use uuid::Uuid;

/// Map the shared serving-scope refusal into this adapter's typed errors.
///
/// A tenant/not-serving/legacy refusal never discloses more than
/// `RepositoryNotFound`/`Unsupported`; a realm disagreement is a scope mismatch,
/// and a stored-vs-live backend disagreement is refused explicitly instead of
/// being promoted into a byte/proof success.
pub(super) fn map_scope_refusal(refusal: ScopeRefusal) -> RefStoreError {
    match refusal {
        ScopeRefusal::Tenant | ScopeRefusal::NotServing | ScopeRefusal::MissingBinding => {
            RefStoreError::Unsupported(refusal.reason())
        }
        ScopeRefusal::Realm(field) => RefStoreError::MetadataScopeMismatch(match field {
            super::super::serving_scope::RealmField::ObjectFormat => "repository object format",
            super::super::serving_scope::RealmField::HistoryIncarnation => "repository history incarnation",
            super::super::serving_scope::RealmField::AuthorityEpoch => "repository authority epoch",
            super::super::serving_scope::RealmField::GroupEpoch => "repository group epoch",
        }),
        ScopeRefusal::BackendIdentity => RefStoreError::MetadataScopeMismatch("live Blob backend identity"),
        ScopeRefusal::Inconsistent(reason) => RefStoreError::Database(reason.into()),
        other => RefStoreError::Unsupported(other.reason()),
    }
}

/// Lock and classify the strict `pg_refstore` serving realm of the caller scope
/// and return the current (locked) core gate.
///
/// This goes through the one shared authority predicate twice on purpose:
/// `snapshot_sql::lock_scope` proves the repository lane, the durable serving
/// binding readiness and the full stored-vs-requested realm, and
/// `LockedScope::require_serving` additionally compares the binding's stored
/// Blob backend digest with the identity of the store the caller actually holds
/// open. A ready row or a stored hex string alone is never authority.
pub(super) async fn lock_serving_realm(
    tx: &Transaction<'_>,
    scope: &MetadataSnapshotScope,
    backend_identity_hex: &str,
    gate_for_update: bool,
) -> Result<super::super::contract::CoreGate, RefStoreError> {
    let gate = snapshot_sql::lock_scope(tx, scope, true, gate_for_update).await?;
    let locked = LockedScope::lock(tx, scope.repository_id(), false).await?.ok_or(RefStoreError::RepositoryNotFound)?;
    locked.require_serving(scope.tenant_id(), backend_identity_hex).map_err(map_scope_refusal)?;
    Ok(gate)
}

/// The current gate pack mode without taking a lock.
///
/// Only used to decide the *shape* of the capture before the ordered usage locks
/// are taken. The decision is always re-proved under the gate `FOR UPDATE`
/// afterwards, so this read grants nothing.
pub(super) async fn peek_pack_mode(tx: &Transaction<'_>, repository_id: Uuid) -> Result<PackMode, RefStoreError> {
    let row = tx
        .query_opt("SELECT pack_mode FROM ref_store_core_gates WHERE repository_id=$1", &[&repository_id])
        .await
        .map_err(pg::db_error)?;
    match row {
        Some(row) => PackMode::parse(&row.get::<_, String>(0)),
        None => Err(RefStoreError::Unsupported("repository has no initialized core gate")),
    }
}
