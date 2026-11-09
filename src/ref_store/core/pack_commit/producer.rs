//! Distinct, durable producer-request binding for the served write path (#144).
//!
//! The core A3/A4 identity invariant stays exactly as it always was:
//!
//! ```text
//! ref_store_operations.request_digest == PackCommitPlan::parent_digest
//!     == A3 acquire/consume receipt.operation_digest
//!     == stored registration ACK.parent_digest
//! ```
//!
//! Registration, the stored-registration reader and the A3 ledger all enforce
//! that equality, so a plan may never re-label its own identity with an HTTP
//! wire digest. The served gateway nevertheless needs one stable producer value
//! to answer an exact retry *before* native Git and any A3/A4 write. This module
//! therefore stores that value in its own migration-147 table
//! (`ref_store_serving_operations`) and leaves the core identity untouched.
//!
//! Two entry points exist and both are crate-private:
//!
//! * [`PgPackCommit::begin_serving_pending_in_tx`] — the only writer. It runs on
//!   a **caller-owned** transaction, never opens or ends one, and performs no
//!   nested pool checkout. It reuses the exact migration-138 prefix of the core
//!   pending writer (`PgRefStore::begin`), requires the strict *ready
//!   `pg_refstore` serving* lane through the shared typed [`LockedScope`]
//!   predicate, and writes the producer binding in that same transaction. The
//!   pending operation row and its producer binding are therefore atomic: the
//!   caller's `COMMIT` acknowledges both and its rollback discards both.
//!
//!   A binding is only ever *created* together with a newly created pending row.
//!   When the migration-138 operation already existed (`BeginReceipt::created ==
//!   false`, an exact Pending replay) this function never inserts: it accepts
//!   only an already-present binding with the same repository, operation,
//!   issuer, wire digest and parent digest, and otherwise refuses with a typed
//!   conflict. That keeps the promised atomic-creation property and makes it
//!   impossible to retroactively assert wire-byte identity for a pending
//!   operation created by another path.
//! * [`read_serving_operation`] — the only reader. It runs inside a caller
//!   supplied bounded read transaction, joins the binding to its migration-138
//!   parent and refuses a binding whose issuer or parent digest disagrees with
//!   that parent. A missing row is `None` (the caller turns it into a typed
//!   conflict, never a replay); an inconsistent row is a `LedgerIntegrity`
//!   refusal, never `Some`.
//!
//! Deliberately absent: no nested PostgreSQL connection, no Blob/provider IO, no
//! native Git child, no per-GET row, no rewrite of `ref_store_operations` and no
//! derived/truncated UUID "proof". The public [`PgPackCommit::begin_pending`]
//! path is unchanged and still writes the original core parent digest only.
use super::error::{PackCommitError, PackCommitRejectCode};
use super::pg::{PgPackCommit, reject};
use super::plan::PackCommitPlan;
use super::request::PackPendingToken;
use crate::ref_store::contract::{RefStoreError, RequestDigest};
use crate::ref_store::core::serving_scope::{CoreLane, CoreRealm, LockedScope, RealmField, ScopeRefusal};
use crate::ref_store::pg::{before_deadline, bound, db_error};
use tokio::time::Instant;
use tokio_postgres::Transaction;
use uuid::Uuid;

/// Binding + parent identity in one statement, so the read adapter can never
/// validate a binding against a different record than the one it joined.
const SELECT_WITH_PARENT: &str = "SELECT s.repository_id,s.operation_id,s.issuer_id,\
        s.producer_request_digest,s.plan_parent_digest,o.issuer_id,o.request_digest \
     FROM ref_store_serving_operations s \
     JOIN ref_store_operations o \
       ON o.repository_id=s.repository_id AND o.operation_id=s.operation_id \
     WHERE s.repository_id=$1 AND s.operation_id=$2";

const SELECT_BINDING: &str = "SELECT repository_id,operation_id,issuer_id,\
        producer_request_digest,plan_parent_digest \
     FROM ref_store_serving_operations WHERE repository_id=$1 AND operation_id=$2";

const INSERT_BINDING: &str = "INSERT INTO ref_store_serving_operations \
        (repository_id,operation_id,issuer_id,producer_request_digest,plan_parent_digest) \
     VALUES ($1,$2,$3,$4,$5) ON CONFLICT (repository_id,operation_id) DO NOTHING";

/// One validated durable producer binding.
///
/// Both values are typed digests, never caller strings: `producer_digest` is the
/// producer's request digest used for exact HTTP replay and `parent_digest` is
/// the core canonical plan parent digest the A3 ledger was written under.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ServingOperationBinding {
    producer_digest: RequestDigest,
    parent_digest: RequestDigest,
}

impl ServingOperationBinding {
    pub(crate) fn producer_digest(&self) -> &RequestDigest {
        &self.producer_digest
    }

    pub(crate) fn parent_digest(&self) -> &RequestDigest {
        &self.parent_digest
    }
}

impl PgPackCommit {
    /// Establish (or exactly confirm) the pending operation **and** its durable
    /// producer binding inside the caller's already open transaction.
    ///
    /// Order inside the transaction is fixed and matches every other fresh core
    /// mutation: migration-138 prefix (operation advisory lock, repository
    /// existence, issuer lane, pending/tombstone state and exact identity) →
    /// strict ready `pg_refstore` serving lane → the producer binding write.
    ///
    /// This function never begins, commits or rolls back a transaction and never
    /// checks out another connection: the trusted gateway caller owns the
    /// acknowledgment durability (`SET LOCAL synchronous_commit = 'on'`), the
    /// bounded `COMMIT` that atomically publishes the lane reservation, the
    /// pending row and this binding, and the bounded rollback of every refusal.
    /// It is crate-private on purpose: it is a producer integration point, not a
    /// public plan constructor, and it cannot be used to upload or commit.
    pub(crate) async fn begin_serving_pending_in_tx(
        &self,
        tx: &Transaction<'_>,
        plan: &PackCommitPlan,
        producer_request_digest: RequestDigest,
        deadline: Instant,
    ) -> Result<PackPendingToken, PackCommitError> {
        let (token, created) = self.begin_pending_in_tx(tx, plan, deadline).await?;
        ensure_ready_serving_scope(tx, plan).await?;
        if created {
            // The pending row was inserted by this very transaction, so the
            // binding is created atomically with it.
            bind_producer_request(tx, plan, &producer_request_digest, deadline).await?;
        } else {
            // An exact existing pending row may already be bound (identical
            // concurrent retry) but must never be *newly* bound here: a
            // pre-existing unbound pending operation cannot acquire wire-byte
            // identity after the fact.
            require_existing_binding(tx, plan, &producer_request_digest).await?;
        }
        Ok(token)
    }
}

/// Typed read adapter for the durable producer binding.
///
/// Runs on the caller's already bounded read transaction (the gateway reads the
/// migration-138 record under the same transaction, so both rows come from one
/// consistent snapshot). `None` means "this operation has no producer binding"
/// and must be resolved by the caller as a typed conflict, never as a replay.
pub(crate) async fn read_serving_operation(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    operation_id: Uuid,
    deadline: Instant,
) -> Result<Option<ServingOperationBinding>, PackCommitError> {
    if repository_id.is_nil() || operation_id.is_nil() {
        return Err(PackCommitError::Invalid("serving operation lookup ids must be non-nil"));
    }
    bound(tx, deadline).await?;
    let rows = before_deadline(deadline, async {
        tx.query(SELECT_WITH_PARENT, &[&repository_id, &operation_id]).await.map_err(db_error)
    })
    .await?;
    let Some(row) = rows.first() else { return Ok(None) };
    let mapping_repository: Uuid = row.get(0);
    let mapping_operation: Uuid = row.get(1);
    let mapping_issuer: Uuid = row.get(2);
    let parent_digest = digest_column(row, 4)?;
    let producer_digest = digest_column(row, 3)?;
    let record_issuer: Uuid = row.get(5);
    let record_digest = digest_column(row, 6)?;
    if mapping_repository != repository_id || mapping_operation != operation_id {
        return Err(reject(
            PackCommitRejectCode::LedgerIntegrity,
            "serving producer binding names another repository or operation",
        ));
    }
    ensure_parent_consistency(mapping_issuer, parent_digest, record_issuer, record_digest)?;
    Ok(Some(ServingOperationBinding { producer_digest, parent_digest }))
}

/// The binding must be the *same* issuer and the *same* plan parent digest as
/// the migration-138 operation it hangs from; anything else is durable ledger
/// corruption, never a weaker "probably fine" replay.
fn ensure_parent_consistency(
    mapping_issuer: Uuid,
    mapping_parent: RequestDigest,
    record_issuer: Uuid,
    record_digest: RequestDigest,
) -> Result<(), PackCommitError> {
    if mapping_issuer != record_issuer {
        return Err(reject(
            PackCommitRejectCode::LedgerIntegrity,
            "serving producer binding issuer differs from its operation",
        ));
    }
    if mapping_parent != record_digest {
        return Err(reject(
            PackCommitRejectCode::LedgerIntegrity,
            "serving producer binding parent digest differs from the operation request digest",
        ));
    }
    Ok(())
}

/// Insert (or exactly confirm) the single producer binding of a pending row this
/// transaction just created.
///
/// The insert is guarded in SQL by migration 147 as well: same issuer, pending
/// parent and `plan_parent_digest == parent.request_digest`. The read-back
/// comparison here makes the typed adapter independently strict, so a durable
/// row written under another wire digest can never be reused.
async fn bind_producer_request(
    tx: &Transaction<'_>,
    plan: &PackCommitPlan,
    producer_request_digest: &RequestDigest,
    deadline: Instant,
) -> Result<(), PackCommitError> {
    let repository_id = plan.repository_id();
    let operation_id = plan.identity().operation_id();
    let issuer_id = plan.identity().issuer_id();
    let producer_hex = producer_request_digest.as_hex();
    let parent_hex = plan.parent_digest().as_hex();
    before_deadline(deadline, async {
        tx.execute(INSERT_BINDING, &[&repository_id, &operation_id, &issuer_id, &producer_hex, &parent_hex])
            .await
            .map_err(db_error)
    })
    .await?;
    let Some((stored_issuer, stored_producer, stored_parent)) =
        read_binding_row(tx, repository_id, operation_id).await?
    else {
        return Err(reject(
            PackCommitRejectCode::LedgerIntegrity,
            "durable serving producer binding disappeared inside its own transaction",
        ));
    };
    if stored_issuer != issuer_id {
        return Err(reject(
            PackCommitRejectCode::LedgerIntegrity,
            "durable serving producer binding belongs to another issuer",
        ));
    }
    if stored_producer != *producer_request_digest || stored_parent != *plan.parent_digest() {
        return Err(reject(
            PackCommitRejectCode::LedgerIntegrity,
            "operation identifier was already bound to a different producer request",
        ));
    }
    Ok(())
}

/// Accept an existing pending row only when its durable producer binding is
/// already exactly this request. Nothing is inserted on this path.
async fn require_existing_binding(
    tx: &Transaction<'_>,
    plan: &PackCommitPlan,
    producer_request_digest: &RequestDigest,
) -> Result<(), PackCommitError> {
    let repository_id = plan.repository_id();
    let operation_id = plan.identity().operation_id();
    let Some((stored_issuer, stored_producer, stored_parent)) =
        read_binding_row(tx, repository_id, operation_id).await?
    else {
        return Err(PackCommitError::from(RefStoreError::IdentityConflict));
    };
    if stored_issuer != plan.identity().issuer_id()
        || stored_producer != *producer_request_digest
        || stored_parent != *plan.parent_digest()
    {
        return Err(PackCommitError::from(RefStoreError::IdentityConflict));
    }
    Ok(())
}

/// Read one raw binding row (already inside the write transaction).
async fn read_binding_row(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    operation_id: Uuid,
) -> Result<Option<(Uuid, RequestDigest, RequestDigest)>, PackCommitError> {
    let rows = tx.query(SELECT_BINDING, &[&repository_id, &operation_id]).await.map_err(db_error)?;
    let Some(row) = rows.first() else { return Ok(None) };
    let issuer_id: Uuid = row.get(2);
    let producer_digest = digest_column(row, 3)?;
    let parent_digest = digest_column(row, 4)?;
    Ok(Some((issuer_id, producer_digest, parent_digest)))
}

/// Strict lane check: only a *ready* `pg_refstore` serving authority whose
/// durable migration-145 binding matches this plan realm may own a producer
/// binding. The unserved `gitfs` fixture lane keeps its own (unchanged) A4
/// semantics and is refused here instead of silently gaining HTTP replay.
async fn ensure_ready_serving_scope(tx: &Transaction<'_>, plan: &PackCommitPlan) -> Result<(), PackCommitError> {
    let scope = LockedScope::lock(tx, plan.repository_id(), false)
        .await?
        .ok_or_else(|| PackCommitError::from(RefStoreError::RepositoryNotFound))?;
    if scope.owner_id() != plan.tenant_id() {
        return Err(reject(PackCommitRejectCode::TenantMismatch, "repository belongs to another tenant"));
    }
    let realm = CoreRealm::new(
        plan.tenant_id(),
        plan.object_format(),
        plan.history_incarnation(),
        plan.authority_epoch(),
        plan.group_epoch(),
    );
    match scope.require_fresh_core(&realm) {
        Ok(CoreLane::PgRefStore) => Ok(()),
        Ok(CoreLane::LegacyUnservedGitfs) => Err(PackCommitError::from(RefStoreError::Unsupported(
            "a producer operation binding requires a ready pg_refstore serving authority",
        ))),
        Err(ScopeRefusal::Realm(RealmField::ObjectFormat)) => {
            Err(reject(PackCommitRejectCode::ObjectFormatMismatch, "repository object format differs"))
        }
        Err(ScopeRefusal::Realm(_)) => {
            Err(reject(PackCommitRejectCode::HistoryIncarnationMismatch, "repository gate epochs differ"))
        }
        Err(refusal) => Err(PackCommitError::from(RefStoreError::Unsupported(refusal.reason()))),
    }
}

/// Parse one stored 64-hex digest column. A non-canonical stored value is
/// durable corruption, never a weaker value to compare against.
fn digest_column(row: &tokio_postgres::Row, index: usize) -> Result<RequestDigest, PackCommitError> {
    let raw: String = row.get(index);
    raw.parse().map_err(|_| {
        reject(PackCommitRejectCode::LedgerIntegrity, "stored serving producer digest is not 64 lowercase hex")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> RequestDigest {
        RequestDigest::from_bytes([byte; 32])
    }

    #[test]
    fn binding_requires_the_same_issuer_and_parent_digest() {
        let issuer = Uuid::from_bytes([1; 16]);
        assert!(ensure_parent_consistency(issuer, digest(2), issuer, digest(2)).is_ok());

        let foreign = ensure_parent_consistency(issuer, digest(2), Uuid::from_bytes([3; 16]), digest(2));
        assert!(matches!(
            foreign,
            Err(PackCommitError::Rejected(rejection))
                if rejection.code == PackCommitRejectCode::LedgerIntegrity
        ));

        let relabelled = ensure_parent_consistency(issuer, digest(2), issuer, digest(4));
        assert!(matches!(
            relabelled,
            Err(PackCommitError::Rejected(rejection))
                if rejection.code == PackCommitRejectCode::LedgerIntegrity
        ));
    }
}
