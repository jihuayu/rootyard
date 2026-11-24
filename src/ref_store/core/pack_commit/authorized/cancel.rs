//! Authorized cancellation: the migration-138 tombstone **and** the decision
//! tombstone in one short transaction.
//!
//! `publication_decision::coordinator_cancel` performs both writes under the
//! operation advisory key — it authorizes the caller, takes the 138 prefix
//! (`PgRefStore::cancel`, which persists the cancellation tombstone) and then
//! closes the decision row (`OPEN -> CANCELLED`). This module adds the pool,
//! deadline and durability framing only; it never re-implements an authority
//! check and never writes a ref row, a gate revision or an event.
use super::super::error::{PackCommitError, PackCommitRejectCode};
use super::super::producer::read_serving_operation;
use super::{AuthorizedCommitError, PgAuthorizedCommit, effective_deadline, pooled_client};
use crate::db::Identity;
use crate::ref_store::contract::{OperationIdentity, OperationLookup, OperationRecord};
use crate::ref_store::core::publication_decision::{self, CancelOutcome};
use crate::ref_store::pg::{LegacyStatusLookup, PgRefStore};
use crate::ref_store::serving::ServingRepository;
use crate::ref_store::tx::{begin_bounded, commit_bounded};
use tokio::time::{Instant, timeout_at};
use tokio_postgres::Transaction;
use uuid::Uuid;

/// Public cancel outcome. It carries ids only — never a token, a digest or a
/// receipt body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorizedCancelOutcome {
    /// The tombstone won: no ref or revision write can ever happen for this
    /// operation under this identity.
    Cancelled,
    /// An identical cancellation was already durable (idempotent replay).
    AlreadyCancelled,
    /// The publication already committed; cancellation lost the race.
    AlreadyCommitted,
    /// The decision was already durably rejected.
    AlreadyRejected,
}

/// Bounded result of one authorized cancel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedCancelReceipt {
    pub operation_id: Uuid,
    pub decision_id: Option<Uuid>,
    pub outcome: AuthorizedCancelOutcome,
}

impl AuthorizedCancelReceipt {
    pub fn is_cancelled(&self) -> bool {
        matches!(self.outcome, AuthorizedCancelOutcome::Cancelled | AuthorizedCancelOutcome::AlreadyCancelled)
    }
}

enum GatewayCancellation {
    Missing,
    Legacy,
    Public(OperationRecord),
}

impl PgAuthorizedCommit {
    /// Resolve the stable HTTP identifier and cancel its exact current attempt.
    /// The coordinator rechecks live owner/admin authority before committing.
    pub(crate) async fn cancel_gateway_operation(
        &self,
        pool: &deadpool_postgres::Pool,
        actor: &Identity,
        serving: &ServingRepository,
        public_id: Uuid,
        reason: &str,
        deadline: Instant,
    ) -> Result<Option<OperationRecord>, AuthorizedCommitError> {
        let deadline = effective_deadline(deadline)?;
        let repository_id = serving.gate.repository_id();
        let mut client = pooled_client(pool, deadline).await?;
        let tx = begin_bounded(&mut client, deadline).await?;
        let stage = async {
            let route = PgRefStore.get_legacy_status(&tx, repository_id, public_id, deadline).await?;
            match route {
                LegacyStatusLookup::PrivateIdentifier | LegacyStatusLookup::Unknown => {
                    return Ok(GatewayCancellation::Missing);
                }
                LegacyStatusLookup::Legacy(_) => return Ok(GatewayCancellation::Legacy),
                LegacyStatusLookup::PublicWrapper => {}
            }
            super::super::pg::set_ack_durability(&tx, deadline).await?;
            let cancellation = PgRefStore
                .lock_public_cancellation(&tx, serving, self.store.backend_identity().as_hex(), public_id, deadline)
                .await?;
            publication_decision::cancel::coordinator_cancel_public_attempt(
                &tx,
                actor,
                &cancellation,
                reason,
                deadline,
            )
            .await
            .map_err(super::decision_error)?;
            let private_id = cancellation.identity().operation_id();
            let OperationLookup::Known(record) = PgRefStore.get(&tx, repository_id, private_id, deadline).await? else {
                return Err(AuthorizedCommitError::Ledger("public cancellation current attempt disappeared"));
            };
            PgRefStore.finish_public_cancellation(&tx, &cancellation, &record, deadline).await?;
            Ok(GatewayCancellation::Public(record))
        };
        match timeout_at(deadline, stage).await {
            Ok(Ok(GatewayCancellation::Public(record))) => {
                commit_bounded(tx, deadline, repository_id, Some(public_id)).await.map_err(PackCommitError::from)?;
                Ok(Some(record))
            }
            Ok(Ok(GatewayCancellation::Missing)) => {
                super::rollback(tx, deadline).await?;
                Ok(None)
            }
            Ok(Ok(GatewayCancellation::Legacy)) => {
                super::rollback(tx, deadline).await?;
                drop(client);
                self.cancel_known(pool, actor, repository_id, public_id, reason, deadline).await
            }
            Ok(Err(error)) => {
                let _ = super::rollback(tx, deadline).await;
                Err(error)
            }
            Err(_) => {
                let _ = super::rollback(tx, deadline).await;
                Err(AuthorizedCommitError::Timeout)
            }
        }
    }

    /// Cancel one publication before it installs (or after it installed but before
    /// it consumed).
    ///
    /// * current authority for the calling actor is checked by the decision module
    ///   (it re-reads the live token/RBAC rows inside the transaction);
    /// * the 138 cancellation tombstone and the decision tombstone are written in
    ///   the **same** short transaction, under the operation advisory key, so a
    ///   racing commit and this cancel cannot both win;
    /// * an unknown operation stays unknown to callers: no refund, no root/hold
    ///   release and no authority replay happens here.
    pub async fn cancel(
        &self,
        pool: &deadpool_postgres::Pool,
        actor: &Identity,
        identity: &OperationIdentity,
        reason: &str,
        deadline: Instant,
    ) -> Result<AuthorizedCancelReceipt, AuthorizedCommitError> {
        let deadline = effective_deadline(deadline)?;
        let mut client = pooled_client(pool, deadline).await?;
        let tx = begin_bounded(&mut client, deadline).await?;
        let stage = async {
            super::super::pg::set_ack_durability(&tx, deadline).await.map_err(AuthorizedCommitError::from)?;
            publication_decision::coordinator_cancel(&tx, actor, identity, reason, deadline)
                .await
                .map_err(super::decision_error)
        };
        let result = match timeout_at(deadline, stage).await {
            Ok(value) => value,
            Err(_) => Err(AuthorizedCommitError::Timeout),
        };
        match result {
            Ok(outcome) => {
                commit_bounded(tx, deadline, identity.repository_id(), Some(identity.operation_id()))
                    .await
                    .map_err(PackCommitError::from)?;
                Ok(receipt(identity.operation_id(), outcome))
            }
            Err(error) => {
                let _cleanup = super::rollback(tx, deadline).await;
                Err(error)
            }
        }
    }

    /// Resolve one **already registered** operation by its repository-scoped
    /// UUID and cancel it in one bounded, `synchronous_commit=on` transaction.
    ///
    /// The stored migration-138 record is the only identity source: the caller
    /// supplies no issuer, lane, sequence, digest or reason beyond the fixed
    /// server reason. The migration-138 operation advisory key is taken *before*
    /// the registry read, so this resolution is linearized with a concurrent
    /// begin/commit on the same UUID. A known record must also have its exact
    /// migration-147 producer binding; a missing or inconsistent binding is a
    /// ledger refusal, never a weaker cancellation. Wrapper and attempt UUIDs
    /// are conflicts at this legacy entrypoint.
    ///
    /// `Ok(None)` means no operation row exists for this repository; the
    /// transaction is rolled back and **no cancellation tombstone is written**.
    /// For a known operation, the existing authorized decision coordinator is
    /// called in the same transaction. It rechecks the live writable token and
    /// current owner/admin role under its documented lock order, then either
    /// wins with an immutable `Cancelled` terminal or observes the exact
    /// committed/rejected terminal that already won. The returned record is read
    /// back inside this same transaction, so an ambiguous `COMMIT` stays a typed
    /// unknown rather than a guessed success or failure.
    pub async fn cancel_known(
        &self,
        pool: &deadpool_postgres::Pool,
        actor: &Identity,
        repository_id: Uuid,
        operation_id: Uuid,
        reason: &str,
        deadline: Instant,
    ) -> Result<Option<OperationRecord>, AuthorizedCommitError> {
        if repository_id.is_nil() || operation_id.is_nil() {
            return Err(AuthorizedCommitError::Unverifiable("operation cancellation ids must be non-nil"));
        }
        let deadline = effective_deadline(deadline)?;
        let mut client = pooled_client(pool, deadline).await?;
        let tx = begin_bounded(&mut client, deadline).await?;
        let stage = async {
            super::super::pg::set_ack_durability(&tx, deadline).await.map_err(AuthorizedCommitError::from)?;
            // Same migration-138 prefix as begin/reserve/cancel. The coordinator
            // reacquires this transaction-scoped key below; that is a no-op and
            // preserves operation -> lane -> ... ordering.
            crate::ref_store::pg::lock_operation(&tx, repository_id, operation_id, deadline)
                .await
                .map_err(AuthorizedCommitError::from)?;
            let Some(record) = resolve_registered_operation(&tx, repository_id, operation_id, deadline).await? else {
                return Ok(None);
            };
            publication_decision::coordinator_cancel(&tx, actor, record.identity(), reason, deadline)
                .await
                .map_err(super::decision_error)?;
            let final_record = match PgRefStore.get(&tx, repository_id, operation_id, deadline).await? {
                OperationLookup::Known(record) => record,
                OperationLookup::Unknown => {
                    return Err(AuthorizedCommitError::Ledger(
                        "operation disappeared inside its cancellation transaction",
                    ));
                }
            };
            if final_record.identity().repository_id() != repository_id
                || final_record.identity().operation_id() != operation_id
            {
                return Err(AuthorizedCommitError::Ledger("cancellation returned a foreign operation identity"));
            }
            if !final_record.state().is_terminal() || final_record.terminal_result().is_none() {
                return Err(AuthorizedCommitError::Ledger("cancellation did not produce an immutable terminal result"));
            }
            Ok(Some(final_record))
        };
        let staged = match timeout_at(deadline, stage).await {
            Ok(value) => value,
            Err(_) => Err(AuthorizedCommitError::Timeout),
        };
        match staged {
            Ok(Some(record)) => {
                commit_bounded(tx, deadline, repository_id, Some(operation_id)).await.map_err(PackCommitError::from)?;
                Ok(Some(record))
            }
            Ok(None) => {
                // The caller resolved an unknown UUID after authorization. No
                // operation row, cancellation tombstone or decision row exists.
                super::rollback(tx, deadline).await?;
                Ok(None)
            }
            Err(error) => {
                let _cleanup = super::rollback(tx, deadline).await;
                Err(error)
            }
        }
    }
}

/// Resolve the stored migration-138 record and its exact migration-147 producer
/// binding in the caller-owned cancellation transaction without writing anything.
///
/// This is the same A3/Core identity check the served receive probe uses
/// (`operation::lookup_in_tx`): the binding must exist, name this repository and
/// operation, and its parent digest must equal the core record digest. The
/// migration-147 adapter itself also rejects a different issuer or parent.
async fn resolve_registered_operation(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    operation_id: Uuid,
    deadline: Instant,
) -> Result<Option<OperationRecord>, AuthorizedCommitError> {
    let record = match PgRefStore.get_legacy_locked(tx, repository_id, operation_id, deadline).await? {
        OperationLookup::Unknown => return Ok(None),
        OperationLookup::Known(record) => record,
    };
    let identity = record.identity();
    if identity.repository_id() != repository_id || identity.operation_id() != operation_id {
        return Err(AuthorizedCommitError::Ledger("operation lookup returned a foreign identity"));
    }
    let Some(binding) = read_serving_operation(tx, repository_id, operation_id, deadline).await? else {
        return Err(super::reject(
            PackCommitRejectCode::LedgerIntegrity,
            "operation has no durable producer request binding; it cannot be cancelled from this endpoint",
        ));
    };
    if binding.parent_digest() != identity.digest() {
        return Err(super::reject(
            PackCommitRejectCode::LedgerIntegrity,
            "serving producer binding parent digest differs from its operation record",
        ));
    }
    Ok(Some(record))
}

/// Public projection of the decision module's cancel outcome.
fn receipt(operation_id: Uuid, outcome: CancelOutcome) -> AuthorizedCancelReceipt {
    let (decision_id, outcome) = match outcome {
        CancelOutcome::Cancelled { decision_id, .. } => (decision_id, AuthorizedCancelOutcome::Cancelled),
        CancelOutcome::AlreadyCancelled { decision_id, .. } => (decision_id, AuthorizedCancelOutcome::AlreadyCancelled),
        CancelOutcome::AlreadyConsumed { decision_id, .. } => {
            (Some(decision_id), AuthorizedCancelOutcome::AlreadyCommitted)
        }
        CancelOutcome::AlreadyRejected { decision_id, .. } => (decision_id, AuthorizedCancelOutcome::AlreadyRejected),
    };
    AuthorizedCancelReceipt { operation_id, decision_id, outcome }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancel_receipts_are_secret_free_and_typed() {
        let id = Uuid::from_bytes([4; 16]);
        let cancelled =
            receipt(id, CancelOutcome::Cancelled { operation_id: id, decision_id: Some(id), tombstone_created: true });
        assert!(cancelled.is_cancelled());
        assert_eq!(cancelled.operation_id, id);
        assert!(!format!("{cancelled:?}").contains("token"));
        let consumed =
            receipt(id, CancelOutcome::AlreadyConsumed { operation_id: id, decision_id: id, receipt_id: id });
        assert!(!consumed.is_cancelled());
        assert_eq!(consumed.outcome, AuthorizedCancelOutcome::AlreadyCommitted);
    }
}
