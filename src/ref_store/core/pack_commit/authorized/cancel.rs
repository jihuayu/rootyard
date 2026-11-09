//! Authorized cancellation: the migration-138 tombstone **and** the decision
//! tombstone in one short transaction.
//!
//! `publication_decision::coordinator_cancel` performs both writes under the
//! operation advisory key — it authorizes the caller, takes the 138 prefix
//! (`PgRefStore::cancel`, which persists the cancellation tombstone) and then
//! closes the decision row (`OPEN -> CANCELLED`). This module adds the pool,
//! deadline and durability framing only; it never re-implements an authority
//! check and never writes a ref row, a gate revision or an event.
use super::super::error::PackCommitError;
use super::{AuthorizedCommitError, PgAuthorizedCommit, effective_deadline, pooled_client};
use crate::db::Identity;
use crate::ref_store::contract::OperationIdentity;
use crate::ref_store::core::publication_decision::{self, CancelOutcome};
use crate::ref_store::tx::{begin_bounded, commit_bounded};
use tokio::time::{Instant, timeout_at};
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

impl PgAuthorizedCommit {
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
