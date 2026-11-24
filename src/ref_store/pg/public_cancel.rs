//! Exact public-to-private cancellation under the wrapper and restore locks.

use tokio::time::Instant;
use tokio_postgres::Transaction;
use uuid::Uuid;

use super::{
    PgRefStore, bound,
    public_attempt::{PublicAttemptFinishLookup, PublicAttemptRequest, ledger, parse_digest, parse_mode},
    public_terminal::current_scope_revision,
};
use crate::ref_store::{
    CancelReceipt, OperationIdentity, OperationLookup, OperationRecord, OperationState, RefStoreError,
    core::{pack_commit::PackCommitError, pack_snapshot::lock_cluster_incarnation},
    serving::ServingRepository,
};

/// Capability for the exact current attempt, resolved under the public lock set.
pub(crate) struct PublicCancellation {
    request: PublicAttemptRequest,
    identity: OperationIdentity,
    wrapper_state: OperationState,
}

impl PublicCancellation {
    pub(crate) fn identity(&self) -> &OperationIdentity {
        &self.identity
    }
}

impl PgRefStore {
    /// Resolve a public ID after the gateway's owner/admin preflight. No writes
    /// occur here. The caller must still run the authorized cancel coordinator.
    pub(crate) async fn lock_public_cancellation(
        &self,
        tx: &Transaction<'_>,
        serving: &ServingRepository,
        backend_identity: &str,
        public_id: Uuid,
        deadline: Instant,
    ) -> Result<PublicCancellation, PackCommitError> {
        let gate = &serving.gate;
        let repository_id = gate.repository_id();
        bound(tx, deadline).await?;
        let row = tx
            .query_opt(
                "SELECT w.issuer_id, w.wire_digest, w.request_mode, a.private_id
                 FROM ref_store_public_operations w JOIN ref_store_private_attempts a
                   ON a.repository_id=w.repository_id AND a.public_id=w.public_id AND a.slot=w.current_slot
                 WHERE w.repository_id=$1 AND w.public_id=$2",
                &[&repository_id, &public_id],
            )
            .await
            .map_err(super::db_error)?
            .ok_or_else(|| ledger("public cancellation has no current attempt"))?;
        let digest: String = row.get(1);
        let mode: String = row.get(2);
        let observed_private: Uuid = row.get(3);
        let request = PublicAttemptRequest {
            repository_id,
            admission_owner_id: gate.tenant_id(),
            issuer_id: row.get(0),
            public_id,
            wire_digest: parse_digest(&digest, "public cancellation wire digest is invalid")?,
            request_mode: parse_mode(&mode, "public cancellation mode is invalid")?,
            backend_identity: backend_identity.to_owned(),
            object_format: gate.object_format(),
            history_incarnation: gate.history_incarnation(),
            authority_epoch: gate.authority_epoch(),
            group_epoch: gate.group_epoch(),
            restore_incarnation: serving.cluster_incarnation,
        };
        self.lock_public_attempt(tx, &request, observed_private, deadline).await?;
        bound(tx, deadline).await?;
        if lock_cluster_incarnation(tx).await? != request.restore_incarnation {
            return Err(RefStoreError::IdentityConflict.into());
        }
        let PublicAttemptFinishLookup::Evidence(locked) =
            self.lookup_public_attempt_finish(tx, &request, deadline).await?
        else {
            return Err(RefStoreError::IdentityConflict.into());
        };
        let current = locked.evidence.current;
        let OperationLookup::Known(record) = self.get(tx, repository_id, current.private_id, deadline).await? else {
            return Err(ledger("public cancellation current operation is missing"));
        };
        if record.identity().digest() != &current.plan_digest
            || record.identity().lane() != &current.lane
            || record.identity().sequence() != current.sequence
            || record.state() != current.state
        {
            return Err(ledger("public cancellation current operation differs from its attempt"));
        }
        Ok(PublicCancellation { request, identity: record.identity().clone(), wrapper_state: locked.wrapper_state })
    }

    pub(crate) async fn cancel_locked_public_attempt(
        &self,
        tx: &Transaction<'_>,
        cancellation: &PublicCancellation,
        deadline: Instant,
    ) -> Result<CancelReceipt, RefStoreError> {
        bound(tx, deadline).await?;
        let request = &cancellation.request;
        tx.query_one(
            "SELECT rootyard_ref_store_require_attempt_lock($1,$2),
                    rootyard_ref_store_require_attempt_lock($1,$3)",
            &[&request.repository_id, &request.public_id, &cancellation.identity.operation_id()],
        )
        .await
        .map_err(super::db_error)?;
        self.cancel_locked(tx, &cancellation.identity).await
    }

    /// Publish the outcome in the same transaction as the private tombstone.
    pub(crate) async fn finish_public_cancellation(
        &self,
        tx: &Transaction<'_>,
        cancellation: &PublicCancellation,
        record: &OperationRecord,
        deadline: Instant,
    ) -> Result<(), PackCommitError> {
        let request = &cancellation.request;
        if record.identity() != cancellation.identity() || !record.state().is_terminal() {
            return Err(ledger("public cancellation returned an unrelated or pending operation"));
        }
        if record.state() != OperationState::Cancelled {
            self.mirror_public_attempt_terminal_after_cancel(tx, request, record, deadline).await?;
            return Ok(());
        }
        bound(tx, deadline).await?;
        // The coordinator now holds the repository and authority locks. An
        // archive or serving-realm change during the lane wait must roll the
        // tombstone back together with the wrapper update.
        current_scope_revision(tx, request).await?;
        if cancellation.wrapper_state == OperationState::Pending {
            let changed = tx
                .execute(
                    "UPDATE ref_store_public_operations w SET state='cancelled', cancelled_private_id=$3
                     WHERE w.repository_id=$1 AND w.public_id=$2 AND w.state='pending' AND EXISTS (
                       SELECT 1 FROM ref_store_private_attempts a
                       WHERE a.repository_id=w.repository_id AND a.public_id=w.public_id
                         AND a.slot=w.current_slot AND a.private_id=$3)",
                    &[&request.repository_id, &request.public_id, &record.identity().operation_id()],
                )
                .await
                .map_err(super::db_error)?;
            if changed != 1 {
                return Err(ledger("public cancellation did not settle its wrapper"));
            }
        } else if cancellation.wrapper_state != OperationState::Cancelled {
            return Err(ledger("public cancellation would replace a durable terminal"));
        }
        tx.query_one(
            "SELECT rootyard_ref_store_verify_public_operation($1,$2)",
            &[&request.repository_id, &request.public_id],
        )
        .await
        .map_err(super::db_error)?;
        Ok(())
    }
}
