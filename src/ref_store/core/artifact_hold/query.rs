//! Receipt-only queries for the artifact-hold adapter (A3).
//!
//! These methods resolve an unknown acquire/consume `COMMIT` from the stable
//! global request ids. They never mint a grant, a consumed token or any IO
//! capability, and they never call the Blob layer. Both run in one read-only
//! short transaction over immutable rows.
//!
//! A missing request row is `Unknown`; a row set that is only *partly* present,
//! or that disagrees with its own body, another ledger row or the immutable
//! bounded hold set is a typed [`ArtifactHoldError::LedgerIntegrity`] error.
//! Such a partial or corrupt answer is never reported as `Found`, because
//! `Found` is what a caller treats as the complete durable outcome, and it is
//! never guessed as `Unknown` either.
//!
//! Historical receipt checks use the *immutable* ACK scope (owner, purpose,
//! format, history incarnation, epochs, parent operation, gate proof recorded at
//! acquire time) and the complete durable hold rows. They never read the
//! current core gate or the parent business operation, so a later gate move,
//! profile change or deleted parent cannot rewrite history and cannot
//! resurrect authority.
use super::consume::{ensure_immutable_batch, ensure_receipt_matches_hold};
use super::contract::{ArtifactHoldError, HoldScope};
use super::pg::{PgArtifactHoldStore, before_deadline};
use super::receipt::{AcquireAck, AcquireLookup, ConsumeAck, ConsumeLookup};
use super::{sql, sql_rows};
use crate::ref_store::pg;
use crate::ref_store::tx::begin_bounded;
use tokio::time::Instant;
use tokio_postgres::Client;
use uuid::Uuid;

impl PgArtifactHoldStore {
    /// Receipt-only resolution of an acquire request. A missing row is
    /// `Unknown`, never an abort or a grant. It is a read-only short
    /// transaction over immutable rows, including every bounded hold row of
    /// the request: the answer is `Found` only when the complete hold set
    /// matches the ACK batch.
    pub async fn acquire_receipt(
        &self,
        client: &mut Client,
        scope: &HoldScope,
        request_id: Uuid,
        deadline: Instant,
    ) -> Result<AcquireLookup, ArtifactHoldError> {
        if request_id.is_nil() {
            return Err(ArtifactHoldError::InvalidRequest("artifact hold request id must be non-nil".into()));
        }
        let tx = begin_bounded(client, deadline).await.map_err(ArtifactHoldError::from)?;
        let result = before_deadline(deadline, async {
            pg::bound(&tx, deadline).await?;
            let Some(stored) = sql::stored_acquire(&tx, request_id).await? else {
                return Ok(AcquireLookup::Unknown);
            };
            if stored.repository_id != scope.repository_id() || stored.tenant_id != scope.tenant_id() {
                return Err(ArtifactHoldError::RepositoryNotFound);
            }
            let ack = AcquireAck::decode(&stored.body)?;
            ack.ensure_scope(scope)?;
            // Read every bounded hold row of this request and require the
            // exact canonical batch: count, slots, hold ids, backend/locator,
            // active generation-1 state, duplicated scope, parent operation and
            // per-hold byte accounting. The request row/body/outer columns are
            // validated by the same shared helper.
            let holds = sql_rows::holds_for_request(&tx, request_id).await?;
            ensure_immutable_batch(&stored, &ack, &holds)?;
            Ok(AcquireLookup::Found(ack))
        })
        .await;
        let _ = tx.rollback().await;
        result
    }

    /// Receipt-only resolution of an unknown consume `COMMIT`. It returns no
    /// token and grants no IO. A missing acquire/consume row is `Unknown`; a
    /// partial or corrupt receipt set, or an acquire hold set that is not the
    /// exact bounded ACK batch, is an integrity error.
    pub async fn consume_receipt(
        &self,
        client: &mut Client,
        scope: &HoldScope,
        acquire_request_id: Uuid,
        consume_request_id: Uuid,
        deadline: Instant,
    ) -> Result<ConsumeLookup, ArtifactHoldError> {
        if acquire_request_id.is_nil() || consume_request_id.is_nil() {
            return Err(ArtifactHoldError::InvalidRequest(
                "artifact acquire/consume request ids must be non-nil".into(),
            ));
        }
        let tx = begin_bounded(client, deadline).await.map_err(ArtifactHoldError::from)?;
        let result = before_deadline(deadline, async {
            pg::bound(&tx, deadline).await?;
            let Some(stored_request) = sql::stored_acquire(&tx, acquire_request_id).await? else {
                return Ok(ConsumeLookup::Unknown);
            };
            if stored_request.repository_id != scope.repository_id() || stored_request.tenant_id != scope.tenant_id() {
                return Err(ArtifactHoldError::RepositoryNotFound);
            }
            let ack = AcquireAck::decode(&stored_request.body)?;
            ack.ensure_scope(scope)?;
            if ack.consume_request_id != consume_request_id {
                return Err(ArtifactHoldError::LedgerIntegrity(
                    "consume request id differs from its immutable acquire ACK",
                ));
            }
            // The immutable acquire row/body and the complete bounded hold set
            // must agree before an empty receipt set may be reported as
            // `Unknown`: a partial or rewritten acquire ledger is corruption,
            // not an uncommitted consume.
            let holds = sql_rows::holds_for_request(&tx, acquire_request_id).await?;
            ensure_immutable_batch(&stored_request, &ack, &holds)?;
            let stored = sql_rows::receipts_for_consume_request(&tx, consume_request_id).await?;
            if stored.is_empty() {
                // Nothing committed (yet): this is the only legitimate Unknown.
                return Ok(ConsumeLookup::Unknown);
            }
            if stored.len() != ack.artifacts.len() {
                return Err(ArtifactHoldError::LedgerIntegrity(
                    "stored consume receipt set is not the complete acquire batch",
                ));
            }
            let mut receipts = Vec::with_capacity(stored.len());
            for row in &stored {
                let receipt = ConsumeAck::decode(&row.body)?;
                // Body vs its own outer row, including the database-clock
                // consumption timestamp.
                row.ensure_receipt(&receipt)?;
                receipt.ensure_scope(scope)?;
                // Full immutable scope/parent/gate tuple vs the acquire ACK.
                receipt.ensure_acquire_ack(&ack)?;
                let hold_row = holds.iter().find(|hold| hold.hold_id == row.hold_id).ok_or(
                    ArtifactHoldError::LedgerIntegrity("stored consume receipt names a hold outside the hold set"),
                )?;
                ensure_receipt_matches_hold(&receipt, hold_row)?;
                receipts.push(receipt);
            }
            for hold in &ack.artifacts {
                if !stored.iter().any(|row| row.hold_id == hold.hold_id) {
                    return Err(ArtifactHoldError::LedgerIntegrity(
                        "stored consume receipt set is missing an acquire slot",
                    ));
                }
            }
            receipts.sort_by_key(|receipt| receipt.slot);
            Ok(ConsumeLookup::Found(receipts))
        })
        .await;
        let _ = tx.rollback().await;
        result
    }
}
