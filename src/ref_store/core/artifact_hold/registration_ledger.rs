//! Read-only internal A3 ledger view for A4 pack registration.
//!
//! A4 registers an actual protected publication by the *direct* acquire and
//! consume request ids of the A3 batch it just uploaded. This module exposes one
//! core-scoped reader returning the fully cross-validated immutable artefacts of
//! that batch: the acquire [`AcquireAck`] and the complete canonical
//! [`ConsumeAck`] receipt set. It is neither a public external API nor a
//! capability:
//!
//! * it never opens, commits, rolls back or nests a transaction, and it sets no
//!   statement timeout or other session/`SET LOCAL` state: the caller passes its
//!   own `Transaction` and keeps ownership of the absolute PostgreSQL deadline,
//!   the parent 138 operation/gate locks and the quota locks;
//! * it performs only ordinary bounded `SELECT`s — the same keyed 16+1 row reads
//!   and the same validators as the receipt-only `query::consume_receipt` — so
//!   it takes no advisory lock, no row lock, no provider IO and no write;
//! * it mints no grant, consumed token, upload intent or receipt body, and it
//!   never reconstructs a `BlobReceipt`, locator write intent or serialization
//!   capability;
//! * a missing, partial or rewritten request/hold/receipt set is a typed refusal
//!   ([`ArtifactHoldError::IdentityConflict`] or
//!   [`ArtifactHoldError::LedgerIntegrity`]) that names the id; it is never a
//!   grant, never an implicit registration and never `Unknown`;
//! * the checks are historical. They read only the immutable ACK, the complete
//!   durable hold rows and the immutable consume receipts; they never read the
//!   current core gate or a live parent business operation, so no later gate
//!   move, profile change or deleted parent can rewrite this history and no
//!   historical row can revive current authority. A4 must still check the
//!   current exact pending parent, its cancellation tombstone and the current
//!   gate revision/mode separately.
//!
//! The receipt-only adapter query (`PgArtifactHoldStore::consume_receipt`) opens
//! its own short transaction, so it must not be called from inside an A4
//! transaction; [`read_registration_ledger`] is the in-transaction form. It
//! reuses the existing `pub(super)` helpers of `sql`, `sql_rows` and `consume`
//! unchanged and widens no private capability mint point.
use super::consume::{ensure_immutable_batch, ensure_receipt_matches_hold};
use super::contract::{ArtifactHoldError, HoldScope};
use super::receipt::{AcquireAck, ConsumeAck};
use super::{sql, sql_rows};
use uuid::Uuid;

/// Opaque, read-only metadata of one finished A3 acquire+consume batch.
///
/// The fields are private on purpose: this value is inert historical evidence,
/// not authority. It carries no grant, token, write intent or capability, and it
/// can only be built by [`read_registration_ledger`] after the immutable ledger
/// rows, their bodies and their cross-references all agree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::ref_store::core) struct RegistrationLedger {
    acquire_ack: AcquireAck,
    consume_receipts: Vec<ConsumeAck>,
}

impl RegistrationLedger {
    /// The immutable acquire ACK of the registered batch: request/scope identity,
    /// parent operation tuple, gate proof recorded at acquire time, physical
    /// backend identity and the bounded hold set.
    pub(in crate::ref_store::core) fn acquire_ack(&self) -> &AcquireAck {
        &self.acquire_ack
    }

    /// The complete immutable consume receipts, in canonical slot order. Their
    /// length always equals the ACK batch length.
    pub(in crate::ref_store::core) fn consume_receipts(&self) -> &[ConsumeAck] {
        &self.consume_receipts
    }
}

/// Read and fully cross-validate the immutable A3 ledger view of one finished
/// acquire+consume batch inside the caller's transaction.
///
/// Preconditions owned by the caller (never by this function): an open
/// transaction with its absolute deadline, and the parent 138/gate/quota lock
/// order if the surrounding A4 work needs it. This reader adds no lock of its
/// own.
///
/// A nil id is `InvalidRequest`. A missing acquire row or a missing consume
/// receipt set is `IdentityConflict`. A consume id that differs from the
/// immutable ACK's stable id, or a partial/corrupt request/hold/receipt set, is
/// `LedgerIntegrity`. None of those is a grant and none registers anything.
pub(in crate::ref_store::core) async fn read_registration_ledger(
    tx: &tokio_postgres::Transaction<'_>,
    scope: &HoldScope,
    acquire_request_id: Uuid,
    consume_request_id: Uuid,
) -> Result<RegistrationLedger, ArtifactHoldError> {
    if acquire_request_id.is_nil() || consume_request_id.is_nil() {
        return Err(ArtifactHoldError::InvalidRequest(
            "artifact hold acquire/consume request ids must be non-nil".into(),
        ));
    }
    let Some(stored_request) = sql::stored_acquire(tx, acquire_request_id).await? else {
        return Err(ArtifactHoldError::IdentityConflict { request_id: acquire_request_id });
    };
    if stored_request.repository_id != scope.repository_id() || stored_request.tenant_id != scope.tenant_id() {
        return Err(ArtifactHoldError::RepositoryNotFound);
    }
    let ack = AcquireAck::decode(&stored_request.body)?;
    ack.ensure_scope(scope)?;
    // The consume id must be the stable id allocated by that very acquire, never
    // a caller-chosen replacement.
    if ack.consume_request_id != consume_request_id {
        return Err(ArtifactHoldError::LedgerIntegrity("consume request id differs from its immutable acquire ACK"));
    }
    // The immutable acquire row/body and the complete bounded hold set must agree
    // before any receipt is considered: a partial or rewritten acquire ledger is
    // corruption, not an unregistered publication.
    let holds = sql_rows::holds_for_request(tx, acquire_request_id).await?;
    ensure_immutable_batch(&stored_request, &ack, &holds)?;
    let stored = sql_rows::receipts_for_consume_request(tx, consume_request_id).await?;
    if stored.is_empty() {
        // Nothing durable for this consume id: refuse, never treat it as an
        // implicit registration of the acquired holds.
        return Err(ArtifactHoldError::IdentityConflict { request_id: consume_request_id });
    }
    if stored.len() != ack.artifacts.len() {
        return Err(ArtifactHoldError::LedgerIntegrity("stored consume receipt set is not the complete acquire batch"));
    }
    let mut receipts = Vec::with_capacity(stored.len());
    for row in &stored {
        let receipt = ConsumeAck::decode(&row.body)?;
        // Body vs its own outer row, including the database-clock timestamp.
        row.ensure_receipt(&receipt)?;
        receipt.ensure_scope(scope)?;
        // Full immutable scope/parent/gate tuple vs the acquire ACK.
        receipt.ensure_acquire_ack(&ack)?;
        let hold_row = holds
            .iter()
            .find(|hold| hold.hold_id == row.hold_id)
            .ok_or(ArtifactHoldError::LedgerIntegrity("stored consume receipt names a hold outside the hold set"))?;
        ensure_receipt_matches_hold(&receipt, hold_row)?;
        receipts.push(receipt);
    }
    for hold in &ack.artifacts {
        if !stored.iter().any(|row| row.hold_id == hold.hold_id) {
            return Err(ArtifactHoldError::LedgerIntegrity("stored consume receipt set is missing an acquire slot"));
        }
    }
    // Canonical slot order, so callers never depend on `hold_id` row order.
    receipts.sort_by_key(|receipt| receipt.slot);
    Ok(RegistrationLedger { acquire_ack: ack, consume_receipts: receipts })
}
