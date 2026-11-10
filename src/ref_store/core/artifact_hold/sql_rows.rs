//! SQL-only row helpers for the global artifact-hold ledger (A3): immutable
//! acquire/hold/consume receipts and their bounded keyed reads.
//!
//! Every function here runs inside the one owned short transaction that
//! `super::pg` starts; no function opens a connection or commits/rolls back.
//! The caller has already taken the fixed lock order of `super::sql`, so the
//! hold rows are read/locked in stable `hold_id` order and the immutable
//! receipts are inserted last. All batches are bounded to the 16-slot maximum.
//!
//! Reads here return *every* column the ledger duplicates, so the adapter can
//! compare a decoded body against its outer row instead of trusting either one.
use super::contract::{ArtifactHoldError, ArtifactHoldPurpose, MAX_BATCH_ARTIFACTS};
use super::receipt::HoldArtifactIdentity;
use super::receipt::{AcquireAck, ConsumeAck};
use crate::ref_store::pg;
use tokio_postgres::{Row, Transaction, error::SqlState};
use uuid::Uuid;

/// Largest row set one keyed read may return: the 16-slot maximum plus one
/// sentinel row, so an over-full corrupt set is rejected by the caller instead
/// of being silently truncated into a smaller, apparently valid batch.
const MAX_FETCH_ROWS: i64 = MAX_BATCH_ARTIFACTS as i64 + 1;

/// Insert the immutable acquire ledger row and every immutable hold row in one
/// statement batch inside the caller's transaction.
pub(super) async fn insert_acquire(
    tx: &Transaction<'_>,
    ack: &AcquireAck,
    digest_hex: &str,
    body: &str,
) -> Result<(), ArtifactHoldError> {
    let artifact_count = i32::try_from(ack.artifacts.len())
        .map_err(|_| ArtifactHoldError::InvalidRequest("artifact hold batch does not fit the INTEGER column".into()))?;
    tx.execute(
        "INSERT INTO artifact_hold_requests(
             request_id,request_digest,repository_id,tenant_id,owner_id,purpose,object_format,
             history_incarnation,authority_epoch,group_epoch,operation_issuer_id,operation_lane,
             operation_sequence,operation_id,operation_digest,gate_revision,gate_digest,shard_id,
             backend_identity,consume_request_id,artifact_count,declared_bytes,logical_bytes,ack_body)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)",
        &[
            &ack.request_id,
            &digest_hex,
            &ack.repository_id,
            &ack.tenant_id,
            &ack.owner_id,
            &ack.purpose.as_str(),
            &ack.object_format.as_str(),
            &ack.history_incarnation,
            &ack.authority_epoch,
            &ack.group_epoch,
            &ack.issuer_id,
            &ack.lane,
            &ack.sequence,
            &ack.operation_id,
            &ack.operation_digest,
            &ack.gate_revision,
            &ack.gate_digest,
            &ack.shard,
            &ack.backend_identity,
            &ack.consume_request_id,
            &artifact_count,
            &ack.declared_bytes,
            &ack.logical_bytes,
            &body,
        ],
    )
    .await
    .map_err(pg::db_error)?;
    for hold in &ack.artifacts {
        tx.execute(
            "INSERT INTO artifact_holds(
                 hold_id,request_id,slot,repository_id,tenant_id,owner_id,purpose,operation_id,
                 operation_digest,provider,backend_identity,storage_tenant_id,authority_id,
                 authority_generation,attempt_id,namespace,sha256,content_length,declared_bytes,
                 logical_bytes)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)",
            &[
                &hold.hold_id,
                &ack.request_id,
                &hold.slot,
                &ack.repository_id,
                &ack.tenant_id,
                &ack.owner_id,
                &ack.purpose.as_str(),
                &ack.operation_id,
                &ack.operation_digest,
                &hold.artifact.provider,
                &hold.artifact.backend_identity,
                &hold.artifact.tenant_id,
                &hold.artifact.authority_id,
                &hold.artifact.authority_generation,
                &hold.artifact.attempt_id,
                &hold.artifact.namespace,
                &hold.artifact.sha256,
                &content_length_param(hold.artifact.length)?,
                &hold.declared_bytes,
                &hold.logical_bytes,
            ],
        )
        .await
        .map_err(pg::db_error)?;
    }
    Ok(())
}

/// Stored `content_length` is `BIGINT`, while the locator length is `u64`
/// bounded to `1 << 40`. Convert explicitly and reject anything that would not
/// round-trip instead of truncating.
fn content_length_param(length: u64) -> Result<i64, ArtifactHoldError> {
    i64::try_from(length)
        .map_err(|_| ArtifactHoldError::InvalidRequest("artifact length does not fit the BIGINT column".into()))
}

/// One locked durable hold row.
pub(super) struct StoredHold {
    pub hold_id: Uuid,
    pub request_id: Uuid,
    pub slot: i32,
    pub state: String,
    pub generation: i32,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub purpose: String,
    pub operation_id: Uuid,
    pub operation_digest: String,
    pub artifact: HoldArtifactIdentity,
    pub declared_bytes: i64,
    pub logical_bytes: i64,
}

const HOLD_COLUMNS: &str = "hold_id,request_id,slot,state,generation,repository_id,tenant_id,owner_id,purpose,
    operation_id,operation_digest,provider,backend_identity,storage_tenant_id,authority_id,authority_generation,
    attempt_id,namespace,sha256,content_length,declared_bytes,logical_bytes";

fn hold_from_row(row: &Row) -> Result<StoredHold, ArtifactHoldError> {
    let content_length: i64 = row.get(19);
    let length = u64::try_from(content_length)
        .map_err(|_| ArtifactHoldError::LedgerIntegrity("stored hold content length is negative"))?;
    Ok(StoredHold {
        hold_id: row.get(0),
        request_id: row.get(1),
        slot: row.get(2),
        state: row.get(3),
        generation: row.get(4),
        repository_id: row.get(5),
        tenant_id: row.get(6),
        owner_id: row.get(7),
        purpose: row.get(8),
        operation_id: row.get(9),
        operation_digest: row.get(10),
        artifact: HoldArtifactIdentity {
            provider: row.get(11),
            backend_identity: row.get(12),
            tenant_id: row.get(13),
            authority_id: row.get(14),
            authority_generation: row.get(15),
            attempt_id: row.get(16),
            namespace: row.get(17),
            sha256: row.get(18),
            length,
        },
        declared_bytes: row.get(20),
        logical_bytes: row.get(21),
    })
}

/// Lock *every* durable hold row of one acquire request in stable `hold_id`
/// order. The caller then compares the complete, canonical set against the ACK
/// body, so a missing row (partial batch) or an extra row is corruption rather
/// than a smaller successful consume. A request is bounded to 16 rows.
pub(super) async fn lock_request_holds(
    tx: &Transaction<'_>,
    request_id: Uuid,
) -> Result<Vec<StoredHold>, ArtifactHoldError> {
    let query = format!(
        "SELECT {} FROM artifact_holds WHERE request_id=$1 ORDER BY hold_id LIMIT {MAX_FETCH_ROWS} FOR UPDATE",
        HOLD_COLUMNS
    );
    let rows = tx.query(&query, &[&request_id]).await.map_err(pg::db_error)?;
    rows.iter().map(hold_from_row).collect()
}

/// Read-only form of [`lock_request_holds`], used by the receipt-only query
/// path. It takes no row locks and is bounded by the same 16-row batch.
pub(super) async fn holds_for_request(
    tx: &Transaction<'_>,
    request_id: Uuid,
) -> Result<Vec<StoredHold>, ArtifactHoldError> {
    let query = format!(
        "SELECT {} FROM artifact_holds WHERE request_id=$1 ORDER BY hold_id LIMIT {MAX_FETCH_ROWS}",
        HOLD_COLUMNS
    );
    let rows = tx.query(&query, &[&request_id]).await.map_err(pg::db_error)?;
    rows.iter().map(hold_from_row).collect()
}

/// One immutable consume receipt row.
pub(super) struct StoredConsume {
    pub hold_id: Uuid,
    pub request_id: Uuid,
    pub consume_request_id: Uuid,
    pub consume_digest: String,
    pub slot: i32,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub operation_id: Uuid,
    pub operation_digest: String,
    pub gate_revision: i64,
    pub gate_digest: String,
    pub body: String,
    pub consumed_at_unix_micros: i64,
}

impl StoredConsume {
    /// The decoded receipt body must agree with every duplicated column of its
    /// own immutable row. A disagreement is ledger corruption.
    pub(super) fn ensure_receipt(&self, receipt: &ConsumeAck) -> Result<(), ArtifactHoldError> {
        if receipt.consume_request_id != self.consume_request_id
            || receipt.request_id != self.request_id
            || receipt.consume_digest != self.consume_digest
            || receipt.hold_id != self.hold_id
            || receipt.slot != self.slot
            || receipt.repository_id != self.repository_id
            || receipt.tenant_id != self.tenant_id
            || receipt.owner_id != self.owner_id
            || receipt.operation_id != self.operation_id
            || receipt.operation_digest != self.operation_digest
            || receipt.gate_revision != self.gate_revision
            || receipt.gate_digest != self.gate_digest
            || receipt.consumed_at_unix_micros != self.consumed_at_unix_micros
        {
            return Err(ArtifactHoldError::LedgerIntegrity(
                "stored consume receipt body disagrees with its immutable ledger row",
            ));
        }
        Ok(())
    }
}

const CONSUME_COLUMNS: &str = "hold_id,request_id,consume_request_id,consume_digest,slot,repository_id,tenant_id,
    owner_id,operation_id,operation_digest,gate_revision,gate_digest,body,consumed_at_unix_micros";

fn consume_from_row(row: &Row) -> StoredConsume {
    StoredConsume {
        hold_id: row.get(0),
        request_id: row.get(1),
        consume_request_id: row.get(2),
        consume_digest: row.get(3),
        slot: row.get(4),
        repository_id: row.get(5),
        tenant_id: row.get(6),
        owner_id: row.get(7),
        operation_id: row.get(8),
        operation_digest: row.get(9),
        gate_revision: row.get(10),
        gate_digest: row.get(11),
        body: row.get(12),
        consumed_at_unix_micros: row.get(13),
    }
}

/// Any consume receipt already recorded for this acquire request. A non-empty
/// answer means the granted slots are (at least partly) burned.
pub(super) async fn receipts_for_request(
    tx: &Transaction<'_>,
    request_id: Uuid,
) -> Result<Vec<StoredConsume>, ArtifactHoldError> {
    let query = format!(
        "SELECT {} FROM artifact_hold_consume_receipts WHERE request_id=$1 ORDER BY hold_id LIMIT {MAX_FETCH_ROWS}",
        CONSUME_COLUMNS
    );
    let rows = tx.query(&query, &[&request_id]).await.map_err(pg::db_error)?;
    Ok(rows.iter().map(consume_from_row).collect())
}

/// Receipt-only query for an unknown consume COMMIT.
pub(super) async fn receipts_for_consume_request(
    tx: &Transaction<'_>,
    consume_request_id: Uuid,
) -> Result<Vec<StoredConsume>, ArtifactHoldError> {
    let query = format!(
        "SELECT {} FROM artifact_hold_consume_receipts WHERE consume_request_id=$1 ORDER BY hold_id LIMIT {MAX_FETCH_ROWS}",
        CONSUME_COLUMNS
    );
    let rows = tx.query(&query, &[&consume_request_id]).await.map_err(pg::db_error)?;
    Ok(rows.iter().map(consume_from_row).collect())
}

/// Insert one immutable consume receipt. A unique-slot violation is reported as
/// `HoldAlreadyConsumed` (the durable one-shot CAS), never as a retryable
/// identity conflict.
pub(super) async fn insert_consume_receipt(
    tx: &Transaction<'_>,
    ack: &ConsumeAck,
    body: &str,
) -> Result<(), ArtifactHoldError> {
    let result = tx
        .execute(
            "INSERT INTO artifact_hold_consume_receipts(
                 hold_id,request_id,consume_request_id,consume_digest,slot,repository_id,tenant_id,
                 owner_id,operation_id,operation_digest,gate_revision,gate_digest,body,
                 consumed_at_unix_micros)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
            &[
                &ack.hold_id,
                &ack.request_id,
                &ack.consume_request_id,
                &ack.consume_digest,
                &ack.slot,
                &ack.repository_id,
                &ack.tenant_id,
                &ack.owner_id,
                &ack.operation_id,
                &ack.operation_digest,
                &ack.gate_revision,
                &ack.gate_digest,
                &body,
                &ack.consumed_at_unix_micros,
            ],
        )
        .await;
    match result {
        Ok(_) => Ok(()),
        Err(error) if error.code() == Some(&SqlState::UNIQUE_VIOLATION) => {
            Err(ArtifactHoldError::HoldAlreadyConsumed { hold_id: ack.hold_id })
        }
        Err(error) => Err(pg::db_error(error).into()),
    }
}

/// Database-clock consumption timestamp, used by the immutable receipt body so
/// no client clock can influence it.
pub(super) async fn database_now_micros(tx: &Transaction<'_>) -> Result<i64, ArtifactHoldError> {
    let row = tx
        .query_one("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint", &[])
        .await
        .map_err(pg::db_error)?;
    Ok(row.get(0))
}

/// Typed error for a stored purpose value that is outside the contract enum.
pub(super) fn stored_purpose(value: &str) -> Result<ArtifactHoldPurpose, ArtifactHoldError> {
    ArtifactHoldPurpose::parse(value)
}
