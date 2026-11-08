//! PostgreSQL operation-identity adapter.
//!
//! Every public method runs inside a caller-owned transaction and therefore
//! commits or rolls back with the authoritative ref/pack CAS. The adapter only
//! orders operations for one repository/issuer/lane; it does not replace the
//! existing `FOR UPDATE OF s` ref CAS, read leases, decisions, roots, holds or
//! GC. Queries are bounded by the caller deadline and by a local statement
//! timeout. There is intentionally no router or unauthenticated public query.
use super::contract::{
    BeginReceipt, CancelReceipt, Capabilities, CommitReceipt, IssuerLane, OperationIdentity, OperationLookup,
    OperationRecord, OperationState, RefStoreError, RequestDigest, SequenceReservation, TerminalOutcome,
    TerminalResult,
};
use std::{future::Future, time::Duration};
use tokio::time::{Instant, timeout_at};
use tokio_postgres::{Row, Transaction, error::SqlState};
use uuid::Uuid;

const MAX_QUERY_WINDOW: Duration = Duration::from_secs(30);
pub const OPERATION_LOCK_DOMAIN: &str = "rootyard-ref-store-operation-v1";
pub const OPERATION_LOCK_SQL: &str =
    "SELECT pg_advisory_xact_lock(hashtextextended($1::text || '/' || $2::uuid::text || '/' || $3::uuid::text,0))";

async fn before_deadline<T, F>(deadline: Instant, future: F) -> Result<T, RefStoreError>
where
    F: Future<Output = Result<T, RefStoreError>>,
{
    match timeout_at(deadline, future).await {
        Ok(result) => result,
        Err(_) => Err(RefStoreError::Timeout),
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PgRefStore;

impl PgRefStore {
    pub const fn capabilities(&self) -> Capabilities {
        Capabilities::pg_transition_increment()
    }

    /// Reserve the next sequence in one durable issuer lane. This is the
    /// preallocation primitive for trusted callers that can keep their own
    /// operation id across a retry. The caller chooses `operation_id` before
    /// this call; reservation acquires the same repository+operation advisory
    /// lock as begin/cancel before touching the lane row, so the lock order is
    /// operation -> lane everywhere. The reservation is bound to that UUID and
    /// cannot mint an identity with a different one. Reservation is
    /// transactional; if the caller rolls back, the sequence is not consumed.
    pub async fn reserve_sequence(
        &self,
        tx: &Transaction<'_>,
        repository_id: Uuid,
        issuer_id: Uuid,
        operation_id: Uuid,
        lane: &IssuerLane,
        deadline: Instant,
    ) -> Result<SequenceReservation, RefStoreError> {
        before_deadline(
            deadline,
            self.reserve_sequence_inner(tx, repository_id, issuer_id, operation_id, lane, deadline),
        )
        .await
    }

    async fn reserve_sequence_inner(
        &self,
        tx: &Transaction<'_>,
        repository_id: Uuid,
        issuer_id: Uuid,
        operation_id: Uuid,
        lane: &IssuerLane,
        deadline: Instant,
    ) -> Result<SequenceReservation, RefStoreError> {
        validate_scope(repository_id, issuer_id)?;
        if operation_id.is_nil() {
            return Err(RefStoreError::InvalidIdentity("operation id must be non-nil".into()));
        }
        bound(tx, deadline).await?;
        lock_operation_key(tx, repository_id, operation_id).await?;
        ensure_repository(tx, repository_id).await?;
        let row = tx
            .query_one(
                "INSERT INTO ref_store_issuer_lanes(repository_id,issuer_id,lane,last_reserved_sequence)
                 VALUES($1,$2,$3,1) ON CONFLICT(repository_id,issuer_id,lane) DO UPDATE
                 SET last_reserved_sequence=ref_store_issuer_lanes.last_reserved_sequence+1,
                     updated_at=clock_timestamp()
                 RETURNING last_reserved_sequence",
                &[&repository_id, &issuer_id, &lane.as_str()],
            )
            .await
            .map_err(db_error)?;
        let sequence: i64 = row.get(0);
        Ok(SequenceReservation::new(repository_id, issuer_id, lane.clone(), sequence, operation_id))
    }

    /// Register a pending operation, or replay its existing durable state.
    ///
    /// Cancellation tombstones are read and the lane head is locked first, so
    /// a cancel that arrived before registration wins and produces a terminal
    /// `Cancelled` record instead of a pending one.
    pub async fn begin(
        &self,
        tx: &Transaction<'_>,
        identity: &OperationIdentity,
        deadline: Instant,
    ) -> Result<BeginReceipt, RefStoreError> {
        before_deadline(deadline, self.begin_inner(tx, identity, deadline)).await
    }

    async fn begin_inner(
        &self,
        tx: &Transaction<'_>,
        identity: &OperationIdentity,
        deadline: Instant,
    ) -> Result<BeginReceipt, RefStoreError> {
        bound(tx, deadline).await?;
        lock_operation_key(tx, identity.repository_id(), identity.operation_id()).await?;
        ensure_repository(tx, identity.repository_id()).await?;
        lock_lane(tx, identity).await?;
        if let Some(row) = operation_row(tx, identity.repository_id(), identity.operation_id(), true).await? {
            let stored = record_from_row(&row, identity.repository_id())?;
            verify_identity(stored.identity(), identity)?;
            return Ok(BeginReceipt { created: false, record: stored });
        }
        if let Some(cancelled) = cancellation_by_key(tx, identity, true).await? {
            verify_cancellation(&cancelled, identity.operation_id(), identity.digest())?;
            let result = TerminalResult::json(serde_json::json!({
                "state": "cancelled",
                "reason": "cancel_before_register"
            }))?;
            insert_operation(tx, identity, OperationState::Cancelled, Some(&result)).await?;
            let record = OperationRecord::new(identity.clone(), OperationState::Cancelled, Some(result))?;
            return Ok(BeginReceipt { created: true, record });
        }
        if cancellation_by_operation(tx, identity.repository_id(), identity.operation_id(), true).await?.is_some() {
            return Err(RefStoreError::CancellationConflict);
        }
        insert_operation(tx, identity, OperationState::Pending, None).await?;
        let record = OperationRecord::new(identity.clone(), OperationState::Pending, None)?;
        Ok(BeginReceipt { created: true, record })
    }
}

struct Cancellation {
    operation_id: Uuid,
    digest: RequestDigest,
}
impl PgRefStore {
    /// Persist a cancellation tombstone even when the operation has not been
    /// registered yet. Cancelling a committed/rejected operation records the
    /// tombstone but never rewrites its terminal result. No tombstone is ever
    /// trimmed automatically.
    pub async fn cancel(
        &self,
        tx: &Transaction<'_>,
        identity: &OperationIdentity,
        deadline: Instant,
    ) -> Result<CancelReceipt, RefStoreError> {
        before_deadline(deadline, self.cancel_inner(tx, identity, deadline)).await
    }

    async fn cancel_inner(
        &self,
        tx: &Transaction<'_>,
        identity: &OperationIdentity,
        deadline: Instant,
    ) -> Result<CancelReceipt, RefStoreError> {
        bound(tx, deadline).await?;
        lock_operation_key(tx, identity.repository_id(), identity.operation_id()).await?;
        ensure_repository(tx, identity.repository_id()).await?;
        lock_lane(tx, identity).await?;
        let existing = match operation_row(tx, identity.repository_id(), identity.operation_id(), true).await? {
            Some(row) => {
                let record = record_from_row(&row, identity.repository_id())?;
                verify_identity(record.identity(), identity)?;
                Some(record)
            }
            None => None,
        };
        if existing.is_none() {
            // A lane sequence already bound to another operation cannot be
            // cancelled under a different operation id.
            if operation_by_lane(tx, identity, true).await?.is_some() {
                return Err(RefStoreError::IdentityConflict);
            }
        }
        let tombstone_created = match cancellation_by_key(tx, identity, true).await? {
            Some(cancelled) => {
                verify_cancellation(&cancelled, identity.operation_id(), identity.digest())?;
                false
            }
            None => {
                if cancellation_by_operation(tx, identity.repository_id(), identity.operation_id(), true)
                    .await?
                    .is_some()
                {
                    return Err(RefStoreError::CancellationConflict);
                }
                insert_cancellation(tx, identity).await?;
                true
            }
        };
        let record = match existing {
            Some(record) if record.state() == OperationState::Pending => {
                let result = TerminalResult::json(serde_json::json!({
                    "state": "cancelled",
                    "reason": "cancel_requested"
                }))?;
                let result_value = result.value();
                let updated = tx
                    .query_opt(
                        "UPDATE ref_store_operations SET state='cancelled',terminal_result=$3,
                         terminal_at=clock_timestamp() WHERE repository_id=$1 AND operation_id=$2
                         AND state='pending' RETURNING issuer_id,lane,sequence,request_digest,state,terminal_result,operation_id",
                        &[&identity.repository_id(), &identity.operation_id(), &result_value],
                    )
                    .await
                    .map_err(db_error)?;
                match updated {
                    Some(row) => Some(record_from_row(&row, identity.repository_id())?),
                    // A concurrent terminal writer cannot happen under the lane
                    // lock, but preserve whatever durably won if it did.
                    None => operation_row(tx, identity.repository_id(), identity.operation_id(), false)
                        .await?
                        .map(|row| record_from_row(&row, identity.repository_id()))
                        .transpose()?,
                }
            }
            other => other,
        };
        Ok(CancelReceipt { record, tombstone_created })
    }

    /// Record an immutable terminal result. `Pending` is never accepted here.
    /// Identical replay returns the original result; any attempt to change a
    /// terminal state or result is rejected.
    pub async fn record_terminal(
        &self,
        tx: &Transaction<'_>,
        identity: &OperationIdentity,
        outcome: TerminalOutcome,
        result: &TerminalResult,
        deadline: Instant,
    ) -> Result<CommitReceipt, RefStoreError> {
        before_deadline(deadline, self.record_terminal_inner(tx, identity, outcome, result, deadline)).await
    }

    async fn record_terminal_inner(
        &self,
        tx: &Transaction<'_>,
        identity: &OperationIdentity,
        outcome: TerminalOutcome,
        result: &TerminalResult,
        deadline: Instant,
    ) -> Result<CommitReceipt, RefStoreError> {
        bound(tx, deadline).await?;
        lock_operation_key(tx, identity.repository_id(), identity.operation_id()).await?;
        ensure_repository(tx, identity.repository_id()).await?;
        lock_lane(tx, identity).await?;
        let requested = outcome.state();
        let row = operation_row(tx, identity.repository_id(), identity.operation_id(), true)
            .await?
            .ok_or(RefStoreError::UnknownOperation { operation_id: identity.operation_id() })?;
        let record = record_from_row(&row, identity.repository_id())?;
        verify_identity(record.identity(), identity)?;
        match record.state() {
            state if state == requested => {
                if record.terminal_result().map(TerminalResult::value) != Some(result.value()) {
                    return Err(RefStoreError::TerminalImmutable);
                }
                return Ok(CommitReceipt { record, replayed: true });
            }
            OperationState::Pending => {}
            OperationState::Cancelled => {
                return Err(RefStoreError::Cancelled { operation_id: identity.operation_id() });
            }
            OperationState::Committed | OperationState::Rejected => {
                return Err(RefStoreError::TerminalImmutable);
            }
        }
        // The lane lock serializes cancel, but read the tombstone explicitly so
        // a direct SQL/crash-left tombstone still blocks the commit.
        if cancellation_by_key(tx, identity, true).await?.is_some()
            || cancellation_by_operation(tx, identity.repository_id(), identity.operation_id(), true).await?.is_some()
        {
            return Err(RefStoreError::Cancelled { operation_id: identity.operation_id() });
        }
        let result_value = result.value();
        let updated = tx
            .query_opt(
                "UPDATE ref_store_operations SET state=$3,terminal_result=$4,
                 terminal_at=clock_timestamp() WHERE repository_id=$1 AND operation_id=$2
                 AND state='pending' RETURNING issuer_id,lane,sequence,request_digest,state,terminal_result,operation_id",
                &[&identity.repository_id(), &identity.operation_id(), &requested.as_str(), &result_value],
            )
            .await
            .map_err(db_error)?;
        let Some(updated) = updated else {
            return Err(RefStoreError::TerminalImmutable);
        };
        let record = record_from_row(&updated, identity.repository_id())?;
        Ok(CommitReceipt { record, replayed: false })
    }

    /// Internal repository-scoped lookup. No route exposes this today. A missing
    /// row is [`OperationLookup::Unknown`], never an aborted result.
    pub async fn get(
        &self,
        tx: &Transaction<'_>,
        repository_id: Uuid,
        operation_id: Uuid,
        deadline: Instant,
    ) -> Result<OperationLookup, RefStoreError> {
        before_deadline(deadline, self.get_inner(tx, repository_id, operation_id, deadline)).await
    }

    async fn get_inner(
        &self,
        tx: &Transaction<'_>,
        repository_id: Uuid,
        operation_id: Uuid,
        deadline: Instant,
    ) -> Result<OperationLookup, RefStoreError> {
        if repository_id.is_nil() || operation_id.is_nil() {
            return Err(RefStoreError::InvalidIdentity("lookup ids must be non-nil".into()));
        }
        bound(tx, deadline).await?;
        match operation_row(tx, repository_id, operation_id, false).await? {
            Some(row) => Ok(OperationLookup::Known(record_from_row(&row, repository_id)?)),
            None => Ok(OperationLookup::Unknown),
        }
    }
}
/// Serialize every mutation of one repository operation UUID before any lane
/// row is touched. Adversarial cross-lane identities therefore cannot commit a
/// pending operation and a foreign cancellation tombstone concurrently. Hash
/// collisions only cause extra serialization; the durable identity check after
/// the lock still decides correctness.
async fn lock_operation_key(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    operation_id: Uuid,
) -> Result<(), RefStoreError> {
    tx.query_one(OPERATION_LOCK_SQL, &[&OPERATION_LOCK_DOMAIN, &repository_id, &operation_id])
        .await
        .map_err(db_error)?;
    Ok(())
}

async fn bound(tx: &Transaction<'_>, deadline: Instant) -> Result<(), RefStoreError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(RefStoreError::Timeout);
    }
    let millis = remaining.min(MAX_QUERY_WINDOW).as_millis().max(1);
    tx.batch_execute(&format!("SET LOCAL statement_timeout = {millis}; SET LOCAL lock_timeout = {millis};"))
        .await
        .map_err(db_error)?;
    Ok(())
}

fn validate_scope(repository_id: Uuid, issuer_id: Uuid) -> Result<(), RefStoreError> {
    if repository_id.is_nil() || issuer_id.is_nil() {
        return Err(RefStoreError::InvalidIdentity("repository and issuer ids must be non-nil".into()));
    }
    Ok(())
}

async fn ensure_repository(tx: &Transaction<'_>, repository_id: Uuid) -> Result<(), RefStoreError> {
    let exists: bool = tx
        .query_one("SELECT EXISTS(SELECT 1 FROM repositories WHERE id=$1)", &[&repository_id])
        .await
        .map_err(db_error)?
        .get(0);
    if exists { Ok(()) } else { Err(RefStoreError::RepositoryNotFound) }
}

async fn lock_lane(tx: &Transaction<'_>, identity: &OperationIdentity) -> Result<(), RefStoreError> {
    tx.execute(
        "INSERT INTO ref_store_issuer_lanes(repository_id,issuer_id,lane,last_reserved_sequence)
         VALUES($1,$2,$3,$4) ON CONFLICT(repository_id,issuer_id,lane) DO UPDATE
         SET last_reserved_sequence=GREATEST(ref_store_issuer_lanes.last_reserved_sequence,EXCLUDED.last_reserved_sequence),
             updated_at=clock_timestamp()",
        &[&identity.repository_id(), &identity.issuer_id(), &identity.lane().as_str(), &identity.sequence()],
    )
    .await
    .map_err(db_error)?;
    Ok(())
}

async fn operation_row(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    operation_id: Uuid,
    for_update: bool,
) -> Result<Option<Row>, RefStoreError> {
    let query = format!(
        "SELECT issuer_id,lane,sequence,request_digest,state,terminal_result,operation_id
         FROM ref_store_operations WHERE repository_id=$1 AND operation_id=$2{}",
        if for_update { " FOR UPDATE" } else { "" }
    );
    tx.query_opt(&query, &[&repository_id, &operation_id]).await.map_err(db_error)
}

async fn operation_by_lane(
    tx: &Transaction<'_>,
    identity: &OperationIdentity,
    for_update: bool,
) -> Result<Option<Row>, RefStoreError> {
    let query = format!(
        "SELECT issuer_id,lane,sequence,request_digest,state,terminal_result,operation_id
         FROM ref_store_operations WHERE repository_id=$1 AND issuer_id=$2 AND lane=$3 AND sequence=$4{}",
        if for_update { " FOR UPDATE" } else { "" }
    );
    tx.query_opt(
        &query,
        &[&identity.repository_id(), &identity.issuer_id(), &identity.lane().as_str(), &identity.sequence()],
    )
    .await
    .map_err(db_error)
}

async fn cancellation_by_key(
    tx: &Transaction<'_>,
    identity: &OperationIdentity,
    for_update: bool,
) -> Result<Option<Cancellation>, RefStoreError> {
    let query = format!(
        "SELECT operation_id,request_digest FROM ref_store_cancellations
         WHERE repository_id=$1 AND issuer_id=$2 AND lane=$3 AND sequence=$4{}",
        if for_update { " FOR UPDATE" } else { "" }
    );
    let row = tx
        .query_opt(
            &query,
            &[&identity.repository_id(), &identity.issuer_id(), &identity.lane().as_str(), &identity.sequence()],
        )
        .await
        .map_err(db_error)?;
    row.map(cancellation_from_row).transpose()
}

async fn cancellation_by_operation(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    operation_id: Uuid,
    for_update: bool,
) -> Result<Option<Cancellation>, RefStoreError> {
    let query = format!(
        "SELECT operation_id,request_digest FROM ref_store_cancellations
         WHERE repository_id=$1 AND operation_id=$2{}",
        if for_update { " FOR UPDATE" } else { "" }
    );
    let row = tx.query_opt(&query, &[&repository_id, &operation_id]).await.map_err(db_error)?;
    row.map(cancellation_from_row).transpose()
}

fn cancellation_from_row(row: Row) -> Result<Cancellation, RefStoreError> {
    let digest: String = row.get(1);
    Ok(Cancellation { operation_id: row.get(0), digest: digest.parse()? })
}

fn verify_cancellation(
    cancelled: &Cancellation,
    operation_id: Uuid,
    digest: &RequestDigest,
) -> Result<(), RefStoreError> {
    if cancelled.operation_id == operation_id && cancelled.digest == *digest {
        Ok(())
    } else {
        Err(RefStoreError::CancellationConflict)
    }
}

fn verify_identity(stored: &OperationIdentity, expected: &OperationIdentity) -> Result<(), RefStoreError> {
    if stored == expected {
        return Ok(());
    }
    if stored.digest() != expected.digest() {
        return Err(RefStoreError::DigestConflict);
    }
    Err(RefStoreError::IdentityConflict)
}
async fn insert_operation(
    tx: &Transaction<'_>,
    identity: &OperationIdentity,
    state: OperationState,
    result: Option<&TerminalResult>,
) -> Result<(), RefStoreError> {
    let state = state.as_str();
    let result = result.map(TerminalResult::value);
    tx.execute(
        "INSERT INTO ref_store_operations(
             repository_id,issuer_id,lane,sequence,operation_id,request_digest,state,terminal_result,terminal_at)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,
             CASE WHEN $7='pending' THEN NULL ELSE clock_timestamp() END)",
        &[
            &identity.repository_id(),
            &identity.issuer_id(),
            &identity.lane().as_str(),
            &identity.sequence(),
            &identity.operation_id(),
            &identity.digest().as_hex(),
            &state,
            &result,
        ],
    )
    .await
    .map_err(db_error)?;
    Ok(())
}

async fn insert_cancellation(tx: &Transaction<'_>, identity: &OperationIdentity) -> Result<(), RefStoreError> {
    tx.execute(
        "INSERT INTO ref_store_cancellations(
             repository_id,issuer_id,lane,sequence,operation_id,request_digest)
         VALUES($1,$2,$3,$4,$5,$6)",
        &[
            &identity.repository_id(),
            &identity.issuer_id(),
            &identity.lane().as_str(),
            &identity.sequence(),
            &identity.operation_id(),
            &identity.digest().as_hex(),
        ],
    )
    .await
    .map_err(db_error)?;
    Ok(())
}

fn record_from_row(row: &Row, repository_id: Uuid) -> Result<OperationRecord, RefStoreError> {
    let issuer_id: Uuid = row.get(0);
    let lane_value: String = row.get(1);
    let sequence: i64 = row.get(2);
    let digest_value: String = row.get(3);
    let state_value: String = row.get(4);
    let terminal_value: Option<serde_json::Value> = row.get(5);
    let lane: IssuerLane = lane_value.parse()?;
    let digest: RequestDigest = digest_value.parse()?;
    let state = OperationState::parse(&state_value)
        .ok_or_else(|| RefStoreError::Database(format!("unknown stored operation state {state_value}")))?;
    let terminal_result = terminal_value.map(TerminalResult::from_stored);
    let identity = OperationIdentity::new(repository_id, issuer_id, lane, sequence, row.get(6), digest)?;
    OperationRecord::new(identity, state, terminal_result)
}

fn db_error(error: tokio_postgres::Error) -> RefStoreError {
    match error.code() {
        Some(code) if *code == SqlState::UNIQUE_VIOLATION => RefStoreError::IdentityConflict,
        Some(code) if *code == SqlState::QUERY_CANCELED || *code == SqlState::LOCK_NOT_AVAILABLE => {
            RefStoreError::Timeout
        }
        _ => RefStoreError::Database(error.to_string()),
    }
}
