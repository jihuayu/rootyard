//! PostgreSQL operation-identity adapter.
//!
//! Every public method runs inside a caller-owned transaction and therefore
//! commits or rolls back with the authoritative ref/pack CAS. The adapter only
//! orders operations for one repository/issuer/lane; it does not replace the
//! existing `FOR UPDATE OF s` ref CAS, read leases, decisions, roots, holds or
//! GC. Queries are bounded by the caller deadline and by a local statement
//! timeout. There is intentionally no router or unauthenticated public query.
//!
//! Legacy reserve, begin and cancel refuse migration-152 wrapper and attempt
//! UUIDs. The core-only lookup and exact-identity terminal writer are still
//! shared ledger primitives. A wrapper producer needs its own authorized
//! attempt lifecycle before it can use the core ledger.
use super::contract::{
    BeginReceipt, CancelReceipt, Capabilities, CommitReceipt, IssuerLane, OperationIdentity, OperationLookup,
    OperationRecord, OperationState, RefStoreError, RequestDigest, SequenceReservation, TerminalOutcome,
    TerminalResult,
};
use std::{future::Future, time::Duration};
use tokio::time::{Instant, timeout_at};
use tokio_postgres::{Row, Transaction, error::SqlState, types::ToSql};
use uuid::Uuid;

/// Crate-private migration-152 slot-zero admission.
pub(crate) mod slot_zero;

/// Read-only migration-152 public operation/current attempt resolver.
pub(crate) mod public_attempt;

/// Crate-private migration-152 public terminal mirror.
#[allow(dead_code)]
pub(crate) mod public_terminal;

/// Crate-private migration-152 rotation over exact revision-mismatch retirements.
#[allow(dead_code)]
pub(crate) mod slot_one;

const MAX_QUERY_WINDOW: Duration = Duration::from_secs(30);
pub const OPERATION_LOCK_DOMAIN: &str = "rootyard-ref-store-operation-v1";
pub const OPERATION_LOCK_SQL: &str =
    "SELECT pg_advisory_xact_lock(hashtextextended($1::text || '/' || $2::uuid::text || '/' || $3::uuid::text,0))";

/// One MVCC snapshot for the legacy status route: the eligible legacy operation
/// row (columns 0..6, read by `record_from_row`), whether this exact UUID is a
/// migration-152 public wrapper, and whether it is a private attempt claim.
/// Keeping all three in one statement prevents a concurrent admission commit
/// from being split between a claim probe and a private core-row read.
const LEGACY_STATUS_SNAPSHOT: &str = "SELECT \
        o.issuer_id, o.lane, o.sequence, o.request_digest, o.state, o.terminal_result, o.operation_id, \
        (w.public_id IS NOT NULL) AS public_wrapper, \
        (p.private_id IS NOT NULL) AS private_claimed, \
        (sp.private_id IS NOT NULL) AS selected_private \
    FROM (VALUES (1)) AS anchor(one) \
    LEFT JOIN ref_store_operations o \
        ON o.repository_id=$1 AND o.operation_id=$2 \
    LEFT JOIN ref_store_public_operations w \
        ON w.repository_id=$1 AND w.public_id=$2 \
    LEFT JOIN ref_store_private_attempts p \
        ON p.repository_id=$1 AND p.private_id=$2 \
    LEFT JOIN ref_store_private_attempts sp \
        ON sp.repository_id=w.repository_id AND sp.public_id=w.public_id AND sp.slot=w.current_slot";

const LEGACY_STATUS_SCHEMA_REQUIRED: &str = "legacy operation status requires a complete migration 152 catalog";

/// Read-only legacy status classification. Only `Legacy` carries durable state;
/// `PublicWrapper`, `PrivateIdentifier` and `Unknown` carry no identity or
/// payload. A private claim must be rendered exactly like an unknown id.
pub(crate) enum LegacyStatusLookup {
    Legacy(OperationRecord),
    PublicWrapper,
    PrivateIdentifier,
    Unknown,
}

pub(crate) async fn before_deadline<T, F>(deadline: Instant, future: F) -> Result<T, RefStoreError>
where
    F: Future<Output = Result<T, RefStoreError>>,
{
    match timeout_at(deadline, future).await {
        Ok(result) => result,
        Err(_) => Err(RefStoreError::Timeout),
    }
}

/// Lock and read the authoritative `public.cluster_authority` restore
/// incarnation `FOR SHARE NOWAIT`.
///
/// This is the same singleton the initial serving lookup captured. It is called
/// as the first lock of the final A4 transaction, before the operation/
/// repository/gate/usage prefix, so it cannot form a cycle with a restore fence.
/// Exactly one non-nil singleton row is required. Lock contention is a typed
/// retryable `Timeout`; the caller's absolute deadline remains the outer bound.
pub(crate) async fn public_cluster_incarnation_nowait(tx: &Transaction<'_>) -> Result<Uuid, RefStoreError> {
    let rows = match tx
        .query("SELECT incarnation FROM public.cluster_authority WHERE singleton=true FOR SHARE NOWAIT", &[])
        .await
    {
        Ok(rows) => rows,
        Err(error) if error.code() == Some(&SqlState::LOCK_NOT_AVAILABLE) => return Err(RefStoreError::Timeout),
        Err(error) => return Err(db_error(error)),
    };
    let [row] = rows.as_slice() else {
        return Err(RefStoreError::Database(format!(
            "cluster authority has {} singleton incarnation rows, expected exactly one",
            rows.len()
        )));
    };
    let incarnation: Uuid =
        row.try_get(0).map_err(|_| RefStoreError::Database("cluster authority row has no uuid incarnation".into()))?;
    if incarnation.is_nil() {
        return Err(RefStoreError::Database("cluster authority incarnation is nil".into()));
    }
    Ok(incarnation)
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PgRefStore;

impl PgRefStore {
    pub const fn capabilities(&self) -> Capabilities {
        Capabilities::pg_transition_increment()
    }

    /// Lock the expected issuer lane, creating its zero row only when it does
    /// not yet exist.
    ///
    /// This is the gateway's fresh-admission lane acquisition and must run after
    /// the public/operation locks but before any repository/binding authority
    /// read. It never evaluates `last_reserved_sequence + 1` and never advances
    /// a sequence; the slot-zero coordinator still previews and conditionally
    /// advances the now-visible lane later in this same transaction.
    ///
    /// An existing lane takes one `FOR NO KEY UPDATE` lock. A missing lane is
    /// initialized at zero with `ON CONFLICT DO NOTHING`; a concurrent creator
    /// is visible to that insert's conflict wait, and the loser re-locks the
    /// winner's row before returning. This closes the READ COMMITTED gap where
    /// a plain select of an absent row cannot see an in-flight insert. The
    /// caller must hold the operation key and roll back on later refusal.
    pub(crate) async fn lock_or_create_expected_lane(
        &self,
        tx: &Transaction<'_>,
        repository_id: Uuid,
        issuer_id: Uuid,
        lane: &IssuerLane,
        deadline: Instant,
    ) -> Result<(), RefStoreError> {
        if repository_id.is_nil() || issuer_id.is_nil() {
            return Err(RefStoreError::InvalidIdentity("expected lane ids must be non-nil".into()));
        }
        const LOCK: &str = "SELECT 1 FROM ref_store_issuer_lanes
             WHERE (repository_id,issuer_id,lane)=($1,$2,$3) FOR NO KEY UPDATE";
        const CREATE: &str = "INSERT INTO ref_store_issuer_lanes(
                 repository_id,issuer_id,lane,last_reserved_sequence)
             VALUES($1,$2,$3,0) ON CONFLICT(repository_id,issuer_id,lane) DO NOTHING
             RETURNING 1";
        bound(tx, deadline).await?;
        let lane_name = lane.as_str();
        let params: &[&(dyn ToSql + Sync)] = &[&repository_id, &issuer_id, &lane_name];
        if tx.query_opt(LOCK, params).await.map_err(db_error)?.is_some() {
            return Ok(());
        }
        if tx.query_opt(CREATE, params).await.map_err(db_error)?.is_some() {
            return Ok(());
        }
        // A concurrent creator committed the same issuer lane between the read
        // and insert. Re-lock that row before returning to the authority reads.
        tx.query_one(LOCK, params).await.map_err(db_error)?;
        Ok(())
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
        refuse_legacy_collision(tx, repository_id, operation_id).await?;
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
        refuse_legacy_collision(tx, identity.repository_id(), identity.operation_id()).await?;
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

/// A candidate sequence protected by the issuer-lane row lock in this transaction.
/// Only advancement can turn it into a reservation.
struct LockedSequence {
    sequence: i64,
}

impl LockedSequence {
    /// The caller holds the operation key and has checked the UUID namespace.
    ///
    /// An existing lane costs one locked preview plus the conditional advance.
    /// A lane first created here reads its initial candidate straight from the
    /// insert, so it also spends one preview statement rather than a second
    /// locked read. Only a concurrent creator that wins the `ON CONFLICT` race
    /// yields no inserted row; that loser re-reads under `FOR NO KEY UPDATE`.
    async fn preview(
        tx: &Transaction<'_>,
        repository_id: Uuid,
        issuer_id: Uuid,
        lane: &IssuerLane,
    ) -> Result<Self, RefStoreError> {
        const PREVIEW: &str = "SELECT last_reserved_sequence + 1 FROM ref_store_issuer_lanes
             WHERE (repository_id,issuer_id,lane)=($1,$2,$3) FOR NO KEY UPDATE";
        const CREATE_LANE: &str = "INSERT INTO ref_store_issuer_lanes(
                 repository_id,issuer_id,lane,last_reserved_sequence)
             VALUES($1,$2,$3,0) ON CONFLICT(repository_id,issuer_id,lane) DO NOTHING
             RETURNING last_reserved_sequence + 1";
        let lane_name = lane.as_str();
        let params: &[&(dyn ToSql + Sync)] = &[&repository_id, &issuer_id, &lane_name];
        let sequence: i64 = match tx.query_opt(PREVIEW, params).await.map_err(db_error)? {
            Some(row) => row.get(0),
            // No lane row is visible. The insert both creates the row and takes
            // the initial candidate; the row lock is held for the advance.
            None => match tx.query_opt(CREATE_LANE, params).await.map_err(db_error)? {
                Some(row) => row.get(0),
                // A concurrent creator committed the same lane between the
                // preview and this insert. Re-read it under the row lock; the
                // conditional advance below proves the re-read is still current.
                None => tx.query_one(PREVIEW, params).await.map_err(db_error)?.get(0),
            },
        };
        Ok(Self { sequence })
    }
}

/// Advance one already locked lane preview to its candidate sequence.
///
/// The row lock taken by [`LockedSequence::preview`] is transaction-scoped and
/// survives dropping that value, so a caller that must build a plan between the
/// preview and the advance can still call this conditionally. The predicate
/// rejects a stale candidate if this transaction moved the lane in the meantime.
async fn advance_sequence(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    issuer_id: Uuid,
    lane: &IssuerLane,
    operation_id: Uuid,
    sequence: i64,
) -> Result<SequenceReservation, RefStoreError> {
    let changed = tx
        .execute(
            "UPDATE ref_store_issuer_lanes SET last_reserved_sequence=$4, updated_at=clock_timestamp()
             WHERE (repository_id,issuer_id,lane)=($1,$2,$3) AND last_reserved_sequence=$4::bigint - 1",
            &[&repository_id, &issuer_id, &lane.as_str(), &sequence],
        )
        .await
        .map_err(db_error)?;
    if changed != 1 {
        return Err(RefStoreError::IdentityConflict);
    }
    Ok(SequenceReservation::new(repository_id, issuer_id, lane.clone(), sequence, operation_id))
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
        refuse_legacy_collision(tx, identity.repository_id(), identity.operation_id()).await?;
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

    /// Internal repository-scoped core lookup, including private identities.
    /// Mutation/cancel callers that must serialize use `get_legacy_locked`; the
    /// read-only status route uses `get_legacy_status`. A missing row is
    /// [`OperationLookup::Unknown`], never an aborted result.
    pub async fn get(
        &self,
        tx: &Transaction<'_>,
        repository_id: Uuid,
        operation_id: Uuid,
        deadline: Instant,
    ) -> Result<OperationLookup, RefStoreError> {
        before_deadline(deadline, self.get_inner(tx, repository_id, operation_id, deadline)).await
    }

    /// Resolve a legacy operation for an authorized HTTP caller that must
    /// serialize with operation mutations. The caller must already hold the
    /// migration-138 operation lock in this transaction.
    pub(crate) async fn get_legacy_locked(
        &self,
        tx: &Transaction<'_>,
        repository_id: Uuid,
        operation_id: Uuid,
        deadline: Instant,
    ) -> Result<OperationLookup, RefStoreError> {
        before_deadline(deadline, async {
            bound(tx, deadline).await?;
            refuse_legacy_collision(tx, repository_id, operation_id).await?;
            self.get_inner(tx, repository_id, operation_id, deadline).await
        })
        .await
    }

    /// Classify one repository-scoped identifier for the authenticated read-only
    /// status route.
    ///
    /// A complete migration-152 catalog is classified by one statement over one
    /// MVCC snapshot: the eligible legacy operation row, this exact UUID's public
    /// wrapper, and this exact UUID's private attempt claim are read together.
    /// A concurrent admission commit therefore cannot be split between a claim
    /// check and a core-row read, and a private core row is never exposed as a
    /// legacy operation. Private claims return a marker the caller renders as the
    /// same 404 as an unknown id; a public wrapper remains a non-legacy marker.
    ///
    /// A wholly absent migration 152 uses the pre-152 legacy read. A partial
    /// catalog fails closed. This method takes no migration-138 operation key,
    /// writes no row and does not change any writer path.
    pub(crate) async fn get_legacy_status(
        &self,
        tx: &Transaction<'_>,
        repository_id: Uuid,
        operation_id: Uuid,
        deadline: Instant,
    ) -> Result<LegacyStatusLookup, RefStoreError> {
        if repository_id.is_nil() || operation_id.is_nil() {
            return Err(RefStoreError::InvalidIdentity("lookup ids must be non-nil".into()));
        }
        before_deadline(deadline, async {
            bound(tx, deadline).await?;
            let schema = tx.query_one(public_attempt::SCHEMA_PROBE, &[]).await.map_err(db_error)?;
            let version = schema.get::<_, bool>(0);
            let wrapper_relation = schema.get::<_, bool>(1);
            let attempt_relation = schema.get::<_, bool>(2);
            let binding_function = schema.get::<_, bool>(3);
            let retirement_relation = schema.get::<_, bool>(4);
            if !version && !wrapper_relation && !attempt_relation && !binding_function && !retirement_relation {
                return match self.get_inner(tx, repository_id, operation_id, deadline).await? {
                    OperationLookup::Known(record) => Ok(LegacyStatusLookup::Legacy(record)),
                    OperationLookup::Unknown => Ok(LegacyStatusLookup::Unknown),
                };
            }
            if !version || !wrapper_relation || !attempt_relation || !binding_function || !retirement_relation {
                return Err(RefStoreError::Unsupported(LEGACY_STATUS_SCHEMA_REQUIRED));
            }
            let row = tx.query_one(LEGACY_STATUS_SNAPSHOT, &[&repository_id, &operation_id]).await.map_err(db_error)?;
            let legacy_present = row.get::<_, Option<Uuid>>(6).is_some();
            let public_wrapper: bool = row.get(7);
            let private_claimed: bool = row.get(8);
            let selected_private: bool = row.get(9);
            if public_wrapper {
                if legacy_present || private_claimed || !selected_private {
                    return Err(RefStoreError::IdentityConflict);
                }
                return Ok(LegacyStatusLookup::PublicWrapper);
            }
            if private_claimed {
                return Ok(LegacyStatusLookup::PrivateIdentifier);
            }
            if legacy_present {
                return Ok(LegacyStatusLookup::Legacy(record_from_row(&row, repository_id)?));
            }
            Ok(LegacyStatusLookup::Unknown)
        })
        .await
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

/// Acquire the exact migration-138 operation advisory key under the caller's
/// deadline.
///
/// This is the same transaction-scoped key `reserve_sequence`/`begin`/`cancel`
/// take. Reacquiring it inside one transaction is a no-op, so a caller that must
/// resolve a stored identity before cancelling can hold the same
/// operation -> lane/... prefix as every other mutation instead of introducing a
/// second lock domain. The call is bounded by both the absolute deadline and the
/// local statement/lock timeout installed by [`bound`].
pub(crate) async fn lock_operation(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    operation_id: Uuid,
    deadline: Instant,
) -> Result<(), RefStoreError> {
    if repository_id.is_nil() || operation_id.is_nil() {
        return Err(RefStoreError::InvalidIdentity("operation lock ids must be non-nil".into()));
    }
    before_deadline(deadline, async {
        bound(tx, deadline).await?;
        lock_operation_key(tx, repository_id, operation_id).await
    })
    .await
}

/// Called only under the migration-138 key, before any issuer-lane mutation
/// or external replay lookup. Migration 152 claims wrapper and attempt UUIDs
/// with that same key. A read-committed statement issued after locking sees
/// claims committed by the preceding holder of the key.
async fn refuse_legacy_collision(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    operation_id: Uuid,
) -> Result<(), RefStoreError> {
    let schema = tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=152),
                    current_setting('transaction_isolation') = 'read committed'",
            &[],
        )
        .await
        .map_err(db_error)?;
    // Older catalogs lack both relations. Keep their legacy identity contract
    // without preparing a statement that references the absent tables.
    if !schema.get::<_, bool>(0) {
        return Ok(());
    }
    if !schema.get::<_, bool>(1) {
        return Err(RefStoreError::Database("legacy operation UUID checks require read committed".into()));
    }
    let claimed: bool = tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM ref_store_public_operations WHERE repository_id=$1 AND public_id=$2)
                 OR EXISTS(SELECT 1 FROM ref_store_private_attempts WHERE repository_id=$1 AND private_id=$2)",
            &[&repository_id, &operation_id],
        )
        .await
        .map_err(db_error)?
        .get(0);
    if claimed { Err(RefStoreError::IdentityConflict) } else { Ok(()) }
}

pub(crate) async fn bound(tx: &Transaction<'_>, deadline: Instant) -> Result<(), RefStoreError> {
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

pub(crate) fn db_error(error: tokio_postgres::Error) -> RefStoreError {
    match error.code() {
        Some(code) if *code == SqlState::UNIQUE_VIOLATION => RefStoreError::IdentityConflict,
        Some(code) if *code == SqlState::QUERY_CANCELED || *code == SqlState::LOCK_NOT_AVAILABLE => {
            RefStoreError::Timeout
        }
        _ => RefStoreError::Database(error.to_string()),
    }
}
