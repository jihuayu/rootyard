//! Crate-private terminal mirror for migration 152's current public attempt.
//!
//! This is the stage-one production-path prerequisite for issue 42: it makes an
//! already durable migration-138/139 private terminal visible through the
//! migration-152 public wrapper. It mirrors the exact current slot-zero attempt
//! and, once the existing rotation has already atomically admitted slot one, the
//! exact current slot-one attempt. It is deliberately not a serving cutover and
//! has no production caller. Nothing here allocates a sequence, claims a new
//! private UUID, writes an event, rotates or retires a slot, creates a second
//! retirement or third attempt, resolves an unknown COMMIT or calls the legacy
//! gateway.
//!
//! The caller supplies the exact [`PublicAttemptRequest`] already authenticated
//! at the serving boundary and the exact private [`OperationRecord`] already
//! produced by the existing migration-138 terminal writer. Only `Committed` and
//! `Rejected` records are accepted; `Pending` and `Cancelled` are typed
//! refusals. The record's terminal body is never trusted on its own: it must
//! equal the stored migration-138 terminal result and the one immutable
//! migration-139 event body, with the event kind/repository/revision fields and
//! the exact migration-147 serving binding agreeing with the wrapper. On slot
//! one the same snapshot must also prove the exact retired slot-zero event and
//! the fresh successor sequence/base lineage.
//!
//! # Transaction and lock order
//!
//! This method must run in a **fresh caller-owned dedicated transaction** and
//! must be its first lock-taking step. It takes migration 152's public/attempt
//! advisory keys and wrapper row lock first, then the existing cluster
//! restore-incarnation fence, then the repository/current-scope read. It must
//! never be called late inside the authority transaction that already holds the
//! migration-138 operation key, issuer lane, repository, gate or decision
//! locks: that would invert migration 152's documented order. The method never
//! begins, commits or rolls back the caller's transaction.
//!
//! # Atomicity and errors
//!
//! Every identity, attempt, operation, event, binding, realm and revision check
//! is completed before the single guarded `UPDATE`. That update either affects
//! exactly the one pending current-slot row pinned by its slot and, for slot
//! one, the exact `retired_event_id`, or no row; after a successful one-row
//! update the only remaining check is the SQL evidence verifier itself. A
//! verification failure aborts the caller's transaction instead of returning a
//! commit-able partially published wrapper. Any SQL error likewise aborts it; a
//! caller must roll the dedicated transaction back. There is no retry loop and
//! no unknown-resolution speculation.
//!
//! An identical already-published terminal/event is a read-only replay. A
//! different terminal is immutable. A rejected event is accepted at or after
//! its private base revision (the native rejection semantics), while a
//! committed event must be exactly `base + 1` with checked overflow. A delayed
//! good publication is not refused merely because unrelated later revisions
//! advanced.
//!
//! Retirement is independent and slot-zero only. If the rejected event is the
//! exact slot-zero stale rejection (`revision_mismatch`, empty registrations) at
//! the current advanced gate, publishing it would close the only migration-152
//! rotation path. The mirror therefore returns
//! [`PublicAttemptTerminalOutcome::RetirementRequired`] without writing. The
//! slot-one branch never returns that outcome and never mutates the retired
//! attempt; it only publishes or exactly replays the already-current terminal.
use super::{
    bound,
    public_attempt::{
        ledger, parse_digest, parse_state, stale_realm, validate_wrapper, PublicAttemptRequest, RawWrapper, Redacted,
    },
    PgRefStore,
};
use crate::ref_store::{
    core::{
        pack_commit::{PackCommitError, PackCommitRejectCode},
        pack_snapshot::lock_cluster_incarnation,
    },
    OperationRecord, OperationState, RefStoreError,
};
use serde::Deserialize;
use serde_json::Value;
use std::fmt;
use tokio::time::Instant;
use tokio_postgres::{error::SqlState, Transaction};
use uuid::Uuid;

/// Probe exactly the migration-152 objects this mirror uses. The relation and
/// function checks keep an older or partial catalog an explicit `Unsupported`
/// result instead of preparing a statement whose objects do not exist.
const SCHEMA_PROBE: &str = "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=152), \
        current_setting('transaction_isolation') = 'read committed', \
        to_regprocedure('rootyard_ref_store_lock_public_operation(uuid,uuid,uuid)') IS NOT NULL, \
        to_regprocedure('rootyard_ref_store_attempt_has_binding(\
            ref_store_public_operations,ref_store_private_attempts)') IS NOT NULL, \
        to_regprocedure('rootyard_ref_store_attempt_current_scope(\
            ref_store_public_operations)') IS NOT NULL, \
        to_regprocedure('rootyard_ref_store_attempt_stale_gate(\
            ref_store_public_operations,ref_store_private_attempts)') IS NOT NULL, \
        to_regprocedure('rootyard_ref_store_verify_public_operation(uuid,uuid)') IS NOT NULL";

/// One snapshot of the wrapper, both possible attempts, the private operation
/// and its event. The migration-152 binding predicate stays inside PostgreSQL;
/// it is the reviewed authoritative SQL check, not a second vocabulary here.
const SELECT_EVIDENCE: &str = r#"
SELECT jsonb_build_object(
    'wrapper', (
        SELECT to_jsonb(w) FROM (
            SELECT repository_id, public_id, admission_owner_id, issuer_id, wire_digest,
                   request_mode, backend_identity, object_format, history_incarnation,
                   authority_epoch, group_epoch, restore_incarnation, current_slot,
                   state, event_id, retired_event_id, cancelled_private_id
              FROM ref_store_public_operations
             WHERE repository_id=$1 AND public_id=$2
        ) w
    ),
    'attempts', COALESCE((
        SELECT jsonb_agg(to_jsonb(x) ORDER BY x.slot) FROM (
            SELECT a.slot, a.private_id, a.plan_digest, a.proof_digest, a.base_revision,
                   rootyard_ref_store_attempt_has_binding(w, a) AS serving_bound,
                   o.issuer_id AS operation_issuer_id,
                   o.lane AS operation_lane,
                   o.sequence AS operation_sequence,
                   o.request_digest AS operation_request_digest,
                   o.state AS operation_state,
                   o.terminal_result IS NOT NULL AS terminal_present,
                   e.event_id,
                   e.revision AS event_revision,
                   COALESCE(e.event_id IS NOT NULL AND e.outcome = o.state, false)
                       AS event_outcome_matches,
                   COALESCE(e.event_id IS NOT NULL
                            AND e.payload IS NOT DISTINCT FROM o.terminal_result
                            AND e.payload->>'kind' = o.state
                            AND e.payload->'repository_id' = to_jsonb(w.repository_id)
                            AND e.payload->'revision' = to_jsonb(e.revision), false)
                       AS event_body_matches,
                   COALESCE(e.event_id IS NOT NULL
                            AND e.payload#>>'{rejection,code}' = 'revision_mismatch'
                            AND e.payload->'registrations' = '[]'::jsonb, false)
                       AS revision_mismatch_rejection,
                   COALESCE(c.operation_id IS NOT NULL, false) AS tombstone_present,
                   (c.operation_id IS NULL AND k.operation_id IS NULL) AS tombstone_absent,
                   COALESCE(c.operation_id IS NOT NULL AND c.operation_id = k.operation_id, false)
                       AS tombstone_matches_lane,
                   COALESCE(c.operation_id IS NOT NULL
                            AND c.operation_id = a.private_id
                            AND c.issuer_id = o.issuer_id
                            AND c.lane = o.lane
                            AND c.sequence = o.sequence
                            AND c.request_digest = o.request_digest, false)
                       AS tombstone_exact_operation
              FROM ref_store_private_attempts a
              JOIN ref_store_public_operations w
                ON w.repository_id=a.repository_id AND w.public_id=a.public_id
              LEFT JOIN ref_store_operations o
                ON o.repository_id=a.repository_id AND o.operation_id=a.private_id
              LEFT JOIN ref_store_core_events e
                ON e.repository_id=a.repository_id AND e.operation_id=a.private_id
              LEFT JOIN ref_store_cancellations c
                ON c.repository_id=a.repository_id AND c.operation_id=a.private_id
              LEFT JOIN ref_store_cancellations k
                ON k.repository_id=o.repository_id AND k.issuer_id=o.issuer_id
               AND k.lane=o.lane AND k.sequence=o.sequence
             WHERE a.repository_id=$1 AND a.public_id=$2
        ) x
    ), '[]'::jsonb),
    'operation', (
        SELECT to_jsonb(o) FROM (
            SELECT issuer_id, lane, sequence, request_digest, state, terminal_result
              FROM ref_store_operations
             WHERE repository_id=$1 AND operation_id=$3
        ) o
    ),
    'event', (
        SELECT to_jsonb(e) FROM (
            SELECT event_id, revision, outcome, payload
              FROM ref_store_core_events
             WHERE repository_id=$1 AND operation_id=$3
        ) e
    )
) AS evidence
"#;

const LOCK_PUBLIC: &str = "SELECT rootyard_ref_store_lock_public_operation($1,$2,$3)";

const CURRENT_SCOPE: &str = "SELECT rootyard_ref_store_attempt_current_scope(w)
     FROM ref_store_public_operations w
     WHERE w.repository_id=$1 AND w.public_id=$2";

const STALE_GATE: &str = "SELECT rootyard_ref_store_attempt_stale_gate(w,a)
     FROM ref_store_public_operations w
     JOIN ref_store_private_attempts a
       ON a.repository_id=w.repository_id AND a.public_id=w.public_id AND a.slot=0
     WHERE w.repository_id=$1 AND w.public_id=$2";

const UPDATE_TERMINAL: &str = "UPDATE ref_store_public_operations
     SET state=$3,event_id=$4
     WHERE repository_id=$1 AND public_id=$2
       AND state='pending' AND current_slot=0
       AND retired_event_id IS NULL AND event_id IS NULL
       AND cancelled_private_id IS NULL";

/// Slot one is already current on the wrapper. Pin that current slot and the
/// exact retired slot-zero event selected by the existing rotation; never
/// create a second retirement or move the wrapper back to slot zero.
const UPDATE_TERMINAL_SLOT_ONE: &str = "UPDATE ref_store_public_operations
     SET state=$3,event_id=$4
     WHERE repository_id=$1 AND public_id=$2
       AND state='pending' AND current_slot=1
       AND retired_event_id=$5 AND event_id IS NULL
       AND cancelled_private_id IS NULL";

const VERIFY_TERMINAL: &str = "SELECT rootyard_ref_store_verify_public_operation($1,$2)";

/// A mirrored terminal. The event id is durable evidence, never request input.
#[allow(dead_code)] // Crate-private foundation: the future wrapper gateway consumes it.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PublicAttemptTerminalReceipt {
    pub state: OperationState,
    pub event_id: Uuid,
    pub replayed: bool,
}

impl fmt::Debug for PublicAttemptTerminalReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicAttemptTerminalReceipt")
            .field("state", &self.state)
            .field("event_id", &Redacted)
            .field("replayed", &self.replayed)
            .finish()
    }
}

/// A slot-zero stale rejection that is currently retirement-eligible. The
/// wrapper remains pending and the event/operation are untouched.
#[allow(dead_code)] // Crate-private foundation: retirement is a separate reviewed increment.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PublicAttemptRetirement {
    pub event_id: Uuid,
    pub event_revision: i64,
}

impl fmt::Debug for PublicAttemptRetirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicAttemptRetirement")
            .field("event_id", &Redacted)
            .field("event_revision", &self.event_revision)
            .finish()
    }
}

/// The mirror either publishes (or exactly replays) a terminal, or refuses to
/// close a retirement-eligible slot-zero rejection.
#[allow(dead_code)] // Crate-private foundation: the future wrapper gateway consumes it.
#[derive(Clone, Eq, PartialEq)]
pub(crate) enum PublicAttemptTerminalOutcome {
    Mirrored(PublicAttemptTerminalReceipt),
    RetirementRequired(PublicAttemptRetirement),
}

impl fmt::Debug for PublicAttemptTerminalOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mirrored(receipt) => formatter.debug_tuple("Mirrored").field(receipt).finish(),
            Self::RetirementRequired(retirement) => {
                formatter.debug_tuple("RetirementRequired").field(retirement).finish()
            }
        }
    }
}

impl PgRefStore {
    /// Mirror one already-durable migration-138/139 terminal into its pending
    /// migration-152 current wrapper inside a caller-owned dedicated
    /// transaction. Current slot zero keeps its exact prior semantics; current
    /// slot one must already have been admitted by the existing rotation and is
    /// mirrored only when the record is that exact current private operation.
    ///
    /// The method never begins, commits or rolls back. On any error the caller
    /// must roll the dedicated transaction back; SQL errors already abort it.
    /// The absolute deadline is enforced by the existing per-statement
    /// statement/lock budget, refreshed before every read phase and before the
    /// single write. After the write the verifier runs under the same local
    /// budget, so no post-update deadline error can leave a commit-able
    /// unverified wrapper.
    #[allow(dead_code)] // No production caller until the wrapper entry is deliberately opened.
    pub(crate) async fn mirror_public_attempt_terminal_in_tx(
        &self,
        tx: &Transaction<'_>,
        request: &PublicAttemptRequest,
        record: &OperationRecord,
        deadline: Instant,
    ) -> Result<PublicAttemptTerminalOutcome, PackCommitError> {
        request.validate()?;
        validate_record(request, record)?;
        if Instant::now() >= deadline {
            return Err(PackCommitError::from(RefStoreError::Timeout));
        }
        self.mirror_public_attempt_terminal_checked(tx, request, record, deadline).await
    }

    async fn mirror_public_attempt_terminal_checked(
        &self,
        tx: &Transaction<'_>,
        request: &PublicAttemptRequest,
        record: &OperationRecord,
        deadline: Instant,
    ) -> Result<PublicAttemptTerminalOutcome, PackCommitError> {
        refresh_bound(tx, deadline).await?;
        let schema = tx
            .query_one(SCHEMA_PROBE, &[])
            .await
            .map_err(|error| read_sql_error(error, "public terminal mirror schema probe failed"))?;
        if !schema.get::<_, bool>(0) {
            return Err(PackCommitError::from(RefStoreError::Unsupported(
                "public terminal mirror requires migration 152",
            )));
        }
        if !schema.get::<_, bool>(1) {
            return Err(PackCommitError::from(RefStoreError::Unsupported(
                "public terminal mirror requires a read committed transaction",
            )));
        }
        for index in 2usize..7 {
            if !schema.get::<_, bool>(index) {
                return Err(PackCommitError::from(RefStoreError::Unsupported(
                    "public terminal mirror requires the migration 152 lock and evidence functions",
                )));
            }
        }

        // First lock in this fresh transaction: migration 152's normalized
        // public/proposed/existing-attempt advisory keys, then the wrapper row.
        refresh_bound(tx, deadline).await?;
        tx.query_one(LOCK_PUBLIC, &[&request.repository_id, &request.public_id, &record.identity().operation_id()])
            .await
            .map_err(lock_sql_error)?;

        // Hold the existing restore fence through the caller's commit/rollback.
        refresh_bound(tx, deadline).await?;
        let incarnation = lock_cluster_incarnation(tx).await.map_err(|error| match error {
            RefStoreError::Timeout => PackCommitError::from(RefStoreError::Timeout),
            _ => mirror_failure("public terminal mirror could not read the restore fence"),
        })?;
        if incarnation != request.restore_incarnation {
            return Err(PackCommitError::Invalid(
                "public terminal mirror restore incarnation differs from the live cluster authority",
            ));
        }

        refresh_bound(tx, deadline).await?;
        let evidence = read_evidence(tx, request, record.identity().operation_id()).await?;
        let wrapper = evidence.wrapper.ok_or_else(|| ledger("public operation wrapper is missing"))?;

        // The shared resolver owns the public identity/digest/state-shape
        // validation. This module adds only the current-slot terminal
        // constraints.
        let wrapper_state = validate_wrapper(&wrapper, request)?;
        if wrapper_state == OperationState::Cancelled {
            return Err(PackCommitError::from(RefStoreError::Cancelled {
                operation_id: record.identity().operation_id(),
            }));
        }

        // Slot one is the already-rotated successor. It has exactly one retired
        // slot-zero rejection and one current slot-one attempt; the caller's
        // record must be that current private operation, never the retired one.
        // There is no second retirement, sequence allocation or third attempt.
        if wrapper.current_slot() == 1 {
            let retired_event_id = wrapper
                .retired_event_id()
                .filter(|event_id| !event_id.is_nil())
                .ok_or_else(|| ledger("slot one public operation has no exact retired event"))?;
            if wrapper.cancelled_private_id().is_some() {
                return Err(PackCommitError::from(RefStoreError::Unsupported(
                    "slot one terminal mirror requires a non-cancelled public operation",
                )));
            }

            let (retired, current) = slot_one_attempts(&evidence.attempts)?;
            let (retired_sequence, retired_event_revision) =
                validate_slot_zero_retired(retired, request, retired_event_id)?;
            let operation =
                evidence.operation.as_ref().ok_or_else(|| ledger("terminal private operation is missing"))?;
            validate_operation(operation, record)?;
            let event = evidence.event.as_ref().ok_or_else(|| ledger("terminal core event is missing"))?;
            validate_event(event, request, record)?;
            let current_sequence = validate_slot_one_current(current, request, record, operation, event)?;
            if current.private_id == retired.private_id
                || current.plan_digest == retired.plan_digest
                || current.proof_digest == retired.proof_digest
                || current.operation_lane != retired.operation_lane
            {
                return Err(ledger("slot one terminal reuses retired identity, plan, proof or lane"));
            }
            validate_slot_one_lineage(
                retired_sequence,
                retired_event_revision,
                current_sequence,
                current.base_revision,
            )?;
            validate_revision(record.state(), current.base_revision, event.revision)?;

            // The wrapper transition still requires the current ready
            // repository/serving realm and the active restore incarnation. The
            // gate revision may legitimately be later than the slot-one base.
            refresh_bound(tx, deadline).await?;
            let gate_revision = current_scope_revision(tx, request).await?;
            if gate_revision < current.base_revision {
                return Err(ledger("slot one terminal current gate precedes its base revision"));
            }

            if wrapper_state == OperationState::Pending {
                refresh_bound(tx, deadline).await?;
                tx.execute("SET LOCAL synchronous_commit = 'on'", &[]).await.map_err(|error| {
                    write_sql_error(error, "public terminal mirror durability could not be requested")
                })?;
                let state = record.state().as_str();
                let changed = tx
                    .execute(
                        UPDATE_TERMINAL_SLOT_ONE,
                        &[&request.repository_id, &request.public_id, &state, &event.event_id, &retired_event_id],
                    )
                    .await
                    .map_err(|error| write_sql_error(error, "public operation terminal update was refused"))?;
                if changed != 1 {
                    return Err(ledger("public operation terminal update did not match exactly one row"));
                }

                verify_public_operation(tx, request).await?;
                return Ok(PublicAttemptTerminalOutcome::Mirrored(PublicAttemptTerminalReceipt {
                    state: record.state(),
                    event_id: event.event_id,
                    replayed: false,
                }));
            }

            // Only the exact already-published slot-one terminal may replay.
            if wrapper_state != record.state() {
                return Err(PackCommitError::from(RefStoreError::TerminalImmutable));
            }
            if wrapper.event_id() != Some(event.event_id) {
                return Err(ledger("public operation published event differs from its terminal"));
            }
            refresh_bound(tx, deadline).await?;
            verify_public_operation(tx, request).await?;
            return Ok(PublicAttemptTerminalOutcome::Mirrored(PublicAttemptTerminalReceipt {
                state: wrapper_state,
                event_id: event.event_id,
                replayed: true,
            }));
        }

        if wrapper.current_slot() != 0
            || wrapper.retired_event_id().is_some()
            || wrapper.cancelled_private_id().is_some()
        {
            return Err(PackCommitError::from(RefStoreError::Unsupported(
                "public terminal mirror requires current slot zero without retirement or cancellation",
            )));
        }

        let attempt = validate_attempt(&evidence.attempts, record)?;
        let operation = evidence.operation.as_ref().ok_or_else(|| ledger("terminal private operation is missing"))?;
        validate_operation(operation, record)?;
        let event = evidence.event.as_ref().ok_or_else(|| ledger("terminal core event is missing"))?;
        validate_event(event, request, record)?;
        validate_revision(record.state(), attempt, event.revision)?;

        refresh_bound(tx, deadline).await?;
        let gate_revision = current_scope_revision(tx, request).await?;

        if wrapper_state == OperationState::Pending {
            if retirement_candidate(record.state(), attempt, event.revision, gate_revision, &event.payload) {
                refresh_bound(tx, deadline).await?;
                let stale_revision = stale_gate_revision(tx, request).await?;
                if stale_revision != gate_revision || stale_revision != event.revision {
                    return Err(ledger("public operation stale retirement evidence differs"));
                }
                return Ok(PublicAttemptTerminalOutcome::RetirementRequired(PublicAttemptRetirement {
                    event_id: event.event_id,
                    event_revision: event.revision,
                }));
            }

            refresh_bound(tx, deadline).await?;
            // The caller's COMMIT is the publication point; request WAL
            // durability before the only data-mutating statement.
            tx.execute("SET LOCAL synchronous_commit = 'on'", &[])
                .await
                .map_err(|error| write_sql_error(error, "public terminal mirror durability could not be requested"))?;
            let state = record.state().as_str();
            let changed = tx
                .execute(UPDATE_TERMINAL, &[&request.repository_id, &request.public_id, &state, &event.event_id])
                .await
                .map_err(|error| write_sql_error(error, "public operation terminal update was refused"))?;
            if changed != 1 {
                return Err(ledger("public operation terminal update did not match exactly one row"));
            }

            // Prove the deferred evidence trigger's shape before returning. A
            // failure here is a SQL error and aborts the dedicated transaction.
            verify_public_operation(tx, request).await?;

            return Ok(PublicAttemptTerminalOutcome::Mirrored(PublicAttemptTerminalReceipt {
                state: record.state(),
                event_id: event.event_id,
                replayed: false,
            }));
        }

        // Already published. All exact evidence above still had to agree, and
        // every mismatching terminal is immutable rather than republished.
        if wrapper_state != record.state() {
            return Err(PackCommitError::from(RefStoreError::TerminalImmutable));
        }
        if wrapper.event_id() != Some(event.event_id) {
            return Err(ledger("public operation published event differs from its terminal"));
        }
        // Replay is read-only but must still prove the same durable shape,
        // including cancellation-tombstone consistency that the manual checks
        // deliberately do not duplicate.
        refresh_bound(tx, deadline).await?;
        verify_public_operation(tx, request).await?;
        Ok(PublicAttemptTerminalOutcome::Mirrored(PublicAttemptTerminalReceipt {
            state: wrapper_state,
            event_id: event.event_id,
            replayed: true,
        }))
    }
}

fn validate_record(request: &PublicAttemptRequest, record: &OperationRecord) -> Result<(), PackCommitError> {
    let identity = record.identity();
    if identity.repository_id() != request.repository_id || identity.issuer_id() != request.issuer_id {
        return Err(PackCommitError::from(RefStoreError::IdentityConflict));
    }
    if identity.operation_id() == request.public_id {
        return Err(ledger("public and private operation identifiers alias"));
    }
    match record.state() {
        OperationState::Pending => {
            return Err(PackCommitError::from(RefStoreError::OperationPending {
                operation_id: identity.operation_id(),
            }));
        }
        OperationState::Cancelled => {
            return Err(PackCommitError::from(RefStoreError::Cancelled { operation_id: identity.operation_id() }));
        }
        OperationState::Committed | OperationState::Rejected => {}
    }
    if record.terminal_result().is_none() {
        return Err(ledger("terminal operation record has no result"));
    }
    Ok(())
}

fn validate_attempt(attempts: &[MirrorAttempt], record: &OperationRecord) -> Result<i64, PackCommitError> {
    let [attempt] = attempts else {
        return Err(ledger("public operation must have exactly one slot-zero attempt"));
    };
    if attempt.slot != 0 {
        return Err(ledger("public operation current attempt is not slot zero"));
    }
    if attempt.private_id != record.identity().operation_id() {
        return Err(ledger("private attempt identity differs from the terminal record"));
    }
    if !attempt.serving_bound {
        return Err(ledger("private attempt serving producer binding differs"));
    }
    let plan_digest = parse_digest(&attempt.plan_digest, "stored private attempt plan digest is not canonical")?;
    if plan_digest != *record.identity().digest() {
        return Err(ledger("private attempt plan digest differs from the terminal record"));
    }
    // The proof is not part of the mirror predicate, but a non-canonical
    // stored proof is still durable inconsistency and must fail closed.
    let _proof = parse_digest(&attempt.proof_digest, "stored private attempt proof digest is not canonical")?;
    if attempt.base_revision <= 0 {
        return Err(ledger("stored private attempt base revision is not positive"));
    }
    Ok(attempt.base_revision)
}

/// The rotated wrapper carries exactly the retired slot-zero attempt and the
/// current slot-one attempt. The SQL already orders by slot; any other shape is
/// ambiguous and fails closed.
fn slot_one_attempts(attempts: &[MirrorAttempt]) -> Result<(&MirrorAttempt, &MirrorAttempt), PackCommitError> {
    let [retired, current] = attempts else {
        return Err(ledger("slot one public operation must have exactly two attempts"));
    };
    if retired.slot != 0 || current.slot != 1 {
        return Err(ledger("slot one public operation attempts are not exactly slot zero then one"));
    }
    Ok((retired, current))
}

/// Re-prove the already-retired slot-zero attempt from the same snapshot. Its
/// event must be the wrapper's exact retired event, its terminal body must be
/// the canonical revision-mismatch rejection at an advanced revision, and it
/// must not carry a cancellation tombstone.
fn validate_slot_zero_retired(
    attempt: &MirrorAttempt,
    request: &PublicAttemptRequest,
    retired_event_id: Uuid,
) -> Result<(i64, i64), PackCommitError> {
    if attempt.slot != 0 {
        return Err(ledger("retired public attempt is not slot zero"));
    }
    if attempt.private_id.is_nil() || attempt.private_id == request.public_id {
        return Err(ledger("retired public attempt identity aliases the public identifier"));
    }
    let plan_digest = parse_digest(&attempt.plan_digest, "stored retired attempt plan digest is not canonical")?;
    let _proof_digest = parse_digest(&attempt.proof_digest, "stored retired attempt proof digest is not canonical")?;
    if attempt.base_revision <= 0 {
        return Err(ledger("stored retired attempt base revision is not positive"));
    }
    if !attempt.serving_bound {
        return Err(ledger("retired private attempt serving producer binding differs"));
    }
    if attempt.operation_issuer_id != Some(request.issuer_id) {
        return Err(ledger("retired private attempt operation issuer differs from its wrapper"));
    }
    if attempt.operation_lane.is_none() {
        return Err(ledger("retired private attempt operation lane is missing"));
    }
    let sequence = attempt.operation_sequence.ok_or_else(|| ledger("retired private attempt sequence is missing"))?;
    if sequence <= 0 {
        return Err(ledger("retired private attempt sequence is not positive"));
    }
    let operation_digest = parse_digest(
        attempt
            .operation_request_digest
            .as_deref()
            .ok_or_else(|| ledger("retired private attempt request digest is missing"))?,
        "stored retired attempt operation digest is not canonical",
    )?;
    if operation_digest != plan_digest {
        return Err(ledger("retired private attempt operation digest differs from its plan digest"));
    }
    let state = parse_state(
        attempt.operation_state.as_deref().ok_or_else(|| ledger("retired private attempt state is missing"))?,
        "stored retired attempt operation state is not recognized",
    )?;
    if state != OperationState::Rejected {
        return Err(ledger("retired public attempt is not a rejection"));
    }
    if !attempt.terminal_present {
        return Err(ledger("retired private attempt has no terminal result"));
    }
    let event_id = attempt.event_id.ok_or_else(|| ledger("retired private attempt has no migration-139 event"))?;
    if event_id != retired_event_id {
        return Err(ledger("retired public attempt event differs from the wrapper retirement"));
    }
    let event_revision =
        attempt.event_revision.ok_or_else(|| ledger("retired private attempt event revision is missing"))?;
    if event_revision <= attempt.base_revision {
        return Err(ledger("retired public attempt did not observe an advanced gate"));
    }
    if !attempt.event_outcome_matches || !attempt.event_body_matches {
        return Err(ledger("retired private attempt event differs from its operation"));
    }
    if !attempt.revision_mismatch_rejection {
        return Err(ledger("retired public attempt is not the exact revision-mismatch rejection"));
    }
    if attempt.tombstone_present {
        if !attempt.tombstone_matches_lane || !attempt.tombstone_exact_operation {
            return Err(ledger("retired private attempt cancellation tombstone differs from its operation"));
        }
        return Err(ledger("retired public attempt carries a cancellation tombstone"));
    }
    if !attempt.tombstone_absent {
        return Err(ledger("retired private attempt cancellation evidence differs from its operation lane"));
    }
    Ok((sequence, event_revision))
}

/// Re-prove that the caller's terminal record is the actual current slot-one
/// private operation: exact identity/digest, canonical proof, exact migration
/// 138 operation row, migration 139 event and no cancellation tombstone.
fn validate_slot_one_current(
    attempt: &MirrorAttempt,
    request: &PublicAttemptRequest,
    record: &OperationRecord,
    operation: &MirrorOperation,
    event: &MirrorEvent,
) -> Result<i64, PackCommitError> {
    if attempt.slot != 1 {
        return Err(ledger("public operation current attempt is not slot one"));
    }
    if attempt.private_id != record.identity().operation_id() {
        return Err(ledger("slot one current private identity differs from the terminal record"));
    }
    if attempt.private_id.is_nil() || attempt.private_id == request.public_id {
        return Err(ledger("slot one current private identity aliases the public identifier"));
    }
    let plan_digest = parse_digest(&attempt.plan_digest, "stored slot-one attempt plan digest is not canonical")?;
    if plan_digest != *record.identity().digest() {
        return Err(ledger("slot one current plan digest differs from the terminal record"));
    }
    let _proof_digest = parse_digest(&attempt.proof_digest, "stored slot-one attempt proof digest is not canonical")?;
    if attempt.base_revision <= 0 {
        return Err(ledger("stored slot-one attempt base revision is not positive"));
    }
    if !attempt.serving_bound {
        return Err(ledger("slot one current private attempt serving producer binding differs"));
    }
    let sequence =
        attempt.operation_sequence.ok_or_else(|| ledger("slot one current operation sequence is missing"))?;
    if sequence <= 0 {
        return Err(ledger("slot one current operation sequence is not positive"));
    }
    if attempt.operation_issuer_id != Some(operation.issuer_id)
        || attempt.operation_lane.as_deref() != Some(operation.lane.as_str())
        || attempt.operation_sequence != Some(operation.sequence)
        || attempt.operation_request_digest.as_deref() != Some(operation.request_digest.as_str())
        || attempt.operation_state.as_deref() != Some(operation.state.as_str())
    {
        return Err(ledger("slot one current private operation differs from its terminal record"));
    }
    if !attempt.terminal_present {
        return Err(ledger("slot one current private operation has no terminal result"));
    }
    if attempt.event_id != Some(event.event_id) || attempt.event_revision != Some(event.revision) {
        return Err(ledger("slot one current private event differs from the terminal record"));
    }
    if !attempt.event_outcome_matches || !attempt.event_body_matches {
        return Err(ledger("slot one current private event differs from its operation"));
    }
    if attempt.tombstone_present {
        if !attempt.tombstone_matches_lane || !attempt.tombstone_exact_operation {
            return Err(ledger("slot one current cancellation tombstone differs from its operation"));
        }
        return Err(ledger("slot one current terminal carries a cancellation tombstone"));
    }
    if !attempt.tombstone_absent {
        return Err(ledger("slot one current cancellation evidence differs from its operation lane"));
    }
    Ok(sequence)
}

/// The slot-one successor must use a checked later BIGINT sequence and the
/// retired event revision as its exact base. The base must itself be able to
/// advance by one for a committed terminal.
fn validate_slot_one_lineage(
    retired_sequence: i64,
    retired_event_revision: i64,
    current_sequence: i64,
    current_base_revision: i64,
) -> Result<(), PackCommitError> {
    if retired_sequence <= 0 || retired_event_revision <= 0 {
        return Err(ledger("slot one retired sequence or event revision is not positive"));
    }
    if current_sequence <= 0 || current_base_revision <= 0 {
        return Err(ledger("slot one current sequence or base revision is not positive"));
    }
    let minimum = retired_sequence.checked_add(1).ok_or_else(|| ledger("slot one retired sequence cannot advance"))?;
    if current_sequence < minimum {
        return Err(ledger("slot one sequence does not advance the retired attempt"));
    }
    if current_base_revision != retired_event_revision {
        return Err(ledger("slot one base revision differs from the retired event"));
    }
    current_base_revision.checked_add(1).ok_or_else(|| ledger("slot one base revision cannot advance"))?;
    Ok(())
}

fn validate_operation(operation: &MirrorOperation, record: &OperationRecord) -> Result<(), PackCommitError> {
    let identity = record.identity();
    if operation.issuer_id != identity.issuer_id()
        || operation.lane.as_str() != identity.lane().as_str()
        || operation.sequence != identity.sequence()
    {
        return Err(ledger("private operation identity differs from the terminal record"));
    }
    let digest = parse_digest(&operation.request_digest, "stored private operation digest is not canonical")?;
    if digest != *identity.digest() {
        return Err(ledger("private operation digest differs from the terminal record"));
    }
    let state = parse_state(&operation.state, "stored private operation state is not recognized")?;
    if state != record.state() {
        return Err(ledger("private operation state differs from the terminal record"));
    }
    let stored = operation
        .terminal_result
        .as_ref()
        .ok_or_else(|| ledger("terminal private operation has no terminal result"))?;
    let expected = record.terminal_result().ok_or_else(|| ledger("terminal operation record has no result"))?;
    if stored != expected.value() {
        return Err(ledger("private operation terminal result differs from the terminal record"));
    }
    Ok(())
}

fn validate_event(
    event: &MirrorEvent,
    request: &PublicAttemptRequest,
    record: &OperationRecord,
) -> Result<(), PackCommitError> {
    if event.event_id.is_nil() {
        return Err(ledger("terminal core event identity is nil"));
    }
    if event.outcome.as_str() != record.state().as_str() {
        return Err(ledger("terminal core event outcome differs from the terminal record"));
    }
    let expected = record.terminal_result().ok_or_else(|| ledger("terminal operation record has no result"))?;
    if &event.payload != expected.value() {
        return Err(ledger("terminal core event payload differs from the terminal record"));
    }
    if event.payload.get("kind").and_then(Value::as_str) != Some(record.state().as_str()) {
        return Err(ledger("terminal core event kind differs from its outcome"));
    }
    let repository = request.repository_id.to_string();
    if event.payload.get("repository_id").and_then(Value::as_str) != Some(repository.as_str()) {
        return Err(ledger("terminal core event repository differs from its wrapper"));
    }
    if event.payload.get("revision").and_then(Value::as_i64) != Some(event.revision) {
        return Err(ledger("terminal core event revision differs from its payload"));
    }
    if event.revision < 0 {
        return Err(ledger("terminal core event revision is negative"));
    }
    Ok(())
}

fn validate_revision(state: OperationState, base_revision: i64, event_revision: i64) -> Result<(), PackCommitError> {
    match state {
        OperationState::Committed => {
            let expected = base_revision
                .checked_add(1)
                .ok_or_else(|| ledger("committed event revision overflows its base revision"))?;
            if event_revision != expected {
                return Err(ledger("committed event revision is not exactly base plus one"));
            }
        }
        OperationState::Rejected => {
            // Native rejection records the current gate revision, which may be
            // exactly the base (a normal rejection) or later (stale rejection).
            if event_revision < base_revision {
                return Err(ledger("rejected event revision precedes its base revision"));
            }
        }
        OperationState::Pending | OperationState::Cancelled => {
            return Err(ledger("terminal mirror requires a committed or rejected record"));
        }
    }
    Ok(())
}

fn retirement_candidate(
    state: OperationState,
    base_revision: i64,
    event_revision: i64,
    gate_revision: i64,
    payload: &Value,
) -> bool {
    state == OperationState::Rejected
        && event_revision > base_revision
        && event_revision == gate_revision
        && is_revision_mismatch_rejection(payload)
}

fn is_revision_mismatch_rejection(payload: &Value) -> bool {
    payload
        .get("rejection")
        .and_then(Value::as_object)
        .and_then(|rejection| rejection.get("code"))
        .and_then(Value::as_str)
        == Some(PackCommitRejectCode::RevisionMismatch.as_str())
        && matches!(payload.get("registrations"), Some(Value::Array(registrations)) if registrations.is_empty())
}

async fn verify_public_operation(tx: &Transaction<'_>, request: &PublicAttemptRequest) -> Result<(), PackCommitError> {
    tx.query_one(VERIFY_TERMINAL, &[&request.repository_id, &request.public_id])
        .await
        .map_err(|error| write_sql_error(error, "public operation and private attempt evidence disagree"))?;
    Ok(())
}

async fn current_scope_revision(tx: &Transaction<'_>, request: &PublicAttemptRequest) -> Result<i64, PackCommitError> {
    let row = tx
        .query_opt(CURRENT_SCOPE, &[&request.repository_id, &request.public_id])
        .await
        .map_err(current_scope_error)?
        .ok_or_else(|| ledger("public operation wrapper disappeared during the terminal mirror"))?;
    let revision: i64 = row.get(0);
    if revision <= 0 {
        return Err(ledger("public operation current gate revision is not positive"));
    }
    Ok(revision)
}

async fn stale_gate_revision(tx: &Transaction<'_>, request: &PublicAttemptRequest) -> Result<i64, PackCommitError> {
    let row = tx
        .query_opt(STALE_GATE, &[&request.repository_id, &request.public_id])
        .await
        .map_err(|error| write_sql_error(error, "public operation stale retirement evidence differs"))?
        .ok_or_else(|| ledger("public operation stale retirement evidence is missing"))?;
    let revision: i64 = row.get(0);
    if revision <= 0 {
        return Err(ledger("public operation stale retirement revision is not positive"));
    }
    Ok(revision)
}

async fn read_evidence(
    tx: &Transaction<'_>,
    request: &PublicAttemptRequest,
    private_id: Uuid,
) -> Result<MirrorEvidence, PackCommitError> {
    let row = tx
        .query_one(SELECT_EVIDENCE, &[&request.repository_id, &request.public_id, &private_id])
        .await
        .map_err(|error| read_sql_error(error, "public terminal mirror evidence could not be read"))?;
    let evidence: Value = row.get(0);
    serde_json::from_value(evidence).map_err(|_| ledger("public terminal mirror evidence shape is not recognized"))
}

async fn refresh_bound(tx: &Transaction<'_>, deadline: Instant) -> Result<(), PackCommitError> {
    if Instant::now() >= deadline {
        return Err(PackCommitError::from(RefStoreError::Timeout));
    }
    match bound(tx, deadline).await {
        Ok(()) => Ok(()),
        Err(RefStoreError::Timeout) => Err(PackCommitError::from(RefStoreError::Timeout)),
        Err(_) => Err(mirror_failure("public terminal mirror could not set its bounded statement budget")),
    }
}

fn lock_sql_error(error: tokio_postgres::Error) -> PackCommitError {
    match error.code() {
        Some(code) if *code == SqlState::QUERY_CANCELED || *code == SqlState::LOCK_NOT_AVAILABLE => {
            PackCommitError::from(RefStoreError::Timeout)
        }
        Some(code) if *code == SqlState::UNIQUE_VIOLATION || *code == SqlState::T_R_SERIALIZATION_FAILURE => {
            ledger("public operation lock set or wrapper evidence differs")
        }
        _ => mirror_failure("public terminal mirror could not lock the public operation"),
    }
}

fn read_sql_error(error: tokio_postgres::Error, detail: &'static str) -> PackCommitError {
    match error.code() {
        Some(code) if *code == SqlState::QUERY_CANCELED || *code == SqlState::LOCK_NOT_AVAILABLE => {
            PackCommitError::from(RefStoreError::Timeout)
        }
        _ => mirror_failure(detail),
    }
}

fn write_sql_error(error: tokio_postgres::Error, detail: &'static str) -> PackCommitError {
    match error.code() {
        Some(code) if *code == SqlState::QUERY_CANCELED || *code == SqlState::LOCK_NOT_AVAILABLE => {
            PackCommitError::from(RefStoreError::Timeout)
        }
        Some(code)
            if *code == SqlState::CHECK_VIOLATION
                || *code == SqlState::UNIQUE_VIOLATION
                || *code == SqlState::T_R_SERIALIZATION_FAILURE =>
        {
            ledger(detail)
        }
        _ => mirror_failure(detail),
    }
}

fn current_scope_error(error: tokio_postgres::Error) -> PackCommitError {
    match error.code() {
        Some(code) if *code == SqlState::QUERY_CANCELED || *code == SqlState::LOCK_NOT_AVAILABLE => {
            PackCommitError::from(RefStoreError::Timeout)
        }
        Some(code) if *code == SqlState::CHECK_VIOLATION => stale_realm(),
        _ => mirror_failure("public terminal mirror current scope could not be read"),
    }
}

fn mirror_failure(detail: &'static str) -> PackCommitError {
    PackCommitError::from(RefStoreError::Database(detail.to_owned()))
}

#[derive(Clone, Deserialize)]
struct MirrorEvidence {
    wrapper: Option<RawWrapper>,
    #[serde(default)]
    attempts: Vec<MirrorAttempt>,
    operation: Option<MirrorOperation>,
    event: Option<MirrorEvent>,
}

#[derive(Clone, Deserialize)]
struct MirrorAttempt {
    slot: i16,
    private_id: Uuid,
    plan_digest: String,
    proof_digest: String,
    base_revision: i64,
    serving_bound: bool,
    operation_issuer_id: Option<Uuid>,
    operation_lane: Option<String>,
    operation_sequence: Option<i64>,
    operation_request_digest: Option<String>,
    operation_state: Option<String>,
    terminal_present: bool,
    event_id: Option<Uuid>,
    event_revision: Option<i64>,
    event_outcome_matches: bool,
    event_body_matches: bool,
    tombstone_present: bool,
    tombstone_absent: bool,
    tombstone_matches_lane: bool,
    tombstone_exact_operation: bool,
    revision_mismatch_rejection: bool,
}

#[derive(Clone, Deserialize)]
struct MirrorOperation {
    issuer_id: Uuid,
    lane: String,
    sequence: i64,
    request_digest: String,
    state: String,
    terminal_result: Option<Value>,
}

#[derive(Clone, Deserialize)]
struct MirrorEvent {
    event_id: Uuid,
    revision: i64,
    outcome: String,
    payload: Value,
}

#[cfg(test)]
mod tests {
    use super::{is_revision_mismatch_rejection, retirement_candidate, validate_revision, validate_slot_one_lineage};
    use crate::ref_store::OperationState;
    use serde_json::json;

    #[test]
    fn committed_revision_is_exactly_base_plus_one_with_checked_overflow() {
        assert!(validate_revision(OperationState::Committed, 1, 2).is_ok());
        assert!(validate_revision(OperationState::Committed, 1, 1).is_err());
        assert!(validate_revision(OperationState::Committed, 1, 3).is_err());
        assert!(validate_revision(OperationState::Committed, i64::MAX, i64::MAX).is_err());
    }

    #[test]
    fn slot_one_lineage_advances_sequence_and_pins_the_retired_revision() {
        assert!(validate_slot_one_lineage(4, 7, 5, 7).is_ok());
        assert!(validate_slot_one_lineage(4, 7, 9, 7).is_ok());
        assert!(validate_slot_one_lineage(4, 7, 4, 7).is_err());
        assert!(validate_slot_one_lineage(i64::MAX, 7, i64::MAX, 7).is_err());
        assert!(validate_slot_one_lineage(4, 7, 5, 8).is_err());
        assert!(validate_slot_one_lineage(4, i64::MAX, 5, i64::MAX).is_err());
        assert!(validate_slot_one_lineage(0, 7, 1, 7).is_err());
        assert!(validate_slot_one_lineage(4, 7, 5, 0).is_err());
    }

    #[test]
    fn rejected_revision_is_equal_or_ahead_of_its_base() {
        assert!(validate_revision(OperationState::Rejected, 4, 4).is_ok());
        assert!(validate_revision(OperationState::Rejected, 4, 5).is_ok());
        assert!(validate_revision(OperationState::Rejected, 4, 3).is_err());
    }

    #[test]
    fn retirement_requires_the_exact_stale_shape_at_the_current_gate() {
        let stale = json!({
            "kind": "rejected",
            "rejection": {"code": "revision_mismatch"},
            "registrations": [],
        });
        assert!(is_revision_mismatch_rejection(&stale));
        assert!(retirement_candidate(OperationState::Rejected, 3, 4, 4, &stale));
        assert!(!retirement_candidate(OperationState::Rejected, 3, 4, 5, &stale));
        assert!(!retirement_candidate(OperationState::Rejected, 4, 4, 4, &stale));
        assert!(!retirement_candidate(OperationState::Committed, 3, 4, 4, &stale));

        let nonempty = json!({
            "kind": "rejected",
            "rejection": {"code": "revision_mismatch"},
            "registrations": [{"pack_id": "not-empty"}],
        });
        let other_code = json!({
            "kind": "rejected",
            "rejection": {"code": "old_oid_mismatch"},
            "registrations": [],
        });
        let missing_registrations = json!({
            "kind": "rejected",
            "rejection": {"code": "revision_mismatch"},
        });
        for payload in [&nonempty, &other_code, &missing_registrations] {
            assert!(!is_revision_mismatch_rejection(payload));
            assert!(!retirement_candidate(OperationState::Rejected, 3, 4, 4, payload));
        }
    }
}
