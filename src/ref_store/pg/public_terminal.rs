//! Crate-private terminal mirror for migration 152's current public attempt.
//!
//! An already durable migration-138/139 private terminal becomes visible
//! through the migration-152 public wrapper after the current attempt and every
//! preceding retirement have been verified under the same locks.
//!
//! The caller supplies the exact [`PublicAttemptRequest`] already authenticated
//! at the serving boundary and the exact private [`OperationRecord`] already
//! produced by the existing migration-138 terminal writer. Only `Committed` and
//! `Rejected` records are accepted; `Pending` and `Cancelled` are typed
//! refusals. The record's terminal body is never trusted on its own: it must
//! equal the stored migration-138 terminal result and the one immutable
//! migration-139 event body, with the event kind/repository/revision fields and
//! the exact migration-147 serving binding agreeing with the wrapper. Each
//! predecessor must have its own exact retirement event and contiguous
//! successor lineage.
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
//! exactly the one pending current-slot row pinned by its slot and ordered
//! retirement events, or no row; after a successful one-row
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
//! A gate-aligned stale rejection (`revision_mismatch`, empty registrations)
//! on slot zero or one returns [`PublicAttemptTerminalOutcome::RetirementRequired`]
//! without writing. Slot two publishes or replays its exact terminal outcome.
use super::{
    PgRefStore, bound,
    public_attempt::{
        PublicAttempt, PublicAttemptRequest, RawWrapper, Redacted, ledger, parse_digest, parse_state, stale_realm,
        validate_wrapper,
    },
    slot_one::recompute_slot_two_proof,
    slot_zero::recompute_slot_zero_proof,
};
use crate::ref_store::{
    OperationRecord, OperationState, RefStoreError,
    core::{
        pack_commit::{PackCommitError, PackCommitRejectCode},
        pack_snapshot::lock_cluster_incarnation,
    },
};
use serde::Deserialize;
use serde_json::Value;
use std::fmt;
use tokio::time::Instant;
use tokio_postgres::{Transaction, error::SqlState};
use uuid::Uuid;

/// Probe exactly the migration-152 objects this mirror uses. The relation and
/// function checks keep an older or partial catalog an explicit `Unsupported`
/// result instead of preparing a statement whose objects do not exist.
const SCHEMA_PROBE: &str = "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=152), \
        current_setting('transaction_isolation') = 'read committed', \
        to_regclass('ref_store_attempt_retirements') IS NOT NULL, \
        to_regprocedure('rootyard_ref_store_lock_public_operation(uuid,uuid,uuid)') IS NOT NULL, \
        to_regprocedure('rootyard_ref_store_attempt_has_binding(\
            ref_store_public_operations,ref_store_private_attempts)') IS NOT NULL, \
        to_regprocedure('rootyard_ref_store_attempt_current_scope(\
            ref_store_public_operations)') IS NOT NULL, \
        to_regprocedure('rootyard_ref_store_attempt_stale_gate(\
            ref_store_public_operations,ref_store_private_attempts)') IS NOT NULL, \
        to_regprocedure('rootyard_ref_store_verify_public_operation(uuid,uuid)') IS NOT NULL";

/// One snapshot of the wrapper, its ordered attempts, the private operation
/// and its event. The migration-152 binding predicate stays inside PostgreSQL;
/// it is the reviewed authoritative SQL check, not a second vocabulary here.
const SELECT_EVIDENCE: &str = r#"
SELECT jsonb_build_object(
    'wrapper', (
        SELECT to_jsonb(w) FROM (
            SELECT repository_id, public_id, admission_owner_id, issuer_id, wire_digest,
                   request_mode, backend_identity, object_format, history_incarnation,
                   authority_epoch, group_epoch, restore_incarnation, current_slot,
                   state, event_id, cancelled_private_id
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
                   r.event_id AS retired_event_id,
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
                   COALESCE(c.operation_id IS NOT NULL
                            AND c.repository_id = k.repository_id
                            AND c.operation_id = k.operation_id
                            AND c.issuer_id = k.issuer_id
                            AND c.lane = k.lane
                            AND c.sequence = k.sequence
                            AND c.request_digest = k.request_digest, false)
                       AS tombstone_matches_lane,
                   COALESCE(c.operation_id IS NOT NULL
                            AND c.repository_id = a.repository_id
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
              LEFT JOIN ref_store_attempt_retirements r
                ON r.repository_id=a.repository_id AND r.public_id=a.public_id AND r.slot=a.slot
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
       ON a.repository_id=w.repository_id AND a.public_id=w.public_id AND a.slot=w.current_slot
     WHERE w.repository_id=$1 AND w.public_id=$2";

const UPDATE_TERMINAL: &str = "UPDATE ref_store_public_operations
     SET state=$3,event_id=$4
     WHERE repository_id=$1 AND public_id=$2
       AND state='pending' AND current_slot=$5 AND event_id IS NULL
       AND cancelled_private_id IS NULL
       AND ARRAY(SELECT event_id FROM ref_store_attempt_retirements
                 WHERE repository_id=$1 AND public_id=$2 ORDER BY slot)=$6::uuid[]";

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

/// A stale rejection that is currently retirement-eligible. The
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
/// close a retirement-eligible rejection.
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
    /// transaction. Any prior rotations must already be durable.
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
        for index in 2usize..8 {
            if !schema.get::<_, bool>(index) {
                return Err(PackCommitError::from(RefStoreError::Unsupported(
                    "public terminal mirror requires the migration 152 retirement ledger and evidence functions",
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

        let current_slot = wrapper.current_slot();
        let (current, retired_event_ids) = validate_attempt_chain(&evidence.attempts, current_slot, request)?;
        let operation = evidence.operation.as_ref().ok_or_else(|| ledger("terminal private operation is missing"))?;
        validate_operation(operation, record)?;
        let event = evidence.event.as_ref().ok_or_else(|| ledger("terminal core event is missing"))?;
        validate_event(event, request, record)?;
        if current.private_id != record.identity().operation_id()
            || current.plan_digest != *record.identity().digest()
            || &current.lane != record.identity().lane()
            || current.sequence != record.identity().sequence()
            || current.state != record.state()
            || current.event_id != Some(event.event_id)
            || current.event_revision != Some(event.revision)
        {
            return Err(ledger("current private attempt differs from the terminal record"));
        }
        validate_revision(record.state(), current.base_revision, event.revision)?;

        refresh_bound(tx, deadline).await?;
        let gate_revision = current_scope_revision(tx, request).await?;
        if gate_revision < event.revision {
            return Err(ledger("public terminal current gate precedes its event revision"));
        }

        if wrapper_state == OperationState::Pending {
            if retirement_candidate(
                current_slot,
                record.state(),
                current.base_revision,
                event.revision,
                gate_revision,
                &event.payload,
            ) {
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
            // The caller's COMMIT is the publication point; require WAL
            // durability before touching the wrapper.
            tx.execute("SET LOCAL synchronous_commit = 'on'", &[])
                .await
                .map_err(|error| write_sql_error(error, "public terminal mirror durability could not be requested"))?;
            let state = record.state().as_str();
            let changed = tx
                .execute(
                    UPDATE_TERMINAL,
                    &[
                        &request.repository_id,
                        &request.public_id,
                        &state,
                        &event.event_id,
                        &current_slot,
                        &retired_event_ids,
                    ],
                )
                .await
                .map_err(|error| write_sql_error(error, "public operation terminal update was refused"))?;
            if changed != 1 {
                return Err(ledger("public operation terminal update did not match exactly one row"));
            }

            // A failure here is a SQL error and aborts the dedicated transaction.
            verify_public_operation(tx, request).await?;
            return Ok(PublicAttemptTerminalOutcome::Mirrored(PublicAttemptTerminalReceipt {
                state: record.state(),
                event_id: event.event_id,
                replayed: false,
            }));
        }

        if wrapper_state != record.state() {
            return Err(PackCommitError::from(RefStoreError::TerminalImmutable));
        }
        if wrapper.event_id() != Some(event.event_id) {
            return Err(ledger("public operation published event differs from its terminal"));
        }
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

fn validate_attempt_chain(
    attempts: &[MirrorAttempt],
    current_slot: i16,
    request: &PublicAttemptRequest,
) -> Result<(PublicAttempt, Vec<Uuid>), PackCommitError> {
    let (current, retired) = attempts.split_last().ok_or_else(|| ledger("public operation has no private attempts"))?;
    if !(0..=2).contains(&current_slot) || retired.len() != current_slot as usize || current.slot != current_slot {
        return Err(ledger("public operation does not have a contiguous attempt prefix"));
    }
    if current.retired_event_id.is_some() {
        return Err(ledger("the current private attempt already has a retirement"));
    }
    let current = parse_terminal_attempt(current, request)?;
    let mut preceding = Vec::with_capacity(retired.len());
    let mut retirement_ids = Vec::with_capacity(retired.len());
    for (slot, row) in retired.iter().enumerate() {
        let attempt = parse_terminal_attempt(row, request)?;
        let event_id = row.retired_event_id.ok_or_else(|| ledger("retired attempt has no linked event"))?;
        if attempt.slot as usize != slot
            || attempt.state != OperationState::Rejected
            || attempt.event_id != Some(event_id)
            || !row.revision_mismatch_rejection
            || attempt.event_revision.is_none_or(|revision| revision <= attempt.base_revision)
        {
            return Err(ledger("retired attempt is not the exact ordered revision-mismatch rejection"));
        }
        if current.event_id == Some(event_id) || retirement_ids.contains(&event_id) {
            return Err(ledger("private attempt event is reused"));
        }
        retirement_ids.push(event_id);
        preceding.push(attempt);
    }

    for (index, retired) in preceding.iter().enumerate() {
        let successor = preceding.get(index + 1).unwrap_or(&current);
        let event_revision = retired.event_revision.ok_or_else(|| ledger("retired event revision is missing"))?;
        validate_successor_revision(retired.sequence, event_revision, successor.sequence, successor.base_revision)?;
        if retired.lane != successor.lane {
            return Err(ledger("successor switches the retired attempt's lane"));
        }
        if preceding[index + 1..].iter().chain(std::iter::once(&current)).any(|later| {
            later.private_id == retired.private_id
                || later.plan_digest == retired.plan_digest
                || later.proof_digest == retired.proof_digest
        }) {
            return Err(ledger("successor reuses a retired identity, plan or proof"));
        }
    }

    if let [first, second] = preceding.as_slice()
        && (recompute_slot_zero_proof(request, first)? != first.proof_digest
            || recompute_slot_two_proof(request, first, second, &current)? != current.proof_digest)
    {
        return Err(ledger("third terminal proof does not bind the ordered attempt chain"));
    }

    Ok((current, retirement_ids))
}

fn parse_terminal_attempt(
    attempt: &MirrorAttempt,
    request: &PublicAttemptRequest,
) -> Result<PublicAttempt, PackCommitError> {
    if attempt.private_id.is_nil() || attempt.private_id == request.public_id || attempt.base_revision <= 0 {
        return Err(ledger("private attempt has an invalid identity or base revision"));
    }
    if !attempt.serving_bound || attempt.operation_issuer_id != Some(request.issuer_id) {
        return Err(ledger("private attempt differs from its serving producer binding or issuer"));
    }
    let plan_digest = parse_digest(&attempt.plan_digest, "stored private attempt plan digest is not canonical")?;
    let proof_digest = parse_digest(&attempt.proof_digest, "stored private attempt proof digest is not canonical")?;
    let stored_digest = attempt
        .operation_request_digest
        .as_deref()
        .ok_or_else(|| ledger("private attempt operation digest is missing"))?;
    if parse_digest(stored_digest, "stored private attempt operation digest is not canonical")? != plan_digest {
        return Err(ledger("private attempt operation digest differs from its plan"));
    }

    let lane = attempt
        .operation_lane
        .as_deref()
        .ok_or_else(|| ledger("private attempt lane is missing"))?
        .parse()
        .map_err(|_| ledger("private attempt lane is not canonical"))?;
    let sequence = attempt
        .operation_sequence
        .filter(|sequence| *sequence > 0)
        .ok_or_else(|| ledger("private attempt lacks a positive sequence"))?;
    let stored_state = attempt.operation_state.as_deref().ok_or_else(|| ledger("private attempt state is missing"))?;
    let state = parse_state(stored_state, "stored private attempt state is not recognized")?;
    if !matches!(state, OperationState::Committed | OperationState::Rejected) || !attempt.terminal_present {
        return Err(ledger("private attempt does not have a committed or rejected terminal"));
    }
    let (Some(event_id), Some(event_revision)) = (attempt.event_id, attempt.event_revision) else {
        return Err(ledger("private attempt terminal event evidence is missing"));
    };
    if event_id.is_nil() || !attempt.event_outcome_matches || !attempt.event_body_matches {
        return Err(ledger("private attempt event differs from its operation"));
    }
    validate_terminal_tombstone(attempt, state, "private attempt cancellation tombstone differs from its operation")?;

    Ok(PublicAttempt {
        slot: attempt.slot,
        private_id: attempt.private_id,
        plan_digest,
        proof_digest,
        base_revision: attempt.base_revision,
        lane,
        sequence,
        state,
        event_id: Some(event_id),
        event_revision: Some(event_revision),
    })
}

/// A terminal private attempt may have the immutable cancellation tombstone
/// that migration 138 permits on a terminal lane. That tombstone is accepted
/// only when both the ForOperation and issuer-lane lookups resolve to the same
/// exact repository/operation/issuer/lane/sequence/request-digest binding. No
/// tombstone is allowed on pending evidence, and a missing, mixed, stale or
/// otherwise divergent tombstone remains a ledger refusal.
fn validate_terminal_tombstone(
    attempt: &MirrorAttempt,
    state: OperationState,
    mismatch_detail: &'static str,
) -> Result<(), PackCommitError> {
    if attempt.tombstone_present {
        if !attempt.tombstone_matches_lane || !attempt.tombstone_exact_operation {
            return Err(ledger(mismatch_detail));
        }
        if state == OperationState::Pending {
            return Err(ledger("pending private attempt has a cancellation tombstone"));
        }
        return Ok(());
    }
    if !attempt.tombstone_absent {
        return Err(ledger("private attempt cancellation evidence differs from its operation lane"));
    }
    if state == OperationState::Cancelled {
        return Err(ledger("cancelled private attempt has no cancellation tombstone"));
    }
    Ok(())
}

/// The successor must use a checked later BIGINT sequence and the
/// retired event revision as its exact base. The base must itself be able to
/// advance by one for a committed terminal.
fn validate_successor_revision(
    retired_sequence: i64,
    retired_event_revision: i64,
    current_sequence: i64,
    current_base_revision: i64,
) -> Result<(), PackCommitError> {
    if retired_sequence <= 0 || retired_event_revision <= 0 {
        return Err(ledger("retired sequence or event revision is not positive"));
    }
    if current_sequence <= 0 || current_base_revision <= 0 {
        return Err(ledger("successor sequence or base revision is not positive"));
    }
    let minimum = retired_sequence.checked_add(1).ok_or_else(|| ledger("retired sequence cannot advance"))?;
    if current_sequence < minimum {
        return Err(ledger("successor sequence does not advance the retired attempt"));
    }
    if current_base_revision != retired_event_revision {
        return Err(ledger("successor base revision differs from the retired event"));
    }
    current_base_revision.checked_add(1).ok_or_else(|| ledger("successor base revision cannot advance"))?;
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
    slot: i16,
    state: OperationState,
    base_revision: i64,
    event_revision: i64,
    gate_revision: i64,
    payload: &Value,
) -> bool {
    (0..2).contains(&slot)
        && state == OperationState::Rejected
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
    retired_event_id: Option<Uuid>,
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
    use super::{
        MirrorAttempt, PublicAttemptRequest, is_revision_mismatch_rejection, parse_terminal_attempt,
        recompute_slot_two_proof, recompute_slot_zero_proof, retirement_candidate, validate_attempt_chain,
        validate_revision, validate_successor_revision, validate_terminal_tombstone,
    };
    use crate::ref_store::{
        CommitMode, GitObjectFormat, OperationState, RequestDigest, pg::slot_one::recompute_slot_one_proof,
    };
    use serde_json::json;
    use uuid::Uuid;

    fn mirror_attempt() -> MirrorAttempt {
        MirrorAttempt {
            slot: 1,
            private_id: Uuid::from_u128(1),
            plan_digest: String::new(),
            proof_digest: String::new(),
            base_revision: 1,
            serving_bound: true,
            operation_issuer_id: Some(Uuid::from_u128(2)),
            operation_lane: Some("lane".into()),
            operation_sequence: Some(2),
            operation_request_digest: Some(String::new()),
            operation_state: Some("rejected".into()),
            terminal_present: true,
            event_id: Some(Uuid::from_u128(3)),
            retired_event_id: None,
            event_revision: Some(2),
            event_outcome_matches: true,
            event_body_matches: true,
            tombstone_present: false,
            tombstone_absent: true,
            tombstone_matches_lane: false,
            tombstone_exact_operation: false,
            revision_mismatch_rejection: true,
        }
    }

    #[test]
    fn terminal_tombstones_require_exact_non_pending_binding() {
        let absent = mirror_attempt();
        assert!(validate_terminal_tombstone(&absent, OperationState::Rejected, "mismatch").is_ok());
        assert!(validate_terminal_tombstone(&absent, OperationState::Committed, "mismatch").is_ok());

        let exact = MirrorAttempt {
            tombstone_present: true,
            tombstone_absent: false,
            tombstone_matches_lane: true,
            tombstone_exact_operation: true,
            ..mirror_attempt()
        };
        assert!(validate_terminal_tombstone(&exact, OperationState::Rejected, "mismatch").is_ok());
        assert!(validate_terminal_tombstone(&exact, OperationState::Committed, "mismatch").is_ok());
        assert!(validate_terminal_tombstone(&exact, OperationState::Pending, "mismatch").is_err());

        let mixed = MirrorAttempt { tombstone_matches_lane: false, ..exact.clone() };
        assert!(validate_terminal_tombstone(&mixed, OperationState::Rejected, "mismatch").is_err());

        let wrong = MirrorAttempt { tombstone_exact_operation: false, ..exact };
        assert!(validate_terminal_tombstone(&wrong, OperationState::Rejected, "mismatch").is_err());

        let unreadable = MirrorAttempt { tombstone_absent: false, ..mirror_attempt() };
        assert!(validate_terminal_tombstone(&unreadable, OperationState::Rejected, "mismatch").is_err());
        assert!(validate_terminal_tombstone(&unreadable, OperationState::Cancelled, "mismatch").is_err());
    }

    #[test]
    fn committed_revision_is_exactly_base_plus_one_with_checked_overflow() {
        assert!(validate_revision(OperationState::Committed, 1, 2).is_ok());
        assert!(validate_revision(OperationState::Committed, 1, 1).is_err());
        assert!(validate_revision(OperationState::Committed, 1, 3).is_err());
        assert!(validate_revision(OperationState::Committed, i64::MAX, i64::MAX).is_err());
    }

    #[test]
    fn successor_advances_sequence_and_starts_at_the_exact_retired_revision() {
        assert!(validate_successor_revision(4, 7, 5, 7).is_ok());
        assert!(validate_successor_revision(4, 7, 9, 7).is_ok());
        assert!(validate_successor_revision(4, 7, 4, 7).is_err());
        assert!(validate_successor_revision(i64::MAX, 7, i64::MAX, 7).is_err());
        assert!(validate_successor_revision(4, 7, 5, 8).is_err());
        assert!(validate_successor_revision(4, i64::MAX, 5, i64::MAX).is_err());
        assert!(validate_successor_revision(0, 7, 1, 7).is_err());
        assert!(validate_successor_revision(4, 7, 5, 0).is_err());
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
        assert!(retirement_candidate(0, OperationState::Rejected, 3, 4, 4, &stale));
        assert!(retirement_candidate(1, OperationState::Rejected, 3, 4, 4, &stale));
        assert!(!retirement_candidate(2, OperationState::Rejected, 3, 4, 4, &stale));
        assert!(!retirement_candidate(1, OperationState::Rejected, 3, 4, 5, &stale));
        assert!(!retirement_candidate(1, OperationState::Rejected, 4, 4, 4, &stale));
        assert!(!retirement_candidate(1, OperationState::Committed, 3, 4, 4, &stale));

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
            assert!(!retirement_candidate(1, OperationState::Rejected, 3, 4, 4, payload));
        }
    }

    #[test]
    fn final_terminal_binds_both_normalized_retirements() {
        let request = PublicAttemptRequest {
            repository_id: Uuid::from_u128(10),
            admission_owner_id: Uuid::from_u128(11),
            issuer_id: Uuid::from_u128(2),
            public_id: Uuid::from_u128(12),
            wire_digest: RequestDigest::of("terminal-test-wire", &[b"original request"]),
            request_mode: CommitMode::AcceptedSubset,
            backend_identity: "a".repeat(64),
            object_format: GitObjectFormat::Sha1,
            history_incarnation: Uuid::from_u128(13),
            authority_epoch: 1,
            group_epoch: 1,
            restore_incarnation: Uuid::from_u128(14),
        };
        let mut rows = [0i16, 1, 2].map(|slot| {
            let event_id = Uuid::from_u128(90 + slot as u128);
            let plan = RequestDigest::of("terminal-test-plan", &[&slot.to_be_bytes()]).as_hex();
            MirrorAttempt {
                slot,
                private_id: Uuid::from_u128(20 + slot as u128),
                plan_digest: plan.clone(),
                proof_digest: RequestDigest::of("terminal-test-proof", &[&slot.to_be_bytes()]).as_hex(),
                base_revision: 6 + i64::from(slot),
                operation_sequence: Some(10 + i64::from(slot)),
                operation_request_digest: Some(plan),
                event_id: Some(event_id),
                event_revision: Some(7 + i64::from(slot)),
                retired_event_id: (slot < 2).then_some(event_id),
                ..mirror_attempt()
            }
        });
        let first = parse_terminal_attempt(&rows[0], &request).unwrap();
        rows[0].proof_digest = recompute_slot_zero_proof(&request, &first).unwrap().as_hex();
        let first = parse_terminal_attempt(&rows[0], &request).unwrap();
        let second = parse_terminal_attempt(&rows[1], &request).unwrap();
        rows[1].proof_digest = recompute_slot_one_proof(&request, &first, &second).unwrap().as_hex();
        let second = parse_terminal_attempt(&rows[1], &request).unwrap();
        let current = parse_terminal_attempt(&rows[2], &request).unwrap();
        rows[2].proof_digest = recompute_slot_two_proof(&request, &first, &second, &current).unwrap().as_hex();

        let (current, used_events) = validate_attempt_chain(&rows, 2, &request).unwrap();
        assert_eq!(current.slot, 2);
        assert_eq!(used_events, [Uuid::from_u128(90), Uuid::from_u128(91)]);

        let wrong_link =
            [rows[0].clone(), MirrorAttempt { retired_event_id: rows[0].event_id, ..rows[1].clone() }, rows[2].clone()];
        assert!(validate_attempt_chain(&wrong_link, 2, &request).is_err());

        let wrong_order = [rows[1].clone(), rows[0].clone(), rows[2].clone()];
        assert!(validate_attempt_chain(&wrong_order, 2, &request).is_err());

        rows[2].proof_digest = RequestDigest::of("terminal-test-proof", &[b"other context"]).as_hex();
        assert!(validate_attempt_chain(&rows, 2, &request).is_err());
    }
}
