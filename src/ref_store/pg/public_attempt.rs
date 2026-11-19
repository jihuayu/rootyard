//! Read-only resolution of migration 152's public operation and current private attempt.
//!
//! This is a crate-private lookup primitive for the future stock-Git serving
//! boundary. It is deliberately not a gateway cutover: nothing here publishes a
//! wrapper, allocates a sequence, claims a private UUID, writes a row or takes a
//! lock. The caller owns a read transaction with an absolute deadline; the
//! lookup adds only the ordinary statement/lock timeouts and never begins,
//! commits or rolls back a transaction.
//!
//! The typed caller supplies the exact public request identity already known at
//! the serving boundary: repository, public UUID, admission owner, issuer, wire
//! digest, request mode, backend identity, object format, history/authority/
//! group/restore incarnations. No private UUID is caller-controlled. The caller
//! owns authentication and authorization of that scope; this module proves that
//! the durable wrapper is exactly that scope, that it still belongs to the
//! current ready `pg_refstore` realm and cluster restore incarnation, and that
//! the current/retired attempt evidence is internally consistent.
//!
//! One statement reads the wrapper, both attempt candidates, the migration-138
//! operation, the migration-139 event, the migration-147 producer binding, the
//! cancellation tombstone and the current realm from one snapshot. The durable
//! terminal/event payload JSON never crosses into Rust: the SELECT projects the
//! same finite predicates migration 152's verifier evaluates (terminal present,
//! exact cancelled terminal, event outcome/body binding, revision-mismatch
//! retirement and tombstone key/exactness) as non-NULL booleans. A missing
//! migration 152 is reported separately as unsupported before any relation is
//! referenced. A wrapper from a stale realm, a false/unknown predicate, a
//! partially written attempt or a second current candidate is a fixed
//! ledger-integrity refusal, never a weaker replay.
//!
//! The result never returns a legacy operation or cancellation row: an
//! identifier that is privately claimed is a [`PublicAttemptLookup::PrivateIdentifier`]
//! marker, and a legacy-only identifier is a [`PublicAttemptLookup::LegacyPath`]
//! marker for the separately authorized legacy path. Terminal JSON is verified
//! against its event but is not re-exposed here; an authorized caller can read
//! the returned current private operation through the normal core reader.
//! Error values and the lookup types' `Debug` output are fixed/redacted rather
//! than carrying PostgreSQL text, IDs, digests or payload bodies.
//!
//! A current attempt must agree with its wrapper state. In particular, a slot
//! zero private rejection whose wrapper is still pending is refused closed
//! rather than returned as a final rejection; a committed/retired slot one is
//! returned only from the current slot after the slot-zero revision-mismatch
//! retirement has been proved.
use super::bound;
use crate::ref_store::{
    CommitMode, GitObjectFormat, IssuerLane, OperationState, PgRefStore, RefStoreError, RequestDigest,
    core::pack_commit::{PackCommitError, PackCommitRejectCode, PackCommitRejection},
};
use serde::Deserialize;
use serde_json::Value;
use std::fmt;
use tokio::time::{Instant, timeout_at};
use tokio_postgres::{Transaction, error::SqlState};
use uuid::Uuid;

/// Migration 152 is the compatibility probe, not a second authority. The
/// catalog/table/function checks keep an older or partial catalog an explicit
/// `Unsupported` result instead of preparing a statement whose objects do not
/// exist.
const SCHEMA_PROBE: &str = "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=152), \
        to_regclass('ref_store_public_operations') IS NOT NULL, \
        to_regclass('ref_store_private_attempts') IS NOT NULL, \
        to_regprocedure('rootyard_ref_store_attempt_has_binding(\
            ref_store_public_operations,ref_store_private_attempts)') IS NOT NULL";

/// One statement snapshot. The wrapper and attempt subqueries deliberately use
/// plain reads; the migration-152 binding predicate is a SQL `STABLE` function
/// so this adapter reuses the reviewed durable check instead of inventing a
/// second binding vocabulary.
///
/// Every projected predicate is a non-NULL boolean. The terminal/event payload
/// JSON stays inside PostgreSQL: it is compared with `IS [NOT] DISTINCT FROM`
/// only inside the finite booleans below. Required equalities are gated by
/// explicit presence predicates, so a missing event/terminal cannot become a
/// tautological NULL-equality success.
const SELECT_SNAPSHOT: &str = r#"
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
                   COALESCE(o.terminal_result =
                       '{"state":"cancelled","reason":"cancel_requested"}'::jsonb, false)
                       AS terminal_cancelled_exact,
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
                       AS tombstone_exact_operation,
                   COALESCE(e.event_id IS NOT NULL
                            AND e.payload#>>'{rejection,code}' = 'revision_mismatch'
                            AND e.payload->'registrations' = '[]'::jsonb, false)
                       AS revision_mismatch_rejection
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
    'private_occupied', EXISTS(
        SELECT 1 FROM ref_store_private_attempts p
         WHERE p.repository_id=$1 AND p.private_id=$2
    ),
    'legacy_operation', EXISTS(
        SELECT 1 FROM ref_store_operations o
         WHERE o.repository_id=$1 AND o.operation_id=$2
    ),
    'legacy_cancellation', EXISTS(
        SELECT 1 FROM ref_store_cancellations c
         WHERE c.repository_id=$1 AND c.operation_id=$2
    ),
    'realm_matches', COALESCE((
        SELECT (
            r.archived_at IS NULL AND r.deleted_at IS NULL
            AND (r.owner_id, r.object_format, r.state, r.storage_backend, r.transition_state)
                = (w.admission_owner_id, w.object_format, 'ready', 'pg_refstore', 'stable')
            AND (g.tenant_id, g.object_format, g.history_incarnation, g.authority_epoch, g.group_epoch)
                = (w.admission_owner_id, w.object_format, w.history_incarnation, w.authority_epoch, w.group_epoch)
            AND (s.owner_id, s.object_format, s.history_incarnation, s.authority_epoch, s.group_epoch)
                = (g.tenant_id, g.object_format, g.history_incarnation, g.authority_epoch, g.group_epoch)
            AND (p.tenant_id, p.object_format, p.history_incarnation, p.authority_epoch, p.group_epoch)
                = (g.tenant_id, g.object_format, g.history_incarnation, g.authority_epoch, g.group_epoch)
            AND s.state = 'ready' AND s.name = r.name AND p.decision_required
            AND s.backend_identity = w.backend_identity AND c.incarnation = w.restore_incarnation
        )
          FROM ref_store_public_operations w
          JOIN repositories r ON r.id = w.repository_id
          JOIN ref_store_core_gates g ON g.repository_id = w.repository_id
          JOIN ref_store_serving_repositories s ON s.repository_id = w.repository_id
          JOIN ref_store_core_protocol_repos p ON p.repository_id = w.repository_id
          JOIN public.cluster_authority c ON c.singleton
         WHERE w.repository_id = $1 AND w.public_id = $2
    ), false)
) AS snapshot
"#;

/// The exact public identity a serving caller already knows.
///
/// `public_id` is the stable public UUID. There is intentionally no private
/// identity, lane, sequence, event id or caller-supplied state: those are
/// durable evidence, never request inputs.
#[allow(dead_code)] // Crate-private foundation: the ignored tests and the future serving boundary consume it.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PublicAttemptRequest {
    pub repository_id: Uuid,
    pub admission_owner_id: Uuid,
    pub issuer_id: Uuid,
    pub public_id: Uuid,
    pub wire_digest: RequestDigest,
    pub request_mode: CommitMode,
    pub backend_identity: String,
    pub object_format: GitObjectFormat,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
    pub group_epoch: i64,
    pub restore_incarnation: Uuid,
}

impl PublicAttemptRequest {
    /// Validate the fixed request shape before any relation is referenced.
    pub(crate) fn validate(&self) -> Result<(), PackCommitError> {
        validate_request(self)
    }
}

impl fmt::Debug for PublicAttemptRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicAttemptRequest")
            .field("repository_id", &Redacted)
            .field("admission_owner_id", &Redacted)
            .field("issuer_id", &Redacted)
            .field("public_id", &Redacted)
            .field("wire_digest", &Redacted)
            .field("request_mode", &self.request_mode)
            .field("backend_identity", &Redacted)
            .field("object_format", &self.object_format)
            .field("history_incarnation", &Redacted)
            .field("authority_epoch", &self.authority_epoch)
            .field("group_epoch", &self.group_epoch)
            .field("restore_incarnation", &Redacted)
            .finish()
    }
}

/// Read-only routing answer. The two marker variants carry no legacy row,
/// digest, terminal, event or private identity.
#[allow(dead_code)] // Crate-private foundation: the ignored tests and the future serving boundary consume it.
#[derive(Clone, Eq, PartialEq)]
pub(crate) enum PublicAttemptLookup {
    /// No public wrapper, private claim or legacy operation/cancellation is
    /// visible for this repository-scoped identifier.
    Unknown,
    /// The identifier is a durable private attempt id. It must never be routed
    /// to the legacy public replay path.
    PrivateIdentifier,
    /// A legacy operation or cancellation exists without a public wrapper. The
    /// separately authorized legacy path may resolve it; this lookup returns no
    /// data from it.
    LegacyPath,
    Pending(PublicAttemptEvidence),
    Committed(PublicAttemptEvidence),
    Rejected(PublicAttemptEvidence),
    Cancelled(PublicAttemptEvidence),
}

impl fmt::Debug for PublicAttemptLookup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => formatter.write_str("Unknown"),
            Self::PrivateIdentifier => formatter.write_str("PrivateIdentifier"),
            Self::LegacyPath => formatter.write_str("LegacyPath"),
            Self::Pending(evidence) => formatter.debug_tuple("Pending").field(evidence).finish(),
            Self::Committed(evidence) => formatter.debug_tuple("Committed").field(evidence).finish(),
            Self::Rejected(evidence) => formatter.debug_tuple("Rejected").field(evidence).finish(),
            Self::Cancelled(evidence) => formatter.debug_tuple("Cancelled").field(evidence).finish(),
        }
    }
}

/// The durable current attempt plus, when current slot one is in use, the
/// already retired slot-zero evidence.
#[allow(dead_code)] // Crate-private foundation: the ignored tests and the future serving boundary consume it.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PublicAttemptEvidence {
    pub public_id: Uuid,
    pub current: PublicAttempt,
    pub retired: Option<PublicAttempt>,
}

impl fmt::Debug for PublicAttemptEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicAttemptEvidence")
            .field("public_id", &Redacted)
            .field("current", &self.current)
            .field("retired", &self.retired)
            .finish()
    }
}

/// One immutable private attempt candidate whose operation/binding/event and
/// optional tombstone were proved consistent in the same snapshot.
#[allow(dead_code)] // Crate-private foundation: the ignored tests and the future serving boundary consume it.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PublicAttempt {
    pub slot: i16,
    pub private_id: Uuid,
    pub plan_digest: RequestDigest,
    pub proof_digest: RequestDigest,
    pub base_revision: i64,
    pub lane: IssuerLane,
    pub sequence: i64,
    pub state: OperationState,
    pub event_id: Option<Uuid>,
    pub event_revision: Option<i64>,
}

impl fmt::Debug for PublicAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicAttempt")
            .field("slot", &self.slot)
            .field("private_id", &Redacted)
            .field("plan_digest", &Redacted)
            .field("proof_digest", &Redacted)
            .field("base_revision", &self.base_revision)
            .field("lane", &Redacted)
            .field("sequence", &self.sequence)
            .field("state", &self.state)
            .field("event_id", &self.event_id.map(|_| Redacted))
            .field("event_revision", &self.event_revision)
            .finish()
    }
}

impl PgRefStore {
    /// Take migration 152's normalized public/attempt advisory lock set before
    /// an authorized private-mode preflight reads a wrapper.
    ///
    /// The public UUID and the freshly proposed private UUID are both locked;
    /// for an existing wrapper the SQL function also locks every durable private
    /// attempt UUID. This is a lock-only step: it writes no row, allocates no
    /// sequence and never enters the legacy migration-138 guard. It must run in
    /// the same read-committed transaction as the subsequent authenticated
    /// public lookup.
    #[allow(dead_code)] // No route selects private mode until the read paths are ready.
    pub(crate) async fn lock_public_attempt(
        &self,
        tx: &Transaction<'_>,
        request: &PublicAttemptRequest,
        proposed_private_id: Uuid,
        deadline: Instant,
    ) -> Result<(), PackCommitError> {
        request.validate()?;
        if proposed_private_id.is_nil() || proposed_private_id == request.public_id {
            return Err(PackCommitError::Invalid("proposed private attempt id must be non-nil and distinct"));
        }
        match timeout_at(deadline, async {
            bound(tx, deadline).await.map_err(PackCommitError::from)?;
            ensure_schema(tx).await?;
            tx.query_one(
                "SELECT rootyard_ref_store_lock_public_operation($1,$2,$3)",
                &[&request.repository_id, &request.public_id, &proposed_private_id],
            )
            .await
            .map_err(lookup_db_error)
            .map_err(PackCommitError::from)?;
            Ok(())
        })
        .await
        {
            Ok(result) => result,
            Err(_) => Err(PackCommitError::from(RefStoreError::Timeout)),
        }
    }

    /// Resolve one exact public attempt inside the caller-owned read transaction.
    ///
    /// The absolute deadline bounds the whole lookup; [`bound`] additionally
    /// installs the existing per-statement/lock timeout. The method performs no
    /// writes, row locks, sequence allocation, retries, Blob/Git IO or nested
    /// connection checkout. It must be called with a transaction the caller
    /// treats as read-only; it never ends that transaction. Database/protocol
    /// failures are collapsed to a fixed error, never raw PostgreSQL text.
    #[allow(dead_code)] // No production caller until the wrapper entry is deliberately opened.
    pub(crate) async fn lookup_public_attempt(
        &self,
        tx: &Transaction<'_>,
        request: &PublicAttemptRequest,
        deadline: Instant,
    ) -> Result<PublicAttemptLookup, PackCommitError> {
        request.validate()?;
        match timeout_at(deadline, self.lookup_public_attempt_checked(tx, request, deadline)).await {
            Ok(result) => result,
            Err(_) => Err(PackCommitError::from(RefStoreError::Timeout)),
        }
    }

    async fn lookup_public_attempt_checked(
        &self,
        tx: &Transaction<'_>,
        request: &PublicAttemptRequest,
        deadline: Instant,
    ) -> Result<PublicAttemptLookup, PackCommitError> {
        // The schema probe has its own statement/lock budget.
        bound(tx, deadline).await.map_err(|error| {
            PackCommitError::from(match error {
                RefStoreError::Timeout => RefStoreError::Timeout,
                _ => RefStoreError::Database("public attempt lookup database error".into()),
            })
        })?;

        ensure_schema(tx).await?;

        // PostgreSQL applies statement_timeout per statement. The schema probe
        // may have consumed its own budget, so refresh the same absolute
        // deadline immediately before the one snapshot query.
        bound(tx, deadline).await.map_err(|error| {
            PackCommitError::from(match error {
                RefStoreError::Timeout => RefStoreError::Timeout,
                _ => RefStoreError::Database("public attempt lookup database error".into()),
            })
        })?;

        let row = tx
            .query_one(SELECT_SNAPSHOT, &[&request.repository_id, &request.public_id])
            .await
            .map_err(lookup_db_error)
            .map_err(PackCommitError::from)?;
        let snapshot: Value = row.get(0);
        let snapshot = serde_json::from_value::<RawSnapshot>(snapshot)
            .map_err(|_| ledger("public attempt lookup snapshot shape is not recognized"))?;
        evaluate(snapshot, request)
    }
}

/// Shared catalog probe for the lock and read adapters. A missing or partial
/// migration 152 is an explicit unsupported outcome before any relation or SQL
/// function is referenced.
async fn ensure_schema(tx: &Transaction<'_>) -> Result<(), PackCommitError> {
    let schema = tx.query_one(SCHEMA_PROBE, &[]).await.map_err(lookup_db_error).map_err(PackCommitError::from)?;
    if !schema.get::<_, bool>(0) || !schema.get::<_, bool>(1) || !schema.get::<_, bool>(2) || !schema.get::<_, bool>(3)
    {
        return Err(PackCommitError::from(RefStoreError::Unsupported("public attempt lookup requires migration 152")));
    }
    Ok(())
}

fn validate_request(request: &PublicAttemptRequest) -> Result<(), PackCommitError> {
    if request.repository_id.is_nil()
        || request.admission_owner_id.is_nil()
        || request.issuer_id.is_nil()
        || request.public_id.is_nil()
        || request.history_incarnation.is_nil()
        || request.restore_incarnation.is_nil()
    {
        return Err(PackCommitError::Invalid("public attempt lookup ids must be non-nil"));
    }
    if !is_canonical_hex_64(&request.backend_identity) {
        return Err(PackCommitError::Invalid("public attempt lookup backend identity must be 64 lowercase hex"));
    }
    if request.authority_epoch <= 0 || request.group_epoch <= 0 {
        return Err(PackCommitError::Invalid("public attempt lookup epochs must be positive"));
    }
    Ok(())
}

fn evaluate(snapshot: RawSnapshot, request: &PublicAttemptRequest) -> Result<PublicAttemptLookup, PackCommitError> {
    validate_request(request)?;
    let Some(wrapper) = snapshot.wrapper else {
        if snapshot.private_occupied {
            return Ok(PublicAttemptLookup::PrivateIdentifier);
        }
        if snapshot.legacy_operation || snapshot.legacy_cancellation {
            return Ok(PublicAttemptLookup::LegacyPath);
        }
        return Ok(PublicAttemptLookup::Unknown);
    };

    if snapshot.private_occupied {
        return Err(ledger("public operation identifier is also a private attempt identifier"));
    }
    if snapshot.legacy_operation || snapshot.legacy_cancellation {
        return Err(ledger("public operation identifier is also claimed by the legacy operation registry"));
    }

    let state = validate_wrapper(&wrapper, request)?;
    if !snapshot.realm_matches {
        return Err(stale_realm());
    }

    if wrapper.current_slot != 0 && wrapper.current_slot != 1 {
        return Err(ledger("public operation current slot is not zero or one"));
    }
    if (wrapper.current_slot == 1) != wrapper.retired_event_id.is_some() {
        return Err(ledger("public operation retired event evidence differs from its current slot"));
    }
    if wrapper.event_id.is_some() && wrapper.event_id == wrapper.retired_event_id {
        return Err(ledger("public operation current and retired events are the same"));
    }

    let mut slot_zero = None;
    let mut slot_one = None;
    for attempt in &snapshot.attempts {
        let slot = match attempt.slot {
            0 => &mut slot_zero,
            1 => &mut slot_one,
            _ => return Err(ledger("public operation has an attempt outside slot zero or one")),
        };
        if slot.replace(attempt).is_some() {
            return Err(ledger("public operation has multiple attempts in one slot"));
        }
    }

    let (current_raw, retired_raw) = if wrapper.current_slot == 0 {
        if slot_one.is_some() {
            return Err(ledger("public operation slot one exists while slot zero is current"));
        }
        (slot_zero.ok_or_else(|| ledger("public operation current attempt is missing"))?, None)
    } else {
        (
            slot_one.ok_or_else(|| ledger("public operation current slot one attempt is missing"))?,
            Some(slot_zero.ok_or_else(|| ledger("public operation retired slot zero attempt is missing"))?),
        )
    };

    let current_facts = validate_attempt(current_raw, &wrapper)?;
    validate_current(&wrapper, state, &current_facts)?;

    let retired_facts = match retired_raw {
        Some(retired_raw) => {
            let facts = validate_attempt(retired_raw, &wrapper)?;
            validate_retired(&wrapper, &facts)?;
            if facts.private_id == current_facts.private_id {
                return Err(ledger("public operation attempts share one private identifier"));
            }
            Some(facts)
        }
        None => None,
    };

    let evidence = PublicAttemptEvidence {
        public_id: wrapper.public_id,
        current: public_attempt(current_facts),
        retired: retired_facts.map(public_attempt),
    };
    match state {
        OperationState::Pending => Ok(PublicAttemptLookup::Pending(evidence)),
        OperationState::Committed => Ok(PublicAttemptLookup::Committed(evidence)),
        OperationState::Rejected => Ok(PublicAttemptLookup::Rejected(evidence)),
        OperationState::Cancelled => Ok(PublicAttemptLookup::Cancelled(evidence)),
    }
}

pub(super) fn validate_wrapper(
    wrapper: &RawWrapper,
    request: &PublicAttemptRequest,
) -> Result<OperationState, PackCommitError> {
    let stored_wire = parse_digest(&wrapper.wire_digest, "stored public operation wire digest is not canonical")?;
    let stored_mode = parse_mode(&wrapper.request_mode, "stored public operation request mode is not recognized")?;
    let stored_format =
        parse_format(&wrapper.object_format, "stored public operation object format is not recognized")?;
    if !is_canonical_hex_64(&wrapper.backend_identity) {
        return Err(ledger("stored public operation backend identity is not canonical hex"));
    }

    if wrapper.repository_id != request.repository_id || wrapper.public_id != request.public_id {
        return Err(PackCommitError::from(RefStoreError::IdentityConflict));
    }
    if stored_wire != request.wire_digest {
        return Err(PackCommitError::from(RefStoreError::DigestConflict));
    }
    if wrapper.admission_owner_id != request.admission_owner_id
        || wrapper.issuer_id != request.issuer_id
        || wrapper.backend_identity != request.backend_identity
        || stored_mode != request.request_mode
        || stored_format != request.object_format
        || wrapper.history_incarnation != request.history_incarnation
        || wrapper.authority_epoch != request.authority_epoch
        || wrapper.group_epoch != request.group_epoch
        || wrapper.restore_incarnation != request.restore_incarnation
    {
        return Err(PackCommitError::from(RefStoreError::IdentityConflict));
    }

    if wrapper.admission_owner_id.is_nil()
        || wrapper.issuer_id.is_nil()
        || wrapper.history_incarnation.is_nil()
        || wrapper.restore_incarnation.is_nil()
        || wrapper.authority_epoch <= 0
        || wrapper.group_epoch <= 0
    {
        return Err(ledger("public operation identity contains an invalid nil or epoch value"));
    }
    if wrapper.current_slot != 0 && wrapper.current_slot != 1 {
        return Err(ledger("public operation current slot is not zero or one"));
    }
    if wrapper.event_id.is_some_and(|id| id.is_nil())
        || wrapper.retired_event_id.is_some_and(|id| id.is_nil())
        || wrapper.cancelled_private_id.is_some_and(|id| id.is_nil())
    {
        return Err(ledger("public operation has a nil event or cancellation identity"));
    }

    let state = parse_state(&wrapper.state, "stored public operation state is not recognized")?;
    let has_current_event = matches!(state, OperationState::Committed | OperationState::Rejected);
    if has_current_event != wrapper.event_id.is_some() {
        return Err(ledger("public operation state and current event disagree"));
    }
    if (state == OperationState::Cancelled) != wrapper.cancelled_private_id.is_some() {
        return Err(ledger("public operation cancellation state and private identity disagree"));
    }
    if wrapper.event_id == wrapper.retired_event_id && wrapper.event_id.is_some() {
        return Err(ledger("public operation current and retired events are the same"));
    }

    Ok(state)
}

struct AttemptFacts {
    slot: i16,
    private_id: Uuid,
    plan_digest: RequestDigest,
    proof_digest: RequestDigest,
    base_revision: i64,
    lane: IssuerLane,
    sequence: i64,
    state: OperationState,
    event_id: Option<Uuid>,
    event_revision: Option<i64>,
    revision_mismatch_rejection: bool,
}

fn validate_attempt(attempt: &RawAttempt, wrapper: &RawWrapper) -> Result<AttemptFacts, PackCommitError> {
    if attempt.slot != 0 && attempt.slot != 1 {
        return Err(ledger("private attempt slot is not zero or one"));
    }
    if attempt.private_id.is_nil() || attempt.private_id == wrapper.public_id {
        return Err(ledger("private attempt identity aliases the public identifier"));
    }
    let plan_digest = parse_digest(&attempt.plan_digest, "stored private attempt plan digest is not canonical")?;
    let proof_digest = parse_digest(&attempt.proof_digest, "stored private attempt proof digest is not canonical")?;
    if attempt.base_revision <= 0 {
        return Err(ledger("stored private attempt base revision is not positive"));
    }
    if !attempt.serving_bound {
        return Err(ledger("private attempt serving producer binding differs"));
    }

    let operation_issuer =
        attempt.operation_issuer_id.ok_or_else(|| ledger("private attempt migration-138 operation is missing"))?;
    if operation_issuer != wrapper.issuer_id {
        return Err(ledger("private attempt operation issuer differs from its wrapper"));
    }
    let lane_value =
        attempt.operation_lane.as_deref().ok_or_else(|| ledger("private attempt operation lane is missing"))?;
    let lane: IssuerLane =
        lane_value.parse().map_err(|_| ledger("stored private attempt operation lane is not canonical"))?;
    let sequence = attempt.operation_sequence.ok_or_else(|| ledger("private attempt operation sequence is missing"))?;
    if sequence <= 0 {
        return Err(ledger("stored private attempt operation sequence is not positive"));
    }
    let operation_digest = parse_digest(
        attempt
            .operation_request_digest
            .as_deref()
            .ok_or_else(|| ledger("private attempt operation request digest is missing"))?,
        "stored private attempt operation digest is not canonical",
    )?;
    if operation_digest != plan_digest {
        return Err(ledger("private attempt operation digest differs from its plan digest"));
    }
    let state = parse_state(
        attempt.operation_state.as_deref().ok_or_else(|| ledger("private attempt operation state is missing"))?,
        "stored private attempt operation state is not recognized",
    )?;

    match state {
        OperationState::Pending => {
            if attempt.terminal_present {
                return Err(ledger("pending private attempt carries a terminal result"));
            }
        }
        OperationState::Committed | OperationState::Rejected => {
            if !attempt.terminal_present {
                return Err(ledger("terminal private attempt has no terminal result"));
            }
        }
        OperationState::Cancelled => {
            if !attempt.terminal_present || !attempt.terminal_cancelled_exact {
                return Err(ledger("cancelled private attempt does not carry the exact cancel terminal"));
            }
        }
    }

    validate_tombstone(attempt, state)?;
    validate_event(attempt, state)?;

    Ok(AttemptFacts {
        slot: attempt.slot,
        private_id: attempt.private_id,
        plan_digest,
        proof_digest,
        base_revision: attempt.base_revision,
        lane,
        sequence,
        state,
        event_id: attempt.event_id,
        event_revision: attempt.event_revision,
        revision_mismatch_rejection: attempt.revision_mismatch_rejection,
    })
}

fn validate_tombstone(attempt: &RawAttempt, state: OperationState) -> Result<(), PackCommitError> {
    if attempt.tombstone_present {
        if !attempt.tombstone_matches_lane || !attempt.tombstone_exact_operation {
            return Err(ledger("private attempt cancellation tombstone differs from its operation"));
        }
        if state == OperationState::Pending {
            return Err(ledger("pending private attempt has a cancellation tombstone"));
        }
    } else {
        if !attempt.tombstone_absent {
            return Err(ledger("private attempt cancellation tombstone differs from its operation lane key"));
        }
        if state == OperationState::Cancelled {
            return Err(ledger("cancelled private attempt has no cancellation tombstone"));
        }
    }
    Ok(())
}

fn validate_event(attempt: &RawAttempt, state: OperationState) -> Result<(), PackCommitError> {
    let Some(event_id) = attempt.event_id else {
        if attempt.event_revision.is_some() {
            return Err(ledger("private attempt event evidence is partial"));
        }
        return Ok(());
    };

    if event_id.is_nil() {
        return Err(ledger("private attempt event identity is nil"));
    }
    let revision = attempt.event_revision.ok_or_else(|| ledger("private attempt event revision is missing"))?;
    if revision < 0 {
        return Err(ledger("private attempt event revision is negative"));
    }
    if !matches!(state, OperationState::Committed | OperationState::Rejected) {
        return Err(ledger("private attempt event state is not committed or rejected"));
    }
    if !attempt.event_outcome_matches || !attempt.event_body_matches {
        return Err(ledger("private attempt event evidence differs from its operation"));
    }
    Ok(())
}

fn validate_current(
    wrapper: &RawWrapper,
    state: OperationState,
    current: &AttemptFacts,
) -> Result<(), PackCommitError> {
    if current.slot != wrapper.current_slot || current.state != state {
        return Err(ledger("current private attempt state differs from its public operation"));
    }
    match state {
        OperationState::Pending => {
            if wrapper.event_id.is_some() || current.event_id.is_some() {
                return Err(ledger("pending public operation carries event evidence"));
            }
        }
        OperationState::Committed | OperationState::Rejected => {
            if wrapper.event_id.is_none() || current.event_id != wrapper.event_id {
                return Err(ledger("terminal public operation event differs from its current attempt"));
            }
        }
        OperationState::Cancelled => {
            if wrapper.event_id.is_some()
                || current.event_id.is_some()
                || wrapper.cancelled_private_id != Some(current.private_id)
            {
                return Err(ledger("cancelled public operation does not name its current private attempt"));
            }
        }
    }
    Ok(())
}

fn validate_retired(wrapper: &RawWrapper, retired: &AttemptFacts) -> Result<(), PackCommitError> {
    if retired.slot != 0 || retired.state != OperationState::Rejected {
        return Err(ledger("retired public attempt is not a slot-zero rejection"));
    }
    if wrapper.retired_event_id.is_none() || retired.event_id != wrapper.retired_event_id {
        return Err(ledger("retired public attempt event differs from its public operation"));
    }
    let revision = retired.event_revision.ok_or_else(|| ledger("retired public attempt event revision is missing"))?;
    if revision <= retired.base_revision {
        return Err(ledger("retired public attempt did not observe an advanced gate"));
    }
    if !retired.revision_mismatch_rejection {
        return Err(ledger("retired public attempt is not the exact revision-mismatch rejection"));
    }
    Ok(())
}

fn public_attempt(facts: AttemptFacts) -> PublicAttempt {
    PublicAttempt {
        slot: facts.slot,
        private_id: facts.private_id,
        plan_digest: facts.plan_digest,
        proof_digest: facts.proof_digest,
        base_revision: facts.base_revision,
        lane: facts.lane,
        sequence: facts.sequence,
        state: facts.state,
        event_id: facts.event_id,
        event_revision: facts.event_revision,
    }
}

pub(super) fn parse_digest(value: &str, detail: &'static str) -> Result<RequestDigest, PackCommitError> {
    value.parse().map_err(|_| ledger(detail))
}

pub(super) fn parse_state(value: &str, detail: &'static str) -> Result<OperationState, PackCommitError> {
    OperationState::parse(value).ok_or_else(|| ledger(detail))
}

pub(super) fn parse_mode(value: &str, detail: &'static str) -> Result<CommitMode, PackCommitError> {
    match value {
        "atomic" => Ok(CommitMode::Atomic),
        "accepted_subset" => Ok(CommitMode::AcceptedSubset),
        _ => Err(ledger(detail)),
    }
}

pub(super) fn parse_format(value: &str, detail: &'static str) -> Result<GitObjectFormat, PackCommitError> {
    GitObjectFormat::parse(value).map_err(|_| ledger(detail))
}

pub(super) fn is_canonical_hex_64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn ledger(detail: &'static str) -> PackCommitError {
    PackCommitError::Rejected(PackCommitRejection::new(PackCommitRejectCode::LedgerIntegrity, detail))
}

pub(super) fn stale_realm() -> PackCommitError {
    ledger("public operation wrapper does not belong to the current repository realm")
}

fn lookup_db_error(error: tokio_postgres::Error) -> RefStoreError {
    match error.code() {
        Some(code) if *code == SqlState::QUERY_CANCELED || *code == SqlState::LOCK_NOT_AVAILABLE => {
            RefStoreError::Timeout
        }
        _ => RefStoreError::Database("public attempt lookup database error".into()),
    }
}

pub(super) struct Redacted;

impl fmt::Debug for Redacted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

#[derive(Clone, Deserialize)]
struct RawSnapshot {
    wrapper: Option<RawWrapper>,
    #[serde(default)]
    attempts: Vec<RawAttempt>,
    private_occupied: bool,
    legacy_operation: bool,
    legacy_cancellation: bool,
    realm_matches: bool,
}

impl RawWrapper {
    pub(super) fn current_slot(&self) -> i16 {
        self.current_slot
    }

    pub(super) fn event_id(&self) -> Option<Uuid> {
        self.event_id
    }

    pub(super) fn retired_event_id(&self) -> Option<Uuid> {
        self.retired_event_id
    }

    pub(super) fn cancelled_private_id(&self) -> Option<Uuid> {
        self.cancelled_private_id
    }
}

#[derive(Clone, Deserialize)]
pub(super) struct RawWrapper {
    repository_id: Uuid,
    public_id: Uuid,
    admission_owner_id: Uuid,
    issuer_id: Uuid,
    wire_digest: String,
    request_mode: String,
    backend_identity: String,
    object_format: String,
    history_incarnation: Uuid,
    authority_epoch: i64,
    group_epoch: i64,
    restore_incarnation: Uuid,
    current_slot: i16,
    state: String,
    event_id: Option<Uuid>,
    retired_event_id: Option<Uuid>,
    cancelled_private_id: Option<Uuid>,
}

#[derive(Clone, Deserialize)]
struct RawAttempt {
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
    terminal_cancelled_exact: bool,
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

#[cfg(test)]
mod tests;
