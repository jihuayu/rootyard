//! Read-only resolution of migration 152's public operation and current private attempt.
//!
//! The gateway uses this crate-private lookup to inspect existing public
//! operations before admission or rotation. It takes no lock and does not write. The caller owns a read transaction with an absolute deadline; the
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
//! One statement reads the wrapper, its ordered attempts and retirement events, the migration-138
//! operation, the migration-139 event, the migration-147 producer binding, the
//! cancellation tombstone and the current realm from one snapshot. The
//! request-aware SELECT projects the same finite predicates migration 152's
//! verifier evaluates (terminal present, exact cancelled terminal, event
//! outcome/body binding, revision-mismatch retirement and tombstone
//! key/exactness) as non-NULL booleans and transfers no terminal body. The
//! GET-only status SELECT adds only the current attempt's terminal body from
//! that same snapshot. A missing migration 152 is reported separately as
//! unsupported before any relation is referenced. A wrapper from a stale realm,
//! a false/unknown predicate, a partially written attempt or a second current
//! candidate is a fixed ledger-integrity refusal, never a weaker replay.
//!
//! The result never returns a legacy operation or cancellation row: an
//! identifier that is privately claimed is a [`PublicAttemptLookup::PrivateIdentifier`]
//! marker, and a legacy-only identifier is a [`PublicAttemptLookup::LegacyPath`]
//! marker for the separately authorized legacy path. The request-aware lookup
//! does not re-expose terminal JSON; the status lookup projects only a bounded,
//! typed, canonical current terminal and never a private id, input binding,
//! retired terminal or arbitrary field. Error values and the lookup types'
//! `Debug` output are fixed/redacted rather than carrying PostgreSQL text, IDs,
//! digests or payload bodies.
//!
//! A current attempt must agree with its wrapper state. In particular, a
//! private rejection whose wrapper is still pending is refused closed
//! rather than returned as a final rejection. Later slots require the full
//! ordered prefix of exact revision-mismatch retirements.
//!
//! [`PgRefStore::lookup_public_operation_status`] is the separate GET-side
//! contract. A GET knows only the repository and public UUID, so the status
//! request carries no wire digest, mode, backend or private identity and never
//! synthesizes a push request. It reuses the same bounded schema probe, one
//! snapshot, realm/attempt/terminal verification and fixed error mapping as the
//! request-aware lookup. The stored immutable digest/mode are parsed only as
//! durable evidence; `rootyard_ref_store_attempt_has_binding` continues to
//! prove each attempt against that stored digest. The status result exposes
//! only the public id and current [`OperationState`], never a private id or raw
//! terminal JSON. The caller must present an already-resolved live-issuer or
//! repository-admin authorization marker before state data is returned; a
//! mismatching live issuer is a data-free refusal.
use super::bound;
use crate::ref_store::{
    CommitMode, GitObjectFormat, IssuerLane, OperationState, PgRefStore, RefStoreError, RequestDigest,
    core::{
        pack_commit::{PackCommitError, PackCommitPlan, PackCommitRejectCode, PackCommitRejection},
        pack_snapshot::lock_cluster_incarnation,
    },
};
use serde::Deserialize;
use serde_json::Value;
use std::fmt;
use tokio::time::{Instant, timeout_at};
use tokio_postgres::{GenericClient, Transaction, error::SqlState, types::ToSql};
use uuid::Uuid;

mod status_terminal;
use status_terminal::{SELECT_STATUS_SNAPSHOT, STATUS_TERMINAL_TRANSPORT_BOUND_BYTES, project_terminal};

/// Migration 152 is the compatibility probe, not a second authority. The
/// catalog/table/function checks keep an older or partial catalog an explicit
/// `Unsupported` result instead of preparing a statement whose objects do not
/// exist.
pub(super) const SCHEMA_PROBE: &str = "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=152), \
        to_regclass('ref_store_public_operations') IS NOT NULL, \
        to_regclass('ref_store_private_attempts') IS NOT NULL, \
        to_regprocedure('rootyard_ref_store_attempt_has_binding(\
            ref_store_public_operations,ref_store_private_attempts)') IS NOT NULL, \
        to_regclass('ref_store_attempt_retirements') IS NOT NULL";

/// The exact schema refusal that a GET adapter may consider for a *proven*
/// pre-migration-152 catalog. Any other `Unsupported` value stays a typed
/// refusal and is never treated as a legacy fallback.
pub(crate) const PUBLIC_ATTEMPT_SCHEMA_REQUIRED: &str = "public attempt lookup requires migration 152";

/// Admission used the archive's original incarnation. Replay uses that
/// immutable value for attempt proofs and proves reachability from live.
#[derive(Clone, Copy)]
pub(crate) struct PublicReplayRestore {
    pub(crate) original: Uuid,
    pub(crate) live: Uuid,
}

pub(crate) async fn prove_historical_public_scope(
    client: &(impl GenericClient + Sync),
    repository_id: Uuid,
    public_id: Uuid,
    restore: PublicReplayRestore,
    deadline: Instant,
) -> Result<bool, PackCommitError> {
    let row = timeout_at(
        deadline,
        client.query_opt(
            "WITH RECURSIVE ancestors(incarnation) AS (
             SELECT $4::uuid
             UNION
             SELECT l.source_incarnation FROM ref_store_restore_lineage l
             JOIN ancestors a ON a.incarnation=l.target_incarnation
         )
         SELECT rootyard_ref_store_attempt_current_scope(
             jsonb_populate_record(w, jsonb_build_object('restore_incarnation', $4::uuid))
         )
         FROM ref_store_public_operations w
         WHERE (w.repository_id,w.public_id,w.restore_incarnation)=($1,$2,$3)
           AND w.state IN ('committed','rejected','cancelled')
           AND $3::uuid<>$4::uuid AND EXISTS (SELECT FROM ancestors WHERE incarnation=$3)",
            &[&repository_id, &public_id, &restore.original, &restore.live],
        ),
    )
    .await
    .map_err(|_| PackCommitError::from(RefStoreError::Timeout))?
    .map_err(|error| match error.code() {
        Some(&SqlState::CHECK_VIOLATION) => stale_realm(),
        _ => PackCommitError::from(lookup_db_error(error)),
    })?;
    Ok(row.is_some_and(|row| row.get::<_, i64>(0) > 0))
}

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
                   COALESCE(o.terminal_result =
                       '{"state":"cancelled","reason":"cancel_requested"}'::jsonb, false)
                       AS terminal_cancelled_exact,
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
              LEFT JOIN ref_store_attempt_retirements r
                ON (r.repository_id,r.public_id,r.slot)=(a.repository_id,a.public_id,a.slot)
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

/// Finish-side read of one public wrapper. Unlike [`PublicAttemptLookup`], this
/// permits the narrow crash window where the exact private attempt is already
/// terminal while the public wrapper is still pending: the terminal mirror has
/// not yet published it. The marker is not a final Git result and carries no
/// terminal body, so a caller must ask the mirror to derive the owned
/// disposition before it may ACK anything.
#[allow(dead_code)] // The private finish path is activation-safe until the serving cutover.
#[allow(clippy::large_enum_variant)] // One exact evidence value, not a hot compact route.
#[derive(Clone)]
pub(crate) enum PublicAttemptFinishLookup {
    Unknown,
    PrivateIdentifier,
    LegacyPath,
    Evidence(PublicAttemptFinishEvidence),
}

impl fmt::Debug for PublicAttemptFinishLookup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => formatter.write_str("Unknown"),
            Self::PrivateIdentifier => formatter.write_str("PrivateIdentifier"),
            Self::LegacyPath => formatter.write_str("LegacyPath"),
            Self::Evidence(evidence) => formatter.debug_tuple("Evidence").field(evidence).finish(),
        }
    }
}

/// The exact current/retired evidence plus the public wrapper state that owns
/// it. `wrapper_state == Pending` with a terminal current attempt is the
/// finishable crash window; every other combination is the ordinary resolved
/// state and still has to pass the same attempt/event/binding proof.
#[allow(dead_code)] // The private finish path is activation-safe until the serving cutover.
#[derive(Clone)]
pub(crate) struct PublicAttemptFinishEvidence {
    pub evidence: PublicAttemptEvidence,
    pub wrapper_state: OperationState,
}

impl fmt::Debug for PublicAttemptFinishEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicAttemptFinishEvidence")
            .field("evidence", &self.evidence)
            .field("wrapper_state", &self.wrapper_state)
            .finish()
    }
}

/// The authorization scope the caller has already resolved before asking for a
/// public operation status. This module does not authenticate a token or query
/// repository roles; it only refuses to return state unless the caller states
/// that one of these prechecks succeeded and, for a live issuer, that the exact
/// durable issuer is the authenticated actor.
#[allow(dead_code)] // Crate-private foundation: the future gateway GET consumes it.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum PublicOperationReadAuthorization {
    /// The caller authenticated this live issuer and it is the durable issuer
    /// of the public operation.
    LiveIssuer { issuer_id: Uuid },
    /// The caller resolved the current repository-admin policy in its own
    /// already-authorized read transaction. Read access alone is insufficient.
    RepositoryAdmin,
}

impl fmt::Debug for PublicOperationReadAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LiveIssuer { .. } => formatter.write_str("LiveIssuer"),
            Self::RepositoryAdmin => formatter.write_str("RepositoryAdmin"),
        }
    }
}

/// The exact GET-side request: repository plus public operation id, with no
/// push wire digest, request mode, backend, private id, lane or sequence.
/// Supplying one of those values would guess at restart evidence rather than
/// verify the immutable durable row.
#[allow(dead_code)] // Crate-private foundation: the future gateway GET consumes it.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct PublicOperationStatusRequest {
    pub repository_id: Uuid,
    pub public_id: Uuid,
    pub authorization: PublicOperationReadAuthorization,
}

impl PublicOperationStatusRequest {
    /// Validate only the fixed GET shape before any relation is referenced.
    pub(crate) fn validate(&self) -> Result<(), PackCommitError> {
        validate_status_request(self)
    }
}

impl fmt::Debug for PublicOperationStatusRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicOperationStatusRequest")
            .field("repository_id", &Redacted)
            .field("public_id", &Redacted)
            .field("authorization", &self.authorization)
            .finish()
    }
}

/// The data a future GET may return. This omits every private attempt field and
/// keeps the terminal body private so it can only leave through a redacted
/// accessor. `Pending` has no terminal; a terminal value is the exact bounded
/// typed projection already checked against the current event and wrapper.
#[allow(dead_code)] // Crate-private foundation: the future gateway GET consumes it.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PublicOperationStatus {
    pub public_id: Uuid,
    /// Current wrapper state. `Pending` means the outcome is still unknown;
    /// terminal variants have already passed the event-body checks.
    pub state: OperationState,
    terminal: Option<Value>,
}

impl PublicOperationStatus {
    /// The bounded, verified terminal body for a future GET view. Pending is
    /// `None`; a terminal state is already canonical and contains no private
    /// attempt, input binding, raw digest or arbitrary extra field.
    pub(crate) fn terminal(&self) -> Option<&Value> {
        self.terminal.as_ref()
    }
}

impl fmt::Debug for PublicOperationStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublicOperationStatus")
            .field("public_id", &Redacted)
            .field("state", &self.state)
            .field("terminal", &self.terminal.as_ref().map(|_| Redacted))
            .finish()
    }
}

/// Read-only GET-side routing answer. The marker variants carry no row, digest,
/// terminal, event, issuer or private identity.
#[allow(dead_code)] // Crate-private foundation: the future gateway GET consumes it.
#[derive(Clone, Eq, PartialEq)]
pub(crate) enum PublicOperationStatusLookup {
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
    /// The supplied authorization is not the durable live issuer and no
    /// repository-admin precheck was asserted. No state data is returned.
    Forbidden,
    /// The current public wrapper, verified in one snapshot.
    Found(PublicOperationStatus),
}

impl fmt::Debug for PublicOperationStatusLookup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => formatter.write_str("Unknown"),
            Self::PrivateIdentifier => formatter.write_str("PrivateIdentifier"),
            Self::LegacyPath => formatter.write_str("LegacyPath"),
            Self::Forbidden => formatter.write_str("Forbidden"),
            Self::Found(status) => formatter.debug_tuple("Found").field(status).finish(),
        }
    }
}

/// The durable current attempt and its retired predecessors in ascending slot order.
#[allow(dead_code)] // Crate-private foundation: the ignored tests and the future serving boundary consume it.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct PublicAttemptEvidence {
    pub public_id: Uuid,
    pub current: PublicAttempt,
    pub retired: Vec<PublicAttempt>,
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
    /// Lock an already admitted attempt for private A4 staging in the caller's
    /// transaction. The legacy begin path still reserves no private UUIDs.
    pub(crate) async fn lock_private_pending_attempt(
        &self,
        tx: &Transaction<'_>,
        public: &PublicAttemptRequest,
        plan: &PackCommitPlan,
        deadline: Instant,
    ) -> Result<(), PackCommitError> {
        let identity = plan.identity();
        if public.repository_id != plan.repository_id()
            || public.admission_owner_id != plan.owner_id()
            || public.admission_owner_id != plan.tenant_id()
            || public.issuer_id != identity.issuer_id()
            || public.request_mode != plan.commit_mode()
            || public.object_format != plan.object_format()
            || public.history_incarnation != plan.history_incarnation()
            || public.authority_epoch != plan.authority_epoch()
            || public.group_epoch != plan.group_epoch()
        {
            return Err(RefStoreError::IdentityConflict.into());
        }
        self.lock_public_attempt(tx, public, identity.operation_id(), deadline).await?;
        let current = match self.lookup_public_attempt(tx, public, deadline).await? {
            PublicAttemptLookup::Pending(evidence) => evidence.current,
            PublicAttemptLookup::Cancelled(_) => {
                return Err(PackCommitError::Rejected(PackCommitRejection::new(
                    PackCommitRejectCode::Cancelled,
                    "cancellation tombstone won",
                )));
            }
            _ => return Err(RefStoreError::IdentityConflict.into()),
        };
        if current.private_id != identity.operation_id()
            || current.plan_digest != *plan.parent_digest()
            || current.base_revision != plan.expected().revision()
            || current.lane != *identity.lane()
            || current.sequence != identity.sequence()
        {
            return Err(RefStoreError::IdentityConflict.into());
        }

        // Match admission's restore -> issuer lane order and lock the existing
        // lane without reserving a sequence or writing to the operation ledger.
        bound(tx, deadline).await?;
        if lock_cluster_incarnation(tx).await? != public.restore_incarnation {
            return Err(RefStoreError::IdentityConflict.into());
        }
        bound(tx, deadline).await?;
        let lane = tx
            .query_opt(
                "SELECT 1 FROM ref_store_issuer_lanes
                   WHERE (repository_id,issuer_id,lane)=($1,$2,$3)
                     AND last_reserved_sequence >= $4 FOR NO KEY UPDATE",
                &[&identity.repository_id(), &identity.issuer_id(), &identity.lane().as_str(), &identity.sequence()],
            )
            .await
            .map_err(lookup_db_error)?;
        if lane.is_none() {
            return Err(ledger("private attempt issuer lane is missing or behind its sequence"));
        }
        Ok(())
    }

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
            .map_err(|error| match error.code() {
                // A concurrent admission or retirement changed the advisory
                // lock set while this transaction was waiting. Roll back and
                // let the caller resolve this same public operation.
                Some(&SqlState::T_R_SERIALIZATION_FAILURE) => {
                    RefStoreError::OperationPending { operation_id: request.public_id }
                }
                _ => lookup_db_error(error),
            })?;
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
        let snapshot = read_public_snapshot(tx, request.repository_id, request.public_id, deadline).await?;
        evaluate(snapshot, request)
    }

    /// Resolve the same request-aware snapshot while allowing exactly one
    /// transient finish window: a pending public wrapper whose current private
    /// attempt is already terminal or cancelled. The ordinary lookup keeps
    /// refusing that window closed, so existing replay semantics are unchanged.
    ///
    /// This is a read-only resolver. It never writes the wrapper, allocates a
    /// sequence or returns a terminal body; the caller must run the reviewed
    /// terminal mirror to derive `Mirrored` or `RetirementRequired` before any
    /// public HTTP result. The exact wrapper identity, realm, attempt/event
    /// binding and retired slot-zero proof still pass the same validators.
    #[allow(dead_code)] // The private finish path is activation-safe until the serving cutover.
    pub(crate) async fn lookup_public_attempt_finish(
        &self,
        tx: &Transaction<'_>,
        request: &PublicAttemptRequest,
        deadline: Instant,
    ) -> Result<PublicAttemptFinishLookup, PackCommitError> {
        request.validate()?;
        match timeout_at(deadline, self.lookup_public_attempt_finish_checked(tx, request, deadline)).await {
            Ok(result) => result,
            Err(_) => Err(PackCommitError::from(RefStoreError::Timeout)),
        }
    }

    async fn lookup_public_attempt_finish_checked(
        &self,
        tx: &Transaction<'_>,
        request: &PublicAttemptRequest,
        deadline: Instant,
    ) -> Result<PublicAttemptFinishLookup, PackCommitError> {
        let snapshot = read_public_snapshot(tx, request.repository_id, request.public_id, deadline).await?;
        evaluate_finish(snapshot, request)
    }

    /// Resolve an exact HTTP receive before any native work. A restored terminal
    /// may replay across a trusted cluster-incarnation edge, but a pending
    /// wrapper must pass the original strict finish path.
    pub(crate) async fn lookup_public_attempt_receive(
        &self,
        tx: &Transaction<'_>,
        request: &PublicAttemptRequest,
        deadline: Instant,
    ) -> Result<(PublicAttemptFinishLookup, Option<PublicReplayRestore>), PackCommitError> {
        request.validate()?;
        timeout_at(deadline, async {
            let snapshot = read_public_snapshot(tx, request.repository_id, request.public_id, deadline).await?;
            let Some(wrapper) = snapshot.wrapper.as_ref().filter(|wrapper| {
                wrapper.restore_incarnation != request.restore_incarnation
                    && matches!(wrapper.state.as_str(), "committed" | "rejected" | "cancelled")
            }) else {
                return Ok((evaluate_finish(snapshot, request)?, None));
            };
            let restore =
                PublicReplayRestore { original: wrapper.restore_incarnation, live: request.restore_incarnation };
            let proof_request = PublicAttemptRequest { restore_incarnation: restore.original, ..request.clone() };
            let terminal = evaluate_finish_in_scope(snapshot, &proof_request, true)?;
            bound(tx, deadline).await?;
            if !prove_historical_public_scope(tx, request.repository_id, request.public_id, restore, deadline).await? {
                return Err(RefStoreError::IdentityConflict.into());
            }
            Ok((terminal, Some(restore)))
        })
        .await
        .map_err(|_| PackCommitError::from(RefStoreError::Timeout))?
    }

    /// Resolve only the current public operation state for a future GET inside
    /// the same caller-owned, caller-preauthorized read transaction.
    ///
    /// The request has no wire digest, request mode, backend, issuer, private
    /// id, lane or sequence. The stored immutable digest/mode are parsed and
    /// checked as durable evidence, and the shared snapshot still proves the
    /// attempt's serving binding against that stored digest. The caller must
    /// supply an [`PublicOperationReadAuthorization`] it already resolved; a
    /// mismatching live issuer yields [`PublicOperationStatusLookup::Forbidden`]
    /// without state data. Unknown, legacy and private markers are preserved so
    /// a GET never routes a private id to the legacy path.
    ///
    /// The terminal body crosses only through the GET-only typed projection in
    /// the same snapshot. Pending is `None`; a terminal state is returned only
    /// after the shared current/retired event/tombstone proof and the typed
    /// repository/revision/kind/field checks have passed. The request-aware
    /// push lookup remains payload-free.
    #[allow(dead_code)] // No production caller until the GET route is deliberately opened.
    pub(crate) async fn lookup_public_operation_status(
        &self,
        tx: &Transaction<'_>,
        request: &PublicOperationStatusRequest,
        deadline: Instant,
    ) -> Result<PublicOperationStatusLookup, PackCommitError> {
        request.validate()?;
        match timeout_at(deadline, self.lookup_public_operation_status_checked(tx, request, deadline)).await {
            Ok(result) => result,
            Err(_) => Err(PackCommitError::from(RefStoreError::Timeout)),
        }
    }

    async fn lookup_public_operation_status_checked(
        &self,
        tx: &Transaction<'_>,
        request: &PublicOperationStatusRequest,
        deadline: Instant,
    ) -> Result<PublicOperationStatusLookup, PackCommitError> {
        let snapshot = read_public_status_snapshot(tx, request.repository_id, request.public_id, deadline).await?;
        evaluate_status(snapshot, request)
    }
}

/// Read the ordinary request-aware snapshot, without transferring any terminal
/// body. Its one-statement/schema/deadline behavior is unchanged.
async fn read_public_snapshot(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    public_id: Uuid,
    deadline: Instant,
) -> Result<RawSnapshot, PackCommitError> {
    let params: &[&(dyn ToSql + Sync)] = &[&repository_id, &public_id];
    read_public_snapshot_sql(tx, SELECT_SNAPSHOT, params, deadline).await
}

/// Read the GET-only snapshot. It is the same single bounded statement and
/// schema probe, with the current attempt's terminal body added; there is no
/// second read after authorization.
async fn read_public_status_snapshot(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    public_id: Uuid,
    deadline: Instant,
) -> Result<RawSnapshot, PackCommitError> {
    let transport_bound = STATUS_TERMINAL_TRANSPORT_BOUND_BYTES;
    let params: &[&(dyn ToSql + Sync)] = &[&repository_id, &public_id, &transport_bound];
    read_public_snapshot_sql(tx, SELECT_STATUS_SNAPSHOT, params, deadline).await
}

/// Shared schema probe, statement/lock budget and deserialization for both
/// snapshots. It never begins, ends, retries or writes the caller's transaction.
async fn read_public_snapshot_sql(
    tx: &Transaction<'_>,
    sql: &str,
    params: &[&(dyn ToSql + Sync)],
    deadline: Instant,
) -> Result<RawSnapshot, PackCommitError> {
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

    let row = tx.query_one(sql, params).await.map_err(lookup_db_error).map_err(PackCommitError::from)?;
    let snapshot: Value = row.get(0);
    serde_json::from_value::<RawSnapshot>(snapshot)
        .map_err(|_| ledger("public attempt lookup snapshot shape is not recognized"))
}

/// Shared catalog probe for the lock and read adapters. A missing or partial
/// migration 152 is an explicit unsupported outcome before any relation or SQL
/// function is referenced.
async fn ensure_schema(tx: &Transaction<'_>) -> Result<(), PackCommitError> {
    let schema = tx.query_one(SCHEMA_PROBE, &[]).await.map_err(lookup_db_error).map_err(PackCommitError::from)?;
    if !schema.get::<_, bool>(0) {
        return Err(PackCommitError::from(RefStoreError::Unsupported(PUBLIC_ATTEMPT_SCHEMA_REQUIRED)));
    }
    if (1usize..=4).any(|index| !schema.get::<_, bool>(index)) {
        return Err(PackCommitError::from(RefStoreError::Unsupported(
            "public attempt lookup requires the complete three-attempt migration 152",
        )));
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

fn validate_status_request(request: &PublicOperationStatusRequest) -> Result<(), PackCommitError> {
    if request.repository_id.is_nil() || request.public_id.is_nil() {
        return Err(PackCommitError::Invalid("public operation status ids must be non-nil"));
    }
    if let PublicOperationReadAuthorization::LiveIssuer { issuer_id } = request.authorization
        && issuer_id.is_nil()
    {
        return Err(PackCommitError::Invalid("public operation status live issuer must be non-nil"));
    }
    Ok(())
}

/// GET-side evaluation. It deliberately does not construct a
/// [`PublicAttemptRequest`] from the stored row: that would turn durable
/// evidence into a guessed request and would bypass the request-aware lookup's
/// contract. Instead the same wrapper shape, realm and attempt proofs run
/// against the stored immutable identity, and only the current state plus its
/// bounded typed terminal leave.
fn evaluate_status(
    snapshot: RawSnapshot,
    request: &PublicOperationStatusRequest,
) -> Result<PublicOperationStatusLookup, PackCommitError> {
    validate_status_request(request)?;
    let Some(wrapper) = snapshot.wrapper.as_ref() else {
        if snapshot.private_occupied {
            return Ok(PublicOperationStatusLookup::PrivateIdentifier);
        }
        if snapshot.legacy_operation || snapshot.legacy_cancellation {
            return Ok(PublicOperationStatusLookup::LegacyPath);
        }
        return Ok(PublicOperationStatusLookup::Unknown);
    };

    if snapshot.private_occupied {
        return Err(ledger("public operation identifier is also a private attempt identifier"));
    }
    if snapshot.legacy_operation || snapshot.legacy_cancellation {
        return Err(ledger("public operation identifier is also claimed by the legacy operation registry"));
    }
    if wrapper.repository_id != request.repository_id || wrapper.public_id != request.public_id {
        return Err(PackCommitError::from(RefStoreError::IdentityConflict));
    }

    // Authentication and repository policy are caller-owned prechecks. The
    // live-issuer variant is still bound to the exact durable issuer here; the
    // admin variant is accepted only because the caller already resolved the
    // current repository-admin policy. Neither marker can reveal a private id.
    if let PublicOperationReadAuthorization::LiveIssuer { issuer_id } = request.authorization
        && issuer_id != wrapper.issuer_id
    {
        return Ok(PublicOperationStatusLookup::Forbidden);
    }

    // Parse the stored digest/mode/object format and prove the wrapper's
    // identity, slot, event and cancellation shape. No request digest or mode
    // is guessed; the SQL serving-binding predicate already uses these stored
    // immutable values.
    let stored = parse_wrapper_identity(wrapper)?;
    let state = validate_wrapper_shape(wrapper, &stored)?;
    if !snapshot.realm_matches {
        return Err(stale_realm());
    }

    let evidence = validate_current_attempts(&snapshot, wrapper, state, false)?;
    if snapshot.status_terminal_over_bound {
        return Err(ledger("public terminal exceeds the bounded transport projection"));
    }
    let terminal = project_terminal(
        state,
        wrapper.repository_id,
        stored.object_format,
        stored.request_mode,
        evidence.current.event_revision,
        snapshot.status_terminal.as_ref(),
    )?;
    Ok(PublicOperationStatusLookup::Found(PublicOperationStatus { public_id: evidence.public_id, state, terminal }))
}

fn evaluate(snapshot: RawSnapshot, request: &PublicAttemptRequest) -> Result<PublicAttemptLookup, PackCommitError> {
    validate_request(request)?;
    let Some(wrapper) = snapshot.wrapper.as_ref() else {
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

    let state = validate_wrapper(wrapper, request)?;
    if !snapshot.realm_matches {
        return Err(stale_realm());
    }

    let evidence = validate_current_attempts(&snapshot, wrapper, state, false)?;
    match state {
        OperationState::Pending => Ok(PublicAttemptLookup::Pending(evidence)),
        OperationState::Committed => Ok(PublicAttemptLookup::Committed(evidence)),
        OperationState::Rejected => Ok(PublicAttemptLookup::Rejected(evidence)),
        OperationState::Cancelled => Ok(PublicAttemptLookup::Cancelled(evidence)),
    }
}

/// Finish-side evaluation. It shares every wrapper/attempt/event/binding proof
/// with [`evaluate`] but additionally permits a pending wrapper whose current
/// private attempt is already terminal/cancelled. That is the only difference:
/// the marker is not a final result, and a terminal wrapper still has to match
/// its current attempt exactly.
fn evaluate_finish(
    snapshot: RawSnapshot,
    request: &PublicAttemptRequest,
) -> Result<PublicAttemptFinishLookup, PackCommitError> {
    let realm_matches = snapshot.realm_matches;
    evaluate_finish_in_scope(snapshot, request, realm_matches)
}

fn evaluate_finish_in_scope(
    snapshot: RawSnapshot,
    request: &PublicAttemptRequest,
    realm_matches: bool,
) -> Result<PublicAttemptFinishLookup, PackCommitError> {
    validate_request(request)?;
    let Some(wrapper) = snapshot.wrapper.as_ref() else {
        if snapshot.private_occupied {
            return Ok(PublicAttemptFinishLookup::PrivateIdentifier);
        }
        if snapshot.legacy_operation || snapshot.legacy_cancellation {
            return Ok(PublicAttemptFinishLookup::LegacyPath);
        }
        return Ok(PublicAttemptFinishLookup::Unknown);
    };

    if snapshot.private_occupied {
        return Err(ledger("public operation identifier is also a private attempt identifier"));
    }
    if snapshot.legacy_operation || snapshot.legacy_cancellation {
        return Err(ledger("public operation identifier is also claimed by the legacy operation registry"));
    }

    let state = validate_wrapper(wrapper, request)?;
    if !realm_matches {
        return Err(stale_realm());
    }
    let evidence = validate_current_attempts(&snapshot, wrapper, state, true)?;
    Ok(PublicAttemptFinishLookup::Evidence(PublicAttemptFinishEvidence { evidence, wrapper_state: state }))
}

/// The one current/retired attempt proof shared by the request-aware lookup and
/// the GET-side status contract. The wrapper identity and realm were already
/// validated by the caller.
fn validate_current_attempts(
    snapshot: &RawSnapshot,
    wrapper: &RawWrapper,
    state: OperationState,
    allow_finish: bool,
) -> Result<PublicAttemptEvidence, PackCommitError> {
    if snapshot.attempts.len() != (wrapper.current_slot + 1) as usize {
        return Err(ledger("public operation does not have a complete attempt prefix"));
    }
    let mut attempts = Vec::with_capacity(snapshot.attempts.len());
    for (slot, raw) in (0..).zip(&snapshot.attempts) {
        if raw.slot != slot {
            return Err(ledger("public operation attempts are not an ordered slot prefix"));
        }
        let facts = validate_attempt(raw, wrapper)?;
        if attempts.iter().any(|previous: &AttemptFacts| {
            previous.private_id == facts.private_id || facts.event_id.is_some() && previous.event_id == facts.event_id
        }) {
            return Err(ledger("public operation attempts share a private identifier or event"));
        }
        if let Some(previous) = attempts.last() {
            validate_retired(previous, &facts)?;
        }
        attempts.push(facts);
    }
    let current = attempts.pop().ok_or_else(|| ledger("public operation current attempt is missing"))?;
    if current.retired_event_id.is_some() {
        return Err(ledger("current private attempt already carries retirement evidence"));
    }
    validate_current(wrapper, state, &current, allow_finish)?;

    Ok(PublicAttemptEvidence {
        public_id: wrapper.public_id,
        current: public_attempt(current),
        retired: attempts.into_iter().map(public_attempt).collect(),
    })
}

/// The stored immutable identity parsed from the wrapper. The request-aware
/// lookup must still compare it to the authenticated push request; the
/// GET-side status path uses it as durable evidence and never as a request.
struct StoredWrapperIdentity {
    wire_digest: RequestDigest,
    request_mode: CommitMode,
    object_format: GitObjectFormat,
}

fn parse_wrapper_identity(wrapper: &RawWrapper) -> Result<StoredWrapperIdentity, PackCommitError> {
    let wire_digest = parse_digest(&wrapper.wire_digest, "stored public operation wire digest is not canonical")?;
    let request_mode = parse_mode(&wrapper.request_mode, "stored public operation request mode is not recognized")?;
    let object_format =
        parse_format(&wrapper.object_format, "stored public operation object format is not recognized")?;
    if !is_canonical_hex_64(&wrapper.backend_identity) {
        return Err(ledger("stored public operation backend identity is not canonical hex"));
    }
    Ok(StoredWrapperIdentity { wire_digest, request_mode, object_format })
}

pub(super) fn validate_wrapper(
    wrapper: &RawWrapper,
    request: &PublicAttemptRequest,
) -> Result<OperationState, PackCommitError> {
    let stored = parse_wrapper_identity(wrapper)?;

    if wrapper.repository_id != request.repository_id || wrapper.public_id != request.public_id {
        return Err(PackCommitError::from(RefStoreError::IdentityConflict));
    }
    if stored.wire_digest != request.wire_digest {
        return Err(PackCommitError::from(RefStoreError::DigestConflict));
    }
    if wrapper.admission_owner_id != request.admission_owner_id
        || wrapper.issuer_id != request.issuer_id
        || wrapper.backend_identity != request.backend_identity
        || stored.request_mode != request.request_mode
        || stored.object_format != request.object_format
        || wrapper.history_incarnation != request.history_incarnation
        || wrapper.authority_epoch != request.authority_epoch
        || wrapper.group_epoch != request.group_epoch
        || wrapper.restore_incarnation != request.restore_incarnation
    {
        return Err(PackCommitError::from(RefStoreError::IdentityConflict));
    }

    validate_wrapper_shape(wrapper, &stored)
}

/// Prove the request-independent wrapper shape. Both lookups call this exact
/// function, so the GET path cannot accept a weaker attempt or terminal shape.
fn validate_wrapper_shape(
    wrapper: &RawWrapper,
    _stored: &StoredWrapperIdentity,
) -> Result<OperationState, PackCommitError> {
    // The caller must have parsed the durable digest/mode/format first. They
    // remain the evidence the SQL serving binding used; no request value can
    // replace them on this status path.
    if wrapper.admission_owner_id.is_nil()
        || wrapper.issuer_id.is_nil()
        || wrapper.history_incarnation.is_nil()
        || wrapper.restore_incarnation.is_nil()
        || wrapper.authority_epoch <= 0
        || wrapper.group_epoch <= 0
    {
        return Err(ledger("public operation identity contains an invalid nil or epoch value"));
    }
    if !(0..=2).contains(&wrapper.current_slot) {
        return Err(ledger("public operation current slot is outside zero through two"));
    }
    if wrapper.event_id.is_some_and(|id| id.is_nil()) || wrapper.cancelled_private_id.is_some_and(|id| id.is_nil()) {
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
    retired_event_id: Option<Uuid>,
}

fn validate_attempt(attempt: &RawAttempt, wrapper: &RawWrapper) -> Result<AttemptFacts, PackCommitError> {
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
        retired_event_id: attempt.retired_event_id,
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
    if (state == OperationState::Committed && attempt.base_revision.checked_add(1) != Some(revision))
        || (state == OperationState::Rejected && revision < attempt.base_revision)
    {
        return Err(ledger("private attempt event revision does not follow its base"));
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
    allow_finish: bool,
) -> Result<(), PackCommitError> {
    if current.slot != wrapper.current_slot {
        return Err(ledger("current private attempt state differs from its public operation"));
    }
    if current.state != state {
        if !allow_finish || state != OperationState::Pending {
            return Err(ledger("current private attempt state differs from its public operation"));
        }
        match current.state {
            OperationState::Committed | OperationState::Rejected => {
                if wrapper.event_id.is_some() || current.event_id.is_none() {
                    return Err(ledger("finishable terminal private attempt event differs"));
                }
            }
            OperationState::Cancelled => {
                if wrapper.event_id.is_some() || current.event_id.is_some() || wrapper.cancelled_private_id.is_some() {
                    return Err(ledger("finishable cancelled private attempt evidence differs"));
                }
            }
            OperationState::Pending => {
                return Err(ledger("current private attempt state differs from its public operation"));
            }
        }
        return Ok(());
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

fn validate_retired(retired: &AttemptFacts, next: &AttemptFacts) -> Result<(), PackCommitError> {
    if retired.state != OperationState::Rejected || !retired.revision_mismatch_rejection {
        return Err(ledger("retired public attempt is not the exact revision-mismatch rejection"));
    }
    if retired.retired_event_id.is_none() || retired.event_id != retired.retired_event_id {
        return Err(ledger("retired public attempt event differs from its recorded retirement"));
    }
    let revision = retired.event_revision.ok_or_else(|| ledger("retired public attempt event revision is missing"))?;
    if revision <= retired.base_revision || revision != next.base_revision {
        return Err(ledger("retired public attempt event does not advance to the next base"));
    }
    if retired.lane != next.lane || retired.sequence >= next.sequence {
        return Err(ledger("retired public attempt does not advance the sequence in its issuer lane"));
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
    /// Present only in the GET-only snapshot query; the request-aware query
    /// leaves it absent and therefore payload-free.
    #[serde(default)]
    status_terminal: Option<Value>,
    /// The GET-only SQL cap withheld an oversized terminal body. This is an
    /// explicit fail-closed marker, never a fallback to a direct payload read.
    #[serde(default)]
    status_terminal_over_bound: bool,
}

impl RawWrapper {
    pub(super) fn current_slot(&self) -> i16 {
        self.current_slot
    }

    pub(super) fn event_id(&self) -> Option<Uuid> {
        self.event_id
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
    retired_event_id: Option<Uuid>,
}

#[cfg(test)]
mod tests;
