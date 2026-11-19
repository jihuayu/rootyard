//! Crate-private slot-one rotation over migration 152's public wrapper.
//!
//! This is the next product-path prerequisite for issue 42, not a serving
//! cutover. Nothing here is selected by a feature flag, called by the legacy
//! gateway or exposed as an HTTP route. It adds one narrow mutation: when the
//! exact selected slot-zero private operation is a durable revision-mismatch
//! rejection and the current gate has advanced, reserve exactly one new private
//! attempt in slot one and retire the old event on the still-pending wrapper.
//!
//! # Inputs and identity
//!
//! The caller supplies the same immutable [`PublicAttemptRequest`] used by the
//! read-only resolver and the slot-zero mirror, plus the exact
//! [`PublicAttemptRetirement`] selected from that mirror. No retired private
//! UUID, sequence, plan, closure, registration, A3/A4 identity or event is
//! reused. The rotation stays on the retired operation's exact issuer lane,
//! mints a fresh private UUID, reserves the next sequence in that lane, and
//! asks the caller to build a new canonical [`PackCommitPlan`] from the locked
//! preview. Its proof
//! digest has the distinct `ref-store-slot-one-proof-v1` domain and binds the
//! selected retirement as well as the new identity.
//!
//! # Lock and transaction order
//!
//! The method owns the outer transaction and must be its first lock-taking
//! step. It takes migration 152's sorted public/retired/proposed advisory keys
//! and row lock first, then the existing cluster restore-incarnation fence,
//! then the issuer lane, then the ready `pg_refstore` repository/serving realm
//! and current gate. All fresh writes run inside one named SDK savepoint:
//! insert the slot-one attempt, advance the previewed sequence exactly once,
//! insert the pending migration-138 operation, write its migration-147 binding,
//! and only then flip the guarded wrapper from slot zero to slot one with the
//! exact retired event id. The existing migration-152 evidence verifier runs
//! before the savepoint is released. A failure rolls the savepoint back and
//! releases it, or drops the owned outer transaction when cleanup/release is
//! not confirmed, so no half-flip or commit-able partial rotation escapes.
//!
//! The caller's outer `COMMIT` is the only durability point. This method never
//! begins, commits or rolls back that outer transaction, opens no connection,
//! performs no Blob/Git IO and never retries an unknown COMMIT. There is no
//! third attempt: an already-rotated wrapper is either replayed read-only after
//! fully proving the stored slot-one/retired pair or refused closed. Only the
//! exact pending replay is implemented here; a later terminal slot-one result
//! is intentionally not re-labelled as a rotation replay and must be resolved
//! through the read-only public-attempt resolver/terminal path.
use super::{
    LockedSequence, PgRefStore, advance_sequence, bound, ensure_repository, insert_operation,
    public_attempt::{
        PublicAttempt, PublicAttemptRequest, RawWrapper, Redacted, ledger, parse_digest, parse_state, validate_wrapper,
    },
    public_terminal::PublicAttemptRetirement,
};
use crate::ref_store::{
    IssuerLane, OperationState, RefStoreError, RequestDigest,
    core::{
        CoreGate, PgRefStoreCore,
        pack_commit::{
            GATE_REVISION_MISMATCH_DETAIL, PackCommitError, PackCommitPlan, PackCommitRejectCode, PackCommitRejection,
            PackMode, PgPackCommit,
        },
        pack_snapshot::lock_cluster_incarnation,
        serving_scope::{LockedScope, RealmField, ScopeRefusal, ServingBinding},
    },
};
use serde::Deserialize;
use std::fmt;
use tokio::time::{Instant, timeout_at};
use tokio_postgres::{Transaction, error::SqlState, types::ToSql};
use uuid::Uuid;

/// The fixed proof-domain separator. Slot-zero uses a different domain, so a
/// rotation proof can never be confused with an admission proof even if every
/// other fact were equal.
const SLOT_ONE_PROOF_DOMAIN: &str = "ref-store-slot-one-proof-v1";

/// The one named savepoint that owns every possible slot-one write.
const SLOT_ONE_SAVEPOINT: &str = "rootyard_slot_one_rotation";

/// Probe exactly the migration-147/152 objects this primitive uses. A partial
/// or older catalog is a typed `Unsupported` result before any lock or write.
const SCHEMA_PROBE: &str = r#"
SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=152),
       EXISTS(SELECT 1 FROM schema_migrations WHERE version=147),
       current_setting('transaction_isolation') = 'read committed',
       to_regclass('ref_store_public_operations') IS NOT NULL,
       to_regclass('ref_store_private_attempts') IS NOT NULL,
       to_regclass('ref_store_serving_operations') IS NOT NULL,
       to_regprocedure('rootyard_ref_store_lock_public_operation(uuid,uuid,uuid)') IS NOT NULL,
       to_regprocedure('rootyard_ref_store_attempt_has_binding(ref_store_public_operations,ref_store_private_attempts)') IS NOT NULL,
       to_regprocedure('rootyard_ref_store_attempt_current_scope(ref_store_public_operations)') IS NOT NULL,
       to_regprocedure('rootyard_ref_store_attempt_stale_gate(ref_store_public_operations,ref_store_private_attempts)') IS NOT NULL,
       to_regprocedure('rootyard_ref_store_verify_public_operation(uuid,uuid)') IS NOT NULL
"#;

/// One snapshot of the wrapper, both possible attempts, their migration-138
/// operations, migration-139 events, migration-147 bindings and cancellation
/// tombstones. The terminal/event payload JSON never crosses into Rust: the
/// SELECT projects only the finite exactness predicates the rotation needs.
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
    ), '[]'::jsonb)
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

const REQUIRE_UNCLAIMED: &str = "SELECT rootyard_ref_store_require_unclaimed_attempt($1,$2)";

const INSERT_ATTEMPT: &str = "INSERT INTO ref_store_private_attempts(
        repository_id,public_id,slot,private_id,plan_digest,proof_digest,base_revision)
     VALUES($1,$2,1,$3,$4,$5,$6)";

const UPDATE_WRAPPER: &str = "UPDATE ref_store_public_operations
     SET current_slot=1,retired_event_id=$3
     WHERE repository_id=$1 AND public_id=$2
       AND current_slot=0 AND state='pending'
       AND event_id IS NULL AND retired_event_id IS NULL
       AND cancelled_private_id IS NULL";

const VERIFY_PUBLIC: &str = "SELECT rootyard_ref_store_verify_public_operation($1,$2)";

const SELECT_PACK_MODE: &str = "SELECT pack_mode FROM ref_store_core_gates WHERE repository_id=$1";

/// One trusted slot-one rotation input.
///
/// The public request is the exact immutable wrapper identity. The retirement
/// evidence is the exact selection returned by the slot-zero terminal mirror;
/// it is revalidated here and never trusted on its own.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SlotOneRotationRequest {
    pub public: PublicAttemptRequest,
    pub retirement: PublicAttemptRetirement,
}

/// The locked candidate the caller needs to build a fresh canonical plan.
///
/// `private_id` and `lane` are deliberately redacted from `Debug`. `sequence`
/// and `base_revision` are the exact preview values the plan must freeze.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct SlotOnePreview {
    private_id: Uuid,
    sequence: i64,
    base_revision: i64,
    lane: IssuerLane,
}

#[allow(dead_code)] // Crate-private foundation: the future wrapper gateway consumes it.
impl SlotOnePreview {
    /// The freshly minted private UUID this rotation will claim in slot one.
    pub(crate) fn private_id(&self) -> Uuid {
        self.private_id
    }

    /// The issuer sequence reserved under the held lane row lock.
    pub(crate) fn sequence(&self) -> i64 {
        self.sequence
    }

    /// The exact current gate revision the plan must capture.
    pub(crate) fn base_revision(&self) -> i64 {
        self.base_revision
    }

    /// The retired operation's issuer lane; rotation never switches lanes.
    pub(crate) fn lane(&self) -> &IssuerLane {
        &self.lane
    }
}

impl fmt::Debug for SlotOnePreview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SlotOnePreview")
            .field("private_id", &Redacted)
            .field("sequence", &self.sequence)
            .field("base_revision", &self.base_revision)
            .field("lane", &Redacted)
            .finish()
    }
}

/// Durable result of one slot-one rotation or exact pending replay.
#[allow(dead_code)] // Crate-private foundation: the future wrapper gateway consumes it.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct SlotOneRotationReceipt {
    pub public_id: Uuid,
    pub private_id: Uuid,
    pub retired_private_id: Uuid,
    pub retired_event_id: Uuid,
    pub retired_event_revision: i64,
    pub sequence: i64,
    pub base_revision: i64,
    pub plan_digest: RequestDigest,
    pub proof_digest: RequestDigest,
    pub wire_digest: RequestDigest,
    pub state: OperationState,
    pub replayed: bool,
}

impl fmt::Debug for SlotOneRotationReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SlotOneRotationReceipt")
            .field("public_id", &Redacted)
            .field("private_id", &Redacted)
            .field("retired_private_id", &Redacted)
            .field("retired_event_id", &Redacted)
            .field("retired_event_revision", &self.retired_event_revision)
            .field("sequence", &self.sequence)
            .field("base_revision", &self.base_revision)
            .field("plan_digest", &Redacted)
            .field("proof_digest", &Redacted)
            .field("wire_digest", &Redacted)
            .field("state", &self.state)
            .field("replayed", &self.replayed)
            .finish()
    }
}

/// The outer transaction is returned only when it is safe to use.
///
/// `Released` means the named savepoint was released after the migration-152
/// evidence check, or an exact pending replay proved the stored rotation
/// read-only. `Refused` means the savepoint was never created or was confirmed
/// rolled back and released, so the outer transaction may commit unrelated work
/// but carries no rotation side effect. Fatal/uncertain errors are `Err` and
/// the owned outer transaction is dropped.
#[allow(dead_code)] // Crate-private foundation: the future wrapper gateway consumes it.
pub(crate) enum SlotOneRotation<'a> {
    Released { tx: Transaction<'a>, receipt: SlotOneRotationReceipt },
    Refused { tx: Transaction<'a>, error: PackCommitError },
}

impl<'a> SlotOneRotation<'a> {
    fn released(tx: Transaction<'a>, receipt: SlotOneRotationReceipt) -> Self {
        Self::Released { tx, receipt }
    }

    fn refused(tx: Transaction<'a>, error: PackCommitError) -> Self {
        Self::Refused { tx, error }
    }

    /// Split the returned transaction from its bound rotation result. This is
    /// the only way a caller reaches a transaction it may commit.
    #[allow(dead_code)] // Crate-private foundation: the future wrapper gateway consumes it.
    pub(crate) fn into_parts(self) -> (Transaction<'a>, Result<SlotOneRotationReceipt, PackCommitError>) {
        match self {
            Self::Released { tx, receipt } => (tx, Ok(receipt)),
            Self::Refused { tx, error } => (tx, Err(error)),
        }
    }
}

impl PgRefStore {
    /// Rotate one exact pending slot-zero wrapper to slot one, or exactly
    /// replay an already-pending stored rotation.
    ///
    /// The outer transaction is owned for the whole future. A fresh call mints
    /// the new private UUID internally, so an exact replay returns the stored
    /// slot-one identity rather than any caller proposal. `build_plan` is called
    /// at most once, only on a fresh rotation, after the wrapper, fence, lane,
    /// ready realm and gate are locked and validated, and before any write. It
    /// is never called for a read-only replay.
    ///
    /// `Ok(Released)` returns a transaction whose savepoint release is
    /// acknowledged; the caller's outer `COMMIT` is still the publication
    /// point. `Ok(Refused)` returns a transaction with no rotation write. `Err`
    /// means the owned transaction was dropped and cannot be committed.
    #[allow(dead_code)] // No production caller until the wrapper entry is deliberately opened.
    pub(crate) async fn rotate_slot_one_in_tx<'a, F>(
        &self,
        mut tx: Transaction<'a>,
        request: &SlotOneRotationRequest,
        build_plan: F,
        deadline: Instant,
    ) -> Result<SlotOneRotation<'a>, PackCommitError>
    where
        F: FnOnce(SlotOnePreview) -> Result<PackCommitPlan, PackCommitError>,
    {
        if let Err(error) = validate_request(request) {
            return Ok(SlotOneRotation::refused(tx, error));
        }
        if Instant::now() >= deadline {
            return Ok(SlotOneRotation::refused(tx, PackCommitError::from(RefStoreError::Timeout)));
        }
        if let Err(error) = bound(&tx, deadline).await {
            // `bound` executed SET LOCAL. Any error after the explicit deadline
            // check has an unknown connection outcome, so keep no transaction.
            return Err(slot_one_ref_error(error));
        }

        // Minting is side-effect free and happens before the sorted advisory
        // lock set, so the proposed UUID is covered by the very first lock.
        let proposed = Uuid::new_v4();
        let preflight = match timeout_at(deadline, slot_one_preflight(&tx, request, proposed)).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) if slot_one_error_keeps_outer(&error) => {
                return Ok(SlotOneRotation::refused(tx, error));
            }
            Ok(Err(error)) => return Err(error),
            Err(_) => return Err(PackCommitError::from(RefStoreError::Timeout)),
        };
        let retired = match preflight {
            SlotOnePreflight::Replay(receipt) => return Ok(SlotOneRotation::released(tx, receipt)),
            SlotOnePreflight::Fresh(retired) => retired,
        };
        if Instant::now() >= deadline {
            return Err(PackCommitError::from(RefStoreError::Timeout));
        }

        // From here on the lane preview may create a lane row. Everything that
        // can write stays inside one real SDK savepoint; its `commit` is only
        // `RELEASE SAVEPOINT`, never the outer transaction's `COMMIT`.
        let nested = match tx.savepoint(SLOT_ONE_SAVEPOINT).await {
            Ok(nested) => nested,
            Err(_) => return Err(rotation_failure("slot one rotation could not create its savepoint")),
        };
        let outcome = match timeout_at(
            deadline,
            slot_one_fresh(&nested, request, &retired, proposed, build_plan, deadline),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(PackCommitError::from(RefStoreError::Timeout)),
        };
        match outcome {
            Ok(receipt) => {
                if Instant::now() >= deadline {
                    let rollback = nested.rollback().await;
                    return slot_one_savepoint_recovered(tx, rollback, PackCommitError::from(RefStoreError::Timeout))
                        .await;
                }
                // Owning the outer transaction is the safety boundary: a
                // cancelled or unacknowledged RELEASE can never hand the caller
                // a commit-able outer handle; on every uncertain branch it is
                // dropped and the SDK queues a full outer ROLLBACK.
                match nested.commit().await {
                    Ok(()) => Ok(SlotOneRotation::released(tx, receipt)),
                    Err(_) => {
                        let undo = undo_slot_one_savepoint(&mut tx).await;
                        match slot_one_release_failed(undo) {
                            SlotOneRecovery::Safe(error) => Ok(SlotOneRotation::refused(tx, error)),
                            SlotOneRecovery::Unsafe(error) => Err(error),
                        }
                    }
                }
            }
            Err(original) => {
                let rollback = nested.rollback().await;
                slot_one_savepoint_recovered(tx, rollback, original).await
            }
        }
    }
}

enum SlotOnePreflight {
    Fresh(AttemptFacts),
    /// Fully proved read-only replay; no plan builder or lane write ran.
    Replay(SlotOneRotationReceipt),
}

/// Preflight is lock/read-only. It takes the sorted migration-152 public,
/// retired and proposed advisory keys and wrapper row lock before the shared
/// restore fence, then validates the exact wrapper and attempt evidence. The
/// lane preview and every other write-capable step stay in the savepoint.
async fn slot_one_preflight(
    tx: &Transaction<'_>,
    request: &SlotOneRotationRequest,
    proposed: Uuid,
) -> Result<SlotOnePreflight, PackCommitError> {
    let schema = tx
        .query_one(SCHEMA_PROBE, &[])
        .await
        .map_err(|error| preflight_sql_error(error, "slot one rotation schema probe failed"))?;
    if !schema.get::<_, bool>(0) || !schema.get::<_, bool>(1) {
        return Err(PackCommitError::from(RefStoreError::Unsupported(
            "slot one rotation requires migrations 147 and 152",
        )));
    }
    if !schema.get::<_, bool>(2) {
        return Err(PackCommitError::from(RefStoreError::Unsupported(
            "slot one rotation requires a read committed transaction",
        )));
    }
    for index in 3usize..11 {
        if !schema.get::<_, bool>(index) {
            return Err(PackCommitError::from(RefStoreError::Unsupported(
                "slot one rotation requires the migration 147/152 relations and functions",
            )));
        }
    }

    match ensure_repository(tx, request.public.repository_id).await {
        Ok(()) => {}
        Err(RefStoreError::RepositoryNotFound) => {
            return Err(PackCommitError::from(RefStoreError::RepositoryNotFound));
        }
        Err(error) => return Err(slot_one_ref_error(error)),
    }

    // First lock in this fresh transaction: migration 152's normalized sorted
    // public/retired-attempt/proposed advisory keys, then the wrapper row.
    tx.query_one(LOCK_PUBLIC, &[&request.public.repository_id, &request.public.public_id, &proposed])
        .await
        .map_err(|error| preflight_sql_error(error, "slot one rotation could not lock the public operation"))?;

    // Hold the existing restore fence through the caller's commit/rollback.
    let incarnation = lock_cluster_incarnation(tx).await.map_err(|error| match error {
        RefStoreError::Timeout => PackCommitError::from(RefStoreError::Timeout),
        _ => rotation_failure("slot one rotation could not read the restore fence"),
    })?;
    if incarnation != request.public.restore_incarnation {
        return Err(PackCommitError::Invalid("slot one restore incarnation differs from the live cluster authority"));
    }

    let evidence = read_evidence(tx, request).await?;
    let wrapper = evidence.wrapper.ok_or_else(|| ledger("slot one rotation public operation is missing"))?;
    let wrapper_state = validate_wrapper(&wrapper, &request.public)?;
    let (retired_raw, current_raw) = split_attempts(evidence.attempts)?;

    match wrapper.current_slot() {
        0 => {
            if wrapper_state != OperationState::Pending
                || wrapper.event_id().is_some()
                || wrapper.retired_event_id().is_some()
                || wrapper.cancelled_private_id().is_some()
            {
                return Err(PackCommitError::from(RefStoreError::Unsupported(
                    "slot one rotation requires a pending slot-zero wrapper",
                )));
            }
            if current_raw.is_some() {
                return Err(ledger("slot one attempt exists while slot zero is current"));
            }
            let retired = validate_attempt(retired_raw, &request.public)?;
            validate_retired(&retired, &request.retirement)?;
            if retired.private_id == proposed || proposed == request.public.public_id {
                return Err(ledger(
                    "slot one rotation proposed private identity aliases the retired attempt or public id",
                ));
            }
            Ok(SlotOnePreflight::Fresh(retired))
        }
        1 => {
            if wrapper_state != OperationState::Pending {
                return Err(PackCommitError::from(RefStoreError::Unsupported(
                    "slot one rotation replay requires a pending slot-one wrapper",
                )));
            }
            let current_raw =
                current_raw.ok_or_else(|| ledger("slot one rotation current slot-one attempt is missing"))?;
            let retired = validate_attempt(retired_raw, &request.public)?;
            validate_retired(&retired, &request.retirement)?;
            let current = validate_attempt(current_raw, &request.public)?;
            let receipt = validate_replay(&wrapper, &request.public, &request.retirement, &retired, &current)?;

            // Revalidate the ready realm/advanced gate read-only and then run
            // the same migration-152 evidence verifier the write path uses.
            let gate_revision = current_scope_revision(tx, &request.public).await?;
            if gate_revision <= retired.base_revision || gate_revision < request.retirement.event_revision {
                return Err(ledger("slot one replay current gate does not follow the retired rejection"));
            }
            verify_public_operation_preflight(tx, &request.public).await?;
            Ok(SlotOnePreflight::Replay(receipt))
        }
        _ => Err(ledger("public operation current slot is not zero or one")),
    }
}

/// The one write-capable prefix. Every statement runs inside the caller-created
/// savepoint; an error is rolled back to that savepoint by the entry method.
async fn slot_one_fresh<F>(
    tx: &Transaction<'_>,
    request: &SlotOneRotationRequest,
    retired: &AttemptFacts,
    proposed: Uuid,
    build_plan: F,
    deadline: Instant,
) -> Result<SlotOneRotationReceipt, PackCommitError>
where
    F: FnOnce(SlotOnePreview) -> Result<PackCommitPlan, PackCommitError>,
{
    // Lane before repository/binding/gate, matching the legacy pending order.
    // `LockedSequence::preview` may insert the lane's zero row, which is why it
    // is inside this savepoint and not in preflight.
    let locked =
        LockedSequence::preview(tx, request.public.repository_id, request.public.issuer_id, proposed, &retired.lane)
            .await
            .map_err(slot_one_ref_error)?;
    let sequence = locked.sequence;
    drop(locked);
    let sequence = checked_prospective_sequence(retired.sequence, sequence)?;

    let scope = LockedScope::lock(tx, request.public.repository_id, false)
        .await
        .map_err(slot_one_ref_error)?
        .ok_or_else(|| PackCommitError::from(RefStoreError::RepositoryNotFound))?;
    let binding = scope
        .require_serving(request.public.admission_owner_id, &request.public.backend_identity)
        .map_err(map_scope_refusal)?;
    validate_binding_realm(binding, &request.public)?;

    let gate = PgRefStoreCore
        .read_gate_in_tx(tx, request.public.repository_id, true)
        .await
        .map_err(slot_one_ref_error)?
        .ok_or_else(|| rejection(PackCommitRejectCode::GateNotFound, "slot one core gate missing"))?;
    validate_gate_realm(&gate, &request.public)?;
    let base_revision = gate.revision();
    checked_prospective_revision(base_revision)?;
    validate_retirement_at_gate(retired, &request.retirement, base_revision)?;

    // The authoritative migration-152 stale gate proves the exact binding,
    // ready realm and advanced gate and is also what the slot-one insert and
    // wrapper-flip triggers will require.
    let stale_revision = stale_gate_revision(tx, &request.public).await?;
    if stale_revision != base_revision || stale_revision != request.retirement.event_revision {
        return Err(ledger("slot one stale retirement evidence differs from the current gate"));
    }

    let mode_value: String = tx
        .query_one(SELECT_PACK_MODE, &[&request.public.repository_id])
        .await
        .map_err(|error| savepoint_sql_error(error, "slot one rotation could not read the pack mode"))?
        .get(0);
    let pack_mode = PackMode::parse(&mode_value).map_err(PackCommitError::from)?;

    // Claim the freshly minted UUID under its already-held advisory key. This
    // reuses migration 152's authoritative unclaimed-namespace check.
    tx.query_one(REQUIRE_UNCLAIMED, &[&request.public.repository_id, &proposed]).await.map_err(|error| {
        savepoint_sql_error(error, "slot one rotation proposed private identity is already claimed")
    })?;

    let preview = SlotOnePreview { private_id: proposed, sequence, base_revision, lane: retired.lane.clone() };
    let plan = build_plan(preview.clone())?;
    validate_plan(&plan, &request.public, &gate, pack_mode, &preview, retired.plan_digest)?;

    let plan_digest = *plan.parent_digest();
    let proof = slot_one_proof_digest(&SlotOneProofFacts {
        public: &request.public,
        lane: &retired.lane,
        retired_private_id: retired.private_id,
        retired_event_id: request.retirement.event_id,
        retired_event_revision: request.retirement.event_revision,
        retired_plan_digest: retired.plan_digest,
        private_id: proposed,
        sequence,
        base_revision,
        plan_digest,
    });
    if proof == retired.proof_digest {
        return Err(ledger("slot one rotation proof aliases the retired proof"));
    }

    // The trusted caller owns the acknowledgment; request WAL durability before
    // any attempt/operation/binding/wrapper row can be committed.
    tx.execute("SET LOCAL synchronous_commit = 'on'", &[])
        .await
        .map_err(|error| savepoint_sql_error(error, "slot one rotation durability could not be requested"))?;

    insert_slot_one_attempt(
        tx,
        request.public.repository_id,
        request.public.public_id,
        proposed,
        plan_digest,
        proof,
        base_revision,
    )
    .await?;

    // Advance exactly the previewed lane candidate and claim the private UUID.
    let reservation =
        advance_sequence(tx, request.public.repository_id, request.public.issuer_id, &retired.lane, proposed, sequence)
            .await
            .map_err(slot_one_ref_error)?;
    if reservation.sequence() != sequence || reservation.operation_id() != proposed {
        return Err(PackCommitError::from(RefStoreError::IdentityConflict));
    }

    insert_operation(tx, plan.identity(), OperationState::Pending, None).await.map_err(slot_one_ref_error)?;

    // The plan's parent digest is the migration-147 plan parent digest and the
    // producer wire digest is the wrapper's exact producer request.
    PgPackCommit.bind_existing_serving_pending_in_tx(tx, &plan, request.public.wire_digest, deadline).await?;

    // Only after attempt/operation/binding exist does the guarded flip run. It
    // must match exactly one still-pending slot-zero wrapper; the triggers then
    // re-prove the exact binding and selected retired event.
    let changed = tx
        .execute(
            UPDATE_WRAPPER,
            &[&request.public.repository_id, &request.public.public_id, &request.retirement.event_id],
        )
        .await
        .map_err(|error| savepoint_sql_error(error, "slot one rotation wrapper update was refused"))?;
    if changed != 1 {
        return Err(ledger("slot one wrapper flip did not match exactly one pending slot-zero row"));
    }

    // Run the existing migration-152 verifier before releasing the savepoint.
    // Any failure aborts the savepoint and is never returned as a commit-able
    // half-flip.
    verify_public_operation(tx, &request.public).await?;

    Ok(SlotOneRotationReceipt {
        public_id: request.public.public_id,
        private_id: proposed,
        retired_private_id: retired.private_id,
        retired_event_id: request.retirement.event_id,
        retired_event_revision: request.retirement.event_revision,
        sequence,
        base_revision,
        plan_digest,
        proof_digest: proof,
        wire_digest: request.public.wire_digest,
        state: OperationState::Pending,
        replayed: false,
    })
}

struct SlotOneProofAttempt {
    slot: i16,
    private_id: Uuid,
    plan_digest: RequestDigest,
    proof_digest: RequestDigest,
    lane: IssuerLane,
    sequence: i64,
    base_revision: i64,
    state: OperationState,
    event_id: Option<Uuid>,
    event_revision: Option<i64>,
}

impl SlotOneProofAttempt {
    fn from_facts(facts: &AttemptFacts) -> Self {
        Self {
            slot: facts.slot,
            private_id: facts.private_id,
            plan_digest: facts.plan_digest,
            proof_digest: facts.proof_digest,
            lane: facts.lane.clone(),
            sequence: facts.sequence,
            base_revision: facts.base_revision,
            state: facts.state,
            event_id: facts.event_id,
            event_revision: facts.event_revision,
        }
    }

    fn from_public(attempt: &PublicAttempt) -> Self {
        Self {
            slot: attempt.slot,
            private_id: attempt.private_id,
            plan_digest: attempt.plan_digest,
            proof_digest: attempt.proof_digest,
            lane: attempt.lane.clone(),
            sequence: attempt.sequence,
            base_revision: attempt.base_revision,
            state: attempt.state,
            event_id: attempt.event_id,
            event_revision: attempt.event_revision,
        }
    }
}

/// Shared slot-one invariant check used by both the pending rotation replay
/// validator and writer-replay proof recomputation.
///
/// It mirrors the migration-152 slot-one triggers: the retired attempt must be
/// a slot-zero rejection with a non-nil event; the current slot-one identity
/// must be fresh, on the same lane, at least one sequence step ahead with
/// checked overflow, and based on the retired event revision with a revision
/// that can advance without overflow. Pending attempts carry no event, terminal
/// attempts carry one, and cancelled attempts carry none.
fn validate_slot_one_proof_invariants(
    public_id: Uuid,
    retired: &SlotOneProofAttempt,
    current: &SlotOneProofAttempt,
) -> Result<(Uuid, i64), PackCommitError> {
    if retired.slot != 0 || current.slot != 1 {
        return Err(ledger("slot one proof evidence is not a slot-zero/slot-one pair"));
    }
    if retired.private_id.is_nil()
        || current.private_id.is_nil()
        || retired.private_id == public_id
        || current.private_id == public_id
    {
        return Err(ledger("slot one identity aliases the public operation"));
    }
    if current.private_id == retired.private_id
        || current.plan_digest == retired.plan_digest
        || current.proof_digest == retired.proof_digest
    {
        return Err(ledger("slot one replay reuses retired identity, plan or proof"));
    }
    if current.lane != retired.lane {
        return Err(ledger("slot one replay switched issuer lanes"));
    }
    checked_prospective_sequence(retired.sequence, current.sequence)?;

    if retired.state != OperationState::Rejected {
        return Err(ledger("slot one retired attempt is not a rejection"));
    }
    let event_id = retired.event_id.ok_or_else(|| ledger("slot one retired event is missing"))?;
    if event_id.is_nil() {
        return Err(ledger("slot one retired event id is nil"));
    }
    let event_revision = retired.event_revision.ok_or_else(|| ledger("slot one retired event revision is missing"))?;
    if event_revision <= 0 {
        return Err(ledger("slot one retired event revision is not positive"));
    }
    if current.base_revision != event_revision {
        return Err(ledger("slot one replay base revision differs from the retired event"));
    }
    checked_prospective_revision(current.base_revision)?;

    match current.state {
        OperationState::Pending => {
            if current.event_id.is_some() {
                return Err(ledger("slot one pending attempt carries an event"));
            }
        }
        OperationState::Committed | OperationState::Rejected => {
            if current.event_id.is_none() {
                return Err(ledger("slot one terminal attempt has no event"));
            }
        }
        OperationState::Cancelled => {
            if current.event_id.is_some() {
                return Err(ledger("slot one cancelled attempt carries an event"));
            }
        }
    }
    Ok((event_id, event_revision))
}

fn validate_slot_one_replay_evidence(
    retired: &AttemptFacts,
    current: &AttemptFacts,
    request: &PublicAttemptRequest,
    retirement: &PublicAttemptRetirement,
) -> Result<(), PackCommitError> {
    if current.slot != 1 || current.state != OperationState::Pending || current.event_id.is_some() {
        return Err(ledger("slot one replay current attempt is not pending slot one"));
    }
    if retired.event_id != Some(retirement.event_id) || retired.event_revision != Some(retirement.event_revision) {
        return Err(ledger("slot one replay retirement evidence differs from the retired attempt"));
    }
    let retired = SlotOneProofAttempt::from_facts(retired);
    let current = SlotOneProofAttempt::from_facts(current);
    let (event_id, event_revision) = validate_slot_one_proof_invariants(request.public_id, &retired, &current)?;
    let expected_proof = slot_one_proof_digest(&SlotOneProofFacts {
        public: request,
        lane: &retired.lane,
        retired_private_id: retired.private_id,
        retired_event_id: event_id,
        retired_event_revision: event_revision,
        retired_plan_digest: retired.plan_digest,
        private_id: current.private_id,
        sequence: current.sequence,
        base_revision: current.base_revision,
        plan_digest: current.plan_digest,
    });
    if expected_proof != current.proof_digest {
        return Err(ledger("slot one replay proof does not bind the stored rotation"));
    }
    Ok(())
}

/// Validate an already-pending stored rotation read-only: exact public
/// identity, exact selected slot-zero retirement, exact slot-one attempt and
/// operation, migration-147 binding, no tombstone contradiction, a fresh plan
/// identity and our recomputable slot-one proof. Nothing is written and no
/// plan builder is called.
fn validate_replay(
    wrapper: &RawWrapper,
    request: &PublicAttemptRequest,
    retirement: &PublicAttemptRetirement,
    retired: &AttemptFacts,
    current: &AttemptFacts,
) -> Result<SlotOneRotationReceipt, PackCommitError> {
    if wrapper.current_slot() != 1
        || wrapper.event_id().is_some()
        || wrapper.retired_event_id() != Some(retirement.event_id)
        || wrapper.cancelled_private_id().is_some()
    {
        return Err(ledger("slot one replay wrapper evidence differs"));
    }
    validate_slot_one_replay_evidence(retired, current, request, retirement)?;
    Ok(SlotOneRotationReceipt {
        public_id: request.public_id,
        private_id: current.private_id,
        retired_private_id: retired.private_id,
        retired_event_id: retirement.event_id,
        retired_event_revision: retirement.event_revision,
        sequence: current.sequence,
        base_revision: current.base_revision,
        plan_digest: current.plan_digest,
        proof_digest: current.proof_digest,
        wire_digest: request.wire_digest,
        state: OperationState::Pending,
        replayed: true,
    })
}

fn validate_request(request: &SlotOneRotationRequest) -> Result<(), PackCommitError> {
    request.public.validate()?;
    if request.retirement.event_id.is_nil() {
        return Err(PackCommitError::Invalid("slot one retirement event id must be non-nil"));
    }
    if request.retirement.event_revision <= 0 {
        return Err(PackCommitError::Invalid("slot one retirement event revision must be positive"));
    }
    Ok(())
}

fn validate_attempt(attempt: StoredAttempt, request: &PublicAttemptRequest) -> Result<AttemptFacts, PackCommitError> {
    if attempt.slot != 0 && attempt.slot != 1 {
        return Err(ledger("private attempt slot is not zero or one"));
    }
    if attempt.private_id.is_nil() || attempt.private_id == request.public_id {
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
    if operation_issuer != request.issuer_id {
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
            if attempt.event_id.is_some() || attempt.event_revision.is_some() {
                return Err(ledger("pending private attempt carries event evidence"));
            }
        }
        OperationState::Rejected => {
            if !attempt.terminal_present {
                return Err(ledger("rejected private attempt has no terminal result"));
            }
            let event_id =
                attempt.event_id.ok_or_else(|| ledger("rejected private attempt has no migration-139 event"))?;
            if event_id.is_nil() {
                return Err(ledger("rejected private attempt event identity is nil"));
            }
            let revision =
                attempt.event_revision.ok_or_else(|| ledger("rejected private attempt event revision is missing"))?;
            if revision < 0 {
                return Err(ledger("rejected private attempt event revision is negative"));
            }
            if !attempt.event_outcome_matches || !attempt.event_body_matches {
                return Err(ledger("rejected private attempt event differs from its operation"));
            }
        }
        OperationState::Committed | OperationState::Cancelled => {
            return Err(ledger("slot one rotation attempt state is not pending or rejected"));
        }
    }

    if attempt.tombstone_present {
        if !attempt.tombstone_matches_lane || !attempt.tombstone_exact_operation {
            return Err(ledger("private attempt cancellation tombstone differs from its operation"));
        }
        return Err(ledger("slot one rotation attempt carries a cancellation tombstone"));
    }
    if !attempt.tombstone_absent {
        return Err(ledger("private attempt cancellation evidence differs from its operation lane"));
    }

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

fn validate_retired(retired: &AttemptFacts, retirement: &PublicAttemptRetirement) -> Result<(), PackCommitError> {
    if retired.slot != 0 || retired.state != OperationState::Rejected {
        return Err(ledger("retired public attempt is not a slot-zero rejection"));
    }
    let event_id = retired.event_id.ok_or_else(|| ledger("retired public attempt event is missing"))?;
    let event_revision =
        retired.event_revision.ok_or_else(|| ledger("retired public attempt event revision is missing"))?;
    if event_id != retirement.event_id || event_revision != retirement.event_revision {
        return Err(ledger("retired public attempt event differs from the selected retirement"));
    }
    if event_revision <= retired.base_revision {
        return Err(ledger("retired public attempt did not observe an advanced gate"));
    }
    if !retired.revision_mismatch_rejection {
        return Err(ledger("retired public attempt is not the exact revision-mismatch rejection"));
    }
    Ok(())
}

fn validate_retirement_at_gate(
    retired: &AttemptFacts,
    retirement: &PublicAttemptRetirement,
    gate_revision: i64,
) -> Result<(), PackCommitError> {
    if gate_revision <= retired.base_revision {
        return Err(ledger("slot one current gate revision did not advance past the retired base"));
    }
    if gate_revision != retirement.event_revision {
        return Err(ledger("slot one current gate revision differs from the retired event"));
    }
    checked_prospective_revision(gate_revision)?;
    Ok(())
}

fn validate_plan(
    plan: &PackCommitPlan,
    request: &PublicAttemptRequest,
    gate: &CoreGate,
    pack_mode: PackMode,
    preview: &SlotOnePreview,
    retired_plan_digest: RequestDigest,
) -> Result<(), PackCommitError> {
    if plan.repository_id() != request.repository_id {
        return Err(PackCommitError::Invalid("slot one plan belongs to another repository"));
    }
    if plan.tenant_id() != request.admission_owner_id || plan.owner_id() != request.admission_owner_id {
        return Err(rejection(PackCommitRejectCode::TenantMismatch, "slot one plan tenant or owner differs"));
    }
    if plan.object_format() != request.object_format {
        return Err(rejection(PackCommitRejectCode::ObjectFormatMismatch, "slot one plan object format differs"));
    }
    if plan.history_incarnation() != request.history_incarnation {
        return Err(rejection(
            PackCommitRejectCode::HistoryIncarnationMismatch,
            "slot one plan history incarnation differs",
        ));
    }
    if plan.authority_epoch() != request.authority_epoch {
        return Err(rejection(PackCommitRejectCode::AuthorityEpochMismatch, "slot one plan authority epoch differs"));
    }
    if plan.group_epoch() != request.group_epoch {
        return Err(rejection(PackCommitRejectCode::GroupEpochMismatch, "slot one plan group epoch differs"));
    }
    let identity = plan.identity();
    if identity.repository_id() != request.repository_id
        || identity.issuer_id() != request.issuer_id
        || identity.lane() != &preview.lane
        || identity.sequence() != preview.sequence
        || identity.operation_id() != preview.private_id
    {
        return Err(PackCommitError::Invalid("slot one plan identity does not match the locked preview"));
    }
    if plan.commit_mode() != request.request_mode {
        return Err(rejection(PackCommitRejectCode::ModeMismatch, "slot one plan commit mode differs"));
    }
    if plan.expected().revision() != preview.base_revision {
        return Err(rejection(PackCommitRejectCode::RevisionMismatch, GATE_REVISION_MISMATCH_DETAIL));
    }
    if plan.expected().gate_digest() != gate.digest() {
        return Err(rejection(PackCommitRejectCode::GateDigestMismatch, "slot one plan gate digest differs"));
    }
    if plan.expected().mode() != pack_mode {
        return Err(rejection(PackCommitRejectCode::ModeMismatch, "slot one plan pack mode differs"));
    }
    if identity.digest() != plan.parent_digest() {
        return Err(PackCommitError::Invalid("slot one plan identity digest differs from its parent digest"));
    }
    if *plan.parent_digest() == retired_plan_digest {
        return Err(ledger("slot one rotation reuses the retired plan digest"));
    }
    Ok(())
}

fn validate_binding_realm(binding: &ServingBinding, request: &PublicAttemptRequest) -> Result<(), PackCommitError> {
    if binding.object_format() != request.object_format {
        return Err(rejection(PackCommitRejectCode::ObjectFormatMismatch, "repository object format differs"));
    }
    if binding.history_incarnation() != request.history_incarnation {
        return Err(rejection(
            PackCommitRejectCode::HistoryIncarnationMismatch,
            "repository history incarnation differs",
        ));
    }
    if binding.authority_epoch() != request.authority_epoch {
        return Err(rejection(PackCommitRejectCode::AuthorityEpochMismatch, "repository authority epoch differs"));
    }
    if binding.group_epoch() != request.group_epoch {
        return Err(rejection(PackCommitRejectCode::GroupEpochMismatch, "repository group epoch differs"));
    }
    Ok(())
}

fn validate_gate_realm(gate: &CoreGate, request: &PublicAttemptRequest) -> Result<(), PackCommitError> {
    if gate.repository_id() != request.repository_id {
        return Err(ledger("slot one gate belongs to another repository"));
    }
    if gate.tenant_id() != request.admission_owner_id {
        return Err(rejection(PackCommitRejectCode::TenantMismatch, "repository belongs to another tenant"));
    }
    if gate.object_format() != request.object_format {
        return Err(rejection(PackCommitRejectCode::ObjectFormatMismatch, "repository object format differs"));
    }
    if gate.history_incarnation() != request.history_incarnation {
        return Err(rejection(
            PackCommitRejectCode::HistoryIncarnationMismatch,
            "repository history incarnation differs",
        ));
    }
    if gate.authority_epoch() != request.authority_epoch {
        return Err(rejection(PackCommitRejectCode::AuthorityEpochMismatch, "repository authority epoch differs"));
    }
    if gate.group_epoch() != request.group_epoch {
        return Err(rejection(PackCommitRejectCode::GroupEpochMismatch, "repository group epoch differs"));
    }
    Ok(())
}

fn split_attempts(attempts: Vec<StoredAttempt>) -> Result<(StoredAttempt, Option<StoredAttempt>), PackCommitError> {
    let mut slot_zero = None;
    let mut slot_one = None;
    for attempt in attempts {
        match attempt.slot {
            0 => {
                if slot_zero.replace(attempt).is_some() {
                    return Err(ledger("public operation has multiple attempts in slot zero"));
                }
            }
            1 => {
                if slot_one.replace(attempt).is_some() {
                    return Err(ledger("public operation has multiple attempts in slot one"));
                }
            }
            _ => return Err(ledger("public operation has an attempt outside slot zero or one")),
        }
    }
    let slot_zero = slot_zero.ok_or_else(|| ledger("public operation retired slot-zero attempt is missing"))?;
    Ok((slot_zero, slot_one))
}

fn checked_prospective_sequence(previous: i64, candidate: i64) -> Result<i64, PackCommitError> {
    if previous <= 0 || candidate <= 0 {
        return Err(ledger("slot one sequence is not positive"));
    }
    let minimum = previous.checked_add(1).ok_or_else(|| ledger("slot one retired sequence cannot advance"))?;
    if candidate < minimum {
        return Err(ledger("slot one sequence does not advance the retired attempt"));
    }
    Ok(candidate)
}

fn checked_prospective_revision(base_revision: i64) -> Result<i64, PackCommitError> {
    if base_revision <= 0 {
        return Err(ledger("slot one base revision is not positive"));
    }
    base_revision.checked_add(1).ok_or_else(|| ledger("slot one gate revision cannot advance"))
}

async fn insert_slot_one_attempt(
    tx: &Transaction<'_>,
    repository_id: Uuid,
    public_id: Uuid,
    private_id: Uuid,
    plan_digest: RequestDigest,
    proof_digest: RequestDigest,
    base_revision: i64,
) -> Result<(), PackCommitError> {
    let plan_hex = plan_digest.as_hex();
    let proof_hex = proof_digest.as_hex();
    let params: &[&(dyn ToSql + Sync)] =
        &[&repository_id, &public_id, &private_id, &plan_hex, &proof_hex, &base_revision];
    tx.execute(INSERT_ATTEMPT, params)
        .await
        .map_err(|error| savepoint_sql_error(error, "slot one attempt insert was refused"))?;
    Ok(())
}

async fn read_evidence(
    tx: &Transaction<'_>,
    request: &SlotOneRotationRequest,
) -> Result<RotationEvidence, PackCommitError> {
    let row = tx
        .query_one(SELECT_EVIDENCE, &[&request.public.repository_id, &request.public.public_id])
        .await
        .map_err(|error| preflight_sql_error(error, "slot one rotation evidence could not be read"))?;
    let evidence: serde_json::Value = row.get(0);
    serde_json::from_value(evidence).map_err(|_| ledger("slot one rotation evidence shape is not recognized"))
}

async fn current_scope_revision(tx: &Transaction<'_>, request: &PublicAttemptRequest) -> Result<i64, PackCommitError> {
    let row = tx
        .query_opt(CURRENT_SCOPE, &[&request.repository_id, &request.public_id])
        .await
        .map_err(|error| preflight_sql_error(error, "slot one rotation current scope could not be read"))?
        .ok_or_else(|| ledger("slot one rotation public operation disappeared"))?;
    let revision: i64 = row.get(0);
    if revision <= 0 {
        return Err(ledger("slot one rotation current gate revision is not positive"));
    }
    Ok(revision)
}

async fn stale_gate_revision(tx: &Transaction<'_>, request: &PublicAttemptRequest) -> Result<i64, PackCommitError> {
    let row = tx
        .query_opt(STALE_GATE, &[&request.repository_id, &request.public_id])
        .await
        .map_err(|error| savepoint_sql_error(error, "slot one stale retirement evidence differs"))?
        .ok_or_else(|| ledger("slot one stale retirement evidence is missing"))?;
    let revision: i64 = row.get(0);
    if revision <= 0 {
        return Err(ledger("slot one stale retirement revision is not positive"));
    }
    Ok(revision)
}

async fn verify_public_operation(tx: &Transaction<'_>, request: &PublicAttemptRequest) -> Result<(), PackCommitError> {
    tx.query_one(VERIFY_PUBLIC, &[&request.repository_id, &request.public_id])
        .await
        .map_err(|error| savepoint_sql_error(error, "slot one public operation evidence disagrees"))?;
    Ok(())
}

/// Replay is outside any savepoint, so a verifier exception may have aborted the
/// outer transaction. Keep every non-timeout failure fatal instead of returning
/// a commit-able handle.
async fn verify_public_operation_preflight(
    tx: &Transaction<'_>,
    request: &PublicAttemptRequest,
) -> Result<(), PackCommitError> {
    tx.query_one(VERIFY_PUBLIC, &[&request.repository_id, &request.public_id])
        .await
        .map_err(|error| preflight_sql_error(error, "slot one public operation evidence disagrees"))?;
    Ok(())
}

#[derive(Clone, Deserialize)]
struct RotationEvidence {
    wrapper: Option<RawWrapper>,
    #[serde(default)]
    attempts: Vec<StoredAttempt>,
}

#[derive(Clone, Deserialize)]
struct StoredAttempt {
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

#[derive(Clone, Eq, PartialEq)]
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

struct SlotOneProofFacts<'a> {
    public: &'a PublicAttemptRequest,
    lane: &'a IssuerLane,
    retired_private_id: Uuid,
    retired_event_id: Uuid,
    retired_event_revision: i64,
    retired_plan_digest: RequestDigest,
    private_id: Uuid,
    sequence: i64,
    base_revision: i64,
    plan_digest: RequestDigest,
}

/// Recompute the exact slot-one rotation proof from the verified public
/// evidence. Performs no SQL and accepts no stored proof bytes as input.
pub(crate) fn recompute_slot_one_proof(
    public: &PublicAttemptRequest,
    retired: &PublicAttempt,
    current: &PublicAttempt,
) -> Result<RequestDigest, PackCommitError> {
    let retired = SlotOneProofAttempt::from_public(retired);
    let current = SlotOneProofAttempt::from_public(current);
    let (retired_event_id, retired_event_revision) =
        validate_slot_one_proof_invariants(public.public_id, &retired, &current)?;
    Ok(slot_one_proof_digest(&SlotOneProofFacts {
        public,
        lane: &retired.lane,
        retired_private_id: retired.private_id,
        retired_event_id,
        retired_event_revision,
        retired_plan_digest: retired.plan_digest,
        private_id: current.private_id,
        sequence: current.sequence,
        base_revision: current.base_revision,
        plan_digest: current.plan_digest,
    }))
}

fn slot_one_proof_digest(facts: &SlotOneProofFacts<'_>) -> RequestDigest {
    let fields = slot_one_proof_fields(facts);
    let parts = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
    RequestDigest::of(SLOT_ONE_PROOF_DOMAIN, &parts)
}

fn slot_one_proof_fields(facts: &SlotOneProofFacts<'_>) -> Vec<Vec<u8>> {
    let public = facts.public;
    vec![
        public.repository_id.as_bytes().to_vec(),
        public.public_id.as_bytes().to_vec(),
        public.issuer_id.as_bytes().to_vec(),
        public.admission_owner_id.as_bytes().to_vec(),
        facts.lane.as_str().as_bytes().to_vec(),
        facts.retired_private_id.as_bytes().to_vec(),
        facts.retired_event_id.as_bytes().to_vec(),
        facts.retired_event_revision.to_be_bytes().to_vec(),
        facts.retired_plan_digest.as_bytes().to_vec(),
        facts.private_id.as_bytes().to_vec(),
        facts.sequence.to_be_bytes().to_vec(),
        facts.base_revision.to_be_bytes().to_vec(),
        public.wire_digest.as_bytes().to_vec(),
        facts.plan_digest.as_bytes().to_vec(),
        public.backend_identity.as_bytes().to_vec(),
        public.object_format.as_str().as_bytes().to_vec(),
        public.history_incarnation.as_bytes().to_vec(),
        public.authority_epoch.to_be_bytes().to_vec(),
        public.group_epoch.to_be_bytes().to_vec(),
        public.restore_incarnation.as_bytes().to_vec(),
        public.request_mode.as_str().as_bytes().to_vec(),
    ]
}

fn map_scope_refusal(refusal: ScopeRefusal) -> PackCommitError {
    match refusal {
        ScopeRefusal::Tenant => rejection(PackCommitRejectCode::TenantMismatch, "repository belongs to another tenant"),
        ScopeRefusal::Realm(RealmField::ObjectFormat) => {
            rejection(PackCommitRejectCode::ObjectFormatMismatch, "repository object format differs")
        }
        ScopeRefusal::Realm(RealmField::HistoryIncarnation) => {
            rejection(PackCommitRejectCode::HistoryIncarnationMismatch, "repository history incarnation differs")
        }
        ScopeRefusal::Realm(RealmField::AuthorityEpoch) => {
            rejection(PackCommitRejectCode::AuthorityEpochMismatch, "repository authority epoch differs")
        }
        ScopeRefusal::Realm(RealmField::GroupEpoch) => {
            rejection(PackCommitRejectCode::GroupEpochMismatch, "repository group epoch differs")
        }
        ScopeRefusal::BackendIdentity => {
            PackCommitError::Invalid("slot one backend identity differs from the live serving binding")
        }
        other => PackCommitError::from(RefStoreError::Unsupported(other.reason())),
    }
}

fn rejection(code: PackCommitRejectCode, detail: &'static str) -> PackCommitError {
    PackCommitError::Rejected(PackCommitRejection::new(code, detail))
}

fn rotation_failure(detail: &'static str) -> PackCommitError {
    PackCommitError::from(RefStoreError::Database(detail.to_owned()))
}

fn slot_one_ref_error(error: RefStoreError) -> PackCommitError {
    match error {
        RefStoreError::Timeout => PackCommitError::from(RefStoreError::Timeout),
        RefStoreError::RepositoryNotFound => PackCommitError::from(RefStoreError::RepositoryNotFound),
        RefStoreError::IdentityConflict => ledger("slot one rotation lost its reserved identity"),
        _ => rotation_failure("slot one rotation database error"),
    }
}

fn preflight_sql_error(error: tokio_postgres::Error, detail: &'static str) -> PackCommitError {
    match error.code() {
        Some(code) if *code == SqlState::QUERY_CANCELED || *code == SqlState::LOCK_NOT_AVAILABLE => {
            PackCommitError::from(RefStoreError::Timeout)
        }
        _ => rotation_failure(detail),
    }
}

fn savepoint_sql_error(error: tokio_postgres::Error, detail: &'static str) -> PackCommitError {
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
        _ => rotation_failure(detail),
    }
}

fn slot_one_unknown(error: &PackCommitError) -> bool {
    error.is_unknown() || matches!(error, PackCommitError::RefStore(RefStoreError::CommitUnknown { .. }))
}

/// Preflight SQL may have aborted the outer transaction; never hand it back.
fn slot_one_error_keeps_outer(error: &PackCommitError) -> bool {
    !matches!(
        error,
        PackCommitError::CommitUnknown { .. }
            | PackCommitError::RefStore(
                RefStoreError::Database(_) | RefStoreError::Timeout | RefStoreError::CommitUnknown { .. }
            )
    )
}

enum SlotOneRecovery {
    /// The savepoint is confirmed rolled back and released, or its release was
    /// already confirmed; the outer transaction is safe.
    Safe(PackCommitError),
    /// The rollback/release outcome is unknown; the outer transaction must not
    /// be returned and drops as a full rollback.
    Unsafe(PackCommitError),
}

enum SlotOneSavepointUndo {
    RolledBackAndReleased,
    ReleaseAfterRollback,
    RollbackFailed,
}

/// Finish a failed rotation after the nested transaction was consumed. On
/// confirmed rollback and release the outer transaction is safe for unrelated
/// work and carries no rotation write.
async fn slot_one_savepoint_recovered<'a>(
    tx: Transaction<'a>,
    rollback: Result<(), tokio_postgres::Error>,
    original: PackCommitError,
) -> Result<SlotOneRotation<'a>, PackCommitError> {
    if slot_one_unknown(&original) {
        // Never turn an unacknowledged-or-unknown outcome into a refusal that
        // a caller might retry. Drop the owned outer transaction.
        return Err(original);
    }
    match rollback {
        Ok(()) => match tx.batch_execute(&format!("RELEASE SAVEPOINT {SLOT_ONE_SAVEPOINT}")).await {
            Ok(()) => Ok(SlotOneRotation::refused(tx, original)),
            Err(_) => Err(rotation_failure(
                "slot one rotation failed; savepoint rollback succeeded but releasing the savepoint failed",
            )),
        },
        Err(_) => Err(rotation_failure(
            "slot one rotation failed; savepoint rollback also failed and the outer transaction must be rolled back",
        )),
    }
}

/// Undo a savepoint after its initial `RELEASE` failed. A failed release may be
/// a lost reply, so even "no such savepoint" is not treated as success.
async fn undo_slot_one_savepoint(tx: &mut Transaction<'_>) -> SlotOneSavepointUndo {
    match tx.batch_execute(&format!("ROLLBACK TO SAVEPOINT {SLOT_ONE_SAVEPOINT}")).await {
        Ok(()) => match tx.batch_execute(&format!("RELEASE SAVEPOINT {SLOT_ONE_SAVEPOINT}")).await {
            Ok(()) => SlotOneSavepointUndo::RolledBackAndReleased,
            Err(_) => SlotOneSavepointUndo::ReleaseAfterRollback,
        },
        Err(_) => SlotOneSavepointUndo::RollbackFailed,
    }
}

fn slot_one_release_failed(undo: SlotOneSavepointUndo) -> SlotOneRecovery {
    match undo {
        SlotOneSavepointUndo::RolledBackAndReleased => SlotOneRecovery::Safe(rotation_failure(
            "slot one rotation savepoint release failed; the rotation was rolled back and is not committed",
        )),
        SlotOneSavepointUndo::ReleaseAfterRollback => SlotOneRecovery::Unsafe(rotation_failure(
            "slot one rotation savepoint release failed; rollback succeeded but releasing it also failed",
        )),
        SlotOneSavepointUndo::RollbackFailed => SlotOneRecovery::Unsafe(rotation_failure(
            "slot one rotation savepoint release failed; rollback to it also failed and the outer transaction must be rolled back",
        )),
    }
}

#[cfg(test)]
mod tests;
