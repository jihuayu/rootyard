//! Typed slot-zero initial admission over the migration-152 public wrapper.
//!
//! This is a library-only foundation: the production gateway still uses the
//! legacy migration-138/147 path in `blob_git_gateway::publish::begin_fresh`, no
//! feature flag selects this module, and nothing here uploads a pack, commits a
//! ref or serves HTTP.
//!
//! One caller-owned transaction performs the fixed order:
//!
//! 1. take the normalized public/proposed/existing-attempt advisory keys with
//!    migration 152's own lock function (the same hash key the legacy adapter
//!    uses), then the locked wrapper row;
//! 2. resolve an exact replay from the wrapper before touching the issuer lane;
//!    otherwise take the public restore-incarnation row `FOR SHARE`, preview the
//!    issuer sequence under its row lock, then validate the strict ready
//!    `pg_refstore` realm/backend and lock the gate;
//! 3. the caller builds the canonical plan from that preview; this module
//!    validates every identity, realm, sequence, mode and digest field;
//! 4. write the public wrapper, the slot-zero private attempt, advance the
//!    already locked sequence, insert the private pending operation and its
//!    exact migration-147 producer binding, all in that order.
//!
//! Only the caller's `COMMIT` publishes those rows and the sequence; every
//! rollback discards them. The restore-incarnation `FOR SHARE` lock is held from
//! step 2 through that `COMMIT`/`ROLLBACK`, so a restore fence cannot rotate the
//! singleton between the last trigger check and publication. This function never
//! begins, commits or rolls back a transaction, never opens another connection
//! and performs no Blob/Git IO.
use super::{LockedSequence, PgRefStore, advance_sequence, bound, db_error, ensure_repository, insert_operation};
use crate::ref_store::{
    CommitMode, GitObjectFormat, IssuerLane, OperationState, RefStoreError, RequestDigest,
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
use tokio::time::{Instant, timeout_at};
use tokio_postgres::{Transaction, types::ToSql};
use uuid::Uuid;

const INSERT_WRAPPER: &str = "INSERT INTO ref_store_public_operations(
        repository_id,public_id,admission_owner_id,issuer_id,wire_digest,request_mode,
        backend_identity,object_format,history_incarnation,authority_epoch,group_epoch,restore_incarnation)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)";

const INSERT_ATTEMPT: &str = "INSERT INTO ref_store_private_attempts(
        repository_id,public_id,slot,private_id,plan_digest,proof_digest,base_revision)
     VALUES($1,$2,0,$3,$4,$5,$6)";

const SELECT_WRAPPER: &str = "SELECT admission_owner_id,issuer_id,wire_digest,request_mode,backend_identity,
        object_format,history_incarnation,authority_epoch,group_epoch,restore_incarnation,
        current_slot,state,cancelled_private_id
     FROM ref_store_public_operations WHERE repository_id=$1 AND public_id=$2";

/// One trusted slot-zero admission request.
///
/// All fields are typed or validated before SQL. `private_id` is the proposed
/// private UUID on both a fresh admission and a retry; an exact replay accepts a
/// different proposal, locks it with the durable attempt set, and returns the
/// stored private UUID without claiming or charging anything new.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SlotZeroAdmissionRequest {
    pub repository_id: Uuid,
    pub admission_owner_id: Uuid,
    pub issuer_id: Uuid,
    pub lane: IssuerLane,
    pub public_id: Uuid,
    pub private_id: Uuid,
    pub wire_digest: RequestDigest,
    pub request_mode: CommitMode,
    pub backend_identity: String,
    pub object_format: GitObjectFormat,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
    pub group_epoch: i64,
    pub restore_incarnation: Uuid,
}

/// The locked candidate the caller needs to build its canonical plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SlotZeroPreview {
    sequence: i64,
    base_revision: i64,
}

impl SlotZeroPreview {
    /// The candidate issuer sequence reserved by the held lane row lock.
    pub(crate) fn sequence(self) -> i64 {
        self.sequence
    }

    /// The exact current gate revision the plan must capture.
    pub(crate) fn base_revision(self) -> i64 {
        self.base_revision
    }
}

/// Durable result of one slot-zero admission or exact retry.
#[allow(dead_code)] // Crate-private foundation: the ignored tests and the future gateway cutover consume it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SlotZeroReceipt {
    pub public_id: Uuid,
    pub private_id: Uuid,
    pub sequence: i64,
    pub base_revision: i64,
    pub plan_digest: RequestDigest,
    pub proof_digest: RequestDigest,
    pub wire_digest: RequestDigest,
    pub state: OperationState,
    pub replayed: bool,
}

impl PgRefStore {
    /// Admit (or exactly replay) one slot-zero initial operation in the
    /// caller's transaction.
    ///
    /// `build_plan` is called exactly once, after the operation/wrapper locks,
    /// realm/backend/gate validation and sequence preview, and before any write.
    /// An exact replay returns before the closure is called and never touches
    /// the issuer lane.
    #[allow(dead_code)] // No production caller until the wrapper entry is deliberately opened.
    pub(crate) async fn admit_slot_zero_in_tx<F>(
        &self,
        tx: &Transaction<'_>,
        request: &SlotZeroAdmissionRequest,
        build_plan: F,
        deadline: Instant,
    ) -> Result<SlotZeroReceipt, PackCommitError>
    where
        F: FnOnce(SlotZeroPreview) -> Result<PackCommitPlan, PackCommitError>,
    {
        match timeout_at(deadline, admit_slot_zero_inner(tx, request, build_plan, deadline)).await {
            Ok(result) => result,
            Err(_) => Err(PackCommitError::from(RefStoreError::Timeout)),
        }
    }
}

async fn admit_slot_zero_inner<F>(
    tx: &Transaction<'_>,
    request: &SlotZeroAdmissionRequest,
    build_plan: F,
    deadline: Instant,
) -> Result<SlotZeroReceipt, PackCommitError>
where
    F: FnOnce(SlotZeroPreview) -> Result<PackCommitPlan, PackCommitError>,
{
    validate_request(request).map_err(PackCommitError::from)?;
    bound(tx, deadline).await.map_err(PackCommitError::from)?;

    // Migration 152 owns the wrapper/attempt functions and requires a READ
    // COMMITTED transaction; refuse before referencing any absent relation.
    let catalog = tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=152),
                    current_setting('transaction_isolation') = 'read committed'",
            &[],
        )
        .await
        .map_err(db_error)
        .map_err(PackCommitError::from)?;
    if !catalog.get::<_, bool>(0) {
        return Err(PackCommitError::from(RefStoreError::Unsupported("slot zero admission requires migration 152")));
    }
    if !catalog.get::<_, bool>(1) {
        return Err(PackCommitError::from(RefStoreError::Unsupported(
            "slot zero admission requires a read committed transaction",
        )));
    }
    ensure_repository(tx, request.repository_id).await.map_err(PackCommitError::from)?;

    // The migration-152 function normalizes {public, proposed, existing private}
    // onto the same advisory key domain as legacy reserve/begin/cancel, then
    // locks the wrapper row. It also rejects a changed set under READ COMMITTED.
    tx.query_one(
        "SELECT rootyard_ref_store_lock_public_operation($1,$2,$3)",
        &[&request.repository_id, &request.public_id, &request.private_id],
    )
    .await
    .map_err(db_error)
    .map_err(PackCommitError::from)?;

    if let Some(wrapper) = WrapperRow::load(tx, request.repository_id, request.public_id).await? {
        return replay_slot_zero(tx, request, wrapper).await;
    }

    // A fresh public/private pair must not alias any durable legacy or wrapper
    // claim. The same operation keys are already held, so this READ COMMITTED
    // check cannot race a legacy writer for either UUID.
    ensure_unclaimed(tx, request.repository_id, request.public_id).await.map_err(PackCommitError::from)?;
    ensure_unclaimed(tx, request.repository_id, request.private_id).await.map_err(PackCommitError::from)?;

    // Restore fence: take and hold the public singleton incarnation row
    // `FOR SHARE` until the caller commits or rolls back. A restore fence takes
    // that row `FOR UPDATE` first, so the admission cannot observe one
    // incarnation, pass the migration-152 trigger checks and commit after the
    // restore row moved. This is deliberately acquired before the issuer lane
    // and repository/gate so it cannot wait on a lock held by a path that
    // already owns repository authority.
    let incarnation = lock_cluster_incarnation(tx).await.map_err(PackCommitError::from)?;
    if incarnation != request.restore_incarnation {
        return Err(PackCommitError::Invalid("slot zero restore incarnation differs from the live cluster authority"));
    }

    // Issuer lane before repository/binding/gate, matching the legacy pending
    // order: `PgRefStore::begin` holds the lane row before
    // `begin_serving_pending_in_tx` takes the repository scope and gate. A
    // different operation id on this issuer/lane must wait here, never take the
    // repository/gate locks first and then wait for the lane.
    // Dropping the preview value does not release the transaction-scoped row
    // lock; the conditional advance below still proves this candidate is current.
    let locked =
        LockedSequence::preview(tx, request.repository_id, request.issuer_id, request.private_id, &request.lane)
            .await
            .map_err(PackCommitError::from)?;
    let sequence = locked.sequence;
    drop(locked);

    let scope = LockedScope::lock(tx, request.repository_id, false)
        .await
        .map_err(PackCommitError::from)?
        .ok_or_else(|| PackCommitError::from(RefStoreError::RepositoryNotFound))?;
    let binding =
        scope.require_serving(request.admission_owner_id, &request.backend_identity).map_err(map_scope_refusal)?;
    validate_binding_realm(binding, request)?;

    let gate = PgRefStoreCore
        .read_gate_in_tx(tx, request.repository_id, true)
        .await
        .map_err(PackCommitError::from)?
        .ok_or_else(|| rejection(PackCommitRejectCode::GateNotFound, "core gate missing"))?;
    validate_gate_realm(&gate, request)?;
    let base_revision = gate.revision();
    let mode_value: String = tx
        .query_one("SELECT pack_mode FROM ref_store_core_gates WHERE repository_id=$1", &[&request.repository_id])
        .await
        .map_err(db_error)
        .map_err(PackCommitError::from)?
        .get(0);
    let pack_mode = PackMode::parse(&mode_value).map_err(PackCommitError::from)?;

    let preview = SlotZeroPreview { sequence, base_revision };

    let plan = build_plan(preview)?;
    validate_plan(&plan, request, &gate, pack_mode, preview)?;
    let plan_digest = *plan.parent_digest();
    let proof =
        proof_digest(&ProofFacts { request, private_id: request.private_id, sequence, base_revision, plan_digest });

    // The trusted caller owns the acknowledgment; request WAL durability before
    // any wrapper/attempt/operation/binding row can be committed.
    tx.execute("SET LOCAL synchronous_commit = 'on'", &[]).await.map_err(|_| {
        PackCommitError::from(RefStoreError::Database("slot zero admission durability could not be requested".into()))
    })?;

    insert_wrapper(tx, request).await?;
    insert_attempt(tx, request, plan_digest, proof, base_revision).await?;

    // Advance the exact previewed lane candidate and claim the private UUID.
    let reservation =
        advance_sequence(tx, request.repository_id, request.issuer_id, &request.lane, request.private_id, sequence)
            .await
            .map_err(PackCommitError::from)?;
    if reservation.sequence() != sequence || reservation.operation_id() != request.private_id {
        return Err(PackCommitError::from(RefStoreError::IdentityConflict));
    }

    insert_operation(tx, plan.identity(), OperationState::Pending, None).await.map_err(PackCommitError::from)?;

    // The same plan's parent digest is the migration-147 plan_parent_digest and
    // the producer wire digest is the wrapper's exact producer request.
    PgPackCommit.bind_existing_serving_pending_in_tx(tx, &plan, request.wire_digest, deadline).await?;

    Ok(SlotZeroReceipt {
        public_id: request.public_id,
        private_id: request.private_id,
        sequence,
        base_revision,
        plan_digest,
        proof_digest: proof,
        wire_digest: request.wire_digest,
        state: OperationState::Pending,
        replayed: false,
    })
}

/// Exact retry: verify the immutable wrapper identity, the slot-zero attempt,
/// the private operation and the exact migration-147 binding, then return the
/// stored admission without touching the issuer lane.
async fn replay_slot_zero(
    tx: &Transaction<'_>,
    request: &SlotZeroAdmissionRequest,
    wrapper: WrapperRow,
) -> Result<SlotZeroReceipt, PackCommitError> {
    if wrapper.wire_digest != request.wire_digest.as_hex() {
        return Err(PackCommitError::from(RefStoreError::DigestConflict));
    }
    if wrapper.admission_owner_id != request.admission_owner_id
        || wrapper.issuer_id != request.issuer_id
        || wrapper.request_mode.as_str() != request.request_mode.as_str()
        || wrapper.backend_identity != request.backend_identity
        || wrapper.object_format.as_str() != request.object_format.as_str()
        || wrapper.history_incarnation != request.history_incarnation
        || wrapper.authority_epoch != request.authority_epoch
        || wrapper.group_epoch != request.group_epoch
        || wrapper.restore_incarnation != request.restore_incarnation
    {
        return Err(PackCommitError::from(RefStoreError::IdentityConflict));
    }
    if wrapper.current_slot != 0 {
        return Err(PackCommitError::from(RefStoreError::Unsupported(
            "slot one rotation is not part of slot zero admission",
        )));
    }

    let attempt = tx
        .query_opt(
            "SELECT private_id,plan_digest,proof_digest,base_revision
             FROM ref_store_private_attempts WHERE repository_id=$1 AND public_id=$2 AND slot=0",
            &[&request.repository_id, &request.public_id],
        )
        .await
        .map_err(db_error)
        .map_err(PackCommitError::from)?
        .ok_or_else(|| ledger_integrity("slot zero private attempt is missing"))?;
    let private_id: Uuid = attempt.get(0);
    let plan_digest = digest_column(&attempt, 1)?;
    let proof_hex: String = attempt.get(2);
    let base_revision: i64 = attempt.get(3);

    let operation = tx
        .query_opt(
            "SELECT issuer_id,lane,sequence,request_digest,state
             FROM ref_store_operations WHERE repository_id=$1 AND operation_id=$2",
            &[&request.repository_id, &private_id],
        )
        .await
        .map_err(db_error)
        .map_err(PackCommitError::from)?
        .ok_or_else(|| ledger_integrity("slot zero private operation is missing"))?;
    let operation_issuer: Uuid = operation.get(0);
    let operation_lane: String = operation.get(1);
    let sequence: i64 = operation.get(2);
    let operation_digest = digest_column(&operation, 3)?;
    let operation_state_value: String = operation.get(4);
    let operation_state = OperationState::parse(&operation_state_value)
        .ok_or_else(|| ledger_integrity("stored slot zero operation state is not recognized"))?;
    if operation_issuer != request.issuer_id
        || operation_lane.as_str() != request.lane.as_str()
        || operation_digest != plan_digest
    {
        return Err(ledger_integrity("slot zero private operation binding differs"));
    }

    let wrapper_state = OperationState::parse(&wrapper.state)
        .ok_or_else(|| ledger_integrity("stored slot zero wrapper state is not recognized"))?;
    if wrapper_state != operation_state
        || (operation_state == OperationState::Cancelled) != (wrapper.cancelled_private_id == Some(private_id))
    {
        return Err(ledger_integrity("slot zero wrapper and private operation state differ"));
    }

    let binding = tx
        .query_opt(
            "SELECT issuer_id,producer_request_digest,plan_parent_digest
             FROM ref_store_serving_operations WHERE repository_id=$1 AND operation_id=$2",
            &[&request.repository_id, &private_id],
        )
        .await
        .map_err(db_error)
        .map_err(PackCommitError::from)?
        .ok_or_else(|| ledger_integrity("slot zero serving producer binding is missing"))?;
    let binding_issuer: Uuid = binding.get(0);
    let binding_producer = digest_column(&binding, 1)?;
    let binding_parent = digest_column(&binding, 2)?;
    if binding_issuer != request.issuer_id
        || binding_producer.as_hex() != wrapper.wire_digest
        || binding_parent != plan_digest
    {
        return Err(ledger_integrity("slot zero serving producer binding differs from the wrapper"));
    }

    let proof = proof_digest(&ProofFacts { request, private_id, sequence, base_revision, plan_digest });
    if proof.as_hex() != proof_hex {
        return Err(ledger_integrity("slot zero proof digest differs from the durable attempt"));
    }

    Ok(SlotZeroReceipt {
        public_id: request.public_id,
        private_id,
        sequence,
        base_revision,
        plan_digest,
        proof_digest: proof,
        wire_digest: request.wire_digest,
        state: operation_state,
        replayed: true,
    })
}

async fn insert_wrapper(tx: &Transaction<'_>, request: &SlotZeroAdmissionRequest) -> Result<(), PackCommitError> {
    let wire = request.wire_digest.as_hex();
    let mode = request.request_mode.as_str();
    let backend = request.backend_identity.as_str();
    let format = request.object_format.as_str();
    let params: &[&(dyn ToSql + Sync)] = &[
        &request.repository_id,
        &request.public_id,
        &request.admission_owner_id,
        &request.issuer_id,
        &wire,
        &mode,
        &backend,
        &format,
        &request.history_incarnation,
        &request.authority_epoch,
        &request.group_epoch,
        &request.restore_incarnation,
    ];
    tx.execute(INSERT_WRAPPER, params).await.map_err(db_error).map_err(PackCommitError::from)?;
    Ok(())
}

async fn insert_attempt(
    tx: &Transaction<'_>,
    request: &SlotZeroAdmissionRequest,
    plan_digest: RequestDigest,
    proof_digest: RequestDigest,
    base_revision: i64,
) -> Result<(), PackCommitError> {
    let plan_hex = plan_digest.as_hex();
    let proof_hex = proof_digest.as_hex();
    let params: &[&(dyn ToSql + Sync)] =
        &[&request.repository_id, &request.public_id, &request.private_id, &plan_hex, &proof_hex, &base_revision];
    tx.execute(INSERT_ATTEMPT, params).await.map_err(db_error).map_err(PackCommitError::from)?;
    Ok(())
}

struct WrapperRow {
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
    cancelled_private_id: Option<Uuid>,
}

impl WrapperRow {
    async fn load(tx: &Transaction<'_>, repository_id: Uuid, public_id: Uuid) -> Result<Option<Self>, PackCommitError> {
        let row = tx
            .query_opt(SELECT_WRAPPER, &[&repository_id, &public_id])
            .await
            .map_err(db_error)
            .map_err(PackCommitError::from)?;
        Ok(row.map(|row| Self {
            admission_owner_id: row.get(0),
            issuer_id: row.get(1),
            wire_digest: row.get(2),
            request_mode: row.get(3),
            backend_identity: row.get(4),
            object_format: row.get(5),
            history_incarnation: row.get(6),
            authority_epoch: row.get(7),
            group_epoch: row.get(8),
            restore_incarnation: row.get(9),
            current_slot: row.get(10),
            state: row.get(11),
            cancelled_private_id: row.get(12),
        }))
    }
}

fn validate_request(request: &SlotZeroAdmissionRequest) -> Result<(), RefStoreError> {
    if request.repository_id.is_nil()
        || request.admission_owner_id.is_nil()
        || request.issuer_id.is_nil()
        || request.public_id.is_nil()
        || request.private_id.is_nil()
        || request.history_incarnation.is_nil()
        || request.restore_incarnation.is_nil()
    {
        return Err(RefStoreError::InvalidIdentity("slot zero ids must be non-nil".into()));
    }
    if request.public_id == request.private_id {
        return Err(RefStoreError::InvalidIdentity("slot zero public and private ids must differ".into()));
    }
    if !is_canonical_hex_64(&request.backend_identity) {
        return Err(RefStoreError::InvalidIdentity("slot zero backend identity must be lowercase sha256 hex".into()));
    }
    if request.authority_epoch <= 0 || request.group_epoch <= 0 {
        return Err(RefStoreError::InvalidIdentity("slot zero epochs must be positive".into()));
    }
    Ok(())
}

fn validate_binding_realm(binding: &ServingBinding, request: &SlotZeroAdmissionRequest) -> Result<(), PackCommitError> {
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

fn validate_gate_realm(gate: &CoreGate, request: &SlotZeroAdmissionRequest) -> Result<(), PackCommitError> {
    if gate.repository_id() != request.repository_id {
        return Err(ledger_integrity("slot zero gate belongs to another repository"));
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

fn validate_plan(
    plan: &PackCommitPlan,
    request: &SlotZeroAdmissionRequest,
    gate: &CoreGate,
    pack_mode: PackMode,
    preview: SlotZeroPreview,
) -> Result<(), PackCommitError> {
    if plan.repository_id() != request.repository_id {
        return Err(PackCommitError::Invalid("slot zero plan belongs to another repository"));
    }
    if plan.tenant_id() != request.admission_owner_id || plan.owner_id() != request.admission_owner_id {
        return Err(rejection(PackCommitRejectCode::TenantMismatch, "slot zero plan tenant or owner differs"));
    }
    if plan.object_format() != request.object_format {
        return Err(rejection(PackCommitRejectCode::ObjectFormatMismatch, "slot zero plan object format differs"));
    }
    if plan.history_incarnation() != request.history_incarnation {
        return Err(rejection(
            PackCommitRejectCode::HistoryIncarnationMismatch,
            "slot zero plan history incarnation differs",
        ));
    }
    if plan.authority_epoch() != request.authority_epoch {
        return Err(rejection(PackCommitRejectCode::AuthorityEpochMismatch, "slot zero plan authority epoch differs"));
    }
    if plan.group_epoch() != request.group_epoch {
        return Err(rejection(PackCommitRejectCode::GroupEpochMismatch, "slot zero plan group epoch differs"));
    }
    let identity = plan.identity();
    if identity.repository_id() != request.repository_id
        || identity.issuer_id() != request.issuer_id
        || identity.lane() != &request.lane
        || identity.sequence() != preview.sequence()
        || identity.operation_id() != request.private_id
    {
        return Err(PackCommitError::Invalid("slot zero plan identity does not match the locked preview"));
    }
    if plan.commit_mode() != request.request_mode {
        return Err(rejection(PackCommitRejectCode::ModeMismatch, "slot zero plan commit mode differs"));
    }
    if plan.expected().revision() != preview.base_revision() {
        return Err(rejection(PackCommitRejectCode::RevisionMismatch, GATE_REVISION_MISMATCH_DETAIL));
    }
    if plan.expected().gate_digest() != gate.digest() {
        return Err(rejection(PackCommitRejectCode::GateDigestMismatch, "slot zero plan gate digest differs"));
    }
    if plan.expected().mode() != pack_mode {
        return Err(rejection(PackCommitRejectCode::ModeMismatch, "slot zero plan pack mode differs"));
    }
    if identity.digest() != plan.parent_digest() {
        return Err(PackCommitError::Invalid("slot zero plan identity digest differs from its parent digest"));
    }
    Ok(())
}

async fn ensure_unclaimed(tx: &Transaction<'_>, repository_id: Uuid, operation_id: Uuid) -> Result<(), RefStoreError> {
    let claimed: bool = tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM ref_store_operations WHERE repository_id=$1 AND operation_id=$2)
                 OR EXISTS(SELECT 1 FROM ref_store_cancellations WHERE repository_id=$1 AND operation_id=$2)
                 OR EXISTS(SELECT 1 FROM ref_store_public_operations WHERE repository_id=$1 AND public_id=$2)
                 OR EXISTS(SELECT 1 FROM ref_store_private_attempts WHERE repository_id=$1 AND private_id=$2)",
            &[&repository_id, &operation_id],
        )
        .await
        .map_err(db_error)?
        .get(0);
    if claimed { Err(RefStoreError::IdentityConflict) } else { Ok(()) }
}

struct ProofFacts<'a> {
    request: &'a SlotZeroAdmissionRequest,
    private_id: Uuid,
    sequence: i64,
    base_revision: i64,
    plan_digest: RequestDigest,
}

fn proof_digest(facts: &ProofFacts<'_>) -> RequestDigest {
    let request = facts.request;
    let fields = [
        request.repository_id.as_bytes().to_vec(),
        request.public_id.as_bytes().to_vec(),
        facts.private_id.as_bytes().to_vec(),
        request.issuer_id.as_bytes().to_vec(),
        request.admission_owner_id.as_bytes().to_vec(),
        request.lane.as_str().as_bytes().to_vec(),
        facts.sequence.to_be_bytes().to_vec(),
        facts.base_revision.to_be_bytes().to_vec(),
        request.wire_digest.as_bytes().to_vec(),
        facts.plan_digest.as_bytes().to_vec(),
        request.backend_identity.as_bytes().to_vec(),
        request.object_format.as_str().as_bytes().to_vec(),
        request.history_incarnation.as_bytes().to_vec(),
        request.authority_epoch.to_be_bytes().to_vec(),
        request.group_epoch.to_be_bytes().to_vec(),
        request.restore_incarnation.as_bytes().to_vec(),
        request.request_mode.as_str().as_bytes().to_vec(),
    ];
    let parts = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
    RequestDigest::of("ref-store-slot-zero-proof-v1", &parts)
}

fn digest_column(row: &tokio_postgres::Row, index: usize) -> Result<RequestDigest, PackCommitError> {
    let raw: String = row.get(index);
    raw.parse().map_err(|_| ledger_integrity("stored slot zero digest is not canonical lowercase sha256 hex"))
}

fn is_canonical_hex_64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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
            PackCommitError::Invalid("slot zero backend identity differs from the live serving binding")
        }
        other => PackCommitError::from(RefStoreError::Unsupported(other.reason())),
    }
}

fn rejection(code: PackCommitRejectCode, detail: &'static str) -> PackCommitError {
    PackCommitError::Rejected(PackCommitRejection::new(code, detail))
}

fn ledger_integrity(detail: &'static str) -> PackCommitError {
    rejection(PackCommitRejectCode::LedgerIntegrity, detail)
}

#[cfg(test)]
mod tests;
