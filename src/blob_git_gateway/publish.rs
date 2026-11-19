//! Protected publication and the decision-gated commit pipeline.
//!
//! Ordering is fixed and each stage drops its pooled PostgreSQL client before
//! any Blob/native work:
//!
//! 1. the receive handler already probed the immutable operation registry with
//!    the producer request digest before native ingestion; here an operation
//!    that appeared meanwhile is classified again (terminal replay, pending =>
//!    unknown, different request => conflict);
//! 2. a fresh operation reserves a real issuer-lane sequence, re-checks the
//!    operation and its producer binding, and writes the durable pending row plus
//!    its migration-147 binding in **one** caller-owned short transaction, so an
//!    identical concurrent retry never charges a second sequence or reports a
//!    false identity conflict;
//! 3. one A3 acquire + protected OpenDAL upload + A4 registration per received
//!    pack pair;
//! 4. `prepare` -> native-facts `select` -> native-closure `verify` -> final
//!    `commit` on the original operation identity.
//!
//! The client `old` values are the CAS preconditions; the temporary native view
//! is never the authority. An unknown `COMMIT` stays unknown and is resolved
//! only through the persisted operation id. The producer digest is the
//! operation-level request identity and lives in its own migration-147 row; the
//! sealed core plan keeps its own canonical parent digest over the actual
//! pack-pair metadata, and `identity.digest() == parent_digest` still holds for
//! every A3 receipt and stored registration.
//!
//! [`begin_slot_zero`] is the crate-private migration-152 private-mode adapter.
//! It is deliberately not selected by the live route: the legacy transaction
//! above remains authoritative until GET/cancel/replay/terminal read paths and
//! real PostgreSQL qualification are ready. When selected, it keeps the public
//! UUID and producer digest stable, mints one independent private UUID, and
//! admits it through [`crate::ref_store::pg::slot_zero`] before any A3/Blob IO.
//! It never falls back to the legacy fresh transaction after the private mode
//! has accepted the public identity or when the migration-152 foundation is
//! absent.
use std::{path::PathBuf, time::Instant as StdInstant};

use tokio::time::{Instant, timeout_at};
use uuid::Uuid;

use crate::{
    blob_store::protected::{ProtectedUploadError, ProtectedUploader, UploadSource},
    db::Identity,
    ref_store::{
        GitOid, HeadUpdate, IssuerLane, OperationIdentity, OperationState, PgRefStore, RefName, RefUpdate,
        RequestDigest,
        artifact_hold::{
            AcquireArtifactHoldsRequest, AcquireOutcome, ArtifactHoldError, ArtifactHoldPurpose, ArtifactSpec,
            HoldScope, PgArtifactHoldStore,
        },
        core::{
            CommitMode,
            pack_commit::{
                AuthorizedCommitError, AuthorizedCommitMode, ContentDigest, GATE_REVISION_MISMATCH_DETAIL,
                MAX_ACK_BODY_BYTES, PackArtifactRole, PackCommitBaseline, PackCommitError, PackCommitExpectation,
                PackCommitPlan, PackCommitRejectCode, PackCommitRejection, PackCommitScope, PackCommitTerminal,
                PackMembershipEntry, PackPendingToken, PackRegistrationRequest, PgAuthorizedCommit, PgPackCommit,
                PlannedArtifact, PlannedPack, PrepareOutcome, ensure_pack_terminal_budget,
            },
        },
        pg::{
            public_attempt::{PublicAttemptLookup, PublicAttemptRequest},
            slot_zero::SlotZeroAdmissionRequest,
        },
        tx::{begin_bounded, commit_bounded},
    },
};

use super::{
    error::GatewayError,
    native::{derived_uuid, file_digest},
    operation::{self, Claim},
    protocol::PushRequest,
    serving::ServingRepository,
    snapshot::{capture_baseline, ref_error},
    state::BlobGitState,
};

/// Crate-private exact slot-zero-retirement handoff. No route selects it until
/// the separate reviewed HTTP admission switch is opened.
#[allow(dead_code)]
pub(super) mod slot_one;

const HOLD_NAMESPACE: &str = "gateway-pack";
const ISSUER_LANE: &str = "blob-git-receive";

/// The one fixed 409 refusal for a durable cancellation tombstone, shared with
/// `RefStoreError::Cancelled`. It carries no operation id or provider detail.
const DURABLY_CANCELLED: GatewayError = GatewayError::Conflict("operation is durably cancelled");

/// A typed gate-revision refusal under `begin_serving_pending_in_tx` is raised
/// only inside the caller-owned admission transaction, before its `COMMIT`.
/// Each retry therefore observes a definitively rolled-back pending row and
/// sequence reservation. The bound is deliberately tiny: a request may race at
/// most this many distinct winners against the same original deadline.
const MAX_ADMISSION_REBASES: usize = 2;

/// One gateway-owned savepoint on the authenticated deadpool transaction. The
/// slot-zero coordinator creates its own nested savepoint inside this one, so
/// the outer `COMMIT` remains the only durability point.
const GATEWAY_SLOT_ZERO_SAVEPOINT: &str = "rootyard_gateway_slot_zero_admission";

/// One staged `.pack` + `.idx` pair with its verified content digest.
pub(super) struct Pair {
    pub pack: PathBuf,
    pub idx: PathBuf,
    pub pack_id: Uuid,
    pub pack_sha: String,
    pub pack_len: u64,
    pub idx_sha: String,
    pub idx_len: u64,
}

impl Pair {
    pub(super) async fn stage(pack: PathBuf, idx: PathBuf, operation: Uuid) -> Result<Self, GatewayError> {
        let (pack_sha, pack_len) = file_digest(&pack).await?;
        let (idx_sha, idx_len) = file_digest(&idx).await?;
        let pack_id = derived_uuid("pack-id", operation, pack_sha.as_bytes());
        Ok(Self { pack, idx, pack_id, pack_sha, pack_len, idx_sha, idx_len })
    }
}

/// Durable result of one push, always rendered from a persisted core terminal.
pub(super) enum PushOutcome {
    /// A committed or rejected pack terminal (fresh or an exact replay).
    Terminal(PackCommitTerminal),
    /// A verified migration-138 cancellation tombstone.
    Cancelled(&'static str),
}

pub(super) enum Start {
    Terminal(PackCommitTerminal),
    Cancelled(&'static str),
    Fresh {
        _token: PackPendingToken,
        plan: Box<PackCommitPlan>,
    },
    /// The admission transaction proved this plan's captured gate revision was
    /// superseded and rolled back before any pending row, binding or sequence
    /// reservation became durable. The caller may capture a fresh baseline and
    /// rebuild the plan once more, still under the same request/operation
    /// identity and absolute deadline.
    Rebaseline,
}

/// Drive the full protected publication for one already-parsed push.
#[allow(clippy::too_many_arguments)]
pub(super) async fn push(
    state: &BlobGitState,
    serving: &ServingRepository,
    actor: &Identity,
    operation_id: Uuid,
    request_digest: RequestDigest,
    request: &PushRequest,
    pairs: &[Pair],
    mode: CommitMode,
    deadline: Instant,
) -> Result<PushOutcome, GatewayError> {
    // The baseline is captured after native ingestion and is the authoritative
    // old-tip set for this plan. A concurrent commit is handled per-ref by the
    // accepted-subset facade, not by comparing against the earlier lookup.
    //
    // One narrow exception is required *before* admission: the migration-138
    // pending prefix locks and checks the gate revision inside the same
    // transaction that would create the pending row. If a winner commits
    // between this capture and that check, `begin_serving_pending_in_tx`
    // returns the typed `RevisionMismatch` refusal and the caller-owned
    // transaction is rolled back. That refusal is not a Git verdict, but
    // returning it as HTTP 409 would hide the now-current CAS fact from the
    // client. Re-capture and rebuild the plan under the original deadline so
    // the normal native-facts selection can persist the exact
    // `OldOidMismatch` rejection. Nothing else is retried here. The producer
    // operation id/digest and the received request/pack bytes stay identical;
    // only the core plan's expected revision, ref set and old-membership set
    // are rebuilt. The rolled-back attempt created no A3/A4 effect and no
    // closure proof, so prepare/verify later recompute those from the refreshed
    // baseline instead of rebinding an existing proof.
    let mut rebases = 0usize;
    let start = loop {
        let baseline =
            capture_baseline(state, serving.gate.repository_id(), serving.gate.tenant_id(), deadline).await?;
        #[cfg(test)]
        state.pause_before_admission(operation_id).await;
        // A rebase may adopt a newer revision/ref/membership set, and a
        // legitimate winner may also retarget HEAD or activate pack-verified
        // mode; those are rebuilt and revalidated by prepare/select/verify.
        // It must never adopt a different tenant, format, history incarnation
        // or authority/group epoch. The request was authorized against the
        // original serving realm; a moved realm is a conflict to resolve, not a
        // baseline to silently adopt. The admission prefix itself re-checks the
        // realm before any pending row becomes durable, so a second move still
        // fails closed.
        if rebases > 0 && !admission_realm_matches_serving(&baseline, serving) {
            return Err(GatewayError::Conflict("repository authority changed; retry"));
        }
        let owner = repository_owner(state, serving.gate.repository_id(), deadline).await?;
        match begin(
            state,
            serving,
            actor,
            operation_id,
            request_digest,
            request,
            pairs,
            mode,
            owner,
            &baseline,
            deadline,
        )
        .await?
        {
            Start::Rebaseline => {
                if rebases >= MAX_ADMISSION_REBASES {
                    return Err(GatewayError::Conflict("repository gate changed during publication admission"));
                }
                rebases += 1;
                if Instant::now() >= deadline {
                    return Err(GatewayError::Timeout);
                }
                continue;
            }
            start => break start,
        }
    };
    match start {
        Start::Terminal(terminal) => Ok(PushOutcome::Terminal(terminal)),
        Start::Cancelled(reason) => Ok(PushOutcome::Cancelled(reason)),
        Start::Rebaseline => Err(GatewayError::Internal("admission rebase escaped its bounded loop")),
        Start::Fresh { plan, _token: token } => {
            // Test-only rendezvous after the pending operation is durable and
            // before prepare/select/verify/commit. Absent from every non-test
            // build and unreachable from any request or configuration.
            #[cfg(test)]
            state.pause_after_admission(operation_id).await;
            let result = async {
                for (index, pair) in pairs.iter().enumerate() {
                    let planned =
                        plan.packs().get(index).ok_or(GatewayError::Internal("planned pack set is incomplete"))?;
                    publish_pair(state, &plan, planned.pack_id(), pair, deadline).await?;
                }
                decide(state, actor, (*plan).clone(), mode, deadline).await
            }
            .await;
            match result {
                Ok(terminal) => Ok(PushOutcome::Terminal(terminal)),
                Err(error @ GatewayError::Conflict(_)) => {
                    // Only a definite conflict is eligible. Unknown COMMIT,
                    // timeout and provider failures keep their original outcome.
                    match authorized(state)?
                        .reject_superseded_serving(state.pool(), &token, &plan, actor, request_digest, deadline)
                        .await
                        .map_err(map_authorized)?
                    {
                        Some(terminal) => Ok(PushOutcome::Terminal(terminal)),
                        None => Err(error),
                    }
                }
                Err(error) => Err(error),
            }
        }
    }
}

async fn repository_owner(state: &BlobGitState, repository_id: Uuid, deadline: Instant) -> Result<Uuid, GatewayError> {
    let client = state.pooled(deadline).await?;
    let row =
        timeout_at(deadline, client.query_opt("SELECT owner_id FROM repositories WHERE id=$1", &[&repository_id]))
            .await
            .map_err(|_| GatewayError::Timeout)?
            .map_err(|_| GatewayError::Internal("repository owner read failed"))?
            .ok_or(GatewayError::NotFound)?;
    Ok(row.get(0))
}

/// The original authorized realm must survive every baseline recapture. A
/// rebase may follow a newer revision, ref set and pack membership set, but it
/// must never follow a different repository history, authority epoch, group
/// epoch, tenant or object format.
fn admission_realm_matches_serving(baseline: &PackCommitBaseline, serving: &ServingRepository) -> bool {
    let gate = baseline.gate();
    let authorized = &serving.gate;
    gate.repository_id() == authorized.repository_id()
        && gate.tenant_id() == authorized.tenant_id()
        && gate.object_format() == authorized.object_format()
        && gate.history_incarnation() == authorized.history_incarnation()
        && gate.authority_epoch() == authorized.authority_epoch()
        && gate.group_epoch() == authorized.group_epoch()
}

/// Only the exact typed refusal raised by `ensure_gate_matches` inside the
/// freshly created pending prefix is eligible for a rebase. It can only be
/// produced after `begin_fresh` observed `Lookup::Unknown` while holding the
/// operation advisory lock in that same transaction, so no pending row can
/// already exist for this operation. Every other refusal (cancellation,
/// already verified, history/authority/mode, digest, ambiguity, timeout,
/// provider or permission error) keeps its original outcome.
fn is_rolled_back_revision_mismatch(error: &PackCommitError) -> bool {
    matches!(
        error,
        PackCommitError::Rejected(rejection)
            if rejection.code == PackCommitRejectCode::RevisionMismatch
                && rejection.detail == GATE_REVISION_MISMATCH_DETAIL
    )
}

#[allow(clippy::too_many_arguments)]
async fn begin(
    state: &BlobGitState,
    serving: &ServingRepository,
    actor: &Identity,
    operation_id: Uuid,
    request_digest: RequestDigest,
    request: &PushRequest,
    pairs: &[Pair],
    mode: CommitMode,
    owner: Uuid,
    baseline: &PackCommitBaseline,
    deadline: Instant,
) -> Result<Start, GatewayError> {
    let repository_id = baseline.gate().repository_id();
    match operation::lookup(state, serving, actor, operation_id, deadline).await? {
        operation::Lookup::Known(resolved) => start_from_claim(operation::classify(
            resolved,
            repository_id,
            actor.id,
            operation_id,
            request,
            request_digest,
        )?),
        // The authorized probe saw no operation row. A concurrent identical
        // retry can still commit this operation id between that probe and here,
        // so the sequence reservation, the re-check of the operation plus its
        // migration-147 producer binding, the pending row and the binding are
        // all decided in one fresh transaction below.
        operation::Lookup::Unknown => {
            begin_fresh(state, actor, operation_id, request_digest, request, pairs, mode, owner, baseline, deadline)
                .await
        }
    }
}

/// Crate-private entry for the migration-152 private-slot admission mode.
///
/// The public UUID and producer digest remain the caller-visible operation
/// identity. The public preflight and the coordinator's lock, receipts and
/// captured authorized baseline are all migration-152 objects; this entry never
/// enters the legacy operation lookup for an unknown or privately claimed
/// public identifier. Only an explicit `LegacyPath` marker may use the older
/// legacy lookup, in the same authenticated transaction and under its operation
/// key. A private admission refusal, an unsupported Foundation or an unknown
/// private `COMMIT` is returned as-is: this entry never calls [`begin_fresh`].
///
/// The caller must already have captured `baseline` after native ingestion and
/// hold the staged raw pack pairs. This function performs only the short
/// PostgreSQL preflight/admission; it holds no transaction while reading or
/// uploading a pair.
#[allow(dead_code)] // No route selects private mode until the GET/replay/cancel paths are ready.
#[allow(clippy::too_many_arguments)]
pub(super) async fn begin_slot_zero(
    state: &BlobGitState,
    serving: &ServingRepository,
    actor: &Identity,
    public_id: Uuid,
    request_digest: RequestDigest,
    request: &PushRequest,
    pairs: &[Pair],
    mode: CommitMode,
    baseline: &PackCommitBaseline,
    deadline: Instant,
) -> Result<Start, GatewayError> {
    let private_id = Uuid::new_v4();
    let backend_identity = state.store().backend_identity().as_hex().to_owned();
    let public_request =
        public_attempt_request(serving, actor, public_id, request_digest, mode, baseline, backend_identity)?;
    let lane = IssuerLane::new(ISSUER_LANE).map_err(ref_error)?;

    let mut client = state.pooled(deadline).await?;
    let tx = match timeout_at(deadline, client.transaction()).await {
        Ok(Ok(tx)) => tx,
        Ok(Err(_)) => return Err(GatewayError::Internal("private admission transaction failed")),
        Err(_) => return Err(GatewayError::Timeout),
    };
    let preflight = timeout_at(
        deadline,
        slot_zero_public_preflight(
            &tx,
            serving,
            actor,
            &public_request,
            state.store().backend_identity(),
            &lane,
            private_id,
            request,
            baseline,
            deadline,
        ),
    )
    .await;
    match preflight {
        Ok(Ok(SlotZeroPreflight::Fresh(public_request))) => {
            // Keep the same owning transaction: current user/role/token,
            // namespace, restore and realm were just validated under its locks,
            // and the migration-152 admission must publish or roll back with
            // those exact locks. No Git/Blob IO occurs in this transaction.
            begin_slot_zero_fresh(tx, request, pairs, mode, baseline, public_request, private_id, deadline).await
        }
        Ok(Ok(SlotZeroPreflight::Claim(claim))) => {
            rollback_deadpool_bounded(tx, deadline).await?;
            start_from_claim(claim)
        }
        Ok(Err(error)) => {
            // Every branch above returned a typed refusal, not a legacy
            // fallback. The transaction has no publishable admission; keep the
            // typed error if best-effort cleanup is unconfirmed.
            let _ = rollback_deadpool_bounded(tx, deadline).await;
            Err(error)
        }
        Err(_) => {
            let _ = rollback_deadpool_bounded(tx, deadline).await;
            Err(GatewayError::Timeout)
        }
    }
}

/// Read-only classification made under the public/operation locks before any
/// lane or authority lock. It only selects the lock order; the authenticated
/// lookup below makes the final decision.
#[derive(Clone, Copy, Eq, PartialEq)]
enum SlotZeroRoute {
    Replay,
    Fresh,
}

/// What the authenticated public preflight found for this public UUID.
enum SlotZeroPreflight {
    /// No wrapper, private claim or legacy operation exists. The typed request
    /// is carried forward for the fresh migration-152 admission.
    Fresh(PublicAttemptRequest),
    /// An exact wrapper attempt or an explicit legacy-path record was resolved.
    Claim(Claim),
}

/// One authenticated, lock-ordered public preflight in the caller's transaction.
///
/// Order is fixed and enforced under the public/attempt and migration-138
/// operation locks: a read-only public precheck; for an exact `Unknown`, the
/// issuer lane is locked or its zero row created; then live serving authority
/// (token/role/scope/restore/realm/binding/backend) and the final public lookup.
/// A known replay never locks or creates the lane, so an exhausted lane cannot
/// overflow and no allocation is observable. The fresh lane is held before any
/// repository/binding/gate read and advances no sequence; the slot-zero
/// coordinator previews/advances it later. A moved restore/realm is a conflict,
/// never a silently adopted realm.
///
/// Exits are closed: only the fresh precheck may become fresh after
/// authentication, and then keeps this transaction for admission; a replay
/// precheck that becomes `Unknown` returns its precheck error; wrapper evidence
/// resolves in this transaction then rolls back; `PrivateIdentifier` is a
/// conflict; `LegacyPath` is the only branch that calls the older legacy lookup
/// and only under the already-held operation key; mixed/corrupt evidence returns
/// a typed error. No branch falls through to the legacy fresh writer.
#[allow(clippy::too_many_arguments)]
async fn slot_zero_public_preflight(
    tx: &deadpool_postgres::Transaction<'_>,
    serving: &ServingRepository,
    actor: &Identity,
    public_request: &PublicAttemptRequest,
    backend_identity: &crate::blob_store::BlobBackendIdentity,
    lane: &IssuerLane,
    private_id: Uuid,
    request: &PushRequest,
    baseline: &PackCommitBaseline,
    deadline: Instant,
) -> Result<SlotZeroPreflight, GatewayError> {
    let repository_id = baseline.gate().repository_id();
    PgRefStore.lock_public_attempt(&**tx, public_request, private_id, deadline).await.map_err(GatewayError::from)?;
    crate::ref_store::pg::lock_operation(&**tx, repository_id, public_request.public_id, deadline)
        .await
        .map_err(GatewayError::from)?;

    // Classify under the public/operation locks before touching any lane or
    // authority lock. A wrapper/private/legacy hit, or a malformed/restore
    // mismatch, is a known replay route and must stay read-only. Only an exact
    // `Unknown` may create/lock the lane before repository/binding locks.
    let preliminary = PgRefStore.lookup_public_attempt(&**tx, public_request, deadline).await;
    let (route, precheck_error) = match preliminary {
        Ok(PublicAttemptLookup::Unknown) => (SlotZeroRoute::Fresh, None),
        Ok(_) => (SlotZeroRoute::Replay, None),
        Err(error) => (SlotZeroRoute::Replay, Some(GatewayError::from(error))),
    };

    if route == SlotZeroRoute::Fresh {
        // Strict order for an authorized fresh attempt: public/operation locks
        // are held, then the lane is locked or its zero row is created. The
        // helper never computes `+1`, so a replay never reaches it and cannot
        // overflow an exhausted lane. A concurrent first insert is waited out by
        // ON CONFLICT before any repository/binding read.
        PgRefStore
            .lock_or_create_expected_lane(&**tx, repository_id, actor.id, lane, deadline)
            .await
            .map_err(GatewayError::from)?;
    }

    // Authorization and the live restore/realm fence still run in this same
    // transaction. On a fresh route the lane is already held; on replay no lane
    // or sequence effect exists to leak if this refuses.
    let fresh = crate::ref_store::serving::lookup_in_tx(
        tx,
        actor,
        &serving.repository.owner,
        &serving.repository.name,
        true,
        backend_identity,
        deadline,
    )
    .await
    .map_err(GatewayError::from)?;
    if fresh.gate.repository_id() != repository_id
        || crate::ref_store::core::RealmExpectation::from_gate(&fresh.gate)
            != crate::ref_store::core::RealmExpectation::from_gate(&serving.gate)
        || !admission_realm_matches_serving(baseline, &fresh)
        || fresh.cluster_incarnation != public_request.restore_incarnation
    {
        return Err(GatewayError::Conflict("repository authority changed; retry"));
    }

    // Final lookup after authentication (and, for fresh, after the lane lock)
    // supplies the exact restore-scoped evidence. A replay route can never
    // become fresh here; a fresh route that resolves to a known/malformed result
    // rolls back the provisionally created lane with the outer transaction.
    let final_lookup =
        PgRefStore.lookup_public_attempt(&**tx, public_request, deadline).await.map_err(GatewayError::from)?;

    match final_lookup {
        PublicAttemptLookup::Unknown if route == SlotZeroRoute::Fresh => {
            Ok(SlotZeroPreflight::Fresh(public_request.clone()))
        }
        PublicAttemptLookup::Unknown => Err(precheck_error.unwrap_or(GatewayError::Internal(
            "replay route resolved to an unknown public operation after authentication",
        ))),
        PublicAttemptLookup::PrivateIdentifier => {
            Err(GatewayError::Conflict("operation identifier is already a private attempt"))
        }
        PublicAttemptLookup::LegacyPath => {
            // Explicitly authorized compatibility branch. The migration-152
            // lookup proved there is no wrapper or private claim for this UUID;
            // the migration-138 key is already held, so the guarded legacy
            // lookup can resolve only its own durable record.
            match operation::lookup_in_tx(&**tx, repository_id, public_request.public_id, deadline).await? {
                operation::Lookup::Known(resolved) => Ok(SlotZeroPreflight::Claim(operation::classify(
                    resolved,
                    repository_id,
                    actor.id,
                    public_request.public_id,
                    request,
                    public_request.wire_digest,
                )?)),
                operation::Lookup::Unknown => {
                    Err(GatewayError::Internal("legacy public marker has no durable operation record"))
                }
            }
        }
        PublicAttemptLookup::Pending(evidence)
        | PublicAttemptLookup::Committed(evidence)
        | PublicAttemptLookup::Rejected(evidence)
        | PublicAttemptLookup::Cancelled(evidence) => Ok(SlotZeroPreflight::Claim(
            operation::lookup_public_private_in_tx(
                &**tx,
                public_request,
                &evidence,
                request,
                public_request.wire_digest,
                deadline,
            )
            .await?,
        )),
    }
}

/// One fresh slot-zero admission transaction against the reviewed migration-152
/// coordinator.
///
/// The request was constructed before the public preflight and carries the exact
/// issuer/lane realm, authorized restore incarnation and opened Blob backend.
/// The plan builder receives the locked preview and reuses the same canonical
/// [`build_plan_core`] as the legacy transaction, so HEAD/ref and same-ref
/// atomic/subset rules are not reimplemented here.
///
/// A preview whose revision differs from the captured baseline is a typed
/// revision refusal. `admit_slot_zero_in_tx` rolls the savepoint back and
/// releases it; this adapter then requires an acknowledged outer rollback
/// before returning [`Start::Rebaseline`]. No raw pair is read, no private UUID
/// is written to an operation header, and an unknown `COMMIT` is mapped to the
/// existing generic gateway outcome.
#[allow(clippy::too_many_arguments)]
async fn begin_slot_zero_fresh(
    mut tx: deadpool_postgres::Transaction<'_>,
    request: &PushRequest,
    pairs: &[Pair],
    mode: CommitMode,
    baseline: &PackCommitBaseline,
    public_request: PublicAttemptRequest,
    private_id: Uuid,
    deadline: Instant,
) -> Result<Start, GatewayError> {
    let admission = slot_zero_admission_request(&public_request, private_id)?;

    // Keep the authenticated deadpool transaction as the owner. The helper gets
    // one mutable borrow of its tokio transaction and returns only owned data,
    // so every savepoint, result and future is dropped before this function
    // moves `tx` into the single outer COMMIT or ROLLBACK below. No connection
    // or transaction is split.
    let disposition = slot_zero_fresh_scope(
        &mut tx,
        &admission,
        request,
        pairs,
        mode,
        baseline,
        &public_request,
        private_id,
        deadline,
    )
    .await;

    match disposition {
        SlotZeroFreshDisposition::Commit { token, plan } => {
            // The gateway savepoint was already released inside the scope; this
            // is the one outer durability point and the public UUID stays the
            // stable operation header.
            commit_deadpool_bounded(tx, deadline).await?;
            Ok(Start::Fresh { _token: token, plan })
        }
        SlotZeroFreshDisposition::Replay { claim, savepoint_cleanup } => {
            // Preserve the proven replay cleanup ordering and error precedence:
            // resolve the claim, acknowledge the savepoint rollback, then roll
            // back the outer owner; the claim error outranks cleanup errors.
            let outer_cleanup = rollback_deadpool_bounded(tx, deadline).await;
            let claim = claim?;
            savepoint_cleanup?;
            outer_cleanup?;
            start_from_claim(claim)
        }
        SlotZeroFreshDisposition::Rebaseline => {
            // A rebase is safe only after the whole owned transaction is
            // acknowledged as rolled back.
            rollback_deadpool_bounded(tx, deadline).await?;
            Ok(Start::Rebaseline)
        }
        SlotZeroFreshDisposition::Refused(error) => {
            // The savepoint (if any) was already consumed by the scope. Keep the
            // typed answer if best-effort outer cleanup is unconfirmed, exactly
            // like `begin_fresh`.
            let _ = rollback_deadpool_bounded(tx, deadline).await;
            Err(error)
        }
    }
}

/// One owned disposition from the savepoint-scoped half of a fresh slot-zero
/// admission.
///
/// Every variant is produced only after the savepoint, its admission result and
/// all borrowed futures have been dropped. The caller still owns the
/// authenticated transaction and performs its one outer `COMMIT` or `ROLLBACK`.
enum SlotZeroFreshDisposition {
    /// The gateway savepoint was released. The outer `COMMIT` is the sole
    /// durability point.
    Commit { token: PackPendingToken, plan: Box<PackCommitPlan> },
    /// An exact public replay was resolved. `claim` carries the typed lookup
    /// result and `savepoint_cleanup` its savepoint rollback acknowledgement;
    /// the outer owner must still roll back.
    Replay { claim: Result<Claim, GatewayError>, savepoint_cleanup: Result<(), GatewayError> },
    /// The captured revision was already superseded and the savepoint was
    /// rolled back. A rebase is allowed only after the outer rollback is
    /// acknowledged.
    Rebaseline,
    /// The typed answer to keep after the outer owner's best-effort rollback.
    Refused(GatewayError),
}

/// Run the savepoint-scoped half of one fresh slot-zero admission.
///
/// This function borrows the authenticated transaction only through `tx`. It
/// creates the gateway savepoint, hands it to the migration-152 coordinator,
/// consumes every returned savepoint/rollback/future, and drops all of them
/// before returning an owned disposition. The caller therefore remains free to
/// move the outer owner into exactly one `COMMIT` or `ROLLBACK`.
#[allow(clippy::too_many_arguments)]
async fn slot_zero_fresh_scope(
    tx: &mut tokio_postgres::Transaction<'_>,
    admission: &SlotZeroAdmissionRequest,
    request: &PushRequest,
    pairs: &[Pair],
    mode: CommitMode,
    baseline: &PackCommitBaseline,
    public_request: &PublicAttemptRequest,
    private_id: Uuid,
    deadline: Instant,
) -> SlotZeroFreshDisposition {
    let repository_id = public_request.repository_id;
    let savepoint =
        match timeout_at(deadline, tokio_postgres::Transaction::savepoint(&mut *tx, GATEWAY_SLOT_ZERO_SAVEPOINT)).await
        {
            Ok(Ok(savepoint)) => savepoint,
            Ok(Err(_)) => {
                return SlotZeroFreshDisposition::Refused(GatewayError::Internal(
                    "slot zero admission savepoint failed",
                ));
            }
            Err(_) => return SlotZeroFreshDisposition::Refused(GatewayError::Timeout),
        };

    let mut built = None;
    let outcome = timeout_at(
        deadline,
        PgRefStore.admit_slot_zero_in_tx(
            savepoint,
            admission,
            |preview| {
                let plan = build_slot_zero_plan(
                    request,
                    pairs,
                    mode,
                    admission.admission_owner_id,
                    admission.issuer_id,
                    baseline,
                    private_id,
                    public_request.wire_digest,
                    preview.sequence(),
                    preview.base_revision(),
                )?;
                built = Some(plan.clone());
                Ok(plan)
            },
            deadline,
        ),
    )
    .await;
    let (savepoint, admission_result) = match outcome {
        Ok(Ok(admission)) => admission.into_parts(),
        // The coordinator owns and drops the savepoint on an inner fatal or
        // uncertain error; only the outer transaction remains and is rolled
        // back by the caller.
        Ok(Err(error)) => {
            return SlotZeroFreshDisposition::Refused(GatewayError::from(error));
        }
        Err(_) => return SlotZeroFreshDisposition::Refused(GatewayError::Timeout),
    };

    match admission_result {
        Ok(receipt) if receipt.replayed => {
            // Exact public replay: no plan was built and no sequence, wrapper or
            // operation write occurred. Resolve the stored private operation
            // through the same verified public evidence, never the legacy
            // private-id lookup, then roll back the savepoint. The caller rolls
            // back the outer owner.
            let claim =
                replay_slot_zero_claim(&savepoint, public_request, request, public_request.wire_digest, deadline)
                    .await;
            let savepoint_cleanup = rollback_bounded(savepoint, deadline).await;
            SlotZeroFreshDisposition::Replay { claim, savepoint_cleanup }
        }
        Ok(receipt) => {
            let Some(plan) = built else {
                let _ = rollback_bounded(savepoint, deadline).await;
                return SlotZeroFreshDisposition::Refused(GatewayError::Internal(
                    "slot zero admission did not build its plan",
                ));
            };
            if receipt.state != OperationState::Pending
                || receipt.public_id != public_request.public_id
                || receipt.private_id != private_id
                || receipt.private_id != plan.identity().operation_id()
                || receipt.sequence != plan.identity().sequence()
                || receipt.base_revision != plan.expected().revision()
                || receipt.plan_digest != *plan.parent_digest()
            {
                let _ = rollback_bounded(savepoint, deadline).await;
                return SlotZeroFreshDisposition::Refused(GatewayError::Internal(
                    "slot zero admission receipt differs from its plan",
                ));
            }
            // The token is only the opaque plan identity the existing prepare
            // path consumes; it carries no additional authority. Mint it before
            // COMMIT so a successful admission cannot fail on a local shaping
            // error after the durability point.
            let token = match PackPendingToken::established(
                repository_id,
                plan.tenant_id(),
                receipt.private_id,
                receipt.plan_digest,
            ) {
                Ok(token) => token,
                Err(error) => {
                    let _ = rollback_bounded(savepoint, deadline).await;
                    return SlotZeroFreshDisposition::Refused(GatewayError::from(error));
                }
            };
            // Release the gateway savepoint; the caller's outer COMMIT is the
            // only durability point. The public UUID is the stable operation
            // header; the private UUID never enters the COMMIT-unknown identity.
            match commit_bounded(savepoint, deadline, repository_id, Some(public_request.public_id)).await {
                Ok(()) => SlotZeroFreshDisposition::Commit { token, plan: Box::new(plan) },
                Err(error) => SlotZeroFreshDisposition::Refused(ref_error(error)),
            }
        }
        Err(error) if is_rolled_back_revision_mismatch(&error) => {
            let _ = rollback_bounded(savepoint, deadline).await;
            SlotZeroFreshDisposition::Rebaseline
        }
        Err(error) => {
            // The coordinator has already rolled back and released its nested
            // savepoint. The gateway savepoint and outer transaction are a
            // definite non-success; keep the typed answer if best-effort
            // cleanup is unconfirmed, exactly like `begin_fresh`.
            let _ = rollback_bounded(savepoint, deadline).await;
            SlotZeroFreshDisposition::Refused(GatewayError::from(error))
        }
    }
}

/// Construct the exact typed public request from the authorized serving realm
/// and the captured base baseline.
///
/// `admission_owner_id` is the owner/tenant UUID proven by the authorized
/// serving lookup, never the actor or a caller-supplied tenant. The restore
/// incarnation comes from the same authorized lookup; the coordinator re-locks
/// the live singleton before any fresh write.
#[allow(clippy::too_many_arguments)]
fn public_attempt_request(
    serving: &ServingRepository,
    actor: &Identity,
    public_id: Uuid,
    wire_digest: RequestDigest,
    request_mode: CommitMode,
    baseline: &PackCommitBaseline,
    backend_identity: String,
) -> Result<PublicAttemptRequest, GatewayError> {
    if !admission_realm_matches_serving(baseline, serving) {
        return Err(GatewayError::Conflict("repository authority changed; retry"));
    }
    let gate = baseline.gate();
    Ok(PublicAttemptRequest {
        repository_id: gate.repository_id(),
        admission_owner_id: gate.tenant_id(),
        issuer_id: actor.id,
        public_id,
        wire_digest,
        request_mode,
        backend_identity,
        object_format: gate.object_format(),
        history_incarnation: gate.history_incarnation(),
        authority_epoch: gate.authority_epoch(),
        group_epoch: gate.group_epoch(),
        restore_incarnation: serving.cluster_incarnation,
    })
}

/// Add the private slot identity to an already validated public request. Both
/// migration-152 records are populated from this one typed source, so the
/// wrapper and private attempt cannot diverge on realm or wiring fields.
fn slot_zero_admission_request(
    public: &PublicAttemptRequest,
    private_id: Uuid,
) -> Result<SlotZeroAdmissionRequest, GatewayError> {
    let lane = IssuerLane::new(ISSUER_LANE).map_err(ref_error)?;
    Ok(SlotZeroAdmissionRequest {
        repository_id: public.repository_id,
        admission_owner_id: public.admission_owner_id,
        issuer_id: public.issuer_id,
        lane,
        public_id: public.public_id,
        private_id,
        wire_digest: public.wire_digest,
        request_mode: public.request_mode,
        backend_identity: public.backend_identity.clone(),
        object_format: public.object_format,
        history_incarnation: public.history_incarnation,
        authority_epoch: public.authority_epoch,
        group_epoch: public.group_epoch,
        restore_incarnation: public.restore_incarnation,
    })
}

/// Build the canonical plan from the locked slot-zero preview.
///
/// This is the exact adapter between the coordinator preview and the existing
/// plan builder. It refuses before plan construction when the preview revision
/// is not the captured baseline revision, so a stale candidate can only become
/// the typed rollback-then-recapture answer. It otherwise constructs the
/// private `OperationIdentity` with the locked sequence/private UUID and calls
/// [`build_plan_core`] unchanged.
#[allow(clippy::too_many_arguments)]
fn build_slot_zero_plan(
    request: &PushRequest,
    pairs: &[Pair],
    mode: CommitMode,
    owner: Uuid,
    issuer_id: Uuid,
    baseline: &PackCommitBaseline,
    private_id: Uuid,
    wire_digest: RequestDigest,
    sequence: i64,
    preview_base_revision: i64,
) -> Result<PackCommitPlan, PackCommitError> {
    if preview_base_revision != baseline.gate().revision() {
        return Err(PackCommitError::Rejected(PackCommitRejection::new(
            PackCommitRejectCode::RevisionMismatch,
            GATE_REVISION_MISMATCH_DETAIL,
        )));
    }
    let identity = OperationIdentity::new(
        baseline.gate().repository_id(),
        issuer_id,
        IssuerLane::new(ISSUER_LANE).map_err(PackCommitError::from)?,
        sequence,
        private_id,
        wire_digest,
    )
    .map_err(PackCommitError::from)?;
    build_plan_core(request, pairs, mode, owner, baseline, identity)
}

/// Resolve one exact slot-zero replay through the verified public evidence.
/// No legacy operation lookup is used: the public attempt lookup re-proves the
/// wrapper/attempt, then the separately scoped internal helper reads the exact
/// private record under the already-held migration-152 lock.
async fn replay_slot_zero_claim(
    tx: &tokio_postgres::Transaction<'_>,
    public_request: &PublicAttemptRequest,
    request: &PushRequest,
    request_digest: RequestDigest,
    deadline: Instant,
) -> Result<Claim, GatewayError> {
    let evidence =
        match PgRefStore.lookup_public_attempt(tx, public_request, deadline).await.map_err(GatewayError::from)? {
            PublicAttemptLookup::Pending(evidence)
            | PublicAttemptLookup::Committed(evidence)
            | PublicAttemptLookup::Rejected(evidence)
            | PublicAttemptLookup::Cancelled(evidence) => evidence,
            PublicAttemptLookup::Unknown | PublicAttemptLookup::PrivateIdentifier | PublicAttemptLookup::LegacyPath => {
                return Err(GatewayError::Internal("slot zero replay evidence is not a verified public attempt"));
            }
        };
    operation::lookup_public_private_in_tx(tx, public_request, &evidence, request, request_digest, deadline).await
}

/// What one fresh-write transaction decided about this operation identity.
enum Reserved {
    /// The operation already existed when this transaction re-checked it; the
    /// reservation is rolled back unused and the answer comes from that durable
    /// state alone.
    Known(Claim),
    /// The freshly created pending prefix saw the locked gate advance between
    /// the captured baseline and this transaction. Nothing was committed, so
    /// the caller may recapture and rebuild.
    Rebaseline,
    /// This transaction created the pending row *and* its producer binding; only
    /// `COMMIT` may publish the reserved sequence, the pending row and the
    /// binding together.
    Created { _token: PackPendingToken, plan: Box<PackCommitPlan> },
}

/// Reserve the identity sequence, re-check the operation and atomically create
/// the pending row plus its producer binding in **one** caller-owned
/// transaction.
///
/// Same-identity concurrent retries serialize on the migration-138 operation
/// advisory key that `reserve_sequence` takes before touching the issuer lane,
/// so the loser blocks, then re-reads the winner's committed operation inside
/// its own transaction. It answers from that durable state (exact pending =>
/// unknown, exact terminal/tombstone => replay, different wire bytes =>
/// conflict) after rolling its own unused reservation back: no second sequence
/// is charged and the loser's own derived identity can never surface as an
/// `IdentityConflict`.
///
/// Only `Created` is committed. Every other outcome and every error rolls this
/// transaction back under the original deadline. The transaction is finished
/// before any Blob/native work, so no PostgreSQL transaction is held across
/// provider or native Git IO.
#[allow(clippy::too_many_arguments)]
async fn begin_fresh(
    state: &BlobGitState,
    actor: &Identity,
    operation_id: Uuid,
    request_digest: RequestDigest,
    request: &PushRequest,
    pairs: &[Pair],
    mode: CommitMode,
    owner: Uuid,
    baseline: &PackCommitBaseline,
    deadline: Instant,
) -> Result<Start, GatewayError> {
    let repository_id = baseline.gate().repository_id();
    let lane = IssuerLane::new(ISSUER_LANE).map_err(ref_error)?;
    let mut client = state.pooled(deadline).await?;
    let tx = begin_bounded(&mut client, deadline).await.map_err(ref_error)?;
    let staged = match timeout_at(deadline, async {
        // The trusted gateway caller owns acknowledgment durability for this
        // transaction: neither the pending row nor its producer binding may be
        // acknowledged before the WAL flush.
        tx.execute("SET LOCAL synchronous_commit = 'on'", &[])
            .await
            .map_err(|_| GatewayError::Internal("pending operation durability could not be requested"))?;
        let sequence = PgRefStore
            .reserve_sequence(&tx, repository_id, actor.id, operation_id, &lane, deadline)
            .await
            .map_err(ref_error)?;
        // Re-check inside the same transaction, now serialized by the operation
        // advisory key taken above. A row created by a concurrent identical
        // retry is always visible here.
        match operation::lookup_in_tx(&tx, repository_id, operation_id, deadline).await? {
            operation::Lookup::Known(resolved) => Ok(Reserved::Known(operation::classify(
                resolved,
                repository_id,
                actor.id,
                operation_id,
                request,
                request_digest,
            )?)),
            operation::Lookup::Unknown => {
                let identity = OperationIdentity::new(
                    repository_id,
                    actor.id,
                    lane.clone(),
                    sequence.sequence(),
                    operation_id,
                    request_digest,
                )
                .map_err(ref_error)?;
                // The plan keeps its ORIGINAL core parent digest: the A3/A4
                // identity invariant (`identity.digest() == parent_digest` ==
                // every receipt) is never relabelled with the HTTP wire digest.
                // The durable producer value stays in its own migration-147 row,
                // written by the core adapter in this same transaction.
                let plan = build_plan(request, pairs, mode, owner, baseline, identity)?;
                let token = match PgPackCommit.begin_serving_pending_in_tx(&tx, &plan, request_digest, deadline).await {
                    Ok(token) => token,
                    Err(error) if is_rolled_back_revision_mismatch(&error) => {
                        // The pending prefix was created by this transaction and
                        // the gate check failed before `COMMIT`; the caller rolls
                        // the whole transaction back below. No admission exists.
                        return Ok(Reserved::Rebaseline);
                    }
                    Err(error) => return Err(GatewayError::from(error)),
                };
                Ok(Reserved::Created { _token: token, plan: Box::new(plan) })
            }
        }
    })
    .await
    {
        Ok(staged) => staged,
        Err(_) => Err(GatewayError::Timeout),
    };
    match staged {
        Ok(Reserved::Created { _token, plan }) => {
            commit_bounded(tx, deadline, repository_id, Some(operation_id)).await.map_err(ref_error)?;
            Ok(Start::Fresh { _token, plan })
        }
        Ok(Reserved::Rebaseline) => {
            // The transaction contains no publishable admission. A rebase is
            // allowed only after the rollback itself is acknowledged; an
            // unknown cleanup outcome stays an error instead of being retried.
            rollback_bounded(tx, deadline).await?;
            Ok(Start::Rebaseline)
        }
        Ok(Reserved::Known(claim)) => {
            let _ = rollback_bounded(tx, deadline).await;
            start_from_claim(claim)
        }
        Err(error) => {
            let _ = rollback_bounded(tx, deadline).await;
            Err(error)
        }
    }
}

/// Bounded rollback of a caller-owned transaction. A rebase requires the
/// acknowledged success; callers that already have a definite non-retryable
/// answer may keep that answer if cleanup itself is unconfirmed.
async fn rollback_bounded(tx: tokio_postgres::Transaction<'_>, deadline: Instant) -> Result<(), GatewayError> {
    match timeout_at(deadline, tx.rollback()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(GatewayError::Internal("admission rollback was not acknowledged")),
        Err(_) => Err(GatewayError::Timeout),
    }
}

/// Bounded rollback of the gateway-owned deadpool transaction. The tokio
/// savepoint is always consumed first, so this is the real outer cleanup.
async fn rollback_deadpool_bounded(
    tx: deadpool_postgres::Transaction<'_>,
    deadline: Instant,
) -> Result<(), GatewayError> {
    match timeout_at(deadline, tx.rollback()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) => Err(GatewayError::Internal("admission rollback was not acknowledged")),
        Err(_) => Err(GatewayError::Timeout),
    }
}

/// Commit the real outer transaction after the gateway savepoint was released.
/// An unacknowledged COMMIT is the existing generic unknown outcome and never
/// carries the private UUID.
async fn commit_deadpool_bounded(
    tx: deadpool_postgres::Transaction<'_>,
    deadline: Instant,
) -> Result<(), GatewayError> {
    if Instant::now() >= deadline {
        let _ = timeout_at(Instant::now() + std::time::Duration::from_secs(2), tx.rollback()).await;
        return Err(GatewayError::Timeout);
    }
    match timeout_at(deadline, tx.commit()).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(_)) | Err(_) => Err(GatewayError::OutcomeUnknown),
    }
}

fn start_from_claim(claim: Claim) -> Result<Start, GatewayError> {
    match claim {
        Claim::Pending => Err(GatewayError::OutcomeUnknown),
        Claim::Cancelled(reason) => Ok(Start::Cancelled(reason)),
        Claim::Replay(terminal) => Ok(Start::Terminal(terminal)),
        Claim::Fresh => Err(GatewayError::Internal("known operation was classified as fresh")),
    }
}

fn build_plan(
    request: &PushRequest,
    pairs: &[Pair],
    mode: CommitMode,
    owner: Uuid,
    baseline: &PackCommitBaseline,
    identity: OperationIdentity,
) -> Result<PackCommitPlan, GatewayError> {
    build_plan_core(request, pairs, mode, owner, baseline, identity).map_err(GatewayError::from)
}

/// Single canonical plan builder shared by the legacy fresh transaction and the
/// crate-private slot-zero adapter. Keeping this typed lets the private
/// admission callback return `PackCommitError` without re-wrapping or
/// reimplementing any HEAD, ref, membership, pack or same-ref rule.
fn build_plan_core(
    request: &PushRequest,
    pairs: &[Pair],
    mode: CommitMode,
    owner: Uuid,
    baseline: &PackCommitBaseline,
    identity: OperationIdentity,
) -> Result<PackCommitPlan, PackCommitError> {
    let gate = baseline.gate();
    let format = gate.object_format();
    let mut refs = Vec::with_capacity(request.commands.len());
    for command in &request.commands {
        let name = RefName::new(command.name.clone()).map_err(PackCommitError::from)?;
        let precondition = GitOid::precondition_value(format, &command.old).map_err(PackCommitError::from)?;
        let target = GitOid::target_value(format, &command.new).map_err(PackCommitError::from)?;
        refs.push(RefUpdate::new(name, precondition, target));
    }
    let current_head = gate.head_ref().as_str();
    let head_exists = baseline.refs().iter().any(|reference| reference.name() == current_head);
    let head = if head_exists {
        HeadUpdate::Keep
    } else if let Some(branch) =
        request.commands.iter().find(|command| command.name.starts_with("refs/heads/") && !command.is_delete())
    {
        HeadUpdate::retarget(branch.name.clone()).map_err(PackCommitError::from)?
    } else {
        HeadUpdate::Keep
    };
    let old_memberships =
        baseline.old_packs().iter().map(PackMembershipEntry::from_pack).collect::<Result<Vec<_>, _>>()?;
    let mut planned = Vec::with_capacity(pairs.len());
    for pair in pairs {
        let registration_id = derived_uuid("registration-id", identity.operation_id(), pair.pack_sha.as_bytes());
        planned.push(PlannedPack::new(
            pair.pack_id,
            registration_id,
            PlannedArtifact::new(PackArtifactRole::Pack, ContentDigest::parse(pair.pack_sha.clone())?, pair.pack_len)?,
            PlannedArtifact::new(PackArtifactRole::Idx, ContentDigest::parse(pair.idx_sha.clone())?, pair.idx_len)?,
        )?);
    }
    let scope = PackCommitScope::new(
        gate.repository_id(),
        gate.tenant_id(),
        owner,
        format,
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )?;
    let expectation = PackCommitExpectation::new(gate.revision(), *gate.digest(), baseline.mode())?;
    let plan = PackCommitPlan::new_with_mode(
        scope,
        identity,
        expectation,
        head,
        refs,
        baseline.membership_digest(),
        old_memberships,
        planned,
        mode,
    )?;
    ensure_pack_terminal_budget(&plan).map_err(|_| PackCommitError::Capacity {
        limit: "terminal_budget",
        bound: MAX_ACK_BODY_BYTES as i64,
        actual: plan.refs().len() as i64,
    })?;
    Ok(plan)
}

async fn publish_pair(
    state: &BlobGitState,
    plan: &PackCommitPlan,
    pack_id: Uuid,
    pair: &Pair,
    deadline: Instant,
) -> Result<(), GatewayError> {
    let scope = HoldScope::new(
        plan.repository_id(),
        plan.tenant_id(),
        plan.owner_id(),
        ArtifactHoldPurpose::RefPublication,
        plan.object_format(),
        plan.history_incarnation(),
        plan.authority_epoch(),
        plan.group_epoch(),
    )
    .map_err(|_| GatewayError::Internal("artifact hold scope is invalid"))?;
    let request_id = derived_uuid("hold-request", plan.identity().operation_id(), pair.pack_sha.as_bytes());
    let authority_id = derived_uuid("hold-authority", plan.identity().operation_id(), b"");
    let specs = vec![
        ArtifactSpec::new(HOLD_NAMESPACE, pair.pack_sha.clone(), pair.pack_len)
            .map_err(|_| GatewayError::Internal("pack artifact specification is invalid"))?,
        ArtifactSpec::new(HOLD_NAMESPACE, pair.idx_sha.clone(), pair.idx_len)
            .map_err(|_| GatewayError::Internal("index artifact specification is invalid"))?,
    ];
    let request = AcquireArtifactHoldsRequest::new(
        scope,
        plan.identity().clone(),
        request_id,
        state.store().backend_identity().clone(),
        authority_id,
        1,
        *plan.expected().gate_digest(),
        specs,
    )
    .map_err(|_| GatewayError::Internal("artifact hold request is invalid"))?;
    let grant = {
        let mut client = state.pooled(deadline).await?;
        match PgArtifactHoldStore.acquire(&mut client, state.store(), &request, deadline).await {
            Ok(AcquireOutcome::Granted { grant, .. }) => grant,
            Ok(AcquireOutcome::Replayed { .. }) => {
                // A durable hold replay is a real conflict, not a ref result.
                return Err(GatewayError::Conflict(
                    "this operation already consumed its artifact hold; it cannot upload again",
                ));
            }
            Err(error) => return Err(map_acquire(error)),
        }
        // The pooled client returns here, before any provider IO.
    };
    let uploader = ProtectedUploader::new(state.store().clone());
    let sources = [UploadSource::new(pair.pack.clone()), UploadSource::new(pair.idx.clone())];
    let publication = uploader
        .consume_and_upload(state.pool(), grant, &sources, to_std(deadline)?)
        .await
        .map_err(map_protected_upload)?;
    let mut client = state.pooled(deadline).await?;
    let registration = PackRegistrationRequest::new(plan, pack_id, &publication)?;
    let _ = PgPackCommit.register_publication(&mut client, registration, deadline).await?;
    Ok(())
}

/// These A3 refusals are produced only after matching the live immutable
/// scope and observing its gate proof move, or after the ledger proved the
/// durable operation is cancelled. Other scope/ledger/provider errors are not a
/// stale-base result; unknown durability must not enter the refusal transaction.
/// Its sealed-token check independently proves revision progress.
fn map_acquire(error: ArtifactHoldError) -> GatewayError {
    match error {
        ArtifactHoldError::ScopeMismatch("expected core gate proof") => {
            GatewayError::Conflict("repository gate changed before artifact admission")
        }
        ArtifactHoldError::OperationCancelled { .. } => DURABLY_CANCELLED,
        _ => GatewayError::Internal("artifact hold acquisition was refused"),
    }
}

fn map_protected_upload(error: ProtectedUploadError) -> GatewayError {
    match error {
        ProtectedUploadError::Consume(ArtifactHoldError::ScopeMismatch("current core gate moved before consume")) => {
            GatewayError::Conflict("repository gate changed before artifact consumption")
        }
        ProtectedUploadError::Consume(ArtifactHoldError::OperationCancelled { .. }) => DURABLY_CANCELLED,
        _ => GatewayError::Internal("protected Blob upload was refused"),
    }
}

async fn decide(
    state: &BlobGitState,
    actor: &Identity,
    plan: PackCommitPlan,
    mode: CommitMode,
    deadline: Instant,
) -> Result<PackCommitTerminal, GatewayError> {
    let adapter = authorized(state)?;
    let mode = match mode {
        CommitMode::Atomic => AuthorizedCommitMode::Atomic,
        CommitMode::AcceptedSubset => AuthorizedCommitMode::AcceptedSubset,
    };
    let prepared = match adapter.prepare(state.pool(), plan, deadline).await.map_err(map_authorized)? {
        PrepareOutcome::Prepared(prepared) => prepared,
        PrepareOutcome::Replayed(receipt) => return Ok(receipt.terminal),
    };
    let selection = adapter.select(state.pool(), *prepared, actor, mode, deadline).await.map_err(map_authorized)?;
    let verified = adapter.verify(selection, deadline).await.map_err(map_authorized)?;
    let receipt = adapter.commit(state.pool(), &verified, deadline).await.map_err(map_authorized)?;
    Ok(receipt.terminal)
}

/// The authorized A4 facade over this gateway's one opened Blob store and
/// trusted Git binary. It grants nothing by itself: every stage re-reads live
/// authorization and the coordinating transaction (`cancel`) re-checks the live
/// token, RBAC and decision/terminal state inside the same short transaction.
pub(super) fn authorized(state: &BlobGitState) -> Result<PgAuthorizedCommit, GatewayError> {
    PgAuthorizedCommit::new(state.store().clone(), state.git_binary().to_path_buf())
        .map_err(|_| GatewayError::Unsupported("authorized publication adapter is unavailable"))
}

fn to_std(deadline: Instant) -> Result<StdInstant, GatewayError> {
    let now = Instant::now();
    if deadline <= now {
        return Err(GatewayError::Timeout);
    }
    Ok(StdInstant::now() + (deadline - now))
}

/// Map the authorized facade without collapsing distinct outcomes into `ng`.
///
/// Only a persisted terminal returned by `decide`/`begin` is rendered as a Git
/// report-status. Refusals below stay typed HTTP errors with the operation
/// header so a client can query the same operation id instead of seeing a false
/// `ng`/`ok`.
pub(super) fn map_authorized(error: AuthorizedCommitError) -> GatewayError {
    if error.is_unknown() {
        return GatewayError::OutcomeUnknown;
    }
    match error {
        AuthorizedCommitError::Timeout => GatewayError::Timeout,
        // A durable cancellation tombstone is a definite no-effect refusal.
        AuthorizedCommitError::Terminal("cancelled") => DURABLY_CANCELLED,
        AuthorizedCommitError::Contended(_) => GatewayError::Unavailable("publication dependency is contended; retry"),
        // Only the typed cancellation code is a tombstone; every other pack
        // refusal keeps its existing `PackCommitError` mapping.
        AuthorizedCommitError::Pack(PackCommitError::Rejected(rejection))
            if rejection.code == PackCommitRejectCode::Cancelled =>
        {
            DURABLY_CANCELLED
        }
        AuthorizedCommitError::Pack(error) => error.into(),
        AuthorizedCommitError::Denied(_) => GatewayError::Forbidden("publication is not authorized"),
        // The decision/operation is already terminal; resolve it by querying the
        // operation id rather than guessing a ref result.
        AuthorizedCommitError::Terminal(_) => GatewayError::OutcomeUnknown,
        AuthorizedCommitError::QuotaExceeded => {
            GatewayError::Unavailable("retained publication quota is exhausted; retry later")
        }
        AuthorizedCommitError::Unverifiable(_) => GatewayError::Unavailable("publication could not be verified; retry"),
        AuthorizedCommitError::Ledger(_) | AuthorizedCommitError::Database(_) => {
            GatewayError::Internal("publication ledger could not be verified")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ref_store::core::pack_commit::PackCommitRejection;

    #[test]
    fn artifact_gate_refusals_only_route_same_realm_progress_to_terminalization() {
        assert!(matches!(
            map_acquire(ArtifactHoldError::ScopeMismatch("expected core gate proof")),
            GatewayError::Conflict(_)
        ));
        assert!(matches!(
            map_protected_upload(ProtectedUploadError::Consume(ArtifactHoldError::ScopeMismatch(
                "current core gate moved before consume"
            ))),
            GatewayError::Conflict(_)
        ));
        for field in
            ["gate history incarnation", "gate authority epoch", "gate object format", "parent operation identity"]
        {
            assert!(matches!(map_acquire(ArtifactHoldError::ScopeMismatch(field)), GatewayError::Internal(_)));
            assert!(matches!(
                map_protected_upload(ProtectedUploadError::Consume(ArtifactHoldError::ScopeMismatch(field))),
                GatewayError::Internal(_)
            ));
        }
    }

    #[test]
    fn ambiguous_artifact_durability_and_provider_failure_never_route_to_terminalization() {
        assert!(matches!(
            map_acquire(ArtifactHoldError::AcquireUnknown { request_id: Uuid::new_v4() }),
            GatewayError::Internal(_)
        ));
        assert!(matches!(
            map_protected_upload(ProtectedUploadError::Consume(ArtifactHoldError::ConsumeUnknown {
                consume_request_id: Uuid::new_v4(),
                hold_ids: vec![Uuid::new_v4()]
            })),
            GatewayError::Internal(_)
        ));
        assert!(matches!(map_protected_upload(ProtectedUploadError::Checkout), GatewayError::Internal(_)));
        assert!(matches!(map_protected_upload(ProtectedUploadError::ForeignBackend), GatewayError::Internal(_)));
    }

    #[test]
    fn only_the_exact_rolled_back_gate_revision_refusal_is_rebasable() {
        use crate::ref_store::RefStoreError;

        let rejected = |code: PackCommitRejectCode, detail: &'static str| {
            PackCommitError::Rejected(PackCommitRejection::new(code, detail))
        };
        assert!(is_rolled_back_revision_mismatch(&rejected(
            PackCommitRejectCode::RevisionMismatch,
            GATE_REVISION_MISMATCH_DETAIL
        )));
        for error in [
            rejected(PackCommitRejectCode::RevisionMismatch, "another fixed detail"),
            rejected(PackCommitRejectCode::HistoryIncarnationMismatch, GATE_REVISION_MISMATCH_DETAIL),
            rejected(PackCommitRejectCode::ModeMismatch, GATE_REVISION_MISMATCH_DETAIL),
            rejected(PackCommitRejectCode::Cancelled, GATE_REVISION_MISMATCH_DETAIL),
            rejected(PackCommitRejectCode::AlreadyVerified, GATE_REVISION_MISMATCH_DETAIL),
            rejected(PackCommitRejectCode::GateDigestMismatch, GATE_REVISION_MISMATCH_DETAIL),
            PackCommitError::RefStore(RefStoreError::Timeout),
            PackCommitError::CommitUnknown { repository_id: Uuid::new_v4(), operation_id: Uuid::new_v4() },
        ] {
            assert!(!is_rolled_back_revision_mismatch(&error), "{error:?} must not rebase");
        }
    }

    fn rejected(code: PackCommitRejectCode) -> AuthorizedCommitError {
        AuthorizedCommitError::Pack(PackCommitError::Rejected(PackCommitRejection::new(
            code,
            "cancellation tombstone won",
        )))
    }

    #[test]
    fn legacy_identity_collision_keeps_the_fixed_conflict_refusal() {
        use crate::ref_store::RefStoreError;

        let expected = GatewayError::Conflict("operation identity conflicts with a durable record");
        let collision = RefStoreError::IdentityConflict;
        assert_eq!(ref_error(collision.clone()), expected);
        assert_eq!(map_authorized(AuthorizedCommitError::from(collision)), expected);
    }

    #[test]
    fn durable_cancellation_keeps_the_fixed_conflict_refusal() {
        let operation_id = Uuid::new_v4();
        let cases = [
            ("A3 acquire", map_acquire(ArtifactHoldError::OperationCancelled { operation_id })),
            (
                "A3 protected consume",
                map_protected_upload(ProtectedUploadError::Consume(ArtifactHoldError::OperationCancelled {
                    operation_id,
                })),
            ),
            ("A4 terminal", map_authorized(AuthorizedCommitError::Terminal("cancelled"))),
            ("A4 rejected", map_authorized(rejected(PackCommitRejectCode::Cancelled))),
        ];
        for (label, error) in cases {
            assert_eq!(error, DURABLY_CANCELLED, "{label}");
            assert_eq!(error, GatewayError::Conflict("operation is durably cancelled"), "{label}");
        }
    }

    #[test]
    fn non_cancel_unknown_and_terminal_refusals_stay_unchanged() {
        let unknown = AuthorizedCommitError::Pack(PackCommitError::CommitUnknown {
            repository_id: Uuid::new_v4(),
            operation_id: Uuid::new_v4(),
        });
        assert!(map_authorized(unknown).eq(&GatewayError::OutcomeUnknown));
        assert!(map_authorized(AuthorizedCommitError::Terminal("committed")).eq(&GatewayError::OutcomeUnknown));
        assert!(map_authorized(AuthorizedCommitError::Terminal("rejected")).eq(&GatewayError::OutcomeUnknown));
        let other_terminal = map_authorized(rejected(PackCommitRejectCode::DecisionRejected));
        assert_eq!(other_terminal, GatewayError::Conflict("publication was rejected by the core ledger"));
        for code in [
            PackCommitRejectCode::PendingMissing,
            PackCommitRejectCode::OldOidMismatch,
            PackCommitRejectCode::LedgerIntegrity,
            PackCommitRejectCode::NoRefApplied,
        ] {
            assert_eq!(
                map_authorized(rejected(code)),
                GatewayError::Conflict("publication was rejected by the core ledger"),
                "{}",
                code.as_str()
            );
        }
        // Other hold refusals are not cancellations and keep their fail-closed 500.
        assert!(matches!(
            map_acquire(ArtifactHoldError::OperationNotPending { operation_id: Uuid::new_v4() }),
            GatewayError::Internal("artifact hold acquisition was refused")
        ));
        assert!(matches!(
            map_protected_upload(ProtectedUploadError::Consume(ArtifactHoldError::OperationNotPending {
                operation_id: Uuid::new_v4()
            })),
            GatewayError::Internal("protected Blob upload was refused")
        ));
    }

    fn test_serving_repository() -> ServingRepository {
        use crate::{
            db::Repository,
            ref_store::{GitObjectFormat, core::contract::CoreGate},
        };

        let repository_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let gate = CoreGate::new(
            repository_id,
            tenant_id,
            GitObjectFormat::Sha1,
            Uuid::new_v4(),
            1,
            1,
            RefName::new("refs/heads/main").unwrap(),
            7,
        )
        .unwrap();
        ServingRepository {
            repository: Repository {
                id: repository_id,
                name: "private-slot-zero".to_owned(),
                owner: "owner".to_owned(),
                state: "ready".to_owned(),
                clone_path: "/git/owner/private-slot-zero.git".to_owned(),
                storage_backend: "pg_refstore".to_owned(),
                storage_generation: 1,
                object_format: "sha1".to_owned(),
            },
            gate,
            cluster_incarnation: Uuid::new_v4(),
        }
    }

    fn test_actor() -> Identity {
        Identity {
            id: Uuid::new_v4(),
            token_id: Uuid::new_v4(),
            parent_token_id: None,
            username: "actor".to_owned(),
            read_only: false,
            token_digest: vec![0; 32],
        }
    }

    fn test_baseline(serving: &ServingRepository) -> PackCommitBaseline {
        use crate::ref_store::core::pack_commit::PackMode;
        PackCommitBaseline::new(serving.gate.version(), PackMode::MetadataOnly, Vec::new(), Vec::new()).unwrap()
    }

    fn test_pair() -> Pair {
        Pair {
            pack: PathBuf::from("private.pack"),
            idx: PathBuf::from("private.idx"),
            pack_id: Uuid::new_v4(),
            pack_sha: "1".repeat(64),
            pack_len: 128,
            idx_sha: "2".repeat(64),
            idx_len: 64,
        }
    }

    fn test_push_request() -> PushRequest {
        use super::super::protocol::PushCommand;
        PushRequest {
            commands: vec![PushCommand {
                old: "0".repeat(40),
                new: "a".repeat(40),
                name: "refs/heads/main".to_owned(),
            }],
            capabilities: vec!["report-status".to_owned()],
        }
    }

    #[test]
    fn slot_zero_request_keeps_public_identity_and_copies_the_full_authorized_realm() {
        let serving = test_serving_repository();
        let baseline = test_baseline(&serving);
        let actor = test_actor();
        let public_id = Uuid::new_v4();
        let private_id = Uuid::new_v4();
        let digest = RequestDigest::of("test-slot-zero-request", &[b"wire"]);
        let backend = "b".repeat(64);

        let public = public_attempt_request(
            &serving,
            &actor,
            public_id,
            digest,
            CommitMode::AcceptedSubset,
            &baseline,
            backend.clone(),
        )
        .unwrap();
        let request = slot_zero_admission_request(&public, private_id).unwrap();

        assert_eq!(public.repository_id, serving.gate.repository_id());
        assert_eq!(public.admission_owner_id, serving.gate.tenant_id());
        assert_eq!(public.issuer_id, actor.id);
        assert_eq!(public.public_id, public_id);
        assert_eq!(public.wire_digest, digest);
        assert_eq!(public.restore_incarnation, serving.cluster_incarnation);
        assert_eq!(request.repository_id, serving.gate.repository_id());
        assert_eq!(request.admission_owner_id, serving.gate.tenant_id());
        assert_eq!(request.issuer_id, actor.id);
        assert_eq!(request.lane.as_str(), ISSUER_LANE);
        assert_eq!(request.public_id, public_id);
        assert_eq!(request.private_id, private_id);
        assert_ne!(request.public_id, request.private_id);
        assert_eq!(request.wire_digest, digest);
        assert_eq!(request.request_mode, CommitMode::AcceptedSubset);
        assert_eq!(request.backend_identity, backend);
        assert_eq!(request.object_format, serving.gate.object_format());
        assert_eq!(request.history_incarnation, serving.gate.history_incarnation());
        assert_eq!(request.authority_epoch, serving.gate.authority_epoch());
        assert_eq!(request.group_epoch, serving.gate.group_epoch());
        assert_eq!(request.restore_incarnation, serving.cluster_incarnation);
    }

    #[test]
    fn slot_zero_request_refuses_a_baseline_outside_the_authorized_realm() {
        use crate::ref_store::{GitObjectFormat, core::contract::CoreGate};

        let serving = test_serving_repository();
        let moved_gate = CoreGate::new(
            serving.gate.repository_id(),
            Uuid::new_v4(),
            GitObjectFormat::Sha1,
            serving.gate.history_incarnation(),
            1,
            1,
            serving.gate.head_ref().clone(),
            serving.gate.revision(),
        )
        .unwrap();
        let moved = PackCommitBaseline::new(
            moved_gate.version(),
            crate::ref_store::core::pack_commit::PackMode::MetadataOnly,
            Vec::new(),
            Vec::new(),
        )
        .unwrap();

        let error = public_attempt_request(
            &serving,
            &test_actor(),
            Uuid::new_v4(),
            RequestDigest::of("test-slot-zero-moved-realm", &[b"wire"]),
            CommitMode::Atomic,
            &moved,
            "c".repeat(64),
        )
        .unwrap_err();
        assert!(matches!(error, GatewayError::Conflict("repository authority changed; retry")));
    }

    #[test]
    fn slot_zero_plan_binds_only_the_locked_preview_and_private_identity() {
        let serving = test_serving_repository();
        let baseline = test_baseline(&serving);
        let actor = test_actor();
        let public_id = Uuid::new_v4();
        let private_id = Uuid::new_v4();
        let digest = RequestDigest::of("test-slot-zero-plan", &[b"wire"]);
        let request = test_push_request();
        let pair = test_pair();
        let sequence = 3;

        let plan = build_slot_zero_plan(
            &request,
            std::slice::from_ref(&pair),
            CommitMode::AcceptedSubset,
            serving.gate.tenant_id(),
            actor.id,
            &baseline,
            private_id,
            digest,
            sequence,
            baseline.gate().revision(),
        )
        .unwrap();
        assert_eq!(plan.identity().operation_id(), private_id);
        assert_eq!(plan.identity().issuer_id(), actor.id);
        assert_eq!(plan.identity().sequence(), sequence);
        assert_eq!(plan.identity().digest(), plan.parent_digest());
        assert_eq!(plan.commit_mode(), CommitMode::AcceptedSubset);
        assert_eq!(plan.tenant_id(), serving.gate.tenant_id());
        assert_eq!(plan.owner_id(), serving.gate.tenant_id());
        assert_ne!(plan.identity().operation_id(), public_id);

        let stale = build_slot_zero_plan(
            &request,
            std::slice::from_ref(&pair),
            CommitMode::AcceptedSubset,
            serving.gate.tenant_id(),
            actor.id,
            &baseline,
            private_id,
            digest,
            sequence,
            baseline.gate().revision() + 1,
        )
        .unwrap_err();
        assert!(is_rolled_back_revision_mismatch(&stale), "{stale:?}");
    }

    #[test]
    fn private_slot_zero_commit_unknown_never_renders_the_private_uuid() {
        let private_id = Uuid::new_v4();
        let error = GatewayError::from(PackCommitError::CommitUnknown {
            repository_id: Uuid::new_v4(),
            operation_id: private_id,
        });
        assert_eq!(error, GatewayError::OutcomeUnknown);
        assert!(!error.message().contains(&private_id.to_string()));
        assert!(!format!("{error:?}").contains(&private_id.to_string()));
    }

    #[test]
    fn build_plan_rejects_terminal_budget_overflow_before_admission() {
        use super::super::protocol::PushCommand;
        use crate::ref_store::{
            GitObjectFormat,
            core::{contract::CoreGate, pack_commit::PackMode},
        };

        let repo_id = Uuid::new_v4();
        let tenant_id = Uuid::new_v4();
        let owner_id = Uuid::new_v4();
        let issuer_id = Uuid::new_v4();
        let operation_id = Uuid::new_v4();
        let head = RefName::new("refs/heads/main").unwrap();
        let gate =
            CoreGate::new(repo_id, tenant_id, GitObjectFormat::Sha1, Uuid::new_v4(), 1, 1, head, 1).unwrap().version();
        let baseline = PackCommitBaseline::new(gate, PackMode::MetadataOnly, Vec::new(), Vec::new()).unwrap();
        let pair = Pair {
            pack: PathBuf::from("test.pack"),
            idx: PathBuf::from("test.idx"),
            pack_id: Uuid::new_v4(),
            pack_sha: "1".repeat(64),
            pack_len: 128,
            idx_sha: "2".repeat(64),
            idx_len: 64,
        };
        let request_for = |count: usize| PushRequest {
            commands: (0..count)
                .map(|idx| PushCommand {
                    old: "0".repeat(40),
                    new: "a".repeat(40),
                    name: if idx == 0 { "refs/heads/main".to_owned() } else { format!("refs/heads/z-page-{idx:02}") },
                })
                .collect(),
            capabilities: vec!["report-status".to_owned()],
        };
        let digest = RequestDigest::of("test-build-plan-budget", &[b"budget"]);
        let lane = IssuerLane::new(ISSUER_LANE).unwrap();
        let identity = OperationIdentity::new(repo_id, issuer_id, lane, 1, operation_id, digest).unwrap();

        assert!(
            build_plan(
                &request_for(52),
                std::slice::from_ref(&pair),
                CommitMode::Atomic,
                owner_id,
                &baseline,
                identity.clone(),
            )
            .is_ok()
        );
        assert_eq!(
            build_plan(
                &request_for(53),
                std::slice::from_ref(&pair),
                CommitMode::Atomic,
                owner_id,
                &baseline,
                identity.clone(),
            )
            .unwrap_err(),
            GatewayError::TooLarge
        );
        assert_eq!(
            build_plan(&request_for(55), &[pair], CommitMode::Atomic, owner_id, &baseline, identity).unwrap_err(),
            GatewayError::TooLarge
        );
    }
}
