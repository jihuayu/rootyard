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
use std::{path::PathBuf, time::Instant as StdInstant};

use tokio::time::{Instant, timeout_at};
use uuid::Uuid;

use crate::{
    blob_store::protected::{ProtectedUploadError, ProtectedUploader, UploadSource},
    db::Identity,
    ref_store::{
        GitOid, HeadUpdate, IssuerLane, OperationIdentity, PgRefStore, RefName, RefUpdate, RequestDigest,
        artifact_hold::{
            AcquireArtifactHoldsRequest, AcquireOutcome, ArtifactHoldError, ArtifactHoldPurpose, ArtifactSpec,
            HoldScope, PgArtifactHoldStore,
        },
        core::{
            CommitMode,
            pack_commit::{
                AuthorizedCommitError, AuthorizedCommitMode, ContentDigest, GATE_REVISION_MISMATCH_DETAIL,
                PackArtifactRole, PackCommitBaseline, PackCommitError, PackCommitExpectation, PackCommitPlan,
                PackCommitRejectCode, PackCommitScope, PackCommitTerminal, PackMembershipEntry, PackPendingToken,
                PackRegistrationRequest, PgAuthorizedCommit, PgPackCommit, PlannedArtifact, PlannedPack,
                PrepareOutcome,
            },
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

enum Start {
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
    let gate = baseline.gate();
    let format = gate.object_format();
    let mut refs = Vec::with_capacity(request.commands.len());
    for command in &request.commands {
        let name = RefName::new(command.name.clone()).map_err(ref_error)?;
        let precondition = GitOid::precondition_value(format, &command.old).map_err(ref_error)?;
        let target = GitOid::target_value(format, &command.new).map_err(ref_error)?;
        refs.push(RefUpdate::new(name, precondition, target));
    }
    let current_head = gate.head_ref().as_str();
    let head_exists = baseline.refs().iter().any(|reference| reference.name() == current_head);
    let head = if head_exists {
        HeadUpdate::Keep
    } else if let Some(branch) =
        request.commands.iter().find(|command| command.name.starts_with("refs/heads/") && !command.is_delete())
    {
        HeadUpdate::retarget(branch.name.clone()).map_err(ref_error)?
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
    PackCommitPlan::new_with_mode(
        scope,
        identity,
        expectation,
        head,
        refs,
        baseline.membership_digest(),
        old_memberships,
        planned,
        mode,
    )
    .map_err(Into::into)
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
}
