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
    blob_store::protected::{ProtectedUploader, UploadSource},
    db::Identity,
    ref_store::{
        GitOid, HeadUpdate, IssuerLane, OperationIdentity, PgRefStore, RefName, RefUpdate, RequestDigest,
        artifact_hold::{
            AcquireArtifactHoldsRequest, AcquireOutcome, ArtifactHoldPurpose, ArtifactSpec, HoldScope,
            PgArtifactHoldStore,
        },
        core::{
            CommitMode,
            pack_commit::{
                AuthorizedCommitError, AuthorizedCommitMode, ContentDigest, PackArtifactRole, PackCommitBaseline,
                PackCommitExpectation, PackCommitPlan, PackCommitScope, PackCommitTerminal, PackMembershipEntry,
                PackPendingToken, PackRegistrationRequest, PgAuthorizedCommit, PgPackCommit, PlannedArtifact,
                PlannedPack, PrepareOutcome,
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
    Fresh { _token: PackPendingToken, plan: Box<PackCommitPlan> },
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
    let baseline = capture_baseline(state, serving.gate.repository_id(), serving.gate.tenant_id(), deadline).await?;
    let owner = repository_owner(state, serving.gate.repository_id(), deadline).await?;
    match begin(state, serving, actor, operation_id, request_digest, request, pairs, mode, owner, &baseline, deadline)
        .await?
    {
        Start::Terminal(terminal) => Ok(PushOutcome::Terminal(terminal)),
        Start::Cancelled(reason) => Ok(PushOutcome::Cancelled(reason)),
        Start::Fresh { plan, .. } => {
            for (index, pair) in pairs.iter().enumerate() {
                let planned =
                    plan.packs().get(index).ok_or(GatewayError::Internal("planned pack set is incomplete"))?;
                publish_pair(state, &plan, planned.pack_id(), pair, deadline).await?;
            }
            let terminal = decide(state, actor, *plan, mode, deadline).await?;
            Ok(PushOutcome::Terminal(terminal))
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
                let token = PgPackCommit.begin_serving_pending_in_tx(&tx, &plan, request_digest, deadline).await?;
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
        Ok(Reserved::Known(claim)) => {
            rollback_bounded(tx, deadline).await;
            start_from_claim(claim)
        }
        Err(error) => {
            rollback_bounded(tx, deadline).await;
            Err(error)
        }
    }
}

/// Bounded best-effort rollback of a caller-owned transaction.
///
async fn rollback_bounded(tx: tokio_postgres::Transaction<'_>, deadline: Instant) {
    let _ = timeout_at(deadline, tx.rollback()).await;
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
            Err(_) => return Err(GatewayError::Internal("artifact hold acquisition was refused")),
        }
        // The pooled client returns here, before any provider IO.
    };
    let uploader = ProtectedUploader::new(state.store().clone());
    let sources = [UploadSource::new(pair.pack.clone()), UploadSource::new(pair.idx.clone())];
    let publication = uploader
        .consume_and_upload(state.pool(), grant, &sources, to_std(deadline)?)
        .await
        .map_err(|_| GatewayError::Internal("protected Blob upload was refused"))?;
    let mut client = state.pooled(deadline).await?;
    let registration = PackRegistrationRequest::new(plan, pack_id, &publication)?;
    let _ = PgPackCommit.register_publication(&mut client, registration, deadline).await?;
    Ok(())
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

fn authorized(state: &BlobGitState) -> Result<PgAuthorizedCommit, GatewayError> {
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
fn map_authorized(error: AuthorizedCommitError) -> GatewayError {
    if error.is_unknown() {
        return GatewayError::OutcomeUnknown;
    }
    match error {
        AuthorizedCommitError::Timeout => GatewayError::Timeout,
        AuthorizedCommitError::Contended(_) => GatewayError::Unavailable("publication dependency is contended; retry"),
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
