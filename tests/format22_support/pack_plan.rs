//! `retention_roots_support::pack::{draft, publish, register}` with an explicit
//! pack owner.
//!
//! Those three shared helpers set `owner_id = tenant_id` (the request-bound
//! producer). Issue #169 additionally needs registered packs whose producer
//! owner is a *different* real user than the repository tenant: it is the owner
//! every `artifact_holds` and publication row keeps. The bodies below are the
//! unchanged production calls; only the `PackCommitScope` owner and the A3
//! `HoldScope` owner are parameters. Nothing else is re-implemented.

use anyhow::{Result, anyhow, ensure};
use rootyard::blob_store::opendal::BlobStore;
use rootyard::blob_store::protected::{ProtectedPublication, ProtectedUploader, UploadSource};
use rootyard::ref_store::artifact_hold::{
    AcquireArtifactHoldsRequest, AcquireOutcome, ArtifactHoldPurpose, ArtifactSpec, HoldScope, PgArtifactHoldStore,
};
use rootyard::ref_store::core::pack_commit::{
    ContentDigest, PackArtifactRole, PackCommitBaseline, PackCommitExpectation, PackCommitPlan, PackCommitScope,
    PackMembershipEntry, PackRegistrationRequest, PgPackCommit, PlannedArtifact, PlannedPack,
};
use rootyard::ref_store::{CoreGateVersion, HeadUpdate, IssuerLane, OperationIdentity, RefUpdate, RequestDigest};
use uuid::Uuid;

use super::db::{Db, deadline};
use super::git::{PairFiles, digest_file};

pub const HOLD_NAMESPACE: &str = "core-pack";

pub struct Draft {
    pub plan: PackCommitPlan,
}

/// The shared `draft` with `owner_id` = the pack producer instead of the tenant.
///
/// The producer is also the operation issuer (the shared helper issues as the
/// tenant). That is the same relationship a real serving receive request has:
/// `db::Identity.id` is both the request owner and the issuer lane actor, and
/// the decision-gated commit refuses any other issuer (`issuer_mismatch`).
pub struct DraftInput {
    pub repo: Uuid,
    pub tenant: Uuid,
    pub owner: Uuid,
    pub sequence: i64,
}

/// The shared `draft` with `owner_id` = the pack producer instead of the tenant.
pub async fn draft(
    db: &Db,
    input: DraftInput,
    gate: &CoreGateVersion,
    refs: Vec<RefUpdate>,
    files: &[PairFiles],
) -> Result<Draft> {
    let DraftInput { repo, tenant, owner, sequence } = input;
    let mut client = db.pool.get().await?;
    let baseline: PackCommitBaseline = PgPackCommit.capture_baseline(&mut client, repo, tenant, deadline()).await?;
    ensure!(
        baseline.gate().revision() == gate.revision() && baseline.gate().digest() == gate.digest(),
        "captured baseline differs from expected gate"
    );
    let old_entries = baseline.old_packs().iter().map(PackMembershipEntry::from_pack).collect::<Result<Vec<_>, _>>()?;
    let mut planned = Vec::with_capacity(files.len());
    for file in files {
        let (pack_sha, pack_len) = digest_file(&file.pack)?;
        let (idx_sha, idx_len) = digest_file(&file.idx)?;
        planned.push(PlannedPack::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            PlannedArtifact::new(PackArtifactRole::Pack, ContentDigest::parse(pack_sha)?, pack_len)?,
            PlannedArtifact::new(PackArtifactRole::Idx, ContentDigest::parse(idx_sha)?, idx_len)?,
        )?);
    }
    let scope = PackCommitScope::new(
        repo,
        tenant,
        owner,
        gate.object_format(),
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )?;
    let identity = OperationIdentity::new(
        repo,
        owner,
        IssuerLane::new("pack")?,
        sequence,
        Uuid::new_v4(),
        RequestDigest::from_bytes([0; 32]),
    )?;
    let expectation = PackCommitExpectation::new(gate.revision(), *gate.digest(), baseline.mode())?;
    let plan = PackCommitPlan::new(
        scope,
        identity,
        expectation,
        HeadUpdate::Keep,
        refs,
        baseline.membership_digest(),
        old_entries,
        planned,
    )?;
    let _pending = PgPackCommit.begin_pending(&mut client, &plan, deadline()).await?;
    drop(client);
    Ok(Draft { plan })
}

fn hold_scope(plan: &PackCommitPlan) -> Result<HoldScope> {
    HoldScope::new(
        plan.repository_id(),
        plan.tenant_id(),
        plan.owner_id(),
        ArtifactHoldPurpose::RefPublication,
        plan.object_format(),
        plan.history_incarnation(),
        plan.authority_epoch(),
        plan.group_epoch(),
    )
    .map_err(|error| anyhow!("hold scope rejected: {error}"))
}

/// A3 acquire + consume + protected upload of the exact pack/idx pair. The
/// durable holds carry `plan.owner_id()` (the producer), never the tenant.
pub async fn publish(
    db: &Db,
    store: &BlobStore,
    plan: &PackCommitPlan,
    file: &PairFiles,
) -> Result<ProtectedPublication> {
    let (pack_sha, pack_len) = digest_file(&file.pack)?;
    let (idx_sha, idx_len) = digest_file(&file.idx)?;
    let request = AcquireArtifactHoldsRequest::new(
        hold_scope(plan)?,
        plan.identity().clone(),
        Uuid::new_v4(),
        store.backend_identity().clone(),
        Uuid::new_v4(),
        1,
        *plan.expected().gate_digest(),
        vec![
            ArtifactSpec::new(HOLD_NAMESPACE, pack_sha, pack_len)?,
            ArtifactSpec::new(HOLD_NAMESPACE, idx_sha, idx_len)?,
        ],
    )?;
    let grant = {
        let mut client = db.pool.get().await?;
        match PgArtifactHoldStore.acquire(&mut client, store, &request, deadline()).await? {
            AcquireOutcome::Granted { grant, .. } => grant,
            AcquireOutcome::Replayed { .. } => return Err(anyhow!("fresh A3 acquire replayed")),
        }
    };
    let sources = [UploadSource::new(file.pack.clone()), UploadSource::new(file.idx.clone())];
    let publication = ProtectedUploader::new(store.clone())
        .consume_and_upload(&db.pool, grant, &sources, deadline().into_std())
        .await
        .map_err(|_| anyhow!("protected upload refused"))?;
    ensure!(publication.receipts().len() == 2, "publication is not exactly one pair");
    Ok(publication)
}

/// A4 registration of the exact publication under the plan's producer owner.
pub async fn register(db: &Db, plan: &PackCommitPlan, pack_id: Uuid, publication: &ProtectedPublication) -> Result<()> {
    let mut client = db.pool.get().await?;
    let request = PackRegistrationRequest::new(plan, pack_id, publication)?;
    PgPackCommit.register_publication(&mut client, request, deadline()).await?;
    Ok(())
}
