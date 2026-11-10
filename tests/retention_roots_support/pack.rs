//! Actual A3/A4 publication + verified-commit path and the A5 pack snapshot
//! create/read path used to establish genuinely durable source snapshots.
//! Every pack is uploaded through the real protected uploader, registered by
//! the real A4 registration API and verified by the real native verifier; no
//! SQL row is treated as a proof.
#![allow(clippy::too_many_arguments)]

use anyhow::{Result, anyhow, ensure};
use deadpool_postgres::Pool;
use rootyard::blob_store::opendal::BlobStore;
use rootyard::blob_store::protected::{ProtectedPublication, ProtectedUploader, UploadSource};
use rootyard::ref_store::artifact_hold::{
    AcquireArtifactHoldsRequest, AcquireOutcome, ArtifactHoldPurpose, ArtifactSpec, HoldScope, PgArtifactHoldStore,
};
use rootyard::ref_store::core::pack_commit::{
    ContentDigest, PackArtifactRole, PackClosureContext, PackClosureProof, PackCommitExpectation, PackCommitPlan,
    PackCommitReceipt, PackCommitScope, PackMembershipEntry, PackPendingToken, PackRegistrationRequest, PackVerifier,
    PgPackCommit, PlannedArtifact, PlannedPack, RegisteredPack,
};
use rootyard::ref_store::core::{
    CreatePackSnapshotRequest, MetadataPinOutcome, MetadataSnapshotScope, PackReadSnapshot, PackSnapshotExpectation,
    PackSnapshotOutcome, PackSnapshotRef, PgPackSnapshot, ReleaseMetadataPinRequest,
};
use rootyard::ref_store::{
    CoreGateVersion, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, MetadataPinPurpose, OperationIdentity,
    PinReleaseReason, RefName, RefPrecondition, RefStoreError, RefTarget, RefUpdate, RequestDigest,
};
use uuid::Uuid;

use super::db::{Db, deadline};
use super::git::{GitRepo, PairFiles, digest_file};

const HOLD_NAMESPACE: &str = "core-pack";

pub struct Draft {
    pub plan: PackCommitPlan,
    pub token: PackPendingToken,
}

pub fn main_update(format: GitObjectFormat, old: Option<&str>, new: &str) -> Result<RefUpdate> {
    let precondition = match old {
        Some(value) => RefPrecondition::Present(GitOid::parse(format, value)?),
        None => RefPrecondition::Absent,
    };
    Ok(RefUpdate::new(RefName::branch("refs/heads/main")?, precondition, RefTarget::Oid(GitOid::parse(format, new)?)))
}

pub async fn draft(
    db: &Db,
    repo: Uuid,
    tenant: Uuid,
    sequence: i64,
    gate: &CoreGateVersion,
    refs: Vec<RefUpdate>,
    files: &[PairFiles],
) -> Result<Draft> {
    let mut client = db.pool.get().await?;
    let baseline = PgPackCommit.capture_baseline(&mut client, repo, tenant, deadline()).await?;
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
        tenant,
        gate.object_format(),
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )?;
    let identity = OperationIdentity::new(
        repo,
        tenant,
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
    let token = PgPackCommit.begin_pending(&mut client, &plan, deadline()).await?;
    drop(client);
    Ok(Draft { plan, token })
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

async fn publish(db: &Db, store: &BlobStore, plan: &PackCommitPlan, file: &PairFiles) -> Result<ProtectedPublication> {
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
    let uploader = ProtectedUploader::new(store.clone());
    let sources = [UploadSource::new(file.pack.clone()), UploadSource::new(file.idx.clone())];
    let publication = uploader
        .consume_and_upload(&db.pool, grant, &sources, deadline().into_std())
        .await
        .map_err(|_| anyhow!("protected upload refused"))?;
    ensure!(publication.receipts().len() == 2, "publication is not exactly one pair");
    Ok(publication)
}

async fn register(db: &Db, plan: &PackCommitPlan, pack_id: Uuid, publication: &ProtectedPublication) -> Result<()> {
    let mut client = db.pool.get().await?;
    let request = PackRegistrationRequest::new(plan, pack_id, publication)?;
    PgPackCommit.register_publication(&mut client, request, deadline()).await?;
    Ok(())
}

pub async fn closure(db: &Db, plan: &PackCommitPlan) -> Result<PackClosureContext> {
    let mut client = db.pool.get().await?;
    Ok(PgPackCommit.capture_context(&mut client, plan, deadline()).await?)
}

pub async fn prove(
    store: &BlobStore,
    git: &std::path::Path,
    plan: &PackCommitPlan,
    context: &PackClosureContext,
) -> Result<PackClosureProof> {
    Ok(PackVerifier::new(store.clone(), git.to_path_buf())?.verify(plan, context, deadline().into_std()).await?)
}

pub async fn commit(
    db: &Db,
    plan: &PackCommitPlan,
    token: &PackPendingToken,
    proof: &PackClosureProof,
) -> Result<PackCommitReceipt> {
    let mut client = db.pool.get().await?;
    Ok(PgPackCommit.commit_verified_pending(&mut client, plan, token, proof, deadline()).await?)
}

pub struct Verified {
    pub tenant: Uuid,
    pub repo: Uuid,
    pub gate: CoreGateVersion,
    pub fixture: GitRepo,
    pub commit_oid: String,
    pub plan: PackCommitPlan,
    pub new_packs: Vec<RegisteredPack>,
}

pub async fn verify_new(
    db: &Db,
    store: &BlobStore,
    git: &std::path::Path,
    format: GitObjectFormat,
) -> Result<Verified> {
    let (tenant, repo) = db.business(format).await?;
    let gate = db.gate(repo, tenant, format).await?;
    let fixture = GitRepo::new(git.to_path_buf(), format).await?;
    let commit_oid = fixture.build_commit("file.txt", b"root fixture\n", "fixture main").await?;
    fixture.update_ref("refs/heads/main", &commit_oid).await?;
    let files = fixture.pack_all("first").await?;
    let draft =
        draft(db, repo, tenant, 1, &gate, vec![main_update(format, None, &commit_oid)?], std::slice::from_ref(&files))
            .await?;
    let publication = publish(db, store, &draft.plan, &files).await?;
    let pack_id = draft.plan.packs().first().ok_or_else(|| anyhow!("plan has no pack"))?.pack_id();
    register(db, &draft.plan, pack_id, &publication).await?;
    let context = closure(db, &draft.plan).await?;
    ensure!(context.new_packs().len() == 1 && context.old_packs().is_empty(), "first closure is not one new pack");
    let proof = prove(store, git, &draft.plan, &context).await?;
    let receipt = commit(db, &draft.plan, &draft.token, &proof).await?;
    ensure!(receipt.is_committed() && !receipt.replayed, "fresh verified commit did not commit");
    let gate = super::db::gate_version(&db.pool, repo, tenant).await?;
    ensure!(gate.revision() == receipt.terminal.revision, "gate after commit differs");
    let new_packs = context.new_packs().to_vec();
    Ok(Verified { tenant, repo, gate, fixture, commit_oid, plan: draft.plan, new_packs })
}

pub async fn verify_advance(
    db: &Db,
    store: &BlobStore,
    verified: &mut Verified,
    sequence: i64,
    content: &[u8],
) -> Result<Vec<RegisteredPack>> {
    let format = verified.gate.object_format();
    let old_oid = verified.commit_oid.clone();
    let oid = verified.fixture.build_commit("advance.txt", content, "fixture advance").await?;
    verified.fixture.update_ref("refs/heads/main", &oid).await?;
    let files = verified.fixture.pack_all("advance").await?;
    let draft = draft(
        db,
        verified.repo,
        verified.tenant,
        sequence,
        &verified.gate,
        vec![main_update(format, Some(&old_oid), &oid)?],
        std::slice::from_ref(&files),
    )
    .await?;
    let publication = publish(db, store, &draft.plan, &files).await?;
    let pack_id = draft.plan.packs().first().ok_or_else(|| anyhow!("plan has no pack"))?.pack_id();
    register(db, &draft.plan, pack_id, &publication).await?;
    let context = closure(db, &draft.plan).await?;
    ensure!(context.new_packs().len() == 1, "second closure is not one new pack");
    let proof = prove(store, &verified.fixture.git.clone(), &draft.plan, &context).await?;
    let receipt = commit(db, &draft.plan, &draft.token, &proof).await?;
    ensure!(receipt.is_committed() && !receipt.replayed, "second verified commit did not commit");
    let packs = context.new_packs().to_vec();
    verified.commit_oid = oid;
    verified.gate = super::db::gate_version(&db.pool, verified.repo, verified.tenant).await?;
    verified.plan = draft.plan;
    verified.new_packs = packs.clone();
    ensure!(verified.gate.revision() == receipt.terminal.revision, "advanced gate revision differs");
    Ok(packs)
}

pub fn snapshot_scope(repo: Uuid, tenant: Uuid, gate: &CoreGateVersion) -> Result<MetadataSnapshotScope> {
    Ok(MetadataSnapshotScope::new(
        repo,
        tenant,
        tenant,
        MetadataPinPurpose::Verification,
        gate.object_format(),
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )?)
}

pub struct SourceSnapshot {
    pub scope: MetadataSnapshotScope,
    pub request_id: Uuid,
    pub snapshot_id: Uuid,
    pub pin_id: Uuid,
    pub read: PackReadSnapshot,
}

pub async fn create_snapshot(db: &Db, verified: &Verified, lease: i64) -> Result<SourceSnapshot> {
    let scope = snapshot_scope(verified.repo, verified.tenant, &verified.gate)?;
    let request_id = Uuid::new_v4();
    let snapshot_id = Uuid::new_v4();
    let pin_id = Uuid::new_v4();
    let expected = PackSnapshotExpectation::new(verified.gate.revision(), *verified.gate.digest())?;
    let request = CreatePackSnapshotRequest::new(scope, request_id, pin_id, snapshot_id, lease, expected)?;
    let outcome = a5_create(&db.pool, &request).await?;
    ensure!(!outcome.replayed, "fresh pack snapshot replayed");
    ensure!(
        outcome.receipt.snapshot_id() == snapshot_id && outcome.receipt.pin_id() == pin_id,
        "pack snapshot receipt ids differ"
    );
    let read = a5_read(&db.pool, verified.repo, verified.tenant, snapshot_id, pin_id, 1).await?;
    ensure!(read.pack_mode() == "pack_verified", "source snapshot is not pack_verified");
    ensure!(read.pack_count() > 0, "source snapshot has no registered pack membership");
    Ok(SourceSnapshot { scope, request_id, snapshot_id, pin_id, read })
}

pub async fn a5_create(pool: &Pool, request: &CreatePackSnapshotRequest) -> Result<PackSnapshotOutcome, RefStoreError> {
    let mut client = pool.get().await.map_err(pool_error)?;
    PgPackSnapshot.create(&mut client, request, deadline()).await
}

pub async fn a5_read(
    pool: &Pool,
    repo: Uuid,
    tenant: Uuid,
    snapshot_id: Uuid,
    pin_id: Uuid,
    generation: i64,
) -> Result<PackReadSnapshot, RefStoreError> {
    let reference = PackSnapshotRef::new(repo, tenant, snapshot_id, pin_id, generation)?;
    let mut client = pool.get().await.map_err(pool_error)?;
    PgPackSnapshot.read(&mut client, &reference, deadline()).await
}

pub fn pool_error(error: deadpool_postgres::PoolError) -> RefStoreError {
    RefStoreError::Database(error.to_string())
}

pub async fn release_pin(
    pool: &Pool,
    scope: MetadataSnapshotScope,
    pin_id: Uuid,
) -> Result<MetadataPinOutcome, RefStoreError> {
    let request = ReleaseMetadataPinRequest::new(scope, Uuid::new_v4(), pin_id, 1, PinReleaseReason::ClientDone)?;
    let mut client = pool.get().await.map_err(pool_error)?;
    rootyard::ref_store::core::PgRefStoreCore.release_metadata_pin(&mut client, &request, deadline()).await
}
