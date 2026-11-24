//! Canonical plan/baseline/wire construction, real A3/A4 staging and the
//! authorized publication pipeline.

use super::db::deadline;
use super::{WIRE_BODY, WIRE_DOMAIN, db, git, pack};
use anyhow::{Result, anyhow, ensure};
use rootyard::blob_store::opendal::BlobStore;
use rootyard::db::Identity;
use rootyard::ref_store::{
    CommitMode, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, OperationIdentity, RefName, RefPrecondition,
    RefTarget, RefUpdate, RequestDigest,
    core::pack_commit::{
        AuthorizedCommitMode, AuthorizedCommitReceipt, ContentDigest, PackArtifactRole, PackCommitBaseline,
        PackCommitError, PackCommitExpectation, PackCommitPlan, PackCommitScope, PackMembershipEntry,
        PgAuthorizedCommit, PgPackCommit, PlannedArtifact, PlannedPack, PrepareOutcome,
    },
};
use std::path::Path;
use uuid::Uuid;

pub(super) fn plan_from_baseline(
    baseline: &PackCommitBaseline,
    tenant: Uuid,
    sequence: i64,
    private_id: Uuid,
    lane: &IssuerLane,
    refs: Vec<RefUpdate>,
    files: &[git::PairFiles],
) -> Result<PackCommitPlan, PackCommitError> {
    let gate = baseline.gate();
    let mut planned = Vec::with_capacity(files.len());
    for file in files {
        let (pack_sha, pack_len) = git::digest_file(&file.pack)
            .map_err(|_| PackCommitError::Invalid("fixture pack digest could not be read"))?;
        let (idx_sha, idx_len) = git::digest_file(&file.idx)
            .map_err(|_| PackCommitError::Invalid("fixture idx digest could not be read"))?;
        planned.push(PlannedPack::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            PlannedArtifact::new(PackArtifactRole::Pack, ContentDigest::parse(pack_sha)?, pack_len)?,
            PlannedArtifact::new(PackArtifactRole::Idx, ContentDigest::parse(idx_sha)?, idx_len)?,
        )?);
    }
    let scope = PackCommitScope::new(
        gate.repository_id(),
        tenant,
        tenant,
        gate.object_format(),
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )?;
    let identity = OperationIdentity::new(
        gate.repository_id(),
        tenant,
        lane.clone(),
        sequence,
        private_id,
        RequestDigest::from_bytes([0; 32]),
    )?;
    let expectation = PackCommitExpectation::new(gate.revision(), *gate.digest(), baseline.mode())?;
    let old_entries = baseline.old_packs().iter().map(PackMembershipEntry::from_pack).collect::<Result<Vec<_>, _>>()?;
    PackCommitPlan::new(
        scope,
        identity,
        expectation,
        HeadUpdate::Keep,
        refs,
        baseline.membership_digest(),
        old_entries,
        planned,
    )
}

pub(super) async fn stage(db: &db::Db, store: &BlobStore, plan: &PackCommitPlan, files: &git::PairFiles) -> Result<()> {
    let publication = pack::publish(db, store, plan, files).await?;
    let pack_id = plan.packs().first().ok_or_else(|| anyhow!("fixture plan has no planned pack"))?.pack_id();
    pack::register(db, plan, pack_id, &publication).await?;
    Ok(())
}

pub(super) async fn authorized_commit(
    db: &db::Db,
    store: &BlobStore,
    git: &Path,
    actor: &Identity,
    plan: PackCommitPlan,
) -> Result<AuthorizedCommitReceipt> {
    let mode = match plan.commit_mode() {
        CommitMode::Atomic => AuthorizedCommitMode::Atomic,
        CommitMode::AcceptedSubset => AuthorizedCommitMode::AcceptedSubset,
    };
    let authorized = PgAuthorizedCommit::new(store.clone(), git.to_path_buf())
        .map_err(|error| anyhow!("authorized adapter rejected the fixture: {error:?}"))?;
    let prepared = match authorized
        .prepare(&db.pool, plan, deadline())
        .await
        .map_err(|error| anyhow!("authorized prepare refused ({}): {error:?}", error.code()))?
    {
        PrepareOutcome::Prepared(prepared) => prepared,
        PrepareOutcome::Replayed(_) => return Err(anyhow!("authorized prepare replayed a fresh operation")),
    };
    let selection = authorized
        .select(&db.pool, *prepared, actor, mode, deadline())
        .await
        .map_err(|error| anyhow!("authorized select refused ({}): {error:?}", error.code()))?;
    let verified = authorized
        .verify(selection, deadline())
        .await
        .map_err(|error| anyhow!("authorized verify refused ({}): {error:?}", error.code()))?;
    let receipt = authorized
        .commit(&db.pool, &verified, deadline())
        .await
        .map_err(|error| anyhow!("authorized commit refused ({}): {error:?}", error.code()))?;
    ensure!(
        receipt.is_committed() && !receipt.replayed,
        "authorized fixture commit was not a fresh committed terminal"
    );
    Ok(receipt)
}

pub(super) async fn capture_baseline(db: &db::Db, repository_id: Uuid, tenant_id: Uuid) -> Result<PackCommitBaseline> {
    let mut client = db.pool.get().await?;
    PgPackCommit
        .capture_baseline(&mut client, repository_id, tenant_id, deadline())
        .await
        .map_err(|error| anyhow!("baseline capture refused: {error:?}"))
}

pub(super) async fn child_commit(
    fixture: &git::GitRepo,
    parent: &str,
    file: &str,
    content: &[u8],
    message: &str,
) -> Result<String> {
    let blob = fixture.add_blob(content).await?;
    let entry = format!("100644 blob {blob}\t{file}\n");
    let tree = git::GitRepo::text(&fixture.run(&["mktree"], Some(entry.as_bytes())).await?)?;
    git::GitRepo::text(&fixture.run(&["commit-tree", tree.as_str(), "-p", parent, "-m", message], None).await?)
}

pub(super) fn ref_update(format: GitObjectFormat, name: &str, old: Option<&str>, new: &str) -> Result<RefUpdate> {
    let precondition = match old {
        Some(value) => RefPrecondition::Present(GitOid::parse(format, value)?),
        None => RefPrecondition::Absent,
    };
    Ok(RefUpdate::new(RefName::branch(name)?, precondition, RefTarget::Oid(GitOid::parse(format, new)?)))
}

pub(super) fn wire_digest(
    format: GitObjectFormat,
    name: &str,
    old: Option<&str>,
    new: &str,
    mode: CommitMode,
) -> RequestDigest {
    let old = old.unwrap_or_default();
    let parts: [&[u8]; 6] = [
        format.as_str().as_bytes(),
        name.as_bytes(),
        old.as_bytes(),
        new.as_bytes(),
        mode.as_str().as_bytes(),
        WIRE_BODY,
    ];
    RequestDigest::of(WIRE_DOMAIN, &parts)
}
