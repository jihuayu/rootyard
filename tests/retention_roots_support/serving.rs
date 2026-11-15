//! Serving-only composition of the real provisioning path with the shared
//! verified A3/A4/native fixture. This module is not included by the
//! roots/decisions backup support, which reuses `pack.rs` against its
//! parent-owned attachment database and intentionally has no serving actor or
//! provisioning helpers.

use anyhow::{Result, anyhow, ensure};
use rootyard::blob_store::opendal::BlobStore;
use rootyard::db::{Identity, Repository};
use rootyard::ref_store::{CommitMode, GitObjectFormat};
use rootyard::ref_store::core::pack_commit::{
    AuthorizedCommitMode, PgAuthorizedCommit, PrepareOutcome,
};

use super::db::{Db, deadline};
use super::git::GitRepo;
use super::pack::{Verified, closure, draft, main_update, publish, register};

/// Actual provision + first verified publication on a ready `pg_refstore`
/// repository. Production provisioning enables the irreversible decision fence
/// before `ready`; therefore the first refs are installed through the real
/// authorized decision pipeline rather than the legacy fresh-write path.
pub async fn verify_new_serving(
    db: &Db,
    store: &BlobStore,
    git: &std::path::Path,
    name: &str,
) -> Result<(Verified, Identity, Repository)> {
    let actor = super::db::serving_actor(&db.pool, "roots-serving-owner-").await?;
    let repository = super::db::provision_serving(&db.pool, &actor, store, name).await?;
    let tenant = actor.id;
    let gate = super::db::gate_version(&db.pool, repository.id, tenant).await?;
    let fixture = GitRepo::new(git.to_path_buf(), GitObjectFormat::Sha1).await?;
    let commit_oid = fixture.build_commit("file.txt", b"root fixture\n", "fixture main").await?;
    fixture.update_ref("refs/heads/main", &commit_oid).await?;
    let files = fixture.pack_all("first").await?;
    let draft = draft(
        db,
        repository.id,
        tenant,
        1,
        &gate,
        vec![main_update(GitObjectFormat::Sha1, None, &commit_oid)?],
        std::slice::from_ref(&files),
    )
    .await?;
    let publication = publish(db, store, &draft.plan, &files).await?;
    let pack_id = draft.plan.packs().first().ok_or_else(|| anyhow!("plan has no pack"))?.pack_id();
    register(db, &draft.plan, pack_id, &publication).await?;
    let context = closure(db, &draft.plan).await?;
    ensure!(
        context.new_packs().len() == 1 && context.old_packs().is_empty(),
        "first serving closure is not one new pack"
    );

    let authorized = PgAuthorizedCommit::new(store.clone(), git.to_path_buf())
        .map_err(|error| anyhow!("authorized adapter rejected the serving fixture: {error:?}"))?;
    let mode = match draft.plan.commit_mode() {
        CommitMode::Atomic => AuthorizedCommitMode::Atomic,
        CommitMode::AcceptedSubset => AuthorizedCommitMode::AcceptedSubset,
    };
    let prepared = match authorized
        .prepare(&db.pool, draft.plan.clone(), deadline())
        .await
        .map_err(|error| anyhow!("authorized serving prepare refused ({}): {error:?}", error.code()))?
    {
        PrepareOutcome::Prepared(prepared) => prepared,
        PrepareOutcome::Replayed(_) => return Err(anyhow!("authorized serving prepare replayed a fresh operation")),
    };
    let selection = authorized
        .select(&db.pool, *prepared, &actor, mode, deadline())
        .await
        .map_err(|error| anyhow!("authorized serving select refused ({}): {error:?}", error.code()))?;
    let verified = authorized
        .verify(selection, deadline())
        .await
        .map_err(|error| anyhow!("authorized serving verify refused ({}): {error:?}", error.code()))?;
    let receipt = authorized
        .commit(&db.pool, &verified, deadline())
        .await
        .map_err(|error| anyhow!("authorized serving commit refused ({}): {error:?}", error.code()))?;
    ensure!(receipt.is_committed() && !receipt.replayed, "authorized serving commit was not a fresh committed terminal");
    let gate = super::db::gate_version(&db.pool, repository.id, tenant).await?;
    ensure!(gate.revision() == receipt.terminal.revision, "serving gate after authorized commit differs");
    let new_packs = context.new_packs().to_vec();
    Ok((
        Verified { tenant, repo: repository.id, gate, fixture, commit_oid, plan: draft.plan, new_packs },
        actor,
        repository,
    ))
}
