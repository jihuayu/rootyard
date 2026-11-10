//! Additional real PG/S3/Git retention-root cases 9-11.
//!
//! These cases are part of the `ref_store_retention_roots` integration target
//! through this module. They use the same actual A3/A4/A5 helper path and the
//! shared public `draft` / `closure` / `prove` / `commit` fixture functions.
use anyhow::{Result, anyhow, ensure};
use rootyard::blob_store::BlobProvider;
use rootyard::blob_store::config::BlobProfile;
use rootyard::blob_store::opendal::BlobStore;
use rootyard::ref_store::core::retention_root::{
    PgRetentionRoots, REPO_MAX_LOGICAL_BYTES, RootError, RootQuotaResource, RootRef, RootSelector,
    TENANT_MAX_LOGICAL_BYTES,
};
use rootyard::ref_store::{GitObjectFormat, GitOid, RefName, RefPrecondition, RefTarget, RefUpdate};
use uuid::Uuid;

use crate::retention_roots_support::db::{
    Db, deadline, gate_version, repo_usage, root_counts, roots_revision, tenant_usage,
};
use crate::retention_roots_support::git::{git_binary, stock_git_accepts_view};
use crate::retention_roots_support::pack::{Verified, closure, commit, create_snapshot, draft, prove, verify_new};
use crate::retention_roots_support::roots;

fn open_store() -> Result<BlobStore> {
    let profile = BlobProfile::from_env().map_err(|error| anyhow!("ROOTYARD_BLOB_* profile rejected: {error}"))?;
    ensure!(profile.provider() == BlobProvider::S3, "ROOTYARD_BLOB_SERVICE must be s3 for this suite");
    BlobStore::open(profile).map_err(|error| anyhow!("configured Blob store rejected: {error}"))
}

async fn one_verified(
    db: &Db,
    store: &BlobStore,
    git: &std::path::Path,
) -> Result<(Verified, crate::retention_roots_support::pack::SourceSnapshot)> {
    let verified = verify_new(db, store, git, GitObjectFormat::Sha1).await?;
    let source = create_snapshot(db, &verified, 300).await?;
    Ok((verified, source))
}

fn missing_oid(format: GitObjectFormat) -> String {
    let width = if format == GitObjectFormat::Sha1 { 20 } else { 32 };
    hex::encode(vec![0xcd; width])
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated roots module"]
async fn selected_tree_oid_from_registered_pack_is_a_native_non_branch_root() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let (verified, source) = one_verified(&db, &store, &git).await?;
        ensure!(source.read.packs().len() == 1, "source snapshot did not capture the real pack");
        let tree_oid = verified.fixture.rev_parse(&format!("{}^{{tree}}", verified.commit_oid)).await?;
        ensure!(tree_oid.len() == verified.gate.object_format().oid_hex_len(), "tree oid has the wrong width");
        ensure!(verified.fixture.object_type(&tree_oid).await? == "tree", "selected object is not a real tree");
        ensure!(
            source.read.refs().iter().all(|reference| reference.oid_hex() != tree_oid.as_str()),
            "tree oid unexpectedly appears as a direct captured ref"
        );

        let roots = PgRetentionRoots::new(store.clone(), git.clone())?;
        let scope = roots::scope(verified.repo, verified.tenant, &verified.gate)?;
        let root_id = Uuid::new_v4();
        let candidate = roots::prepare(
            &roots,
            &db.pool,
            scope,
            &source,
            root_id,
            Uuid::new_v4(),
            RootSelector::ObjectIds(vec![tree_oid.clone()]),
            Uuid::new_v4(),
            deadline(),
        )
        .await?;
        ensure!(candidate.root_oids() == [tree_oid.clone()], "tree selector was not preserved");
        roots::register(&roots, &db.pool, candidate, Uuid::new_v4(), deadline()).await?;
        let view = roots
            .materialize(
                &db.pool,
                roots::read_request(verified.repo, verified.tenant, &verified.gate, root_id)?,
                deadline(),
            )
            .await?;
        ensure!(view.root_oids() == [tree_oid.clone()], "materialized tree selector differs");
        ensure!(view.selector_kind().as_str() == "oids", "tree root is not an explicit-oid root");
        ensure!(
            view.refs().iter().all(|reference| !reference.name().starts_with("refs/roots/oid/")),
            "synthetic root refs leaked into the captured ref set"
        );
        stock_git_accepts_view(&view, &verified.fixture, deadline()).await?;
        ensure!(verified.fixture.object_type(&tree_oid).await? == "tree", "stock Git lost the selected tree");

        let missing_id = Uuid::new_v4();
        let missing = roots::prepare(
            &roots,
            &db.pool,
            scope,
            &source,
            missing_id,
            Uuid::new_v4(),
            RootSelector::ObjectIds(vec![missing_oid(verified.gate.object_format())]),
            Uuid::new_v4(),
            deadline(),
        )
        .await;
        ensure!(
            matches!(missing, Err(RootError::RootObjectMissing { .. }) | Err(RootError::RootClosureUnproven(_))),
            "missing tree/blob oid was not refused natively: {missing:?}"
        );
        ensure!(
            roots.get(&db.pool, RootRef::new(verified.repo, missing_id, 1)?, deadline()).await?.is_none(),
            "missing selected object produced root metadata"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated roots module"]
async fn long_published_ref_bytes_are_charged_and_logical_quota_refuses_atomically() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let mut verified = verify_new(&db, &store, &git, GitObjectFormat::Sha1).await?;
        let format = verified.gate.object_format();
        let long_name = format!("refs/heads/retained/{}", vec!["long-ref-segment"; 20].join("/"));
        ensure!(long_name.len() > 300 && long_name.len() <= 1024, "long ref name is outside the real bound");
        let update = RefUpdate::new(
            RefName::new(&long_name)?,
            RefPrecondition::Absent,
            RefTarget::Oid(GitOid::parse(format, &verified.commit_oid)?),
        );
        // Actual A4 ref-only commit: zero new packs, one old registered pack,
        // real closure context, real native proof and real verified commit.
        let ref_draft = draft(&db, verified.repo, verified.tenant, 2, &verified.gate, vec![update], &[]).await?;
        ensure!(ref_draft.plan.packs().is_empty(), "ref-only plan unexpectedly planned a pack");
        let context = closure(&db, &ref_draft.plan).await?;
        ensure!(
            context.old_packs().len() == 1 && context.new_packs().is_empty(),
            "long-ref closure is not one old/zero new packs"
        );
        let proof = prove(&store, &verified.fixture.git, &ref_draft.plan, &context).await?;
        let receipt = commit(&db, &ref_draft.plan, &ref_draft.token, &proof).await?;
        ensure!(receipt.is_committed() && !receipt.replayed, "long-ref ref-only commit did not commit");
        verified.gate = gate_version(&db.pool, verified.repo, verified.tenant).await?;
        ensure!(verified.gate.revision() == receipt.terminal.revision, "long-ref commit did not advance the real gate");

        let source = create_snapshot(&db, &verified, 300).await?;
        ensure!(source.read.refs().len() == 2, "pack snapshot did not capture both real refs");
        ensure!(
            source.read.refs().iter().any(|reference| reference.name() == long_name.as_str()),
            "pack snapshot omitted the long ref name"
        );
        let roots = PgRetentionRoots::new(store.clone(), git.clone())?;
        let scope = roots::scope(verified.repo, verified.tenant, &verified.gate)?;
        let root_id = Uuid::new_v4();
        let candidate = roots::prepare(
            &roots,
            &db.pool,
            scope,
            &source,
            root_id,
            Uuid::new_v4(),
            RootSelector::Snapshot,
            Uuid::new_v4(),
            deadline(),
        )
        .await?;
        ensure!(
            candidate.captured_refs().iter().any(|reference| reference.name() == long_name.as_str()),
            "sealed candidate lost the long ref name"
        );
        roots::register(&roots, &db.pool, candidate, Uuid::new_v4(), deadline()).await?;
        let record = roots
            .get(&db.pool, RootRef::new(verified.repo, root_id, 1)?, deadline())
            .await?
            .ok_or_else(|| anyhow!("long-ref root metadata missing"))?;
        ensure!(
            record.refs().iter().any(|reference| reference.name() == long_name.as_str()),
            "retained root lost the long ref name"
        );
        let usage = repo_usage(&db.pool, verified.repo).await?.ok_or_else(|| anyhow!("root usage missing"))?;
        let minimum_ref_row = long_name.len() as i64 + format.oid_hex_len() as i64 + 128;
        ensure!(
            usage.logical_bytes >= minimum_ref_row,
            "retained logical bytes do not reflect the variable long ref name: {} < {minimum_ref_row}",
            usage.logical_bytes
        );

        let fail_id = Uuid::new_v4();
        let fail_candidate = roots::prepare(
            &roots,
            &db.pool,
            scope,
            &source,
            fail_id,
            Uuid::new_v4(),
            RootSelector::Snapshot,
            Uuid::new_v4(),
            deadline(),
        )
        .await?;
        db.pool
            .get()
            .await?
            .execute(
                "UPDATE ref_store_core_root_repo_usage SET logical_bytes=$2 WHERE repository_id=$1",
                &[&verified.repo, &REPO_MAX_LOGICAL_BYTES],
            )
            .await?;
        db.pool
            .get()
            .await?
            .execute(
                "UPDATE ref_store_core_root_tenant_usage SET logical_bytes=$2 WHERE tenant_id=$1",
                &[&verified.tenant, &TENANT_MAX_LOGICAL_BYTES],
            )
            .await?;
        let seeded_repo = repo_usage(&db.pool, verified.repo).await?;
        let seeded_tenant = tenant_usage(&db.pool, verified.tenant).await?;
        let counts = root_counts(&db.pool, verified.repo).await?;
        let revision = roots_revision(&db.pool, verified.repo).await?;
        let error = roots::register(&roots, &db.pool, fail_candidate, Uuid::new_v4(), deadline())
            .await
            .expect_err("logical-byte over-quota register must be refused");
        ensure!(
            matches!(error, RootError::RootQuotaExceeded { resource: RootQuotaResource::LogicalBytes, .. }),
            "logical-byte over-quota refusal is the wrong resource: {error}"
        );
        ensure!(root_counts(&db.pool, verified.repo).await? == counts, "logical over-quota wrote root rows");
        ensure!(
            repo_usage(&db.pool, verified.repo).await? == seeded_repo
                && tenant_usage(&db.pool, verified.tenant).await? == seeded_tenant,
            "logical over-quota partially charged repo/tenant usage"
        );
        ensure!(
            roots_revision(&db.pool, verified.repo).await? == revision,
            "logical over-quota advanced roots_revision"
        );
        ensure!(
            roots.get(&db.pool, RootRef::new(verified.repo, fail_id, 1)?, deadline()).await?.is_none(),
            "logical over-quota candidate gained a capture"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated roots module"]
async fn concurrent_identical_register_and_release_share_one_charge_and_stored_receipt() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let (verified, source) = one_verified(&db, &store, &git).await?;
        let roots = PgRetentionRoots::new(store.clone(), git.clone())?;
        let scope = roots::scope(verified.repo, verified.tenant, &verified.gate)?;
        let root_id = Uuid::new_v4();
        let operation_id = Uuid::new_v4();
        let prepare_request = Uuid::new_v4();
        let register_request = Uuid::new_v4();
        let first = roots::prepare(
            &roots,
            &db.pool,
            scope,
            &source,
            root_id,
            operation_id,
            RootSelector::Snapshot,
            prepare_request,
            deadline(),
        )
        .await?;
        let second = roots::prepare(
            &roots,
            &db.pool,
            scope,
            &source,
            root_id,
            operation_id,
            RootSelector::Snapshot,
            prepare_request,
            deadline(),
        )
        .await?;
        ensure!(first.register_digest() == second.register_digest(), "identical candidates sealed different digests");
        let (first, second) = tokio::join!(
            roots::register(&roots, &db.pool, first, register_request, deadline()),
            roots::register(&roots, &db.pool, second, register_request, deadline())
        );
        let first = first?;
        let second = second?;
        let replay_count = [first.replayed(), second.replayed()].into_iter().filter(|value| *value).count();
        ensure!(replay_count == 1, "concurrent identical register did not produce exactly one replay");
        ensure!(first.body() == second.body(), "concurrent identical register returned different stored bodies");
        ensure!(
            first.created_at_unix_micros() == second.created_at_unix_micros(),
            "concurrent identical register returned unstable receipt timestamps"
        );
        ensure!(first.request_digest() == second.request_digest(), "concurrent register request digests differ");
        let counts = root_counts(&db.pool, verified.repo).await?;
        ensure!(
            counts.heads == 1 && counts.captures == 1 && counts.receipts == 1,
            "concurrent register wrote more than one root/receipt"
        );
        let usage = repo_usage(&db.pool, verified.repo).await?.ok_or_else(|| anyhow!("register usage missing"))?;
        ensure!(usage.roots == 1 && usage.receipts == 1, "concurrent register charged roots/receipts twice");
        let register_digest = first.body()["register_digest"]
            .as_str()
            .ok_or_else(|| anyhow!("stored register receipt missing its digest"))?
            .to_owned();

        let release_request = Uuid::new_v4();
        let release_digest = roots::release_digest("concurrent-release");
        let (first, second) = tokio::join!(
            roots::release(
                &roots,
                &db.pool,
                scope,
                root_id,
                release_request,
                &register_digest,
                &release_digest,
                deadline(),
            ),
            roots::release(
                &roots,
                &db.pool,
                scope,
                root_id,
                release_request,
                &register_digest,
                &release_digest,
                deadline(),
            )
        );
        let first = first?;
        let second = second?;
        let replay_count = [first.replayed(), second.replayed()].into_iter().filter(|value| *value).count();
        ensure!(replay_count == 1, "concurrent identical release did not produce exactly one replay");
        ensure!(first.body() == second.body(), "concurrent identical release returned different stored bodies");
        ensure!(
            first.created_at_unix_micros() == second.created_at_unix_micros(),
            "concurrent identical release returned unstable receipt timestamps"
        );
        let counts = root_counts(&db.pool, verified.repo).await?;
        ensure!(
            counts.heads == 1 && counts.captures == 1 && counts.tombstones == 1 && counts.receipts == 2,
            "concurrent release wrote more than one tombstone/receipt"
        );
        let usage = repo_usage(&db.pool, verified.repo).await?.ok_or_else(|| anyhow!("release usage missing"))?;
        ensure!(usage.receipts == 2, "concurrent release charged its receipt twice");
        ensure!(usage.roots == 1, "concurrent release changed the retained root count");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}
