//! Original retention-root runtime cases 7 and 8, kept as real PG/S3/Git tests
//! in the same integration target while keeping the root test file under 600
//! lines.
use anyhow::{Context, Result, anyhow, ensure};
use rootyard::ref_store::core::retention_root::{
    PgRetentionRoots, REPO_MAX_ROOTS, RootError, RootQuotaResource, RootRef, RootSelector, TENANT_MAX_ROOTS,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use uuid::Uuid;

use crate::retention_roots_support::common::{adapter, assert_record_matches_source, one_verified, open_store};
use crate::retention_roots_support::db::{Db, deadline, repo_usage, root_counts, roots_revision, tenant_usage};
use crate::retention_roots_support::git::{
    GateRelease, GitGate, assert_pack_identity, git_binary, stock_git_accepts_view,
};
use crate::retention_roots_support::roots;

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated roots module"]
async fn release_while_native_is_paused_grants_no_read_and_shared_max_pool_has_no_pg_over_native() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let (verified, source) = one_verified(&db, &store, &git).await?;
        let roots = Arc::new(adapter(&store, &git)?);
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
        let register_digest = candidate.register_digest().as_hex();
        roots::register(&roots, &db.pool, candidate, Uuid::new_v4(), deadline()).await?;

        let gate = GitGate::new(&git)?;
        let release_guard = GateRelease(&gate);
        let gated = Arc::new(PgRetentionRoots::new(store.clone(), gate.binary())?);
        let max_one = db.new_pool(1)?;
        let paused_pool = max_one.clone();
        let request = roots::read_request(verified.repo, verified.tenant, &verified.gate, root_id)?;
        let paused = tokio::spawn(async move { gated.materialize(&paused_pool, request, deadline()).await });
        gate.wait_ready().await.context("paused materialization never reached native Git")?;

        // The max-size-one pool is completely free while native Git is paused.
        let observer_pool = db.new_pool(1)?;
        let client = timeout(Duration::from_secs(2), observer_pool.get())
            .await
            .map_err(|_| anyhow!("pool connection stayed occupied across native IO"))??;
        let one: i32 = client.query_one("SELECT 1", &[]).await?.get(0);
        ensure!(one == 1, "observer query failed");
        drop(client);

        // A second concurrent read on the same max-size-one pool succeeds while
        // the first is paused in native, proving the shared capacity does not
        // hide a PostgreSQL client across native IO.
        let second_roots = roots.clone();
        let second_pool = max_one.clone();
        let second_request = roots::read_request(verified.repo, verified.tenant, &verified.gate, root_id)?;
        let second =
            tokio::spawn(async move { second_roots.materialize(&second_pool, second_request, deadline()).await });
        let second_view = timeout(Duration::from_secs(30), second)
            .await
            .map_err(|_| anyhow!("concurrent root read stalled"))???;
        ensure!(second_view.root_id() == root_id, "concurrent read returned another root");
        drop(second_view);

        let release_pool = db.new_pool(1)?;
        let released = roots::release(
            &roots,
            &release_pool,
            scope,
            root_id,
            Uuid::new_v4(),
            &register_digest,
            &roots::release_digest("during-native"),
            deadline(),
        )
        .await?;
        ensure!(released.state() == "released", "release while native paused did not commit");
        gate.release()?;
        let result = timeout(Duration::from_secs(30), paused)
            .await
            .map_err(|_| anyhow!("paused materialization did not finish"))??;
        let error = result.expect_err("materialization that reached T2 after release must not grant a view");
        ensure!(matches!(error, RootError::RootReleased { .. }), "post-release T2 returned the wrong refusal: {error}");
        drop(release_guard);
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated roots module"]
async fn independent_roots_share_packs_without_affecting_holds_and_over_quota_is_atomic() -> Result<()> {
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let (verified, source) = one_verified(&db, &store, &git).await?;
        let roots = adapter(&store, &git)?;
        let scope = roots::scope(verified.repo, verified.tenant, &verified.gate)?;
        let first_id = Uuid::new_v4();
        let first = roots::prepare(
            &roots,
            &db.pool,
            scope,
            &source,
            first_id,
            Uuid::new_v4(),
            RootSelector::Snapshot,
            Uuid::new_v4(),
            deadline(),
        )
        .await?;
        let first_digest = first.register_digest().as_hex();
        let _first_receipt = roots::register(&roots, &db.pool, first, Uuid::new_v4(), deadline()).await?;
        let second_id = Uuid::new_v4();
        let second = roots::prepare(
            &roots,
            &db.pool,
            scope,
            &source,
            second_id,
            Uuid::new_v4(),
            RootSelector::Snapshot,
            Uuid::new_v4(),
            deadline(),
        )
        .await?;
        roots::register(&roots, &db.pool, second, Uuid::new_v4(), deadline()).await?;
        let second_record = roots
            .get(&db.pool, RootRef::new(verified.repo, second_id, 1)?, deadline())
            .await?
            .ok_or_else(|| anyhow!("second independent root missing"))?;
        assert_record_matches_source(&second_record, &source.read)?;
        for expected in source.read.packs() {
            let actual = second_record
                .packs()
                .iter()
                .find(|pack| pack.pack_id() == expected.pack_id())
                .ok_or_else(|| anyhow!("second root lost a shared pack"))?;
            assert_pack_identity(expected, actual)?;
        }
        let released = roots::release(
            &roots,
            &db.pool,
            scope,
            first_id,
            Uuid::new_v4(),
            &first_digest,
            &roots::release_digest("independent"),
            deadline(),
        )
        .await?;
        ensure!(
            released.body()["released_holds"].as_bool() == Some(false),
            "release claimed to release another consumer's holds"
        );
        ensure!(released.body()["deleted_blob_bytes"].as_bool() == Some(false), "release claimed to delete bytes");
        let second_view = roots
            .materialize(
                &db.pool,
                roots::read_request(verified.repo, verified.tenant, &verified.gate, second_id)?,
                deadline(),
            )
            .await?;
        ensure!(
            second_view.root_id() == second_id && second_view.packs() == second_record.packs(),
            "releasing one root damaged the independent root"
        );
        stock_git_accepts_view(&second_view, &verified.fixture, deadline()).await?;

        // Seed the retained repo/tenant counters at their exact bounds. The next
        // register must fail before any root row/receipt write and without a
        // partial tenant or repository charge.
        let third_id = Uuid::new_v4();
        let third = roots::prepare(
            &roots,
            &db.pool,
            scope,
            &source,
            third_id,
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
                "UPDATE ref_store_core_root_repo_usage SET roots=$2 WHERE repository_id=$1",
                &[&verified.repo, &REPO_MAX_ROOTS],
            )
            .await?;
        db.pool
            .get()
            .await?
            .execute(
                "UPDATE ref_store_core_root_tenant_usage SET roots=$2 WHERE tenant_id=$1",
                &[&verified.tenant, &TENANT_MAX_ROOTS],
            )
            .await?;
        let seeded_repo = repo_usage(&db.pool, verified.repo).await?;
        let seeded_tenant = tenant_usage(&db.pool, verified.tenant).await?;
        let counts = root_counts(&db.pool, verified.repo).await?;
        let revision = roots_revision(&db.pool, verified.repo).await?;
        let error = roots::register(&roots, &db.pool, third, Uuid::new_v4(), deadline())
            .await
            .expect_err("over-quota register must be refused");
        ensure!(
            matches!(error, RootError::RootQuotaExceeded { resource: RootQuotaResource::Roots, .. }),
            "over-quota refusal is not the roots charge: {error}"
        );
        ensure!(root_counts(&db.pool, verified.repo).await? == counts, "failed over-quota register wrote root rows");
        ensure!(
            repo_usage(&db.pool, verified.repo).await? == seeded_repo
                && tenant_usage(&db.pool, verified.tenant).await? == seeded_tenant,
            "failed over-quota register partially charged quota"
        );
        ensure!(
            roots_revision(&db.pool, verified.repo).await? == revision,
            "failed over-quota register advanced roots_revision"
        );
        ensure!(
            roots.get(&db.pool, RootRef::new(verified.repo, third_id, 1)?, deadline()).await?.is_none(),
            "over-quota candidate gained a capture"
        );
        let still = roots
            .materialize(
                &db.pool,
                roots::read_request(verified.repo, verified.tenant, &verified.gate, second_id)?,
                deadline(),
            )
            .await?;
        ensure!(
            still.packs() == second_record.packs(),
            "failed over-quota register disturbed an existing independent root"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}
