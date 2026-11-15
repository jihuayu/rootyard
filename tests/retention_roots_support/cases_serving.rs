//! Serving-lane retention-root source fixtures. These remain ignored real
//! PG/S3/trusted-Git tests: they build a ready `pg_refstore` repository through
//! the production provision path, publish real packs through A3/A4/native, and
//! create a real serving pack snapshot before exercising the new core lanes.
//! No HTTP coordinator/authorization is claimed here.
use anyhow::{Context, Result, anyhow, ensure};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use uuid::Uuid;

use rootyard::ref_store::core::retention_root::{PgRetentionRoots, RootError, RootRef, RootSelector};

use crate::retention_roots_support::common::{
    adapter, assert_record_matches_source, one_verified, open_store, open_store_with_root,
};
use crate::retention_roots_support::db::{
    Db, cluster_incarnation, deadline, root_counts, rotate_cluster, set_cluster_incarnation, wait_pin_expired,
};
use crate::retention_roots_support::git::{
    GateRelease, GitGate, assert_pack_identity, git_binary, stock_git_accepts_view,
};
use crate::retention_roots_support::pack::{create_serving_snapshot, verify_new_serving};
use crate::retention_roots_support::roots;

/// The serving lane anchors the process-wide public cluster row, so these
/// fixture cases serialize their own rotation window. No production API is
/// changed by this test-only lock.
static SERVING_ROOT_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated roots/serving modules"]
async fn serving_root_materializes_after_source_release_and_expiry() -> Result<()> {
    let _serial = SERVING_ROOT_SERIAL.lock().await;
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let (verified, actor, repository) = verify_new_serving(&db, &store, &git, "roots-serving-positive").await?;
        let source = create_serving_snapshot(&db, &store, &actor, &repository, 300).await?;
        let roots = adapter(&store, &git)?;
        let scope = roots::scope(verified.repo, verified.tenant, &verified.gate)?;
        let root_id = Uuid::new_v4();
        let candidate = roots::prepare_serving(
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
        ensure!(candidate.pack_count() == source.read.pack_count(), "serving candidate omitted a pack");
        ensure!(candidate.ref_count() == source.read.ref_count(), "serving candidate omitted a ref");
        let expected_oids = candidate.root_oids().to_vec();
        let register_digest = candidate.register_digest().as_hex();
        let receipt = roots::register_serving(&roots, &db.pool, candidate, Uuid::new_v4(), deadline()).await?;
        ensure!(receipt.state() == "active" && receipt.root_id() == root_id, "serving register receipt differs");

        let reference = RootRef::new(verified.repo, root_id, 1)?;
        let record = roots
            .get(&db.pool, reference, deadline())
            .await?
            .ok_or_else(|| anyhow!("serving root metadata missing"))?;
        assert_record_matches_source(&record, &source.read)?;
        ensure!(record.register_digest_hex() == register_digest.as_str(), "serving root register digest differs");

        roots::release_serving_source(
            &rootyard::ref_store::serving::PgServingSnapshotMetadata,
            &db.pool,
            &actor,
            &store,
            &repository,
            &source,
            deadline(),
        )
        .await?;
        let view = roots::materialize_serving(&roots, &db.pool, root_id, verified.repo, deadline()).await?;
        ensure!(view.root_id() == root_id && view.generation() == 1, "serving view identity differs");
        ensure!(view.root_oids() == expected_oids.as_slice(), "serving view selector oids differ");
        ensure!(view.refs() == record.refs(), "serving view refs differ from retained refs");
        ensure!(view.binding_digest_hex().as_str() == record.binding_digest_hex(), "serving view binding differs");
        for expected in source.read.packs() {
            let actual = view
                .packs()
                .iter()
                .find(|pack| pack.pack_id() == expected.pack_id())
                .ok_or_else(|| anyhow!("serving view omitted a retained pack"))?;
            assert_pack_identity(expected, actual)?;
        }
        stock_git_accepts_view(&view, &verified.fixture, deadline()).await?;
        let body = verified
            .fixture
            .cat_file(view.head_oid_hex().ok_or_else(|| anyhow!("serving root HEAD is unborn"))?)
            .await?;
        ensure!(body.contains("fixture main"), "stock Git did not read the serving root commit");

        // A second root survives actual source-pin expiry, not just release.
        let expiring = create_serving_snapshot(&db, &store, &actor, &repository, 8).await?;
        let expiring_id = Uuid::new_v4();
        let expiring_candidate = roots::prepare_serving(
            &roots,
            &db.pool,
            scope,
            &expiring,
            expiring_id,
            Uuid::new_v4(),
            RootSelector::Snapshot,
            Uuid::new_v4(),
            deadline(),
        )
        .await?;
        roots::register_serving(&roots, &db.pool, expiring_candidate, Uuid::new_v4(), deadline()).await?;
        wait_pin_expired(&db.pool, expiring.pin_id).await?;
        let expiring_view =
            roots::materialize_serving(&roots, &db.pool, expiring_id, verified.repo, deadline()).await?;
        ensure!(expiring_view.refs() == expiring.read.refs(), "expired-pin serving view changed refs");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated roots/serving modules"]
async fn serving_root_refuses_wrong_backend_realm_lane_expired_source_and_cluster_rotation() -> Result<()> {
    let _serial = SERVING_ROOT_SERIAL.lock().await;
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let (verified, actor, repository) = verify_new_serving(&db, &store, &git, "roots-serving-refusals").await?;
        let source = create_serving_snapshot(&db, &store, &actor, &repository, 300).await?;
        let roots = adapter(&store, &git)?;
        let scope = roots::scope(verified.repo, verified.tenant, &verified.gate)?;
        let baseline = root_counts(&db.pool, verified.repo).await?;

        // Wrong actual opened backend: a distinct validated store identity is
        // not the repository's durable ready backend.
        let foreign_store = open_store_with_root("serving-roots-foreign")?;
        let foreign = PgRetentionRoots::new(foreign_store, git.clone())?;
        let foreign_id = Uuid::new_v4();
        let foreign_result = roots::prepare_serving(
            &foreign,
            &db.pool,
            scope,
            &source,
            foreign_id,
            Uuid::new_v4(),
            RootSelector::Snapshot,
            Uuid::new_v4(),
            deadline(),
        )
        .await;
        ensure!(foreign_result.is_err(), "foreign actual backend was accepted");
        ensure!(
            root_counts(&db.pool, verified.repo).await?.heads == baseline.heads,
            "foreign backend refusal wrote root rows"
        );

        // Wrong stored realm is rejected by the sealed-source comparison.
        let wrong_scope = roots::scope_with_history(verified.repo, verified.tenant, &verified.gate, Uuid::new_v4())?;
        let realm_result = roots::prepare_serving(
            &roots,
            &db.pool,
            wrong_scope,
            &source,
            Uuid::new_v4(),
            Uuid::new_v4(),
            RootSelector::Snapshot,
            Uuid::new_v4(),
            deadline(),
        )
        .await;
        ensure!(realm_result.is_err(), "wrong source realm was accepted");

        // Wrong lane: a legacy unserved source is not a ready pg_refstore
        // source and the serving prepare lane must refuse it.
        let (legacy_verified, legacy_source) = one_verified(&db, &store, &git).await?;
        let legacy_scope = roots::scope(legacy_verified.repo, legacy_verified.tenant, &legacy_verified.gate)?;
        let lane_result = roots::prepare_serving(
            &roots,
            &db.pool,
            legacy_scope,
            &legacy_source,
            Uuid::new_v4(),
            Uuid::new_v4(),
            RootSelector::Snapshot,
            Uuid::new_v4(),
            deadline(),
        )
        .await;
        ensure!(lane_result.is_err(), "serving prepare accepted a legacy source lane");

        // Actual source expiry before register: prepare succeeds, register's
        // pinned source-liveness read refuses, and no root rows are written.
        let expired_source = create_serving_snapshot(&db, &store, &actor, &repository, 8).await?;
        let expired_candidate = roots::prepare_serving(
            &roots,
            &db.pool,
            scope,
            &expired_source,
            Uuid::new_v4(),
            Uuid::new_v4(),
            RootSelector::Snapshot,
            Uuid::new_v4(),
            deadline(),
        )
        .await?;
        wait_pin_expired(&db.pool, expired_source.pin_id).await?;
        let expired_error = roots::register_serving(&roots, &db.pool, expired_candidate, Uuid::new_v4(), deadline())
            .await
            .expect_err("register accepted an expired source pin");
        ensure!(matches!(expired_error, RootError::Store(_)), "expired source returned an unrelated refusal");
        let after_expired = root_counts(&db.pool, verified.repo).await?;
        ensure!(
            after_expired.heads == baseline.heads
                && after_expired.captures == baseline.captures
                && after_expired.receipts == baseline.receipts,
            "expired source register wrote durable root rows"
        );

        // Cluster rotation after prepare, before register: the serving anchor
        // check refuses and rolls back all staged root rows/receipts.
        let rotated_source = create_serving_snapshot(&db, &store, &actor, &repository, 300).await?;
        let rotated_candidate = roots::prepare_serving(
            &roots,
            &db.pool,
            scope,
            &rotated_source,
            Uuid::new_v4(),
            Uuid::new_v4(),
            RootSelector::Snapshot,
            Uuid::new_v4(),
            deadline(),
        )
        .await?;
        let original_cluster = cluster_incarnation(&db.pool).await?;
        rotate_cluster(&db.pool).await?;
        let rotated_result =
            roots::register_serving(&roots, &db.pool, rotated_candidate, Uuid::new_v4(), deadline()).await;
        set_cluster_incarnation(&db.pool, original_cluster).await?;
        let rotated_error = rotated_result.expect_err("register accepted a rotated cluster anchor");
        ensure!(
            matches!(rotated_error, RootError::RootRealmMismatch(_)),
            "cluster rotation returned the wrong refusal: {rotated_error}"
        );
        let after_rotation = root_counts(&db.pool, verified.repo).await?;
        ensure!(
            after_rotation.heads == baseline.heads
                && after_rotation.captures == baseline.captures
                && after_rotation.receipts == baseline.receipts,
            "cluster-rotation register wrote durable root rows"
        );
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated roots/serving modules"]
async fn serving_root_release_before_t2_grants_no_view_and_holds_no_pg_across_native() -> Result<()> {
    let _serial = SERVING_ROOT_SERIAL.lock().await;
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let (verified, actor, repository) = verify_new_serving(&db, &store, &git, "roots-serving-barrier").await?;
        let source = create_serving_snapshot(&db, &store, &actor, &repository, 300).await?;
        let roots = Arc::new(adapter(&store, &git)?);
        let scope = roots::scope(verified.repo, verified.tenant, &verified.gate)?;
        let root_id = Uuid::new_v4();
        let candidate = roots::prepare_serving(
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
        roots::register_serving(&roots, &db.pool, candidate, Uuid::new_v4(), deadline()).await?;

        let gate = GitGate::new(&git)?;
        let release_guard = GateRelease(&gate);
        let gated = Arc::new(PgRetentionRoots::new(store.clone(), gate.binary())?);
        let max_one = db.new_pool(1)?;
        let paused_pool = max_one.clone();
        let paused = tokio::spawn(async move {
            roots::materialize_serving(&gated, &paused_pool, root_id, verified.repo, deadline()).await
        });
        gate.wait_ready().await.context("serving native materialization never reached Git")?;

        let observer_pool = db.new_pool(1)?;
        let client = timeout(Duration::from_secs(2), observer_pool.get())
            .await
            .map_err(|_| anyhow!("serving root held a PG connection across native IO"))??;
        let one: i32 = client.query_one("SELECT 1", &[]).await?.get(0);
        ensure!(one == 1, "observer query failed");
        drop(client);

        let release_pool = db.new_pool(1)?;
        roots::release(
            &roots,
            &release_pool,
            scope,
            root_id,
            Uuid::new_v4(),
            &register_digest,
            &roots::release_digest("serving-before-t2"),
            deadline(),
        )
        .await?;
        gate.release()?;
        let result = timeout(Duration::from_secs(30), paused)
            .await
            .map_err(|_| anyhow!("serving materialization did not finish"))??;
        let error = result.expect_err("released serving root still produced a view");
        ensure!(matches!(error, RootError::RootReleased { .. }), "serving T2 returned the wrong refusal: {error}");
        drop(release_guard);
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}

#[tokio::test]
#[ignore = "requires real PG/S3/Git and the integrated roots/serving modules"]
async fn serving_root_materialize_refuses_cluster_rotation_before_t2() -> Result<()> {
    let _serial = SERVING_ROOT_SERIAL.lock().await;
    let db = Db::setup().await?;
    let store = open_store()?;
    let git = git_binary()?;
    let outcome = async {
        let (verified, actor, repository) =
            verify_new_serving(&db, &store, &git, "roots-serving-rotation-native").await?;
        let source = create_serving_snapshot(&db, &store, &actor, &repository, 300).await?;
        let roots = Arc::new(adapter(&store, &git)?);
        let scope = roots::scope(verified.repo, verified.tenant, &verified.gate)?;
        let root_id = Uuid::new_v4();
        let candidate = roots::prepare_serving(
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
        roots::register_serving(&roots, &db.pool, candidate, Uuid::new_v4(), deadline()).await?;

        let gate = GitGate::new(&git)?;
        let release_guard = GateRelease(&gate);
        let gated = Arc::new(PgRetentionRoots::new(store.clone(), gate.binary())?);
        let paused_pool = db.new_pool(1)?;
        let paused = tokio::spawn(async move {
            roots::materialize_serving(&gated, &paused_pool, root_id, verified.repo, deadline()).await
        });
        gate.wait_ready().await.context("serving native rotation read never reached Git")?;
        let original_cluster = cluster_incarnation(&db.pool).await?;
        rotate_cluster(&db.pool).await?;
        gate.release()?;
        let joined = timeout(Duration::from_secs(30), paused)
            .await
            .map_err(|_| anyhow!("serving rotated-cluster read did not finish"));
        set_cluster_incarnation(&db.pool, original_cluster).await?;
        let result = joined??;
        let error = result.expect_err("rotated cluster still produced a serving root view");
        ensure!(
            matches!(error, RootError::RootRealmMismatch(_)),
            "serving T2 cluster rotation returned the wrong refusal: {error}"
        );
        drop(release_guard);
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}
