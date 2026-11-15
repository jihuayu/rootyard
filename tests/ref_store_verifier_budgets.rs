//! Live PostgreSQL + S3 + stock Git integration and benchmark suite for Issue #176.

mod verifier_budgets_support;

use anyhow::{Result, anyhow, ensure};
use rootyard::blob_store::config::BlobProfile;
use rootyard::blob_store::opendal::BlobStore;
use rootyard::ref_store::core::pack_commit::PackVerifier;
use rootyard::ref_store::core::pack_snapshot::PgPackSnapshotMaterializer;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant};
use tokio::sync::Mutex;
use verifier_budgets_support::bench::{metric_delta, metric_u64, verifier_metrics};
use verifier_budgets_support::bench_runner::{execute_isolated_benchmark, run_benchmark_worker};
use verifier_budgets_support::pg_git::{
    Db, commit_and_pin_snapshot, deadline, git_binary, pin_committed_snapshot, prepare_fresh_commit, resolved_database,
    std_deadline,
};
use verifier_budgets_support::s3::LoopbackS3;
use verifier_budgets_support::worker_exec::{
    ENV_BENCH_PHASE, run_hang_cleanup_probe, run_hang_cleanup_probe_with_reap_failure,
};

static SUITE_LOCK: Mutex<()> = Mutex::const_new(());

fn verify_sha256_equal(actual: &[u8], expected: &[u8], label: &str) -> Result<()> {
    ensure!(actual.len() == expected.len(), "{label} length mismatch: {} != {}", actual.len(), expected.len());
    ensure!(Sha256::digest(actual) == Sha256::digest(expected), "{label} sha256 mismatch");
    ensure!(actual == expected, "{label} bytes differ");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_blob_downloads_do_not_starve_fast_native_git_slots() -> Result<()> {
    let _serial = SUITE_LOCK.lock().await;
    let s3 = LoopbackS3::shared();
    let store = s3.open_blob_store()?;
    let git = git_binary()?;
    let db = Db::setup().await?;

    let outcome = async {
        let s3_before_prep = s3.counters();
        let mut slow_commits = Vec::with_capacity(3);
        let mut fast_commits = Vec::with_capacity(3);
        for i in 0..3 {
            slow_commits.push(Arc::new(prepare_fresh_commit(&db, &store, &git, 100 + i, 96 * 1024).await?));
            fast_commits.push(Arc::new(prepare_fresh_commit(&db, &store, &git, 200 + i, 64 * 1024).await?));
        }
        let s3_after_prep = s3.counters().delta_since(s3_before_prep);
        ensure!(s3_after_prep.put_requests >= 12, "expected >=12 S3 PUT objects for 6 prepared repos");

        let mut delays = Vec::with_capacity(3);
        for slow in &slow_commits {
            delays.push(s3.add_get_delay(slow.tenant.to_string(), Duration::from_millis(1800)));
        }

        let m_before = verifier_metrics();
        let c_before = s3.counters();
        let verifier = Arc::new(PackVerifier::new(store.clone(), git.clone())?);
        let materializer = Arc::new(PgPackSnapshotMaterializer::new(store.clone(), git.clone())?);

        let slow_start = StdInstant::now();
        let mut slow_handles = Vec::with_capacity(3);
        for slow in slow_commits {
            let v = Arc::clone(&verifier);
            slow_handles.push(tokio::spawn(async move { v.verify(&slow.plan, &slow.context, std_deadline()).await }));
        }

        tokio::time::sleep(Duration::from_millis(45)).await;

        let fast_start = StdInstant::now();
        let mut fast_handles = Vec::with_capacity(3);
        for fast in fast_commits {
            let v = Arc::clone(&verifier);
            let mat = Arc::clone(&materializer);
            let db_pool = db.pool.clone();
            let db_snapshot = db_pool.clone();
            fast_handles.push(tokio::spawn(async move {
                let proof = v.verify(&fast.plan, &fast.context, std_deadline()).await?;
                let mut client = db_snapshot.get().await?;
                let receipt = rootyard::ref_store::core::pack_commit::PgPackCommit
                    .commit_verified_pending(&mut client, &fast.plan, &fast.token, &proof, deadline())
                    .await?;
                ensure!(receipt.is_committed(), "fast commit failed");
                drop(client);
                let snap_ref = pin_committed_snapshot(&db_pool, &fast).await?;
                let view = mat.read(&db_pool, &snap_ref, deadline()).await?;
                let got_pack = view.pack_bytes(fast.pack_id, deadline()).await?;
                let got_idx = view.idx_bytes(fast.pack_id, deadline()).await?;
                verify_sha256_equal(&got_pack, &fast.pack_bytes, "fast materialized pack")?;
                verify_sha256_equal(&got_idx, &fast.idx_bytes, "fast materialized idx")?;
                ensure!(
                    view.verified_bytes() == (fast.pack_bytes.len() + fast.idx_bytes.len()) as u64,
                    "verified_bytes mismatch"
                );
                Ok::<(), anyhow::Error>(())
            }));
        }

        for h in fast_handles {
            h.await.map_err(|e| anyhow!("fast task panicked: {e}"))??;
        }
        let fast_wall = fast_start.elapsed();
        let slow_still_running = slow_handles.iter().filter(|h| !h.is_finished()).count();

        for h in slow_handles {
            let proof = h.await.map_err(|e| anyhow!("slow task panicked: {e}"))??;
            ensure!(proof.verified_pairs() >= 1 && proof.verified_bytes() > 0);
        }
        let slow_wall = slow_start.elapsed();
        ensure!(
            slow_still_running >= 1
                && fast_wall < Duration::from_millis(2900)
                && fast_wall + Duration::from_millis(500) < slow_wall,
            "fast native Git commits starved behind 1800ms slow Blob downloads: fast_wall={fast_wall:?}, slow_wall={slow_wall:?}, slow_still_running={slow_still_running}"
        );
        drop(delays);

        let m_after = verifier_metrics();
        let c_delta = s3.counters().delta_since(c_before);
        ensure!(metric_delta(&m_after, &m_before, "download_permits_acquired") >= 9);
        ensure!(metric_delta(&m_after, &m_before, "native_permits_acquired") >= 9);
        ensure!(metric_delta(&m_after, &m_before, "view_permits_acquired") >= 3);
        ensure!(metric_delta(&m_after, &m_before, "blob_get_requests") >= 18);
        ensure!(metric_delta(&m_after, &m_before, "blob_get_bytes") > 0);
        ensure!(metric_delta(&m_after, &m_before, "readback_bytes") > 0);
        ensure!(metric_delta(&m_after, &m_before, "staging_reclaimed_bytes_total") > 0);
        ensure!(metric_u64(&m_after, "download_in_flight") == 0);
        ensure!(metric_u64(&m_after, "native_in_flight") == 0);
        ensure!(metric_u64(&m_after, "view_in_flight") == 0);
        ensure!(metric_u64(&m_after, "staging_reserved_bytes_current") == 0);
        ensure!(c_delta.get_requests >= 18 && c_delta.get_bytes > 0);
        Ok::<(), anyhow::Error>(())
    }
    .await;

    db.finish(outcome).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn maintenance_saturation_preserves_foreground_pg_commit_and_reclaim() -> Result<()> {
    let _serial = SUITE_LOCK.lock().await;
    let s3 = LoopbackS3::shared();
    let store = s3.open_blob_store()?;
    let git = git_binary()?;
    let db = Db::setup().await?;

    let outcome = async {
        let mut maint_commits = Vec::with_capacity(4);
        for i in 0..4 {
            maint_commits.push(prepare_fresh_commit(&db, &store, &git, 300 + i, 96 * 1024).await?);
        }
        let fg_commit = prepare_fresh_commit(&db, &store, &git, 400, 96 * 1024).await?;
        let timeout_commit = prepare_fresh_commit(&db, &store, &git, 500, 96 * 1024).await?;

        let mut guards = Vec::new();
        for m in &maint_commits {
            guards.push(s3.add_get_delay(m.tenant.to_string(), Duration::from_millis(1200)));
        }
        guards.push(s3.add_get_delay(timeout_commit.tenant.to_string(), Duration::from_millis(1200)));

        let m_before = verifier_metrics();
        let verifier = Arc::new(PackVerifier::new(store.clone(), git.clone())?);

        let maint_start = StdInstant::now();
        let mut maint_tasks = Vec::with_capacity(4);
        for m in maint_commits {
            let v = Arc::clone(&verifier);
            maint_tasks
                .push(tokio::spawn(async move { v.verify_maintenance(&m.plan, &m.context, std_deadline()).await }));
        }

        // Wait until maintenance wave saturates its <=50% sub-cap before launching foreground work.
        tokio::time::sleep(Duration::from_millis(45)).await;

        let fg_start = StdInstant::now();
        let snap_ref = commit_and_pin_snapshot(&db, &fg_commit, &verifier, false).await?;
        let materializer = PgPackSnapshotMaterializer::new(store.clone(), git.clone())?;
        let view = materializer.read(&db.pool, &snap_ref, deadline()).await?;
        verify_sha256_equal(&view.pack_bytes(fg_commit.pack_id, deadline()).await?, &fg_commit.pack_bytes, "fg pack")?;
        verify_sha256_equal(&view.idx_bytes(fg_commit.pack_id, deadline()).await?, &fg_commit.idx_bytes, "fg idx")?;
        drop(view);
        let fg_elapsed = fg_start.elapsed();
        let maint_still_running = maint_tasks.iter().filter(|h| !h.is_finished()).count();

        let tight_deadline = StdInstant::now() + Duration::from_millis(80);
        let timed_out = verifier.verify(&timeout_commit.plan, &timeout_commit.context, tight_deadline).await;
        ensure!(timed_out.is_err(), "1200ms download under 80ms unified deadline must fail closed");

        for h in maint_tasks {
            let proof = h.await.map_err(|e| anyhow!("maintenance verify panicked: {e}"))??;
            ensure!(proof.verified_pairs() >= 1 && proof.verified_bytes() > 0);
        }
        let maint_wall = maint_start.elapsed();
        ensure!(
            maint_still_running >= 1
                && fg_elapsed < Duration::from_millis(2200)
                && fg_elapsed + Duration::from_millis(500) < maint_wall,
            "foreground commit + view blocked behind 1200ms maintenance backlog: fg_elapsed={fg_elapsed:?}, maint_wall={maint_wall:?}, maint_still_running={maint_still_running}"
        );
        drop(guards);

        let m_after = verifier_metrics();
        ensure!(metric_delta(&m_after, &m_before, "download_maintenance_permits_acquired") >= 4);
        ensure!(metric_delta(&m_after, &m_before, "native_maintenance_permits_acquired") >= 4);
        ensure!(metric_delta(&m_after, &m_before, "staging_reclaimed_bytes_total") > 0);
        ensure!(metric_u64(&m_after, "download_in_flight") == 0);
        ensure!(metric_u64(&m_after, "native_in_flight") == 0);
        ensure!(metric_u64(&m_after, "view_in_flight") == 0);
        ensure!(metric_u64(&m_after, "staging_reserved_bytes_current") == 0);
        Ok::<(), anyhow::Error>(())
    }
    .await;

    db.finish(outcome).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verifier_budget_before_vs_after_pg_s3_git_benchmark() -> Result<()> {
    if let Ok(phase) = std::env::var(ENV_BENCH_PHASE) {
        return run_benchmark_worker(&phase).await;
    }

    let _serial = SUITE_LOCK.lock().await;
    execute_isolated_benchmark().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn timed_out_isolated_worker_cleans_up_owned_pg_schema() -> Result<()> {
    let _serial = SUITE_LOCK.lock().await;
    let (pg_url, _) = resolved_database().await?;
    ensure!(Db::drop_owned_schema(&pg_url, "verifier_budgets_%").await.is_err());
    ensure!(Db::drop_owned_schema(&pg_url, "public").await.is_err());
    ensure!(Db::drop_owned_schema(&pg_url, "verifier_budgets_Bad!").await.is_err());

    let exe = std::env::current_exe()?;
    let temp = tempfile::tempdir()?;
    let schema = Db::fresh_schema_name();
    let marker = temp.path().join("migrated.marker");

    let res = run_hang_cleanup_probe(
        &exe,
        &pg_url,
        &temp.path().join("unused.json"),
        &schema,
        &marker,
        Duration::from_secs(8),
    )
    .await;
    let err = res.expect_err("hanging isolated probe worker must time out");
    let text = format!("{err:#}");
    ensure!(text.contains("timed out"), "expected timeout error, got: {text}");
    ensure!(text.contains("child_reaped=true"), "expected confirmed child exit/reap, got: {text}");
    ensure!(!text.contains("cleanup-not-complete"), "unexpected unconfirmed cleanup error: {text}");
    ensure!(marker.is_file(), "probe worker did not migrate `{schema}` before timeout kill");
    ensure!(
        !Db::schema_exists(&pg_url, &schema).await?,
        "owned schema `{schema}` leaked after timed-out isolated child termination"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_reap_preserves_owned_schema_with_cleanup_not_complete_error() -> Result<()> {
    let _serial = SUITE_LOCK.lock().await;
    let (pg_url, _) = resolved_database().await?;
    let exe = std::env::current_exe()?;
    let temp = tempfile::tempdir()?;
    let schema = Db::fresh_schema_name();
    let marker = temp.path().join("migrated.marker");

    let probe = run_hang_cleanup_probe_with_reap_failure(
        &exe,
        &pg_url,
        &temp.path().join("unused.json"),
        &schema,
        &marker,
        Duration::from_secs(8),
    )
    .await;
    if !probe.real_child_reaped {
        return match probe.result {
            Err(err) => {
                Err(err
                    .context(format!("real child exit/reap failed; preserving owned schema `{schema}` without DROP")))
            }
            Ok(_) => Err(anyhow!(
                "real child exit/reap could not be confirmed; preserving owned schema `{schema}` without DROP"
            )),
        };
    }

    let check_res: Result<()> = async {
        let err = match probe.result {
            Err(err) => err,
            Ok(_) => return Err(anyhow!("simulated reap failure probe must fail")),
        };
        let text = format!("{err:#}");
        ensure!(text.contains("cleanup-not-complete"), "expected cleanup-not-complete error, got: {text}");
        ensure!(text.contains(&schema), "expected preserved owned schema `{schema}` in error: {text}");
        ensure!(marker.is_file(), "probe worker did not migrate `{schema}` before timeout");
        ensure!(
            Db::schema_exists(&pg_url, &schema).await?,
            "owned schema `{schema}` must NOT be dropped when child exit/reap is unconfirmed"
        );
        Ok(())
    }
    .await;

    let cleanup_res: Result<()> = match tokio::time::timeout(Duration::from_secs(10), async {
        Db::drop_owned_schema(&pg_url, &schema).await?;
        ensure!(
            !Db::schema_exists(&pg_url, &schema).await?,
            "final test-harness drop_owned_schema failed to remove `{schema}`"
        );
        Ok::<(), anyhow::Error>(())
    })
    .await
    {
        Ok(inner) => inner,
        Err(_) => Err(anyhow!("timed out after 10s cleaning up owned schema `{schema}`")),
    };

    match (check_res, cleanup_res) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(c_err)) => Err(c_err),
        (Err(err), Ok(())) => Err(err),
        (Err(err), Err(c_err)) => {
            Err(err.context(format!("additionally, bounded cleanup of owned schema `{schema}` failed: {c_err:#}")))
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires real PG + Garage S3 + stock Git"]
async fn real_garage_s3_and_pg_verifier_budgets_smoke() -> Result<()> {
    let _serial = SUITE_LOCK.lock().await;
    let profile = BlobProfile::from_env().map_err(|e| anyhow!("real BlobProfile::from_env failed: {e}"))?;
    let store = BlobStore::open(profile).map_err(|e| anyhow!("real BlobStore::open failed: {e}"))?;
    let git = git_binary()?;
    let db = Db::setup().await?;

    let outcome = async {
        let prepared = prepare_fresh_commit(&db, &store, &git, 9001, 128 * 1024).await?;
        let verifier = PackVerifier::new(store.clone(), git.clone())?;
        let snap_ref = commit_and_pin_snapshot(&db, &prepared, &verifier, false).await?;
        let materializer = PgPackSnapshotMaterializer::new(store.clone(), git.clone())?;
        let view = materializer.read(&db.pool, &snap_ref, deadline()).await?;
        verify_sha256_equal(
            &view.pack_bytes(prepared.pack_id, deadline()).await?,
            &prepared.pack_bytes,
            "garage pack",
        )?;
        verify_sha256_equal(&view.idx_bytes(prepared.pack_id, deadline()).await?, &prepared.idx_bytes, "garage idx")?;
        let metrics = verifier_metrics();
        ensure!(metric_u64(&metrics, "staging_reclaimed_bytes_total") > 0);
        ensure!(metric_u64(&metrics, "staging_reserved_bytes_current") == 0);
        Ok::<(), anyhow::Error>(())
    }
    .await;

    db.finish(outcome).await
}
