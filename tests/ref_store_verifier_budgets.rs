//! Live PostgreSQL + S3 + stock Git integration and benchmark suite for Issue #176.

mod verifier_budgets_support;

use anyhow::{Result, anyhow, ensure};
use rootyard::blob_store::config::BlobProfile;
use rootyard::blob_store::opendal::BlobStore;
use rootyard::ref_store::core::pack_commit::PackVerifier;
use rootyard::ref_store::core::pack_snapshot::PgPackSnapshotMaterializer;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant as StdInstant};
use tokio::sync::{Mutex, Semaphore};
use verifier_budgets_support::bench::{
    BenchmarkReceipt, CohortMeasurement, ComparisonDeltas, EnvironmentInfo, LatencyStats, metric_delta, metric_u64,
    read_proc_vm_hwm_kib, verifier_metrics, write_receipt,
};
use verifier_budgets_support::pg_git::{
    Db, PreparedCommit, commit_and_pin_snapshot, deadline, git_binary, git_version_string, prepare_fresh_commit,
    std_deadline,
};
use verifier_budgets_support::s3::LoopbackS3;

static SUITE_LOCK: Mutex<()> = Mutex::const_new(());

fn update_peak(peak: &AtomicUsize, value: usize) {
    let mut cur = peak.load(Ordering::Relaxed);
    while value > cur {
        match peak.compare_exchange_weak(cur, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(observed) => cur = observed,
        }
    }
}

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
            delays.push(s3.add_get_delay(slow.tenant.to_string(), Duration::from_millis(800)));
        }

        let m_before = verifier_metrics();
        let c_before = s3.counters();
        let verifier = Arc::new(PackVerifier::new(store.clone(), git.clone())?);
        let materializer = Arc::new(PgPackSnapshotMaterializer::new(store.clone(), git.clone())?);

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
                let snap_ref = commit_fast_snapshot(&db_pool, &fast, &receipt).await?;
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
        ensure!(
            fast_wall < Duration::from_millis(950),
            "fast native Git commits starved behind 800ms slow Blob downloads: fast_wall={fast_wall:?}"
        );

        for h in slow_handles {
            let proof = h.await.map_err(|e| anyhow!("slow task panicked: {e}"))??;
            ensure!(proof.evidence_digest().as_hex().len() == 64);
        }
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

async fn commit_fast_snapshot(
    pool: &deadpool_postgres::Pool,
    fast: &PreparedCommit,
    receipt: &rootyard::ref_store::core::pack_commit::PackCommitReceipt,
) -> Result<rootyard::ref_store::core::PackSnapshotRef> {
    let owner = uuid::Uuid::new_v4();
    let scope = rootyard::ref_store::core::MetadataSnapshotScope::new(
        fast.repo,
        fast.tenant,
        owner,
        rootyard::ref_store::MetadataPinPurpose::Verification,
        fast.gate.object_format(),
        fast.gate.history_incarnation(),
        fast.gate.authority_epoch(),
        fast.gate.group_epoch(),
    )?;
    let snapshot_id = uuid::Uuid::new_v4();
    let pin_id = uuid::Uuid::new_v4();
    let expected =
        rootyard::ref_store::core::PackSnapshotExpectation::new(receipt.terminal.revision, receipt.terminal.digest)?;
    let req = rootyard::ref_store::core::CreatePackSnapshotRequest::new(
        scope,
        uuid::Uuid::new_v4(),
        pin_id,
        snapshot_id,
        300,
        expected,
    )?;
    let mut client = pool.get().await?;
    let outcome = rootyard::ref_store::core::PgPackSnapshot.create(&mut client, &req, deadline()).await?;
    ensure!(
        matches!(outcome, rootyard::ref_store::core::PackSnapshotOutcome::Created { .. }),
        "snapshot was not created"
    );
    Ok(rootyard::ref_store::core::PackSnapshotRef::new(fast.repo, fast.tenant, snapshot_id, pin_id, 1)?)
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
            guards.push(s3.add_get_delay(m.tenant.to_string(), Duration::from_millis(800)));
        }
        guards.push(s3.add_get_delay(timeout_commit.tenant.to_string(), Duration::from_millis(800)));

        let m_before = verifier_metrics();
        let verifier = Arc::new(PackVerifier::new(store.clone(), git.clone())?);

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
        ensure!(
            fg_elapsed < Duration::from_millis(950),
            "foreground commit + view blocked behind 800ms maintenance backlog: {fg_elapsed:?}"
        );

        let tight_deadline = StdInstant::now() + Duration::from_millis(80);
        let timed_out = verifier.verify(&timeout_commit.plan, &timeout_commit.context, tight_deadline).await;
        ensure!(timed_out.is_err(), "800ms download under 80ms unified deadline must fail closed");

        for h in maint_tasks {
            let proof = h.await.map_err(|e| anyhow!("maintenance verify panicked: {e}"))??;
            ensure!(proof.evidence_digest().as_hex().len() == 64);
        }
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

async fn run_benchmark_phase(
    db: &Db,
    verifier: &Arc<PackVerifier>,
    commits: Vec<(PreparedCommit, bool)>,
    coupled_cap: Option<Arc<Semaphore>>,
    s3: &LoopbackS3,
) -> Result<CohortMeasurement> {
    let slow_indices: Vec<_> = commits.iter().enumerate().filter(|(_, (_, slow))| *slow).map(|(i, _)| i).collect();
    let fast_indices: Vec<_> = commits.iter().enumerate().filter(|(_, (_, slow))| !*slow).map(|(i, _)| i).collect();
    let wrapped: Vec<Arc<PreparedCommit>> = commits.into_iter().map(|(c, _)| Arc::new(c)).collect();

    let m0 = verifier_metrics();
    let c0 = s3.counters();
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let phase_start = StdInstant::now();

    let mut handles = Vec::with_capacity(wrapped.len());
    for is_slow in [true, false] {
        let indices = if is_slow { &slow_indices } else { &fast_indices };
        if !is_slow {
            // Brief offset guarantees slow Blob GETs enter the pool ahead of fast jobs identically in both phases.
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
        for &idx in indices {
            let item = Arc::clone(&wrapped[idx]);
            let v = Arc::clone(verifier);
            let pool = db.pool.clone();
            let sem = coupled_cap.clone();
            let active_c = Arc::clone(&active);
            let peak_c = Arc::clone(&peak);
            handles.push(tokio::spawn(async move {
                let t0 = StdInstant::now();
                let _coupled_permit = match sem {
                    Some(s) => Some(s.acquire_owned().await.map_err(|e| anyhow!("coupled sem closed: {e}"))?),
                    None => None,
                };
                let cur = active_c.fetch_add(1, Ordering::Relaxed) + 1;
                update_peak(&peak_c, cur);
                let proof = v.verify(&item.plan, &item.context, std_deadline()).await?;
                let mut client = pool.get().await?;
                let receipt = rootyard::ref_store::core::pack_commit::PgPackCommit
                    .commit_verified_pending(&mut client, &item.plan, &item.token, &proof, deadline())
                    .await?;
                ensure!(receipt.is_committed(), "bench commit did not commit");
                active_c.fetch_sub(1, Ordering::Relaxed);
                Ok::<(bool, u64), anyhow::Error>((is_slow, t0.elapsed().as_micros() as u64))
            }));
        }
    }

    let mut all_us = Vec::with_capacity(wrapped.len());
    let mut slow_us = Vec::new();
    let mut fast_us = Vec::new();
    for h in handles {
        let (is_slow, us) = h.await.map_err(|e| anyhow!("bench worker panicked: {e}"))??;
        all_us.push(us);
        if is_slow {
            slow_us.push(us);
        } else {
            fast_us.push(us);
        }
    }
    let wall_ms = phase_start.elapsed().as_secs_f64() * 1000.0;
    let m1 = verifier_metrics();
    let c1 = s3.counters().delta_since(c0);
    let total_ops = all_us.len();

    Ok(CohortMeasurement {
        total_ops,
        wall_ms,
        throughput_ops_per_sec: if wall_ms > 0.0 { total_ops as f64 / (wall_ms / 1000.0) } else { 0.0 },
        all_latency: LatencyStats::from_micros(&all_us),
        slow_latency: LatencyStats::from_micros(&slow_us),
        fast_latency: LatencyStats::from_micros(&fast_us),
        peak_active_ops: peak.load(Ordering::Relaxed),
        download_queue_wait_micros: metric_delta(&m1, &m0, "download_queue_wait_micros"),
        native_queue_wait_micros: metric_delta(&m1, &m0, "native_queue_wait_micros"),
        view_queue_wait_micros: metric_delta(&m1, &m0, "view_queue_wait_micros"),
        blob_get_requests: metric_delta(&m1, &m0, "blob_get_requests"),
        blob_get_bytes: metric_delta(&m1, &m0, "blob_get_bytes"),
        readback_bytes: metric_delta(&m1, &m0, "readback_bytes"),
        staging_reserved_bytes_peak: metric_u64(&m1, "staging_reserved_bytes_peak"),
        staging_reclaimed_bytes_delta: metric_delta(&m1, &m0, "staging_reclaimed_bytes_total"),
        download_in_flight_peak: metric_u64(&m1, "download_in_flight_peak"),
        native_in_flight_peak: metric_u64(&m1, "native_in_flight_peak"),
        s3_get_requests: c1.get_requests,
        s3_get_bytes: c1.get_bytes,
        proc_vm_hwm_kib: read_proc_vm_hwm_kib(),
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verifier_budget_before_vs_after_pg_s3_git_benchmark() -> Result<()> {
    let _serial = SUITE_LOCK.lock().await;
    let s3 = LoopbackS3::shared();
    let store = s3.open_blob_store()?;
    let git = git_binary()?;
    let db = Db::setup().await?;

    let outcome = async {
        let mut before_set = Vec::with_capacity(7);
        let mut after_set = Vec::with_capacity(7);
        let mut delays = Vec::new();
        for i in 0..3 {
            let b = prepare_fresh_commit(&db, &store, &git, 1000 + i, 192 * 1024).await?;
            let a = prepare_fresh_commit(&db, &store, &git, 2000 + i, 192 * 1024).await?;
            delays.push(s3.add_get_delay(b.tenant.to_string(), Duration::from_millis(400)));
            delays.push(s3.add_get_delay(a.tenant.to_string(), Duration::from_millis(400)));
            before_set.push((b, true));
            after_set.push((a, true));
        }
        for i in 0..4 {
            before_set.push((prepare_fresh_commit(&db, &store, &git, 3000 + i, 128 * 1024).await?, false));
            after_set.push((prepare_fresh_commit(&db, &store, &git, 4000 + i, 128 * 1024).await?, false));
        }

        let verifier = Arc::new(PackVerifier::new(store.clone(), git.clone())?);
        let before =
            run_benchmark_phase(&db, &verifier, before_set, Some(Arc::new(Semaphore::new(2))), s3).await?;
        let after = run_benchmark_phase(&db, &verifier, after_set, None, s3).await?;
        drop(delays);

        let deltas = ComparisonDeltas {
            wall_speedup: if after.wall_ms > 0.0 { before.wall_ms / after.wall_ms } else { 0.0 },
            fast_p95_ratio: if after.fast_latency.p95_ms > 0.0 {
                before.fast_latency.p95_ms / after.fast_latency.p95_ms
            } else {
                0.0
            },
            fast_p99_ratio: if after.fast_latency.p99_ms > 0.0 {
                before.fast_latency.p99_ms / after.fast_latency.p99_ms
            } else {
                0.0
            },
            native_wait_delta_micros: after.native_queue_wait_micros as i64 - before.native_queue_wait_micros as i64,
            download_wait_delta_micros: after.download_queue_wait_micros as i64
                - before.download_queue_wait_micros as i64,
            reclaimed_bytes_after: after.staging_reclaimed_bytes_delta,
        };

        let receipt = BenchmarkReceipt {
            issue: "#176",
            workload: "3 slow (400ms GET delay, ~192KiB pack) + 4 fast (0ms GET delay, ~128KiB pack) per phase"
                .to_owned(),
            methodology: "before_coupled wraps PackVerifier::verify+commit in Semaphore(2) across Blob GET + native Git (mirroring pre-#176 single 2-slot pool); after_separated runs uncoupled DOWNLOAD_SLOTS=4 and VERIFIER_SLOTS=2",
            environment: EnvironmentInfo {
                os: std::env::consts::OS,
                arch: std::env::consts::ARCH,
                blob_backend: "loopback_http_s3_via_opendal",
                postgres_source: db.pg_source,
                git_version: git_version_string(&git)?,
                source_commit: std::env::var("GITHUB_SHA").ok(),
            },
            before_coupled: before,
            after_separated: after,
            deltas,
        };
        let path = write_receipt(&receipt)?;
        eprintln!("[verifier-budget-bench] wrote {}:\n{}", path.display(), serde_json::to_string_pretty(&receipt)?);
        ensure!(receipt.deltas.reclaimed_bytes_after > 0, "expected reclaimed staging bytes in separated phase");
        Ok::<(), anyhow::Error>(())
    }
    .await;

    db.finish(outcome).await
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
