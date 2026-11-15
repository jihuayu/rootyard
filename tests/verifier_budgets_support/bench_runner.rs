//! Isolated child-process runner for comparing coupled `Semaphore(2)` vs. separated verifier budgets.

use super::bench::{
    BenchmarkReceipt, CohortMeasurement, ComparisonDeltas, EnvironmentInfo, LatencyStats, metric_delta, metric_u64,
    read_cohort_file, read_proc_vm_hwm_kib, verifier_metrics, write_cohort_file, write_receipt,
};
use super::pg_git::{
    Db, PreparedCommit, deadline, git_binary, git_version_string, prepare_commit_with_tenant, resolved_database,
    std_deadline,
};
use super::s3::{LoopbackS3, SLOW_DELAY_KEY_TAG, open_blob_store_at, tagged_tenant_uuid};
use anyhow::{Result, anyhow, ensure};
use rootyard::ref_store::core::pack_commit::{PackVerifier, PgPackCommit};
use std::path::Path;
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant as StdInstant};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Child;
use tokio::sync::Semaphore;

pub const ENV_BENCH_PHASE: &str = "ROOTYARD_VB_PHASE";
const ENV_BENCH_OUT: &str = "ROOTYARD_VB_OUT";
const ENV_BENCH_S3_ENDPOINT: &str = "ROOTYARD_VB_S3_ENDPOINT";
const ENV_BENCH_SCHEMA: &str = "ROOTYARD_VB_SCHEMA";
const ENV_BENCH_PROBE_MARKER: &str = "ROOTYARD_VB_PROBE_MARKER";

fn update_peak(peak: &AtomicU64, value: u64) {
    let mut cur = peak.load(Ordering::Relaxed);
    while value > cur {
        match peak.compare_exchange_weak(cur, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(observed) => cur = observed,
        }
    }
}

async fn run_benchmark_phase(
    db: &Db,
    verifier: &Arc<PackVerifier>,
    commits: Vec<(PreparedCommit, bool)>,
    coupled_cap: Option<Arc<Semaphore>>,
) -> Result<CohortMeasurement> {
    let slow_indices: Vec<_> = commits.iter().enumerate().filter(|(_, (_, slow))| *slow).map(|(i, _)| i).collect();
    let fast_indices: Vec<_> = commits.iter().enumerate().filter(|(_, (_, slow))| !*slow).map(|(i, _)| i).collect();
    let wrapped: Vec<Arc<PreparedCommit>> = commits.into_iter().map(|(c, _)| Arc::new(c)).collect();

    let m0 = verifier_metrics();
    ensure!(
        metric_u64(&m0, "staging_reserved_bytes_peak") == 0
            && metric_u64(&m0, "download_in_flight_peak") == 0
            && metric_u64(&m0, "native_in_flight_peak") == 0,
        "isolated benchmark worker started with non-zero global peaks: {m0}"
    );
    let active = Arc::new(AtomicU64::new(0));
    let peak = Arc::new(AtomicU64::new(0));
    let sampling_done = Arc::new(AtomicBool::new(false));
    let sampled_staging_peak = Arc::new(AtomicU64::new(0));
    let sampled_download_peak = Arc::new(AtomicU64::new(0));
    let sampled_native_peak = Arc::new(AtomicU64::new(0));
    let sampler = {
        let done = Arc::clone(&sampling_done);
        let st_peak = Arc::clone(&sampled_staging_peak);
        let dl_peak = Arc::clone(&sampled_download_peak);
        let nat_peak = Arc::clone(&sampled_native_peak);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(5));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            while !done.load(Ordering::Relaxed) {
                interval.tick().await;
                let snap = verifier_metrics();
                update_peak(&st_peak, metric_u64(&snap, "staging_reserved_bytes_current"));
                update_peak(&dl_peak, metric_u64(&snap, "download_in_flight"));
                update_peak(&nat_peak, metric_u64(&snap, "native_in_flight"));
            }
        })
    };

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
                let receipt = PgPackCommit
                    .commit_verified_pending(&mut client, &item.plan, &item.token, &proof, deadline())
                    .await?;
                ensure!(receipt.is_committed(), "bench commit did not commit");
                active_c.fetch_sub(1, Ordering::Relaxed);
                Ok::<(bool, u64), anyhow::Error>((is_slow, t0.elapsed().as_micros() as u64))
            }));
        }
    }

    let join_outcome: Result<(Vec<u64>, Vec<u64>, Vec<u64>)> = async {
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
        Ok((all_us, slow_us, fast_us))
    }
    .await;
    let wall_ms = phase_start.elapsed().as_secs_f64() * 1000.0;
    sampling_done.store(true, Ordering::Relaxed);
    let _ = sampler.await;
    let (all_us, slow_us, fast_us) = join_outcome?;
    let m1 = verifier_metrics();
    let total_ops = all_us.len();

    Ok(CohortMeasurement {
        total_ops,
        wall_ms,
        throughput_ops_per_sec: if wall_ms > 0.0 { total_ops as f64 / (wall_ms / 1000.0) } else { 0.0 },
        all_latency: LatencyStats::from_micros(&all_us),
        slow_latency: LatencyStats::from_micros(&slow_us),
        fast_latency: LatencyStats::from_micros(&fast_us),
        peak_active_ops: peak.load(Ordering::Relaxed) as usize,
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
        cohort_sampled_staging_bytes_peak: sampled_staging_peak.load(Ordering::Relaxed),
        cohort_sampled_download_in_flight_peak: sampled_download_peak.load(Ordering::Relaxed),
        cohort_sampled_native_in_flight_peak: sampled_native_peak.load(Ordering::Relaxed),
        s3_get_requests: 0,
        s3_get_bytes: 0,
        proc_vm_hwm_kib: read_proc_vm_hwm_kib(),
    })
}

async fn drain_pipe<R: AsyncRead + Unpin>(pipe: Option<R>) -> Result<Vec<u8>> {
    let Some(mut reader) = pipe else {
        return Ok(Vec::new());
    };
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).await?;
    Ok(buf)
}

async fn collect_pipe(mut task: tokio::task::JoinHandle<Result<Vec<u8>>>) -> String {
    match tokio::time::timeout(Duration::from_secs(2), &mut task).await {
        Ok(Ok(Ok(bytes))) => String::from_utf8_lossy(&bytes).into_owned(),
        Ok(Ok(Err(err))) => format!("<pipe read error: {err}>"),
        Ok(Err(join_err)) => format!("<pipe task panicked: {join_err}>"),
        Err(_) => {
            task.abort();
            "<pipe drain timed out>".to_owned()
        }
    }
}

async fn terminate_and_reap(child: &mut Child) -> Result<ExitStatus> {
    if let Some(status) = child.try_wait()? {
        return Ok(status);
    }
    let _ = child.start_kill();
    tokio::time::timeout(Duration::from_secs(5), child.wait())
        .await
        .map_err(|_| anyhow!("timed out waiting 5s for killed child exit"))?
        .map_err(Into::into)
}

pub async fn run_benchmark_worker(phase: &str) -> Result<()> {
    let schema = std::env::var(ENV_BENCH_SCHEMA).map_err(|_| anyhow!("{ENV_BENCH_SCHEMA} missing in worker"))?;
    if phase == "hang_cleanup_probe" {
        let marker =
            std::env::var(ENV_BENCH_PROBE_MARKER).map_err(|_| anyhow!("{ENV_BENCH_PROBE_MARKER} missing in worker"))?;
        let db = Db::setup_with_schema(schema).await?;
        let outcome = async {
            std::fs::write(&marker, b"migrated\n")?;
            tokio::time::sleep(Duration::from_secs(60)).await;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        return db.finish(outcome).await;
    }

    let out_path = std::env::var(ENV_BENCH_OUT).map_err(|_| anyhow!("{ENV_BENCH_OUT} missing in worker"))?;
    let endpoint =
        std::env::var(ENV_BENCH_S3_ENDPOINT).map_err(|_| anyhow!("{ENV_BENCH_S3_ENDPOINT} missing in worker"))?;
    let (seed_base, coupled_cap) = match phase {
        "before" => (1000_u64, Some(Arc::new(Semaphore::new(2)))),
        "after" => (2000_u64, None),
        other => return Err(anyhow!("unsupported {ENV_BENCH_PHASE} value `{other}`")),
    };

    let store = open_blob_store_at(&endpoint)?;
    let git = git_binary()?;
    let db = Db::setup_with_schema(schema).await?;
    let outcome = async {
        let mut commits = Vec::with_capacity(7);
        for i in 0..3 {
            let slow =
                prepare_commit_with_tenant(&db, &store, &git, seed_base + i, 192 * 1024, tagged_tenant_uuid(true))
                    .await?;
            commits.push((slow, true));
        }
        for i in 0..4 {
            let fast = prepare_commit_with_tenant(
                &db,
                &store,
                &git,
                seed_base + 2000 + i,
                128 * 1024,
                tagged_tenant_uuid(false),
            )
            .await?;
            commits.push((fast, false));
        }
        let verifier = Arc::new(PackVerifier::new(store, git)?);
        let measurement = run_benchmark_phase(&db, &verifier, commits, coupled_cap).await?;
        write_cohort_file(Path::new(&out_path), &measurement)?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    db.finish(outcome).await
}

struct WorkerSpec<'a> {
    exe: &'a Path,
    phase: &'a str,
    pg_url: &'a str,
    s3_endpoint: &'a str,
    out_path: &'a Path,
    schema: &'a str,
    probe_marker: Option<&'a Path>,
    timeout: Duration,
}

async fn spawn_worker_with_cleanup(spec: WorkerSpec<'_>) -> Result<CohortMeasurement> {
    let mut cmd = tokio::process::Command::new(spec.exe);
    cmd.args(["verifier_budget_before_vs_after_pg_s3_git_benchmark", "--exact", "--nocapture", "--test-threads=1"])
        .env(ENV_BENCH_PHASE, spec.phase)
        .env(ENV_BENCH_OUT, spec.out_path)
        .env("ROOTYARD_TEST_DATABASE_URL", spec.pg_url)
        .env(ENV_BENCH_S3_ENDPOINT, spec.s3_endpoint)
        .env(ENV_BENCH_SCHEMA, spec.schema)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(marker) = spec.probe_marker {
        cmd.env(ENV_BENCH_PROBE_MARKER, marker);
    }

    let mut child = cmd.spawn()?;
    let stdout_task = tokio::spawn(drain_pipe(child.stdout.take()));
    let stderr_task = tokio::spawn(drain_pipe(child.stderr.take()));

    let wait_res = tokio::time::timeout(spec.timeout, child.wait()).await;
    let cohort_result: Result<CohortMeasurement> = match wait_res {
        Ok(Ok(status)) => {
            let stdout = collect_pipe(stdout_task).await;
            let stderr = collect_pipe(stderr_task).await;
            if status.success() {
                read_cohort_file(spec.out_path)
            } else {
                Err(anyhow!(
                    "isolated cohort `{}` exited with {status}:\nstdout:\n{stdout}\nstderr:\n{stderr}",
                    spec.phase
                ))
            }
        }
        Ok(Err(err)) => {
            let reap = terminate_and_reap(&mut child).await;
            let stdout = collect_pipe(stdout_task).await;
            let stderr = collect_pipe(stderr_task).await;
            Err(anyhow!(
                "failed waiting on isolated cohort `{}`: {err} (reap: {reap:?})\nstdout:\n{stdout}\nstderr:\n{stderr}",
                spec.phase
            ))
        }
        Err(_) => {
            let reap = terminate_and_reap(&mut child).await;
            let stdout = collect_pipe(stdout_task).await;
            let stderr = collect_pipe(stderr_task).await;
            Err(anyhow!(
                "isolated cohort `{}` timed out after {:?} (reap: {reap:?})\nstdout:\n{stdout}\nstderr:\n{stderr}",
                spec.phase,
                spec.timeout
            ))
        }
    };

    let cleanup_res = Db::drop_owned_schema(spec.pg_url, spec.schema).await;
    match (cohort_result, cleanup_res) {
        (Ok(cohort), Ok(())) => Ok(cohort),
        (Ok(_), Err(cleanup_err)) => Err(cleanup_err.context(format!("cleanup failed for schema `{}`", spec.schema))),
        (Err(err), Ok(())) => Err(err),
        (Err(err), Err(cleanup_err)) => {
            Err(err.context(format!("cleanup also failed for schema `{}`: {cleanup_err:#}", spec.schema)))
        }
    }
}

pub(crate) async fn run_isolated_cohort_with_timeout(
    exe: &Path,
    phase: &str,
    pg_url: &str,
    s3_endpoint: &str,
    out_path: &Path,
    timeout: Duration,
) -> Result<CohortMeasurement> {
    let schema = Db::fresh_schema_name();
    spawn_worker_with_cleanup(WorkerSpec {
        exe,
        phase,
        pg_url,
        s3_endpoint,
        out_path,
        schema: &schema,
        probe_marker: None,
        timeout,
    })
    .await
}

pub(crate) async fn run_hang_cleanup_probe(
    exe: &Path,
    pg_url: &str,
    out_path: &Path,
    schema: &str,
    marker: &Path,
    timeout: Duration,
) -> Result<CohortMeasurement> {
    spawn_worker_with_cleanup(WorkerSpec {
        exe,
        phase: "hang_cleanup_probe",
        pg_url,
        s3_endpoint: "http://127.0.0.1:0",
        out_path,
        schema,
        probe_marker: Some(marker),
        timeout,
    })
    .await
}

async fn run_isolated_cohort(
    exe: &Path,
    phase: &str,
    pg_url: &str,
    s3: &LoopbackS3,
    out_path: &Path,
) -> Result<CohortMeasurement> {
    let c_before = s3.counters();
    let mut cohort =
        run_isolated_cohort_with_timeout(exe, phase, pg_url, s3.endpoint(), out_path, Duration::from_secs(120)).await?;
    let s3_delta = s3.counters().delta_since(c_before);
    cohort.s3_get_requests = s3_delta.get_requests;
    cohort.s3_get_bytes = s3_delta.get_bytes;
    Ok(cohort)
}

pub async fn execute_isolated_benchmark() -> Result<()> {
    let (pg_url, postgres_source) = resolved_database().await?;
    let s3 = LoopbackS3::shared();
    let _slow_delay = s3.add_get_delay(SLOW_DELAY_KEY_TAG, Duration::from_millis(400));
    let git = git_binary()?;
    let exe = std::env::current_exe()?;
    let temp = tempfile::tempdir()?;

    let before = run_isolated_cohort(&exe, "before", &pg_url, s3, &temp.path().join("before.json")).await?;
    let after = run_isolated_cohort(&exe, "after", &pg_url, s3, &temp.path().join("after.json")).await?;
    drop(_slow_delay);

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
        download_wait_delta_micros: after.download_queue_wait_micros as i64 - before.download_queue_wait_micros as i64,
        reclaimed_bytes_after: after.staging_reclaimed_bytes_delta,
    };

    let receipt = BenchmarkReceipt {
        issue: "#176",
        baseline_kind: "simulated_coupled_semaphore_2_on_current_binary",
        process_isolation: "fresh_child_process_per_cohort_via_current_exe",
        rss_measurement: "per_child_process_proc_self_status_VmHWM_kib",
        peak_measurement: "fresh_child_process_budget_registry_peak_plus_5ms_cohort_gauge_sampler",
        workload: "3 slow (400ms GET delay via 5105de1a- tag, ~192KiB pack) + 4 fast (0ms GET delay, ~128KiB pack) per isolated cohort".to_owned(),
        methodology: "Each cohort runs in a fresh child process (`ROOTYARD_VB_PHASE=before|after`) against shared PostgreSQL + parent LoopbackS3; `before_coupled` wraps `PackVerifier::verify+commit` in a simulated `Semaphore(2)` across Blob GET + native Git, while `after_separated` runs uncoupled `DOWNLOAD_SLOTS=4` and `VERIFIER_SLOTS=2`",
        limitations: vec![
            "before_coupled is a simulated Semaphore(2) harness on the current binary rather than a checkout of pre-#176 main".to_owned(),
            "blob storage uses in-process loopback_http_s3_via_opendal with synthetic 400ms GET delay on slow-tagged objects rather than a networked Garage S3 cluster".to_owned(),
        ],
        environment: EnvironmentInfo {
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            binary_path: exe.display().to_string(),
            blob_backend: "loopback_http_s3_via_opendal",
            postgres_source,
            git_version: git_version_string(&git)?,
            source_commit: std::env::var("GITHUB_SHA").ok(),
        },
        before_coupled: before,
        after_separated: after,
        deltas,
    };
    let path = write_receipt(&receipt)?;
    eprintln!("[verifier-budget-bench] wrote {}:\n{}", path.display(), serde_json::to_string_pretty(&receipt)?);
    ensure!(receipt.before_coupled.s3_get_requests > 0 && receipt.after_separated.s3_get_requests > 0);
    ensure!(
        receipt.before_coupled.slow_latency.min_ms >= 400.0 && receipt.after_separated.slow_latency.min_ms >= 400.0
    );
    ensure!(receipt.deltas.reclaimed_bytes_after > 0, "expected reclaimed staging bytes in separated phase");
    Ok(())
}
