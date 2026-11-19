//! Real multi-process scheduled-runtime child for Safe GC acceptance (#122).
//!
//! The parent integration test spawns this binary as a separate OS process so a
//! `DistributedRefCas` scheduled pass proves production-source capture and worker
//! runtime in a process that never shared the parent's in-memory registry. Pass #1 is
//! terminated with an uncatchable `SIGKILL` while it holds the PG fence.

use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use rootyard::{AppState, dispatch, metrics, storage};
use serde_json::Value;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub(super) const CHILD_MODE_ENV: &str = "ROOTYARD_SAFE_GC_CHILD_MODE";
const CHILD_DB_URL_ENV: &str = "ROOTYARD_SAFE_GC_CHILD_DB_URL";
const CHILD_PG_SCHEMA_ENV: &str = "ROOTYARD_SAFE_GC_CHILD_PG_SCHEMA";
const CHILD_ROOT_ENV: &str = "ROOTYARD_SAFE_GC_CHILD_ROOT";
const CHILD_REPO_ID_ENV: &str = "ROOTYARD_SAFE_GC_CHILD_REPO_ID";
const CHILD_SKIP_JOB_ID_ENV: &str = "ROOTYARD_SAFE_GC_CHILD_SKIP_JOB_ID";
const CHILD_READY_MARKER_ENV: &str = "ROOTYARD_SAFE_GC_CHILD_READY_MARKER";
const CHILD_OUT_JSON_ENV: &str = "ROOTYARD_SAFE_GC_CHILD_OUT_JSON";
const ENV_BLOB_SAFE_GC_DESTRUCTIVE: &str = "ROOTYARD_BLOB_SAFE_GC_DESTRUCTIVE";
const MODE_PASS1: &str = "pass1_sigkill_after_one_delete";
const MODE_PASS2: &str = "pass2_scheduled_runtime";
const MODE_PROBE_NO_DELETE: &str = "probe_cold_runtime_no_delete";
const FENCE_BUSY: &str = "another physical GC holds the repository fence";
const ENTRYPOINT: &str = "pg_child_worker::child_process_entrypoint";

pub(super) struct ChildOutcome {
    pub pid: u32,
    pub job_id: Uuid,
    pub result: Value,
}

pub(super) struct SigkillOutcome {
    pub pid: u32,
    pub job_id: Uuid,
}

/// Spawn pass #1 in a fresh OS process, wait for its durable pause marker, then `SIGKILL` it.
pub(super) async fn spawn_pass1_sigkill_child(
    storage_root: &Path,
    db_url: &str,
    schema: &str,
    repo_id: Uuid,
    s3_env_pairs: &[(String, Option<std::ffi::OsString>)],
    pool: &deadpool_postgres::Pool,
) -> Result<SigkillOutcome> {
    let marker = storage_root.join(format!("safe-gc-pass1-ready-{}.json", Uuid::new_v4()));
    let out_path = storage_root.join(format!("safe-gc-pass1-out-{}.json", Uuid::new_v4()));
    let mut child = spawn_command(MODE_PASS1, storage_root, db_url, schema, repo_id, s3_env_pairs)
        .env(CHILD_READY_MARKER_ENV, &marker)
        .env(CHILD_OUT_JSON_ENV, &out_path)
        .spawn()
        .context("spawn safe-gc pass1 child process")?;
    let pid = child.id();
    let deadline = Instant::now() + Duration::from_secs(90);
    while !marker.is_file() {
        if Instant::now() > deadline {
            let _ = child.kill();
            bail!("pass1 child never paused after its first provider delete");
        }
        if let Some(status) = child.try_wait()? {
            bail!("pass1 child exited before the external-kill pause: {status}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let ready: Value = serde_json::from_slice(&std::fs::read(&marker)?).context("parse pass1 ready marker")?;
    ensure!(ready["deleted_this_pass"].as_u64() == Some(1), "pass1 must stop after exactly one delete");
    let job_id = running_job_id(pool, repo_id).await?;
    let status = {
        child.kill().context("SIGKILL pass1 child")?;
        child.wait().context("wait for SIGKILLed pass1 child")?
    };
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        ensure!(status.signal() == Some(libc::SIGKILL), "pass1 must die from SIGKILL, got {status:?}");
    }
    #[cfg(not(unix))]
    ensure!(!status.success(), "pass1 must be terminated, got {status:?}");
    assert_eq!(running_job_id(pool, repo_id).await?, job_id, "SIGKILL must leave the leased job running");
    Ok(SigkillOutcome { pid, job_id })
}

/// Spawn pass #2 in a fresh OS process: the scheduled runtime recovers the stale lease itself.
pub(super) async fn spawn_pass2_scheduled_runtime_child(
    storage_root: &Path,
    db_url: &str,
    schema: &str,
    repo_id: Uuid,
    skip_job_id: Uuid,
    s3_env_pairs: &[(String, Option<std::ffi::OsString>)],
) -> Result<ChildOutcome> {
    let out_path = storage_root.join(format!("safe-gc-child-{MODE_PASS2}-{}.json", Uuid::new_v4()));
    let mut std_cmd = spawn_command(MODE_PASS2, storage_root, db_url, schema, repo_id, s3_env_pairs);
    std_cmd.env(CHILD_SKIP_JOB_ID_ENV, skip_job_id.to_string()).env(CHILD_OUT_JSON_ENV, &out_path);
    let mut child = tokio::process::Command::from(std_cmd).spawn().context("spawn safe-gc pass2 child process")?;
    let status = child.wait().await.context("wait for safe-gc pass2 child")?;
    ensure!(status.success(), "safe-gc child {MODE_PASS2} exited with {status}");
    let raw = std::fs::read_to_string(&out_path).context("read safe-gc child output JSON")?;
    let value: Value = serde_json::from_str(&raw).context("parse safe-gc child output JSON")?;
    Ok(ChildOutcome {
        pid: u32::try_from(value["pid"].as_u64().context("child pid")?).context("child pid overflow")?,
        job_id: value["job_id"].as_str().context("child job_id")?.parse()?,
        result: value.get("result").cloned().unwrap_or(Value::Null),
    })
}

/// Spawn a cold scheduled runtime that must refuse every delete without a live voter quorum.
pub(super) async fn spawn_cold_runtime_no_delete_child(
    storage_root: &Path,
    db_url: &str,
    schema: &str,
    repo_id: Uuid,
    s3_env_pairs: &[(String, Option<std::ffi::OsString>)],
) -> Result<u32> {
    let out_path = storage_root.join(format!("safe-gc-child-{MODE_PROBE_NO_DELETE}-{}.json", Uuid::new_v4()));
    let mut std_cmd = spawn_command(MODE_PROBE_NO_DELETE, storage_root, db_url, schema, repo_id, s3_env_pairs);
    std_cmd.env(CHILD_OUT_JSON_ENV, &out_path);
    let mut child = tokio::process::Command::from(std_cmd).spawn().context("spawn safe-gc cold runtime child")?;
    let status = child.wait().await.context("wait for safe-gc cold runtime child")?;
    ensure!(status.success(), "safe-gc child {MODE_PROBE_NO_DELETE} exited with {status}");
    let raw = std::fs::read_to_string(&out_path).context("read safe-gc cold runtime output JSON")?;
    let value: Value = serde_json::from_str(&raw).context("parse safe-gc cold runtime output JSON")?;
    let pid = u32::try_from(value["pid"].as_u64().context("cold child pid")?).context("cold child pid overflow")?;
    Ok(pid)
}

/// The exactly-one `running` `pg_refstore` job and its live PG fence owner, with no manual SQL.
async fn running_job_id(pool: &deadpool_postgres::Pool, repo_id: Uuid) -> Result<Uuid> {
    let row = pool
        .get()
        .await?
        .query_opt(
            "SELECT j.id, (j.lease_until IS NOT NULL), (r.gc_owner IS NOT NULL), (r.gc_lease_until IS NOT NULL) \
             FROM storage_maintenance_jobs j JOIN repositories r ON r.id = j.repository_id \
             WHERE j.repository_id = $1 AND j.state = 'running' ORDER BY j.created_at DESC LIMIT 1",
            &[&repo_id],
        )
        .await?;
    let row = row.context("no running storage_maintenance_jobs row")?;
    let job_id: Uuid = row.get(0);
    let has_lease: bool = row.get(1);
    let has_gc_owner: bool = row.get(2);
    let has_gc_lease: bool = row.get(3);
    ensure!(
        has_lease && has_gc_owner && has_gc_lease,
        "running job {job_id} must hold a durable lease and a PG repository fence"
    );
    Ok(job_id)
}

fn spawn_command(
    mode: &str,
    storage_root: &Path,
    db_url: &str,
    schema: &str,
    repo_id: Uuid,
    s3_env_pairs: &[(String, Option<std::ffi::OsString>)],
) -> Command {
    let exe = std::env::current_exe().expect("resolve current test executable");
    let mut child = Command::new(exe);
    child
        .args(["--exact", ENTRYPOINT, "--ignored", "--nocapture", "--test-threads=1"])
        .env(CHILD_MODE_ENV, mode)
        .env(CHILD_DB_URL_ENV, db_url)
        .env(CHILD_PG_SCHEMA_ENV, schema)
        .env(CHILD_ROOT_ENV, storage_root)
        .env(CHILD_REPO_ID_ENV, repo_id.to_string())
        .env(ENV_BLOB_SAFE_GC_DESTRUCTIVE, "true")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    for (key, value) in s3_env_pairs {
        match value {
            Some(value) => child.env(key, value),
            None => child.env_remove(key),
        };
    }
    child
}

#[test]
#[ignore = "spawned by the parent integration test as a separate OS process"]
fn child_process_entrypoint() {
    let Ok(mode) = std::env::var(CHILD_MODE_ENV) else {
        return;
    };
    match mode.as_str() {
        MODE_PASS1 | MODE_PASS2 | MODE_PROBE_NO_DELETE => run_child(&mode).expect("safe-gc child process"),
        other => panic!("unknown safe-gc child mode {other}"),
    }
}

fn run_child(mode: &str) -> Result<()> {
    let db_url = std::env::var(CHILD_DB_URL_ENV).context("child database URL")?;
    let schema = std::env::var(CHILD_PG_SCHEMA_ENV).context("child PG schema")?;
    let root = PathBuf::from(std::env::var_os(CHILD_ROOT_ENV).context("child storage root")?);
    let repo_id: Uuid = std::env::var(CHILD_REPO_ID_ENV).context("child repository id")?.parse()?;
    let out_path = PathBuf::from(std::env::var_os(CHILD_OUT_JSON_ENV).context("child output path")?);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("child tokio runtime")?;
    runtime.block_on(async move {
        let pool = super::open_pg_pool_for_schema(&db_url, &schema).await?;
        let cfg = super::app_config(&root, db_url);
        let state = Arc::new(AppState {
            mirror_primary: None,
            dispatch: dispatch::Signals::default(),
            storage: storage::Storage::open(&cfg)?,
            config: cfg,
            pool: pool.clone(),
            hooks: None,
            transfer_metrics: Arc::new(metrics::TransferCounters::default()),
            git_slots: Arc::new(tokio::sync::Semaphore::new(2)),
        });
        let payload = match mode {
            MODE_PASS1 => {
                let marker =
                    PathBuf::from(std::env::var_os(CHILD_READY_MARKER_ENV).context("child ready marker path")?);
                let out = super::pg_refcas_restart_cases::execute_pass1_pause_for_sigkill_after_one_delete(
                    &state,
                    &pool,
                    &super::test_policy(),
                    repo_id,
                    &marker,
                )
                .await?;
                ensure!(out.state == "failed", "pass1 child job state {} != failed", out.state);
                serde_json::json!({"pid": std::process::id(), "job_id": out.job_id})
            }
            MODE_PASS2 => {
                let skip: Uuid = std::env::var(CHILD_SKIP_JOB_ID_ENV).context("child skip job id")?.parse()?;
                unsafe {
                    std::env::set_var("ROOTYARD_STORAGE_MAINTENANCE", "true");
                    std::env::set_var("ROOTYARD_STORAGE_MAINTENANCE_POLL_SECONDS", "1");
                    std::env::set_var("ROOTYARD_STORAGE_SCAN_PERIOD_SECONDS", "1");
                    std::env::set_var("ROOTYARD_STORAGE_REPACK_PACKS", "2");
                    std::env::set_var("ROOTYARD_STORAGE_MAINTENANCE_LEASE_SECONDS", "5");
                    std::env::set_var("ROOTYARD_STORAGE_MAINTENANCE_QUIESCENCE_SECONDS", "2");
                    std::env::set_var("ROOTYARD_STORAGE_MAINTENANCE_MAX_ATTEMPTS", "5");
                    std::env::set_var(ENV_BLOB_SAFE_GC_DESTRUCTIVE, "true");
                }
                let stop = CancellationToken::new();
                let since: f64 = pool
                    .get()
                    .await?
                    .query_one(
                        "SELECT extract(epoch FROM COALESCE(MAX(created_at), to_timestamp(0)))::float8 \
                         FROM storage_maintenance_jobs WHERE repository_id = $1",
                        &[&repo_id],
                    )
                    .await?
                    .get(0);
                let run_task = tokio::spawn(rootyard::storage_lifecycle::run(Arc::clone(&state), stop.clone()));
                let deadline = Instant::now() + Duration::from_secs(35);
                let mut poll = tokio::time::interval(Duration::from_millis(100));
                loop {
                    if Instant::now() > deadline {
                        stop.cancel();
                        bail!("pass2 scheduled runtime did not recover the stale lease within 35s");
                    }
                    poll.tick().await;
                    let rows = pool
                        .get()
                        .await?
                        .query(
                            "SELECT id, kind, state, result, last_error FROM storage_maintenance_jobs \
                             WHERE repository_id = $1 AND id <> $2 AND created_at > to_timestamp($3) \
                             ORDER BY created_at DESC LIMIT 4",
                            &[&repo_id, &skip, &since],
                        )
                        .await?;
                    let mut succeeded = None;
                    for row in rows {
                        let job_id: Uuid = row.get(0);
                        let kind: String = row.get(1);
                        let job_state: String = row.get(2);
                        if job_state == "succeeded" && kind == "pando_tombstone_delete" {
                            let result: Value = row.get(3);
                            succeeded = Some((job_id, result));
                            break;
                        }
                        if job_state == "failed" {
                            let last_error: Option<String> = row.get(4);
                            let err = last_error.unwrap_or_default();
                            if !err.contains(FENCE_BUSY) && !err.contains("lease") {
                                stop.cancel();
                                bail!("pass2 job {job_id} failed unexpectedly: {err}");
                            }
                        }
                    }
                    if let Some((job_id, result)) = succeeded {
                        stop.cancel();
                        run_task.await??;
                        break serde_json::json!({"pid": std::process::id(), "job_id": job_id, "result": result});
                    }
                }
            }
            MODE_PROBE_NO_DELETE => {
                unsafe {
                    std::env::set_var("ROOTYARD_STORAGE_MAINTENANCE", "true");
                    std::env::set_var("ROOTYARD_STORAGE_MAINTENANCE_POLL_SECONDS", "1");
                    std::env::set_var("ROOTYARD_STORAGE_SCAN_PERIOD_SECONDS", "1");
                    std::env::set_var("ROOTYARD_STORAGE_MAINTENANCE_LEASE_SECONDS", "5");
                    std::env::set_var("ROOTYARD_STORAGE_MAINTENANCE_QUIESCENCE_SECONDS", "2");
                    std::env::set_var(ENV_BLOB_SAFE_GC_DESTRUCTIVE, "true");
                }
                let stop = CancellationToken::new();
                let run_task = tokio::spawn(rootyard::storage_lifecycle::run(Arc::clone(&state), stop.clone()));
                tokio::time::sleep(Duration::from_millis(2_200)).await;
                stop.cancel();
                let _ = run_task.await;
                let succeeded: i64 = pool
                    .get()
                    .await?
                    .query_one(
                        "SELECT count(*) FROM storage_maintenance_jobs \
                         WHERE repository_id = $1 AND kind = 'pando_tombstone_delete' AND state = 'succeeded'",
                        &[&repo_id],
                    )
                    .await?
                    .get(0);
                ensure!(succeeded == 0, "cold runtime deleted {succeeded} objects without a live voter quorum");
                serde_json::json!({"pid": std::process::id(), "deleted_jobs": succeeded})
            }
            other => bail!("unknown safe-gc child mode {other}"),
        };
        std::fs::write(&out_path, serde_json::to_vec(&payload)?)?;
        drop(state);
        Ok(())
    })
}
