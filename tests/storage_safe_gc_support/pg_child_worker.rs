//! Real multi-process scheduled-runtime child for Safe GC acceptance (#122).
//!
//! The parent integration test spawns this binary as a separate OS process so a
//! `DistributedRefCas` scheduled pass proves production-source capture and worker
//! runtime in a process that never shared the parent's in-memory registry.

use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::Duration,
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
const CHILD_OUT_JSON_ENV: &str = "ROOTYARD_SAFE_GC_CHILD_OUT_JSON";
const ENV_BLOB_SAFE_GC_DESTRUCTIVE: &str = "ROOTYARD_BLOB_SAFE_GC_DESTRUCTIVE";
const MODE_PASS1: &str = "pass1_crash_after_one_delete";
const MODE_PASS2: &str = "pass2_scheduled_runtime";
const ENTRYPOINT: &str = "pg_child_worker::child_process_entrypoint";

pub(super) struct ChildOutcome {
    pub pid: u32,
    pub job_id: Uuid,
    pub result: Value,
}

/// Spawn pass #1 in a fresh OS process: interrupt after exactly one provider delete.
pub(super) fn spawn_pass1_crash_child(
    storage_root: &Path,
    db_url: &str,
    schema: &str,
    repo_id: Uuid,
    s3_env_pairs: &[(String, Option<std::ffi::OsString>)],
) -> Result<ChildOutcome> {
    spawn_child(MODE_PASS1, storage_root, db_url, schema, repo_id, None, s3_env_pairs)
}

/// Spawn pass #2 in a fresh OS process: the scheduled runtime resumes the batch.
pub(super) fn spawn_pass2_scheduled_runtime_child(
    storage_root: &Path,
    db_url: &str,
    schema: &str,
    repo_id: Uuid,
    skip_job_id: Uuid,
    s3_env_pairs: &[(String, Option<std::ffi::OsString>)],
) -> Result<ChildOutcome> {
    spawn_child(MODE_PASS2, storage_root, db_url, schema, repo_id, Some(skip_job_id), s3_env_pairs)
}

fn spawn_child(
    mode: &str,
    storage_root: &Path,
    db_url: &str,
    schema: &str,
    repo_id: Uuid,
    skip_job_id: Option<Uuid>,
    s3_env_pairs: &[(String, Option<std::ffi::OsString>)],
) -> Result<ChildOutcome> {
    let exe = std::env::current_exe().context("resolve current test executable")?;
    let out_path = storage_root.join(format!("safe-gc-child-{mode}-{}.json", Uuid::new_v4()));
    let mut child = Command::new(exe);
    child
        .args(["--exact", ENTRYPOINT, "--ignored", "--nocapture", "--test-threads=1"])
        .env(CHILD_MODE_ENV, mode)
        .env(CHILD_DB_URL_ENV, db_url)
        .env(CHILD_PG_SCHEMA_ENV, schema)
        .env(CHILD_ROOT_ENV, storage_root)
        .env(CHILD_REPO_ID_ENV, repo_id.to_string())
        .env(CHILD_OUT_JSON_ENV, &out_path)
        .env(ENV_BLOB_SAFE_GC_DESTRUCTIVE, "true")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if let Some(skip) = skip_job_id {
        child.env(CHILD_SKIP_JOB_ID_ENV, skip.to_string());
    }
    for (key, value) in s3_env_pairs {
        match value {
            Some(value) => child.env(key, value),
            None => child.env_remove(key),
        };
    }
    let status = child.spawn().context("spawn safe-gc child process")?.wait().context("wait for safe-gc child")?;
    ensure!(status.success(), "safe-gc child {mode} exited with {status}");
    let raw = std::fs::read_to_string(&out_path).context("read safe-gc child output JSON")?;
    let value: Value = serde_json::from_str(&raw).context("parse safe-gc child output JSON")?;
    Ok(ChildOutcome {
        pid: u32::try_from(value["pid"].as_u64().context("child pid")?).context("child pid overflow")?,
        job_id: value["job_id"].as_str().context("child job_id")?.parse()?,
        result: value.get("result").cloned().unwrap_or(Value::Null),
    })
}

#[test]
#[ignore = "spawned by the parent integration test as a separate OS process"]
fn child_process_entrypoint() {
    let Ok(mode) = std::env::var(CHILD_MODE_ENV) else {
        return;
    };
    match mode.as_str() {
        MODE_PASS1 | MODE_PASS2 => run_child(&mode).expect("safe-gc child process"),
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
                let out = super::pg_refcas_restart_cases::execute_pass1_crash_after_one_delete(
                    &state,
                    &pool,
                    &super::test_policy(),
                    repo_id,
                )
                .await?;
                ensure!(out.state == "failed", "pass1 child job state {} != failed", out.state);
                serde_json::json!({"pid": std::process::id(), "job_id": out.job_id})
            }
            MODE_PASS2 => {
                let skip: Uuid = std::env::var(CHILD_SKIP_JOB_ID_ENV).context("child skip job id")?.parse()?;
                pool.get()
                    .await?
                    .execute(
                        "UPDATE storage_maintenance_repo_state SET last_scan_at = NULL WHERE repository_id = $1",
                        &[&repo_id],
                    )
                    .await?;
                unsafe {
                    std::env::set_var("ROOTYARD_STORAGE_MAINTENANCE", "true");
                    std::env::set_var("ROOTYARD_STORAGE_MAINTENANCE_POLL_SECONDS", "1");
                    std::env::set_var("ROOTYARD_STORAGE_SCAN_PERIOD_SECONDS", "1");
                    std::env::set_var("ROOTYARD_STORAGE_REPACK_PACKS", "2");
                    std::env::set_var("ROOTYARD_STORAGE_MAINTENANCE_LEASE_SECONDS", "15");
                    std::env::set_var("ROOTYARD_STORAGE_MAINTENANCE_QUIESCENCE_SECONDS", "2");
                    std::env::set_var("ROOTYARD_STORAGE_MAINTENANCE_MAX_ATTEMPTS", "3");
                    std::env::set_var("ROOTYARD_BLOB_SAFE_GC_DESTRUCTIVE", "true");
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
                let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
                let mut poll = tokio::time::interval(Duration::from_millis(50));
                let payload = loop {
                    if tokio::time::Instant::now() > deadline {
                        stop.cancel();
                        bail!("pass2 scheduled runtime did not finish within 15s");
                    }
                    poll.tick().await;
                    let row = pool
                        .get()
                        .await?
                        .query_opt(
                            "SELECT id, state, result, last_error FROM storage_maintenance_jobs \
                             WHERE repository_id = $1 AND id <> $2 AND created_at > to_timestamp($3) \
                             ORDER BY created_at DESC LIMIT 1",
                            &[&repo_id, &skip, &since],
                        )
                        .await?;
                    let Some(row) = row else {
                        continue;
                    };
                    let job_id: Uuid = row.get(0);
                    let job_state: String = row.get(1);
                    if job_state == "failed" {
                        stop.cancel();
                        let last_error: Option<String> = row.get(3);
                        bail!("pass2 job {job_id} failed: {}", last_error.unwrap_or_default());
                    }
                    if job_state == "succeeded" {
                        let result: Value = row.get(2);
                        stop.cancel();
                        run_task.await??;
                        break serde_json::json!({"pid": std::process::id(), "job_id": job_id, "result": result});
                    }
                };
                payload
            }
            other => bail!("unknown safe-gc child mode {other}"),
        };
        std::fs::write(&out_path, serde_json::to_vec(&payload)?)?;
        drop(state);
        Ok(())
    })
}
