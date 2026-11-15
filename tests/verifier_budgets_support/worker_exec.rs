//! Isolated child-process execution, reaping precondition, and owned PostgreSQL schema cleanup.

use super::bench::{CohortMeasurement, read_cohort_file};
use super::pg_git::Db;
use anyhow::{Result, anyhow};
use std::path::Path;
use std::process::{ExitStatus, Stdio};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::Child;

pub const ENV_BENCH_PHASE: &str = "ROOTYARD_VB_PHASE";
pub(super) const ENV_BENCH_OUT: &str = "ROOTYARD_VB_OUT";
pub(super) const ENV_BENCH_S3_ENDPOINT: &str = "ROOTYARD_VB_S3_ENDPOINT";
pub(super) const ENV_BENCH_SCHEMA: &str = "ROOTYARD_VB_SCHEMA";
pub(super) const ENV_BENCH_PROBE_MARKER: &str = "ROOTYARD_VB_PROBE_MARKER";

#[derive(Clone, Copy)]
enum ReapAction {
    TerminateAndReap,
    SimulateUnconfirmedExit(&'static str),
}

pub(crate) struct ReapFailureProbeResult {
    pub(crate) result: Result<CohortMeasurement>,
    pub(crate) real_child_reaped: bool,
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
    reap_action: ReapAction,
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

async fn run_reap(child: &mut Child, action: ReapAction) -> (Result<ExitStatus>, bool) {
    match action {
        ReapAction::TerminateAndReap => {
            let res = terminate_and_reap(child).await;
            let real_child_reaped = res.is_ok();
            (res, real_child_reaped)
        }
        ReapAction::SimulateUnconfirmedExit(reason) => {
            // Confirm real OS child exit cleanly without forcing schema DROP so the test records whether reap succeeded.
            let real_res = terminate_and_reap(child).await;
            let real_child_reaped = real_res.is_ok();
            let sim_err = match real_res {
                Ok(_) => anyhow!("{reason}"),
                Err(real_err) => anyhow!("{reason}; real child reap also failed: {real_err:#}"),
            };
            (Err(sim_err), real_child_reaped)
        }
    }
}

async fn handle_terminated_or_timed_out(
    spec: &WorkerSpec<'_>,
    base_reason: String,
    reap_res: Result<ExitStatus>,
    stdout: String,
    stderr: String,
) -> Result<CohortMeasurement> {
    let status = match reap_res {
        Ok(status) => status,
        Err(reap_err) => {
            return Err(anyhow!(
                "cleanup-not-complete: {base_reason}; owned schema `{}` was NOT dropped because child exit could not be confirmed ({reap_err:#})\nstdout:\n{stdout}\nstderr:\n{stderr}",
                spec.schema
            ));
        }
    };
    let cleanup_res = Db::drop_owned_schema(spec.pg_url, spec.schema).await;
    let err = anyhow!("{base_reason} (child_reaped=true, exit={status})\nstdout:\n{stdout}\nstderr:\n{stderr}");
    match cleanup_res {
        Ok(()) => Err(err),
        Err(c_err) => Err(err.context(format!(
            "cleanup-not-complete: failed dropping owned schema `{}` after confirmed exit: {c_err:#}",
            spec.schema
        ))),
    }
}

async fn spawn_worker_with_cleanup(spec: WorkerSpec<'_>) -> ReapFailureProbeResult {
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

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(err) => return ReapFailureProbeResult { result: Err(err.into()), real_child_reaped: false },
    };
    let stdout_task = tokio::spawn(drain_pipe(child.stdout.take()));
    let stderr_task = tokio::spawn(drain_pipe(child.stderr.take()));

    match tokio::time::timeout(spec.timeout, child.wait()).await {
        Ok(Ok(status)) => {
            let stdout = collect_pipe(stdout_task).await;
            let stderr = collect_pipe(stderr_task).await;
            let cohort_res = if status.success() {
                read_cohort_file(spec.out_path)
            } else {
                Err(anyhow!(
                    "isolated cohort `{}` exited with {status} (child_reaped=true)\nstdout:\n{stdout}\nstderr:\n{stderr}",
                    spec.phase
                ))
            };
            let cleanup_res = Db::drop_owned_schema(spec.pg_url, spec.schema).await;
            let result = match (cohort_res, cleanup_res) {
                (Ok(cohort), Ok(())) => Ok(cohort),
                (Ok(_), Err(c_err)) => Err(c_err.context(format!(
                    "cleanup-not-complete: failed dropping owned schema `{}` after confirmed exit",
                    spec.schema
                ))),
                (Err(err), Ok(())) => Err(err),
                (Err(err), Err(c_err)) => Err(err.context(format!(
                    "cleanup-not-complete: failed dropping owned schema `{}`: {c_err:#}",
                    spec.schema
                ))),
            };
            ReapFailureProbeResult { result, real_child_reaped: true }
        }
        Ok(Err(err)) => {
            let (reap_res, real_child_reaped) = run_reap(&mut child, spec.reap_action).await;
            let stdout = collect_pipe(stdout_task).await;
            let stderr = collect_pipe(stderr_task).await;
            let reason = format!("failed waiting on isolated cohort `{}`: {err}", spec.phase);
            let result = handle_terminated_or_timed_out(&spec, reason, reap_res, stdout, stderr).await;
            ReapFailureProbeResult { result, real_child_reaped }
        }
        Err(_) => {
            let (reap_res, real_child_reaped) = run_reap(&mut child, spec.reap_action).await;
            let stdout = collect_pipe(stdout_task).await;
            let stderr = collect_pipe(stderr_task).await;
            let reason = format!("isolated cohort `{}` timed out after {:?}", spec.phase, spec.timeout);
            let result = handle_terminated_or_timed_out(&spec, reason, reap_res, stdout, stderr).await;
            ReapFailureProbeResult { result, real_child_reaped }
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
        reap_action: ReapAction::TerminateAndReap,
    })
    .await
    .result
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
        reap_action: ReapAction::TerminateAndReap,
    })
    .await
    .result
}

pub(crate) async fn run_hang_cleanup_probe_with_reap_failure(
    exe: &Path,
    pg_url: &str,
    out_path: &Path,
    schema: &str,
    marker: &Path,
    timeout: Duration,
) -> ReapFailureProbeResult {
    spawn_worker_with_cleanup(WorkerSpec {
        exe,
        phase: "hang_cleanup_probe",
        pg_url,
        s3_endpoint: "http://127.0.0.1:0",
        out_path,
        schema,
        probe_marker: Some(marker),
        timeout,
        reap_action: ReapAction::SimulateUnconfirmedExit("simulated 5s reap timeout"),
    })
    .await
}
