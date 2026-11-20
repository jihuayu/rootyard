//! Fresh-process trust-commit/journal-persist boundary child for the legacy `DistributedRefCas`
//! migration test (#122).
//!
//! The boundary mode enters the existing test-only hook after the migrated trust document is
//! durable but before the journal is replaced, writes a marker, and parks until the parent sends
//! `SIGKILL` to this exact owned PID. The probe mode is a separate process that opens the same
//! fixture volume and database and reports the durable trust/journal observations.

use std::{
    ffi::OsString,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use rootyard::storage_lifecycle::safe_gc::{
    SafeGcError, SafeGcRepoTrustConfig, TrustedConsensusVoter, store::DurableSafeGcAuthority,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::pg_child_worker::{
    CHILD_DB_URL_ENV, CHILD_MODE_ENV, CHILD_OUT_JSON_ENV, CHILD_PG_SCHEMA_ENV, CHILD_REPO_ID_ENV, CHILD_ROOT_ENV,
};

const MODE_BOUNDARY: &str = "migration_boundary_sigkill";
const MODE_PROBE: &str = "probe_migrated_boundary";
const CHILD_JOURNAL_ENV: &str = "ROOTYARD_SAFE_GC_CHILD_JOURNAL";
const CHILD_MARKER_ENV: &str = "ROOTYARD_SAFE_GC_CHILD_MIGRATION_MARKER";
const CHILD_VOTERS_ENV: &str = "ROOTYARD_SAFE_GC_CHILD_TRUSTED_VOTERS_JSON";
const CHILD_NONCE_ENV: &str = "ROOTYARD_SAFE_GC_CHILD_MIGRATION_NONCE";
const CHILD_QUORUM_ENV: &str = "ROOTYARD_SAFE_GC_CHILD_MIGRATION_QUORUM";
const ENTRYPOINT: &str = "pg_child_worker::child_process_entrypoint";
const BOUNDARY_NAME: &str = "trust_committed_before_journal_persist";

pub(super) struct BoundaryKillOutcome {
    pub pid: u32,
    pub signal: Option<i32>,
    pub marker: Value,
}

pub(super) struct MigratedProbeOutcome {
    pub pid: u32,
    pub trust_quorum_threshold: u64,
    pub trusted_voter_count: usize,
    pub journal_sha256_hex: String,
    pub legacy_refusal: String,
}

pub(super) fn is_migration_mode(mode: &str) -> bool {
    matches!(mode, MODE_BOUNDARY | MODE_PROBE)
}

pub(super) fn run_migration_child(mode: &str) -> Result<()> {
    match mode {
        MODE_BOUNDARY => run_boundary_child(),
        MODE_PROBE => run_probe_child(),
        other => bail!("unknown safe-gc migration child mode {other}"),
    }
}

/// Park in a fresh process at the post-trust/pre-journal hook, then `SIGKILL` that exact PID.
pub(super) async fn spawn_migration_boundary_sigkill_child(
    storage_root: &Path,
    db_url: &str,
    schema: &str,
    repo_id: Uuid,
    quorum_threshold: usize,
    journal_path: &Path,
    trusted_voters: &[TrustedConsensusVoter],
) -> Result<BoundaryKillOutcome> {
    let marker_path = storage_root.join(format!("safe-gc-migration-boundary-{}.json", Uuid::new_v4()));
    let nonce = Uuid::new_v4().to_string();
    let voters_json = serde_json::to_string(trusted_voters)?;
    let mut child = minimal_child_command(MODE_BOUNDARY, storage_root, db_url, schema, repo_id)
        .env(CHILD_JOURNAL_ENV, journal_path)
        .env(CHILD_MARKER_ENV, &marker_path)
        .env(CHILD_VOTERS_ENV, voters_json)
        .env(CHILD_NONCE_ENV, &nonce)
        .env(CHILD_QUORUM_ENV, quorum_threshold.to_string())
        .spawn()
        .context("spawn safe-gc migration boundary child")?;
    let pid = child.id();
    let deadline = Instant::now() + Duration::from_secs(60);
    while !marker_path.is_file() {
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("migration boundary child never reported the post-trust/pre-journal marker");
        }
        if let Some(status) = child.try_wait()? {
            bail!("migration boundary child exited before the marker: {status}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let marker: Value =
        serde_json::from_slice(&std::fs::read(&marker_path)?).context("parse migration boundary marker")?;
    ensure!(marker["boundary"].as_str() == Some(BOUNDARY_NAME), "unexpected migration boundary marker");
    ensure!(marker["nonce"].as_str() == Some(nonce.as_str()), "migration boundary marker nonce mismatch");
    ensure!(
        marker["pid"].as_u64() == Some(u64::from(pid)),
        "migration boundary marker pid {} does not match owned child {pid}",
        marker["pid"]
    );
    let marker_start = marker["start_time"].as_u64().context("migration boundary marker start_time")?;
    let live_start = process_start_time(pid).context("read owned child /proc start_time")?;
    ensure!(marker_start == live_start, "migration boundary child identity changed before SIGKILL");
    ensure!(child.try_wait()?.is_none(), "migration boundary child exited at the marker before SIGKILL");
    child.kill().context("SIGKILL migration boundary child")?;
    let status = child.wait().context("reap SIGKILLed migration boundary child")?;
    #[cfg(unix)]
    let signal = {
        use std::os::unix::process::ExitStatusExt;
        status.signal()
    };
    #[cfg(not(unix))]
    let signal = None;
    ensure!(signal == Some(libc::SIGKILL), "migration boundary child must die from SIGKILL, got {status:?}");
    Ok(BoundaryKillOutcome { pid, signal, marker })
}

/// Open the same volume and database in a new process and report the durable boundary outcome.
pub(super) async fn spawn_migrated_fixture_probe_child(
    storage_root: &Path,
    db_url: &str,
    schema: &str,
    repo_id: Uuid,
    quorum_threshold: usize,
    journal_path: &Path,
    trusted_voters: &[TrustedConsensusVoter],
) -> Result<MigratedProbeOutcome> {
    let out_path = storage_root.join(format!("safe-gc-migration-probe-{}.json", Uuid::new_v4()));
    let voters_json = serde_json::to_string(trusted_voters)?;
    let mut command = minimal_child_command(MODE_PROBE, storage_root, db_url, schema, repo_id);
    command
        .env(CHILD_JOURNAL_ENV, journal_path)
        .env(CHILD_VOTERS_ENV, voters_json)
        .env(CHILD_QUORUM_ENV, quorum_threshold.to_string())
        .env(CHILD_OUT_JSON_ENV, &out_path);
    let mut child =
        tokio::process::Command::from(command).spawn().context("spawn safe-gc migrated fixture probe child")?;
    let status = child.wait().await.context("wait for safe-gc migrated fixture probe child")?;
    ensure!(status.success(), "safe-gc migrated fixture probe exited with {status}");
    let value: Value = serde_json::from_slice(&std::fs::read(&out_path)?).context("parse migrated fixture probe")?;
    Ok(MigratedProbeOutcome {
        pid: u32::try_from(value["pid"].as_u64().context("probe pid")?).context("probe pid overflow")?,
        trust_quorum_threshold: value["trust_quorum_threshold"].as_u64().context("probe trust threshold")?,
        trusted_voter_count: usize::try_from(value["trusted_voter_count"].as_u64().context("probe voter count")?)
            .context("probe voter count overflow")?,
        journal_sha256_hex: value["journal_sha256_hex"].as_str().context("probe journal sha256")?.to_owned(),
        legacy_refusal: value["legacy_refusal"].as_str().context("probe legacy refusal")?.to_owned(),
    })
}

fn minimal_child_command(mode: &str, storage_root: &Path, db_url: &str, schema: &str, repo_id: Uuid) -> Command {
    let exe = std::env::current_exe().expect("resolve current test executable");
    let mut child = Command::new(exe);
    child
        .args(["--exact", ENTRYPOINT, "--ignored", "--nocapture", "--test-threads=1"])
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_else(|| OsString::from("/usr/local/bin:/usr/bin:/bin")))
        .env("HOME", std::env::var_os("HOME").unwrap_or_else(|| OsString::from("/tmp")))
        .env(CHILD_MODE_ENV, mode)
        .env(CHILD_DB_URL_ENV, db_url)
        .env(CHILD_PG_SCHEMA_ENV, schema)
        .env(CHILD_ROOT_ENV, storage_root)
        .env(CHILD_REPO_ID_ENV, repo_id.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    child
}

fn run_boundary_child() -> Result<()> {
    let root = PathBuf::from(std::env::var_os(CHILD_ROOT_ENV).context("child storage root")?);
    let db_url = std::env::var(CHILD_DB_URL_ENV).context("child database URL")?;
    let schema = std::env::var(CHILD_PG_SCHEMA_ENV).context("child PG schema")?;
    let repo_id: Uuid = std::env::var(CHILD_REPO_ID_ENV).context("child repository id")?.parse()?;
    let journal = PathBuf::from(std::env::var_os(CHILD_JOURNAL_ENV).context("child journal path")?);
    let marker_path = PathBuf::from(std::env::var_os(CHILD_MARKER_ENV).context("child marker path")?);
    let nonce = std::env::var(CHILD_NONCE_ENV).context("child migration nonce")?;
    let voters: Vec<TrustedConsensusVoter> =
        serde_json::from_str(&std::env::var(CHILD_VOTERS_ENV).context("child trusted voters JSON")?)?;
    let quorum_threshold: usize =
        std::env::var(CHILD_QUORUM_ENV).context("child quorum threshold")?.parse().context("child quorum parse")?;
    ensure!(quorum_threshold > 0 && quorum_threshold <= voters.len(), "child quorum threshold is out of range");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("child tokio runtime")?;
    runtime.block_on(async move {
        ensure_same_database(&db_url, &schema, repo_id).await?;
        tokio::task::spawn_blocking(move || {
            let voters_for_check = voters.clone();
            let (_trust, _report) = SafeGcRepoTrustConfig::migrate_legacy_trust_and_journal_with_boundary_hook(
                &root,
                &journal,
                repo_id,
                quorum_threshold,
                voters,
                || {
                    let loaded = SafeGcRepoTrustConfig::load(&root, repo_id)?;
                    if loaded.quorum_threshold != Some(quorum_threshold)
                        || loaded.trusted_consensus_voters != voters_for_check
                    {
                        return Err(SafeGcError::Io(
                            "post-trust boundary did not observe the migrated voter trust".into(),
                        ));
                    }
                    let raw = std::fs::read(&journal).map_err(|e| SafeGcError::Io(e.to_string()))?;
                    let marker = json!({
                        "boundary": BOUNDARY_NAME,
                        "nonce": nonce,
                        "pid": std::process::id(),
                        "start_time": process_start_time(std::process::id()),
                        "repo_id": repo_id.to_string(),
                        "journal_path": journal.display().to_string(),
                        "journal_sha256_hex": hex::encode(Sha256::digest(&raw)),
                        "trust_quorum_threshold": quorum_threshold,
                        "trusted_voter_count": loaded.trusted_consensus_voters.len(),
                    });
                    let tmp = marker_path.with_extension("tmp");
                    let mut file = std::fs::OpenOptions::new()
                        .create_new(true)
                        .write(true)
                        .open(&tmp)
                        .map_err(|e| SafeGcError::Io(e.to_string()))?;
                    file.write_all(&serde_json::to_vec(&marker).map_err(|e| SafeGcError::Io(e.to_string()))?)
                        .map_err(|e| SafeGcError::Io(e.to_string()))?;
                    file.sync_all().map_err(|e| SafeGcError::Io(e.to_string()))?;
                    std::fs::rename(&tmp, &marker_path).map_err(|e| SafeGcError::Io(e.to_string()))?;
                    let deadline = Instant::now() + Duration::from_secs(120);
                    while Instant::now() < deadline {
                        std::thread::park_timeout(Duration::from_secs(1));
                    }
                    Err(SafeGcError::Io("migration boundary park timed out".into()))
                },
            )?;
            Ok::<(), SafeGcError>(())
        })
        .await??;
        bail!("migration boundary child returned without being SIGKILLed")
    })
}

fn run_probe_child() -> Result<()> {
    let root = PathBuf::from(std::env::var_os(CHILD_ROOT_ENV).context("child storage root")?);
    let db_url = std::env::var(CHILD_DB_URL_ENV).context("child database URL")?;
    let schema = std::env::var(CHILD_PG_SCHEMA_ENV).context("child PG schema")?;
    let repo_id: Uuid = std::env::var(CHILD_REPO_ID_ENV).context("child repository id")?.parse()?;
    let journal = PathBuf::from(std::env::var_os(CHILD_JOURNAL_ENV).context("child journal path")?);
    let out_path = PathBuf::from(std::env::var_os(CHILD_OUT_JSON_ENV).context("child output path")?);
    let voters: Vec<TrustedConsensusVoter> =
        serde_json::from_str(&std::env::var(CHILD_VOTERS_ENV).context("child trusted voters JSON")?)?;
    let quorum_threshold: usize =
        std::env::var(CHILD_QUORUM_ENV).context("child quorum threshold")?.parse().context("child quorum parse")?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("child tokio runtime")?;
    runtime.block_on(async move {
        ensure_same_database(&db_url, &schema, repo_id).await?;
        let trust = SafeGcRepoTrustConfig::load(&root, repo_id)?;
        ensure!(
            trust.quorum_threshold == Some(quorum_threshold),
            "probe trust threshold {:?} != {quorum_threshold}",
            trust.quorum_threshold
        );
        ensure!(trust.trusted_consensus_voters == voters, "probe trust voters differ from the migrated bundle");
        let raw = std::fs::read(&journal)?;
        let legacy_refusal = match DurableSafeGcAuthority::open_with_journal(&journal, None) {
            Err(SafeGcError::ArmingRejected(message)) => message.to_owned(),
            Ok(_) => bail!("probe unexpectedly accepted the unmigrated legacy journal"),
            Err(other) => bail!("probe failed for an unexpected reason: {other}"),
        };
        let payload = json!({
            "pid": std::process::id(),
            "start_time": process_start_time(std::process::id()),
            "trust_quorum_threshold": trust.quorum_threshold,
            "trusted_voter_count": trust.trusted_consensus_voters.len(),
            "journal_sha256_hex": hex::encode(Sha256::digest(&raw)),
            "legacy_refusal": legacy_refusal,
        });
        std::fs::write(&out_path, serde_json::to_vec(&payload)?)?;
        Ok::<(), anyhow::Error>(())
    })
}

async fn ensure_same_database(db_url: &str, schema: &str, repo_id: Uuid) -> Result<()> {
    let pool = super::open_pg_pool_for_schema(db_url, schema).await?;
    let row = pool.get().await?.query_opt("SELECT 1 FROM repositories WHERE id = $1", &[&repo_id]).await?;
    ensure!(row.is_some(), "fresh child must observe the parent repository row in the same PG schema");
    Ok(())
}

#[cfg(target_os = "linux")]
fn process_start_time(pid: u32) -> Option<u64> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_pid, tail) = raw.rsplit_once(')')?;
    tail.split_whitespace().nth(19)?.parse().ok()
}

#[cfg(not(target_os = "linux"))]
fn process_start_time(_pid: u32) -> Option<u64> {
    None
}
