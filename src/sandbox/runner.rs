use super::{cgroup, export, terminal};
use crate::{AppState, Error, workspace_lab::core, workspaces::service};
use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::process::Command;
use uuid::Uuid;

/// Per-file cap for user-written files and therefore logs/artifacts.
const ARTIFACT_FILE_BYTES: u64 = 16 * 1024 * 1024;

#[allow(clippy::large_enum_variant)] // one owned claim per job; indirection would only add an allocation
pub(super) enum Source {
    Workspace { id: Uuid, live: bool },
    Ci { checkout: PathBuf, claim: crate::webhooks::claimed::ClaimedRun },
}

enum Mode {
    Dev,
    Cgroup(PathBuf),
}

/// Bubblewrap capability the sandbox runtime depends on.
///
/// Every profile bounds `/tmp` and the cgroup profile bounds `/workspace` with
/// `--size BYTES --tmpfs DEST`. Ubuntu 22.04 ships bubblewrap 0.6.1, which
/// predates `--size`: Bubblewrap exits with a usage error before the start gate
/// and the job fails with an opaque 503/failed state. Probe the real binary
/// once (functional probe, not a version string) so an incapable runtime fails
/// closed with a precise reason instead of executing an unbounded job.
fn bwrap_supports_size(binary: &str) -> bool {
    match std::process::Command::new(binary).arg("--version").output() {
        Ok(output) if output.status.success() => {}
        _ => return false,
    }
    std::process::Command::new(binary)
        // Bubblewrap builds an empty root, so /bin/true must come from a
        // read-only host root bind. This argv is probe-only and never changes
        // the untrusted job mounts; /tmp is still size-bounded and the network
        // is still unshared.
        .args([
            "--unshare-all",
            "--die-with-parent",
            "--ro-bind",
            "/",
            "/",
            "--size",
            "1048576",
            "--tmpfs",
            "/tmp",
            "--",
            "/bin/true",
        ])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn bubblewrap_ready() -> bool {
    static READY: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *READY.get_or_init(|| bwrap_supports_size("bwrap"))
}

fn require_bubblewrap() -> Result<(), Error> {
    if bubblewrap_ready() {
        return Ok(());
    }
    // Static, secret-free diagnostic: the API body stays generic on purpose.
    eprintln!(
        "rootyard: bubblewrap does not support --size; the sandbox runtime requires a bubblewrap that implements --size"
    );
    Err(Error::internal("sandbox runtime requires bubblewrap --size support"))
}

fn isolation_mode(job: Uuid, limits: &cgroup::Limits) -> Result<Mode, Error> {
    require_bubblewrap()?;
    match std::env::var("ROOTYARD_SANDBOX_MODE").as_deref() {
        Ok("dev") => Ok(Mode::Dev),
        Ok("cgroup") => {
            let base = cgroup::delegated_root()?;
            Ok(Mode::Cgroup(cgroup::create(&base, job, limits)?))
        }
        _ => Err(Error::internal("sandbox cgroup mode required")),
    }
}

pub fn job_root(state: &AppState, id: Uuid) -> PathBuf {
    state.storage.root.join("sandbox-jobs").join(id.to_string())
}

/// The only host directory a job may write artifacts into. It is bind-mounted
/// read-write at `/artifacts` and never exposes the rest of the job root.
pub(super) fn artifacts_root(state: &AppState, id: Uuid) -> PathBuf {
    match export::configured_pool() {
        Some(pool) => pool.join(id.to_string()),
        None => job_root(state, id).join("artifacts"),
    }
}

/// Remove both the retained job root (logs) and the artifact export directory,
/// which may live in a separate bounded tmpfs pool.
pub(super) fn cleanup_job(state: &AppState, id: Uuid) -> Result<bool, Error> {
    let mut removed = export::remove_job_root(&job_root(state, id))?;
    let store = artifacts_root(state, id);
    if store != job_root(state, id).join("artifacts") {
        removed |= export::remove_job_root(&store)?;
    }
    Ok(removed)
}

fn limit(resource: libc::__rlimit_resource_t, soft: u64) -> std::io::Result<()> {
    let lim = libc::rlimit { rlim_cur: soft, rlim_max: soft };
    if unsafe { libc::setrlimit(resource, &lim) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
fn leader_exited(pid: i32) -> std::io::Result<bool> {
    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
    let result = unsafe {
        libc::waitid(libc::P_PID, pid as u32, info.as_mut_ptr(), libc::WEXITED | libc::WNOHANG | libc::WNOWAIT)
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { info.assume_init().si_pid() != 0 })
}
async fn open_start_gate(state: &AppState, job: Uuid, source: &Source, root: &Path) -> Result<(), Error> {
    #[cfg(test)]
    let probe = super::gate_probe::GateProbe::current();
    let mut client = state
        .pool
        .get()
        .await
        .inspect_err(|_error| {
            #[cfg(test)]
            if let Some(probe) = &probe {
                probe.record_pool_error(super::gate_probe::GateStage::PoolTxPolicy, _error);
            }
        })
        .map_err(Error::internal)?;
    let tx = client
        .transaction()
        .await
        .inspect_err(|_error| {
            #[cfg(test)]
            if let Some(probe) = &probe {
                probe.record_pg_error(super::gate_probe::GateStage::PoolTxPolicy, _error);
            }
        })
        .map_err(Error::internal)?;
    // Lock order: repository policy fence -> sandbox_jobs -> CI authority rows.
    // Trusted bind/revoke/PATCH writers take the same fence exclusively before
    // their binding/webhook/run row locks. A shared reader is enough here and
    // never upgrades. No policy writer locks sandbox_jobs, so taking the fence
    // before the job row cannot create a policy/job cycle. The immutable claim
    // supplies the repository identity; authority is revalidated below after
    // all rows are locked.
    if let Source::Ci { claim, .. } = source {
        let locked = crate::webhooks::trust::lock_policy_shared_tx(&tx, claim.repository_id).await;
        #[cfg(test)]
        if locked.is_err()
            && let Some(probe) = &probe
        {
            probe.record(super::gate_probe::GateStage::PoolTxPolicy, super::gate_probe::StageOutcome::Failed);
        }
        locked?;
    }
    #[cfg(test)]
    if let Some(probe) = &probe {
        probe.record(super::gate_probe::GateStage::PoolTxPolicy, super::gate_probe::StageOutcome::Ok);
    }
    let row = tx
        .query_opt(
            "SELECT state,ci_run_id,ci_attempt,ci_lease_generation FROM sandbox_jobs \
             WHERE id=$1 AND host_id=$2 FOR UPDATE",
            &[&job, &state.storage.volume_id],
        )
        .await
        .inspect_err(|_error| {
            #[cfg(test)]
            if let Some(probe) = &probe {
                probe.record_pg_error(super::gate_probe::GateStage::JobSelect, _error);
            }
        })
        .map_err(Error::internal)?
        .ok_or_else(|| {
            #[cfg(test)]
            if let Some(probe) = &probe {
                probe.record(super::gate_probe::GateStage::JobSelect, super::gate_probe::StageOutcome::Failed);
            }
            Error::not_found()
        })?;
    #[cfg(test)]
    if let Some(probe) = &probe {
        probe.record(super::gate_probe::GateStage::JobSelect, super::gate_probe::StageOutcome::Ok);
    }
    if row.get::<_, String>(0) != "running" {
        #[cfg(test)]
        if let Some(probe) = &probe {
            probe.record(super::gate_probe::GateStage::StateGuard, super::gate_probe::StageOutcome::Refused);
        }
        return Err(Error::internal("sandbox cancelled before start"));
    }
    #[cfg(test)]
    if let Some(probe) = &probe {
        probe.record(super::gate_probe::GateStage::StateGuard, super::gate_probe::StageOutcome::Ok);
    }
    // The policy fence used the immutable claim repository. Revalidate the
    // locked job's immutable CI identity before trusting that claim below.
    if let Source::Ci { claim, .. } = source
        && (row.get::<_, Option<Uuid>>(1) != Some(claim.run_id)
            || row.get::<_, Option<i64>>(2) != Some(claim.attempt)
            || row.get::<_, Option<i64>>(3) != Some(claim.lease_generation))
    {
        #[cfg(test)]
        if let Some(probe) = &probe {
            probe.record(super::gate_probe::GateStage::IdentityGuard, super::gate_probe::StageOutcome::Refused);
        }
        return Err(Error::internal("sandbox cancelled before start"));
    }
    #[cfg(test)]
    if let Source::Ci { .. } = source
        && let Some(probe) = &probe
    {
        probe.record(super::gate_probe::GateStage::IdentityGuard, super::gate_probe::StageOutcome::Ok);
    }
    let authorized = match source {
        Source::Ci { claim, .. } => {
            let result = super::ci::gate_authorized(&tx, claim).await;
            #[cfg(test)]
            if result.is_err()
                && let Some(probe) = &probe
            {
                probe.record(super::gate_probe::GateStage::AuthoritySelect, super::gate_probe::StageOutcome::Failed);
            }
            let authorized = result?;
            #[cfg(test)]
            if let Some(probe) = &probe {
                probe.record(
                    super::gate_probe::GateStage::AuthoritySelect,
                    if authorized {
                        super::gate_probe::StageOutcome::Ok
                    } else {
                        super::gate_probe::StageOutcome::Refused
                    },
                );
            }
            authorized
        }
        Source::Workspace { .. } => {
            let authorized = tx
                .query_opt(
                    "SELECT 1 FROM workspaces w JOIN sandbox_jobs j \
            ON j.workspace_id=w.id WHERE j.id=$1 AND j.lease_epoch=w.lease_epoch \
            AND j.host_id=w.host_id AND w.lease_until>clock_timestamp()+interval '2 seconds' \
            FOR SHARE OF w",
                    &[&job],
                )
                .await
                .inspect_err(|_error| {
                    #[cfg(test)]
                    if let Some(probe) = &probe {
                        probe.record_pg_error(super::gate_probe::GateStage::AuthoritySelect, _error);
                    }
                })
                .map_err(Error::internal)?
                .is_some();
            #[cfg(test)]
            if let Some(probe) = &probe {
                probe.record(
                    super::gate_probe::GateStage::AuthoritySelect,
                    if authorized {
                        super::gate_probe::StageOutcome::Ok
                    } else {
                        super::gate_probe::StageOutcome::Refused
                    },
                );
            }
            authorized
        }
    };
    if !authorized {
        return Err(Error::internal("sandbox authority expired before start"));
    }
    let marker = fs::write(root.join("control/start"), b"start");
    #[cfg(test)]
    if let Some(probe) = &probe {
        probe.record(
            super::gate_probe::GateStage::Marker,
            if marker.is_ok() { super::gate_probe::StageOutcome::Ok } else { super::gate_probe::StageOutcome::Failed },
        );
    }
    marker.map_err(Error::internal)?;
    let committed = tx.commit().await;
    #[cfg(test)]
    if let Some(probe) = &probe {
        match &committed {
            Ok(()) => probe.record(super::gate_probe::GateStage::Commit, super::gate_probe::StageOutcome::Ok),
            Err(_error) => probe.record_pg_error(super::gate_probe::GateStage::Commit, _error),
        }
    }
    committed.map_err(Error::internal)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Default)]
struct Usage {
    bytes: u64,
    entries: u64,
}

/// Iteratively account a job-owned tree without following symlinks. The walk
/// stops as soon as a limit is crossed so exhaustion cannot turn accounting
/// into another denial of service. A scan failure fails closed.
fn usage(path: &Path, max_bytes: u64, max_entries: u64) -> std::io::Result<Usage> {
    let mut total = Usage::default();
    let mut stack = vec![path.to_path_buf()];
    while let Some(directory) = stack.pop() {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        for entry in entries {
            let entry = entry?;
            total.entries += 1;
            if total.entries > max_entries {
                return Ok(total);
            }
            let metadata = match fs::symlink_metadata(entry.path()) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error),
            };
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                stack.push(entry.path());
            } else {
                total.bytes = total.bytes.saturating_add(metadata.len());
                if total.bytes > max_bytes {
                    return Ok(total);
                }
            }
        }
    }
    Ok(total)
}

fn quota_issue(artifacts: &Path, workspace: Option<&Path>, limits: &cgroup::Limits) -> Option<String> {
    let check = |tree: &Path, bytes: u64, label: &str| -> Option<String> {
        match usage(tree, bytes, limits.max_entries) {
            Ok(used) if used.bytes > bytes => Some(format!("{label} quota exceeded: {} bytes", used.bytes)),
            Ok(used) if used.entries > limits.max_entries => {
                Some(format!("{label} entry quota exceeded: {} entries", used.entries))
            }
            Ok(_) => None,
            Err(_) => Some(format!("{label} quota accounting failed; job stopped")),
        }
    };
    check(artifacts, limits.artifacts_bytes, "artifact")
        .or_else(|| workspace.and_then(|tree| check(tree, limits.workspace_bytes, "workspace")))
}

fn note(root: &Path, message: &str) {
    let Ok(mut file) = OpenOptions::new().append(true).create(true).mode(0o600).open(root.join("stderr.log")) else {
        return;
    };
    let _ = writeln!(file, "rootyard: {message}");
}

/// Reclaim the large transient copy but keep the bounded logs and artifacts
/// available for authorized export. Retained job roots are removed later by
/// the retention sweep or an explicit cleanup request.
async fn reclaim_transient(root: &Path, live: bool, ci: bool, group: Option<&Path>) {
    if !live {
        let _ = fs::remove_dir_all(root.join("workspace"));
    }
    if ci {
        let _ = fs::remove_dir_all(root.join("checkout"));
    }
    if let Some(group) = group {
        // A failure is retained and blocks new launches until reclaimed;
        // startup recovery also fails closed on leftovers.
        cgroup::retire(group).await;
    }
}

#[derive(Clone, Copy)]
struct ProcStat {
    state: u8,
    group: i32,
    session: i32,
}

fn proc_stat(pid: i32) -> std::io::Result<Option<ProcStat>> {
    let raw = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let Some((_, tail)) = raw.rsplit_once(") ") else {
        return Ok(None);
    };
    let fields: Vec<&str> = tail.split_whitespace().collect();
    let (Some(state), Some(group), Some(session)) = (fields.first(), fields.get(2), fields.get(3)) else {
        return Ok(None);
    };
    let (Ok(group), Ok(session)) = (group.parse::<i32>(), session.parse::<i32>()) else {
        return Ok(None);
    };
    Ok(Some(ProcStat { state: state.as_bytes()[0], group, session }))
}

/// Every process group in the recorded sandbox session. The launcher called
/// setsid, so this session was created by this job and cannot contain unrelated
/// host processes.
fn session_groups(session: i32) -> std::io::Result<Vec<i32>> {
    let mut groups = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let Ok(entry) = entry else { continue };
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else { continue };
        let Ok(Some(stat)) = proc_stat(pid) else { continue };
        if stat.session == session && stat.state != b'Z' && stat.state != b'X' && !groups.contains(&stat.group) {
            groups.push(stat.group);
        }
    }
    Ok(groups)
}

fn live_job_pids(root: &Path) -> std::io::Result<Vec<i32>> {
    let needle = root.to_string_lossy();
    let mut pids = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let Ok(entry) = entry else { continue };
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else { continue };
        let Ok(Some(stat)) = proc_stat(pid) else { continue };
        if stat.state == b'Z' || stat.state == b'X' {
            continue;
        }
        let Ok(cmdline) = fs::read(entry.path().join("cmdline")) else { continue };
        if cmdline.windows(needle.len()).any(|window| window == needle.as_bytes()) {
            pids.push(pid);
        }
    }
    Ok(pids)
}

/// Prove the sandbox process tree is gone before its storage is deleted.
///
/// The launcher is a session leader (`setsid`) and Bubblewrap's
/// `--die-with-parent` tears down the PID namespace when the leader dies, so
/// descendants that create their own process group or double-fork are still
/// covered by kernel namespace teardown. We first kill every process group in
/// the recorded session (including such descendants while the leader is still
/// alive), then the leader, then verify that no live process still references
/// this exact job root. Verification failure keeps the job row retryable and
/// prevents root deletion; unrelated PIDs are never signalled.
async fn reclaim_orphan(root: &Path, pid: Option<i32>) -> Result<(), Error> {
    if let Some(pid) = pid.filter(|pid| *pid > 1)
        && let Some(stat) = proc_stat(pid).map_err(Error::internal)?
    {
        let cmdline = fs::read(format!("/proc/{pid}/cmdline")).map_err(Error::internal)?;
        let needle = root.to_string_lossy();
        let ours = cmdline.windows(5).any(|window| window == b"bwrap")
            && cmdline.windows(needle.len()).any(|window| window == needle.as_bytes());
        if ours {
            if stat.session != pid || stat.group != pid {
                return Err(Error::internal("sandbox leader is not the isolated session leader"));
            }
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                for group in session_groups(pid).map_err(Error::internal)? {
                    // SAFETY: every group belongs to the sandbox session
                    // created by our own setsid launcher.
                    unsafe { libc::kill(-group, libc::SIGKILL) };
                }
                // SAFETY: identity (bwrap plus this job root) was verified
                // above; PID reuse would have changed the cmdline.
                unsafe { libc::kill(pid, libc::SIGKILL) };
                let leader_alive = matches!(proc_stat(pid).map_err(Error::internal)?, Some(stat)
                        if stat.state != b'Z' && stat.state != b'X');
                if !leader_alive && session_groups(pid).map_err(Error::internal)?.is_empty() {
                    break;
                }
                if Instant::now() >= deadline {
                    return Err(Error::internal("sandbox session did not terminate"));
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let live = live_job_pids(root).map_err(Error::internal)?;
        if live.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(Error::internal("sandbox descendants still reference the job root"));
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

pub async fn launch(
    state: Arc<AppState>,
    job: Uuid,
    workspace: Uuid,
    argv: Vec<String>,
    timeout_seconds: u64,
    live: bool,
    terminal: bool,
) -> Result<(), Error> {
    launch_source(state, job, Source::Workspace { id: workspace, live }, argv, timeout_seconds, terminal).await
}

pub(super) async fn launch_ci(
    state: Arc<AppState>,
    job: Uuid,
    checkout: PathBuf,
    claim: crate::webhooks::claimed::ClaimedRun,
    argv: Vec<String>,
    timeout_seconds: u64,
    terminal: bool,
) -> Result<(), Error> {
    launch_source(state, job, Source::Ci { checkout, claim }, argv, timeout_seconds, terminal).await
}

async fn launch_source(
    state: Arc<AppState>,
    job: Uuid,
    source: Source,
    argv: Vec<String>,
    timeout_seconds: u64,
    terminal: bool,
) -> Result<(), Error> {
    let live = matches!(&source, Source::Workspace { live: true, .. });
    if live && std::env::var("ROOTYARD_SANDBOX_MODE").as_deref() != Ok("dev") {
        return Err(Error::internal("live FUSE workspace requires dev namespace mode"));
    }
    cgroup::ensure_clean().await?;
    let limits = cgroup::Limits::from_env()?;
    let production = std::env::var("ROOTYARD_SANDBOX_MODE").as_deref() == Ok("cgroup");
    // Validate the isolation backend before touching any job-owned copy. A
    // cgroup that cannot be created must fail the launch without leaving a
    // workspace snapshot behind on the host.
    let isolation = isolation_mode(job, &limits)?;
    let pool = match export::configured_pool() {
        Some(_) => match export::verify_pool() {
            Ok(pool) => Some(pool),
            Err(error) => {
                if let Mode::Cgroup(group) = &isolation {
                    cgroup::retire(group).await;
                }
                return Err(error);
            }
        },
        None => None,
    };
    if production && pool.is_none() {
        if let Mode::Cgroup(group) = &isolation {
            cgroup::retire(group).await;
        }
        return Err(Error::internal("bounded artifact tmpfs pool required"));
    }
    let root = job_root(&state, job);
    let workspace_dir = root.join("workspace");
    let artifacts = match &pool {
        Some(pool) => pool.join(job.to_string()),
        None => root.join("artifacts"),
    };
    let prepared = (|| -> Result<(), Error> {
        fs::create_dir_all(&root).map_err(Error::internal)?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).map_err(Error::internal)?;
        match &pool {
            Some(pool) => {
                export::job_pool_dir(pool, job)?;
            }
            None => {
                fs::create_dir_all(&artifacts).map_err(Error::internal)?;
                fs::set_permissions(&artifacts, fs::Permissions::from_mode(0o700)).map_err(Error::internal)?;
            }
        }
        if !live {
            let source_path = match &source {
                Source::Workspace { id, .. } => service::workspace_repo(&state, *id),
                Source::Ci { checkout, .. } => checkout.clone(),
            };
            core::copy_all(&source_path, &workspace_dir).map_err(Error::internal)?;
        }
        Ok(())
    })();
    if let Err(error) = prepared {
        cleanup_failed_setup(&root, &workspace_dir, Some(&artifacts), &isolation).await;
        return Err(error);
    }
    let outcome = launch_inner(
        state.clone(),
        job,
        &source,
        &root,
        &workspace_dir,
        &artifacts,
        &isolation,
        &limits,
        argv,
        timeout_seconds,
        terminal,
        live,
    )
    .await;
    if outcome.is_err() {
        cleanup_failed_setup(&root, &workspace_dir, Some(&artifacts), &isolation).await;
    }
    outcome
}

/// Remove every job-owned copy created before a failed launch. Retired cgroup
/// cleanup is retained and blocks new launches if it cannot be proven complete.
async fn cleanup_failed_setup(root: &Path, workspace: &Path, artifacts: Option<&Path>, isolation: &Mode) {
    let _ = fs::remove_dir_all(workspace);
    let _ = fs::remove_dir_all(root.join("checkout"));
    if let Some(artifacts) = artifacts {
        let _ = fs::remove_dir_all(artifacts);
    }
    if let Mode::Cgroup(group) = isolation {
        cgroup::retire(group).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn launch_inner(
    state: Arc<AppState>,
    job: Uuid,
    source: &Source,
    root: &Path,
    workspace_dir: &Path,
    artifacts: &Path,
    isolation: &Mode,
    limits: &cgroup::Limits,
    argv: Vec<String>,
    timeout_seconds: u64,
    terminal: bool,
    live: bool,
) -> Result<(), Error> {
    let stdout = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join("stdout.log"))
        .map_err(Error::internal)?;
    let stderr = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join("stderr.log"))
        .map_err(Error::internal)?;
    let pty = if terminal { Some(terminal::Pty::open()?) } else { None };
    let drain_output = if terminal { Some(stdout.try_clone().map_err(Error::internal)?) } else { None };
    let ctl = root.join("control");
    fs::create_dir(&ctl).map_err(Error::internal)?;
    let mut command = Command::new("bwrap");
    command.args([
        "--unshare-all",
        "--die-with-parent",
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "HOME",
        "/home",
        "--setenv",
        "TMPDIR",
        "/tmp",
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind",
        "/bin",
        "/bin",
        "--ro-bind",
        "/lib",
        "/lib",
        "--ro-bind",
        "/lib64",
        "/lib64",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--size",
        &limits.tmp_bytes.to_string(),
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/run",
        "--dir",
        "/home",
        "--dir",
        "/artifacts",
        "--bind",
    ]);
    command.arg(artifacts).args(["/artifacts"]);
    // The pre-exec file-size limit must admit the baseline copy; the wrapper
    // lowers it for user code before `exec` so a single artifact or log file
    // cannot exceed the export bound.
    let user_file_limit = (ARTIFACT_FILE_BYTES / 512).to_string();
    match isolation {
        Mode::Dev => {
            let source_root = if live {
                match source {
                    Source::Workspace { id, .. } => service::workspace_repo(&state, *id),
                    Source::Ci { .. } => unreachable!(),
                }
            } else {
                workspace_dir.to_path_buf()
            };
            command
                .arg("--bind")
                .arg(&source_root)
                .args(["/workspace", "--dir", "/run/rootyard", "--ro-bind"])
                .arg(&ctl)
                .args(["/run/rootyard", "--chdir", "/workspace", "--", "/bin/sh", "-c"])
                .arg(format!(
                    "while [ ! -f /run/rootyard/start ]; do sleep 0.05; done; \
                    ulimit -f {user_file_limit} 2>/dev/null || exit 97; exec \"$@\""
                ))
                .arg("rootyard-job")
                .args(argv.iter().map(String::as_str));
        }
        Mode::Cgroup(_) => {
            command
                .args(["--size", &limits.workspace_bytes.to_string(), "--tmpfs", "/workspace", "--ro-bind"])
                .arg(workspace_dir)
                .args(["/baseline", "--dir", "/run/rootyard", "--ro-bind"])
                .arg(&ctl)
                .args(["/run/rootyard", "--chdir", "/workspace", "--", "/bin/sh", "-c"])
                .arg(format!(
                    "while [ ! -f /run/rootyard/start ]; do sleep 0.05; done; \
                    cp -a /baseline/. /workspace/ && cd /workspace && \
                    ulimit -f {user_file_limit} 2>/dev/null || exit 97; exec \"$@\""
                ))
                .arg("rootyard-job")
                .args(argv.iter().map(String::as_str));
        }
    }
    if let Some(ref pty) = pty {
        command
            .stdin(Stdio::from(pty.slave.try_clone().map_err(Error::internal)?))
            .stdout(Stdio::from(pty.slave.try_clone().map_err(Error::internal)?))
            .stderr(Stdio::from(pty.slave.try_clone().map_err(Error::internal)?));
    } else {
        command.stdout(Stdio::from(stdout)).stderr(Stdio::from(stderr)).stdin(Stdio::null());
    }
    command.kill_on_drop(true);
    let file_limit = limits.workspace_bytes.max(ARTIFACT_FILE_BYTES);
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if terminal && libc::ioctl(0, libc::TIOCSCTTY, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            limit(libc::RLIMIT_CPU, timeout_seconds + 2)?;
            limit(libc::RLIMIT_AS, 512 * 1024 * 1024)?;
            limit(libc::RLIMIT_FSIZE, file_limit)?;
            limit(libc::RLIMIT_NOFILE, 128)?;
            // Production process accounting is the job cgroup's pids.max. The
            // development mode runs the same namespace isolation but is not a
            // production aggregate-limit boundary.
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(Error::internal)?;
    let pid = child.id().ok_or_else(|| Error::internal("sandbox process missing pid"))? as i32;
    if let Some(pty) = pty {
        pty.drain(job, drain_output.expect("terminal output file"));
    }
    let group = match isolation {
        Mode::Cgroup(group) => Some(group.clone()),
        Mode::Dev => None,
    };
    if let Some(group) = &group
        && cgroup::attach(group, pid).is_err()
    {
        let _ = crate::git_http::stop_group_child(&mut child).await;
        terminal::close(job);
        cgroup::retire(group).await;
        return Err(Error::internal("sandbox cgroup attach failed"));
    }
    let registration = tokio::time::timeout(Duration::from_secs(5), async {
        match source {
            Source::Workspace { .. } => async {
                let client = state.pool.get().await.map_err(Error::internal)?;
                let changed = client.execute("UPDATE sandbox_jobs j SET state='running',pid=$2,started_at=clock_timestamp() FROM workspaces w WHERE j.id=$1 AND j.state='queued' AND j.workspace_id=w.id AND j.lease_epoch=w.lease_epoch AND j.host_id=w.host_id AND w.lease_until>clock_timestamp()", &[&job,&pid]).await.map_err(Error::internal)?;
                if changed != 1 {
                    return Err(Error::internal("sandbox job was not queued"));
                }
                Ok::<_, Error>(())
            }
            .await,
            Source::Ci { claim, .. } => super::ci::mark_running(&state, claim, job, pid).await,
        }
    })
    .await
    .unwrap_or_else(|_| Err(Error::timeout()));
    if let Err(error) = registration {
        let _ = crate::git_http::stop_group_child(&mut child).await;
        terminal::close(job);
        if let Some(group) = &group {
            cgroup::retire(group).await;
        }
        return Err(error);
    }
    if let Ok(delay) = std::env::var("ROOTYARD_TEST_SANDBOX_GATE_PAUSE_MS")
        && let Ok(delay) = delay.parse::<u64>()
    {
        tokio::time::sleep(Duration::from_millis(delay.min(2000))).await;
    }
    if let Err(error) = open_start_gate(&state, job, source, root).await {
        let _ = crate::git_http::stop_group_child(&mut child).await;
        terminal::close(job);
        if let Some(group) = &group {
            cgroup::retire(group).await;
        }
        if let Ok(client) = state.pool.get().await {
            let _ = client
                .execute(
                    "UPDATE sandbox_jobs SET state='failed',pid=NULL,finished_at=clock_timestamp() \
                WHERE id=$1 AND state='running'",
                    &[&job],
                )
                .await;
        }
        return Err(error);
    }
    let root_owned = root.to_path_buf();
    let artifacts_owned = artifacts.to_path_buf();
    let workspace_owned = workspace_dir.to_path_buf();
    let ci = matches!(source, Source::Ci { .. });
    let source_owned = match source {
        Source::Workspace { id, live } => Source::Workspace { id: *id, live: *live },
        Source::Ci { checkout, claim } => Source::Ci { checkout: checkout.clone(), claim: claim.clone() },
    };
    let dev_mode = matches!(isolation, Mode::Dev);
    let limits = limits.clone();
    tokio::spawn(async move {
        let workspace_quota = (!live && dev_mode).then_some(workspace_owned.as_path());
        let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_seconds);
        let mut last_quota = Instant::now() - Duration::from_secs(1);
        let (mut state_name, mut code) = loop {
            match leader_exited(pid) {
                Ok(true) => match crate::git_http::finish_group_child(&mut child).await {
                    Ok(status) if status.success() => break ("succeeded", status.code()),
                    Ok(status) => break ("failed", status.code()),
                    Err(_) => break ("failed", None),
                },
                Err(_) => break ("failed", None),
                Ok(false) => {}
            }
            if tokio::time::Instant::now() >= deadline {
                let _ = crate::git_http::stop_group_child(&mut child).await;
                break ("timed_out", None);
            }
            if last_quota.elapsed() >= Duration::from_millis(750) {
                last_quota = Instant::now();
                if quota_issue(&artifacts_owned, workspace_quota, &limits).is_some() {
                    let _ = crate::git_http::stop_group_child(&mut child).await;
                    break ("failed", None);
                }
            }
            let lease_live = match &source_owned {
                Source::Workspace { .. } => match state.pool.get().await {
                    Ok(client) => client
                        .query_opt("SELECT j.state,j.lease_epoch=w.lease_epoch AND j.host_id=w.host_id AND w.lease_until>clock_timestamp() AS lease_live FROM sandbox_jobs j JOIN workspaces w ON w.id=j.workspace_id WHERE j.id=$1", &[&job])
                        .await.ok().flatten()
                        .is_some_and(|row| row.get::<_, String>(0) == "running" && row.get::<_, bool>(1)),
                    Err(_) => false,
                },
                Source::Ci { claim, .. } => super::ci::still_active(&state, claim, job).await.unwrap_or(false),
            };
            if !lease_live {
                let _ = crate::git_http::stop_group_child(&mut child).await;
                break ("cancelled", None);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        };
        // A job that wrote past its quota is failed even if the shell itself
        // exited zero: resource exhaustion must be a terminal failure, never a
        // success result.
        if let Some(reason) = quota_issue(&artifacts_owned, workspace_quota, &limits) {
            state_name = "failed";
            code = None;
            note(&root_owned, &reason);
        }
        if let Source::Ci { claim, .. } = &source_owned
            && !super::ci::still_active(&state, claim, job).await.unwrap_or(false)
        {
            state_name = "cancelled";
            code = None;
        }
        if let Ok(client) = state.pool.get().await {
            let _ = client.execute("UPDATE sandbox_jobs SET state=$2,exit_code=$3,finished_at=clock_timestamp(),pid=NULL WHERE id=$1 AND state='running'", &[&job,&state_name,&code]).await;
        }
        terminal::close(job);
        reclaim_transient(&root_owned, live, ci, group.as_deref()).await;
    });
    Ok(())
}

/// Mark every non-terminal job owned by this host as failed and reclaim its
/// processes and storage. The sweeper also removes cgroups and terminal roots
/// left by a crash between the result update and cleanup.
pub async fn reconcile_startup(state: &AppState) -> Result<(), Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let rows = client
        .query(
            "SELECT id,state,pid,workspace_access,ci_run_id FROM sandbox_jobs WHERE host_id=$1 \
        AND state IN ('queued','preparing','running')",
            &[&state.storage.volume_id],
        )
        .await
        .map_err(Error::internal)?;
    let cgroup_base = if std::env::var("ROOTYARD_SANDBOX_MODE").as_deref() == Ok("cgroup") {
        Some(cgroup::delegated_root()?)
    } else {
        None
    };
    for row in rows {
        let id: Uuid = row.get(0);
        let job_state: String = row.get(1);
        let pid: Option<i32> = row.get(2);
        let access: String = row.get(3);
        let ci = row.get::<_, Option<Uuid>>(4).is_some();
        let root = job_root(state, id);
        if job_state == "running" {
            // Kill the kernel-enforced group first, then prove the process tree
            // is gone. A failure leaves the row non-terminal and aborts startup
            // so no new work is admitted while an unclean job still exists.
            if let Some(base) = &cgroup_base {
                cgroup::destroy(&base.join(id.to_string())).await?;
            }
            reclaim_orphan(&root, pid).await?;
        }
        client
            .execute(
                "UPDATE sandbox_jobs SET state='failed',pid=NULL,finished_at=clock_timestamp()             WHERE id=$1 AND state IN ('queued','preparing','running')",
                &[&id],
            )
            .await
            .map_err(Error::internal)?;
        if job_state == "queued" || job_state == "preparing" {
            // No result was produced yet; the checkout or snapshot is disposable.
            cleanup_job(state, id)?;
        } else {
            reclaim_transient(&root, access == "live", ci, None).await;
        }
    }
    // Every non-terminal job is terminal after the loop, so every job cgroup in
    // our delegated subtree is stale. Unrelated cgroups are never touched.
    if let Some(base) = &cgroup_base {
        cgroup::reap_stale(base, &HashSet::new()).await?;
    }
    // Terminal roots hold bounded logs and artifacts for authorized export.
    // A restart sweeps roots older than the retention window; an explicit
    // cleanup request removes an individual root immediately.
    let retention = std::env::var("ROOTYARD_SANDBOX_RETENTION_SECONDS")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|value| (0..=30 * 24 * 3600).contains(value))
        .unwrap_or(3600);
    let expired = client
        .query(
            "SELECT id FROM sandbox_jobs WHERE host_id=$1         AND state IN ('succeeded','failed','cancelled','timed_out')         AND finished_at < clock_timestamp() - ($2::bigint * interval '1 second')",
            &[&state.storage.volume_id, &retention],
        )
        .await
        .map_err(Error::internal)?;
    for row in expired {
        let id: Uuid = row.get(0);
        cleanup_job(state, id)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Source, bwrap_supports_size, open_start_gate};
    use crate::sandbox::gate_probe::{GATE_PROBE, GateProbe};
    use crate::{
        AppState,
        ci_checkouts::{Plan, dependencies::Manifest},
        config::Config,
        db, dispatch, metrics,
        storage::Storage,
        webhooks::{claimed::ClaimedRun, trust::ContextInput},
    };
    use axum::{
        Json,
        extract::{Path, State},
        http::{HeaderMap, HeaderValue, StatusCode, header},
    };
    use deadpool_postgres::{Manager, Pool};
    use std::{path::PathBuf, sync::Arc, time::Duration};
    use tokio::time::Instant;
    use uuid::Uuid;

    const GATE_CONTEXT: &str = "ci/trusted";

    struct BackendWait {
        query: String,
        wait_event_type: Option<String>,
        wait_event: Option<String>,
    }

    fn app_state(pool: Pool, data_dir: PathBuf) -> AppState {
        let config = Config {
            database_url: String::new(),
            data_dir,
            bind: "127.0.0.1:0".parse().unwrap(),
            git: PathBuf::from("/usr/bin/git"),
            max_request_bytes: 1024 * 1024,
            max_output_bytes: 1024 * 1024,
            max_concurrent_git: 1,
            git_timeout: Duration::from_secs(10),
            git_memory_bytes: 1024 * 1024 * 1024,
            max_repo_bytes: 1024 * 1024,
            max_pending_deliveries: 100,
            outbox_worker: false,
            metrics_bind: None,
        };
        let storage = Storage::open(&config).expect("test storage");
        AppState {
            mirror_primary: None,
            dispatch: dispatch::Signals::default(),
            config,
            pool,
            storage,
            hooks: None,
            transfer_metrics: Arc::new(metrics::TransferCounters::default()),
            git_slots: Arc::new(tokio::sync::Semaphore::new(1)),
        }
    }

    async fn wait_backend(
        pool: &Pool,
        application_name: &str,
        patterns: &[&str],
        deadline: Instant,
    ) -> anyhow::Result<BackendWait> {
        loop {
            let found = {
                let client = pool.get().await.map_err(|error| {
                    anyhow::anyhow!(
                        "backend observation pool error sqlstate={}",
                        crate::sandbox::gate_probe::safe_pool_sqlstate(&error).unwrap_or("none")
                    )
                })?;
                let rows = client
                    .query(
                        "SELECT query,wait_event_type,wait_event FROM pg_stat_activity \
                         WHERE application_name=$1 AND state='active' AND pid<>pg_backend_pid()",
                        &[&application_name],
                    )
                    .await
                    .map_err(|error| {
                        anyhow::anyhow!(
                            "backend observation query error sqlstate={}",
                            crate::sandbox::gate_probe::safe_pg_sqlstate(&error).unwrap_or("none")
                        )
                    })?;
                rows.into_iter().find_map(|row| {
                    let query: String = row.get(0);
                    let wait_event_type: Option<String> = row.get(1);
                    if patterns.iter().any(|pattern| query.contains(*pattern))
                        && wait_event_type.as_deref() == Some("Lock")
                    {
                        Some(BackendWait { query, wait_event_type, wait_event: row.get(2) })
                    } else {
                        None
                    }
                })
            };
            if let Some(found) = found {
                return Ok(found);
            }
            if Instant::now() >= deadline {
                anyhow::bail!("no backend reached the expected test barrier");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    async fn join_timeout<T>(handle: &mut tokio::task::JoinHandle<T>, label: &str) -> anyhow::Result<T>
    where
        T: Send + 'static,
    {
        match tokio::time::timeout(Duration::from_secs(15), &mut *handle).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(_)) => Err(anyhow::anyhow!("{label} task failed")),
            Err(_) => {
                handle.abort();
                Err(anyhow::anyhow!("{label} timed out"))
            }
        }
    }

    /// PostgreSQL-only lock-order regression for the sandbox start gate.
    ///
    /// The real `open_start_gate` transaction and the real trusted-context
    /// revoke path run concurrently. Revoke (like PATCH) first takes the
    /// repository policy fence exclusively, then the binding `FOR UPDATE`, and
    /// only afterwards updates `ci_runs`. The test makes that binding update
    /// wait on a private advisory barrier, starts the gate while the writer is
    /// paused, and releases the barrier.
    ///
    /// Before the fix the gate locked `sandbox_jobs`, then the authority rows
    /// `FOR SHARE`; it could hold the run row and wait for the binding while the
    /// writer held the binding and waited for the run. The old order deadlocks.
    /// The fixed gate must be observed waiting on the shared policy advisory
    /// lock instead. This case proves PostgreSQL authority lock ordering only:
    /// it does not launch bubblewrap, an executor or a kernel process.
    ///
    /// A cfg(test)-only task-local probe reports a fixed stage name, any
    /// validated five-character SQLSTATE, whether the shared fence wait was
    /// observed, and the revoke HTTP status. It records no SQL, parameters,
    /// error Display, causes, URLs, tokens or paths.
    ///
    /// Run with `ROOTYARD_TEST_DATABASE_URL=... cargo test --lib
    /// start_gate_serializes_context_removal_under_policy_fence -- --ignored`.
    #[tokio::test]
    #[ignore = "requires ROOTYARD_TEST_DATABASE_URL and PostgreSQL schema creation permission"]
    async fn start_gate_serializes_context_removal_under_policy_fence() -> anyhow::Result<()> {
        let Ok(base_url) = std::env::var("ROOTYARD_TEST_DATABASE_URL") else {
            eprintln!("skipping: ROOTYARD_TEST_DATABASE_URL is not set");
            return Ok(());
        };
        let admin = db::pool(&base_url)?;
        let schema = format!("gate_lock_{}", Uuid::new_v4().simple());
        admin.get().await?.batch_execute(&format!("CREATE SCHEMA \"{schema}\"")).await?;
        let case = tokio::spawn(run_gate_lock_case(base_url, schema.clone())).await;
        let cleanup = admin.get().await?.batch_execute(&format!("DROP SCHEMA \"{schema}\" CASCADE")).await;
        let case = case.map_err(|_| anyhow::anyhow!("gate lock case panicked"))?;
        cleanup?;
        case
    }

    async fn run_gate_lock_case(base_url: String, schema: String) -> anyhow::Result<()> {
        let mut config: tokio_postgres::Config = base_url.parse()?;
        config.application_name(schema.as_str());
        config.options(format!("-c search_path={schema} -c statement_timeout=30000 -c lock_timeout=15000"));
        let pool = Pool::builder(Manager::new(config, tokio_postgres::NoTls))
            .runtime(deadpool_postgres::Runtime::Tokio1)
            .max_size(16)
            .build()?;
        db::migrate(&pool).await?;

        let storage = tempfile::tempdir()?;
        let state = Arc::new(app_state(pool.clone(), storage.path().join("data")));
        let job_root = storage.path().join("job");
        std::fs::create_dir_all(job_root.join("control"))?;

        let owner = Uuid::new_v4();
        let repo_id = Uuid::new_v4();
        let token_id = Uuid::new_v4();
        let hook_id = Uuid::new_v4();
        let run_id = Uuid::new_v4();
        let ci_job_id = Uuid::new_v4();
        let sandbox_job_id = Uuid::new_v4();
        let token = format!("ryt_{}", "ab".repeat(32));
        let head = "a".repeat(40);
        let base = "b".repeat(40);
        let now: i64 = {
            let client = pool.get().await?;
            client.query_one("SELECT extract(epoch FROM clock_timestamp())::bigint", &[]).await?.get(0)
        };
        let expires = now + 3600;
        let plan = Plan {
            version: 1,
            job_id: ci_job_id,
            owner_id: owner,
            repository_id: repo_id,
            storage_generation: 1,
            object_format: "sha1".into(),
            target_oid: head.clone(),
            source_receipt_sha256: "d".repeat(64),
            mirror_audience: Uuid::new_v4(),
            expires_unix: expires,
            dependencies: Manifest { version: 1, ..Default::default() },
        };
        let plan_json = serde_json::to_value(&plan)?;
        let client = pool.get().await?;
        client.execute("INSERT INTO users(id,username) VALUES($1,'alice')", &[&owner]).await?;
        client
            .execute(
                "INSERT INTO repositories(id,owner_id,name,state,storage_generation) \
                 VALUES($1,$2,'gate','ready',1)",
                &[&repo_id, &owner],
            )
            .await?;
        client
            .execute(
                "INSERT INTO tokens(id,user_id,digest,read_only) VALUES($1,$2,$3,false)",
                &[&token_id, &owner, &db::digest(&token)],
            )
            .await?;
        client
            .execute(
                "INSERT INTO forge_pulls(tenant_id,repository_id,number,author_id,title,state, \
                   head_ref,base_ref,head_oid,base_oid,version) \
                 VALUES($1,$2,1,$1,'gate fixture','open','refs/heads/feature', \
                   'refs/heads/main',$3,$4,1)",
                &[&owner, &repo_id, &head, &base],
            )
            .await?;
        client
            .execute(
                "INSERT INTO forge_webhooks(id,tenant_id,repository_id,url,secret,secret_sha256, \
                   events,ci_contexts,active) \
                 VALUES($1,$2,$3,'http://127.0.0.1:1/hook','gate-secret-0123456789',$4, \
                   '[\"pull_request\"]'::jsonb,$5::jsonb,true)",
                &[&hook_id, &owner, &repo_id, &"c".repeat(64), &serde_json::json!([GATE_CONTEXT])],
            )
            .await?;
        client
            .execute(
                "INSERT INTO forge_trusted_check_contexts(tenant_id,repository_id,context,webhook_id,active) \
                 VALUES($1,$2,$3,$4,true)",
                &[&owner, &repo_id, &GATE_CONTEXT, &hook_id],
            )
            .await?;
        client
            .execute(
                "INSERT INTO ci_runs(id,tenant_id,repository_id,pull_number,pull_version,context, \
                   job_id,head_oid,base_oid,storage_generation,config_sha256,state,attempt, \
                   lease_generation,lease_expires_unix,runner_id,source_url) \
                 VALUES($1,$2,$3,1,1,$4,$5,$6,$7,1,$8,'leased',1,1,$9,'runner','origin')",
                &[&run_id, &owner, &repo_id, &GATE_CONTEXT, &ci_job_id, &head, &base, &"e".repeat(64), &expires],
            )
            .await?;
        client
            .execute(
                "INSERT INTO ci_integration_checkout_jobs(run_id,attempt,lease_generation, \
                   repository_id,job_id,owner_id,issuer_webhook_id,plan,credential_digest,expires_unix) \
                 VALUES($1,1,1,$2,$3,$4,$5,$6,$7,$8)",
                &[&run_id, &repo_id, &ci_job_id, &owner, &hook_id, &plan_json, &vec![7u8; 32], &expires],
            )
            .await?;
        client
            .execute(
                "INSERT INTO sandbox_jobs(id,workspace_id,actor_id,host_id,state,argv, \
                   timeout_seconds,lease_epoch,workspace_access,ci_run_id,ci_attempt, \
                   ci_lease_generation,ci_hook_id,ci_runner_id,ci_head_oid,ci_storage_generation,terminal) \
                 VALUES($1,NULL,NULL,$2,'running','[]'::jsonb,60,0,'private',$3,1,1,$4,'runner',$5,1,false)",
                &[&sandbox_job_id, &state.storage.volume_id, &run_id, &hook_id, &head],
            )
            .await?;
        drop(client);

        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {token}"))?);
        // Hold this private barrier in the test session. The real revoke
        // writer reaches the binding trigger after taking the policy fence and
        // the binding row lock, then waits here before it can update ci_runs.
        let barrier = format!("gate-lock-{schema}");
        let barrier_client = pool.get().await?;
        let held: bool =
            barrier_client.query_one("SELECT pg_try_advisory_lock(hashtextextended($1,0))", &[&barrier]).await?.get(0);
        anyhow::ensure!(held, "test barrier was not available");
        pool.get()
            .await?
            .batch_execute(&format!(
                "CREATE FUNCTION {schema}.gate_pause() RETURNS trigger LANGUAGE plpgsql AS $$ \
                 BEGIN PERFORM pg_advisory_xact_lock(hashtextextended('{barrier}',0)); RETURN NEW; END $$; \
                 CREATE TRIGGER gate_pause AFTER UPDATE ON forge_trusted_check_contexts \
                 FOR EACH ROW EXECUTE FUNCTION {schema}.gate_pause();"
            ))
            .await?;

        let probe = Arc::new(GateProbe::default());
        let revoke_state = state.clone();
        let mut revoke = tokio::spawn(async move {
            crate::webhooks::trust::revoke(
                State(revoke_state),
                Path(("alice".to_owned(), "gate".to_owned(), hook_id)),
                headers,
                Json(ContextInput { context: GATE_CONTEXT.to_owned() }),
            )
            .await
        });

        let writer_wait = wait_backend(
            &pool,
            &schema,
            &["UPDATE forge_trusted_check_contexts"],
            Instant::now() + Duration::from_secs(10),
        )
        .await
        .map_err(|error| anyhow::anyhow!("{error}; {}", probe.snapshot()))?;
        anyhow::ensure!(
            writer_wait.wait_event_type.as_deref() == Some("Lock"),
            "writer did not reach the binding barrier; {}",
            probe.snapshot()
        );

        let gate_state = state.clone();
        let gate_root = job_root.clone();
        let claim = ClaimedRun {
            run_id,
            hook_id,
            repository_id: repo_id,
            tenant_id: owner,
            head_oid: head.clone(),
            storage_generation: 1,
            attempt: 1,
            lease_generation: 1,
            runner_id: "runner".into(),
            source: "origin".into(),
            job_id: ci_job_id,
            plan,
        };
        let gate_probe = Arc::clone(&probe);
        let mut gate = tokio::spawn(async move {
            GATE_PROBE
                .scope(gate_probe, async move {
                    let source = Source::Ci { checkout: PathBuf::from("/unused-gate-checkout"), claim };
                    open_start_gate(&gate_state, sandbox_job_id, &source, &gate_root).await
                })
                .await
        });
        let gate_wait = wait_backend(
            &pool,
            &schema,
            &["pg_advisory_xact_lock_shared", "FROM ci_runs c"],
            Instant::now() + Duration::from_secs(10),
        )
        .await;
        let observed_shared = gate_wait.as_ref().is_ok_and(|wait| wait.query.contains("pg_advisory_xact_lock_shared"));
        let observed_event = gate_wait.as_ref().ok().and_then(|wait| wait.wait_event.clone());
        probe.note_shared_policy_advisory_wait(observed_shared);

        let unlocked: bool =
            barrier_client.query_one("SELECT pg_advisory_unlock(hashtextextended($1,0))", &[&barrier]).await?.get(0);
        anyhow::ensure!(unlocked, "test barrier was not released; {}", probe.snapshot());
        drop(barrier_client);

        let revoke = join_timeout(&mut revoke, "revoke")
            .await
            .map_err(|error| anyhow::anyhow!("{error}; {}", probe.snapshot()))?;
        let revoke_status = match &revoke {
            Ok(response) => response.status().as_u16(),
            Err(error) => error.0.as_u16(),
        };
        probe.note_revoke_final_http_status(revoke_status);
        let gate =
            join_timeout(&mut gate, "gate").await.map_err(|error| anyhow::anyhow!("{error}; {}", probe.snapshot()))?;
        let gate_wait = gate_wait.map_err(|error| anyhow::anyhow!("{error}; {}", probe.snapshot()))?;
        anyhow::ensure!(observed_shared, "gate did not wait on the shared policy fence; {}", probe.snapshot());
        anyhow::ensure!(
            observed_event.as_deref() == Some("advisory"),
            "gate waited on the old authority row order: {:?}; {}",
            gate_wait.wait_event,
            probe.snapshot()
        );
        let response =
            revoke.map_err(|error| anyhow::anyhow!("revoke returned HTTP {}; {}", error.0, probe.snapshot()))?;
        anyhow::ensure!(
            response.status() == StatusCode::OK,
            "revoke returned {}; {}",
            response.status(),
            probe.snapshot()
        );
        let error = gate.err().ok_or_else(|| anyhow::anyhow!("gate unexpectedly authorized; {}", probe.snapshot()))?;
        anyhow::ensure!(
            error.1 == "sandbox authority expired before start",
            "gate returned a different refusal: HTTP {} {}; {}",
            error.0.as_u16(),
            error.1,
            probe.snapshot()
        );

        let client = pool.get().await?;
        let active: bool = client
            .query_one(
                "SELECT active FROM forge_trusted_check_contexts WHERE repository_id=$1 AND context=$2",
                &[&repo_id, &GATE_CONTEXT],
            )
            .await?
            .get(0);
        let generation: i64 =
            client.query_one("SELECT lease_generation FROM ci_runs WHERE id=$1", &[&run_id]).await?.get(0);
        anyhow::ensure!(!active, "context removal did not deactivate the binding; {}", probe.snapshot());
        anyhow::ensure!(generation == 2, "context removal did not advance the run epoch; {}", probe.snapshot());
        anyhow::ensure!(
            !job_root.join("control/start").exists(),
            "failed gate wrote the start marker; {}",
            probe.snapshot()
        );
        Ok(())
    }

    /// The capability probe must fail closed for a binary that is missing or
    /// unusable instead of reporting a usable runtime.
    #[test]
    fn bubblewrap_probe_rejects_unusable_binaries() {
        assert!(!bwrap_supports_size("rootyard-no-such-bubblewrap-binary"));
        assert!(!bwrap_supports_size("/bin/false"));
    }

    /// Positive check: when the host has bubblewrap, the probe must actually
    /// succeed. Bubblewrap creates an empty root, so a probe without
    /// `--ro-bind / /` fails even on a capable binary; this test catches that
    /// mistake. A host whose bubblewrap lacks `--size` fails here by design,
    /// because the runtime does require the capability.
    #[test]
    fn bubblewrap_probe_accepts_a_capable_host_binary() {
        if std::process::Command::new("bwrap").arg("--version").output().is_err() {
            return;
        }
        assert!(bwrap_supports_size("bwrap"), "host bubblewrap must satisfy the --size runtime probe");
    }
}
