use crate::{AppState, Error, workspace_lab::core, workspaces::service};
use std::{
    fs::{self, OpenOptions},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::process::Command;
use uuid::Uuid;

pub(super) enum Source {
    Workspace {
        id: Uuid,
        live: bool,
    },
    Ci {
        checkout: PathBuf,
        claim: Box<crate::webhooks::claimed::ClaimedRun>,
    },
}

enum Mode {
    Dev,
    Cgroup(PathBuf),
}
fn mode(job: Uuid) -> Result<Mode, Error> {
    if std::env::var("ROOTYARD_SANDBOX_MODE").as_deref() == Ok("dev") {
        return Ok(Mode::Dev);
    }
    if std::env::var("ROOTYARD_SANDBOX_MODE").as_deref() != Ok("cgroup") {
        return Err(Error::internal("sandbox cgroup mode required"));
    }
    let base =
        PathBuf::from(std::env::var("ROOTYARD_SANDBOX_CGROUP_ROOT").map_err(Error::internal)?);
    if !base.starts_with("/sys/fs/cgroup/") || !base.join("cgroup.controllers").exists() {
        return Err(Error::internal("delegated cgroup v2 root required"));
    }
    let group = base.join(job.to_string());
    fs::create_dir(&group).map_err(Error::internal)?;
    for (name, value) in [
        ("memory.max", "536870912"),
        ("memory.swap.max", "0"),
        ("pids.max", "64"),
        ("cpu.max", "50000 100000"),
    ] {
        if fs::write(group.join(name), value).is_err() {
            let _ = fs::remove_dir(&group);
            return Err(Error::internal("sandbox cgroup controller unavailable"));
        }
    }
    Ok(Mode::Cgroup(group))
}
fn attach_group(group: &Path, pid: i32) -> Result<(), Error> {
    // Bubblewrap's shell gate prevents user code from running until descendants
    // have been moved. The direct process is attached first, then any forks.
    fs::write(group.join("cgroup.procs"), pid.to_string()).map_err(Error::internal)?;
    for entry in fs::read_dir("/proc").map_err(Error::internal)? {
        let Ok(entry) = entry else { continue };
        let Ok(candidate) = entry.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else {
            continue;
        };
        let Some(rest) = stat.rsplit_once(") ").map(|(_, r)| r) else {
            continue;
        };
        if rest
            .split_whitespace()
            .nth(2)
            .and_then(|v| v.parse::<i32>().ok())
            == Some(pid)
        {
            let _ = fs::write(group.join("cgroup.procs"), candidate.to_string());
        }
    }
    Ok(())
}

pub fn job_root(state: &AppState, id: Uuid) -> PathBuf {
    state.storage.root.join("sandbox-jobs").join(id.to_string())
}

fn limit(resource: libc::__rlimit_resource_t, soft: u64) -> std::io::Result<()> {
    let lim = libc::rlimit {
        rlim_cur: soft,
        rlim_max: soft,
    };
    if unsafe { libc::setrlimit(resource, &lim) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
fn leader_exited(pid: i32) -> std::io::Result<bool> {
    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            pid as u32,
            info.as_mut_ptr(),
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { info.assume_init().si_pid() != 0 })
}

pub async fn launch(
    state: Arc<AppState>,
    job: Uuid,
    workspace: Uuid,
    argv: Vec<String>,
    timeout_seconds: u64,
    live: bool,
) -> Result<(), Error> {
    launch_source(
        state,
        job,
        Source::Workspace {
            id: workspace,
            live,
        },
        argv,
        timeout_seconds,
    )
    .await
}

pub(super) async fn launch_ci(
    state: Arc<AppState>,
    job: Uuid,
    checkout: PathBuf,
    claim: crate::webhooks::claimed::ClaimedRun,
    argv: Vec<String>,
    timeout_seconds: u64,
) -> Result<(), Error> {
    launch_source(
        state,
        job,
        Source::Ci {
            checkout,
            claim: Box::new(claim),
        },
        argv,
        timeout_seconds,
    )
    .await
}

async fn launch_source(
    state: Arc<AppState>,
    job: Uuid,
    source: Source,
    argv: Vec<String>,
    timeout_seconds: u64,
) -> Result<(), Error> {
    let live = matches!(&source, Source::Workspace { live: true, .. });
    if live && std::env::var("ROOTYARD_SANDBOX_MODE").as_deref() != Ok("dev") {
        return Err(Error::internal(
            "live FUSE workspace requires dev namespace mode",
        ));
    }
    let isolation = mode(job)?;
    let root = job_root(&state, job);
    fs::create_dir_all(&root).map_err(Error::internal)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).map_err(Error::internal)?;
    let workspace_dir = root.join("workspace");
    if !live {
        let source_path = match &source {
            Source::Workspace { id, .. } => service::workspace_repo(&state, *id),
            Source::Ci { checkout, .. } => checkout.clone(),
        };
        core::copy_all(&source_path, &workspace_dir).map_err(Error::internal)?;
    }
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
        "67108864",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/run",
        "--dir",
        "/home",
    ]);
    match &isolation {
        Mode::Dev => {
            let source = if live {
                match &source {
                    Source::Workspace { id, .. } => service::workspace_repo(&state, *id),
                    Source::Ci { .. } => unreachable!(),
                }
            } else {
                workspace_dir.clone()
            };
            command
                .arg("--bind")
                .arg(&source)
                .args(["/workspace", "--dir", "/run/rootyard", "--ro-bind"])
                .arg(&ctl)
                .args([
                    "/run/rootyard",
                    "--chdir",
                    "/workspace",
                    "--",
                    "/bin/sh",
                    "-c",
                    "while [ ! -f /run/rootyard/start ]; do sleep 0.05; done; exec \"$@\"",
                    "rootyard-job",
                ])
                .args(argv.iter().map(String::as_str));
        }
        Mode::Cgroup(_) => {
            command.args(["--size","268435456","--tmpfs","/workspace","--ro-bind"])
                .arg(&workspace_dir).args(["/baseline","--dir","/run/rootyard","--ro-bind"])
                .arg(&ctl).args(["/run/rootyard","--chdir","/workspace","--","/bin/sh","-c",
                    "while [ ! -f /run/rootyard/start ]; do sleep 0.05; done; cp -a /baseline/. /workspace/ && cd /workspace && exec \"$@\"","rootyard-job"])
                .args(argv.iter().map(String::as_str));
        }
    }
    command
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .stdin(Stdio::null());
    command.kill_on_drop(true);
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            limit(libc::RLIMIT_CPU, timeout_seconds + 2)?;
            limit(libc::RLIMIT_AS, 512 * 1024 * 1024)?;
            limit(libc::RLIMIT_FSIZE, 16 * 1024 * 1024)?;
            limit(libc::RLIMIT_NOFILE, 128)?;
            // Production process accounting is the job cgroup's pids.max=64.
            // RLIMIT_NPROC counts unrelated same-UID host processes (including
            // unreaped zombies) and can prevent bubblewrap from starting at all.
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(Error::internal)?;
    let pid = child
        .id()
        .ok_or_else(|| Error::internal("sandbox process missing pid"))? as i32;
    if let Mode::Cgroup(group) = &isolation {
        if attach_group(group, pid).is_err() {
            let _ = crate::git_http::stop_group_child(&mut child).await;
            let _ = fs::write(group.join("cgroup.kill"), "1");
            let _ = fs::remove_dir(group);
            return Err(Error::internal("sandbox cgroup attach failed"));
        }
    }
    let registration=tokio::time::timeout(Duration::from_secs(5),async {match &source {
        Source::Workspace{..}=>async {
            let client=state.pool.get().await.map_err(Error::internal)?;
            let changed=client.execute("UPDATE sandbox_jobs j SET state='running',pid=$2,started_at=clock_timestamp() FROM workspaces w WHERE j.id=$1 AND j.state='queued' AND j.workspace_id=w.id AND j.lease_epoch=w.lease_epoch AND j.host_id=w.host_id AND w.lease_until>clock_timestamp()", &[&job,&pid]).await.map_err(Error::internal)?;
            if changed!=1 { return Err(Error::internal("sandbox job was not queued")); }
            Ok::<_,Error>(())
        }.await,
        Source::Ci{claim,..}=>super::ci::mark_running(&state,claim,job,pid).await,
    }}).await.unwrap_or_else(|_|Err(Error::timeout()));
    if let Err(error) = registration {
        let _ = crate::git_http::stop_group_child(&mut child).await;
        if let Mode::Cgroup(group) = &isolation {
            let _ = fs::write(group.join("cgroup.kill"), "1");
            let _ = fs::remove_dir(group);
        }
        return Err(error);
    }
    if let Err(error) = fs::write(root.join("control/start"), b"start") {
        let _ = crate::git_http::stop_group_child(&mut child).await;
        if let Mode::Cgroup(group) = &isolation {
            let _ = fs::write(group.join("cgroup.kill"), "1");
            let _ = fs::remove_dir(group);
        }
        return Err(Error::internal(error));
    }
    tokio::spawn(async move {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_seconds);
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
            let lease_live = match &source {
                Source::Workspace{..}=>match state.pool.get().await {
                    Ok(client) => client
                        .query_opt("SELECT j.state,j.lease_epoch=w.lease_epoch AND j.host_id=w.host_id AND w.lease_until>clock_timestamp() AS lease_live FROM sandbox_jobs j JOIN workspaces w ON w.id=j.workspace_id WHERE j.id=$1", &[&job])
                        .await.ok().flatten()
                        .is_some_and(|row| row.get::<_, String>(0) == "running" && row.get::<_, bool>(1)),
                    Err(_) => false,
                },
                Source::Ci{claim,..}=>super::ci::still_active(&state,claim,job).await.unwrap_or(false),
            };
            if !lease_live {
                let _ = crate::git_http::stop_group_child(&mut child).await;
                break ("cancelled", None);
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        };
        if let Source::Ci { claim, .. } = &source {
            if !super::ci::still_active(&state, claim, job)
                .await
                .unwrap_or(false)
            {
                state_name = "cancelled";
                code = None;
            }
        }
        if let Ok(client) = state.pool.get().await {
            let _=client.execute("UPDATE sandbox_jobs SET state=$2,exit_code=$3,finished_at=clock_timestamp(),pid=NULL WHERE id=$1 AND state='running'", &[&job,&state_name,&code]).await;
        }
        if let Mode::Cgroup(group) = isolation {
            let _ = fs::write(group.join("cgroup.kill"), "1");
            let _ = fs::remove_dir(group);
        }
    });
    Ok(())
}

pub async fn reconcile_startup(state: &AppState) -> Result<(), Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let abandoned = client
        .query(
            "SELECT id FROM sandbox_jobs WHERE host_id=$1 \
        AND state IN ('queued','preparing')",
            &[&state.storage.volume_id],
        )
        .await
        .map_err(Error::internal)?;
    let rows = client
        .query(
            "SELECT id,pid FROM sandbox_jobs WHERE host_id=$1 AND state='running'",
            &[&state.storage.volume_id],
        )
        .await
        .map_err(Error::internal)?;
    for row in rows {
        let id: Uuid = row.get(0);
        let pid: Option<i32> = row.get(1);
        let _ = pid; // --die-with-parent kills the namespace on service crash.
        client.execute("UPDATE sandbox_jobs SET state='failed',finished_at=clock_timestamp(),pid=NULL WHERE id=$1 AND state='running'", &[&id]).await.map_err(Error::internal)?;
    }
    client.execute("UPDATE sandbox_jobs SET state='failed',finished_at=clock_timestamp() WHERE host_id=$1 AND state IN ('queued','preparing')", &[&state.storage.volume_id]).await.map_err(Error::internal)?;
    for row in abandoned {
        let id: Uuid = row.get(0);
        let root = job_root(state, id);
        if root.exists() {
            fs::remove_dir_all(root).map_err(Error::internal)?;
        }
    }
    Ok(())
}
