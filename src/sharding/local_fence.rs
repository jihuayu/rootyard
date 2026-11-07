//! Trusted single-host process-group fencing. This driver does not fence remote hosts.
use crate::sharding::models::{VolumeFenceMarker, valid_node_id};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use fs2::FileExt;
use std::{fs::{self, OpenOptions}, os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf}, sync::OnceLock, time::Duration};
use uuid::Uuid;

static LOCAL_NODE_LOCK: OnceLock<fs::File> = OnceLock::new();

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessIdentity {
    node_id: String,
    pid: i32,
    start_ticks: u64,
    boot_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VolumeRegistration {
    pub(crate) node_id: String,
    pub(crate) data_dir: String,
    pub(crate) volume_id: Uuid,
}

#[derive(Clone, Copy)]
struct ProcessStat { state: u8, group: i32, session: i32, start_ticks: u64 }

fn stat(pid: i32) -> Result<Option<ProcessStat>> {
    let raw = match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let tail = raw.rsplit_once(") ").context("invalid process stat")?.1;
    let fields: Vec<_> = tail.split_whitespace().collect();
    ensure!(fields.len() > 19, "incomplete process stat");
    Ok(Some(ProcessStat { state: fields[0].as_bytes()[0], group: fields[2].parse()?,
        session: fields[3].parse()?, start_ticks: fields[19].parse()? }))
}

fn boot_id() -> Result<String> { Ok(fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim().to_owned()) }

fn directory() -> Result<Option<PathBuf>> {
    let Some(value) = std::env::var_os("ROOTYARD_LOCAL_FENCE_DIR") else { return Ok(None); };
    let path = PathBuf::from(value);
    ensure!(path.is_absolute(), "local fence directory must be absolute");
    let meta = fs::symlink_metadata(&path)?;
    ensure!(meta.is_dir() && !meta.file_type().is_symlink() && meta.mode() & 0o777 == 0o700
        && meta.uid() == unsafe { libc::geteuid() }, "local fence directory must be owned by service UID and mode 0700");
    Ok(Some(path))
}

fn paths(dir: &Path, node_id: &str) -> Result<(PathBuf, PathBuf)> {
    ensure!(valid_node_id(node_id), "invalid local fence node id");
    Ok((dir.join(format!("{node_id}.process.json")), dir.join(format!("{node_id}.blocked"))))
}

fn volume_path(dir: &Path, node_id: &str) -> Result<PathBuf> {
    ensure!(valid_node_id(node_id), "invalid local fence node id");
    Ok(dir.join(format!("{node_id}.volume.json")))
}

fn read_volume_identity(data_dir: &Path) -> Result<Uuid> {
    let meta = fs::symlink_metadata(data_dir)?;
    ensure!(meta.is_dir() && !meta.file_type().is_symlink(), "registered volume is not a real directory");
    let bytes = fs::read_to_string(data_dir.join(".volume-id"))?;
    ensure!(bytes.len() == 36, "invalid registered volume identity");
    Ok(bytes.parse()?)
}

/// Publish the trusted node-to-volume binding. A promoter may only write a
/// retired marker after this binding and the old volume identity agree.
pub fn register_local_volume(node_id: &str, data_dir: &Path, volume_id: Uuid) -> Result<()> {
    let Some(dir) = directory()? else { return Ok(()); };
    ensure!(data_dir.is_absolute(), "registered data directory must be absolute");
    let canonical = data_dir.canonicalize().context("registered data directory missing")?;
    ensure!(read_volume_identity(&canonical)? == volume_id, "registered volume identity changed");
    let registration = VolumeRegistration {
        node_id: node_id.to_owned(),
        data_dir: canonical.to_str().context("non-UTF8 registered data directory")?.to_owned(),
        volume_id,
    };
    crate::journal::atomic(&volume_path(&dir, node_id)?, &serde_json::to_vec(&registration)?, true)?;
    Ok(())
}

pub fn registered_volume(node_id: &str) -> Result<Option<VolumeRegistration>> {
    let Some(dir) = directory()? else { return Ok(None); };
    let path = volume_path(&dir, node_id)?;
    if !crate::journal::exists(&path)? { return Ok(None); }
    let bytes = crate::journal::read(&path)?;
    let registration: VolumeRegistration = serde_json::from_slice(&bytes)?;
    ensure!(registration.node_id == node_id && registration.volume_id != Uuid::nil()
        && Path::new(&registration.data_dir).is_absolute(), "invalid local volume registration");
    Ok(Some(registration))
}

/// Resolve the registered, still-attached repository directory for a node.
/// A missing or changed volume identity is an error, never a reason to skip
/// physical fencing or promote from an unverified target.
pub fn registered_repository(node_id: &str, repository_id: Uuid) -> Result<(VolumeRegistration, PathBuf)> {
    let registration = registered_volume(node_id)?.context("old node volume registration is missing")?;
    let data_dir = PathBuf::from(&registration.data_dir);
    ensure!(read_volume_identity(&data_dir)? == registration.volume_id,
        "old node volume identity changed");
    let repo_dir = data_dir.join("repos").join(format!("{repository_id}.git"));
    let meta = fs::symlink_metadata(&repo_dir)?;
    ensure!(meta.is_dir() && !meta.file_type().is_symlink(), "old repository volume is unsafe");
    ensure!(repo_dir.canonicalize()?.parent() == Some(data_dir.canonicalize()?.join("repos").as_path()),
        "old repository escaped its registered volume");
    Ok((registration, repo_dir))
}

/// After the old process session is verifiably gone, write a retired read-only
/// marker directly on its still-attached volume. This is same-host fencing:
/// a detached or inaccessible source volume must block promotion instead.
pub fn retire_volume_repository(
    node_id: &str,
    repository_id: Uuid,
    marker: &VolumeFenceMarker,
) -> Result<VolumeRegistration> {
    ensure!(marker.repository_id == repository_id && marker.read_only_degraded,
        "retired source marker is not read-only for this repository");
    let (registration, repo_dir) = registered_repository(node_id, repository_id)?;
    crate::journal::atomic(
        &repo_dir.join(crate::sharding::models::VOLUME_FENCE_MARKER_FILE),
        &serde_json::to_vec_pretty(marker)?,
        true,
    )?;
    let observed = crate::sharding::fencing::read_volume_marker_at(&repo_dir)
        .map_err(|error| anyhow::anyhow!("retired source marker is unreadable: {}", error.1))?
        .context("retired source marker did not publish")?;
    ensure!(&observed == marker, "retired source marker verification failed");
    Ok(registration)
}

/// Called before accepting traffic; the service must run as its own session leader.
pub fn register_local_process(node_id: &str) -> Result<bool> {
    let Some(dir) = directory()? else { return Ok(false); };
    let (path, blocked) = paths(&dir, node_id)?;
    let lock = OpenOptions::new().read(true).write(true).create(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW).open(dir.join(format!("{node_id}.lock")))?;
    lock.try_lock_exclusive().context("node identity already has an active process")?;
    ensure!(!crate::journal::exists(&blocked)?, "node has a durable physical fence; operator recovery required");
    if crate::journal::exists(&path)? {
        let prior: ProcessIdentity = serde_json::from_slice(&crate::journal::read(&path)?)?;
        ensure!(prior.node_id == node_id, "foreign local process registry entry");
        if prior.boot_id == boot_id()?
            && let Some(active) = stat(prior.pid)?
            && active.start_ticks == prior.start_ticks
            && active.state != b'Z' && active.state != b'X' {
                bail!("node identity already has an active process");
            }
    }
    let pid = std::process::id() as i32;
    let self_stat = stat(pid)?.context("self process stat missing")?;
    ensure!(self_stat.group == pid && self_stat.session == pid,
        "local fence driver requires an isolated process session");
    let identity = ProcessIdentity { node_id: node_id.into(), pid, start_ticks: self_stat.start_ticks, boot_id: boot_id()? };
    crate::journal::atomic(&path, &serde_json::to_vec(&identity)?, true)?;
    ensure!(!crate::journal::exists(&blocked)?, "physical fence raced node startup");
    LOCAL_NODE_LOCK.set(lock).map_err(|_| anyhow::anyhow!("local node process registered twice"))?;
    Ok(true)
}

fn session_groups(session: i32) -> Result<Vec<i32>> {
    let mut groups = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else { continue; };
        if let Some(current) = stat(pid)?
            && current.session == session && current.state != b'Z' && current.state != b'X'
            && !groups.contains(&current.group) {
                groups.push(current.group);
            }
    }
    Ok(groups)
}

/// Persist a restart barrier, terminate the exact old process group, and verify no
/// member can run. A missing/reused PID or changed registry never proves fencing.
pub async fn fence_local_process(node_id: &str) -> Result<ProcessIdentity> {
    let dir = directory()?.context("local process fence driver is not configured")?;
    let (path, blocked) = paths(&dir, node_id)?;
    let original = crate::journal::read(&path)?;
    let identity: ProcessIdentity = serde_json::from_slice(&original)?;
    ensure!(identity.node_id == node_id && identity.pid > 1 && identity.pid != std::process::id() as i32
        && identity.boot_id == boot_id()?, "foreign or stale process identity");
    if crate::journal::exists(&blocked)? {
        ensure!(crate::journal::read(&blocked)? == original, "physical fence belongs to another process identity");
        if let Some(current) = stat(identity.pid)? {
            ensure!(current.start_ticks == identity.start_ticks, "process ID reused after physical fence");
        }
        ensure!(session_groups(identity.pid)?.is_empty(), "blocked source process session remains active");
        return Ok(identity);
    }
    let observed = stat(identity.pid)?.context("old process identity is absent; no kill proof")?;
    ensure!(observed.group == identity.pid && observed.session == identity.pid
        && observed.start_ticks == identity.start_ticks,
        "old process identity was reused or is not isolated");
    crate::journal::atomic(&blocked, &original, false)?;
    // Git backends create their own process groups, but stay in the server's
    // isolated session. Kill every group in that session, including admitted
    // receive-pack/hook descendants, before returning physical fence proof.
    for _ in 0..100 {
        ensure!(crate::journal::read(&path)? == original, "process identity changed during fencing");
        if let Some(current) = stat(identity.pid)? {
            ensure!(current.start_ticks == identity.start_ticks, "process ID reused during fencing");
        }
        let groups = session_groups(identity.pid)?;
        if groups.is_empty() {
            ensure!(crate::journal::read(&blocked)? == original, "physical fence changed during verification");
            return Ok(identity);
        }
        for group in groups {
            let result = unsafe { libc::kill(-group, libc::SIGKILL) };
            if result != 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::NotFound {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    bail!("old process session did not stop within physical fence deadline")
}
