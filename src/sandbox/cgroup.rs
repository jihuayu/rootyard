//! Delegated cgroup v2 accounting for sandbox jobs.
//!
//! A job cgroup is created before the sandbox starts, the Bubblewrap process
//! tree is attached while user code is still behind the start gate, and the
//! cgroup is destroyed after the job reaches a terminal state. Missing
//! controllers or denied writes fail closed; there is no implicit fallback to
//! development-mode resource limits.
use crate::Error;
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};
use uuid::Uuid;

pub(super) const MEMORY_DEFAULT: u64 = 512 * 1024 * 1024;
pub(super) const PIDS_DEFAULT: u64 = 64;
pub(super) const WORKSPACE_DEFAULT: u64 = 256 * 1024 * 1024;
pub(super) const TMP_DEFAULT: u64 = 64 * 1024 * 1024;
pub(super) const ARTIFACTS_DEFAULT: u64 = 64 * 1024 * 1024;
pub(super) const ENTRIES_DEFAULT: u64 = 20_000;
pub(super) const CPU_DEFAULT: &str = "50000 100000";

/// Bounded job resources. Values are deployment-tunable but always enforced by
/// the cgroup controls (or, for disk, by the private tmpfs and export walker).
#[derive(Clone, Debug)]
pub(super) struct Limits {
    pub memory_max: u64,
    pub pids_max: u64,
    pub cpu_max: String,
    pub workspace_bytes: u64,
    pub tmp_bytes: u64,
    pub artifacts_bytes: u64,
    pub max_entries: u64,
}

fn env_number(name: &str, default: u64, min: u64, max: u64) -> Result<u64, Error> {
    let Ok(raw) = std::env::var(name) else { return Ok(default) };
    let value = raw.parse::<u64>().map_err(|_| Error::internal("invalid sandbox resource limit"))?;
    if !(min..=max).contains(&value) {
        return Err(Error::internal("sandbox resource limit out of range"));
    }
    Ok(value)
}

fn env_cpu() -> Result<String, Error> {
    let raw = std::env::var("ROOTYARD_SANDBOX_CPU_MAX").unwrap_or_else(|_| CPU_DEFAULT.to_owned());
    let mut parts = raw.split_whitespace();
    let (Some(quota), Some(period), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(Error::internal("invalid sandbox cpu limit"));
    };
    let quota = quota.parse::<u64>().map_err(|_| Error::internal("invalid sandbox cpu limit"))?;
    let period = period.parse::<u64>().map_err(|_| Error::internal("invalid sandbox cpu limit"))?;
    if quota == 0 || !(1_000..=1_000_000).contains(&period) || quota > period {
        return Err(Error::internal("invalid sandbox cpu limit"));
    }
    Ok(format!("{quota} {period}"))
}

impl Limits {
    pub(super) fn from_env() -> Result<Self, Error> {
        Ok(Self {
            memory_max: env_number("ROOTYARD_SANDBOX_MEMORY_MAX", MEMORY_DEFAULT, 16 * 1024 * 1024, 1 << 40)?,
            pids_max: env_number("ROOTYARD_SANDBOX_PIDS_MAX", PIDS_DEFAULT, 2, 4096)?,
            cpu_max: env_cpu()?,
            workspace_bytes: env_number(
                "ROOTYARD_SANDBOX_WORKSPACE_MAX_BYTES",
                WORKSPACE_DEFAULT,
                1024 * 1024,
                64 << 30,
            )?,
            tmp_bytes: env_number("ROOTYARD_SANDBOX_TMP_MAX_BYTES", TMP_DEFAULT, 1024 * 1024, 16 << 30)?,
            artifacts_bytes: env_number("ROOTYARD_SANDBOX_ARTIFACTS_MAX_BYTES", ARTIFACTS_DEFAULT, 4096, 16 << 30)?,
            max_entries: env_number("ROOTYARD_SANDBOX_MAX_ENTRIES", ENTRIES_DEFAULT, 16, 1_000_000)?,
        })
    }
}

/// The operator-delegated cgroup v2 subtree. Only this subtree is ever written;
/// the host root hierarchy is never modified.
pub(super) fn delegated_root() -> Result<PathBuf, Error> {
    let base = PathBuf::from(
        std::env::var("ROOTYARD_SANDBOX_CGROUP_ROOT").map_err(|_| Error::internal("delegated cgroup root required"))?,
    );
    if !base.starts_with("/sys/fs/cgroup/") || base == Path::new("/sys/fs/cgroup/") {
        return Err(Error::internal("delegated cgroup v2 root required"));
    }
    for name in ["cgroup.controllers", "cgroup.procs", "cgroup.subtree_control"] {
        if !base.join(name).is_file() {
            return Err(Error::internal("delegated cgroup v2 root required"));
        }
    }
    let controllers = fs::read_to_string(base.join("cgroup.controllers")).map_err(Error::internal)?;
    for required in ["cpu", "memory", "pids"] {
        if !controllers.split_whitespace().any(|item| item == required) {
            return Err(Error::internal("delegated cgroup is missing a required controller"));
        }
    }
    Ok(base)
}

fn write_limits(group: &Path, limits: &Limits) -> std::io::Result<()> {
    for (name, value) in [
        ("memory.max", limits.memory_max.to_string()),
        ("memory.swap.max", "0".to_owned()),
        ("pids.max", limits.pids_max.to_string()),
        ("cpu.max", limits.cpu_max.clone()),
    ] {
        fs::write(group.join(name), value)?;
    }
    Ok(())
}

/// Create and constrain one job cgroup. Any short write removes the partial
/// group so a failed launch cannot leave an unbounded execution context.
pub(super) fn create(base: &Path, job: Uuid, limits: &Limits) -> Result<PathBuf, Error> {
    let group = base.join(job.to_string());
    fs::create_dir(&group).map_err(Error::internal)?;
    if let Err(error) = write_limits(&group, limits) {
        let _ = fs::remove_dir(&group);
        return Err(Error::internal(error));
    }
    Ok(group)
}

fn process_parents() -> std::io::Result<HashMap<i32, i32>> {
    let mut parents = HashMap::new();
    for entry in fs::read_dir("/proc")? {
        let Ok(entry) = entry else { continue };
        let Ok(pid) = entry.file_name().to_string_lossy().parse::<i32>() else { continue };
        let Ok(stat) = fs::read_to_string(entry.path().join("stat")) else { continue };
        let Some((_, rest)) = stat.rsplit_once(") ") else { continue };
        let fields: Vec<&str> = rest.split_whitespace().collect();
        if let Some(ppid) = fields.get(1).and_then(|value| value.parse::<i32>().ok()) {
            parents.insert(pid, ppid);
        }
    }
    Ok(parents)
}

fn write_procs(group: &Path, pids: impl IntoIterator<Item = i32>) -> std::io::Result<()> {
    for pid in pids {
        fs::write(group.join("cgroup.procs"), pid.to_string())?;
    }
    Ok(())
}

/// Attach the Bubblewrap leader and every descendant while the start gate is
/// still closed. Descendants fork after the gate opens inherit the parent's
/// membership, so a stable scan is sufficient. Repeats until no new process
/// appears so a fork racing with the first scan is not missed.
pub(super) fn attach(group: &Path, leader: i32) -> Result<usize, Error> {
    let mut attached = HashSet::new();
    let mut stable = 0;
    for _ in 0..100 {
        let parents = process_parents().map_err(Error::internal)?;
        let mut children: HashMap<i32, Vec<i32>> = HashMap::new();
        for (pid, ppid) in &parents {
            children.entry(*ppid).or_default().push(*pid);
        }
        let mut found = Vec::new();
        let mut frontier = vec![leader];
        while let Some(pid) = frontier.pop() {
            found.push(pid);
            if let Some(next) = children.get(&pid) {
                frontier.extend(next.iter().copied());
            }
        }
        let fresh: Vec<i32> = found.into_iter().filter(|pid| attached.insert(*pid)).collect();
        let progressed = !fresh.is_empty();
        if progressed {
            write_procs(group, fresh).map_err(Error::internal)?;
        }
        // Require two consecutive complete scans and a non-empty cgroup before
        // opening the gate.
        if attached.contains(&leader) && stable >= 2 {
            if group_pids(group) == 0 {
                return Err(Error::internal("sandbox cgroup attachment is empty"));
            }
            return Ok(attached.len());
        }
        stable = if progressed { 0 } else { stable + 1 };
        std::thread::sleep(Duration::from_millis(10));
    }
    Err(Error::internal("sandbox cgroup attachment did not converge"))
}

fn group_pids(group: &Path) -> usize {
    fs::read_to_string(group.join("cgroup.procs")).map(|contents| contents.split_whitespace().count()).unwrap_or(0)
}

/// Idempotently kill and remove a job cgroup. `cgroup.kill` only signals
/// processes in this subtree and never touches unrelated host cgroups. Failure
/// to prove the cgroup empty and removed is returned so callers cannot report a
/// completed cleanup while processes remain charged to the job.
pub(super) async fn destroy(group: &Path) -> Result<(), Error> {
    destroy_with_timeout(group, Duration::from_secs(10)).await
}

async fn destroy_with_timeout(group: &Path, timeout: Duration) -> Result<(), Error> {
    if !group.exists() {
        return Ok(());
    }
    if let Err(error) = fs::write(group.join("cgroup.kill"), "1") {
        // A missing cgroup that disappeared concurrently is already reclaimed.
        if !group.exists() {
            return Ok(());
        }
        return Err(Error::internal(error));
    }
    let deadline = Instant::now() + timeout;
    loop {
        if group_pids(group) == 0 && fs::remove_dir(group).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(Error::internal("sandbox cgroup did not become empty"));
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Cgroups whose destruction could not be proven. New launches fail closed
/// until these are reclaimed; the list is process-local and rebuilt from the
/// delegated subtree by startup recovery after a restart.
static PENDING: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// Destroy a terminal job cgroup, retaining a failed cleanup so the next launch
/// retries it instead of admitting work while resources remain charged.
pub(super) async fn retire(group: &Path) {
    if destroy(group).await.is_err() {
        eprintln!("rootyard: sandbox cgroup cleanup incomplete; new launches blocked until reclaimed");
        PENDING.lock().expect("cgroup pending queue").push(group.to_path_buf());
    }
}

/// Retry every retained cleanup and fail closed if any cgroup still cannot be
/// proven empty and removed.
pub(super) async fn ensure_clean() -> Result<(), Error> {
    let pending = PENDING.lock().expect("cgroup pending queue").clone();
    for group in pending {
        destroy(&group).await?;
        PENDING.lock().expect("cgroup pending queue").retain(|item| item != &group);
    }
    Ok(())
}

/// Remove job cgroups that do not belong to a live job. The base is our
/// delegated subtree and every child is named after a job UUID. Every stale
/// group must be proven empty and removed; the first failure is returned.
pub(super) async fn reap_stale(base: &Path, live: &HashSet<Uuid>) -> Result<(), Error> {
    let entries = fs::read_dir(base).map_err(Error::internal)?;
    let mut failure = None;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Ok(id) = name.to_string_lossy().parse::<Uuid>() else { continue };
        if !live.contains(&id) {
            if let Err(error) = destroy(&entry.path()).await {
                failure.get_or_insert(error);
            }
        }
    }
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_are_written_and_missing_controller_fails() {
        let root = std::env::temp_dir().join(format!("rootyard-cgroup-test-{}", Uuid::new_v4()));
        let group = root.join(Uuid::new_v4().to_string());
        fs::create_dir_all(&group).unwrap();
        let limits = Limits {
            memory_max: 64 * 1024 * 1024,
            pids_max: 8,
            cpu_max: "25000 100000".to_owned(),
            workspace_bytes: 16 * 1024 * 1024,
            tmp_bytes: 8 * 1024 * 1024,
            artifacts_bytes: 4096,
            max_entries: 32,
        };
        // A control-file name occupied by a directory cannot be written: this
        // must fail, not silently run the job without limits.
        fs::create_dir(group.join("memory.max")).unwrap();
        assert!(write_limits(&group, &limits).is_err());
        fs::remove_dir(group.join("memory.max")).unwrap();
        for name in ["memory.max", "memory.swap.max", "pids.max", "cpu.max"] {
            fs::write(group.join(name), "").unwrap();
        }
        write_limits(&group, &limits).unwrap();
        assert_eq!(fs::read_to_string(group.join("memory.max")).unwrap(), "67108864");
        assert_eq!(fs::read_to_string(group.join("memory.swap.max")).unwrap(), "0");
        assert_eq!(fs::read_to_string(group.join("pids.max")).unwrap(), "8");
        assert_eq!(fs::read_to_string(group.join("cpu.max")).unwrap(), "25000 100000");
        fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn destroy_reports_unreclaimable_group() {
        let root = std::env::temp_dir().join(format!("rootyard-cgroup-destroy-{}", Uuid::new_v4()));
        let group = root.join("job");
        fs::create_dir_all(&group).unwrap();
        // A plain directory that keeps reporting a process can never be
        // proven empty; cleanup must fail instead of silently returning.
        fs::write(group.join("cgroup.procs"), "1\n").unwrap();
        assert!(destroy_with_timeout(&group, Duration::from_millis(60)).await.is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cpu_limit_rejects_unbounded_or_malformed_values() {
        // SAFETY: the test process is single-threaded for this environment key.
        unsafe { std::env::set_var("ROOTYARD_SANDBOX_CPU_MAX", "max") };
        assert!(env_cpu().is_err());
        // SAFETY: as above; restored before the test returns.
        unsafe { std::env::set_var("ROOTYARD_SANDBOX_CPU_MAX", "200000 100000") };
        assert!(env_cpu().is_err());
        // SAFETY: as above.
        unsafe { std::env::set_var("ROOTYARD_SANDBOX_CPU_MAX", "50000 100000") };
        assert_eq!(env_cpu().unwrap(), "50000 100000");
        // SAFETY: remove the test override.
        unsafe { std::env::remove_var("ROOTYARD_SANDBOX_CPU_MAX") };
    }
}
