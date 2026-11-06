//! Git subprocess group lifecycle and bounded maintenance output.
use super::*;

pub(super) struct Process {
    pub(super) child: Child,
    pub(super) input: Option<JoinHandle<io::Result<()>>>,
    pub(super) stderr: JoinHandle<()>,
    pub(super) pid: i32,
}
impl Process {
    pub(super) async fn finish(&mut self) -> io::Result<std::process::ExitStatus> {
        // Observe leader exit without reaping it: the unreaped PID reserves the
        // process-group ID while we clean any surviving descendants. Tokio's
        // Child::wait would reap too early for a safe group signal afterwards.
        loop {
            let exited = {
                let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
                let result = unsafe {
                    libc::waitid(
                        libc::P_PID,
                        self.pid as u32,
                        info.as_mut_ptr(),
                        libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                    )
                };
                if result != 0 {
                    return Err(io::Error::last_os_error());
                }
                unsafe { info.assume_init().si_pid() != 0 }
            };
            if exited {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        unsafe {
            libc::kill(-self.pid, libc::SIGKILL);
        }
        self.wait_group_quiescent().await;
        let status = self.child.wait().await?;
        self.pid = 0;
        Ok(status)
    }
    async fn wait_group_quiescent(&self) {
        // Keep leader unreaped, reserving PGID, until every member is dead or
        // zombie. SIGKILL delivery alone is not proof a descendant stopped.
        let started = Instant::now();
        let mut reported = false;
        while !matches!(group_quiescent(self.pid), Ok(true)) {
            if !reported && started.elapsed() > std::time::Duration::from_secs(5) {
                eprintln!(
                    "rootyard: process group cleanup blocked; retaining write lock and capacity"
                );
                reported = true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
    pub(super) async fn stop(&mut self) {
        if let Some(input) = &self.input {
            input.abort();
        }
        if self.pid <= 0 {
            return;
        }
        // Keep the leader unreaped for the entire grace period. Otherwise an
        // early leader exit could permit PGID reuse while descendants remain.
        unsafe {
            libc::kill(-self.pid, libc::SIGTERM);
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        unsafe {
            libc::kill(-self.pid, libc::SIGKILL);
        }
        self.wait_group_quiescent().await;
        let _ = self.child.wait().await;
        self.pid = 0;
    }
}
fn group_quiescent(group: i32) -> io::Result<bool> {
    for entry in std::fs::read_dir("/proc")? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
            continue;
        }
        // Controlled Git children never change user identity. A restricted
        // /proc may deny other users' processes; they cannot belong to our group.
        use std::os::unix::fs::MetadataExt;
        match entry.metadata() {
            Ok(meta) if meta.uid() != unsafe { libc::geteuid() } => continue,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
            _ => {}
        }
        let stat = match std::fs::read_to_string(entry.path().join("stat")) {
            Ok(stat) => stat,
            Err(error)
                if error.kind() == io::ErrorKind::NotFound
                    || error.raw_os_error() == Some(libc::ESRCH) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        let Some((_, rest)) = stat.rsplit_once(") ") else {
            return Err(io::Error::other("invalid proc stat"));
        };
        let fields: Vec<_> = rest.split_whitespace().collect();
        if fields.len() < 3 {
            return Err(io::Error::other("invalid proc stat"));
        }
        if fields[2].parse::<i32>().ok() == Some(group) && fields[0] != "Z" && fields[0] != "X" {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Reap a native Git leader only after every member of its process group is
/// dead. The unreaped leader reserves the PGID and prevents signaling reuse.
pub(crate) async fn finish_group_child(child: &mut Child) -> io::Result<std::process::ExitStatus> {
    let pid = child.id().ok_or_else(|| io::Error::other("missing Git PID"))? as i32;
    loop {
        let exited = {
            let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
            let rc = unsafe { libc::waitid(libc::P_PID, pid as u32, info.as_mut_ptr(),
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT) };
            if rc != 0 { return Err(io::Error::last_os_error()); }
            unsafe { info.assume_init().si_pid() != 0 }
        };
        if exited { break; }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    unsafe { libc::kill(-pid, libc::SIGKILL); }
    wait_group_child_quiescent(pid).await;
    child.wait().await
}

/// Cancellation and timeout path for a Git leader and all descendants.
pub(crate) async fn stop_group_child(child: &mut Child) -> io::Result<()> {
    let pid = child.id().ok_or_else(|| io::Error::other("missing Git PID"))? as i32;
    unsafe { libc::kill(-pid, libc::SIGTERM); }
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    unsafe { libc::kill(-pid, libc::SIGKILL); }
    wait_group_child_quiescent(pid).await;
    let _ = child.wait().await?;
    Ok(())
}

async fn wait_group_child_quiescent(pid: i32) {
    let started = Instant::now();
    let mut reported = false;
    while !matches!(group_quiescent(pid), Ok(true)) {
        if !reported && started.elapsed() > std::time::Duration::from_secs(5) {
            eprintln!("rootyard: process group cleanup blocked; retaining maintenance guard");
            reported = true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        // The process group covers http-backend, receive/upload-pack and their workers.
        // kill_on_drop only covers the immediate child, which is insufficient here.
        if self.pid > 0 {
            unsafe {
                libc::kill(-self.pid, libc::SIGKILL);
            }
        }
        let _ = self.child.start_kill();
        if let Some(input) = &self.input {
            input.abort();
        }
        self.stderr.abort();
    }
}

/// Bounded read-only maintenance command using the same process-group cleanup.
pub(crate) async fn collect_git_output(
    command: tokio::process::Command,
    limit: usize,
    timeout: std::time::Duration,
) -> anyhow::Result<Vec<u8>> {
    collect_git_output_input(command, limit, timeout, Stdio::null()).await
}

pub(crate) async fn collect_git_output_input(
    mut command: tokio::process::Command,
    limit: usize,
    timeout: std::time::Duration,
    input: Stdio,
) -> anyhow::Result<Vec<u8>> {
    command
        .stdin(input)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == -1 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    let pid = child
        .id()
        .ok_or_else(|| io::Error::other("missing Git PID"))? as i32;
    let mut stdout = child.stdout.take().expect("piped stdout");
    let mut stderr = child.stderr.take().expect("piped stderr");
    let drain = tokio::spawn(async move {
        let mut bytes = [0u8; 4096];
        while matches!(stderr.read(&mut bytes).await,Ok(n) if n>0) {}
    });
    let mut process = Process {
        child,
        input: None,
        stderr: drain,
        pid,
    };
    let mut output = Vec::new();
    let result = tokio::time::timeout(timeout, async {
        (&mut stdout)
            .take(limit as u64 + 1)
            .read_to_end(&mut output)
            .await?;
        if output.len() > limit {
            return Err(io::Error::other("maintenance output exceeds limit"));
        }
        if !process.finish().await?.success() {
            return Err(io::Error::other("read-only Git command failed"));
        }
        Ok::<(), io::Error>(())
    })
    .await;
    process.stop().await;
    result.map_err(|_| io::Error::other("maintenance Git command timed out"))??;
    Ok(output)
}

#[cfg(test)]
mod process_tests {
    use super::*;

    async fn orphan_group() -> (Process, i32) {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("child.pid");
        let mut cmd = tokio::process::Command::new("/bin/sh");
        cmd.args(["-c", "sh -c 'trap \"\" TERM; echo $$ > \"$1\"; while :; do sleep 1; done' child \"$1\" & exit 0", "leader"])
            .arg(&pid_file).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        unsafe {
            cmd.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd.spawn().unwrap();
        let pid = child.id().unwrap() as i32;
        let process = Process {
            child,
            input: None,
            stderr: tokio::spawn(async {}),
            pid,
        };
        let started = Instant::now();
        let child_pid = loop {
            if let Ok(text) = std::fs::read_to_string(&pid_file) {
                if let Ok(pid) = text.trim().parse::<i32>() {
                    break pid;
                }
            }
            assert!(
                started.elapsed().as_secs() < 5,
                "test child failed to start"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        };
        (process, child_pid)
    }
    async fn assert_not_running(pid: i32) {
        let started = Instant::now();
        loop {
            match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
                Err(_) => return,
                Ok(text)
                    if text
                        .rsplit_once(") ")
                        .is_some_and(|(_, tail)| tail.starts_with('Z')) =>
                {
                    return;
                }
                _ => {}
            }
            assert!(
                started.elapsed().as_secs() < 5,
                "descendant survived group cleanup"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
    #[tokio::test]
    async fn successful_leader_does_not_leave_descendants() {
        let (mut process, child_pid) = orphan_group().await;
        let leader = process.pid;
        assert!(process.finish().await.unwrap().success());
        assert_not_running(child_pid).await;
        assert!(
            !std::path::Path::new(&format!("/proc/{leader}")).exists(),
            "leader was not reaped"
        );
    }
    #[tokio::test]
    async fn timeout_cleans_term_ignoring_descendants_before_reaping() {
        let (mut process, child_pid) = orphan_group().await;
        let leader = process.pid;
        process.stop().await;
        assert_not_running(child_pid).await;
        assert!(
            !std::path::Path::new(&format!("/proc/{leader}")).exists(),
            "leader was not reaped"
        );
    }
    #[tokio::test]
    async fn maintenance_helpers_wait_for_descendant_quiescence() {
        let (mut finished, finished_child) = orphan_group().await;
        let leader = finished.pid;
        assert!(finish_group_child(&mut finished.child).await.unwrap().success());
        finished.pid = 0;
        assert_not_running(finished_child).await;
        assert!(!std::path::Path::new(&format!("/proc/{leader}")).exists());

        let (mut cancelled, cancelled_child) = orphan_group().await;
        let leader = cancelled.pid;
        stop_group_child(&mut cancelled.child).await.unwrap();
        cancelled.pid = 0;
        assert_not_running(cancelled_child).await;
        assert!(!std::path::Path::new(&format!("/proc/{leader}")).exists());
    }
}
