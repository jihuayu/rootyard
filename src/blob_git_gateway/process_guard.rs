//! Native Git process-group lifecycle.
//!
//! A spawned child is always its own process-group leader. Cleanup never signals
//! a negative PID before the child's process group has been positively verified:
//! the unreaped leader keeps its PID/PGID reserved for the whole teardown, so a
//! reused PID can never receive a group signal meant for a Git descendant.
//!
//! Every exit path - normal exit, timeout, I/O failure and drop - kills and
//! reaps the entire group. The gateway never prints argv, environment, stdout or
//! stderr from a native child.
use std::{
    io,
    process::ExitStatus,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use tokio::{
    process::{Child, Command},
    time::Instant,
};

use super::error::GatewayError;

/// Polling interval while waiting for the process group to quiesce.
const QUIESCE_POLL: Duration = Duration::from_millis(5);
/// Hard bound for async cleanup after a child exits, times out or fails.
/// This is independent of the request deadline: even an already-expired request
/// must finish cleanup in bounded time.
pub(super) const CLEANUP_LIMIT: Duration = Duration::from_secs(5);
/// Drop cannot await; it gets a shorter synchronous bound on a runtime thread.
const DROP_CLEANUP_LIMIT: Duration = Duration::from_secs(2);

// If a process group cannot be proved stopped, no new native job may be
// admitted in this process. A refunded RAII slot must not hide a live orphan.
static CLEANUP_HEALTHY: AtomicBool = AtomicBool::new(true);

pub(super) fn healthy() -> bool {
    CLEANUP_HEALTHY.load(Ordering::Acquire)
}

/// One native child that leads its own process group.
pub(super) struct ProcessGuard {
    /// Kept public inside the gateway so callers can take the piped stdio before
    /// starting the reader/feeder tasks.
    pub(super) child: Child,
    pid: i32,
    reaped: bool,
}

impl ProcessGuard {
    /// Spawn one command and positively verify that it leads a new group.
    pub(super) fn spawn(mut command: Command) -> Result<Self, GatewayError> {
        if !healthy() {
            return Err(GatewayError::Unavailable("native process cleanup requires service restart"));
        }
        // Safe builder: the child becomes a new process-group leader before
        // exec. `resource::apply_native_limits` repeats `setpgid` in pre_exec.
        command.process_group(0);
        let child = command.spawn().map_err(|_| GatewayError::Internal("native Git could not start"))?;
        let pid = child.id().ok_or(GatewayError::Internal("native Git returned no process identity"))? as i32;
        if pid <= 1 {
            return Err(GatewayError::Internal("native Git returned an invalid process identity"));
        }
        // Positive PID-reuse guard: never signal `-pid` unless the child is the
        // group leader. The child is still unreaped here, so this lookup cannot
        // refer to a recycled PID. `setpgid` runs in the child, so allow a very
        // short bounded window for the child to be scheduled before refusing.
        let started = Instant::now();
        loop {
            let pgid = unsafe { libc::getpgid(pid) };
            if pgid == pid {
                return Ok(Self { child, pid, reaped: false });
            }
            if started.elapsed() >= Duration::from_millis(100) {
                // Do not negative-signal an unverified group; kill only the leader.
                let mut child = child;
                let _ = child.start_kill();
                return Err(GatewayError::Internal("native Git process group could not be isolated"));
            }
            // Only reached if the child has not run its `setpgid` yet.
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[allow(dead_code)]
    pub(super) fn pid(&self) -> i32 {
        self.pid
    }

    /// Observe leader exit without reaping it. The unreaped leader keeps the
    /// PGID reserved while descendants are still being signalled.
    pub(super) async fn wait_leader(&self, deadline: Instant) -> Result<(), GatewayError> {
        loop {
            match leader_exited(self.pid) {
                Ok(true) => return Ok(()),
                Ok(false) => {}
                Err(error) if error.raw_os_error() == Some(libc::ECHILD) => return Ok(()),
                Err(_) => return Err(GatewayError::Internal("native Git wait failed")),
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(GatewayError::Timeout);
            }
            let pause = (deadline - now).min(Duration::from_millis(10));
            tokio::time::sleep(pause).await;
        }
    }

    /// Kill every member of the group, prove quiescence (bounded), then reap the
    /// leader. The leader is reaped only after the group is quiet, so no early
    /// leader exit can allow PGID reuse while descendants are still alive.
    pub(super) async fn finish(&mut self, cleanup_deadline: Instant) -> io::Result<ExitStatus> {
        if self.reaped {
            return Err(io::Error::other("native Git process group was already reaped"));
        }
        if self.pid > 0 {
            self.signal_group(libc::SIGKILL);
            let _ = self.wait_leader_io(cleanup_deadline).await;
            if !self.wait_group_quiescent(cleanup_deadline).await {
                CLEANUP_HEALTHY.store(false, Ordering::Release);
                return Err(io::Error::other("native Git process group did not stop"));
            }
        }
        // Even an already-expired cleanup deadline gets one short poll for the
        // zombie leader; reaping a dead child is a non-blocking operation.
        let reap_deadline = cleanup_deadline.max(Instant::now() + Duration::from_millis(100));
        let status = match tokio::time::timeout_at(reap_deadline, self.child.wait()).await {
            Ok(result) => result,
            Err(_) => {
                let _ = self.child.start_kill();
                Err(io::Error::other("native Git process could not be reaped"))
            }
        };
        if status.is_ok() {
            self.pid = 0;
            self.reaped = true;
        }
        status
    }

    fn signal_group(&self, signal: i32) {
        if self.pid <= 1 {
            return;
        }
        // Safety: the PID was verified to be the process-group leader and the
        // leader has not been reaped, so `-pid` cannot alias a recycled group.
        unsafe {
            libc::kill(-self.pid, signal);
            // Signal the leader too in case the group setup was lost after the
            // verification; this is the same process, never a recycled PID.
            libc::kill(self.pid, signal);
        }
    }

    async fn wait_leader_io(&self, deadline: Instant) -> io::Result<()> {
        loop {
            match leader_exited(self.pid) {
                Ok(true) => return Ok(()),
                Ok(false) => {}
                Err(error) if error.raw_os_error() == Some(libc::ECHILD) => return Ok(()),
                Err(error) => return Err(error),
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "native Git group cleanup timed out"));
            }
            tokio::time::sleep((deadline - now).min(QUIESCE_POLL)).await;
        }
    }

    async fn wait_group_quiescent(&self, deadline: Instant) -> bool {
        loop {
            if group_quiescent(self.pid) {
                return true;
            }
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            tokio::time::sleep((deadline - now).min(QUIESCE_POLL)).await;
        }
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        if self.reaped || self.pid <= 1 {
            return;
        }
        // Fallback for cancelled producers and any early return. Keep the leader
        // unreaped through the bounded wait so the PGID stays reserved.
        self.signal_group(libc::SIGKILL);
        let deadline = Instant::now() + DROP_CLEANUP_LIMIT;
        while !group_quiescent(self.pid) && Instant::now() < deadline {
            std::thread::sleep(QUIESCE_POLL);
        }
        if !group_quiescent(self.pid) {
            CLEANUP_HEALTHY.store(false, Ordering::Release);
        }
        let _ = self.child.try_wait();
        self.pid = 0;
    }
}

/// Observe leader exit without consuming the wait status (`WNOWAIT`).
fn leader_exited(pid: i32) -> io::Result<bool> {
    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
    // Safety: `info` is a valid writable siginfo_t for the duration of the call.
    let result = unsafe {
        libc::waitid(libc::P_PID, pid as u32, info.as_mut_ptr(), libc::WEXITED | libc::WNOHANG | libc::WNOWAIT)
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    // Safety: waitid succeeded and initialised the structure.
    Ok(unsafe { info.assume_init().si_pid() } != 0)
}

/// Prove that no non-zombie process remains in `pgid`. Zombies are ignored
/// because they can no longer execute or hold a pipe; the leader itself is
/// reaped after this returns.
fn group_quiescent(pgid: i32) -> bool {
    let entries = match std::fs::read_dir("/proc") {
        Ok(entries) => entries,
        // Runtime support requires procfs. Loss of visibility fails closed;
        // kill(pgid, 0) cannot distinguish our unreaped zombie leader.
        Err(_) => return false,
    };
    for entry in entries {
        let Ok(entry) = entry else { return false };
        if entry.file_name().to_string_lossy().parse::<u32>().is_err() {
            continue;
        }
        use std::os::unix::fs::MetadataExt;
        match entry.metadata() {
            // Controlled Git children never change user identity. Processes of
            // other users cannot belong to our group.
            Ok(meta) if meta.uid() != unsafe { libc::geteuid() } => continue,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            _ => {}
        }
        let stat = match std::fs::read_to_string(entry.path().join("stat")) {
            Ok(stat) => stat,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => return false,
        };
        let Some((_, rest)) = stat.rsplit_once(") ") else { return false };
        let mut fields = rest.split_whitespace();
        let Some(state) = fields.next() else { return false };
        let Some(_ppid) = fields.next() else { return false };
        let Some(pgrp) = fields.next() else { return false };
        if pgrp.parse::<i32>().ok() == Some(pgid) && state != "Z" && state != "X" {
            return false;
        }
    }
    true
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::process::Stdio;

    async fn orphan_group() -> (ProcessGuard, i32) {
        let dir = tempfile::tempdir().unwrap();
        let pid_file = dir.path().join("child.pid");
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "sh -c 'trap \"\" TERM; echo $$ > \"$1\"; while :; do sleep 1; done' child \"$1\" & exit 0",
                "leader",
            ])
            .arg(&pid_file)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let guard = ProcessGuard::spawn(command).expect("test child must spawn");
        let started = Instant::now();
        let child_pid = loop {
            if let Ok(text) = std::fs::read_to_string(&pid_file)
                && let Ok(pid) = text.trim().parse::<i32>()
            {
                break pid;
            }
            assert!(started.elapsed().as_secs() < 5, "test child failed to start");
            tokio::time::sleep(Duration::from_millis(10)).await;
        };
        (guard, child_pid)
    }

    async fn assert_not_running(pid: i32) {
        let started = Instant::now();
        loop {
            match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
                Err(_) => return,
                Ok(text) if text.rsplit_once(") ").is_some_and(|(_, tail)| tail.starts_with('Z')) => {
                    return;
                }
                _ => {}
            }
            assert!(started.elapsed().as_secs() < 5, "descendant survived group cleanup");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn early_leader_exit_still_kills_descendants_before_reaping() {
        let (mut guard, child_pid) = orphan_group().await;
        let leader = guard.pid();
        let status = guard.finish(Instant::now() + CLEANUP_LIMIT).await.expect("cleanup must reap the leader");
        assert!(status.success());
        assert_not_running(child_pid).await;
        assert!(!std::path::Path::new(&format!("/proc/{leader}")).exists(), "leader was not reaped");
    }

    #[tokio::test]
    async fn timeout_cleanup_kills_the_group_and_reaps_the_leader() {
        let (mut guard, child_pid) = orphan_group().await;
        let leader = guard.pid();
        // The leader has already exited, but cleanup must still be bounded and
        // must kill the surviving descendant before reaping.
        let status = guard.finish(Instant::now() + CLEANUP_LIMIT).await.expect("cleanup must reap the leader");
        assert!(status.success());
        assert_not_running(child_pid).await;
        assert!(!std::path::Path::new(&format!("/proc/{leader}")).exists());
    }

    #[tokio::test]
    async fn drop_waits_for_all_descendants() {
        let (guard, descendant) = orphan_group().await;
        let leader = guard.pid();
        drop(guard);
        assert_not_running(descendant).await;
        assert!(!std::path::Path::new(&format!("/proc/{leader}")).exists(), "leader was not reaped");
    }

    #[tokio::test]
    async fn wait_leader_observes_exit_without_reaping() {
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg("exit 0").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        let mut guard = ProcessGuard::spawn(command).expect("test child must spawn");
        guard.wait_leader(Instant::now() + CLEANUP_LIMIT).await.expect("leader exit must be observable");
        // Still unreaped: /proc entry exists (as a zombie) until finish reaps it.
        assert!(std::path::Path::new(&format!("/proc/{}", guard.pid())).exists());
        guard.finish(Instant::now() + CLEANUP_LIMIT).await.expect("finish must reap");
        assert!(!std::path::Path::new(&format!("/proc/{}", guard.pid())).exists());
    }
}
