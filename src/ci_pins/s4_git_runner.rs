//! Bounded, isolated child Git processes for S4 CI transport.
use super::*;
use crate::git_http::{finish_group_child, group_quiescent, kill_group_child};
use std::{path::Path as FsPath, process::{ExitStatus, Stdio}, time::Duration};
use tokio::{
    io::AsyncReadExt,
    process::{Child, ChildStdin, ChildStdout, Command},
    time::Instant,
};

const GROUP_CLEANUP: Duration = Duration::from_secs(2);
const DROP_GROUP_BUDGET: Duration = Duration::from_millis(500);
const GIT_DIR_CAP: usize = 64 * 1024 * 1024;

/// One refcounted scratch owner that must outlive a child process group.
pub(crate) type ScratchHold = std::sync::Arc<dyn std::any::Any + Send + Sync>;
/// One isolated `git upload-pack` (or bounded disposable-repo command) child.
pub(crate) struct UploadPackGroup {
    child: Option<Child>,
    pid: i32,
    scratch_hold: Option<ScratchHold>,
}
impl UploadPackGroup {
    pub(crate) fn spawn(git_bin: &FsPath, dir: &FsPath, scratch_hold: Option<ScratchHold>) -> Result<Self, Error> {
        Self::spawn_argv(git_bin, Some(dir), &["upload-pack", "--stateless-rpc"], Stdio::piped(), scratch_hold)
    }

    fn spawn_argv(
        git_bin: &FsPath,
        dir: Option<&FsPath>,
        args: &[&str],
        stdin: Stdio,
        scratch_hold: Option<ScratchHold>,
    ) -> Result<Self, Error> {
        let mut cmd = Command::new(git_bin);
        cmd.args(["-c", "core.hooksPath=/dev/null"]);
        if let Some(dir) = dir {
            cmd.arg("--git-dir").arg(dir);
        }
        cmd.args(args)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env_remove("GIT_PROTOCOL")
            .stdin(stdin)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        #[cfg(unix)]
        cmd.process_group(0);
        let mut child = cmd.spawn().map_err(Error::internal)?;
        let pid = child.id().and_then(|id| i32::try_from(id).ok()).unwrap_or(0);
        #[cfg(unix)]
        if pid > 1 {
            let until = Instant::now() + Duration::from_millis(100);
            loop {
                let group = unsafe { libc::getpgid(pid) };
                if group == pid || group < 0 {
                    break;
                }
                if Instant::now() >= until {
                    let _ = child.start_kill();
                    let _ = child.try_wait();
                    return Err(Error::internal("Git process group isolation timed out"));
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        Ok(Self { child: Some(child), pid, scratch_hold })
    }

    pub(crate) fn take_pipes(&mut self) -> Result<(ChildStdin, ChildStdout), Error> {
        let stdin = self.child.as_mut().and_then(|child| child.stdin.take());
        let stdout = self.child.as_mut().and_then(|child| child.stdout.take());
        match (stdin, stdout) {
            (Some(stdin), Some(stdout)) => Ok((stdin, stdout)),
            _ => Err(Error::internal("missing Git pipes")),
        }
    }

    fn take_stdout(&mut self) -> Result<ChildStdout, Error> {
        self.child.as_mut().and_then(|child| child.stdout.take()).ok_or_else(|| Error::internal("missing Git stdout"))
    }

    pub(crate) async fn finish(&mut self) -> Result<ExitStatus, Error> {
        let Some(child) = self.child.as_mut() else {
            return Err(Error::internal("Git child already taken"));
        };
        #[cfg(unix)]
        let outcome = finish_group_child(child).await;
        #[cfg(not(unix))]
        let outcome = child.wait().await;
        match outcome {
            Ok(status) => {
                self.child = None;
                self.pid = 0;
                self.scratch_hold = None;
                Ok(status)
            }
            Err(error) => {
                self.kill_and_reap().await;
                Err(Error::internal(error))
            }
        }
    }

    pub(crate) async fn kill_and_reap(&mut self) {
        let pid = self.pid;
        let Some(child) = self.child.as_mut() else { return };
        #[cfg(unix)]
        if pid > 1 {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
            let _ = kill_group_child(child).await;
        }
        #[cfg(not(unix))]
        {
            let _ = child.kill().await;
            let _ = child.wait().await;
        }
        self.child = None;
        self.pid = 0;
        self.scratch_hold = None;
    }
}
impl Drop for UploadPackGroup {
    fn drop(&mut self) {
        if self.child.is_none() {
            self.scratch_hold = None;
            return;
        }
        let Some(mut child) = self.child.take() else {
            self.scratch_hold = None;
            return;
        };
        let pid = std::mem::replace(&mut self.pid, 0);
        #[cfg(unix)]
        if pid > 1 {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
                libc::kill(pid, libc::SIGKILL);
            }
        }
        let _ = child.start_kill();
        let mut reaped = matches!(child.try_wait(), Ok(Some(_)) | Err(_));
        #[cfg(unix)]
        {
            let started = std::time::Instant::now();
            while started.elapsed() < DROP_GROUP_BUDGET {
                if !reaped {
                    reaped = matches!(child.try_wait(), Ok(Some(_)) | Err(_));
                }
                let quiet = pid <= 1 || matches!(group_quiescent(pid), Ok(true) | Err(_));
                if reaped && quiet {
                    break;
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        let reaped = reaped || matches!(child.try_wait(), Ok(Some(_)) | Err(_));
        #[cfg(unix)]
        let quiet = pid <= 1 || matches!(group_quiescent(pid), Ok(true) | Err(_));
        #[cfg(not(unix))]
        let quiet = true;
        if reaped && quiet {
            self.scratch_hold = None;
            return;
        }
        let hold = self.scratch_hold.take();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                #[cfg(unix)]
                if pid > 1 {
                    let until = Instant::now() + GROUP_CLEANUP;
                    while Instant::now() < until && matches!(group_quiescent(pid), Ok(false)) {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                }
                let _ = tokio::time::timeout(GROUP_CLEANUP, child.wait()).await;
                drop(hold);
            });
        } else {
            std::thread::spawn(move || {
                let started = std::time::Instant::now();
                while started.elapsed() < GROUP_CLEANUP {
                    let done = matches!(child.try_wait(), Ok(Some(_)) | Err(_));
                    #[cfg(unix)]
                    let quiet = pid <= 1 || matches!(group_quiescent(pid), Ok(true) | Err(_));
                    #[cfg(not(unix))]
                    let quiet = true;
                    if done && quiet {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                drop(hold);
            });
        }
    }
}
pub(crate) async fn run_git_dir_bounded(
    git_bin: &FsPath,
    dir: Option<&FsPath>,
    args: &[&str],
    deadline: Instant,
    fail_error: Error,
    scratch_hold: Option<ScratchHold>,
) -> Result<Vec<u8>, Error> {
    if Instant::now() >= deadline {
        return Err(Error::timeout());
    }
    let mut guard = UploadPackGroup::spawn_argv(git_bin, dir, args, Stdio::null(), scratch_hold)?;
    let mut stdout = guard.take_stdout()?;
    let mut output = Vec::new();
    let read =
        tokio::time::timeout_at(deadline, (&mut stdout).take(GIT_DIR_CAP as u64 + 1).read_to_end(&mut output)).await;
    drop(stdout);
    match read {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => {
            guard.kill_and_reap().await;
            return Err(Error::internal(error));
        }
        Err(_) => {
            guard.kill_and_reap().await;
            return Err(Error::timeout());
        }
    }
    if output.len() > GIT_DIR_CAP {
        guard.kill_and_reap().await;
        return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "Git output exceeds limit"));
    }
    let status = guard.finish().await?;
    if !status.success() {
        return Err(fail_error);
    }
    Ok(output)
}
