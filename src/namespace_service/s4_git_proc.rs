//! Bounded process-group execution for every S4 and Git View child Git process.
use crate::Error;
use crate::git_http::{finish_group_child, group_quiescent, kill_group_child};
use axum::http::StatusCode;
use std::{io, path::Path as FsPath, process::{ExitStatus, Stdio}, time::Duration};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, process::{Child, Command}, time::Instant};

pub(crate) const META_OUTPUT_CAP: usize = 4 * 1024 * 1024;
const CLEANUP_BUDGET: Duration = Duration::from_secs(2);
const DROP_POLL_BUDGET: Duration = Duration::from_millis(250);

pub(crate) use super::s4_git_proc_reverse::{
    GitInputSpec, git_input, new_pack, replace_tree, verify_candidate_budget,
};

pub(crate) enum GitStdin<'a> { Null, Bytes(&'a [u8]), File(std::fs::File) }

pub(crate) fn base_command(git_bin: &FsPath) -> Command {
    let mut command = Command::new(git_bin);
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("FILTER_BRANCH_SQUELCH_WARNING", "1")
        .env("GIT_AUTHOR_NAME", "Rootyard")
        .env("GIT_AUTHOR_EMAIL", "view@rootyard.local")
        .env("GIT_COMMITTER_NAME", "Rootyard")
        .env("GIT_COMMITTER_EMAIL", "view@rootyard.local")
        .env_remove("GIT_PROTOCOL");
    command
}

struct ReapOnDropGuard {
    child: Option<Child>,
    pid: i32,
}

impl ReapOnDropGuard {
    fn spawn(mut cmd: Command) -> Result<Self, Error> {
        cmd.kill_on_drop(true);
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
        Ok(Self { child: Some(child), pid })
    }

    async fn finish(&mut self, deadline: Instant) -> Result<ExitStatus, Error> {
        #[cfg(unix)]
        {
            let outcome = {
                let Some(child) = self.child.as_mut() else {
                    return Err(Error::internal("Git child already taken"));
                };
                tokio::time::timeout_at(deadline, finish_group_child(child)).await
            };
            match outcome {
                Ok(Ok(status)) => {
                    self.child = None;
                    self.pid = 0;
                    Ok(status)
                }
                Ok(Err(error)) => {
                    self.kill_and_reap().await;
                    Err(Error::internal(error))
                }
                Err(_) => {
                    self.kill_and_reap().await;
                    Err(Error::timeout())
                }
            }
        }
        #[cfg(not(unix))]
        {
            let outcome = {
                let Some(child) = self.child.as_mut() else {
                    return Err(Error::internal("Git child already taken"));
                };
                tokio::time::timeout_at(deadline, child.wait()).await
            };
            match outcome {
                Ok(Ok(status)) => {
                    self.child = None;
                    self.pid = 0;
                    Ok(status)
                }
                Ok(Err(error)) => {
                    self.kill_and_reap().await;
                    Err(Error::internal(error))
                }
                Err(_) => {
                    self.kill_and_reap().await;
                    Err(Error::timeout())
                }
            }
        }
    }

    async fn kill_and_reap(&mut self) {
        let pid = self.pid;
        let Some(child) = self.child.as_mut() else { return };
        #[cfg(unix)]
        if pid > 1 {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
                libc::kill(pid, libc::SIGKILL);
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
    }
}

impl Drop for ReapOnDropGuard {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else { return };
        let pid = std::mem::replace(&mut self.pid, 0);
        #[cfg(unix)]
        if pid > 1 {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
                libc::kill(pid, libc::SIGKILL);
            }
        }
        let _ = child.start_kill();
        #[cfg(unix)]
        if pid > 1 {
            let started = std::time::Instant::now();
            while started.elapsed() < DROP_POLL_BUDGET && matches!(group_quiescent(pid), Ok(false)) {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        if matches!(child.try_wait(), Ok(Some(_)) | Err(_)) {
            return;
        }
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                #[cfg(unix)]
                if pid > 1 {
                    let until = Instant::now() + CLEANUP_BUDGET;
                    while Instant::now() < until && matches!(group_quiescent(pid), Ok(false)) {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                }
                let _ = tokio::time::timeout(CLEANUP_BUDGET, child.wait()).await;
            });
        }
    }
}

pub(crate) async fn run_git_bounded(
    mut cmd: Command,
    stdin: GitStdin<'_>,
    max_stdout_bytes: usize,
    deadline: Instant,
    fail_error: Error,
) -> Result<Vec<u8>, Error> {
    if Instant::now() >= deadline {
        return Err(Error::timeout());
    }
    let writer_bytes = match stdin {
        GitStdin::Null => {
            cmd.stdin(Stdio::null());
            None
        }
        GitStdin::Bytes(bytes) => {
            cmd.stdin(Stdio::piped());
            Some(bytes.to_vec())
        }
        GitStdin::File(file) => {
            cmd.stdin(Stdio::from(file));
            None
        }
    };
    cmd.stdout(Stdio::piped()).stderr(Stdio::null());
    let mut guard = ReapOnDropGuard::spawn(cmd)?;
    let writer = writer_bytes.map(|bytes| {
        let stdin = guard.child.as_mut().and_then(|child| child.stdin.take());
        tokio::spawn(async move {
            let mut stdin = stdin.ok_or_else(|| io::Error::other("missing Git stdin"))?;
            stdin.write_all(&bytes).await?;
            stdin.shutdown().await
        })
    });
    let Some(mut stdout) = guard.child.as_mut().and_then(|child| child.stdout.take()) else {
        if let Some(writer) = &writer {
            writer.abort();
        }
        guard.kill_and_reap().await;
        return Err(Error::internal("missing Git stdout"));
    };
    let mut output = Vec::new();
    let read = tokio::time::timeout_at(deadline, (&mut stdout).take(max_stdout_bytes as u64 + 1).read_to_end(&mut output))
        .await;
    drop(stdout);
    match read {
        Ok(Ok(_)) => {}
        Ok(Err(error)) => {
            if let Some(writer) = &writer {
                writer.abort();
            }
            guard.kill_and_reap().await;
            return Err(Error::internal(error));
        }
        Err(_) => {
            if let Some(writer) = &writer {
                writer.abort();
            }
            guard.kill_and_reap().await;
            return Err(Error::timeout());
        }
    }
    if output.len() > max_stdout_bytes {
        if let Some(writer) = &writer {
            writer.abort();
        }
        guard.kill_and_reap().await;
        return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "Git output exceeds limit"));
    }
    if let Some(writer) = writer {
        match tokio::time::timeout_at(deadline, writer).await {
            Ok(Ok(Ok(()))) => {}
            Ok(Ok(Err(error))) if error.kind() == io::ErrorKind::BrokenPipe => {}
            Ok(Ok(Err(error))) => {
                guard.kill_and_reap().await;
                return Err(Error::internal(error));
            }
            Ok(Err(error)) => {
                guard.kill_and_reap().await;
                return Err(Error::internal(error));
            }
            Err(_) => {
                guard.kill_and_reap().await;
                return Err(Error::timeout());
            }
        }
    }
    let status = guard.finish(deadline).await?;
    if !status.success() {
        return Err(fail_error);
    }
    Ok(output)
}

pub(crate) async fn git_bytes(
    git_bin: &FsPath,
    repo: &FsPath,
    args: &[&str],
    deadline: Instant,
    conflict_msg: &'static str,
) -> Result<Vec<u8>, Error> {
    let mut cmd = base_command(git_bin);
    cmd.args(["-c", "core.hooksPath=/dev/null", "--no-replace-objects", "-C"])
        .arg(repo)
        .args(args);
    run_git_bounded(
        cmd,
        GitStdin::Null,
        META_OUTPUT_CAP,
        deadline,
        Error(StatusCode::CONFLICT, conflict_msg),
    )
    .await
}

pub(crate) async fn git_text(
    git_bin: &FsPath,
    repo: &FsPath,
    args: &[&str],
    deadline: Instant,
    conflict_msg: &'static str,
) -> Result<String, Error> {
    String::from_utf8(git_bytes(git_bin, repo, args, deadline, conflict_msg).await?).map_err(Error::internal)
}

pub(crate) async fn git_oid(
    git_bin: &FsPath,
    repo: &FsPath,
    args: &[&str],
    deadline: Instant,
) -> Result<String, Error> {
    Ok(git_text(git_bin, repo, args, deadline, "Git View reverse mapping conflict")
        .await?
        .trim()
        .to_owned())
}

pub(crate) async fn git_init_bare(git_bin: &FsPath, bare: &FsPath, format: &str, deadline: Instant) -> Result<(), Error> {
    let object_format = format!("--object-format={format}");
    let mut cmd = base_command(git_bin);
    cmd.args(["-c", "core.hooksPath=/dev/null", "init", "--bare"])
        .arg(object_format)
        .arg(bare);
    run_git_bounded(
        cmd,
        GitStdin::Null,
        META_OUTPUT_CAP,
        deadline,
        Error(StatusCode::CONFLICT, "Git view repository could not be initialized"),
    )
    .await?;
    Ok(())
}

pub(crate) async fn git_clone(
    git_bin: &FsPath,
    source: &FsPath,
    dest: &FsPath,
    extra: &[&str],
    deadline: Instant,
) -> Result<(), Error> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(Error::internal)?;
    }
    let mut cmd = base_command(git_bin);
    cmd.args(["-c", "core.hooksPath=/dev/null", "clone"])
        .args(extra)
        .arg("--")
        .arg(source)
        .arg(dest);
    run_git_bounded(
        cmd,
        GitStdin::Null,
        META_OUTPUT_CAP,
        deadline,
        Error(StatusCode::CONFLICT, "Git view clone failed"),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
#[path = "s4_git_proc_tests.rs"]
mod tests;
