//! Bounded process-group execution for every S4 and Git View child Git process.
use crate::Error;
#[cfg(unix)]
use crate::git_http::{finish_group_child, group_quiescent};
use axum::http::StatusCode;
use std::{io, path::Path as FsPath, process::{ExitStatus, Stdio}, time::Duration};
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, process::{Child, Command}, time::Instant};

pub(crate) const META_OUTPUT_CAP: usize = 4 * 1024 * 1024;
const TIMEOUT_CLEANUP_BOUND: Duration = Duration::from_secs(2);
const LEADER_REAP_BOUND: Duration = Duration::from_millis(100);

/// One refcounted scratch owner that must outlive a child process group.
pub(crate) type ScratchHold = std::sync::Arc<dyn std::any::Any + Send + Sync>;

struct ScratchInner(std::path::PathBuf);

impl Drop for ScratchInner {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Disposable `0o700` tree shared by a Git command and its scratch owners.
#[derive(Clone)]
pub(crate) struct ScratchDir {
    inner: std::sync::Arc<ScratchInner>,
}

impl ScratchDir {
    pub(crate) fn create(prefix: &str) -> Result<Self, Error> {
        let root = std::env::temp_dir().join(format!("{prefix}-{}", uuid::Uuid::new_v4()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&root).map_err(Error::internal)?;
        }
        #[cfg(not(unix))]
        std::fs::create_dir_all(&root).map_err(Error::internal)?;
        Ok(Self { inner: std::sync::Arc::new(ScratchInner(root)) })
    }

    pub(crate) fn root(&self) -> &FsPath {
        &self.inner.0
    }

    pub(crate) fn bare(&self) -> std::path::PathBuf {
        self.inner.0.join("repo.git")
    }

    pub(crate) fn work(&self) -> std::path::PathBuf {
        self.inner.0.join("work")
    }

    pub(crate) fn hold(&self) -> ScratchHold {
        self.inner.clone()
    }
}

tokio::task_local! { static ACTIVE_SCRATCH: Vec<ScratchHold>; }

pub(crate) async fn with_scratch<T>(holds: Vec<ScratchHold>, fut: impl std::future::Future<Output = T>) -> T {
    ACTIVE_SCRATCH.scope(holds, fut).await
}

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
    scratch_holds: Vec<ScratchHold>,
}

impl ReapOnDropGuard {
    fn spawn(cmd: Command) -> Result<Self, Error> {
        Self::spawn_with_warm(cmd, crate::ci_pins::s4_git_reaper::warm_standby_reaper)
    }

    fn spawn_with_warm<W>(mut cmd: Command, warm: W) -> Result<Self, Error>
    where
        W: FnOnce() -> io::Result<()>,
    {
        cmd.kill_on_drop(true);
        #[cfg(unix)]
        cmd.process_group(0);
        warm().map_err(Error::internal)?;
        let child = cmd.spawn().map_err(Error::internal)?;
        let pid = child.id().and_then(|id| i32::try_from(id).ok()).unwrap_or(0);
        let scratch_holds = ACTIVE_SCRATCH.try_with(Clone::clone).unwrap_or_default();
        let guard = Self { child: Some(child), pid, scratch_holds };
        #[cfg(unix)]
        if pid > 1 {
            let until = Instant::now() + Duration::from_millis(100);
            loop {
                let group = unsafe { libc::getpgid(pid) };
                if group == pid || group < 0 {
                    break;
                }
                if Instant::now() >= until {
                    return Err(Error::internal("Git process group isolation timed out"));
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        Ok(guard)
    }

    async fn finish(&mut self, deadline: Instant) -> Result<ExitStatus, Error> {
        let Some(child) = self.child.as_mut() else {
            return Err(Error::internal("Git child already taken"));
        };
        #[cfg(unix)]
        let outcome = tokio::time::timeout_at(deadline, finish_group_child(child)).await;
        #[cfg(not(unix))]
        let outcome = tokio::time::timeout_at(deadline, child.wait()).await;
        match outcome {
            Ok(Ok(status)) => {
                self.child = None;
                self.pid = 0;
                self.scratch_holds.clear();
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

    async fn kill_and_reap(&mut self) {
        self.kill_and_reap_bounded(TIMEOUT_CLEANUP_BOUND).await;
    }

    async fn kill_and_reap_bounded(&mut self, bound: Duration) {
        let Some(child) = self.child.as_mut() else {
            self.pid = 0;
            self.scratch_holds.clear();
            return;
        };
        let pid = if child.id().is_some() { self.pid } else { 0 };
        signal_group(child, pid);
        #[cfg(unix)]
        let quiescent = !bound.is_zero()
            && (pid <= 1
                || tokio::time::timeout(bound, async {
                    while !matches!(group_quiescent(pid), Ok(true)) {
                        signal_group(child, pid);
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .is_ok());
        #[cfg(not(unix))]
        let quiescent = !bound.is_zero();
        if quiescent {
            self.pid = 0;
            if let Some(child) = self.child.as_mut()
                && tokio::time::timeout(LEADER_REAP_BOUND, async {
                    while !child_gone(child) {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                })
                .await
                .is_ok()
            {
                self.child = None;
                self.scratch_holds.clear();
                return;
            }
        }
        if let Some(child) = self.child.take() {
            let reap_pid = if child.id().is_some() { std::mem::replace(&mut self.pid, 0) } else { 0 };
            self.pid = 0;
            spawn_reaper_thread(child, reap_pid, std::mem::take(&mut self.scratch_holds));
        } else {
            self.pid = 0;
            self.scratch_holds.clear();
        }
    }
}

impl Drop for ReapOnDropGuard {
    fn drop(&mut self) {
        const DROP_INLINE_BUDGET: Duration = Duration::from_millis(100);
        let Some(mut child) = self.child.take() else {
            self.pid = 0;
            self.scratch_holds.clear();
            return;
        };
        let pid = if child.id().is_some() { std::mem::replace(&mut self.pid, 0) } else { 0 };
        self.pid = 0;
        signal_group(&mut child, pid);
        #[cfg(unix)]
        let quiescent = pid <= 1 || wait_until(DROP_INLINE_BUDGET, || matches!(group_quiescent(pid), Ok(true)));
        #[cfg(not(unix))]
        let quiescent = true;
        if quiescent && wait_until(Duration::from_millis(50), || child_gone(&mut child)) {
            self.scratch_holds.clear();
            return;
        }
        spawn_reaper_thread(child, if quiescent { 0 } else { pid }, std::mem::take(&mut self.scratch_holds));
    }
}

fn signal_group(child: &mut Child, pid: i32) {
    #[cfg(unix)]
    if pid > 1 && child.id().is_some() {
        unsafe { libc::kill(-pid, libc::SIGKILL) };
        return;
    }
    let _ = child.start_kill();
}

fn spawn_reaper_thread(child: Child, pid: i32, holds: Vec<ScratchHold>) {
    spawn_reaper_with(child, pid, holds, |task| {
        std::thread::Builder::new().name("s4-git-reap".into()).spawn(task).map(|_| ())
    });
}

fn spawn_reaper_with<F>(child: Child, pid: i32, holds: Vec<ScratchHold>, spawn_fn: F)
where
    F: FnOnce(crate::ci_pins::s4_git_runner::ReaperTask) -> std::io::Result<()>,
{
    crate::ci_pins::s4_git_runner::spawn_reaper_with(child, pid, holds, spawn_fn);
}

fn wait_until(budget: Duration, mut done: impl FnMut() -> bool) -> bool {
    let started = std::time::Instant::now();
    loop {
        if done() {
            return true;
        }
        if started.elapsed() >= budget {
            return false;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn child_gone(child: &mut Child) -> bool {
    child.id().is_none() || matches!(child.try_wait(), Ok(Some(_)))
}

#[cfg(debug_assertions)]
fn reverse_failure_phase<'a>(mut args: impl Iterator<Item = &'a std::ffi::OsStr>) -> &'static str {
    use std::ffi::OsStr;
    let global_args = ["-c", "core.hooksPath=/dev/null", "--no-replace-objects", "-C"];
    if !args.by_ref().take(global_args.len()).eq(global_args.map(OsStr::new)) || args.next().is_none() {
        return "unknown";
    }
    match args.next().and_then(OsStr::to_str) {
        Some("bundle") if args.next().and_then(OsStr::to_str) == Some("verify") => "bundle_verify",
        Some("fetch") if args.nth(1).and_then(OsStr::to_str) == Some("--no-write-fetch-head") => "source_fetch",
        Some("fetch") => "fetch",
        Some("rev-parse") => "rev_parse",
        Some("merge-base") => "merge_base",
        Some("rev-list") => "rev_list",
        Some("cat-file") => "cat_file",
        Some("fsck") => "fsck",
        Some("ls-tree") => "ls_tree",
        Some("mktree") => "mktree",
        Some("update-ref") => "update_ref",
        Some("commit-tree") => "commit_tree",
        Some("pack-objects") => "pack_objects",
        Some("index-pack") => "index_pack",
        _ => "unknown",
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
    #[cfg(debug_assertions)]
    let reverse_phase = (fail_error.0 == StatusCode::CONFLICT && fail_error.1 == "Git View reverse mapping conflict")
        .then(|| reverse_failure_phase(cmd.as_std().get_args()));
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
    let read = tokio::time::timeout_at(
        deadline,
        (&mut stdout).take(max_stdout_bytes as u64 + 1).read_to_end(&mut output),
    )
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
        #[cfg(debug_assertions)]
        if let Some(phase) = reverse_phase {
            let code = status.code();
            let exit = if code.is_some() { "nonzero_exit" } else { "no_exit_code" };
            use std::io::Write;
            let _ = writeln!(
                std::io::stderr().lock(),
                "rootyard: Git View reverse child failed phase={phase} exit={exit} code={code:?}"
            );
        }
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

pub(crate) async fn git_init_bare(
    git_bin: &FsPath,
    bare: &FsPath,
    format: &str,
    deadline: Instant,
) -> Result<(), Error> {
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
