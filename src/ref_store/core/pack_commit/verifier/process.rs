//! Bounded native Git child processes owned by the pack-closure verifier.
//!
//! Every step runs the configured *absolute trusted* Git binary in a new process
//! group with a cleared environment (owned empty `HOME`/`XDG_CONFIG_HOME`/template
//! dir, `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`,
//! `GIT_CONFIG_SYSTEM=/dev/null`, `GIT_ATTR_NOSYSTEM=1`,
//! `GIT_NO_REPLACE_OBJECTS=1`), `core.hooksPath=/dev/null` and
//! `--no-replace-objects`. No caller string is ever an argument: the only argv
//! values are compiled literals, values already parsed into bounded types by the
//! core (`RefName`/`GitOid`) and paths this verifier created itself.
//!
//! Resource limits are the frozen verifier limits (CPU 20 s, address space
//! 512 MiB, file size 128 MiB, NOFILE 64). Stdout and stderr are drained
//! concurrently with a `cap + 1` read, so an overflowing stream is refused
//! instead of buffered. One absolute deadline covers the whole child; on
//! timeout, overflow, spawn failure or a dropped future the *entire* process
//! group is signalled and reaped through the shared maintenance helpers, and the
//! pipe-drain tasks are joined before this module returns. Diagnostics are one
//! bounded, secret-free record per failure containing only a compiled step label
//! and a compiled class literal — never argv, stdout, stderr or a path — and no
//! Git text is ever promoted to an authenticated value or a public error.
use super::lease::{VerificationLease, retain_until_stopped};
use super::refuse;
use crate::ref_store::core::pack_commit::contract::{
    VERIFIER_GIT_ADDRESS_SPACE_BYTES, VERIFIER_GIT_CPU_SECONDS, VERIFIER_GIT_FILE_SIZE_BYTES, VERIFIER_GIT_NOFILE,
    VERIFIER_PIPE_BYTES,
};
use crate::ref_store::core::pack_commit::error::PackCommitError;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;

/// Upper bound for one drain: the frozen cap plus one byte to detect overflow.
const PIPE_LIMIT: u64 = VERIFIER_PIPE_BYTES as u64 + 1;
/// Bounded window for joining a pipe task and for the synchronous drop cleanup.
const CLEANUP_WINDOW: Duration = Duration::from_secs(5);

/// Child stdin shape for one step.
pub(super) enum Stdin<'a> {
    Null,
    Bytes(&'a [u8]),
    File(&'a Path),
}

/// Bounded runner for one owned Git view.
pub(super) struct GitRunner {
    binary: PathBuf,
    home: PathBuf,
    template: PathBuf,
}

impl GitRunner {
    pub(super) fn new(binary: PathBuf, home: PathBuf, template: PathBuf) -> Self {
        Self { binary, home, template }
    }

    /// Run one closed step. `git_dir` adds `--git-dir <owned dir>` (never used by
    /// `init`, which takes its target as the single trailing path argument), and
    /// `path_arg` appends one owned path (an `init` target or a registered
    /// `*.idx` copy this verifier wrote). `step` is a compiled diagnostic label.
    pub(super) async fn run(
        &self,
        step: &'static str,
        args: &[&str],
        git_dir: Option<&Path>,
        path_arg: Option<&Path>,
        stdin: Stdin<'_>,
        deadline: Instant,
        lease: &Arc<VerificationLease>,
    ) -> Result<Vec<u8>, PackCommitError> {
        if deadline <= Instant::now() {
            report_step(step, "deadline");
            return Err(refuse("native Git step has no remaining verifier deadline"));
        }
        let mut command = self.command();
        if let Some(dir) = git_dir {
            command.arg("--git-dir").arg(dir);
        }
        command.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());
        if let Some(path) = path_arg {
            command.arg(path);
        }
        let mut payload: Option<&[u8]> = None;
        match stdin {
            Stdin::Null => {
                command.stdin(Stdio::null());
            }
            Stdin::Bytes(bytes) => {
                command.stdin(Stdio::piped());
                payload = Some(bytes);
            }
            Stdin::File(path) => {
                let Ok(file) = std::fs::File::open(path) else {
                    report_step(step, "input");
                    return Err(refuse("verified pack copy cannot be reopened for native Git"));
                };
                command.stdin(Stdio::from(file));
            }
        }
        // SAFETY: the closure only calls async-signal-safe libc setters and
        // allocates nothing between fork and exec.
        unsafe {
            command.pre_exec(limit_child);
        }
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(_) => {
                report_step(step, "spawn");
                return Err(refuse("native Git executable could not be started"));
            }
        };
        let pid = match child.id().and_then(|pid| i32::try_from(pid).ok()) {
            Some(pid) => pid,
            None => {
                // Without an id the group cannot be addressed, so only the leader
                // is signalled; the owned reaper keeps the slot until it is reaped.
                report_step(step, "spawn");
                let _ = child.start_kill();
                retain_until_stopped(Some(child), 0, Some(Arc::clone(lease)));
                return Err(refuse("native Git child has no usable process id"));
            }
        };
        let (stdout, stderr) = match (child.stdout.take(), child.stderr.take()) {
            (Some(stdout), Some(stderr)) => (stdout, stderr),
            _ => {
                // A refused step must never leave a child or its group behind: the
                // retained cleanup owns the child and keeps the verifier slot.
                report_step(step, "pipes");
                retain_until_stopped(Some(child), pid, Some(Arc::clone(lease)));
                return Err(refuse("native Git stdio pipes are missing"));
            }
        };
        let mut out_task = tokio::spawn(drain(stdout));
        let mut err_task = tokio::spawn(drain(stderr));
        let mut group = GroupChild::new(child, pid, Arc::clone(lease));
        let mut timed_out = false;
        if let Some(bytes) = payload {
            match group.take_stdin() {
                Some(mut sink) => {
                    let write = async {
                        sink.write_all(bytes).await?;
                        sink.shutdown().await
                    };
                    if !matches!(tokio::time::timeout_at(tokio_time(deadline), write).await, Ok(Ok(()))) {
                        timed_out = true;
                    }
                    drop(sink);
                }
                None => timed_out = true,
            }
        }
        let status = if timed_out {
            Err(io::Error::new(io::ErrorKind::TimedOut, "native Git step deadline"))
        } else {
            match tokio::time::timeout_at(tokio_time(deadline), group.finish()).await {
                Ok(status) => status,
                Err(_) => Err(io::Error::new(io::ErrorKind::TimedOut, "native Git step deadline")),
            }
        };
        // Foreground cleanup is separately bounded: a group that does not settle in
        // this window is handed to the owned reaper together with its lease, which
        // keeps the process-wide slot reserved until physical quiescence.
        let retained = status.is_err() && !group.stop_bounded(CLEANUP_WINDOW).await;
        // Both pipe tasks are joined on every path before this call returns.
        let stdout = collect(&mut out_task).await;
        let stderr = collect(&mut err_task).await;
        drop(group);
        let outcome = match (stdout, stderr) {
            (Ok(_), Ok(_)) if retained => Err((super::lease::refuse_retained_cleanup(), "retained")),
            (Ok(_), Ok(_)) if status.is_err() => {
                Err((refuse("native Git step exceeded the verifier deadline"), "deadline"))
            }
            (Ok(stdout), Ok(stderr)) => {
                if stdout.len() > VERIFIER_PIPE_BYTES || stderr.len() > VERIFIER_PIPE_BYTES {
                    Err((refuse("native Git output exceeded the verifier pipe bound"), "output-bound"))
                } else {
                    match status {
                        Ok(status) if status.success() => Ok(stdout),
                        Ok(status) => Err((exit_class(status), exit_class_label(status))),
                        Err(_) => Err((refuse("native Git step failed"), "failed")),
                    }
                }
            }
            _ => Err((refuse("native Git pipe drain failed"), "pipes")),
        };
        outcome.map_err(|(error, class)| {
            report_step(step, class);
            error
        })
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.binary);
        command
            .env_clear()
            .env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", &self.home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_ATTR_NOSYSTEM", "1")
            .env("GIT_TEMPLATE_DIR", &self.template)
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("LC_ALL", "C")
            .arg("-c")
            .arg("core.hooksPath=/dev/null")
            .arg("-c")
            .arg("gc.auto=0")
            .arg("--no-replace-objects");
        command
    }
}

fn tokio_time(deadline: Instant) -> tokio::time::Instant {
    tokio::time::Instant::from_std(deadline)
}

/// One bounded, secret-free diagnostic record per failed native step.
fn report_step(step: &'static str, class: &'static str) {
    const BUDGET: u32 = 32;
    static REPORTED: AtomicU32 = AtomicU32::new(0);
    if REPORTED.fetch_add(1, Ordering::Relaxed) >= BUDGET {
        return;
    }
    eprintln!("rootyard: pack verify step={step} class={class}");
}

/// Frozen verifier limits, applied after `fork` and before `exec`.
fn limit_child() -> io::Result<()> {
    if unsafe { libc::setpgid(0, 0) } == -1 {
        return Err(io::Error::last_os_error());
    }
    for (resource, limit) in [
        (libc::RLIMIT_AS, VERIFIER_GIT_ADDRESS_SPACE_BYTES),
        (libc::RLIMIT_CPU, VERIFIER_GIT_CPU_SECONDS),
        (libc::RLIMIT_FSIZE, VERIFIER_GIT_FILE_SIZE_BYTES),
        (libc::RLIMIT_NOFILE, VERIFIER_GIT_NOFILE),
    ] {
        let value = libc::rlimit { rlim_cur: limit, rlim_max: limit };
        if unsafe { libc::setrlimit(resource, &value) } == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

async fn drain<R: AsyncRead + Unpin>(reader: R) -> io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    let mut limited = reader.take(PIPE_LIMIT);
    limited.read_to_end(&mut buffer).await?;
    Ok(buffer)
}

/// Join one pipe task, giving it the bounded cleanup window; a task that cannot
/// finish is aborted and awaited, so no pipe task survives this call.
async fn collect(handle: &mut JoinHandle<io::Result<Vec<u8>>>) -> Result<Vec<u8>, PackCommitError> {
    match tokio::time::timeout(CLEANUP_WINDOW, &mut *handle).await {
        Ok(Ok(Ok(bytes))) => Ok(bytes),
        Ok(_) => Err(refuse("native Git pipe drain failed")),
        Err(_) => {
            handle.abort();
            let _ = handle.await;
            Err(refuse("native Git pipe drain did not settle"))
        }
    }
}

/// Fixed exit-class refusal. The numeric status is classified here and never
/// rendered into the error text, which stays a compiled literal.
fn exit_class(status: ExitStatus) -> PackCommitError {
    match status.code() {
        Some(129) => refuse("native Git does not support a required verifier step"),
        Some(128) => refuse("native Git refused the owned verification repository view"),
        Some(_) => refuse("native Git refused the registered pack closure"),
        None => refuse("native Git step was terminated by a signal"),
    }
}

fn exit_class_label(status: ExitStatus) -> &'static str {
    match status.code() {
        Some(129) => "capability",
        Some(128) => "fatal",
        Some(_) => "refused",
        None => "signal",
    }
}

/// Lifecycle of one spawned child.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    /// The child may still be running: the lease must not be released.
    Running,
    /// Leader reaped and the whole process group confirmed quiescent.
    Confirmed,
    /// Ownership of the child and of its lease was handed to the reaper.
    Retained,
}

/// One spawned child, the lease it retains while it may still be alive, and the
/// confirmation state of its cleanup.
struct GroupChild {
    child: Option<Child>,
    pid: i32,
    /// Declared after `child`, so the handle is dropped before the lease: the
    /// workspace and the process-wide slot are released only once nothing of this
    /// child is left to drop.
    lease: Option<Arc<VerificationLease>>,
    phase: Phase,
}

impl GroupChild {
    fn new(child: Child, pid: i32, lease: Arc<VerificationLease>) -> Self {
        Self { child: Some(child), pid, lease: Some(lease), phase: Phase::Running }
    }

    fn take_stdin(&mut self) -> Option<tokio::process::ChildStdin> {
        self.child.as_mut().and_then(|child| child.stdin.take())
    }

    /// Observe leader exit, kill every surviving group member and reap. Only a
    /// successful return is a confirmed stop.
    async fn finish(&mut self) -> io::Result<ExitStatus> {
        let child = self.child.as_mut().ok_or_else(|| io::Error::other("native Git child is already retained"))?;
        let status = crate::git_http::finish_group_child(child).await?;
        self.phase = Phase::Confirmed;
        Ok(status)
    }

    /// Bounded cancellation path. Returns `true` only when the leader is reaped and
    /// the group is quiescent; otherwise ownership moves to the retained reaper and
    /// the lease stays held, so capacity is never released on an uncertain stop.
    async fn stop_bounded(&mut self, window: Duration) -> bool {
        match self.phase {
            Phase::Confirmed => return true,
            Phase::Retained => return false,
            Phase::Running => {}
        }
        if self.child.is_none() {
            self.phase = Phase::Confirmed;
            return true;
        }
        // The child stays owned by `self` for the whole await, so a cancellation
        // during the cleanup drops no live handle: `Drop` still sees it and hands
        // it to the reaper together with the lease. Ownership is only moved after
        // the await returned, when no cancellation can interleave any more.
        let outcome = match self.child.as_mut() {
            Some(child) => tokio::time::timeout(window, crate::git_http::stop_group_child(child)).await,
            // Unreachable after the check above; refuse to claim a confirmed stop.
            None => return false,
        };
        if matches!(outcome, Ok(Ok(()))) {
            // `stop_group_child` reaped the leader and observed group quiescence.
            self.child = None;
            self.phase = Phase::Confirmed;
            true
        } else {
            let child = self.child.take();
            self.phase = Phase::Retained;
            retain_until_stopped(child, self.pid, self.lease.take());
            false
        }
    }
}

impl Drop for GroupChild {
    fn drop(&mut self) {
        if self.phase != Phase::Running {
            // Confirmed: the reaped handle, then the lease field, are dropped by
            // the normal field order (handle first, slot and workspace last).
            return;
        }
        // Cancellation before any confirmation: signal this verifier's own process
        // group now (one non-blocking syscall, only while we still own the
        // unreaped leader) and hand the child and its lease to the reaper. This
        // thread never sleeps and never releases capacity early.
        self.phase = Phase::Retained;
        let child = self.child.take();
        let lease = self.lease.take();
        if child.is_none() && lease.is_none() {
            return;
        }
        retain_until_stopped(child, self.pid, lease);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stream that exceeds the cap is truncated at `cap + 1`: the drain never
    /// buffers more, so an overflowing child is refused rather than followed.
    #[tokio::test]
    async fn drain_stops_at_cap_plus_one() {
        let (mut writer, reader) = tokio::io::duplex(1024);
        let producer = tokio::spawn(async move {
            let chunk = vec![b'x'; 1024];
            for _ in 0..(VERIFIER_PIPE_BYTES / 1024 + 4) {
                if writer.write_all(&chunk).await.is_err() {
                    return;
                }
            }
        });
        let bytes = drain(reader).await.expect("duplex drain");
        assert_eq!(bytes.len() as u64, PIPE_LIMIT);
        assert!(bytes.len() > VERIFIER_PIPE_BYTES);
        producer.abort();
        let _ = producer.await;
    }

    /// The child environment is closed: no inherited variable, no inherited PATH,
    /// and the frozen Git configuration overrides are present verbatim.
    #[test]
    fn child_environment_is_closed() {
        let runner = GitRunner::new(PathBuf::from("/nonexistent/git"), PathBuf::from("/h"), PathBuf::from("/t"));
        let command = runner.command();
        let envs = command
            .as_std()
            .get_envs()
            .map(|(key, value)| (key.to_string_lossy().into_owned(), value.map(|v| v.to_string_lossy().into_owned())))
            .collect::<std::collections::BTreeMap<_, _>>();
        let recorded = |key: &str| envs.get(key).cloned().flatten();
        assert_eq!(recorded("GIT_CONFIG_NOSYSTEM").as_deref(), Some("1"));
        assert_eq!(recorded("GIT_CONFIG_GLOBAL").as_deref(), Some("/dev/null"));
        assert_eq!(recorded("HOME").as_deref(), Some("/h"));
        assert!(!envs.contains_key("PATH"), "the verifier must not inherit PATH");
        let args = command.as_std().get_args().map(|arg| arg.to_string_lossy().into_owned()).collect::<Vec<_>>();
        assert!(args.iter().any(|arg| arg == "--no-replace-objects"));
        assert!(args.iter().any(|arg| arg == "core.hooksPath=/dev/null"));
    }
}
