//! Bounded, isolated child Git processes for S4 CI transport.
use super::*;
#[cfg(unix)]
use crate::git_http::{finish_group_child, group_quiescent};
use std::{path::{Path as FsPath, PathBuf}, process::{ExitStatus, Stdio}, sync::Arc, time::Duration};
use tokio::{
    io::AsyncReadExt,
    process::{Child, ChildStdin, ChildStdout, Command},
    time::Instant,
};

const GIT_DIR_CAP: usize = 64 * 1024 * 1024;
const TIMEOUT_CLEANUP_BOUND: Duration = Duration::from_secs(2);
const LEADER_REAP_BOUND: Duration = Duration::from_millis(100);
const FALLBACK_ASYNC_BUDGET: Duration = Duration::from_millis(250);
const UNRESOLVED_OWNER_CAP: usize = 256;

/// One refcounted scratch owner that must outlive a child process group.
pub(crate) type ScratchHold = std::sync::Arc<dyn std::any::Any + Send + Sync>;

struct DisposableDir(PathBuf);

impl Drop for DisposableDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Disposable `0o700` bare repository removed when the last hold is dropped.
#[derive(Clone)]
pub(crate) struct DisposableCiView {
    dir: Arc<DisposableDir>,
}

impl DisposableCiView {
    pub(crate) fn create() -> Result<Self, Error> {
        let dir = std::env::temp_dir().join(format!("rootyard-s4-{}", Uuid::new_v4()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir).map_err(Error::internal)?;
        }
        #[cfg(not(unix))]
        std::fs::create_dir_all(&dir).map_err(Error::internal)?;
        Ok(Self { dir: Arc::new(DisposableDir(dir)) })
    }

    pub(crate) fn path(&self) -> &FsPath {
        &self.dir.0
    }

    pub(crate) fn hold(&self) -> ScratchHold {
        self.dir.clone()
    }
}

/// One isolated `git upload-pack` (or bounded disposable-repo command) child.
pub(crate) struct UploadPackGroup {
    child: Option<Child>,
    pid: i32,
    scratch_hold: Option<ScratchHold>,
}
impl UploadPackGroup {
    pub(crate) fn spawn(git_bin: &FsPath, dir: &FsPath, scratch_hold: Option<ScratchHold>) -> Result<Self, Error> {
        Self::spawn_argv(
            git_bin,
            Some(dir),
            &["upload-pack", "--stateless-rpc"],
            Some(dir),
            Stdio::piped(),
            scratch_hold,
        )
    }

    fn spawn_argv(
        git_bin: &FsPath,
        dir: Option<&FsPath>,
        args: &[&str],
        positional: Option<&FsPath>,
        stdin: Stdio,
        scratch_hold: Option<ScratchHold>,
    ) -> Result<Self, Error> {
        let mut cmd = Command::new(git_bin);
        cmd.args(["-c", "core.hooksPath=/dev/null"]);
        if let Some(dir) = dir {
            cmd.arg("--git-dir").arg(dir);
        }
        cmd.args(args);
        if let Some(target) = positional {
            cmd.arg(target);
        }
        cmd.env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env_remove("GIT_PROTOCOL")
            .stdin(stdin)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        #[cfg(unix)]
        cmd.process_group(0);
        let child = cmd.spawn().map_err(Error::internal)?;
        let pid = child.id().and_then(|id| i32::try_from(id).ok()).unwrap_or(0);
        let guard = Self { child: Some(child), pid, scratch_hold };
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

    pub(crate) async fn finish(&mut self, deadline: Instant) -> Result<ExitStatus, Error> {
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
                self.scratch_hold = None;
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

    pub(crate) async fn kill_and_reap(&mut self) {
        self.kill_and_reap_bounded(TIMEOUT_CLEANUP_BOUND).await;
    }

    pub(crate) async fn kill_and_reap_bounded(&mut self, bound: Duration) {
        let Some(child) = self.child.as_mut() else {
            self.pid = 0;
            self.scratch_hold = None;
            return;
        };
        let pid = if child.id().is_some() { self.pid } else { 0 };
        signal_group(child, pid);
        #[cfg(unix)]
        let quiescent = !bound.is_zero()
            && (pid <= 1
                || tokio::time::timeout(bound, async {
                    while !matches!(group_quiescent(pid), Ok(true)) {
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
                self.scratch_hold = None;
                return;
            }
        }
        if let Some(child) = self.child.take() {
            let reap_pid = if child.id().is_some() { std::mem::replace(&mut self.pid, 0) } else { 0 };
            self.pid = 0;
            spawn_reaper_thread(child, reap_pid, self.scratch_hold.take());
        } else {
            self.pid = 0;
            self.scratch_hold = None;
        }
    }
}
impl Drop for UploadPackGroup {
    fn drop(&mut self) {
        const DROP_INLINE_BUDGET: Duration = Duration::from_millis(100);
        let Some(mut child) = self.child.take() else {
            self.pid = 0;
            self.scratch_hold = None;
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
            self.scratch_hold = None;
            return;
        }
        spawn_reaper_thread(child, if quiescent { 0 } else { pid }, self.scratch_hold.take());
    }
}

fn signal_group(child: &mut Child, pid: i32) {
    #[cfg(unix)]
    if pid > 1 {
        unsafe { libc::kill(-pid, libc::SIGKILL) };
        return;
    }
    let _ = child.start_kill();
}

pub(crate) type ReaperTask = Box<dyn FnOnce() + Send + 'static>;
pub(crate) type GroupProbe = fn(i32) -> std::io::Result<bool>;

fn spawn_reaper_thread(child: Child, pid: i32, hold: Option<ScratchHold>) {
    let holds: Vec<ScratchHold> = hold.into_iter().collect();
    spawn_reaper_with(child, pid, holds, |task| {
        std::thread::Builder::new().name("s4-git-reap".into()).spawn(task).map(|_| ())
    });
}

pub(crate) fn spawn_reaper_with<F>(child: Child, pid: i32, holds: Vec<ScratchHold>, spawn_fn: F)
where
    F: FnOnce(ReaperTask) -> std::io::Result<()>,
{
    #[cfg(unix)]
    let probe: GroupProbe = group_quiescent;
    #[cfg(not(unix))]
    let probe: GroupProbe = |_| Ok(true);
    spawn_reaper_with_probe(child, pid, holds, spawn_fn, probe);
}

pub(crate) fn spawn_reaper_with_probe<F>(
    child: Child,
    pid: i32,
    holds: Vec<ScratchHold>,
    spawn_fn: F,
    probe: GroupProbe,
) where
    F: FnOnce(ReaperTask) -> std::io::Result<()>,
{
    let mut fallback = SpawnFallback { state: Some((child, pid, holds, probe)) };
    let spawned = spawn_fn(Box::new(move || {
        if let Some((child, pid, holds, probe)) = fallback.state.take() {
            reap_until_confirmed(child, pid, holds, probe);
        }
    }));
    drop(spawned);
}

struct SpawnFallback {
    state: Option<(Child, i32, Vec<ScratchHold>, GroupProbe)>,
}

impl Drop for SpawnFallback {
    fn drop(&mut self) {
        let Some((mut child, pid, holds, probe)) = self.state.take() else {
            return;
        };
        signal_group(&mut child, pid);
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(reap_fallback_bounded(child, pid, holds, probe));
            return;
        }
        #[cfg(unix)]
        let quiescent = pid <= 1 || matches!(probe(pid), Ok(true));
        #[cfg(not(unix))]
        let quiescent = {
            let _ = probe;
            true
        };
        if quiescent && child_gone(&mut child) {
            drop(child);
            drop(holds);
            return;
        }
        eprintln!("rootyard: Git reaper fallback timed out or group probe failed; preserving unverified scratch");
        std::mem::forget(holds);
        handoff_unresolved_child(child, pid);
    }
}

pub(super) type WaitFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<ExitStatus>> + Send + 'a>>;
pub(super) type WaitChildFn = for<'a> fn(&'a mut Child) -> WaitFuture<'a>;
fn default_wait_child(child: &mut Child) -> WaitFuture<'_> {
    Box::pin(child.wait())
}
async fn reap_fallback_bounded(child: Child, pid: i32, holds: Vec<ScratchHold>, probe: GroupProbe) {
    reap_fallback_with_wait(child, pid, holds, probe, default_wait_child).await;
}
pub(super) async fn reap_fallback_with_wait(
    mut child: Child,
    pid: i32,
    holds: Vec<ScratchHold>,
    probe: GroupProbe,
    wait_child: WaitChildFn,
) {
    signal_group(&mut child, pid);
    let confirmed = pid <= 1
        || child.id().is_none()
        || tokio::time::timeout(FALLBACK_ASYNC_BUDGET, async {
            while !matches!(probe(pid), Ok(true)) {
                signal_group(&mut child, pid);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .is_ok();
    let reaped = confirmed
        && (matches!(tokio::time::timeout(Duration::from_secs(1), wait_child(&mut child)).await, Ok(Ok(_)))
            || child.id().is_none());
    if !reaped {
        eprintln!("rootyard: Git reaper fallback timed out or group probe failed; preserving unverified scratch");
        std::mem::forget(holds);
        handoff_unresolved_child(child, pid);
        return;
    }
    drop(child);
    drop(holds);
}
static UNRESOLVED_QUEUE: std::sync::Mutex<std::collections::VecDeque<(Child, i32)>> =
    std::sync::Mutex::new(std::collections::VecDeque::new());
static UNRESOLVED_ACTIVE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
struct ActiveOwnerGuard(bool);
impl Drop for ActiveOwnerGuard {
    fn drop(&mut self) {
        if self.0 {
            UNRESOLVED_ACTIVE.store(false, std::sync::atomic::Ordering::Release);
        }
    }
}
fn handoff_unresolved_child(mut child: Child, pid: i32) {
    if child.id().is_none() {
        return;
    }
    signal_group(&mut child, pid);
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        let _ = child_gone(&mut child);
        return;
    };
    let mut queue = UNRESOLVED_QUEUE.lock().unwrap_or_else(|e| e.into_inner());
    if queue.len() < UNRESOLVED_OWNER_CAP {
        queue.push_back((child, pid));
        drop(queue);
        ensure_unresolved_owner(&handle);
        return;
    }
    drop(queue);
    let _ = child_gone(&mut child);
}
fn pop_unresolved(active: &mut ActiveOwnerGuard) -> Option<(Child, i32)> {
    let mut queue = UNRESOLVED_QUEUE.lock().unwrap_or_else(|e| e.into_inner());
    let popped = queue.pop_front();
    if popped.is_none() {
        UNRESOLVED_ACTIVE.store(false, std::sync::atomic::Ordering::Release);
        active.0 = false;
    }
    popped
}
fn ensure_unresolved_owner(handle: &tokio::runtime::Handle) {
    if UNRESOLVED_ACTIVE.swap(true, std::sync::atomic::Ordering::AcqRel) {
        return;
    }
    handle.spawn(async move {
        let mut active = ActiveOwnerGuard(true);
        while let Some((mut child, pid)) = pop_unresolved(&mut active) {
            signal_group(&mut child, pid);
            let waited = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
            if !matches!(waited, Ok(Ok(_))) && !child_gone(&mut child) {
                drop(child);
            }
        }
    });
}

fn reap_until_confirmed(mut child: Child, pid: i32, holds: Vec<ScratchHold>, probe: GroupProbe) {
    #[cfg(unix)]
    if pid > 1 {
        let started = std::time::Instant::now();
        let mut reported = false;
        while !matches!(probe(pid), Ok(true)) {
            unsafe { libc::kill(-pid, libc::SIGKILL) };
            if !reported && started.elapsed() > Duration::from_secs(5) {
                eprintln!("rootyard: cancelled Git process group cleanup blocked; retaining scratch hold");
                reported = true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    #[cfg(not(unix))]
    let _ = (pid, probe);
    while !child_gone(&mut child) {
        std::thread::sleep(Duration::from_millis(5));
    }
    drop(holds);
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

pub(crate) async fn run_git_dir_bounded(
    git_bin: &FsPath,
    dir: Option<&FsPath>,
    args: &[&str],
    deadline: Instant,
    fail_error: impl FnOnce() -> Error,
    scratch_hold: Option<ScratchHold>,
) -> Result<Vec<u8>, Error> {
    if Instant::now() >= deadline {
        return Err(Error::timeout());
    }
    let mut guard = UploadPackGroup::spawn_argv(git_bin, dir, args, None, Stdio::null(), scratch_hold)?;
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
    let status = guard.finish(deadline).await?;
    if !status.success() {
        return Err(fail_error());
    }
    Ok(output)
}
