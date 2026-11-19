//! Bounded native Git execution for workspace file and mutation routes.
//!
//! Read-only Git views and post-clone `rev-parse` share `state.git_slots` and
//! `collect_git_output` (process group, drained stderr, capped stdout, deadline,
//! group kill/reap on drop or timeout). Child environments are scrubbed via
//! `env_clear()` and honor `state.config.git`. Mutations reserve a capacity
//! permit up front and run inside an owned `JoinSet` job drained on shutdown so
//! client disconnects never strand `.git/index.lock` or split baselines.
use crate::{AppState, Error};
use axum::http::StatusCode;
use std::{
    future::Future,
    path::Path,
    process::Stdio,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    process::Command,
    sync::{OwnedSemaphorePermit, Semaphore, oneshot},
    task::JoinSet,
};

pub(super) fn ensure_admission_open() -> Result<(), Error> {
    if ADMISSION_OPEN.load(Ordering::Acquire) {
        Ok(())
    } else {
        Err(Error(StatusCode::SERVICE_UNAVAILABLE, "workspace admission is closed for shutdown"))
    }
}

pub(super) fn try_slot(state: &AppState) -> Result<OwnedSemaphorePermit, Error> {
    ensure_admission_open()?;
    slot(&state.git_slots)
}

/// Stop admitting new workspace Git work before shutdown drains accepted jobs.
/// Jobs that already hold a permit remain owned in the JoinSet.
pub(crate) fn close_admission() {
    ADMISSION_OPEN.store(false, Ordering::Release);
}

static ADMISSION_OPEN: AtomicBool = AtomicBool::new(true);

fn slot(slots: &Arc<Semaphore>) -> Result<OwnedSemaphorePermit, Error> {
    slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error(StatusCode::SERVICE_UNAVAILABLE, "Git capacity exhausted; retry later"))
}

pub(super) async fn run(state: &AppState, repo: &Path, args: &[&str], limit: usize) -> Result<Vec<u8>, Error> {
    let _slot = try_slot(state)?;
    collect(command_with_git(&state.config.git, repo, args), limit, state.config.git_timeout).await
}

pub(super) async fn run_in_job_with_git(
    git_bin: &Path,
    repo: &Path,
    args: &[&str],
    limit: usize,
    timeout: Duration,
) -> Result<Vec<u8>, Error> {
    collect(command_env_git(git_bin, repo, args, &[]), limit, timeout).await
}

#[cfg(test)]
pub(super) async fn run_in_job(repo: &Path, args: &[&str], limit: usize, timeout: Duration) -> Result<Vec<u8>, Error> {
    run_in_job_env(repo, args, limit, timeout, &[]).await
}

#[cfg(test)]
async fn run_in_job_env(
    repo: &Path,
    args: &[&str],
    limit: usize,
    timeout: Duration,
    env: &[(String, String)],
) -> Result<Vec<u8>, Error> {
    collect(command_env(repo, args, env), limit, timeout).await
}

fn jobs() -> &'static Mutex<JoinSet<bool>> {
    static JOBS: OnceLock<Mutex<JoinSet<bool>>> = OnceLock::new();
    JOBS.get_or_init(|| Mutex::new(JoinSet::new()))
}

/// Retain unfinished owned jobs after the bounded shutdown drain expires. The
/// JoinSet is intentionally not dropped: dropping an accepted job would cancel
/// its future (and its process cleanup) before ownership is proved.
fn held_jobs() -> &'static Mutex<Option<JoinSet<bool>>> {
    static HELD: OnceLock<Mutex<Option<JoinSet<bool>>>> = OnceLock::new();
    HELD.get_or_init(|| Mutex::new(None))
}

pub(super) trait JobOutcome {
    fn failed(&self) -> bool;
}

impl<T, E> JobOutcome for Result<T, E> {
    fn failed(&self) -> bool {
        self.is_err()
    }
}

fn hold_unfinished(jobs: JoinSet<bool>) {
    let mut held = match held_jobs().lock() {
        Ok(held) => held,
        Err(poisoned) => poisoned.into_inner(),
    };
    if held.is_none() {
        *held = Some(jobs);
    } else {
        // A second shutdown drain cannot happen in one process; if it does,
        // retain the newer owned set rather than dropping it inside a timeout.
        std::mem::forget(jobs);
    }
}

pub(super) fn spawn_job<T, F>(future: F) -> oneshot::Receiver<T>
where
    F: Future<Output = T> + Send + 'static,
    T: JobOutcome + Send + 'static,
{
    let (sender, receiver) = oneshot::channel();
    let mut jobs = match jobs().lock() {
        Ok(jobs) => jobs,
        Err(poisoned) => poisoned.into_inner(),
    };
    while let Some(finished) = jobs.try_join_next() {
        if let Err(error) = finished
            && !error.is_cancelled()
        {
            eprintln!("rootyard: owned workspace Git job failed");
        }
    }
    jobs.spawn(async move {
        let outcome = future.await;
        let failed = outcome.failed();
        let _ = sender.send(outcome);
        failed
    });
    receiver
}

pub(crate) async fn drain(grace: Duration) {
    let mut jobs = {
        let mut jobs = match jobs().lock() {
            Ok(jobs) => jobs,
            Err(poisoned) => poisoned.into_inner(),
        };
        std::mem::take(&mut *jobs)
    };
    if jobs.is_empty() {
        return;
    }
    let deadline = tokio::time::Instant::now() + grace;
    let mut warned = false;
    loop {
        tokio::select! {
            finished = jobs.join_next() => match finished {
                None => break,
                Some(Ok(failed)) => {
                    if failed {
                        eprintln!("rootyard: owned workspace Git job failed during shutdown");
                    }
                }
                Some(Err(error)) => {
                    if !error.is_cancelled() {
                        eprintln!("rootyard: owned workspace Git job failed during shutdown");
                    }
                }
            },
            _ = tokio::time::sleep_until(deadline), if !warned => {
                warned = true;
                eprintln!("rootyard: owned workspace Git jobs still running after shutdown grace; waiting for them to finish");
            },
        }
    }
}

/// Bounded shutdown drain for the retained owned-job set. Returns true only
/// when every job joined and no native process cleanup failure was recorded.
/// A joined business/job error is not a cleanup success claim; a cancelled job,
/// JoinError, deadline expiry, or unproved process-group quiescence fails. On
/// deadline the unfinished set is retained in `held_jobs` (not dropped).
pub(crate) async fn drain_until(deadline: tokio::time::Instant) -> bool {
    let mut jobs = {
        let mut jobs = match jobs().lock() {
            Ok(jobs) => jobs,
            Err(poisoned) => poisoned.into_inner(),
        };
        std::mem::take(&mut *jobs)
    };
    if jobs.is_empty() {
        return !super::process_cleanup_failed();
    }
    let mut failed = false;
    loop {
        if tokio::time::Instant::now() >= deadline {
            hold_unfinished(jobs);
            eprintln!("rootyard: owned workspace Git jobs did not join within the shutdown deadline");
            return false;
        }
        let next = tokio::time::timeout_at(deadline, jobs.join_next()).await;
        match next {
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(_))) => {
                // A cancelled/panicked owned task is not a successful join.
                failed = true;
            }
            Ok(None) => return !failed && !super::process_cleanup_failed(),
            Err(_) => {
                hold_unfinished(jobs);
                eprintln!("rootyard: owned workspace Git jobs did not join within the shutdown deadline");
                return false;
            }
        }
    }
}

fn command_with_git(git_bin: &Path, repo: &Path, args: &[&str]) -> Command {
    command_env_git(git_bin, repo, args, &[])
}

#[cfg(test)]
fn command_env(repo: &Path, args: &[&str], env: &[(String, String)]) -> Command {
    command_env_git(Path::new("git"), repo, args, env)
}

fn command_env_git(git_bin: &Path, repo: &Path, args: &[&str], env: &[(String, String)]) -> Command {
    let mut command = Command::new(git_bin);
    command
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_else(|| "/usr/local/bin:/usr/bin:/bin".into()))
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .arg("-c")
        .arg("core.hooksPath=/dev/null")
        .arg("-c")
        .arg("core.fsmonitor=false")
        .arg("-c")
        .arg("gc.auto=0")
        .arg("-c")
        .arg("maintenance.auto=false")
        .arg("--no-replace-objects")
        .arg("-C")
        .arg(repo)
        .args(args)
        .stdin(Stdio::null());
    for (key, value) in env {
        command.env(key, value);
    }
    command
}

async fn collect(command: Command, limit: usize, timeout: Duration) -> Result<Vec<u8>, Error> {
    let error = match crate::git_http::collect_git_output(command, limit, timeout).await {
        Ok(bytes) => return Ok(bytes),
        Err(error) => error,
    };
    let text = error.to_string();
    if text.contains("timed out") {
        Err(Error::timeout())
    } else if text.contains("exceeds limit") || text.contains("Git command failed") {
        Err(super::service::conflict())
    } else {
        Err(Error::internal(text))
    }
}

#[cfg(test)]
#[path = "git_tests.rs"]
mod tests;
