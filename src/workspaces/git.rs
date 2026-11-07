//! Bounded native Git execution for workspace file and mutation routes.
//!
//! The previous wrapper used `std::process::Command::output`, which blocked an
//! async worker, buffered unbounded stdout/stderr, and had no deadline or
//! process-group cleanup. This facade always builds a hardened Git command and
//! delegates to the shared bounded collector used by GitFS and maintenance.
//!
//! # Discovery and disconnect contract
//!
//! A mutation request is answered by an *owned* Tokio job. The outer HTTP
//! handler only extracts the request inputs, reserves one `git_slots` permit
//! and awaits the job result. Authentication, the DB client and transaction,
//! the `FOR UPDATE` row lock and lease checks, the native Git child, and the
//! fingerprint/event/idempotency commit all run inside that job. If the caller
//! disconnects, only the response future is dropped; the job still reaches its
//! normal bounded deadline and commit. The client therefore cannot distinguish
//! "not applied" from "applied but response lost" and must retry with the same
//! `Idempotency-Key`: the committed `workspace_operations` row replays the
//! original result instead of repeating the mutation. A concurrent retry
//! waits on the retained row lock and then replays the same result.
//!
//! Jobs are admitted only after taking a permit, so the registry can never
//! exceed Git capacity. Completed jobs are pruned on admission, and `drain`
//! joins all of them during graceful HTTP shutdown before the runtime exits.
//! The configured grace duration is a *warning* threshold only: owned jobs are
//! never detached, aborted or handed back to process drop while the runtime can
//! still join them, so a real index mutation always reaches its bounded finish
//! or child cleanup. A hard shutdown bound would need cooperative child
//! cancellation inside the collector and is deliberately out of scope. An
//! operator who force-kills the process (`SIGKILL`, power loss) leaves that
//! guarantee; a later retry of an unknown mutation must reuse the same
//! `Idempotency-Key`. This module never unlinks
//! `.git/index.lock` or any other lock it did not observe being created by its
//! own child and finish cleanly, so a pre-existing foreign lock is preserved
//! and the operation fails cleanly instead of deleting someone else's state.
use crate::{AppState, Error};
use axum::http::StatusCode;
use std::{
    future::Future,
    path::Path,
    process::Stdio,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
use tokio::{
    process::Command,
    sync::{OwnedSemaphorePermit, Semaphore, oneshot},
    task::JoinSet,
};

/// Reserve the single native Git child permit for one workspace operation.
/// This happens before any DB transaction is opened, so overload is a retryable
/// 503 that never holds a workspace row lock.
pub(super) fn try_slot(state: &AppState) -> Result<OwnedSemaphorePermit, Error> {
    slot(&state.git_slots)
}

fn slot(slots: &Arc<Semaphore>) -> Result<OwnedSemaphorePermit, Error> {
    slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error(StatusCode::SERVICE_UNAVAILABLE, "Git capacity exhausted; retry later"))
}

/// Read-only managed Git for HEAD/index views. The owned permit is held for the
/// whole child lifetime and released when this future completes or is
/// cancelled, so concurrent read views stay within the shared Git capacity.
pub(super) async fn run(state: &AppState, repo: &Path, args: &[&str], limit: usize) -> Result<Vec<u8>, Error> {
    let _slot = try_slot(state)?;
    collect(command(repo, args), limit, state.config.git_timeout).await
}

/// Narrow mutation path: the owned job already holds the `git_slots` permit, so
/// this never acquires a second one and never releases it early.
pub(super) async fn run_in_job(repo: &Path, args: &[&str], limit: usize, timeout: Duration) -> Result<Vec<u8>, Error> {
    run_in_job_env(repo, args, limit, timeout, &[]).await
}

async fn run_in_job_env(
    repo: &Path,
    args: &[&str],
    limit: usize,
    timeout: Duration,
    env: &[(String, String)],
) -> Result<Vec<u8>, Error> {
    collect(command_env(repo, args, env), limit, timeout).await
}

fn jobs() -> &'static Mutex<JoinSet<()>> {
    static JOBS: OnceLock<Mutex<JoinSet<()>>> = OnceLock::new();
    JOBS.get_or_init(|| Mutex::new(JoinSet::new()))
}

/// Register one self-contained mutation job and return the channel that carries
/// its response. Dropping the receiver discards only the response: the job is
/// not tied to the caller and still finishes normally.
pub(super) fn spawn_job<T, F>(future: F) -> oneshot::Receiver<T>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let (sender, receiver) = oneshot::channel();
    let mut jobs = match jobs().lock() {
        Ok(jobs) => jobs,
        Err(poisoned) => poisoned.into_inner(),
    };
    // The registry is bounded by Git permits; pruning completed handles here
    // keeps it from growing with request count. Panics are logged without the
    // payload; the lost oneshot sender already tells the client "no result".
    while let Some(finished) = jobs.try_join_next() {
        if let Err(error) = finished {
            if !error.is_cancelled() {
                eprintln!("rootyard: owned workspace Git job failed");
            }
        }
    }
    jobs.spawn(async move {
        let _ = sender.send(future.await);
    });
    receiver
}

/// Drain every owned job during graceful shutdown. The registry is taken as a
/// whole so new admissions cannot extend the wait. `grace` is only a warning
/// threshold: once it elapses the operator is told that shutdown is still
/// waiting, and every owned job is still joined to completion. Aborting here
/// would drop a live child into the collector's immediate process-group kill
/// and could leave a real `.git/index.lock` behind, so no job is ever detached
/// or aborted; only an operator force-kill ends the wait early.
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
                Some(Ok(())) => {}
                Some(Err(error)) => {
                    if !error.is_cancelled() {
                        eprintln!("rootyard: owned workspace Git job failed during shutdown");
                    }
                }
            },
            // Sanitized, constant, logged once: a slow job is not an error and
            // must not leak repository paths or client data into the log.
            _ = tokio::time::sleep_until(deadline), if !warned => {
                warned = true;
                eprintln!("rootyard: owned workspace Git jobs still running after shutdown grace; waiting for them to finish");
            },
        }
    }
}

fn command(repo: &Path, args: &[&str]) -> Command {
    command_env(repo, args, &[])
}

/// Same hardened command plus an explicit environment. Production passes no
/// extra variables; the real-Git disconnect test injects an `LD_PRELOAD`
/// rename gate into its own child so the disconnect happens while the native
/// index lock is live.
fn command_env(repo: &Path, args: &[&str], env: &[(String, String)]) -> Command {
    let mut command = Command::new("git");
    command
        .arg("-c")
        .arg("core.hooksPath=/dev/null")
        .arg("--no-replace-objects")
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
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
        // A rejected path or an over-sized object is a client conflict, exactly
        // like the previous exit-status check.
        Err(super::service::conflict())
    } else {
        // Spawn failures and pipe errors must not masquerade as a conflict.
        Err(Error::internal(text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::Instant;

    fn shell(script: &str, pid_file: Option<&Path>) -> Command {
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg(script);
        if let Some(path) = pid_file {
            command.arg("leader").arg(path);
        }
        command
    }

    fn descendant_running(pid: u32) -> bool {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Err(_) => false,
            Ok(stat) => stat.rsplit_once(") ").is_some_and(|(_, tail)| !tail.starts_with('Z')),
        }
    }

    async fn wait_for_pid(path: &Path) -> u32 {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(raw) = std::fs::read_to_string(path) {
                if let Ok(pid) = raw.trim().parse() {
                    return pid;
                }
            }
            assert!(Instant::now() < deadline, "test child did not start");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    fn git(repo: &Path, args: &[&str]) {
        let output = std::process::Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["-c", "user.name=Workspace", "-c", "user.email=workspace@example.invalid"])
            .args(["-c", "commit.gpgsign=false"])
            .args(args)
            .output()
            .expect("run fixture git");
        assert!(output.status.success(), "fixture git {args:?} failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    fn committed_repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        git(dir.path(), &["init", "-q"]);
        std::fs::write(dir.path().join("committed.txt"), b"committed").unwrap();
        git(dir.path(), &["add", "--", "committed.txt"]);
        git(dir.path(), &["commit", "-q", "-m", "base"]);
        dir
    }

    #[tokio::test]
    async fn huge_stdout_is_rejected_without_waiting_for_eof() {
        let started = Instant::now();
        let error = collect(shell("head -c 200000 /dev/zero", None), 4096, Duration::from_secs(5)).await.unwrap_err();
        assert_eq!(error.0, StatusCode::CONFLICT);
        assert!(started.elapsed() < Duration::from_secs(4), "stdout cap was not enforced");
    }

    #[tokio::test]
    async fn huge_stderr_is_drained_without_deadlock() {
        let output = collect(shell("head -c 400000 /dev/zero >&2; printf ok", None), 4096, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(output, b"ok");
    }

    #[tokio::test]
    async fn deadline_cancels_the_whole_process_group() {
        let root = tempfile::tempdir().unwrap();
        let pid_file = root.path().join("child.pid");
        let script = "sh -c 'trap \"\" TERM; echo $$ > \"$1\"; while :; do sleep 1; done' child \"$1\" & sleep 100";
        let started = Instant::now();
        let error = collect(shell(script, Some(&pid_file)), 4096, Duration::from_millis(200)).await.unwrap_err();
        assert_eq!(error.0, StatusCode::GATEWAY_TIMEOUT);
        assert!(started.elapsed() < Duration::from_secs(6));
        let pid = wait_for_pid(&pid_file).await;
        assert!(!descendant_running(pid), "timed-out Git descendant survived group cleanup");
    }

    #[tokio::test]
    async fn cancellation_drops_the_process_group() {
        let root = tempfile::tempdir().unwrap();
        let pid_file = root.path().join("child.pid");
        let script = "sh -c 'trap \"\" TERM; echo $$ > \"$1\"; while :; do sleep 1; done' child \"$1\" & sleep 100";
        let outcome = tokio::time::timeout(
            Duration::from_millis(500),
            collect(shell(script, Some(&pid_file)), 4096, Duration::from_secs(30)),
        )
        .await;
        assert!(outcome.is_err(), "cancelled collection unexpectedly completed");
        let pid = wait_for_pid(&pid_file).await;
        let deadline = Instant::now() + Duration::from_secs(5);
        while descendant_running(pid) {
            assert!(Instant::now() < deadline, "cancelled Git descendant survived");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn native_git_success_is_returned_with_bounded_output() {
        let mut command = Command::new("git");
        command.arg("--version");
        let output = collect(command, 4096, Duration::from_secs(10)).await.unwrap();
        assert!(output.starts_with(b"git version"));
    }

    #[test]
    fn capacity_exhaustion_is_a_retryable_503() {
        let slots = Arc::new(Semaphore::new(1));
        let permit = slot(&slots).unwrap();
        assert_eq!(slot(&slots).unwrap_err().0, StatusCode::SERVICE_UNAVAILABLE);
        drop(permit);
        assert!(slot(&slots).is_ok());
    }

    /// Serializes the tests that observe the process-global owned-job registry.
    async fn job_test_lock() -> tokio::sync::MutexGuard<'static, ()> {
        static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        SERIAL.lock().await
    }

    /// Compile the rename gate (see `tests/fixtures/rename_gate.c`) and return
    /// the owning directory plus the library and flag paths.
    fn gate() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("rename_gate.c");
        std::fs::write(&source, include_str!("../../tests/fixtures/rename_gate.c")).unwrap();
        let library = dir.path().join("librootyard_rename_gate.so");
        let compiled = std::process::Command::new("cc")
            .args(["-shared", "-fPIC", "-O1", "-o"])
            .arg(&library)
            .arg(&source)
            .output()
            .expect("run cc for the rename gate");
        assert!(compiled.status.success(), "cc failed: {}", String::from_utf8_lossy(&compiled.stderr));
        let flag = dir.path().join("gate.flag");
        (dir, library, flag)
    }

    fn gate_env(library: &Path, flag: &Path) -> Vec<(String, String)> {
        vec![
            ("LD_PRELOAD".to_owned(), library.to_str().unwrap().to_owned()),
            ("ROOTYARD_GATE_MARKER".to_owned(), "index.lock".to_owned()),
            ("ROOTYARD_GATE_FLAG".to_owned(), flag.to_str().unwrap().to_owned()),
        ]
    }

    async fn wait_for_gate(flag: &Path, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while !flag.exists() {
            assert!(Instant::now() < deadline, "Git never reached the index.lock commit");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn disconnect_with_a_live_real_index_lock_keeps_the_owned_add() {
        let _serial = job_test_lock().await;
        let (gate_dir, library, flag) = gate();
        let dir = committed_repo();
        let repo = dir.path().to_path_buf();
        std::fs::write(repo.join("staged.txt"), b"staged").unwrap();
        let slots = Arc::new(Semaphore::new(1));
        let permit = slot(&slots).unwrap();
        let (finished_tx, finished_rx) = oneshot::channel();
        let env = gate_env(&library, &flag);
        let path = repo.clone();
        let args = ["add", "--", "staged.txt"];
        let response = spawn_job(async move {
            // The permit travels with the job, not with the response future.
            let _permit = permit;
            let result = run_in_job_env(&path, &args, 64 * 1024, Duration::from_secs(60), &env).await;
            let _ = finished_tx.send(());
            result
        });
        // The real child is now stopped inside `add`, holding `.git/index.lock`
        // and about to commit it: the disconnect below happens in that window.
        wait_for_gate(&flag, Duration::from_secs(30)).await;
        let lock = repo.join(".git/index.lock");
        assert!(lock.exists(), "the gate fired without a live index.lock");
        drop(response);
        assert_eq!(
            slot(&slots).unwrap_err().0,
            StatusCode::SERVICE_UNAVAILABLE,
            "a dropped response released the job's Git capacity"
        );
        std::fs::remove_file(&flag).unwrap();
        tokio::time::timeout(Duration::from_secs(30), finished_rx)
            .await
            .expect("owned job did not finish after the caller disconnected")
            .expect("owned job dropped its completion signal");
        assert!(!lock.exists(), "Git left an index lock");
        let staged = std::process::Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(["ls-files", "--stage", "--", "staged.txt"])
            .output()
            .unwrap();
        assert!(staged.status.success());
        assert!(
            String::from_utf8_lossy(&staged.stdout).contains("staged.txt"),
            "the owned add did not reach the index"
        );
        assert!(slot(&slots).is_ok(), "capacity was not released after the child settled");
        run_in_job(&repo, &["reset", "HEAD", "--", "staged.txt"], 64 * 1024, Duration::from_secs(30)).await.unwrap();
        assert!(!lock.exists());
        drop(gate_dir);
    }

    #[tokio::test]
    async fn drain_warns_past_grace_but_joins_the_owned_job() {
        let _serial = job_test_lock().await;
        let (gate_dir, library, flag) = gate();
        let dir = committed_repo();
        let repo = dir.path().to_path_buf();
        std::fs::write(repo.join("staged.txt"), b"staged").unwrap();
        let slots = Arc::new(Semaphore::new(1));
        let permit = slot(&slots).unwrap();
        let (finished_tx, finished_rx) = oneshot::channel();
        let env = gate_env(&library, &flag);
        let path = repo.clone();
        let args = ["add", "--", "staged.txt"];
        let response = spawn_job(async move {
            let _permit = permit;
            let result = run_in_job_env(&path, &args, 64 * 1024, Duration::from_secs(60), &env).await;
            let _ = finished_tx.send(());
            result
        });
        wait_for_gate(&flag, Duration::from_secs(30)).await;
        let lock = repo.join(".git/index.lock");
        assert!(lock.exists(), "the gate fired without a live index.lock");
        // The caller is gone and shutdown passes its grace window while the
        // owned child still holds the real index lock.
        drop(response);
        let shutdown = tokio::spawn(drain(Duration::from_millis(50)));
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!shutdown.is_finished(), "drain aborted or detached an owned job after the grace warning threshold");
        assert!(lock.exists(), "the owned child was torn down while the index lock was live");
        std::fs::remove_file(&flag).unwrap();
        tokio::time::timeout(Duration::from_secs(30), shutdown)
            .await
            .expect("drain did not return after the owned job finished")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(30), finished_rx)
            .await
            .expect("owned job did not finish during drain")
            .expect("owned job dropped its completion signal");
        assert!(!lock.exists(), "Git left an index lock");
        assert!(slot(&slots).is_ok(), "capacity was not released after drain");
        drop(gate_dir);
    }

    #[tokio::test]
    async fn foreign_index_lock_is_preserved_and_the_mutation_fails_cleanly() {
        let dir = committed_repo();
        let repo = dir.path().to_path_buf();
        std::fs::write(repo.join("staged.txt"), b"staged").unwrap();
        let foreign = repo.join(".git/index.lock");
        std::fs::write(&foreign, b"another writer\n").unwrap();
        let error =
            run_in_job(&repo, &["add", "--", "staged.txt"], 64 * 1024, Duration::from_secs(30)).await.unwrap_err();
        assert_eq!(error.0, StatusCode::CONFLICT);
        assert_eq!(std::fs::read(&foreign).unwrap(), b"another writer\n");
    }

    #[tokio::test]
    async fn timed_out_owned_job_releases_capacity_after_clean_cleanup() {
        let slots = Arc::new(Semaphore::new(1));
        let permit = slot(&slots).unwrap();
        let (finished_tx, finished_rx) = oneshot::channel();
        let response = spawn_job(async move {
            let _permit = permit;
            let result = collect(shell("sleep 100", None), 4096, Duration::from_millis(200)).await;
            let _ = finished_tx.send(());
            result
        });
        drop(response);
        let result = tokio::time::timeout(Duration::from_secs(15), finished_rx)
            .await
            .expect("timed-out owned job did not finish")
            .unwrap();
        assert_eq!(result.unwrap_err().0, StatusCode::GATEWAY_TIMEOUT);
        assert!(slot(&slots).is_ok(), "a timed-out job retained Git capacity");
    }
}
