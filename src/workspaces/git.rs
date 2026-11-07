//! Bounded native Git execution for workspace file and mutation routes.
//!
//! The previous wrapper used `std::process::Command::output`, which blocked an
//! async worker, buffered unbounded stdout/stderr, and had no deadline or
//! process-group cleanup. This facade always builds a hardened Git command and
//! delegates to the shared bounded collector used by GitFS and maintenance.
use crate::{AppState, Error};
use std::{path::Path, process::Stdio};
use tokio::process::Command;

pub(super) async fn run(state: &AppState, repo: &Path, args: &[&str], limit: usize) -> Result<Vec<u8>, Error> {
    collect(command(repo, args), limit, state.config.git_timeout).await
}

fn command(repo: &Path, args: &[&str]) -> Command {
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
    command
}

async fn collect(command: Command, limit: usize, timeout: std::time::Duration) -> Result<Vec<u8>, Error> {
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
    use axum::http::StatusCode;
    use std::time::{Duration, Instant};

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
}
