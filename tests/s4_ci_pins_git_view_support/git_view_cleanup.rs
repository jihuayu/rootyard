//! Process and scratch observations for the bounded Git View acceptance cases.
use anyhow::{Result, ensure};
use std::{path::PathBuf, time::Duration};

pub(super) async fn wait_scratch_gone(scratch: &str, leader: &str, descendant: &str) -> Result<()> {
    ensure!(!scratch.is_empty(), "the stalled Git child did not publish its scratch directory");
    let root = PathBuf::from(scratch);
    for _ in 0..200 {
        if !root.exists() {
            let leader_state = child_state(leader);
            let descendant_state = child_state(descendant);
            ensure!(
                leader_state == "missing" && matches!(descendant_state, "missing" | "zombie" | "dead"),
                "Git view scratch was deleted before process cleanup: leader={leader_state}, descendant={descendant_state}"
            );
            if descendant_state == "missing" {
                return Ok(());
            }
            // The service reaps its direct child. Linux may still be handing an
            // exited, reparented descendant to that process's new parent.
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    ensure!(!root.exists(), "the Git view scratch directory was never removed: {}", root.display());
    Err(anyhow::anyhow!("the Git view descendant was not reaped within the cleanup bound: {}", child_state(descendant)))
}

fn child_state(pid: &str) -> &'static str {
    let stat = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => stat,
        Err(err) => return if err.kind() == std::io::ErrorKind::NotFound { "missing" } else { "unknown" },
    };
    let Some((_, tail)) = stat.rsplit_once(')') else { return "unknown" };
    match tail.split_whitespace().next() {
        Some("Z") => "zombie",
        Some("X" | "x") => "dead",
        Some("R" | "S" | "D" | "T" | "t" | "W" | "K" | "P" | "I") => "live",
        _ => "unknown",
    }
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::*;

    #[tokio::test]
    async fn removed_scratch_can_wait_for_an_exited_descendant_to_be_reaped() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let scratch = temp.path().join("removed");
        let mut leader = std::process::Command::new("true").spawn()?;
        let mut descendant = std::process::Command::new("true").spawn()?;
        let leader_pid = leader.id().to_string();
        let descendant_pid = descendant.id().to_string();
        leader.wait()?;
        for _ in 0..200 {
            if child_state(&descendant_pid) == "zombie" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let state_before_reap = child_state(&descendant_pid);
        let check = wait_scratch_gone(scratch.to_str().unwrap(), &leader_pid, &descendant_pid);
        tokio::pin!(check);
        let before_reap = futures_util::poll!(check.as_mut());
        descendant.wait()?;
        ensure!(state_before_reap == "zombie", "the fixture did not observe its exited descendant");
        ensure!(before_reap.is_pending(), "cleanup resolved before the descendant was reaped: {before_reap:?}");
        check.await
    }

    #[tokio::test]
    async fn removed_scratch_rejects_a_live_descendant_immediately() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let scratch = temp.path().join("removed");
        let mut leader = std::process::Command::new("true").spawn()?;
        let leader_pid = leader.id().to_string();
        leader.wait()?;
        let mut descendant = std::process::Command::new("sleep").arg("30").spawn()?;
        let descendant_pid = descendant.id().to_string();
        let check = wait_scratch_gone(scratch.to_str().unwrap(), &leader_pid, &descendant_pid);
        tokio::pin!(check);
        let result = futures_util::poll!(check.as_mut());
        descendant.kill()?;
        descendant.wait()?;
        ensure!(
            matches!(result, std::task::Poll::Ready(Err(_))),
            "cleanup did not reject a live descendant: {result:?}"
        );
        Ok(())
    }
}
