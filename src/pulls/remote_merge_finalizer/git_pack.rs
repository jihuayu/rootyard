//! Isolated stock-Git (`SHA-1` & `SHA-256`) candidate merge object & pack preparation (`Refs #156`).
//!
//! Strictly prepares merged tree/commit objects and self-contained pack bytes without
//! invoking `git update-ref`: Raft `RefCasStateMachine` CAS remains the sole ref commit point.

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Stdio;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use crate::ref_store::core::types::GitObjectFormat;

use super::types::{MergeStrategy, RemoteMergeError, oid_valid_for_format};

#[cfg(unix)]
const NULL_GIT_CONFIG: &str = "/dev/null";
#[cfg(not(unix))]
const NULL_GIT_CONFIG: &str = "NUL";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreparedMergeCandidate {
    pub target_oid: String,
    pub pack_bytes: Vec<u8>,
    pub pack_sha256: String,
    pub object_count: usize,
}

async fn run_isolated_git(
    repo_dir: &Path,
    args: &[&str],
    stdin_bytes: Option<&[u8]>,
    extra_env: &[(&str, &str)],
    deadline: Instant,
) -> Result<Vec<u8>, RemoteMergeError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(RemoteMergeError::UnknownOutcome("git merge preparation deadline exceeded".into()));
    }
    let mut cmd = Command::new("git");
    cmd.args([
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "gc.auto=0",
        "-c",
        "gc.autoDetach=false",
        "-c",
        "maintenance.auto=0",
        "-c",
        "maintenance.autoDetach=false",
        "--no-replace-objects",
        "-C",
    ])
    .arg(repo_dir)
    .args(args)
    .env("GIT_CONFIG_NOSYSTEM", "1")
    .env("GIT_CONFIG_GLOBAL", NULL_GIT_CONFIG)
    .env("GIT_CONFIG_SYSTEM", NULL_GIT_CONFIG)
    .env("GIT_ATTR_NOSYSTEM", "1")
    .env("GIT_NO_REPLACE_OBJECTS", "1")
    .env("GIT_TERMINAL_PROMPT", "0")
    .stdin(if stdin_bytes.is_some() { Stdio::piped() } else { Stdio::null() })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .kill_on_drop(true);
    for &(k, v) in extra_env {
        cmd.env(k, v);
    }

    let mut child = cmd.spawn().map_err(|e| RemoteMergeError::Io(e.to_string()))?;
    let stdin_handle = stdin_bytes.map(|bytes| {
        let payload = bytes.to_vec();
        let stdin = child.stdin.take();
        tokio::spawn(async move {
            if let Some(mut pipe) = stdin {
                pipe.write_all(&payload).await.map_err(|e| RemoteMergeError::Io(e.to_string()))?;
                pipe.shutdown().await.map_err(|e| RemoteMergeError::Io(e.to_string()))?;
            }
            Ok::<(), RemoteMergeError>(())
        })
    });
    let timeout = remaining.min(Duration::from_secs(60));
    let out = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .map_err(|_| RemoteMergeError::UnknownOutcome("git merge subprocess timed out".into()))?
        .map_err(|e| RemoteMergeError::Io(e.to_string()))?;
    if let Some(handle) = stdin_handle {
        let _ = handle.await;
    }
    if !out.status.success() {
        let cmd_name = args.first().copied().unwrap_or("git").to_owned();
        return Err(RemoteMergeError::GitFailed {
            command: cmd_name,
            detail: String::from_utf8_lossy(&out.stderr).trim().to_owned(),
        });
    }
    Ok(out.stdout)
}

#[derive(Clone, Debug)]
pub struct PrepareMergeInput<'a> {
    pub format: GitObjectFormat,
    pub strategy: MergeStrategy,
    pub base_oid: &'a str,
    pub head_oid: &'a str,
    pub author_name: &'a str,
    pub commit_message: &'a str,
}

/// Computes the candidate merged target commit OID (`fast_forward` or 3-way `merge-tree` +
/// `commit-tree`) and emits deterministic self-contained `pack-objects` bytes without
/// mutating any branch ref on disk.
pub async fn prepare_merge_candidate(
    repo_dir: &Path,
    input: &PrepareMergeInput<'_>,
    deadline: Instant,
) -> Result<PreparedMergeCandidate, RemoteMergeError> {
    let format = input.format;
    let base_oid = input.base_oid;
    let head_oid = input.head_oid;
    if !oid_valid_for_format(base_oid, format) || !oid_valid_for_format(head_oid, format) {
        return Err(RemoteMergeError::InvalidInput("invalid base/head OID for repository format".into()));
    }
    run_isolated_git(repo_dir, &["cat-file", "-e", &format!("{base_oid}^{{commit}}")], None, &[], deadline).await?;
    run_isolated_git(repo_dir, &["cat-file", "-e", &format!("{head_oid}^{{commit}}")], None, &[], deadline).await?;

    let target_oid = match input.strategy {
        MergeStrategy::FastForward => {
            if run_isolated_git(repo_dir, &["merge-base", "--is-ancestor", base_oid, head_oid], None, &[], deadline)
                .await
                .is_err()
            {
                return Err(RemoteMergeError::FastForwardNotPossible(format!(
                    "head {head_oid} is not a descendant of base {base_oid}"
                )));
            }
            head_oid.to_owned()
        }
        MergeStrategy::MergeCommit => {
            let tree_raw =
                run_isolated_git(repo_dir, &["merge-tree", "--write-tree", base_oid, head_oid], None, &[], deadline)
                    .await
                    .map_err(|e| RemoteMergeError::MergeConflict(e.to_string()))?;
            let tree_str = String::from_utf8(tree_raw).map_err(|e| RemoteMergeError::Io(e.to_string()))?;
            let tree_oid = tree_str.lines().next().unwrap_or("").trim().to_owned();
            if !oid_valid_for_format(&tree_oid, format) {
                return Err(RemoteMergeError::GitFailed {
                    command: "merge-tree".into(),
                    detail: format!("unexpected tree OID `{tree_oid}`"),
                });
            }
            let author_email = format!("{}@rootyard.local", input.author_name);
            let env_vars = [
                ("GIT_AUTHOR_NAME", input.author_name),
                ("GIT_AUTHOR_EMAIL", author_email.as_str()),
                ("GIT_AUTHOR_DATE", "1700000000 +0000"),
                ("GIT_COMMITTER_NAME", input.author_name),
                ("GIT_COMMITTER_EMAIL", author_email.as_str()),
                ("GIT_COMMITTER_DATE", "1700000000 +0000"),
            ];
            let commit_raw = run_isolated_git(
                repo_dir,
                &["commit-tree", &tree_oid, "-p", base_oid, "-p", head_oid, "-m", input.commit_message],
                None,
                &env_vars,
                deadline,
            )
            .await?;
            let cid = String::from_utf8(commit_raw)
                .map_err(|e| RemoteMergeError::Io(e.to_string()))?
                .trim()
                .to_owned();
            if !oid_valid_for_format(&cid, format) {
                return Err(RemoteMergeError::GitFailed {
                    command: "commit-tree".into(),
                    detail: format!("unexpected commit OID `{cid}`"),
                });
            }
            cid
        }
    };

    let rev_spec = format!("{base_oid}..{target_oid}");
    let rev_raw = run_isolated_git(repo_dir, &["rev-list", "--objects", &rev_spec], None, &[], deadline).await?;
    let rev_txt = String::from_utf8(rev_raw).map_err(|e| RemoteMergeError::Io(e.to_string()))?;
    let mut oids = BTreeSet::new();
    for line in rev_txt.lines() {
        if let Some(oid) = line.split_whitespace().next()
            && !oid.is_empty()
        {
            oids.insert(oid.to_owned());
        }
    }
    if oids.is_empty() {
        oids.insert(target_oid.clone());
    }
    let mut stdin_list = String::new();
    for oid in &oids {
        stdin_list.push_str(oid);
        stdin_list.push('\n');
    }
    let pack_bytes =
        run_isolated_git(repo_dir, &["pack-objects", "--stdout", "-q"], Some(stdin_list.as_bytes()), &[], deadline)
            .await?;
    let pack_sha256 = hex::encode(Sha256::digest(&pack_bytes));
    Ok(PreparedMergeCandidate { target_oid, pack_bytes, pack_sha256, object_count: oids.len() })
}
