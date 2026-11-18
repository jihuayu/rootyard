//! Production `lfs_locks` conflict query and quarantined Git tree/log inspection (`Refs #145`).

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use super::pg_store::{PgLfsBlobStore, pg_err};
use super::types::{LfsBlobError, LfsProofRejectCode, LfsRefUpdateSpec};

pub fn valid_lfs_lock_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 1024
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
        && path.split('/').all(|p| !p.is_empty() && p != "." && p != "..")
}

impl PgLfsBlobStore {
    /// Checks Rootyard's authoritative `lfs_locks JOIN users` table for any path modified by a push
    /// that is currently locked by a user other than `actor_id`.
    pub async fn find_conflicting_lock(
        &self,
        repository_id: Uuid,
        actor_id: Uuid,
        touched_paths: &[String],
    ) -> Result<Option<(String, String)>, LfsBlobError> {
        if touched_paths.is_empty() {
            return Ok(None);
        }
        let client = self.pool().get().await.map_err(pg_err)?;
        let row = client
            .query_opt(
                "SELECT l.path, u.username
                 FROM lfs_locks l
                 JOIN users u ON u.id = l.owner_user_id
                 WHERE l.repository_id = $1
                   AND l.path = ANY($2::text[])
                   AND l.owner_user_id <> $3
                 ORDER BY l.path ASC
                 LIMIT 1",
                &[&repository_id, &touched_paths, &actor_id],
            )
            .await
            .map_err(pg_err)?;
        Ok(row.map(|r| (r.get(0), r.get(1))))
    }
}

pub(super) async fn run_git_quarantined(
    git_dir: &Path,
    git_obj_dir: Option<&str>,
    git_alt_dirs: Option<&str>,
    timeout: Duration,
    args: &[&str],
    stdin_bytes: &[u8],
) -> Result<Vec<u8>, LfsBlobError> {
    let mut cmd = tokio::process::Command::new("git");
    cmd.env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("LC_ALL", "C")
        .args(["-c", "core.hooksPath=/dev/null", "--no-replace-objects", "--git-dir"])
        .arg(git_dir)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(obj) = git_obj_dir.filter(|s| !s.is_empty()) {
        cmd.env("GIT_OBJECT_DIRECTORY", obj);
    }
    if let Some(alt) = git_alt_dirs.filter(|s| !s.is_empty()) {
        cmd.env("GIT_ALTERNATE_OBJECT_DIRECTORIES", alt);
    }
    let mut child =
        cmd.spawn().map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, format!("git spawn: {e}")))?;
    if let Some(mut stdin) = child.stdin.take() {
        let payload = stdin_bytes.to_vec();
        tokio::spawn(async move {
            let _ = stdin.write_all(&payload).await;
        });
    }
    let mut stdout = child.stdout.take().ok_or_else(|| LfsBlobError::new(LfsProofRejectCode::InvalidInput, "stdout"))?;
    let mut stderr = child.stderr.take().ok_or_else(|| LfsBlobError::new(LfsProofRejectCode::InvalidInput, "stderr"))?;
    tokio::time::timeout(timeout, async move {
        let mut out = Vec::new();
        stdout
            .read_to_end(&mut out)
            .await
            .map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
        let mut err_buf = Vec::new();
        let _ = stderr.read_to_end(&mut err_buf).await;
        let status = child.wait().await.map_err(|e| LfsBlobError::new(LfsProofRejectCode::InvalidInput, e.to_string()))?;
        if !status.success() {
            return Err(LfsBlobError::new(
                LfsProofRejectCode::InvalidInput,
                format!("git {:?} failed: {}", args, String::from_utf8_lossy(&err_buf).trim()),
            ));
        }
        Ok(out)
    })
    .await
    .map_err(|_| LfsBlobError::new(LfsProofRejectCode::RemoteBlobUnreachable, "git inspection timed out"))?
}

pub(super) async fn collect_touched_paths(
    git_dir: &Path,
    git_obj_dir: Option<&str>,
    git_alt_dirs: Option<&str>,
    timeout: Duration,
    updates: &[LfsRefUpdateSpec],
) -> Result<Vec<String>, LfsBlobError> {
    let mut paths = BTreeSet::new();
    for u in updates {
        if u.new_oid.bytes().all(|b| b == b'0') {
            continue;
        }
        let raw_log = run_git_quarantined(
            git_dir,
            git_obj_dir,
            git_alt_dirs,
            timeout,
            &["log", "--root", "-m", "--format=", "--name-only", "-z", "--no-renames", &u.new_oid, "--not", "--all"],
            &[],
        )
        .await?;
        for p in raw_log.split(|b| *b == 0).filter(|s| !s.is_empty()) {
            let s = std::str::from_utf8(p)
                .map_err(|_| LfsBlobError::new(LfsProofRejectCode::InvalidInput, "non-UTF8 path in git commit"))?;
            paths.insert(s.to_owned());
        }
        if u.old_oid.bytes().any(|b| b != b'0') {
            let raw_diff = run_git_quarantined(
                git_dir,
                git_obj_dir,
                git_alt_dirs,
                timeout,
                &["diff-tree", "-r", "--no-commit-id", "--name-only", "-z", "--no-renames", &u.old_oid, &u.new_oid],
                &[],
            )
            .await?;
            for p in raw_diff.split(|b| *b == 0).filter(|s| !s.is_empty()) {
                let s = std::str::from_utf8(p)
                    .map_err(|_| LfsBlobError::new(LfsProofRejectCode::InvalidInput, "non-UTF8 path in git diff"))?;
                paths.insert(s.to_owned());
            }
        }
    }
    Ok(paths.into_iter().collect())
}
