//! Production `lfs_locks` conflict query, shared-hold grants, restart upload reconciliation,
//! and quarantined Git tree/log inspection (`Refs #145`).

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use super::pg_store::{PgLfsBlobStore, ReconcileUploadsReport, pg_err};
use super::types::{LfsBlobError, LfsProofRejectCode, LfsRefUpdateSpec, SharedLfsHoldGrant};

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

    pub async fn reconcile_in_flight_uploads(&self, repository_id: Uuid) -> Result<ReconcileUploadsReport, LfsBlobError> {
        let mut client = self.pool().get().await.map_err(pg_err)?;
        let tx = client.transaction().await.map_err(pg_err)?;
        let aborted_attempts = tx
            .execute(
                "UPDATE lfs_blob_upload_attempts
                 SET state='aborted_failed', failure_reason='reconciled_orphaned_after_restart', updated_at=clock_timestamp()
                 WHERE repository_id=$1 AND state='pending'",
                &[&repository_id],
            )
            .await
            .map_err(pg_err)?;
        let aborted_ops = tx
            .execute(
                "UPDATE lfs_blob_upload_operations
                 SET state='aborted_failed', updated_at=clock_timestamp()
                 WHERE repository_id=$1 AND state='pending'",
                &[&repository_id],
            )
            .await
            .map_err(pg_err)?;
        let preserved: i64 = tx
            .query_one(
                "SELECT COUNT(*) FROM lfs_blob_objects WHERE repository_id=$1 AND NOT retired",
                &[&repository_id],
            )
            .await
            .map_err(pg_err)?
            .get(0);
        tx.commit().await.map_err(pg_err)?;
        Ok(ReconcileUploadsReport {
            aborted_orphaned_attempts: aborted_attempts,
            aborted_orphaned_operations: aborted_ops,
            committed_objects_preserved: preserved.max(0) as u64,
        })
    }

    pub async fn grant_shared_hold(&self, g: &SharedLfsHoldGrant) -> Result<(), LfsBlobError> {
        let mut client = self.pool().get().await.map_err(pg_err)?;
        let tx = client.transaction().await.map_err(pg_err)?;
        tx.batch_execute("SET LOCAL synchronous_commit = 'on'").await.map_err(pg_err)?;
        tx.execute(
            "INSERT INTO lfs_blob_shared_holds(
                grant_id, source_tenant_id, source_repository_id, target_tenant_id, target_repository_id,
                grantee_actor_id, oid_sha256, size_bytes, source_hold_id, active
             ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
            &[
                &g.grant_id, &g.source_tenant_id, &g.source_repository_id, &g.target_tenant_id, &g.target_repository_id,
                &g.grantee_actor_id, &g.oid_sha256, &g.size_bytes, &g.source_hold_id, &g.active,
            ],
        )
        .await
        .map_err(pg_err)?;
        tx.commit().await.map_err(pg_err)?;
        Ok(())
    }

    pub async fn set_shared_hold_active(&self, grant_id: Uuid, active: bool) -> Result<(), LfsBlobError> {
        let client = self.pool().get().await.map_err(pg_err)?;
        client
            .execute(
                "UPDATE lfs_blob_shared_holds
                 SET active=$2, revoked_at = CASE WHEN $2 THEN NULL ELSE clock_timestamp() END
                 WHERE grant_id=$1",
                &[&grant_id, &active],
            )
            .await
            .map_err(pg_err)?;
        Ok(())
    }

    pub async fn find_shared_holds_for_target(
        &self,
        target_tenant_id: Uuid,
        target_repository_id: Uuid,
        oid_sha256: &str,
    ) -> Result<Vec<SharedLfsHoldGrant>, LfsBlobError> {
        let client = self.pool().get().await.map_err(pg_err)?;
        let rows = client
            .query(
                "SELECT grant_id, source_tenant_id, source_repository_id, target_tenant_id, target_repository_id,
                        grantee_actor_id, oid_sha256, size_bytes, source_hold_id, active
                 FROM lfs_blob_shared_holds
                 WHERE target_tenant_id=$1 AND target_repository_id=$2 AND oid_sha256=$3
                 ORDER BY active DESC, created_at DESC",
                &[&target_tenant_id, &target_repository_id, &oid_sha256],
            )
            .await
            .map_err(pg_err)?;
        Ok(rows
            .into_iter()
            .map(|r| SharedLfsHoldGrant {
                grant_id: r.get(0),
                source_tenant_id: r.get(1),
                source_repository_id: r.get(2),
                target_tenant_id: r.get(3),
                target_repository_id: r.get(4),
                grantee_actor_id: r.get(5),
                oid_sha256: r.get(6),
                size_bytes: r.get(7),
                source_hold_id: r.get(8),
                active: r.get(9),
            })
            .collect())
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
