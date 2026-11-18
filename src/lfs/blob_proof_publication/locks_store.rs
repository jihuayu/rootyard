//! Production `lfs_locks` conflict query, shared-hold grants, restart upload reconciliation,
//! and quarantined Git tree/log inspection (`Refs #145`).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use super::pg_store::{PgLfsBlobStore, ReconcileUploadsReport, pg_err};
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

    pub async fn reconcile_stale_pending_uploads(
        &self,
        repository_id: Uuid,
        stale_after: Duration,
    ) -> Result<ReconcileUploadsReport, LfsBlobError> {
        let stale_secs: f64 = stale_after.as_secs_f64();
        let is_zero = stale_after.is_zero();
        let mut client = self.pool().get().await.map_err(pg_err)?;
        let tx = client.transaction().await.map_err(pg_err)?;
        tx.batch_execute("SET LOCAL synchronous_commit = 'on'").await.map_err(pg_err)?;
        let candidates = tx
            .query(
                "SELECT attempt_id,
                        (updated_at <= clock_timestamp() - make_interval(secs => $2)) AS age_stale,
                        (lease_until <= clock_timestamp()) AS lease_expired
                 FROM lfs_blob_upload_attempts
                 WHERE repository_id = $1 AND state = 'pending'
                 FOR UPDATE SKIP LOCKED",
                &[&repository_id, &stale_secs],
            )
            .await
            .map_err(pg_err)?;
        let mut aborted_attempts: u64 = 0;
        for r in candidates {
            let attempt_id: Uuid = r.get(0);
            let age_stale: bool = r.get(1);
            let lease_expired: bool = r.get(2);
            let (k1, k2) = super::prod_auth_tx::upload_attempt_advisory_keys(attempt_id);
            let lock_free: bool = tx
                .query_one("SELECT pg_try_advisory_xact_lock($1, $2)", &[&k1, &k2])
                .await
                .map_err(pg_err)?
                .get(0);
            if !lock_free && !lease_expired {
                // Actively streaming on a live instance right now — DO NOT reclaim!
                continue;
            }
            if (lock_free && (is_zero || age_stale || lease_expired)) || lease_expired {
                aborted_attempts += tx
                    .execute(
                        "UPDATE lfs_blob_upload_attempts
                         SET state = 'aborted_failed',
                             failure_reason = 'reconciled_stale_pending_upload',
                             updated_at = clock_timestamp()
                         WHERE attempt_id = $1 AND state = 'pending'",
                        &[&attempt_id],
                    )
                    .await
                    .map_err(pg_err)?;
            }
        }
        let aborted_ops = tx
            .execute(
                "UPDATE lfs_blob_upload_operations o
                 SET state = 'aborted_failed',
                     updated_at = clock_timestamp()
                 WHERE o.repository_id = $1
                   AND o.state = 'pending'
                   AND (
                       $3
                       OR o.updated_at <= clock_timestamp() - make_interval(secs => $2)
                       OR EXISTS (
                           SELECT 1 FROM lfs_blob_upload_attempts a
                           WHERE a.repository_id = o.repository_id
                             AND a.operation_id = o.operation_id
                             AND a.state = 'aborted_failed'
                             AND a.updated_at >= o.updated_at
                       )
                   )
                   AND NOT EXISTS (
                       SELECT 1 FROM lfs_blob_upload_attempts a
                       WHERE a.repository_id = o.repository_id
                         AND a.state = 'pending'
                         AND (
                             a.operation_id = o.operation_id
                             OR (a.operation_id IS NULL AND a.actor_id = o.actor_id AND a.oid_sha256 = o.oid_sha256 AND a.size_bytes = o.size_bytes)
                         )
                   )",
                &[&repository_id, &stale_secs, &is_zero],
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
    pub async fn reconcile_in_flight_uploads(
        &self,
        repository_id: Uuid,
    ) -> Result<ReconcileUploadsReport, LfsBlobError> {
        self.reconcile_stale_pending_uploads(repository_id, Duration::ZERO).await
    }
    pub async fn abort_upload_on_cancel(
        &self,
        repository_id: Uuid,
        attempt_id: Uuid,
        operation_id: Option<Uuid>,
        reason: &str,
    ) -> Result<(), LfsBlobError> {
        let mut client = self.pool().get().await.map_err(pg_err)?;
        let tx = client.transaction().await.map_err(pg_err)?;
        tx.batch_execute("SET LOCAL synchronous_commit = 'on'").await.map_err(pg_err)?;
        tx.execute(
            "UPDATE lfs_blob_upload_attempts
             SET state='aborted_cancelled', failure_reason=$2, updated_at=clock_timestamp()
             WHERE attempt_id=$1 AND state='pending'",
            &[&attempt_id, &reason],
        )
        .await
        .map_err(pg_err)?;
        if let Some(op_id) = operation_id {
            tx.execute(
                "UPDATE lfs_blob_upload_operations
                 SET state='aborted_cancelled', updated_at=clock_timestamp()
                 WHERE repository_id=$1 AND operation_id=$2 AND state='pending'",
                &[&repository_id, &op_id],
            )
            .await
            .map_err(pg_err)?;
        }
        tx.commit().await.map_err(pg_err)?;
        Ok(())
    }
}
pub struct ActiveUploadAttemptSpec<'a> {
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub actor_id: Uuid,
    pub oid_sha256: &'a str,
    pub size_bytes: i64,
    pub operation_id: Option<Uuid>,
    pub scratch_path: PathBuf,
    pub lease_ttl: Duration,
}
pub struct InFlightUploadGuard {
    pg: PgLfsBlobStore,
    repository_id: Uuid,
    attempt_id: Uuid,
    operation_id: Option<Uuid>,
    scratch_path: PathBuf,
    settled: std::sync::Arc<std::sync::atomic::AtomicBool>,
    stop_tx: Option<tokio::sync::oneshot::Sender<()>>,
    keeper_handle: Option<tokio::task::JoinHandle<()>>,
}
impl InFlightUploadGuard {
    pub async fn acquire(pg: PgLfsBlobStore, spec: ActiveUploadAttemptSpec<'_>) -> Result<Self, LfsBlobError> {
        let attempt_id = Uuid::new_v4();
        let (k1, k2) = super::prod_auth_tx::upload_attempt_advisory_keys(attempt_id);
        let lease_conn = pg.pool().get().await.map_err(pg_err)?;
        let locked: bool = lease_conn
            .query_one("SELECT pg_try_advisory_lock($1, $2)", &[&k1, &k2])
            .await
            .map_err(pg_err)?
            .get(0);
        if !locked {
            return Err(pg_err("upload advisory lock collision"));
        }
        let lease_secs = spec.lease_ttl.as_secs_f64();
        if let Err(e) = lease_conn
            .execute(
                "INSERT INTO lfs_blob_upload_attempts(
                    attempt_id, tenant_id, repository_id, actor_id, oid_sha256, size_bytes, operation_id, lease_until, state
                 ) VALUES($1, $2, $3, $4, $5, $6, $7, clock_timestamp() + make_interval(secs => $8), 'pending')",
                &[
                    &attempt_id,
                    &spec.tenant_id,
                    &spec.repository_id,
                    &spec.actor_id,
                    &spec.oid_sha256,
                    &spec.size_bytes,
                    &spec.operation_id,
                    &lease_secs,
                ],
            )
            .await
        {
            let _ = lease_conn.execute("SELECT pg_advisory_unlock($1, $2)", &[&k1, &k2]).await;
            return Err(pg_err(e));
        }
        let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
        let settled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let settled_clone = settled.clone();
        let pg_clone = pg.clone();
        let repository_id = spec.repository_id;
        let operation_id = spec.operation_id;
        let keeper_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut stop_rx => break,
                    _ = tokio::time::sleep(Duration::from_millis(250)) => {
                        let renewed = lease_conn
                            .execute(
                                "UPDATE lfs_blob_upload_attempts
                                 SET lease_until = clock_timestamp() + make_interval(secs => $2),
                                     updated_at = clock_timestamp()
                                 WHERE attempt_id = $1
                                   AND state = 'pending'
                                   AND lease_until > clock_timestamp()",
                                &[&attempt_id, &lease_secs],
                            )
                            .await
                            .unwrap_or(0);
                        if renewed > 0
                            && let Some(op_id) = operation_id
                        {
                            let _ = lease_conn
                                .execute(
                                    "UPDATE lfs_blob_upload_operations SET updated_at = clock_timestamp()
                                     WHERE repository_id = $1 AND operation_id = $2 AND state = 'pending'",
                                    &[&repository_id, &op_id],
                                )
                                .await;
                        }
                    }
                }
            }
            let _ = lease_conn.execute("SELECT pg_advisory_unlock($1, $2)", &[&k1, &k2]).await;
            drop(lease_conn);
            if !settled_clone.swap(true, std::sync::atomic::Ordering::SeqCst) {
                let _ = tokio::time::timeout(
                    Duration::from_secs(5),
                    pg_clone.abort_upload_on_cancel(
                        repository_id,
                        attempt_id,
                        operation_id,
                        "client_upload_stream_cancelled",
                    ),
                )
                .await;
            }
        });
        Ok(Self {
            pg,
            repository_id,
            attempt_id,
            operation_id,
            scratch_path: spec.scratch_path,
            settled,
            stop_tx: Some(stop_tx),
            keeper_handle: Some(keeper_handle),
        })
    }
    pub const fn attempt_id(&self) -> Uuid {
        self.attempt_id
    }
    pub async fn finish_and_unlock(&mut self) {
        self.settled.store(true, std::sync::atomic::Ordering::SeqCst);
        self.stop_tx.take();
        if let Some(h) = self.keeper_handle.take() {
            let _ = h.await;
        }
    }
    pub async fn abort_now(&mut self, reason: &str) {
        if !self.settled.swap(true, std::sync::atomic::Ordering::SeqCst) {
            let _ = std::fs::remove_file(&self.scratch_path);
            self.stop_tx.take();
            if let Some(h) = self.keeper_handle.take() {
                let _ = h.await;
            }
            let _ =
                self.pg.abort_upload_on_cancel(self.repository_id, self.attempt_id, self.operation_id, reason).await;
        }
    }
}

impl Drop for InFlightUploadGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.scratch_path);
        let _ = self.stop_tx.take();
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
