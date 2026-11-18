//! Git LFS v1 lock store and pre-receive locked-path inspection (`Refs #145`).

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_postgres::Row;
use uuid::Uuid;

use super::authz::AuthorizedRepoAccess;
use super::pg_store::{PgLfsBlobStore, pg_err};
use super::types::{LfsBlobError, LfsProofRejectCode, LfsRefUpdateSpec};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LfsLockOwnerView {
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LfsLockRecord {
    pub id: String,
    pub path: String,
    pub locked_at: String,
    pub owner: LfsLockOwnerView,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CreateLockOutcome {
    Created(LfsLockRecord),
    AlreadyLocked(LfsLockRecord),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LfsVerifyLocksReport {
    pub ours: Vec<LfsLockRecord>,
    pub theirs: Vec<LfsLockRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

pub fn valid_lfs_lock_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 1024
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
        && path.split('/').all(|p| !p.is_empty() && p != "." && p != "..")
}

fn decode_lock_row(row: &Row) -> LfsLockRecord {
    let id: Uuid = row.get(0);
    LfsLockRecord {
        id: id.to_string(),
        path: row.get(1),
        locked_at: row.get(2),
        owner: LfsLockOwnerView { name: row.get(3) },
    }
}

impl PgLfsBlobStore {
    pub async fn create_lock(
        &self,
        access: &AuthorizedRepoAccess,
        path: &str,
    ) -> Result<CreateLockOutcome, LfsBlobError> {
        if !access.role.allows_write() {
            return Err(LfsBlobError::new(LfsProofRejectCode::UnauthorizedCollaborator, "write role required to lock"));
        }
        if !valid_lfs_lock_path(path) {
            return Err(LfsBlobError::new(LfsProofRejectCode::InvalidInput, "invalid LFS lock path"));
        }
        let id = Uuid::new_v4();
        let client = self.pool().get().await.map_err(pg_err)?;
        let inserted = client
            .query_opt(
                "INSERT INTO lfs_blob_locks(id, tenant_id, repository_id, path, owner_actor_id, owner_username)
                 VALUES($1,$2,$3,$4,$5,$6)
                 ON CONFLICT (repository_id, path) DO NOTHING
                 RETURNING id, path, to_char(locked_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'), owner_username",
                &[
                    &id,
                    &access.owner_tenant_id,
                    &access.repository_id,
                    &path,
                    &access.actor_id,
                    &access.actor_username,
                ],
            )
            .await
            .map_err(pg_err)?;
        if let Some(row) = inserted {
            return Ok(CreateLockOutcome::Created(decode_lock_row(&row)));
        }
        let existing = client
            .query_one(
                "SELECT id, path, to_char(locked_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'), owner_username
                 FROM lfs_blob_locks WHERE repository_id=$1 AND path=$2",
                &[&access.repository_id, &path],
            )
            .await
            .map_err(pg_err)?;
        Ok(CreateLockOutcome::AlreadyLocked(decode_lock_row(&existing)))
    }

    pub async fn list_locks(
        &self,
        repository_id: Uuid,
        path_filter: Option<&str>,
        id_filter: Option<Uuid>,
        cursor: Option<Uuid>,
        limit: i64,
    ) -> Result<(Vec<LfsLockRecord>, Option<String>), LfsBlobError> {
        let cap = limit.clamp(1, 100);
        if let Some(p) = path_filter
            && !valid_lfs_lock_path(p)
        {
            return Err(LfsBlobError::new(LfsProofRejectCode::InvalidInput, "invalid lock path filter"));
        }
        let client = self.pool().get().await.map_err(pg_err)?;
        let rows = client
            .query(
                "SELECT id, path, to_char(locked_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'), owner_username
                 FROM lfs_blob_locks
                 WHERE repository_id=$1
                   AND ($2::text IS NULL OR path=$2)
                   AND ($3::uuid IS NULL OR id=$3)
                   AND ($4::uuid IS NULL OR id>$4)
                 ORDER BY id ASC LIMIT $5",
                &[&repository_id, &path_filter, &id_filter, &cursor, &(cap + 1)],
            )
            .await
            .map_err(pg_err)?;
        let locks: Vec<LfsLockRecord> = rows.iter().take(cap as usize).map(decode_lock_row).collect();
        let next = if rows.len() > cap as usize { locks.last().map(|l| l.id.clone()) } else { None };
        Ok((locks, next))
    }

    pub async fn verify_locks(
        &self,
        access: &AuthorizedRepoAccess,
        cursor: Option<Uuid>,
        limit: i64,
    ) -> Result<LfsVerifyLocksReport, LfsBlobError> {
        if !access.role.allows_write() {
            return Err(LfsBlobError::new(
                LfsProofRejectCode::UnauthorizedCollaborator,
                "write role required to verify locks",
            ));
        }
        let cap = limit.clamp(1, 100);
        let client = self.pool().get().await.map_err(pg_err)?;
        let rows = client
            .query(
                "SELECT id, path, to_char(locked_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'), owner_username, owner_actor_id
                 FROM lfs_blob_locks
                 WHERE repository_id=$1 AND ($2::uuid IS NULL OR id>$2)
                 ORDER BY id ASC LIMIT $3",
                &[&access.repository_id, &cursor, &(cap + 1)],
            )
            .await
            .map_err(pg_err)?;
        let (mut ours, mut theirs) = (Vec::new(), Vec::new());
        for row in rows.iter().take(cap as usize) {
            let rec = decode_lock_row(row);
            let owner_actor: Uuid = row.get(4);
            if owner_actor == access.actor_id {
                ours.push(rec);
            } else {
                theirs.push(rec);
            }
        }
        let next_cursor = if rows.len() > cap as usize {
            rows.get(cap as usize - 1).map(|r| r.get::<_, Uuid>(0).to_string())
        } else {
            None
        };
        Ok(LfsVerifyLocksReport { ours, theirs, next_cursor })
    }

    pub async fn unlock(
        &self,
        access: &AuthorizedRepoAccess,
        lock_id: Uuid,
        force: bool,
    ) -> Result<LfsLockRecord, LfsBlobError> {
        if !access.role.allows_write() {
            return Err(LfsBlobError::new(LfsProofRejectCode::UnauthorizedCollaborator, "write role required"));
        }
        let client = self.pool().get().await.map_err(pg_err)?;
        let row = client
            .query_opt(
                "SELECT id, path, to_char(locked_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.MS\"Z\"'), owner_username, owner_actor_id
                 FROM lfs_blob_locks WHERE repository_id=$1 AND id=$2",
                &[&access.repository_id, &lock_id],
            )
            .await
            .map_err(pg_err)?
            .ok_or_else(|| LfsBlobError::new(LfsProofRejectCode::MissingRemoteBlob, "LFS lock not found"))?;
        let owner_actor: Uuid = row.get(4);
        if owner_actor != access.actor_id && !(force && access.role.allows_admin()) {
            return Err(LfsBlobError::new(
                LfsProofRejectCode::UnauthorizedCollaborator,
                "only lock owner or repository admin (with force) may unlock",
            ));
        }
        let rec = decode_lock_row(&row);
        client
            .execute("DELETE FROM lfs_blob_locks WHERE repository_id=$1 AND id=$2", &[&access.repository_id, &lock_id])
            .await
            .map_err(pg_err)?;
        Ok(rec)
    }

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
                "SELECT path, owner_username FROM lfs_blob_locks
                 WHERE repository_id=$1 AND path = ANY($2::text[]) AND owner_actor_id <> $3
                 ORDER BY path ASC LIMIT 1",
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
