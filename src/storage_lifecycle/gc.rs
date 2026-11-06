//! Durable discovery of unreachable native objects. Physical unlink stays
//! disabled until every origin reader has a durable shared repository lease.
use super::{gitfs, models::Policy};
use crate::{AppState, storage::read_leases::Lease};
use anyhow::{Result, bail};
use serde_json::{Value, json};
use std::{collections::HashSet, fs, os::unix::fs::MetadataExt};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Flip only after Git, browse, CI, pull, and workspace native source readers
/// all acquire the durable shared lease before their local reader gate.
pub const PHYSICAL_DELETE_ENABLED: bool = false;

fn candidate(line: &str) -> Option<(&str, &str)> {
    let mut fields = line.split_ascii_whitespace();
    let status = fields.next()?;
    if status != "unreachable" && status != "dangling" {
        return None;
    }
    let kind = fields.next()?;
    if !matches!(kind, "blob" | "tree" | "commit" | "tag") {
        return None;
    }
    let oid = fields.next()?;
    if fields.next().is_some()
        || !matches!(oid.len(), 40 | 64)
        || !oid.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return None;
    }
    Some((oid, kind))
}

pub async fn mark(
    state: &AppState,
    repo: Uuid,
    tenant: Uuid,
    generation: i64,
    policy: &Policy,
    cancel: &CancellationToken,
) -> Result<Value> {
    // Include reflogs as roots. CI retention refs are native refs and therefore
    // roots too. Rows alone never authorize a physical delete.
    let report =
        gitfs::run_git(state, repo, &["fsck", "--unreachable", "--no-progress"], cancel, 8 * 1024 * 1024).await?;
    let mut oids = Vec::<String>::new();
    let mut kinds = Vec::<String>::new();
    let mut seen = HashSet::new();
    for line in report.lines() {
        if let Some((oid, kind)) = candidate(line) {
            if !seen.insert(oid.to_owned()) {
                continue;
            }
            oids.push(oid.to_owned());
            kinds.push(kind.to_owned());
            if oids.len() > 100_000 {
                bail!("unreachable object inspection exceeded candidate limit");
            }
        }
    }
    if oids.is_empty() {
        return Ok(json!({"candidates":0,"deleted":false}));
    }
    let client = state.pool.get().await?;
    let inserted=client.execute(
        "INSERT INTO storage_maintenance_tombstones(repository_id,tenant_id,oid,object_kind,repository_generation,delete_after) \
         SELECT $1,$2,u.oid,u.kind,$3,clock_timestamp()+make_interval(secs=>($4::bigint)::double precision) \
         FROM unnest($5::text[],$6::text[]) AS u(oid,kind) \
         ON CONFLICT(repository_id,oid) DO UPDATE SET \
           tenant_id=EXCLUDED.tenant_id,object_kind=EXCLUDED.object_kind, \
           repository_generation=EXCLUDED.repository_generation,state='pending', \
           marked_at=clock_timestamp(),delete_after=EXCLUDED.delete_after,last_error=NULL \
         WHERE storage_maintenance_tombstones.repository_generation<>EXCLUDED.repository_generation \
           OR (storage_maintenance_tombstones.state='retained' AND \
               storage_maintenance_tombstones.last_error='native reachability changed')",
        &[&repo,&tenant,&generation,&policy.tombstone_grace_seconds,&oids,&kinds],
    ).await?;
    Ok(json!({"candidates":oids.len(),"new_tombstones":inserted,"deleted":false}))
}

/// SQL-only roots which Git cannot see. A conservative repository-wide hold
/// is safer than trying to infer the object closure of an active workspace.
async fn has_external_roots(tx: &deadpool_postgres::Transaction<'_>, repo: Uuid) -> Result<bool> {
    // All four tables are required by the current schema. A missing table is
    // an error, never permission to delete. The caller holds repositories FOR
    // UPDATE, which blocks new FK-backed roots until this decision commits.
    Ok(tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM workspaces WHERE repository_id=$1 AND state<>'deleted') \
         OR EXISTS(SELECT 1 FROM ci_checkout_jobs WHERE repository_id=$1 AND NOT cancelled AND NOT revoked) \
         OR EXISTS(SELECT 1 FROM ci_runs WHERE repository_id=$1 AND state IN ('queued','leased')) \
         OR EXISTS(SELECT 1 FROM forge_pulls WHERE repository_id=$1 AND state='open')",
            &[&repo],
        )
        .await?
        .get(0))
}

async fn lock_retention_rows(tx: &deadpool_postgres::Transaction<'_>, repo: Uuid) -> Result<()> {
    // Parent-row FOR UPDATE blocks new FK-backed roots. Existing rows could
    // change state without touching that parent, so hold each one stable too.
    // NOWAIT converts any reverse lock-order into a retry, not a deadlock.
    for table in ["workspaces", "ci_checkout_jobs", "ci_runs", "forge_pulls"] {
        let sql = format!("SELECT 1 FROM {table} WHERE repository_id=$1 LIMIT 10001 FOR SHARE NOWAIT");
        if tx.query(&sql, &[&repo]).await?.len() > 10_000 {
            bail!("retention root inspection exceeded limit");
        }
    }
    Ok(())
}

/// Called only while the global backup barrier, durable exclusive repository
/// lease, local write lock, and local reader gate are all held. Every deletion
/// is rechecked against today's complete native reachability scan.
pub async fn delete_due(
    state: &AppState,
    repo: Uuid,
    tenant: Uuid,
    generation: i64,
    lease: &Lease,
    cancel: &CancellationToken,
) -> Result<Value> {
    lease.ensure_active().map_err(|_| anyhow::anyhow!("repository reader barrier lost"))?;
    let mut client = state.pool.get().await?;
    let tx = client.transaction().await?;
    // A root creator can authorize and lock this row before requesting the
    // shared PG read lease. NOWAIT avoids waiting on that row while holding
    // our exclusive PG lease, which would otherwise create a lock cycle.
    let locked = tx
        .query_opt(
            "SELECT id FROM repositories WHERE id=$1 AND owner_id=$2 AND storage_generation=$3 \
         AND state='ready' AND storage_backend='gitfs' FOR UPDATE NOWAIT",
            &[&repo, &tenant, &generation],
        )
        .await?;
    if locked.is_none() {
        bail!("repository changed before collection");
    }
    lock_retention_rows(&tx, repo).await?;
    if has_external_roots(&tx, repo).await? {
        return Ok(json!({"deleted":0,"retained":"active external roots"}));
    }
    let rows = tx
        .query(
            "SELECT oid FROM storage_maintenance_tombstones WHERE repository_id=$1 AND tenant_id=$2 \
         AND repository_generation=$3 AND state='pending' AND delete_after<=clock_timestamp() \
         ORDER BY delete_after,oid LIMIT 100",
            &[&repo, &tenant, &generation],
        )
        .await?;
    if rows.is_empty() {
        return Ok(json!({"deleted":0}));
    }
    let report =
        gitfs::run_git(state, repo, &["fsck", "--unreachable", "--no-progress"], cancel, 8 * 1024 * 1024).await?;
    let unreachable = report.lines().filter_map(candidate).map(|(oid, _)| oid).collect::<HashSet<_>>();
    let git_dir = state.storage.verify_path(repo)?;
    crate::journal::safe_path(&git_dir.join("objects"))?;
    let mut deleted = 0_u64;
    let mut retained = 0_u64;
    for row in rows {
        if cancel.is_cancelled() {
            bail!("maintenance lease lost");
        }
        lease.ensure_active().map_err(|_| anyhow::anyhow!("repository reader barrier lost"))?;
        if has_external_roots(&tx, repo).await? {
            bail!("external retention root appeared during collection");
        }
        let oid: String = row.get(0);
        if !unreachable.contains(oid.as_str()) {
            tx.execute(
                "UPDATE storage_maintenance_tombstones SET state='retained', \
                last_error='native reachability changed' WHERE repository_id=$1 AND tenant_id=$2 \
                AND oid=$3 AND repository_generation=$4 AND state='pending'",
                &[&repo, &tenant, &oid, &generation],
            )
            .await?;
            retained += 1;
            continue;
        }
        let (dir, file) = oid.split_at(2);
        let parent = git_dir.join("objects").join(dir);
        if !parent.exists() {
            tx.execute(
                "UPDATE storage_maintenance_tombstones SET state='retained', \
                last_error='object is packed or loose directory absent' WHERE repository_id=$1 AND tenant_id=$2 \
                AND oid=$3 AND repository_generation=$4 AND state='pending'",
                &[&repo, &tenant, &oid, &generation],
            )
            .await?;
            retained += 1;
            continue;
        }
        crate::journal::safe_path(&parent)?;
        let path = parent.join(file);
        match fs::symlink_metadata(&path) {
            Ok(meta) => {
                if !meta.file_type().is_file() || meta.nlink() != 1 {
                    bail!("unsafe loose Git object");
                }
                fs::remove_file(&path)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                tx.execute(
                    "UPDATE storage_maintenance_tombstones SET state='retained', \
                    last_error='object is packed or loose path absent' WHERE repository_id=$1 AND tenant_id=$2 \
                    AND oid=$3 AND repository_generation=$4 AND state='pending'",
                    &[&repo, &tenant, &oid, &generation],
                )
                .await?;
                retained += 1;
                continue;
            }
            Err(error) => return Err(error.into()),
        }
        tx.execute(
            "UPDATE storage_maintenance_tombstones SET state='deleted', \
            deleted_at=clock_timestamp(),attempts=attempts+1,last_error=NULL \
            WHERE repository_id=$1 AND tenant_id=$2 AND oid=$3 \
            AND repository_generation=$4 AND state='pending'",
            &[&repo, &tenant, &oid, &generation],
        )
        .await?;
        deleted += 1;
    }
    lease.ensure_active().map_err(|_| anyhow::anyhow!("repository reader barrier lost"))?;
    tx.commit().await?;
    Ok(json!({"deleted":deleted,"retained":retained,"remaining_batch":100}))
}

#[cfg(test)]
mod tests {
    use super::candidate;
    #[test]
    fn only_native_unreachable_objects_become_tombstones() {
        let oid = "a".repeat(40);
        assert_eq!(candidate(&format!("unreachable blob {oid}")), Some((oid.as_str(), "blob")));
        assert_eq!(candidate(&format!("dangling commit {oid}")), Some((oid.as_str(), "commit")));
        assert!(candidate(&format!("reachable blob {oid}")).is_none());
        assert!(candidate("unreachable blob ../../escape").is_none());
        assert!(candidate(&format!("unreachable blob {}", "A".repeat(40))).is_none());
    }
}
