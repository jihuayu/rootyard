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

fn candidate(line: &str) -> Option<(&str,&str)> {
    let mut fields=line.split_ascii_whitespace();
    let status=fields.next()?;
    if status!="unreachable" && status!="dangling" { return None; }
    let kind=fields.next()?;
    if !matches!(kind,"blob"|"tree"|"commit"|"tag") { return None; }
    let oid=fields.next()?;
    if fields.next().is_some() || !matches!(oid.len(),40|64)
        || !oid.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        return None;
    }
    Some((oid,kind))
}

pub async fn mark(state: &AppState, repo: Uuid, tenant: Uuid, generation: i64,
                  policy: &Policy, cancel: &CancellationToken) -> Result<Value> {
    // Include reflogs as roots. CI retention refs are native refs and therefore
    // roots too. Rows alone never authorize a physical delete.
    let report=gitfs::run_git(state,repo,&["fsck","--unreachable","--no-progress"],cancel,8*1024*1024).await?;
    let mut oids=Vec::<String>::new();
    let mut kinds=Vec::<String>::new();
    for line in report.lines() {
        if let Some((oid,kind))=candidate(line) {
            oids.push(oid.to_owned());
            kinds.push(kind.to_owned());
            if oids.len()>100_000 { bail!("unreachable object inspection exceeded candidate limit"); }
        }
    }
    if oids.is_empty() { return Ok(json!({"candidates":0,"deleted":false})); }
    let client=state.pool.get().await?;
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

async fn optional_table(state: &AppState, name: &str) -> Result<bool> {
    let client=state.pool.get().await?;
    Ok(client.query_one("SELECT to_regclass($1) IS NOT NULL",&[&name]).await?.get(0))
}

/// SQL-only roots which Git cannot see. A conservative repository-wide hold
/// is safer than trying to infer the object closure of an active workspace.
async fn has_external_roots(state: &AppState, repo: Uuid) -> Result<bool> {
    let client=state.pool.get().await?;
    if optional_table(state,"workspaces").await?
        && client.query_one("SELECT EXISTS(SELECT 1 FROM workspaces WHERE repository_id=$1 AND state<>'deleted')",&[&repo]).await?.get(0) {
        return Ok(true);
    }
    if client.query_one("SELECT EXISTS(SELECT 1 FROM ci_checkout_jobs WHERE repository_id=$1 AND NOT cancelled AND NOT revoked)",&[&repo]).await?.get(0) {
        return Ok(true);
    }
    if optional_table(state,"ci_runs").await?
        && client.query_one("SELECT EXISTS(SELECT 1 FROM ci_runs WHERE repository_id=$1 AND state IN ('queued','leased'))",&[&repo]).await?.get(0) {
        return Ok(true);
    }
    if client.query_one("SELECT EXISTS(SELECT 1 FROM forge_pulls WHERE repository_id=$1 AND state='open')",&[&repo]).await?.get(0) {
        return Ok(true);
    }
    Ok(false)
}

/// Called only while the global backup barrier, durable exclusive repository
/// lease, local write lock, and local reader gate are all held. Every deletion
/// is rechecked against today's complete native reachability scan.
pub async fn delete_due(state: &AppState, repo: Uuid, tenant: Uuid, generation: i64,
                        lease: &Lease, cancel: &CancellationToken) -> Result<Value> {
    lease.ensure_active().map_err(|_| anyhow::anyhow!("repository reader barrier lost"))?;
    if has_external_roots(state,repo).await? {
        return Ok(json!({"deleted":0,"retained":"active external roots"}));
    }
    let client=state.pool.get().await?;
    let rows=client.query(
        "SELECT oid FROM storage_maintenance_tombstones WHERE repository_id=$1 AND tenant_id=$2 \
         AND repository_generation=$3 AND state='pending' AND delete_after<=clock_timestamp() \
         ORDER BY delete_after,oid LIMIT 100",
        &[&repo,&tenant,&generation],
    ).await?;
    if rows.is_empty() { return Ok(json!({"deleted":0})); }
    let report=gitfs::run_git(state,repo,&["fsck","--unreachable","--no-progress"],cancel,8*1024*1024).await?;
    let unreachable=report.lines().filter_map(candidate).map(|(oid,_)| oid).collect::<HashSet<_>>();
    let git_dir=state.storage.verify_path(repo)?;
    crate::journal::safe_path(&git_dir.join("objects"))?;
    let mut deleted=0_u64;
    let mut retained=0_u64;
    for row in rows {
        if cancel.is_cancelled() { bail!("maintenance lease lost"); }
        lease.ensure_active().map_err(|_| anyhow::anyhow!("repository reader barrier lost"))?;
        if has_external_roots(state,repo).await? { bail!("external retention root appeared during collection"); }
        let oid:String=row.get(0);
        if !unreachable.contains(oid.as_str()) {
            client.execute("UPDATE storage_maintenance_tombstones SET state='retained', \
                last_error='native reachability changed' WHERE repository_id=$1 AND tenant_id=$2 \
                AND oid=$3 AND repository_generation=$4 AND state='pending'",
                &[&repo,&tenant,&oid,&generation]).await?;
            retained+=1;
            continue;
        }
        let (dir,file)=oid.split_at(2);
        let parent=git_dir.join("objects").join(dir);
        if !parent.exists() {
            client.execute("UPDATE storage_maintenance_tombstones SET state='retained', \
                last_error='object is packed or loose directory absent' WHERE repository_id=$1 AND tenant_id=$2 \
                AND oid=$3 AND repository_generation=$4 AND state='pending'",
                &[&repo,&tenant,&oid,&generation]).await?;
            retained+=1;
            continue;
        }
        crate::journal::safe_path(&parent)?;
        let path=parent.join(file);
        match fs::symlink_metadata(&path) {
            Ok(meta) => {
                if !meta.file_type().is_file() || meta.nlink()!=1 { bail!("unsafe loose Git object"); }
                fs::remove_file(&path)?;
            }
            Err(error) if error.kind()==std::io::ErrorKind::NotFound => {
                client.execute("UPDATE storage_maintenance_tombstones SET state='retained', \
                    last_error='object is packed or loose path absent' WHERE repository_id=$1 AND tenant_id=$2 \
                    AND oid=$3 AND repository_generation=$4 AND state='pending'",
                    &[&repo,&tenant,&oid,&generation]).await?;
                retained+=1;
                continue;
            }
            Err(error) => return Err(error.into()),
        }
        client.execute("UPDATE storage_maintenance_tombstones SET state='deleted', \
            deleted_at=clock_timestamp(),attempts=attempts+1,last_error=NULL \
            WHERE repository_id=$1 AND tenant_id=$2 AND oid=$3 \
            AND repository_generation=$4 AND state='pending'",
            &[&repo,&tenant,&oid,&generation]).await?;
        deleted+=1;
    }
    Ok(json!({"deleted":deleted,"retained":retained,"remaining_batch":100}))
}

#[cfg(test)]
mod tests {
    use super::candidate;
    #[test]
    fn only_native_unreachable_objects_become_tombstones() {
        let oid="a".repeat(40);
        assert_eq!(candidate(&format!("unreachable blob {oid}")),Some((oid.as_str(),"blob")));
        assert_eq!(candidate(&format!("dangling commit {oid}")),Some((oid.as_str(),"commit")));
        assert!(candidate(&format!("reachable blob {oid}")).is_none());
        assert!(candidate("unreachable blob ../../escape").is_none());
        assert!(candidate(&format!("unreachable blob {}", "A".repeat(40))).is_none());
    }
}
