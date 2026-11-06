//! Durable discovery and two-phase physical collection of unreachable native
//! objects. Physical unlink is admitted only under a committed gc_epoch fence,
//! an anchored SQL root union, and a QUARANTINE directory that can be restored
//! before the final unlink.
use super::{
    fence::Fence,
    gitfs,
    models::{Job, Policy},
    quarantine::Quarantine,
};
use crate::{AppState, storage::read_leases::Lease};
use anyhow::{Result, bail, ensure};
use serde_json::{Value, json};
use std::{collections::HashSet, fs, os::unix::fs::MetadataExt, path::Path};
use tokio_postgres::GenericClient;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Physical collection is enabled only together with the durable admission
/// fence, root keep refs, and quarantine rollback implemented in this module.
pub const PHYSICAL_DELETE_ENABLED: bool = true;

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

fn unreachable_set(report: &str) -> HashSet<String> {
    report.lines().filter_map(candidate).map(|(oid, _)| oid.to_owned()).collect()
}

async fn fsck_unreachable(state: &AppState, repo: Uuid, cancel: &CancellationToken) -> Result<String> {
    gitfs::run_git(state, repo, &["fsck", "--unreachable", "--no-progress"], cancel, 8 * 1024 * 1024).await
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
    // roots too. SQL pins are re-anchored by the physical fence before unlink;
    // a tombstone for a currently pinned object is retained, never deleted.
    let report = fsck_unreachable(state, repo, cancel).await?;
    let client = state.pool.get().await?;
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
    let inserted = client.execute(
        "INSERT INTO storage_maintenance_tombstones(repository_id,tenant_id,oid,object_kind,repository_generation,delete_after) \
         SELECT $1,$2,u.oid,u.kind,$3,clock_timestamp()+make_interval(secs=>($4::bigint)::double precision) \
         FROM unnest($5::text[],$6::text[]) AS u(oid,kind) \
         ON CONFLICT(repository_id,oid) DO UPDATE SET \
           tenant_id=EXCLUDED.tenant_id,object_kind=EXCLUDED.object_kind, \
           repository_generation=EXCLUDED.repository_generation,state='pending', \
           marked_at=clock_timestamp(),delete_after=EXCLUDED.delete_after,last_error=NULL \
         WHERE storage_maintenance_tombstones.repository_generation<>EXCLUDED.repository_generation \
           OR storage_maintenance_tombstones.state IN ('retained','deleted')",
        &[
            &repo,
            &tenant,
            &generation,
            &policy.tombstone_grace_seconds,
            &oids,
            &kinds,
        ],
    )
    .await?;
    Ok(json!({"candidates": oids.len(), "new_tombstones": inserted, "deleted": false}))
}

fn reject_unsafe_topology(git_dir: &Path) -> Result<()> {
    crate::journal::safe_path(&git_dir.join("objects"))?;
    for relative in ["objects/info/alternates", "objects/info/http-alternates", "shallow", "info/grafts"] {
        match fs::symlink_metadata(git_dir.join(relative)) {
            Ok(_) => bail!("unsupported source object topology for physical GC"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

async fn require_pack_rewrite_space(
    state: &AppState,
    repo: Uuid,
    git_dir: &std::path::Path,
    unreachable: &HashSet<String>,
    cancel: &CancellationToken,
) -> Result<()> {
    let counts = gitfs::count(state, repo, cancel).await?;
    let listing = gitfs::run_git(
        state,
        repo,
        &["cat-file", "--batch-all-objects", "--batch-check=%(objectname) %(objectsize)"],
        cancel,
        8 * 1024 * 1024,
    )
    .await?;
    let mut missing = unreachable.clone();
    let mut expanded = 0_u128;
    for line in listing.lines() {
        let mut fields = line.split_ascii_whitespace();
        let oid = fields.next().ok_or_else(|| anyhow::anyhow!("invalid Git object size listing"))?;
        let size = fields.next().ok_or_else(|| anyhow::anyhow!("invalid Git object size listing"))?;
        if fields.next().is_some() {
            bail!("invalid Git object size listing");
        }
        if missing.remove(oid) {
            expanded = expanded.saturating_add(size.parse::<u128>()?);
        }
    }
    if !missing.is_empty() {
        bail!("unreachable Git object missing from size listing");
    }
    // A pack rewrite can temporarily hold old packs and loose objects
    // alongside a new reachable pack. Count both current pack and loose
    // storage twice, plus the expanded contents and room for unrelated writes.
    let existing = (counts.pack_kib as u128).saturating_add(counts.loose_kib as u128).saturating_mul(1024);
    let required = existing.saturating_mul(2).saturating_add(expanded).saturating_add(256 * 1024 * 1024);
    let available = fs2::available_space(git_dir)? as u128;
    if available < required {
        bail!("insufficient free space for packed Git GC");
    }
    Ok(())
}

async fn all_unreachable_due<C: GenericClient + Sync>(
    tx: &C,
    repo: Uuid,
    tenant: Uuid,
    generation: i64,
    report: &str,
) -> Result<bool> {
    let oids = report.lines().filter_map(candidate).map(|(oid, _)| oid.to_owned()).collect::<HashSet<_>>();
    if oids.len() > 100_000 {
        bail!("unreachable closure exceeds inspection limit");
    }
    if oids.is_empty() {
        return Ok(true);
    }
    let oids = oids.into_iter().collect::<Vec<_>>();
    Ok(tx
        .query_one(
            "SELECT NOT EXISTS( \
               SELECT 1 FROM unnest($4::text[]) AS u(oid) \
               LEFT JOIN storage_maintenance_tombstones t ON t.repository_id=$1 \
                 AND t.tenant_id=$2 AND t.repository_generation=$3 AND t.oid=u.oid \
                 AND t.state IN ('pending','deleting') AND t.delete_after<=clock_timestamp() \
               WHERE t.oid IS NULL)",
            &[&repo, &tenant, &generation, &oids],
        )
        .await?
        .get(0))
}

async fn mark_delete_intents(
    state: &AppState,
    repo: Uuid,
    tenant: Uuid,
    generation: i64,
    oids: &[String],
) -> Result<()> {
    // Commit on a separate connection while the caller retains its fence and
    // local guards. A crash after unlink can then be reconciled without
    // pretending an absent object became reachable.
    let client = state.pool.get().await?;
    let rows = client
        .query(
            "UPDATE storage_maintenance_tombstones SET state='deleting', \
             attempts=attempts+CASE WHEN state='pending' THEN 1 ELSE 0 END,last_error=NULL \
             WHERE repository_id=$1 AND tenant_id=$2 AND repository_generation=$3 \
               AND oid=ANY($4) AND state IN ('pending','deleting') \
               AND delete_after<=clock_timestamp() RETURNING oid",
            &[&repo, &tenant, &generation, &oids],
        )
        .await?;
    ensure!(rows.len() == oids.len(), "tombstone delete intent was superseded");
    Ok(())
}

async fn reset_restored_intents(
    state: &AppState,
    repo: Uuid,
    tenant: Uuid,
    generation: i64,
    oids: &[String],
) -> Result<()> {
    if oids.is_empty() {
        return Ok(());
    }
    let client = state.pool.get().await?;
    client
        .execute(
            "UPDATE storage_maintenance_tombstones SET state='pending', \
             last_error='quarantine restored after GC fence loss' \
             WHERE repository_id=$1 AND tenant_id=$2 AND repository_generation=$3 \
               AND oid=ANY($4) AND state='deleting'",
            &[&repo, &tenant, &generation, &oids],
        )
        .await?;
    Ok(())
}

async fn mark_retained(
    state: &AppState,
    repo: Uuid,
    tenant: Uuid,
    generation: i64,
    oids: &[String],
    reason: &str,
) -> Result<u64> {
    if oids.is_empty() {
        return Ok(0);
    }
    let client = state.pool.get().await?;
    Ok(client
        .execute(
            "UPDATE storage_maintenance_tombstones SET state='retained',last_error=$5 \
             WHERE repository_id=$1 AND tenant_id=$2 AND repository_generation=$3 \
               AND oid=ANY($4) AND state IN ('pending','deleting')",
            &[&repo, &tenant, &generation, &oids, &reason],
        )
        .await?)
}

async fn reconcile_deleted(
    state: &AppState,
    repo: Uuid,
    tenant: Uuid,
    generation: i64,
    oids: &[String],
) -> Result<u64> {
    if oids.is_empty() {
        return Ok(0);
    }
    let client = state.pool.get().await?;
    Ok(client
        .execute(
            "UPDATE storage_maintenance_tombstones SET state='deleted', \
             deleted_at=clock_timestamp(),last_error=NULL \
             WHERE repository_id=$1 AND tenant_id=$2 AND repository_generation=$3 \
               AND oid=ANY($4) AND state='deleting'",
            &[&repo, &tenant, &generation, &oids],
        )
        .await?)
}

fn loose_path(git_dir: &Path, oid: &str) -> Result<std::path::PathBuf> {
    ensure!(matches!(oid.len(), 40 | 64), "invalid loose object ID");
    let (dir, file) = oid.split_at(2);
    let path = git_dir.join("objects").join(dir).join(file);
    Ok(path)
}

/// Called only after the worker has acquired the exclusive read lease, local
/// writer/reader gates, and a committed `Fence`.
pub async fn delete_due(
    state: &AppState,
    job: &Job,
    lease: &Lease,
    fence: &Fence,
    cancel: &CancellationToken,
) -> Result<Value> {
    lease.ensure_active().map_err(|_| anyhow::anyhow!("repository reader barrier lost"))?;
    fence.ensure_active()?;
    let repo = job.repository_id;
    let tenant = job.tenant_id;
    let generation = job.repository_generation;
    let git_dir = state.storage.verify_path(repo)?;
    reject_unsafe_topology(&git_dir)?;
    let restored = super::quarantine::recover(&git_dir, repo)?;
    if restored > 0 {
        eprintln!("rootyard: restored {restored} quarantined Git objects before collection");
    }

    let client = state.pool.get().await?;
    let rows = client
        .query(
            "SELECT oid,state FROM storage_maintenance_tombstones \
             WHERE repository_id=$1 AND tenant_id=$2 AND repository_generation=$3 \
               AND state IN ('pending','deleting') AND delete_after<=clock_timestamp() \
             ORDER BY delete_after,oid LIMIT 100",
            &[&repo, &tenant, &generation],
        )
        .await?;
    if rows.is_empty() {
        return Ok(json!({"deleted":0,"retained":0,"gc_epoch":fence.epoch()}));
    }

    let mut report = fsck_unreachable(state, repo, cancel).await?;
    if !all_unreachable_due(&**client, repo, tenant, generation, &report).await? {
        return Ok(json!({
            "deleted":0,
            "retained":"unexpired unreachable object closure",
            "gc_epoch":fence.epoch()
        }));
    }

    let unreachable = unreachable_set(&report);
    let mut packed_due = false;
    for row in &rows {
        let oid: String = row.get(0);
        if unreachable.contains(&oid)
            && !loose_path(&git_dir, &oid)?.exists()
            && gitfs::object_exists(state, repo, &oid, cancel).await?
        {
            packed_due = true;
            break;
        }
    }
    if packed_due {
        fence.verify(job, lease, cancel).await?;
        require_pack_rewrite_space(state, repo, &git_dir, &unreachable, cancel).await?;
        // Under the committed fence, this rewrite retains every reachable
        // object and loosens unreachable objects from old packs. Actual
        // unlinks still go through the quarantine below.
        gitfs::run_git(state, repo, &["repack", "-A", "-d", "--no-write-bitmap-index"], cancel, 1024).await?;
        fence.verify(job, lease, cancel).await?;
        report = fsck_unreachable(state, repo, cancel).await?;
        if !all_unreachable_due(&**client, repo, tenant, generation, &report).await? {
            bail!("unreachable closure changed after pack rewrite");
        }
    }

    let unreachable = unreachable_set(&report);
    let mut due_oids = Vec::new();
    let mut retained_oids = Vec::new();
    let mut prior_deleting = HashSet::new();
    for row in &rows {
        let oid: String = row.get(0);
        let prior: String = row.get(1);
        if prior == "deleting" {
            prior_deleting.insert(oid.clone());
        }
        if unreachable.contains(&oid) {
            due_oids.push(oid);
        } else {
            retained_oids.push(oid);
        }
    }
    // Objects whose intent survived a crash but whose bytes are already gone
    // are reconciled as deleted only after a fresh native absence check.
    let mut absent_before = Vec::new();
    if !prior_deleting.is_empty() {
        let prior = prior_deleting.iter().cloned().collect::<Vec<_>>();
        let existing = gitfs::existing_oids(state, repo, &prior, cancel).await?;
        for oid in prior {
            if !existing.contains(&oid) {
                absent_before.push(oid);
            }
        }
    }
    retained_oids.retain(|oid| !absent_before.contains(oid));
    if !retained_oids.is_empty() {
        mark_retained(state, repo, tenant, generation, &retained_oids, "native reachability changed").await?;
    }
    if due_oids.is_empty() {
        if !absent_before.is_empty() {
            reconcile_deleted(state, repo, tenant, generation, &absent_before).await?;
        }
        let retained = if retained_oids.is_empty() {
            json!(0)
        } else if fence.sql_root_count() > 0 {
            json!("active external roots")
        } else {
            json!(retained_oids.len())
        };
        return Ok(json!({
            "deleted":absent_before.len(),
            "retained":retained,
            "gc_epoch":fence.epoch()
        }));
    }

    mark_delete_intents(state, repo, tenant, generation, &due_oids).await?;
    let mut quarantine = Quarantine::begin(&git_dir, repo, fence.epoch(), job.id)?;
    let mut staged = 0u64;
    let mut absent_after_intent = Vec::new();
    for oid in &due_oids {
        let path = loose_path(&git_dir, oid)?;
        match fs::symlink_metadata(&path) {
            Ok(meta) => {
                if !meta.file_type().is_file() || meta.nlink() != 1 {
                    bail!("unsafe loose Git object");
                }
                quarantine.stage(oid)?;
                staged += 1;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if gitfs::object_exists(state, repo, oid, cancel).await? {
                    bail!("unreachable object remains packed after rewrite");
                }
                absent_after_intent.push(oid.clone());
            }
            Err(error) => return Err(error.into()),
        }
    }

    // This is the destructive-phase gate. Any lost lease, epoch, claim, root
    // change, writer admission, or cancellation restores the quarantine.
    let verified = async {
        fence.verify(job, lease, cancel).await?;
        ensure!(!cancel.is_cancelled(), "maintenance lease lost");
        let client = state.pool.get().await?;
        let active: i64 = client
            .query_one(
                "SELECT count(*) FROM storage_write_admissions \
                 WHERE repository_id=$1 AND state='active' \
                   AND lease_until > clock_timestamp()",
                &[&repo],
            )
            .await?
            .get(0);
        ensure!(active == 0, "a writer was admitted during quarantine");
        Ok::<(), anyhow::Error>(())
    }
    .await;
    if let Err(error) = verified {
        let restored = quarantine.rollback()?;
        reset_restored_intents(state, repo, tenant, generation, &due_oids).await?;
        return Err(error.context(format!("physical deletion aborted; restored {restored} quarantined objects")));
    }

    let unlinked = quarantine.commit()?;
    let mut check_oids = due_oids.clone();
    check_oids.extend(absent_before.iter().cloned());
    check_oids.extend(absent_after_intent.iter().cloned());
    check_oids.sort();
    check_oids.dedup();
    let existing = gitfs::existing_oids(state, repo, &check_oids, cancel).await?;
    let mut gone = Vec::new();
    let mut survived = Vec::new();
    for oid in check_oids {
        if existing.contains(&oid) {
            survived.push(oid);
        } else {
            gone.push(oid);
        }
    }
    let deleted = reconcile_deleted(state, repo, tenant, generation, &gone).await?;
    if !survived.is_empty() {
        mark_retained(state, repo, tenant, generation, &survived, "native object still present after quarantine")
            .await?;
    }
    fence.verify(job, lease, cancel).await?;
    let retained = if retained_oids.is_empty() {
        json!(0)
    } else if fence.sql_root_count() > 0 {
        json!("active external roots")
    } else {
        json!(retained_oids.len())
    };
    Ok(json!({
        "deleted":deleted,
        "retained":retained,
        "quarantined_unlinked":unlinked,
        "quarantine_restored_on_failure":false,
        "gc_epoch":fence.epoch(),
        "staged":staged,
        "absent_intents":absent_before.len()+absent_after_intent.len()
    }))
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
