//! Durable Pando maintenance.
//!
//! Pando authority is the PostgreSQL ref set plus the committed pack-id list.
//! Compaction publishes a new, complete encrypted pack closure and atomically
//! replaces the serving pack list; old pack rows and remote ciphertext are
//! deliberately retained, so this phase can never delete an object that a
//! backup, active snapshot or historical pin may still need.
use super::models::{Job, Policy};
use crate::{
    AppState,
    db::Repository,
    git_http,
    pando_gateway::{pack_store::PackStore, snapshot},
    storage::read_leases::Lease,
};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, HashSet},
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, SystemTime},
};
use tokio::{process::Command, time::Instant};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

const MAX_PACKS: usize = 256;
const MAINTENANCE_DEADLINE: Duration = Duration::from_secs(300);

pub fn is_pando_kind(kind: &str) -> bool {
    matches!(
        kind,
        "pando_repack"
            | "pando_cache_hydrate"
            | "pando_cache_evict"
            | "pando_unreachable_mark"
            | "pando_tombstone_delete"
    )
}

struct VerifyDir(PathBuf);
impl Drop for VerifyDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Debug)]
struct Serving {
    tenant_id: Uuid,
    storage_generation: i64,
    ref_generation: i64,
    object_format: String,
    head_ref: String,
    pack_ids: Vec<Uuid>,
}

async fn serving(state: &AppState, repo: &Repository) -> Result<Serving> {
    let client = state.pool.get().await?;
    let row = client
        .query_one(
            "SELECT r.owner_id,r.storage_backend,r.storage_generation,r.state,r.transition_state, \
             s.tenant_id,s.state AS pando_state,s.storage_generation AS pando_generation,s.ref_generation, \
             s.object_format AS pando_format,s.head_ref,s.pack_ids \
             FROM repositories r JOIN pando_repository_states s ON s.repository_id=r.id \
             WHERE r.id=$1",
            &[&repo.id],
        )
        .await
        .context("load Pando serving authority")?;
    let pack_ids: Vec<Uuid> = row.get("pack_ids");
    ensure!(
        row.get::<_, String>("storage_backend") == "pando"
            && row.get::<_, String>("state") == "ready"
            && row.get::<_, String>("transition_state") == "stable"
            && row.get::<_, Uuid>("tenant_id") == row.get::<_, Uuid>("owner_id")
            && row.get::<_, i64>("storage_generation") == repo.storage_generation
            && row.get::<_, i64>("pando_generation") == repo.storage_generation
            && row.get::<_, String>("pando_format") == repo.object_format
            && row.get::<_, String>("state") == "ready"
            && row.get::<_, String>("pando_state") == "serving",
        "Pando repository is not a stable serving snapshot"
    );
    ensure!(!pack_ids.is_empty() && pack_ids.len() <= MAX_PACKS, "Pando pack set exceeds maintenance bound");
    let head_ref: String = row.get("head_ref");
    ensure!(
        head_ref.starts_with("refs/heads/") && crate::journal::valid_ref(&head_ref),
        "Pando advertised HEAD is invalid"
    );
    Ok(Serving {
        tenant_id: row.get("tenant_id"),
        storage_generation: row.get("storage_generation"),
        ref_generation: row.get("ref_generation"),
        object_format: row.get("pando_format"),
        head_ref,
        pack_ids,
    })
}

async fn pando_git(state: &AppState, path: &Path, args: &[&str], lease: &Lease, deadline: Instant) -> Result<Vec<u8>> {
    lease.ensure_active().map_err(|error| anyhow::anyhow!(error.1))?;
    let mut command = Command::new(&state.config.git);
    command
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .arg("--git-dir")
        .arg(path)
        .args(args)
        .stdin(Stdio::null());
    let timeout = deadline.saturating_duration_since(Instant::now()).min(Duration::from_secs(120));
    ensure!(!timeout.is_zero(), "Pando maintenance deadline elapsed");
    lease
        .guard(git_http::collect_git_output(command, 64 * 1024 * 1024, timeout))
        .await
        .map_err(|error| anyhow::anyhow!(error.1))?
}

async fn pando_git_input(
    state: &AppState,
    path: &Path,
    args: &[&str],
    input: &Path,
    lease: &Lease,
    deadline: Instant,
) -> Result<Vec<u8>> {
    lease.ensure_active().map_err(|error| anyhow::anyhow!(error.1))?;
    let mut command = Command::new(&state.config.git);
    command
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .arg("--git-dir")
        .arg(path)
        .args(args);
    let timeout = deadline.saturating_duration_since(Instant::now()).min(Duration::from_secs(120));
    ensure!(!timeout.is_zero(), "Pando maintenance deadline elapsed");
    let file = std::fs::File::open(input)?;
    lease
        .guard(git_http::collect_git_output_input(command, 64 * 1024 * 1024, timeout, Stdio::from(file)))
        .await
        .map_err(|error| anyhow::anyhow!(error.1))?
}

fn valid_oid(oid: &str) -> bool {
    matches!(oid.len(), 40 | 64)
        && oid.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && oid.bytes().any(|byte| byte != b'0')
}

async fn all_objects(
    state: &AppState,
    path: &Path,
    lease: &Lease,
    deadline: Instant,
) -> Result<BTreeMap<String, String>> {
    let raw = pando_git(
        state,
        path,
        &["cat-file", "--batch-all-objects", "--batch-check=%(objectname) %(objecttype)"],
        lease,
        deadline,
    )
    .await?;
    let text = String::from_utf8(raw)?;
    let mut objects = BTreeMap::new();
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let oid = fields.next().context("missing Pando object identity")?;
        let kind = fields.next().context("missing Pando object type")?;
        ensure!(
            fields.next().is_none() && valid_oid(oid) && matches!(kind, "commit" | "tree" | "blob" | "tag"),
            "invalid Pando native object listing"
        );
        ensure!(objects.insert(oid.to_owned(), kind.to_owned()).is_none(), "duplicate Pando object identity");
    }
    ensure!(!objects.is_empty(), "Pando compaction requires a non-empty object set");
    Ok(objects)
}

async fn packed_objects(
    state: &AppState,
    pack: &Path,
    lease: &Lease,
    deadline: Instant,
) -> Result<BTreeMap<String, String>> {
    lease.ensure_active().map_err(|error| anyhow::anyhow!(error.1))?;
    let mut command = Command::new(&state.config.git);
    command
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args(["verify-pack", "-v"])
        .arg(pack)
        .stdin(Stdio::null());
    let timeout = deadline.saturating_duration_since(Instant::now()).min(Duration::from_secs(120));
    ensure!(!timeout.is_zero(), "Pando maintenance deadline elapsed");
    let raw = lease
        .guard(git_http::collect_git_output(command, 64 * 1024 * 1024, timeout))
        .await
        .map_err(|error| anyhow::anyhow!(error.1))??;
    let text = String::from_utf8(raw)?;
    let mut objects = BTreeMap::new();
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let Some(oid) = fields.next() else { continue };
        if !valid_oid(oid) {
            continue;
        }
        let kind = fields.next().context("missing packed Pando object type")?;
        ensure!(matches!(kind, "commit" | "tree" | "blob" | "tag"), "invalid packed Pando object type");
        ensure!(objects.insert(oid.to_owned(), kind.to_owned()).is_none(), "duplicate packed Pando object");
    }
    Ok(objects)
}

async fn verify_candidate(
    state: &AppState,
    snapshot: &snapshot::Snapshot,
    repo: &Repository,
    pack: &Path,
    index: &Path,
    lease: &Lease,
    deadline: Instant,
) -> Result<()> {
    let parent = snapshot.path().parent().context("Pando session root missing")?;
    let verify = VerifyDir(parent.join(format!(".verify-{}", Uuid::new_v4())));
    std::fs::DirBuilder::new().mode(0o700).create(&verify.0)?;
    let format = format!("--object-format={}", repo.object_format);
    pando_git(state, &verify.0, &["init", "--bare", &format], lease, deadline).await?;
    // Git matches pack/index by basename. Link exactly the candidate pair
    // into an otherwise empty disposable repository.
    let pack_dir = verify.0.join("objects/pack");
    std::fs::create_dir_all(&pack_dir)?;
    let base = format!("pack-{}", Uuid::new_v4());
    let target_pack = pack_dir.join(format!("{base}.pack"));
    let target_index = pack_dir.join(format!("{base}.idx"));
    if std::fs::hard_link(pack, &target_pack).is_err() {
        std::fs::copy(pack, &target_pack)?;
    }
    if std::fs::hard_link(index, &target_index).is_err() {
        std::fs::copy(index, &target_index)?;
    }
    for (name, oid) in &snapshot.refs {
        pando_git(state, &verify.0, &["update-ref", "--no-deref", name, oid], lease, deadline).await?;
    }
    pando_git(state, &verify.0, &["symbolic-ref", "HEAD", &snapshot.head_ref], lease, deadline).await?;
    pando_git(state, &verify.0, &["fsck", "--full", "--strict"], lease, deadline).await?;
    let raw =
        pando_git(state, &verify.0, &["for-each-ref", "--format=%(refname) %(objectname)"], lease, deadline).await?;
    let text = String::from_utf8(raw)?;
    let mut actual = BTreeMap::new();
    for line in text.lines() {
        let (name, oid) = line.split_once(' ').context("invalid compacted Pando ref")?;
        ensure!(valid_oid(oid) && name.starts_with("refs/"), "invalid compacted Pando ref");
        ensure!(actual.insert(name.to_owned(), oid.to_owned()).is_none(), "duplicate compacted Pando ref");
    }
    ensure!(actual == snapshot.refs, "compaction changed the authoritative Pando refs");
    Ok(())
}

fn write_allowed(kind: &str) -> bool {
    matches!(
        kind,
        "pando_repack"
            | "pando_cache_hydrate"
            | "pando_cache_evict"
            | "pando_unreachable_mark"
            | "pando_tombstone_delete"
    )
}

/// Execute one claimed Pando job while the caller holds the global backup
/// barrier, the repository-exclusive PostgreSQL read lease, local writer and
/// reader gates, and a current generation-fenced claim.
pub async fn execute(
    state: &std::sync::Arc<AppState>,
    repo: &Repository,
    job: &Job,
    lease: &Lease,
    policy: &Policy,
    cancel: &CancellationToken,
) -> Result<Value> {
    ensure!(repo.storage_backend == "pando", "Pando maintenance requires a Pando repository");
    ensure!(!cancel.is_cancelled(), "maintenance lease lost");
    ensure!(write_allowed(&job.kind), "unsupported Pando maintenance job kind");
    match job.kind.as_str() {
        "pando_repack" => repack(state, repo, job, lease, cancel).await,
        "pando_cache_hydrate" => cache_hydrate(state, repo, lease, cancel).await,
        "pando_cache_evict" => {
            lease.ensure_active().map_err(|error| anyhow::anyhow!(error.1))?;
            let removed = evict_expired(&state.storage.root, repo.id, policy.cache_max_age_seconds, cancel)?;
            lease.ensure_active().map_err(|error| anyhow::anyhow!(error.1))?;
            Ok(json!({"cache_files_removed":removed,"remote_deleted":false}))
        }
        "pando_unreachable_mark" => mark_unreachable(state, repo, job, lease, policy, cancel).await,
        "pando_tombstone_delete" => delete_tombstones(state, repo, job, lease, policy, cancel).await,
        _ => bail!("unsupported Pando maintenance job kind"),
    }
}

/// SQL predicate shared by marking and deletion. An artifact is retained if
/// *any* manifest that links it is still part of a serving pack set, or if the
/// owning repository is not a stable ready Pando repository. S3 object listing
/// is never consulted.
const RETAINED_LINK: &str = "EXISTS (SELECT 1 FROM pando_manifest_artifacts l \
   JOIN pando_pack_manifests m ON m.id=l.manifest_id \
   JOIN repositories r ON r.id=m.repository_id \
   WHERE l.authority_id=a.authority_id AND l.tenant_id=a.tenant_id \
     AND l.namespace=a.namespace AND l.sha256=a.sha256 \
     AND (r.storage_backend <> 'pando' OR r.state <> 'ready' OR r.transition_state <> 'stable' \
       OR EXISTS (SELECT 1 FROM pando_repository_states s \
                  WHERE s.repository_id=m.repository_id AND m.id = ANY(s.pack_ids))))";

async fn mark_unreachable(
    state: &std::sync::Arc<AppState>,
    repo: &Repository,
    job: &Job,
    lease: &Lease,
    policy: &Policy,
    cancel: &CancellationToken,
) -> Result<Value> {
    lease.ensure_active().map_err(|error| anyhow::anyhow!(error.1))?;
    ensure!(!cancel.is_cancelled(), "maintenance lease lost before Pando mark");
    let client = state.pool.get().await?;
    let authority = crate::pando_gateway::retention::authority(&**client).await?;
    let tenant = job.tenant_id;
    let linked = "EXISTS (SELECT 1 FROM pando_manifest_artifacts l \
        WHERE l.authority_id=a.authority_id AND l.tenant_id=a.tenant_id \
          AND l.namespace=a.namespace AND l.sha256=a.sha256 AND l.repository_id=$3)";
    let eligible = format!(
        "SELECT count(*) FROM pando_remote_artifacts a \
         WHERE a.authority_id=$1 AND a.tenant_id=$2 AND a.state='active' \
           AND a.remote_path LIKE '%/authorities/%' AND {linked} AND NOT {RETAINED_LINK}"
    );
    let protected_serving = format!(
        "SELECT count(*) FROM pando_remote_artifacts a \
         WHERE a.authority_id=$1 AND a.tenant_id=$2 AND a.state='active' AND {linked} \
           AND EXISTS (SELECT 1 FROM pando_manifest_artifacts l \
             JOIN pando_pack_manifests m ON m.id=l.manifest_id \
             JOIN pando_repository_states s ON s.repository_id=m.repository_id \
             WHERE l.authority_id=a.authority_id AND l.tenant_id=a.tenant_id \
               AND l.namespace=a.namespace AND l.sha256=a.sha256 AND m.id = ANY(s.pack_ids))"
    );
    let protected_transition = format!(
        "SELECT count(*) FROM pando_remote_artifacts a \
         WHERE a.authority_id=$1 AND a.tenant_id=$2 AND a.state='active' AND {linked} \
           AND EXISTS (SELECT 1 FROM pando_manifest_artifacts l \
             JOIN pando_pack_manifests m ON m.id=l.manifest_id \
             JOIN repositories r ON r.id=m.repository_id \
             WHERE l.authority_id=a.authority_id AND l.tenant_id=a.tenant_id \
               AND l.namespace=a.namespace AND l.sha256=a.sha256 \
               AND (r.storage_backend <> 'pando' OR r.state <> 'ready' OR r.transition_state <> 'stable'))"
    );
    let dry: i64 = client.query_one(&eligible, &[&authority.id, &tenant, &repo.id]).await?.get(0);
    let serving: i64 = client.query_one(&protected_serving, &[&authority.id, &tenant, &repo.id]).await?.get(0);
    let transition: i64 = client.query_one(&protected_transition, &[&authority.id, &tenant, &repo.id]).await?.get(0);
    lease.ensure_active().map_err(|error| anyhow::anyhow!(error.1))?;
    ensure!(!cancel.is_cancelled(), "maintenance lease lost before Pando mark commit");
    let update = format!(
        "UPDATE pando_remote_artifacts a SET state='retired',updated_at=clock_timestamp(), \
          delete_after=clock_timestamp()+make_interval(secs=>$4) \
         WHERE a.authority_id=$1 AND a.tenant_id=$2 AND a.state='active' \
           AND a.remote_path LIKE '%/authorities/%' AND {linked} AND NOT {RETAINED_LINK}"
    );
    let marked = client.execute(&update, &[&authority.id, &tenant, &repo.id, &policy.tombstone_grace_seconds]).await?;
    let counts = crate::pando_gateway::retention::counts(&**client, tenant).await?;
    Ok(json!({
        "authority_id": authority.id,
        "eligible": dry,
        "marked_retired": marked,
        "protected_serving": serving,
        "protected_transition": transition,
        "reserved_uploads": counts.reserved,
        "active": counts.active,
        "retired": counts.retired,
        "deleting": counts.deleting,
        "deleted": counts.deleted,
        "remote_deleted": false,
        "authority": "authority-scoped registered artifacts only; legacy v1 keys excluded"
    }))
}

async fn delete_tombstones(
    state: &std::sync::Arc<AppState>,
    repo: &Repository,
    job: &Job,
    lease: &Lease,
    policy: &Policy,
    cancel: &CancellationToken,
) -> Result<Value> {
    lease.ensure_active().map_err(|error| anyhow::anyhow!(error.1))?;
    let client = state.pool.get().await?;
    let authority = crate::pando_gateway::retention::authority(&**client).await?;
    let tenant = job.tenant_id;
    let counts = crate::pando_gateway::retention::counts(&**client, tenant).await?;
    let enabled = std::env::var("ROOTYARD_PANDO_REMOTE_DELETE").ok().as_deref() == Some("true");
    if !enabled {
        return Ok(json!({
            "remote_deleted": false,
            "dry_run": true,
            "reason": "ROOTYARD_PANDO_REMOTE_DELETE is not enabled; marking and proofs remain active",
            "retired": counts.retired,
            "deleting": counts.deleting,
            "deleted": counts.deleted
        }));
    }
    let linked = "EXISTS (SELECT 1 FROM pando_manifest_artifacts l \
        WHERE l.authority_id=a.authority_id AND l.tenant_id=a.tenant_id \
          AND l.namespace=a.namespace AND l.sha256=a.sha256 AND l.repository_id=$3)";
    let claim = format!(
        "WITH candidates AS ( \
           SELECT a.authority_id,a.tenant_id,a.namespace,a.sha256 \
           FROM pando_remote_artifacts a \
           WHERE a.authority_id=$1 AND a.tenant_id=$2 AND a.state='retired' \
             AND a.delete_after<=clock_timestamp() AND a.remote_path LIKE '%/authorities/%' \
             AND {linked} AND NOT {RETAINED_LINK} \
           ORDER BY a.delete_after,a.namespace,a.sha256 LIMIT 32 FOR UPDATE SKIP LOCKED) \
         UPDATE pando_remote_artifacts a SET state='deleting',claimed_by=$4, \
           claim_generation=a.claim_generation+1,attempts=a.attempts+1,last_error=NULL, \
           lease_until=clock_timestamp()+make_interval(secs=>$5),updated_at=clock_timestamp() \
         FROM candidates c WHERE a.authority_id=c.authority_id AND a.tenant_id=c.tenant_id \
           AND a.namespace=c.namespace AND a.sha256=c.sha256 \
         RETURNING a.tenant_id,a.namespace,a.sha256,a.object_generation,a.remote_path,a.claim_generation"
    );
    let claimed =
        client.query(&claim, &[&authority.id, &tenant, &repo.id, &job.lease_owner, &policy.lease_seconds]).await?;
    let remote =
        crate::storage::remote_objects::RemoteObjectStore::from_env(state.storage.root.join("pando-pack-work"))?;
    let deadline = Instant::now() + MAINTENANCE_DEADLINE;
    let mut deleted = 0usize;
    let mut fenced = 0usize;
    let mut retryable = 0usize;
    for row in &claimed {
        if cancel.is_cancelled() {
            break;
        }
        let namespace: String = row.get(1);
        let sha256: String = row.get(2);
        let generation: i64 = row.get(3);
        let remote_path: String = row.get(4);
        let claim_generation: i64 = row.get(5);
        let key = match crate::storage::remote_objects::ObjectKey::scoped(
            tenant,
            authority.id,
            generation,
            &namespace,
            &sha256,
        ) {
            Ok(key) if key.path() == remote_path => key,
            _ => {
                fenced += 1;
                continue;
            }
        };
        let still = format!(
            "SELECT 1 FROM pando_remote_artifacts a WHERE a.authority_id=$1 AND a.tenant_id=$2 \
               AND a.namespace=$3 AND a.sha256=$4 AND a.state='deleting' AND a.claimed_by=$5 \
               AND a.claim_generation=$6 AND a.remote_path=$7 AND NOT {RETAINED_LINK}"
        );
        let current = client
            .query_opt(
                &still,
                &[&authority.id, &tenant, &namespace, &sha256, &job.lease_owner, &claim_generation, &remote_path],
            )
            .await?;
        if current.is_none() {
            fenced += 1;
            continue;
        }
        if lease.ensure_active().is_err() {
            break;
        }
        if let Err(error) = remote.delete(&key, deadline).await {
            let _ = client
                .execute(
                    "UPDATE pando_remote_artifacts SET state='retired',claimed_by=NULL,lease_until=NULL, \
                     delete_after=clock_timestamp()+make_interval(secs=>60),last_error=$5,updated_at=clock_timestamp() \
                     WHERE authority_id=$1 AND tenant_id=$2 AND namespace=$3 AND sha256=$4 \
                       AND state='deleting' AND claimed_by=$6 AND claim_generation=$7",
                    &[
                        &authority.id,
                        &tenant,
                        &namespace,
                        &sha256,
                        &format!("remote delete failed: {error:#}"),
                        &job.lease_owner,
                        &claim_generation,
                    ],
                )
                .await?;
            retryable += 1;
            continue;
        }
        let finalized = client
            .execute(
                "UPDATE pando_remote_artifacts SET state='deleted',deleted_at=clock_timestamp(), \
                 claimed_by=NULL,lease_until=NULL,last_error=NULL,updated_at=clock_timestamp() \
                 WHERE authority_id=$1 AND tenant_id=$2 AND namespace=$3 AND sha256=$4 \
                   AND state='deleting' AND claimed_by=$5 AND claim_generation=$6 AND remote_path=$7",
                &[&authority.id, &tenant, &namespace, &sha256, &job.lease_owner, &claim_generation, &remote_path],
            )
            .await?;
        if finalized == 1 {
            deleted += 1;
        } else {
            fenced += 1;
        }
    }
    let after = crate::pando_gateway::retention::counts(&**client, tenant).await?;
    Ok(json!({
        "remote_deleted": true,
        "claimed": claimed.len(),
        "deleted": deleted,
        "fenced_or_resurrected": fenced,
        "retryable": retryable,
        "retired": after.retired,
        "deleted_total": after.deleted
    }))
}

async fn repack(
    state: &std::sync::Arc<AppState>,
    repo: &Repository,
    job: &Job,
    lease: &Lease,
    cancel: &CancellationToken,
) -> Result<Value> {
    let before = serving(state, repo).await?;
    ensure!(before.tenant_id == job.tenant_id, "Pando maintenance tenant changed");
    let deadline = Instant::now() + MAINTENANCE_DEADLINE;
    let snapshot =
        snapshot::materialize(state, repo, lease, deadline).await.map_err(|error| anyhow::anyhow!(error.1))?;
    ensure!(!cancel.is_cancelled(), "maintenance lease lost before Pando repack");
    ensure!(
        snapshot.storage_generation == before.storage_generation
            && snapshot.ref_generation == before.ref_generation
            && snapshot.source_packs == before.pack_ids,
        "Pando serving snapshot changed before repack"
    );
    let all = all_objects(state, snapshot.path(), lease, deadline).await?;
    ensure!(all.len() <= 1_000_000, "Pando compaction object count exceeds bound");
    let output = snapshot.path().join(".compact-output");
    std::fs::DirBuilder::new().mode(0o700).create(&output)?;
    let list = snapshot.path().join(".compact-objects");
    let mut input = String::with_capacity(all.len().saturating_mul(41));
    for oid in all.keys() {
        input.push_str(oid);
        input.push('\n');
    }
    std::fs::write(&list, input.as_bytes())?;
    let prefix = output.join("pack");
    pando_git_input(
        state,
        snapshot.path(),
        &["pack-objects", "-q", prefix.to_str().context("Pando pack prefix path")?],
        &list,
        lease,
        deadline,
    )
    .await?;
    let mut packs = Vec::new();
    for entry in std::fs::read_dir(&output)? {
        let path = entry?.path();
        if path.extension().is_some_and(|extension| extension == "pack") {
            packs.push(path);
        }
    }
    ensure!(packs.len() == 1, "Pando compaction did not produce one complete pack");
    let pack = packs.pop().expect("single compacted pack");
    let index = pack.with_extension("idx");
    ensure!(index.is_file(), "Pando compaction pack index missing");
    let packed = packed_objects(state, &pack, lease, deadline).await?;
    ensure!(packed == all, "Pando compaction did not preserve the complete object set");
    verify_candidate(state, &snapshot, repo, &pack, &index, lease, deadline).await?;
    let store = PackStore::from_env(state.storage.root.join("pando-pack-work"), state.config.git.clone())?;
    let manifest = lease
        .guard(Box::pin(store.publish(
            &state.pool,
            repo.id,
            before.tenant_id,
            before.storage_generation,
            &before.object_format,
            &pack,
            &index,
            deadline,
        )))
        .await
        .map_err(|error| anyhow::anyhow!(error.1))??;
    ensure!(!cancel.is_cancelled(), "maintenance lease lost before Pando pack-set commit");

    // Replace the serving pack list only if the exact PostgreSQL authority
    // snapshot is still current. A concurrent ref publication changes either
    // ref_generation or pack_ids and loses this CAS; the new pack stays an
    // orphan and is retried, never partially published.
    let mut client = state.pool.get().await?;
    let tx = client.transaction().await?;
    let row = tx
        .query_one(
            "SELECT r.owner_id,r.storage_backend,r.storage_generation,r.state,r.transition_state,s.tenant_id,s.storage_generation AS pando_generation,s.ref_generation,s.object_format AS pando_format,s.state AS pando_state,s.head_ref,s.pack_ids FROM repositories r JOIN pando_repository_states s ON s.repository_id=r.id WHERE r.id=$1 FOR UPDATE OF r,s",
            &[&repo.id],
        )
        .await?;
    let current_packs: Vec<Uuid> = row.get("pack_ids");
    ensure!(
        row.get::<_, Uuid>("owner_id") == before.tenant_id
            && row.get::<_, String>("storage_backend") == "pando"
            && row.get::<_, String>("state") == "ready"
            && row.get::<_, String>("transition_state") == "stable"
            && row.get::<_, i64>("storage_generation") == before.storage_generation
            && row.get::<_, i64>("pando_generation") == before.storage_generation
            && row.get::<_, Uuid>("tenant_id") == before.tenant_id
            && row.get::<_, i64>("ref_generation") == before.ref_generation
            && row.get::<_, String>("pando_format") == before.object_format
            && row.get::<_, String>("pando_state") == "serving"
            && row.get::<_, String>("head_ref") == before.head_ref
            && current_packs == before.pack_ids,
        "Pando pack-set authority changed during compaction"
    );
    ensure!(!cancel.is_cancelled(), "maintenance lease lost before Pando pack-set CAS");
    let new_packs = vec![manifest.id];
    let changed = tx
        .execute(
            "UPDATE pando_repository_states SET pack_ids=$2,updated_at=clock_timestamp() \
             WHERE repository_id=$1 AND tenant_id=$3 AND storage_generation=$4 \
               AND ref_generation=$5 AND pack_ids=$6 AND state='serving'",
            &[
                &repo.id,
                &new_packs,
                &before.tenant_id,
                &before.storage_generation,
                &before.ref_generation,
                &before.pack_ids,
            ],
        )
        .await?;
    ensure!(changed == 1, "Pando pack-set CAS was superseded");
    ensure!(!cancel.is_cancelled(), "maintenance lease lost before Pando pack-set commit");
    let state_updated = tx
        .execute(
            "UPDATE storage_maintenance_repo_state SET last_repack_at=clock_timestamp(), \
             last_repack_loose_count=0,last_repack_pack_count=$2 \
             WHERE repository_id=$1 AND tenant_id=$3 AND last_scan_generation=$4",
            &[&repo.id, &(new_packs.len() as i64), &before.tenant_id, &job.repository_generation],
        )
        .await?;
    tx.commit().await?;
    Ok(json!({
        "old_packs": before.pack_ids.len(),
        "new_packs": new_packs.len(),
        "new_pack_id": manifest.id,
        "new_pack_plaintext_bytes": manifest.pack.plaintext_bytes,
        "old_pack_manifests_retained": true,
        "remote_deleted": false,
        "maintenance_state_updated": state_updated == 1
    }))
}

async fn cache_hydrate(
    state: &std::sync::Arc<AppState>,
    repo: &Repository,
    lease: &Lease,
    cancel: &CancellationToken,
) -> Result<Value> {
    let serving = serving(state, repo).await?;
    let cache_dir = PackStore::cache_dir(&state.storage.root, repo.id);
    let store = PackStore::from_env(state.storage.root.join("pando-pack-work"), state.config.git.clone())?;
    let deadline = Instant::now() + MAINTENANCE_DEADLINE;
    let mut recovered = 0usize;
    let mut already_cached = 0usize;
    for pack_id in &serving.pack_ids {
        ensure!(!cancel.is_cancelled(), "maintenance lease lost during Pando cache hydration");
        let pack = cache_dir.join(format!("pack-{pack_id}.pack"));
        let index = cache_dir.join(format!("pack-{pack_id}.idx"));
        let cached = pack.is_file() && index.is_file();
        Box::pin(store.recover_to_cache(&state.pool, repo.id, *pack_id, &cache_dir, deadline)).await?;
        if !(pack.is_file() && index.is_file()) {
            bail!("Pando cache hydration did not produce a pack pair");
        }
        if cached { already_cached += 1 } else { recovered += 1 }
    }
    // Force a complete reconstructed snapshot through the cache. This checks
    // every authoritative ref and pack pair with native Git before reporting a
    // successful hydration.
    let snapshot =
        snapshot::materialize(state, repo, lease, deadline).await.map_err(|error| anyhow::anyhow!(error.1))?;
    drop(snapshot);
    Ok(json!({
        "packs": serving.pack_ids.len(),
        "already_cached": already_cached,
        "recovered": recovered,
        "verified": true,
        "cache_dir_created": cache_dir.is_dir()
    }))
}

fn cache_dir_missing(cache_dir: &Path) -> bool {
    matches!(std::fs::symlink_metadata(cache_dir), Err(error) if error.kind() == std::io::ErrorKind::NotFound)
}

fn validate_cache_dir(cache_dir: &Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(cache_dir)?;
    ensure!(meta.is_dir() && !meta.file_type().is_symlink(), "Pando cache path is not a private directory");
    Ok(())
}

/// Scheduler probe: a pack pair is incomplete when either file is absent.
pub fn cache_incomplete(storage_root: &Path, repo: Uuid, pack_ids: &[Uuid]) -> bool {
    let cache_dir = PackStore::cache_dir(storage_root, repo);
    if cache_dir_missing(&cache_dir) {
        return !pack_ids.is_empty();
    }
    pack_ids.iter().any(|id| {
        !cache_dir.join(format!("pack-{id}.pack")).is_file() || !cache_dir.join(format!("pack-{id}.idx")).is_file()
    })
}

fn expired_ids(cache_dir: &Path, max_age_seconds: i64, cancel: Option<&CancellationToken>) -> Result<Vec<Uuid>> {
    if cache_dir_missing(cache_dir) {
        return Ok(Vec::new());
    }
    validate_cache_dir(cache_dir)?;
    let cutoff = SystemTime::now().checked_sub(Duration::from_secs(max_age_seconds.max(1) as u64));
    let mut expired = HashSet::new();
    for entry in std::fs::read_dir(cache_dir)?.take(10_000) {
        if cancel.is_some_and(CancellationToken::is_cancelled) {
            bail!("maintenance lease lost during Pando cache eviction");
        }
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else { continue };
        let Some(rest) = name.strip_prefix("pack-") else { continue };
        let Some(id) = rest
            .strip_suffix(".pack")
            .or_else(|| rest.strip_suffix(".idx"))
            .and_then(|value| Uuid::parse_str(value).ok())
        else {
            continue;
        };
        let meta = std::fs::symlink_metadata(entry.path())?;
        if !meta.is_file() || meta.file_type().is_symlink() {
            continue;
        }
        if cutoff.is_some_and(|cutoff| meta.modified().is_ok_and(|modified| modified <= cutoff)) {
            expired.insert(id);
        }
    }
    Ok(expired.into_iter().collect())
}

/// Scheduler probe for the configured cache-retention age.
pub fn cache_evict_due(storage_root: &Path, repo: Uuid, max_age_seconds: i64) -> bool {
    let cache_dir = PackStore::cache_dir(storage_root, repo);
    expired_ids(&cache_dir, max_age_seconds, None).is_ok_and(|ids| !ids.is_empty())
}

/// Delete only expired local cache pairs. Remote pack bytes and PostgreSQL
/// manifests are untouched; active snapshots hold hard links to the same
/// inode, so unlinking a cache name cannot remove bytes from a live reader.
pub fn evict_expired(storage_root: &Path, repo: Uuid, max_age_seconds: i64, cancel: &CancellationToken) -> Result<u64> {
    let cache_dir = PackStore::cache_dir(storage_root, repo);
    let mut removed = 0u64;
    for id in expired_ids(&cache_dir, max_age_seconds, Some(cancel))? {
        ensure!(!cancel.is_cancelled(), "maintenance lease lost during Pando cache eviction");
        for path in [cache_dir.join(format!("pack-{id}.pack")), cache_dir.join(format!("pack-{id}.idx"))] {
            match std::fs::remove_file(&path) {
                Ok(()) => removed += 1,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("rootyard-pando-cache-{}", Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn incomplete_cache_is_detected_without_trusting_remote_listing() {
        let root = temp_dir();
        let repo = Uuid::new_v4();
        let id = Uuid::new_v4();
        assert!(cache_incomplete(&root, repo, &[id]));
        let cache_dir = PackStore::cache_dir(&root, repo);
        std::fs::create_dir_all(&cache_dir).unwrap();
        std::fs::write(cache_dir.join(format!("pack-{id}.pack")), b"pack").unwrap();
        assert!(cache_incomplete(&root, repo, &[id]), "a lone pack without its index is incomplete");
        std::fs::write(cache_dir.join(format!("pack-{id}.idx")), b"idx").unwrap();
        assert!(!cache_incomplete(&root, repo, &[id]));
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn only_pando_write_kinds_are_admitted() {
        assert!(write_allowed("pando_repack"));
        assert!(write_allowed("pando_cache_hydrate"));
        assert!(write_allowed("pando_cache_evict"));
        assert!(write_allowed("pando_unreachable_mark"));
        assert!(write_allowed("pando_tombstone_delete"));
        assert!(!write_allowed("gitfs_repack"));
        assert!(is_pando_kind("pando_tombstone_delete"));
    }
}
