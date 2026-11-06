//! Durable two-phase GitFS <-> Pando cutover and rollback.
//!
//! The transition fence lives on `repositories`: a begin step atomically sets
//! `transition_state='draining'`, mints a `transition_id` and bumps
//! `backend_transition_epoch`. Every write admission reads that state, so no
//! operation admitted after the fence can mutate authority. The final switch
//! re-checks the same fence row before committing the new backend.
use super::pack_store::{PackManifest, PackStore};
use crate::{AppState, Error, db::Repository, git_http};
use anyhow::{Result, ensure};
use axum::http::StatusCode;
use deadpool_postgres::{Client, Pool};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::{process::Command, time::Instant};
use uuid::Uuid;

const MAX_REFS: usize = 4096;
const MAX_PACKS: usize = 256;
const MAX_ERROR: usize = 2048;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Direction {
    Cutover,
    Rollback,
}
impl Direction {
    fn name(self) -> &'static str {
        match self {
            Self::Cutover => "gitfs_to_pando",
            Self::Rollback => "pando_to_gitfs",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransitionReport {
    pub repository_id: Uuid,
    pub direction: String,
    pub transition_id: Uuid,
    pub transition_epoch: i64,
    pub old_storage_backend: String,
    pub new_storage_backend: String,
    pub storage_generation: i64,
    pub refs: usize,
    pub packs: usize,
    pub objects_verified: u64,
}

struct Fence {
    id: Uuid,
    epoch: i64,
    generation: i64,
    backend: String,
}

fn conflict() -> Error {
    Error(StatusCode::CONFLICT, "repository storage transition in progress; retry")
}

fn reserved(name: &str) -> bool {
    name.starts_with("refs/rootyard-") || name.starts_with("refs/replace/") || name.starts_with("refs/pull/")
}

/// Only branch and tag refs are part of the authority snapshot. Native journal
/// and internal roots remain local to the GitFS volume and are never exported.
fn exported(name: &str) -> bool {
    (name.starts_with("refs/heads/") || name.starts_with("refs/tags/"))
        && crate::journal::valid_ref(name)
        && !reserved(name)
}

fn parse_refs(bytes: &[u8], object_format: &str) -> Result<BTreeMap<String, String>> {
    ensure!(bytes.len() <= 8 * 1024 * 1024, "ref listing exceeds bound");
    let text = std::str::from_utf8(bytes)?;
    ensure!(text.is_empty() || text.ends_with('\n'), "truncated ref listing");
    let length = if object_format == "sha256" { 64 } else { 40 };
    let zero = "0".repeat(length);
    let mut refs = BTreeMap::new();
    for line in text.lines() {
        ensure!(refs.len() < MAX_REFS, "too many refs");
        let (name, oid) = line.split_once(' ').ok_or_else(|| anyhow::anyhow!("invalid ref listing"))?;
        ensure!(name.starts_with("refs/") && name.len() <= 1024, "invalid ref identity");
        ensure!(!reserved(name), "reserved ref cannot be exported");
        ensure!(oid.len() == length && oid.bytes().all(|b| b.is_ascii_hexdigit()) && oid != zero, "invalid ref oid");
        ensure!(refs.insert(name.to_owned(), oid.to_owned()).is_none(), "duplicate ref");
    }
    Ok(refs)
}

fn valid_head(head_ref: &str) -> bool {
    head_ref.starts_with("refs/heads/") && crate::journal::valid_ref(head_ref)
}

/// Compute the minimal mutations needed to make the GitFS authority refs match
/// the Pando snapshot. Internal refs outside refs/heads and refs/tags are left
/// untouched so native journal state is not destroyed by a rollback.
fn plan_ref_mutations(
    current: &BTreeMap<String, String>,
    desired: &BTreeMap<String, String>,
) -> (Vec<(String, String)>, Vec<String>) {
    let mut updates = Vec::new();
    for (name, oid) in desired {
        if current.get(name) != Some(oid) {
            updates.push((name.clone(), oid.clone()));
        }
    }
    let deletes = current.keys().filter(|name| exported(name) && !desired.contains_key(*name)).cloned().collect();
    (updates, deletes)
}

async fn git(state: &AppState, dir: &Path, args: &[&str], deadline: Instant) -> Result<Vec<u8>> {
    let mut cmd = Command::new(&state.config.git);
    cmd.env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .arg("--git-dir")
        .arg(dir)
        .args(args)
        .stdin(Stdio::null());
    let timeout = deadline.saturating_duration_since(Instant::now()).min(Duration::from_secs(120));
    ensure!(!timeout.is_zero(), "storage transition deadline elapsed");
    git_http::collect_git_output(cmd, 8 * 1024 * 1024, timeout).await
}

async fn index_pack(state: &AppState, dir: &Path, pack: &Path, deadline: Instant) -> Result<()> {
    let file = std::fs::File::open(pack)?;
    let mut cmd = Command::new(&state.config.git);
    cmd.env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .arg("--git-dir")
        .arg(dir)
        .args(["index-pack", "--stdin"]);
    let timeout = deadline.saturating_duration_since(Instant::now()).min(Duration::from_secs(120));
    ensure!(!timeout.is_zero(), "storage transition deadline elapsed");
    git_http::collect_git_output_input(cmd, 8 * 1024 * 1024, timeout, Stdio::from(file)).await?;
    Ok(())
}

async fn object_count(state: &AppState, dir: &Path, deadline: Instant) -> Result<u64> {
    let output = git(state, dir, &["cat-file", "--batch-all-objects", "--batch-check=%(objectname)"], deadline).await?;
    Ok(output.split(|b| *b == b'\n').filter(|line| !line.is_empty()).count() as u64)
}

fn work_dir(state: &AppState) -> Result<PathBuf> {
    let root = state.storage.root.join("pando-transition");
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&root)?;
    let meta = std::fs::symlink_metadata(&root)?;
    ensure!(
        meta.is_dir()
            && !meta.file_type().is_symlink()
            && std::os::unix::fs::MetadataExt::uid(&meta) == unsafe { libc::geteuid() },
        "transition scratch root is not privately owned"
    );
    let path = root.join(format!(".transition-{}", Uuid::new_v4()));
    std::fs::DirBuilder::new().mode(0o700).create(&path)?;
    Ok(path)
}

struct WorkDir(PathBuf);
impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Verify that a pack set covers every desired ref and that the advertised
/// HEAD is reachable from the same object closure. Returns the object count.
async fn verify_closure(
    state: &AppState,
    object_format: &str,
    packs: &[PathBuf],
    refs: &BTreeMap<String, String>,
    head_ref: &str,
    deadline: Instant,
) -> Result<u64> {
    ensure!(!refs.is_empty() && refs.len() <= MAX_REFS, "transition snapshot has no refs");
    ensure!(valid_head(head_ref), "transition snapshot HEAD is invalid");
    let work = WorkDir(work_dir(state)?);
    let view = work.0.join("verify.git");
    let format_arg = format!("--object-format={object_format}");
    let mut init = Command::new(&state.config.git);
    init.env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .args(["init", "--bare", &format_arg])
        .arg(&view)
        .stdin(Stdio::null());
    let timeout = deadline.saturating_duration_since(Instant::now()).min(Duration::from_secs(120));
    ensure!(!timeout.is_zero(), "storage transition deadline elapsed");
    git_http::collect_git_output(init, 4096, timeout).await?;
    for pack in packs {
        index_pack(state, &view, pack, deadline).await?;
    }
    for (name, oid) in refs {
        git(state, &view, &["update-ref", "--no-deref", name, oid], deadline).await?;
    }
    git(state, &view, &["symbolic-ref", "HEAD", head_ref], deadline).await?;
    git(state, &view, &["fsck", "--full", "--strict"], deadline).await?;
    let observed = parse_refs(
        &git(state, &view, &["for-each-ref", "--format=%(refname) %(objectname)"], deadline).await?,
        object_format,
    )?;
    ensure!(&observed == refs, "transition ref parity mismatch");
    let head_oid = git(state, &view, &["rev-parse", "--verify", &format!("{head_ref}^{{commit}}")], deadline).await?;
    ensure!(!head_oid.is_empty(), "transition HEAD does not resolve");
    object_count(state, &view, deadline).await
}

async fn begin(state: &AppState, repo_id: Uuid, direction: Direction) -> Result<Fence, Error> {
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let row = tx
        .query_opt(
            "SELECT storage_backend,state,storage_generation,backend_transition_epoch,transition_state \
        FROM repositories WHERE id=$1 FOR UPDATE",
            &[&repo_id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let backend: String = row.get("storage_backend");
    let repo_state: String = row.get("state");
    let generation: i64 = row.get("storage_generation");
    let epoch: i64 = row.get("backend_transition_epoch");
    let transition_state: String = row.get("transition_state");
    if repo_state != "ready" || !matches!(transition_state.as_str(), "stable" | "failed") {
        return Err(conflict());
    }
    let expected = match direction {
        Direction::Cutover => "gitfs",
        Direction::Rollback => "pando",
    };
    if backend != expected {
        return Err(Error(StatusCode::CONFLICT, "repository is not in the required source backend"));
    }
    let id = Uuid::new_v4();
    let next = epoch.checked_add(1).ok_or_else(conflict)?;
    tx.execute(
        "UPDATE repositories SET transition_state='draining',backend_transition_epoch=$2, \
        transition_id=$3,transition_started_at=clock_timestamp(),transition_error=NULL WHERE id=$1",
        &[&repo_id, &next, &id],
    )
    .await
    .map_err(Error::internal)?;
    tx.commit().await.map_err(Error::internal)?;
    Ok(Fence { id, epoch: next, generation, backend })
}

async fn fail(state: &AppState, repo_id: Uuid, fence: &Fence, error: &anyhow::Error) {
    let message = format!("{error:#}");
    let message: String = message.chars().take(MAX_ERROR).collect();
    let Ok(client) = state.pool.get().await else { return };
    let _ = client
        .execute(
            "UPDATE repositories SET transition_state='failed',transition_error=$3 \
        WHERE id=$1 AND transition_id=$2 AND transition_state='draining'",
            &[&repo_id, &fence.id, &message],
        )
        .await;
}

async fn ensure_fence(tx: &tokio_postgres::Transaction<'_>, repo_id: Uuid, fence: &Fence) -> Result<()> {
    let row = tx
        .query_opt(
            "SELECT storage_backend,state,storage_generation,transition_state,transition_id \
        FROM repositories WHERE id=$1 FOR UPDATE",
            &[&repo_id],
        )
        .await?;
    let row = row.ok_or_else(|| anyhow::anyhow!("repository disappeared during transition"))?;
    ensure!(
        row.get::<_, String>("storage_backend") == fence.backend
            && row.get::<_, String>("state") == "ready"
            && row.get::<_, i64>("storage_generation") == fence.generation
            && row.get::<_, String>("transition_state") == "draining"
            && row.get::<_, Option<Uuid>>("transition_id") == Some(fence.id),
        "transition fence changed before commit"
    );
    Ok(())
}

async fn acquire_publication_lock(pool: &Pool, repo_id: Uuid, deadline: Instant) -> Result<Client, Error> {
    let client = pool.get().await.map_err(Error::internal)?;
    loop {
        let granted: bool = client
            .query_one(
                "SELECT pg_try_advisory_lock(hashtextextended('rootyard-publication-v1:' || $1::uuid::text, 0))",
                &[&repo_id],
            )
            .await
            .map_err(Error::internal)?
            .get(0);
        if granted {
            return Ok(client);
        }
        if Instant::now() >= deadline {
            return Err(conflict());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn release_publication_lock(client: &Client, repo_id: Uuid) {
    let _ = client
        .query_one(
            "SELECT pg_advisory_unlock(hashtextextended('rootyard-publication-v1:' || $1::uuid::text, 0))",
            &[&repo_id],
        )
        .await;
}

/// Write admission for every mutating route. A repository under transition
/// rejects new writes even though its public backend field may still name the
/// old authority until the switch commits.
pub async fn admit_write(pool: &Pool, repository_id: Uuid, expected_backend: &str) -> Result<(), Error> {
    let client = pool.get().await.map_err(Error::internal)?;
    let row = client
        .query_opt(
            "SELECT transition_state,storage_backend,state,storage_generation FROM repositories WHERE id=$1",
            &[&repository_id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    if row.get::<_, String>("transition_state") != "stable" {
        return Err(conflict());
    }
    if row.get::<_, String>("storage_backend") != expected_backend
        || row.get::<_, String>("state") != "ready"
        || row.get::<_, i64>("storage_generation") <= 0
    {
        return Err(Error(StatusCode::CONFLICT, "repository backend changed; retry"));
    }
    Ok(())
}

async fn complete_cutover(
    state: &AppState,
    repo: &Repository,
    fence: &Fence,
    tenant_id: Uuid,
    refs: &BTreeMap<String, String>,
    head_ref: &str,
    pack: &PackManifest,
) -> Result<(), Error> {
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    ensure_fence(&tx, repo.id, fence).await.map_err(Error::internal)?;
    if pack.repository_id != repo.id
        || pack.tenant_id != tenant_id
        || pack.storage_generation != fence.generation
        || pack.object_format != repo.object_format
    {
        return Err(conflict());
    }
    let names: Vec<String> = refs.keys().cloned().collect();
    tx.execute(
        "INSERT INTO pando_repository_states \
        (repository_id,tenant_id,storage_generation,ref_generation,object_format,state,pack_ids,head_ref,operation_sequence) \
        VALUES($1,$2,$3,1,$4,'serving',ARRAY[$5]::uuid[],$6,0) \
        ON CONFLICT(repository_id) DO UPDATE SET tenant_id=EXCLUDED.tenant_id, \
        storage_generation=EXCLUDED.storage_generation,ref_generation=1, \
        object_format=EXCLUDED.object_format,state='serving',pack_ids=EXCLUDED.pack_ids, \
        head_ref=EXCLUDED.head_ref,operation_sequence=0,updated_at=clock_timestamp()",
        &[&repo.id, &tenant_id, &fence.generation, &repo.object_format, &pack.id, &head_ref],
    )
    .await
    .map_err(Error::internal)?;
    tx.execute("DELETE FROM pando_refs WHERE repository_id=$1 AND NOT (ref_name = ANY($2))", &[&repo.id, &names])
        .await
        .map_err(Error::internal)?;
    for (name, oid) in refs {
        tx.execute(
            "INSERT INTO pando_refs(repository_id,ref_name,oid,updated_generation) VALUES($1,$2,$3,1) \
            ON CONFLICT(repository_id,ref_name) DO UPDATE SET oid=EXCLUDED.oid,updated_generation=EXCLUDED.updated_generation",
            &[&repo.id, name, oid],
        )
        .await
        .map_err(Error::internal)?;
    }
    let changed = tx
        .execute(
            "UPDATE repositories SET storage_backend='pando',transition_state='stable', \
        transition_id=NULL,transition_started_at=NULL,transition_error=NULL \
        WHERE id=$1 AND transition_id=$2 AND transition_state='draining'",
            &[&repo.id, &fence.id],
        )
        .await
        .map_err(Error::internal)?;
    if changed != 1 {
        return Err(conflict());
    }
    tx.commit().await.map_err(Error::internal)?;
    Ok(())
}

async fn complete_rollback(state: &AppState, repo: &Repository, fence: &Fence) -> Result<(), Error> {
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    ensure_fence(&tx, repo.id, fence).await.map_err(Error::internal)?;
    tx.execute(
        "UPDATE pando_repository_states SET state='rollback',updated_at=clock_timestamp() WHERE repository_id=$1",
        &[&repo.id],
    )
    .await
    .map_err(Error::internal)?;
    let changed = tx
        .execute(
            "UPDATE repositories SET storage_backend='gitfs',transition_state='stable', \
        transition_id=NULL,transition_started_at=NULL,transition_error=NULL \
        WHERE id=$1 AND transition_id=$2 AND transition_state='draining'",
            &[&repo.id, &fence.id],
        )
        .await
        .map_err(Error::internal)?;
    if changed != 1 {
        return Err(conflict());
    }
    tx.commit().await.map_err(Error::internal)?;
    Ok(())
}

/// Export every GitFS branch/tag into a verified encrypted Pando pack set and
/// atomically switch the authoritative backend. Concurrent writes are rejected
/// by the durable draining fence from `begin` onward.
pub async fn cutover(state: &Arc<AppState>, repo: &Repository, deadline: Instant) -> Result<TransitionReport, Error> {
    if repo.storage_backend != "gitfs" {
        return Err(Error(StatusCode::CONFLICT, "cutover requires a GitFS repository"));
    }
    let fence = begin(state, repo.id, Direction::Cutover).await?;
    let lock = match acquire_publication_lock(&state.pool, repo.id, deadline).await {
        Ok(lock) => lock,
        Err(error) => {
            fail(state, repo.id, &fence, &anyhow::anyhow!("publication lock unavailable")).await;
            return Err(error);
        }
    };
    let result: Result<TransitionReport> = async {
        let _write = state.storage.write_lock(repo.id).await;
        let _exclusive = state.storage.maintenance_exclusive(repo.id).await;
        let bare = state.storage.verify_path(repo.id)?;
        git(state, &bare, &["fsck", "--full", "--strict"], deadline).await?;
        let all = parse_refs(
            &git(state, &bare, &["for-each-ref", "--format=%(refname) %(objectname)"], deadline).await?,
            &repo.object_format,
        )?;
        let refs: BTreeMap<_, _> = all.into_iter().filter(|(name, _)| exported(name)).collect();
        ensure!(!refs.is_empty(), "Pando cutover requires at least one branch or tag");
        let head_ref =
            String::from_utf8(git(state, &bare, &["symbolic-ref", "HEAD"], deadline).await?)?.trim().to_owned();
        ensure!(valid_head(&head_ref), "GitFS HEAD is not an authoritative branch");
        git(state, &bare, &["repack", "-ad"], deadline).await?;
        let pack_dir = bare.join("objects/pack");
        let packs: Vec<PathBuf> = std::fs::read_dir(&pack_dir)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<Vec<_>>>()?
            .into_iter()
            .filter(|path| path.extension().is_some_and(|ext| ext == "pack"))
            .collect();
        ensure!(packs.len() == 1, "GitFS cutover requires one consolidated pack");
        let pack = packs.into_iter().next().expect("consolidated pack");
        let index = pack.with_extension("idx");
        ensure!(index.is_file(), "GitFS cutover pack index missing");
        let objects =
            verify_closure(state, &repo.object_format, std::slice::from_ref(&pack), &refs, &head_ref, deadline).await?;
        let tenant_id: Uuid = {
            let client = state.pool.get().await?;
            client.query_one("SELECT owner_id FROM repositories WHERE id=$1", &[&repo.id]).await?.get(0)
        };
        let store = PackStore::from_env(state.storage.root.join("pando-pack-work"), state.config.git.clone())?;
        let manifest = store
            .publish(
                &state.pool,
                repo.id,
                tenant_id,
                repo.storage_generation,
                &repo.object_format,
                &pack,
                &index,
                deadline,
            )
            .await?;
        complete_cutover(state, repo, &fence, tenant_id, &refs, &head_ref, &manifest)
            .await
            .map_err(|error| anyhow::anyhow!("{}", error.1))?;
        Ok(TransitionReport {
            repository_id: repo.id,
            direction: Direction::Cutover.name().into(),
            transition_id: fence.id,
            transition_epoch: fence.epoch,
            old_storage_backend: "gitfs".into(),
            new_storage_backend: "pando".into(),
            storage_generation: fence.generation,
            refs: refs.len(),
            packs: 1,
            objects_verified: objects,
        })
    }
    .await;
    release_publication_lock(&lock, repo.id).await;
    match result {
        Ok(report) => Ok(report),
        Err(error) => {
            fail(state, repo.id, &fence, &error).await;
            Err(Error(StatusCode::SERVICE_UNAVAILABLE, "repository storage transition failed"))
        }
    }
}

/// Rehydrate the encrypted Pando pack closure into the GitFS bare repository,
/// verify ref/object parity, then atomically restore GitFS authority.
pub async fn rollback(state: &Arc<AppState>, repo: &Repository, deadline: Instant) -> Result<TransitionReport, Error> {
    if repo.storage_backend != "pando" {
        return Err(Error(StatusCode::CONFLICT, "rollback requires a Pando repository"));
    }
    let fence = begin(state, repo.id, Direction::Rollback).await?;
    let lock = match acquire_publication_lock(&state.pool, repo.id, deadline).await {
        Ok(lock) => lock,
        Err(error) => {
            fail(state, repo.id, &fence, &anyhow::anyhow!("publication lock unavailable")).await;
            return Err(error);
        }
    };
    let result: Result<TransitionReport> = async {
        let _write = state.storage.write_lock(repo.id).await;
        let _exclusive = state.storage.maintenance_exclusive(repo.id).await;
        let bare = state.storage.verify_path(repo.id)?;
        let (tenant_id, refs, head_ref, pack_ids) = {
            let client = state.pool.get().await?;
            let row = client
                .query_one(
                    "SELECT r.owner_id,s.state,s.head_ref,s.pack_ids FROM repositories r \
                JOIN pando_repository_states s ON s.repository_id=r.id \
                WHERE r.id=$1 AND s.storage_generation=r.storage_generation",
                    &[&repo.id],
                )
                .await?;
            ensure!(
                matches!(row.get::<_, String>("state").as_str(), "serving" | "rollback"),
                "Pando repository has no serving snapshot"
            );
            let pack_ids: Vec<Uuid> = row.get("pack_ids");
            ensure!(!pack_ids.is_empty() && pack_ids.len() <= MAX_PACKS, "Pando pack closure exceeds bound");
            let head_ref: String = row.get("head_ref");
            ensure!(valid_head(&head_ref), "Pando advertised HEAD is invalid");
            let rows = client
                .query("SELECT ref_name,oid FROM pando_refs WHERE repository_id=$1 ORDER BY ref_name", &[&repo.id])
                .await?;
            let mut refs = BTreeMap::new();
            for row in rows {
                let name: String = row.get(0);
                ensure!(exported(&name), "Pando snapshot contains a non-exported ref");
                refs.insert(name, row.get(1));
            }
            ensure!(!refs.is_empty() && refs.len() <= MAX_REFS, "Pando snapshot has no refs");
            (row.get::<_, Uuid>("owner_id"), refs, head_ref, pack_ids)
        };
        let work = WorkDir(work_dir(state)?);
        let store = PackStore::from_env(state.storage.root.join("pando-pack-work"), state.config.git.clone())?;
        let mut packs = Vec::new();
        for pack_id in &pack_ids {
            let recovered = store.recover(&state.pool, repo.id, *pack_id, &work.0, deadline).await?;
            ensure!(recovered.tenant_id == tenant_id, "Pando pack tenant mismatch");
            let target = work.0.join(format!("pack-{pack_id}.pack"));
            ensure!(target.is_file(), "recovered Pando pack is missing");
            packs.push(target);
        }
        let objects = verify_closure(state, &repo.object_format, &packs, &refs, &head_ref, deadline).await?;
        // Install the verified closure in the durable GitFS volume.
        git(state, &bare, &["fsck", "--full", "--strict"], deadline).await?;
        for pack in &packs {
            index_pack(state, &bare, pack, deadline).await?;
        }
        let current = parse_refs(
            &git(state, &bare, &["for-each-ref", "--format=%(refname) %(objectname)"], deadline).await?,
            &repo.object_format,
        )?;
        let (updates, deletes) = plan_ref_mutations(&current, &refs);
        for (name, oid) in &updates {
            git(state, &bare, &["update-ref", "--no-deref", name, oid], deadline).await?;
        }
        for name in &deletes {
            git(state, &bare, &["update-ref", "--no-deref", "-d", name], deadline).await?;
        }
        git(state, &bare, &["symbolic-ref", "HEAD", &head_ref], deadline).await?;
        git(state, &bare, &["fsck", "--full", "--strict"], deadline).await?;
        let observed = parse_refs(
            &git(state, &bare, &["for-each-ref", "--format=%(refname) %(objectname)"], deadline).await?,
            &repo.object_format,
        )?;
        let observed: BTreeMap<_, _> = observed.into_iter().filter(|(name, _)| exported(name)).collect();
        ensure!(observed == refs, "GitFS ref parity mismatch after rollback");
        let observed_head =
            String::from_utf8(git(state, &bare, &["symbolic-ref", "HEAD"], deadline).await?)?.trim().to_owned();
        ensure!(observed_head == head_ref, "GitFS HEAD parity mismatch after rollback");
        complete_rollback(state, repo, &fence).await.map_err(|error| anyhow::anyhow!("{}", error.1))?;
        Ok(TransitionReport {
            repository_id: repo.id,
            direction: Direction::Rollback.name().into(),
            transition_id: fence.id,
            transition_epoch: fence.epoch,
            old_storage_backend: "pando".into(),
            new_storage_backend: "gitfs".into(),
            storage_generation: fence.generation,
            refs: refs.len(),
            packs: pack_ids.len(),
            objects_verified: objects,
        })
    }
    .await;
    release_publication_lock(&lock, repo.id).await;
    match result {
        Ok(report) => Ok(report),
        Err(error) => {
            fail(state, repo.id, &fence, &error).await;
            Err(Error(StatusCode::SERVICE_UNAVAILABLE, "repository storage transition failed"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oid(c: char) -> String {
        c.to_string().repeat(40)
    }

    #[test]
    fn ref_parsing_rejects_reserved_and_malformed_refs() {
        let listing = format!("refs/heads/main {}\nrefs/tags/v1 {}\n", oid('a'), oid('b'));
        let refs = parse_refs(listing.as_bytes(), "sha1").unwrap();
        assert_eq!(refs.len(), 2);
        assert!(parse_refs(b"refs/rootyard-journal/x 0000000000000000000000000000000000000001\n", "sha1").is_err());
        assert!(parse_refs(b"refs/heads/main nothex\n", "sha1").is_err());
        assert!(parse_refs(b"refs/heads/main 0000000000000000000000000000000000000000\n", "sha1").is_err());
        assert!(parse_refs(b"refs/heads/main 0123456789012345678901234567890123456789", "sha1").is_err());
        assert!(parse_refs(b"refs/heads/main 0123456789012345678901234567890123456789\nrefs/heads/main 0123456789012345678901234567890123456789\n", "sha1").is_err());
    }

    #[test]
    fn exported_refs_cover_only_branches_and_tags() {
        assert!(exported("refs/heads/main"));
        assert!(exported("refs/tags/v1"));
        assert!(!exported("refs/rootyard-journal/abc"));
        assert!(!exported("refs/replace/abc"));
        assert!(!exported("refs/pull/1/head"));
        assert!(!exported("HEAD"));
    }

    #[test]
    fn rollback_plan_keeps_internal_refs_and_removes_stale_authority_refs() {
        let mut current = BTreeMap::new();
        current.insert("refs/heads/main".to_string(), oid('a'));
        current.insert("refs/heads/stale".to_string(), oid('b'));
        current.insert("refs/tags/keep".to_string(), oid('c'));
        current.insert("refs/rootyard-journal/1".to_string(), oid('d'));
        let mut desired = BTreeMap::new();
        desired.insert("refs/heads/main".to_string(), oid('e'));
        desired.insert("refs/tags/keep".to_string(), oid('c'));
        let (updates, deletes) = plan_ref_mutations(&current, &desired);
        assert_eq!(updates, vec![("refs/heads/main".to_string(), oid('e'))]);
        assert_eq!(deletes, vec!["refs/heads/stale".to_string()]);
    }

    #[test]
    fn head_must_be_an_authoritative_branch() {
        assert!(valid_head("refs/heads/main"));
        assert!(!valid_head("refs/tags/v1"));
        assert!(!valid_head("refs/heads/../escape"));
        assert!(!valid_head("refs/heads/bad name"));
    }
}
