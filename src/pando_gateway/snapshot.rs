//! Disposable native Git read view reconstructed from PostgreSQL refs and
//! encrypted remote pack manifests. Nothing in this directory is authority.
use super::pack_store::PackStore;
use crate::{
    AppState, Error,
    baseline_metrics::{Phase, timed_result},
    db::Repository, git_http,
    storage::read_leases::Lease,
};
use anyhow::{Result, ensure};
use std::{
    collections::BTreeMap,
    os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::{process::Command, time::Instant};
use uuid::Uuid;

const MAX_PACKS: usize = 256;
const MAX_REFS: usize = 4096;
fn active(lease: &Lease) -> Result<()> {
    lease.ensure_active().map_err(|error| anyhow::anyhow!(error.1))
}

pub struct Snapshot {
    path: PathBuf,
    pub storage_generation: i64,
    pub ref_generation: i64,
    pub head_ref: String,
    pub refs: BTreeMap<String, String>,
    pub source_packs: Vec<Uuid>,
}
impl Snapshot {
    pub fn path(&self) -> &Path {
        &self.path
    }
}
impl Drop for Snapshot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

async fn run_git(
    state: &AppState,
    path: &Path,
    args: &[&str],
    lease: &Lease,
    deadline: Instant,
    phase: Phase,
) -> Result<Vec<u8>> {
    active(lease)?;
    let mut cmd = Command::new(&state.config.git);
    cmd.env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .arg("--git-dir")
        .arg(path)
        .args(args)
        .stdin(Stdio::null());
    let timeout = deadline.saturating_duration_since(Instant::now()).min(Duration::from_secs(120));
    ensure!(!timeout.is_zero(), "Pando read view deadline elapsed");
    // Wall clock of the awaited subprocess, so it contains that subprocess's CPU
    // time. It is not a separate CPU measurement.
    let bytes = timed_result(phase, lease.guard(git_http::collect_git_output(cmd, 32 * 1024, timeout)))
        .await
        .map_err(|error| anyhow::anyhow!(error.1))??;
    Ok(bytes)
}

/// Caller holds a durable shared read lease and local snapshot gate through
/// the lifetime of this Snapshot and the Git command or response using it.
pub async fn materialize(
    state: &Arc<AppState>,
    repo: &Repository,
    lease: &Lease,
    deadline: Instant,
) -> Result<Snapshot, Error> {
    async fn inner(state: &Arc<AppState>, repo: &Repository, lease: &Lease, deadline: Instant) -> Result<Snapshot> {
        active(lease)?;
        let client = timed_result(Phase::PoolCheckout, state.pool.get()).await?;
        let row = client
            .query_one(
                "SELECT r.owner_id,r.storage_backend,r.storage_generation,r.object_format, \
             s.state,s.ref_generation,s.head_ref,s.pack_ids FROM repositories r \
             JOIN pando_repository_states s ON s.repository_id=r.id \
             WHERE r.id=$1 AND s.tenant_id=r.owner_id AND \
             s.storage_generation=r.storage_generation AND s.object_format=r.object_format",
                &[&repo.id],
            )
            .await?;
        let tenant: Uuid = row.get("owner_id");
        let generation: i64 = row.get("storage_generation");
        let ref_generation: i64 = row.get("ref_generation");
        let head_ref: String = row.get("head_ref");
        let pack_ids: Vec<Uuid> = row.get("pack_ids");
        ensure!(
            row.get::<_, &str>("storage_backend") == "pando"
                && row.get::<_, &str>("state") == "serving"
                && generation == repo.storage_generation
                && row.get::<_, &str>("object_format") == repo.object_format,
            "Pando repository has no serving authoritative snapshot"
        );
        ensure!(!pack_ids.is_empty() && pack_ids.len() <= MAX_PACKS, "Pando pack snapshot exceeds bounded view");
        ensure!(
            head_ref.starts_with("refs/heads/") && crate::journal::valid_ref(&head_ref),
            "Pando advertised HEAD is invalid"
        );
        let rows = client
            .query(
                "SELECT ref_name,oid FROM pando_refs \
            WHERE repository_id=$1 ORDER BY ref_name LIMIT $2",
                &[&repo.id, &((MAX_REFS + 1) as i64)],
            )
            .await?;
        ensure!(rows.len() <= MAX_REFS, "Pando ref snapshot exceeds bounded view");
        let refs: BTreeMap<String, String> = rows.into_iter().map(|r| (r.get(0), r.get(1))).collect();
        ensure!(refs.contains_key(&head_ref), "Pando advertised HEAD is not an authoritative ref");
        let mut total_declared = 0u64;
        for pack_id in &pack_ids {
            let pack = client
                .query_one(
                    "SELECT manifest FROM pando_pack_manifests \
                WHERE repository_id=$1 AND id=$2",
                    &[&repo.id, pack_id],
                )
                .await?;
            let manifest: super::pack_store::PackManifest = serde_json::from_value(pack.get(0))?;
            ensure!(
                manifest.id == *pack_id
                    && manifest.repository_id == repo.id
                    && manifest.tenant_id == tenant
                    && manifest.object_format == repo.object_format,
                "Pando declared pack identity mismatch"
            );
            total_declared = total_declared
                .checked_add(manifest.pack.plaintext_bytes)
                .and_then(|v| v.checked_add(manifest.index.plaintext_bytes))
                .ok_or_else(|| anyhow::anyhow!("Pando declared snapshot size overflow"))?;
            ensure!(total_declared <= state.config.max_repo_bytes, "Pando declared snapshot exceeds repository quota");
        }
        drop(client);
        let root = state.storage.root.join("pando-sessions");
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&root)?;
        let meta = std::fs::symlink_metadata(&root)?;
        ensure!(
            meta.is_dir() && !meta.file_type().is_symlink() && meta.uid() == unsafe { libc::geteuid() },
            "Pando session root is not privately owned"
        );
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        let path = root.join(format!(".snapshot-{}", Uuid::new_v4()));
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        let snapshot = Snapshot {
            path,
            storage_generation: generation,
            ref_generation,
            head_ref,
            refs,
            source_packs: pack_ids.clone(),
        };
        let format_arg = format!("--object-format={}", repo.object_format);
        run_git(state, snapshot.path(), &["init", "--bare", &format_arg], lease, deadline, Phase::NativeGitPrepare)
            .await?;
        let store = PackStore::from_env(state.storage.root.join("pando-pack-work"), state.config.git.clone())?;
        let pack_dir = snapshot.path.join("objects/pack");
        let cache_dir = PackStore::cache_dir(&state.storage.root, repo.id);
        let mut total_bytes = 0u64;
        for pack_id in pack_ids {
            active(lease)?;
            // Hydration of one declared pack into the disposable snapshot; it
            // contains any remote GET and decryption performed underneath.
            let manifest = timed_result(
                Phase::NativeGitHydration,
                lease.guard(Box::pin(store.recover_cached(
                    &state.pool,
                    repo.id,
                    pack_id,
                    &pack_dir,
                    &cache_dir,
                    deadline,
                ))),
            )
            .await
            .map_err(|error| anyhow::anyhow!(error.1))??;
            ensure!(
                manifest.tenant_id == tenant && manifest.object_format == repo.object_format,
                "Pando snapshot pack identity mismatch"
            );
            total_bytes = total_bytes
                .checked_add(manifest.pack.plaintext_bytes)
                .and_then(|v| v.checked_add(manifest.index.plaintext_bytes))
                .ok_or_else(|| anyhow::anyhow!("Pando snapshot size overflow"))?;
            ensure!(total_bytes <= state.config.max_repo_bytes, "Pando snapshot exceeds repository quota");
        }
        for (name, oid) in &snapshot.refs {
            ensure!(
                oid.len() == if repo.object_format == "sha256" { 64 } else { 40 }
                    && oid.bytes().all(|b| b.is_ascii_hexdigit()),
                "Pando ref has wrong object format"
            );
            let args: [&str; 4] = ["update-ref", "--no-deref", name.as_str(), oid.as_str()];
            run_git(state, snapshot.path(), &args, lease, deadline, Phase::NativeGitPrepare).await?;
        }
        // The advertised HEAD is part of the authoritative snapshot. A disposable
        // bare repository must not invent a default branch from git init.
        let args: [&str; 3] = ["symbolic-ref", "HEAD", snapshot.head_ref.as_str()];
        run_git(state, snapshot.path(), &args, lease, deadline, Phase::NativeGitPrepare).await?;
        run_git(state, snapshot.path(), &["fsck", "--full", "--strict"], lease, deadline, Phase::NativeGitFsck).await?;
        active(lease)?;
        let client = timed_result(Phase::PoolCheckout, state.pool.get()).await?;
        let current = client
            .query_one(
                "SELECT r.storage_generation,s.ref_generation,s.state \
            FROM repositories r JOIN pando_repository_states s ON s.repository_id=r.id WHERE r.id=$1",
                &[&repo.id],
            )
            .await?;
        ensure!(
            current.get::<_, i64>(0) == generation
                && current.get::<_, i64>(1) == ref_generation
                && current.get::<_, &str>(2) == "serving",
            "Pando snapshot changed during reconstruction"
        );
        Ok(snapshot)
    }
    Box::pin(inner(state, repo, lease, deadline)).await.map_err(Error::internal)
}
