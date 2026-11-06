//! Observe the exact refs that native receive-pack committed in a disposable
//! Pando session, then stage a complete verified immutable pack before PG CAS.
use super::{
    pack_store::{PackManifest, PackStore},
    snapshot::Snapshot,
};
use crate::{AppState, Error, db::Repository, git_http, journal::RefChange, storage::read_leases::Lease};
use anyhow::{Result, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};
use tokio::{process::Command, time::Instant};
use uuid::Uuid;

const MAX_REFS: usize = 4096;

pub struct PreparedPush {
    pub(crate) pack: Option<PackManifest>,
    pub(crate) changes: Vec<RefChange>,
}
impl PreparedPush {
    pub fn pack(&self) -> Option<&PackManifest> {
        self.pack.as_ref()
    }
    pub fn changes(&self) -> &[RefChange] {
        &self.changes
    }
}

struct VerifyView(PathBuf);
impl Drop for VerifyView {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Verify the changed targets using only the supplied immutable packs. This
/// prevents local receive-pack loose objects from making a refs-only push
/// appear safe when its target is absent from the committed pack set.
async fn pack_set_covers(
    state: &AppState,
    repo: &Repository,
    snapshot: &Snapshot,
    packs: &[PathBuf],
    changes: &[RefChange],
    lease: &Lease,
    deadline: Instant,
) -> Result<bool> {
    let root = snapshot.path().parent().ok_or_else(|| anyhow::anyhow!("Pando session root missing"))?;
    let view = VerifyView(root.join(format!(".verify-{}", Uuid::new_v4())));
    std::fs::DirBuilder::new().mode(0o700).create(&view.0)?;
    let format_arg = format!("--object-format={}", repo.object_format);
    git(state, &view.0, &["init", "--bare", &format_arg], lease, deadline).await?;
    let destination = view.0.join("objects/pack");
    for source in packs {
        let name = source.file_name().ok_or_else(|| anyhow::anyhow!("invalid Pando pack path"))?;
        ensure!(source.extension().is_some_and(|ext| ext == "pack"), "invalid Pando pack extension");
        std::fs::hard_link(source, destination.join(name))?;
        let index = source.with_extension("idx");
        std::fs::hard_link(&index, destination.join(index.file_name().unwrap()))?;
    }
    for change in changes {
        if change.new_oid.bytes().all(|byte| byte == b'0') {
            continue;
        }
        if git(state, &view.0, &["update-ref", "--no-deref", &change.ref_name, &change.new_oid], lease, deadline)
            .await
            .is_err()
        {
            return Ok(false);
        }
    }
    Ok(git(state, &view.0, &["fsck", "--full", "--strict"], lease, deadline).await.is_ok())
}

async fn git(state: &AppState, repo: &Path, args: &[&str], lease: &Lease, deadline: Instant) -> Result<Vec<u8>> {
    lease.ensure_active().map_err(|e| anyhow::anyhow!(e.1))?;
    let mut cmd = Command::new(&state.config.git);
    cmd.env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .arg("--git-dir")
        .arg(repo)
        .args(args)
        .stdin(Stdio::null());
    let timeout = deadline.saturating_duration_since(Instant::now()).min(Duration::from_secs(120));
    ensure!(!timeout.is_zero(), "Pando receive preparation deadline elapsed");
    lease.guard(git_http::collect_git_output(cmd, 1024 * 1024, timeout)).await.map_err(|e| anyhow::anyhow!(e.1))?
}

fn observed_refs(bytes: &[u8], object_format: &str) -> Result<BTreeMap<String, String>> {
    ensure!(bytes.len() <= 1024 * 1024, "Pando ref listing exceeds bound");
    let text = std::str::from_utf8(bytes)?;
    ensure!(text.is_empty() || text.ends_with('\n'), "truncated Pando ref listing");
    let length = if object_format == "sha256" { 64 } else { 40 };
    let mut refs = BTreeMap::new();
    for line in text.lines() {
        ensure!(refs.len() < MAX_REFS, "too many Pando refs");
        let (name, oid) = line.split_once(' ').ok_or_else(|| anyhow::anyhow!("invalid Pando ref listing"))?;
        ensure!(
            name.starts_with("refs/")
                && name.len() <= 1024
                && !name.bytes().any(|b| b <= 32 || b == 127)
                && oid.len() == length
                && oid.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid Pando ref identity"
        );
        ensure!(refs.insert(name.to_owned(), oid.to_owned()).is_none(), "duplicate Pando ref");
    }
    Ok(refs)
}

pub async fn observe(
    state: &AppState,
    repo: &Repository,
    snapshot: &Snapshot,
    lease: &Lease,
    deadline: Instant,
) -> Result<Vec<RefChange>, Error> {
    async fn inner(
        state: &AppState,
        repo: &Repository,
        snapshot: &Snapshot,
        lease: &Lease,
        deadline: Instant,
    ) -> Result<Vec<RefChange>> {
        ensure!(snapshot.storage_generation == repo.storage_generation, "Pando receive snapshot generation changed");
        let output =
            git(state, snapshot.path(), &["for-each-ref", "--format=%(refname) %(objectname)"], lease, deadline)
                .await?;
        let current = observed_refs(&output, &repo.object_format)?;
        let names: BTreeSet<_> = current.keys().chain(snapshot.refs.keys()).cloned().collect();
        let zero = "0".repeat(if repo.object_format == "sha256" { 64 } else { 40 });
        let mut changes = Vec::new();
        for name in names {
            let old = snapshot.refs.get(&name).unwrap_or(&zero);
            let new = current.get(&name).unwrap_or(&zero);
            if old == new {
                continue;
            }
            ensure!(
                !name.starts_with("refs/rootyard-")
                    && !name.starts_with("refs/replace/")
                    && !name.starts_with("refs/pull/"),
                "reserved Pando ref mutation"
            );
            changes.push(RefChange { ref_name: name, old_oid: old.clone(), new_oid: new.clone() });
        }
        Ok(changes)
    }
    Box::pin(inner(state, repo, snapshot, lease, deadline)).await.map_err(Error::internal)
}

/// Prepare remote pack bytes without publishing refs or acknowledging the
/// client. Caller must have already verified native receive-pack status.
pub async fn stage(
    state: &Arc<AppState>,
    repo: &Repository,
    tenant_id: Uuid,
    snapshot: &Snapshot,
    lease: &Lease,
    deadline: Instant,
) -> Result<Option<PreparedPush>, Error> {
    async fn inner(
        state: &Arc<AppState>,
        repo: &Repository,
        tenant_id: Uuid,
        snapshot: &Snapshot,
        lease: &Lease,
        deadline: Instant,
    ) -> Result<Option<PreparedPush>> {
        let changes = observe(state, repo, snapshot, lease, deadline).await.map_err(|e| anyhow::anyhow!(e.1))?;
        if changes.is_empty() {
            return Ok(None);
        }
        if changes.iter().all(|change| change.new_oid.bytes().all(|b| b == b'0')) {
            return Ok(Some(PreparedPush { pack: None, changes }));
        }
        let source_dir = snapshot.path().join("objects/pack");
        let source_packs: Vec<PathBuf> =
            snapshot.source_packs.iter().map(|id| source_dir.join(format!("pack-{id}.pack"))).collect();
        if pack_set_covers(state, repo, snapshot, &source_packs, &changes, lease, deadline).await? {
            return Ok(Some(PreparedPush { pack: None, changes }));
        }
        let pack_dir = snapshot.path().join("objects/pack");
        let previous: BTreeSet<PathBuf> = std::fs::read_dir(&pack_dir)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<_>>()?;
        git(state, snapshot.path(), &["fsck", "--full", "--strict"], lease, deadline).await?;
        git(state, snapshot.path(), &["repack", "-ad"], lease, deadline).await?;
        let mut pack: Option<PathBuf> = None;
        for entry in std::fs::read_dir(&pack_dir)? {
            let path = entry?.path();
            if !previous.contains(&path) && path.extension().is_some_and(|v| v == "pack") {
                ensure!(pack.replace(path).is_none(), "Pando session repack produced multiple new packs");
            }
        }
        let pack = pack.ok_or_else(|| anyhow::anyhow!("Pando session has no new pack"))?;
        ensure!(pack.with_extension("idx").is_file(), "Pando repack index missing");
        ensure!(
            pack_set_covers(state, repo, snapshot, std::slice::from_ref(&pack), &changes, lease, deadline).await?,
            "Pando new pack lacks changed ref closure"
        );
        let store = PackStore::from_env(state.storage.root.join("pando-pack-work"), state.config.git.clone())?;
        let manifest = lease
            .guard(Box::pin(store.publish(
                &state.pool,
                repo.id,
                tenant_id,
                repo.storage_generation,
                &repo.object_format,
                &pack,
                &pack.with_extension("idx"),
                deadline,
            )))
            .await
            .map_err(|e| anyhow::anyhow!(e.1))??;
        Ok(Some(PreparedPush { pack: Some(manifest), changes }))
    }
    Box::pin(inner(state, repo, tenant_id, snapshot, lease, deadline)).await.map_err(Error::internal)
}
