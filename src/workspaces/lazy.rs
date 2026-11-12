//! Verified remote baseline objects hydrated by normal FUSE reads.
#[path = "lazy_hydrator.rs"]
mod hydrator;
#[cfg(test)]
#[path = "lazy_tests.rs"]
mod tests;

use self::hydrator::{HYDRATION_PUBLICATION_GRACE, Hydrator, RemoteFetcher, configured_timeout};
use super::{mounts, remote};
use crate::{AppState, Error, storage::remote_objects::ObjectKey, workspace_lab::core};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{
        ffi::OsStringExt,
        fs::{OpenOptionsExt, PermissionsExt, symlink},
    },
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LazyManifest {
    schema: u32,
    checkpoint_id: Uuid,
    tenant_id: Uuid,
    entries: Vec<core::Entry>,
}

/// Guard for a newly prepared lazy workspace directory and sidecar manifest.
pub(super) struct LazyPublished {
    dest: PathBuf,
    sidecar: PathBuf,
    created: bool,
    kept: bool,
}

impl LazyPublished {
    pub(super) fn keep(mut self) {
        self.kept = true;
    }

    pub(super) async fn cleanup(mut self) {
        if self.created && !self.kept {
            self.kept = true;
            super::cleanup::cleanup_paths_async(Some(self.dest.clone()), Some(self.sidecar.clone()), true).await;
        }
    }
}

impl Drop for LazyPublished {
    fn drop(&mut self) {
        if self.created && !self.kept {
            super::cleanup::cleanup_paths_on_drop(Some(self.dest.clone()), Some(self.sidecar.clone()), true);
        }
    }
}

fn manifest_path(root: &Path, id: Uuid) -> PathBuf {
    root.join("workspace-service/lazy").join(format!("{id}.json"))
}

fn read_manifest(path: &Path) -> Result<LazyManifest, Error> {
    let file = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(path).map_err(Error::internal)?;
    if !file.metadata().map_err(Error::internal)?.is_file() {
        return Err(Error::bad_request());
    }
    let mut raw = Vec::new();
    file.take(16 * 1024 * 1024 + 1).read_to_end(&mut raw).map_err(Error::internal)?;
    if raw.len() > 16 * 1024 * 1024 {
        return Err(Error::bad_request());
    }
    let manifest: LazyManifest = serde_json::from_slice(&raw).map_err(Error::internal)?;
    if manifest.schema != 1 || manifest.tenant_id.is_nil() {
        return Err(Error::bad_request());
    }
    core::validate_entries(&manifest.entries).map_err(Error::internal)?;
    Ok(manifest)
}

/// Build a sparse immutable lower tree from a verified committed manifest.
/// Native Git metadata is materialized; worktree bytes remain remote. All local
/// staging, sparse file setup and fsync work runs on the bounded blocking pool.
pub(super) async fn prepare(
    state: &AppState,
    id: Uuid,
    cp: Uuid,
    repo: Uuid,
    tenant: Uuid,
) -> Result<LazyPublished, Error> {
    let dest = mounts::lower_path(state, id);
    let sidecar = manifest_path(&state.storage.root, id);
    let dest_check = dest.clone();
    let sidecar_check = sidecar.clone();
    let already_ready = super::blocking::run(move || {
        if !dest_check.exists() {
            return Ok(false);
        }
        let old = read_manifest(&sidecar_check)?;
        if old.checkpoint_id == cp && old.tenant_id == tenant && dest_check.join(".git").is_dir() {
            return Ok(true);
        }
        Err(Error::internal("conflicting sparse workspace baseline"))
    })
    .await?;
    if already_ready {
        return Ok(LazyPublished { dest, sidecar, created: false, kept: true });
    }
    let remote = remote::load_manifest(state, cp, repo, tenant).await?;
    if remote.entries.len() > core::MAX_ENTRIES {
        return Err(Error::bad_request());
    }
    let mut paths = BTreeSet::new();
    let mut symlinks = BTreeSet::new();
    let mut total = 0u64;
    let mut git_downloads = Vec::new();
    for item in &remote.entries {
        let rel = core::decode_path(&item.path_base64).map_err(|_| Error::bad_request())?;
        if !paths.insert(rel.clone()) || item.mode > 0o777 || item.size > core::MAX_BYTES {
            return Err(Error::bad_request());
        }
        total = total.checked_add(item.size).ok_or_else(Error::bad_request)?;
        if total > core::MAX_BYTES {
            return Err(Error::bad_request());
        }
        let obj_key = remote::key(tenant, &item.sha256)?;
        if item.kind == "symlink" {
            symlinks.insert(rel);
        } else if item.kind != "file" || item.target_base64.is_some() {
            return Err(Error::bad_request());
        } else if rel.starts_with(".git") {
            git_downloads.push((rel, obj_key, item.size));
        }
    }
    for path in &paths {
        if symlinks.iter().any(|link| path != link && path.starts_with(link)) {
            return Err(Error::bad_request());
        }
    }

    let parent = dest.parent().ok_or_else(Error::bad_request)?.to_path_buf();
    let stage = parent.join(format!(".lazy-{}", Uuid::new_v4()));
    let store = remote::remote_store(state)?;
    let parent_init = parent.clone();
    let stage_init = stage.clone();
    let git_rels: Vec<PathBuf> = git_downloads.iter().map(|(rel, _, _)| rel.clone()).collect();
    super::blocking::run(move || {
        fs::create_dir_all(&parent_init).map_err(Error::internal)?;
        fs::create_dir(&stage_init).map_err(Error::internal)?;
        for rel in git_rels {
            let dir = stage_init.join(rel).parent().ok_or_else(Error::bad_request)?.to_path_buf();
            fs::create_dir_all(dir).map_err(Error::internal)?;
        }
        Ok(())
    })
    .await?;

    let download_outcome: Result<(), Error> = async {
        for (rel, obj_key, size) in &git_downloads {
            let to = stage.join(rel);
            store
                .get_to_file(obj_key, &to, *size, tokio::time::Instant::now() + Duration::from_secs(120))
                .await
                .map_err(Error::internal)?;
        }
        Ok(())
    }
    .await;
    if let Err(err) = download_outcome {
        let cleanup = stage.clone();
        let _ = super::blocking::run(move || {
            let _ = fs::remove_dir_all(&cleanup);
            Ok(())
        })
        .await;
        return Err(err);
    }

    let items = remote.entries;
    let dest_out = dest.clone();
    let sidecar_out = sidecar.clone();
    super::blocking::run(move || {
        let result = (|| -> Result<(), Error> {
            let mut entries = Vec::with_capacity(items.len());
            for item in items {
                let rel = core::decode_path(&item.path_base64).map_err(|_| Error::bad_request())?;
                let to = stage.join(&rel);
                fs::create_dir_all(to.parent().ok_or_else(Error::bad_request)?).map_err(Error::internal)?;
                if item.kind == "symlink" {
                    let target = STANDARD
                        .decode(item.target_base64.as_deref().ok_or_else(Error::bad_request)?)
                        .map_err(|_| Error::bad_request())?;
                    if target.len() as u64 != item.size || hex::encode(Sha256::digest(&target)) != item.sha256 {
                        return Err(Error::bad_request());
                    }
                    let target = PathBuf::from(std::ffi::OsString::from_vec(target));
                    core::validate_symlink(&stage, &rel, &target).map_err(Error::internal)?;
                    symlink(target, &to).map_err(Error::internal)?;
                } else if rel.starts_with(".git") {
                    fs::set_permissions(&to, fs::Permissions::from_mode(item.mode)).map_err(Error::internal)?;
                } else {
                    let file = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(item.mode)
                        .custom_flags(libc::O_NOFOLLOW)
                        .open(&to)
                        .map_err(Error::internal)?;
                    file.set_len(item.size).map_err(Error::internal)?;
                    file.set_permissions(fs::Permissions::from_mode(item.mode)).map_err(Error::internal)?;
                    file.sync_all().map_err(Error::internal)?;
                }
                entries.push(core::Entry {
                    path_base64: item.path_base64,
                    kind: item.kind,
                    mode: item.mode,
                    size: item.size,
                    sha256: item.sha256,
                });
            }
            for path in [".git", ".git/objects", ".git/refs"] {
                fs::create_dir_all(stage.join(path)).map_err(Error::internal)?;
            }
            let manifest = LazyManifest { schema: 1, checkpoint_id: cp, tenant_id: tenant, entries };
            let raw = serde_json::to_vec(&manifest).map_err(Error::internal)?;
            let sidecar_dir = sidecar_out.parent().ok_or_else(Error::bad_request)?;
            fs::create_dir_all(sidecar_dir).map_err(Error::internal)?;
            let temp = sidecar_dir.join(format!(".lazy-{}", Uuid::new_v4()));
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&temp)
                .map_err(Error::internal)?;
            output.write_all(&raw).map_err(Error::internal)?;
            output.sync_all().map_err(Error::internal)?;
            core::sync_tree(&stage).map_err(Error::internal)?;
            fs::rename(&temp, &sidecar_out).map_err(Error::internal)?;
            if let Err(err) = fs::rename(&stage, &dest_out) {
                let _ = fs::remove_file(&sidecar_out);
                return Err(Error::internal(err));
            }
            File::open(&parent).and_then(|file| file.sync_all()).map_err(Error::internal)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&stage);
        }
        result
    })
    .await?;
    Ok(LazyPublished { dest, sidecar, created: true, kept: false })
}

fn fingerprint_manifest(root: &Path, id: Uuid) -> Result<Option<LazyManifest>, Error> {
    let path = manifest_path(root, id);
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(read_manifest(&path)?))
}

pub(super) fn manifest_entries(root: &Path, id: Uuid) -> Result<Option<Vec<core::Entry>>, Error> {
    Ok(fingerprint_manifest(root, id)?.map(|manifest| manifest.entries))
}

/// Blocking facade used by FUSE callbacks to obtain a verified local file.
pub(crate) struct Reader {
    entries: BTreeMap<PathBuf, (ObjectKey, u64)>,
    hydrator: Hydrator,
}

impl Reader {
    pub(super) fn open(state: &AppState, id: Uuid) -> Result<Option<Arc<Self>>, Error> {
        Self::open_root(&state.storage.root, id)
    }

    pub(crate) fn open_root(root: &Path, id: Uuid) -> Result<Option<Arc<Self>>, Error> {
        let Some(manifest) = fingerprint_manifest(root, id)? else {
            return Ok(None);
        };
        let mut entries = BTreeMap::new();
        let mut sizes = HashMap::<String, u64>::new();
        for entry in manifest.entries {
            let rel = core::decode_path(&entry.path_base64).map_err(Error::internal)?;
            if entry.kind != "file" || rel.starts_with(".git") {
                continue;
            }
            let key = remote::key(manifest.tenant_id, &entry.sha256)?;
            if let Some(prior) = sizes.insert(key.sha256.clone(), entry.size)
                && prior != entry.size
            {
                return Err(Error::bad_request());
            }
            entries.insert(rel, (key, entry.size));
        }
        let cache_root = root.join("workspace-service/lazy-cache").join(id.to_string());
        let fetcher = Arc::new(RemoteFetcher { store: Arc::new(remote::store_at(root)?) });
        let hydrator = Hydrator::new(cache_root, fetcher, configured_timeout()).map_err(Error::internal)?;
        Ok(Some(Arc::new(Self { entries, hydrator })))
    }

    pub(crate) fn file(&self, relative: &Path) -> io::Result<Option<File>> {
        let Some((key, size)) = self.entries.get(relative) else {
            return Ok(None);
        };
        self.hydrator.ensure(key, *size).map(Some)
    }

    pub(crate) fn prewarm(&self, paths: &[PathBuf]) -> io::Result<(usize, u64)> {
        let total = self.hydrator.timeout.saturating_mul(paths.len() as u32) + HYDRATION_PUBLICATION_GRACE;
        let deadline = std::time::Instant::now()
            .checked_add(total)
            .unwrap_or_else(|| std::time::Instant::now() + Duration::from_secs(3600));
        self.prewarm_until(paths, deadline)
    }

    pub(crate) fn prewarm_until(&self, paths: &[PathBuf], deadline: std::time::Instant) -> io::Result<(usize, u64)> {
        let mut count = 0;
        let mut bytes = 0;
        for path in paths {
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::from_raw_os_error(libc::ETIMEDOUT));
            }
            let Some((key, size)) = self.entries.get(path) else {
                return Err(io::Error::from_raw_os_error(libc::ENOENT));
            };
            self.hydrator.ensure_until(key, *size, deadline)?;
            count += 1;
            bytes += size;
        }
        Ok((count, bytes))
    }
}

impl crate::workspace_lab::fuse_mount::LazySource for Reader {
    fn file(&self, relative: &Path) -> io::Result<Option<File>> {
        Reader::file(self, relative)
    }
}
