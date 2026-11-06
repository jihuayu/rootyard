//! Verified remote baseline objects hydrated by normal FUSE reads.
use super::{mounts, remote};
use crate::{
    AppState, Error,
    storage::remote_objects::{ObjectKey, RemoteObjectStore},
    workspace_lab::core,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{
        ffi::OsStringExt,
        fs::{OpenOptionsExt, PermissionsExt, symlink},
    },
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};
use tokio::runtime::Runtime;
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LazyManifest {
    schema: u32,
    checkpoint_id: Uuid,
    tenant_id: Uuid,
    entries: Vec<core::Entry>,
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
    let man: LazyManifest = serde_json::from_slice(&raw).map_err(Error::internal)?;
    if man.schema != 1 || man.tenant_id.is_nil() {
        return Err(Error::bad_request());
    }
    core::validate_entries(&man.entries).map_err(Error::internal)?;
    Ok(man)
}

/// Build a sparse immutable lower tree from a verified committed manifest.
/// Native Git metadata is materialized; worktree bytes remain remote.
pub(super) async fn prepare(state: &AppState, id: Uuid, cp: Uuid, repo: Uuid, tenant: Uuid) -> Result<(), Error> {
    let dest = mounts::lower_path(state, id);
    let sidecar = manifest_path(&state.storage.root, id);
    if dest.exists() {
        let old = read_manifest(&sidecar)?;
        if old.checkpoint_id == cp && old.tenant_id == tenant && dest.join(".git").is_dir() {
            return Ok(());
        }
        return Err(Error::internal("conflicting sparse workspace baseline"));
    }
    let remote = remote::load_manifest(state, cp, repo, tenant).await?;
    if remote.entries.len() > core::MAX_ENTRIES {
        return Err(Error::bad_request());
    }
    let mut paths = BTreeSet::new();
    let mut symlinks = BTreeSet::new();
    let mut total = 0u64;
    for item in &remote.entries {
        let rel = core::decode_path(&item.path_base64).map_err(|_| Error::bad_request())?;
        if !paths.insert(rel.clone()) || item.mode > 0o777 || item.size > core::MAX_BYTES {
            return Err(Error::bad_request());
        }
        total = total.checked_add(item.size).ok_or_else(Error::bad_request)?;
        if total > core::MAX_BYTES {
            return Err(Error::bad_request());
        }
        remote::key(tenant, &item.sha256)?;
        if item.kind == "symlink" {
            symlinks.insert(rel);
        } else if item.kind != "file" || item.target_base64.is_some() {
            return Err(Error::bad_request());
        }
    }
    for path in &paths {
        if symlinks.iter().any(|link| path != link && path.starts_with(link)) {
            return Err(Error::bad_request());
        }
    }
    let parent = dest.parent().ok_or_else(Error::bad_request)?;
    fs::create_dir_all(parent).map_err(Error::internal)?;
    let stage = parent.join(format!(".lazy-{}", Uuid::new_v4()));
    fs::create_dir(&stage).map_err(Error::internal)?;
    let store = remote::remote_store(state)?;
    let result = async {
        let mut entries = Vec::with_capacity(remote.entries.len());
        for item in remote.entries {
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
                store
                    .get_to_file(
                        &remote::key(tenant, &item.sha256)?,
                        &to,
                        item.size,
                        tokio::time::Instant::now() + Duration::from_secs(120),
                    )
                    .await
                    .map_err(Error::internal)?;
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
        let sidecar_dir = sidecar.parent().ok_or_else(Error::bad_request)?;
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
        fs::rename(&temp, &sidecar).map_err(Error::internal)?;
        fs::rename(&stage, &dest).map_err(Error::internal)?;
        File::open(parent).and_then(|f| f.sync_all()).map_err(Error::internal)?;
        Ok::<(), Error>(())
    }
    .await;
    if result.is_err() {
        let _ = fs::remove_dir_all(&stage);
    }
    result
}

fn fingerprint_manifest(root: &Path, id: Uuid) -> Result<Option<LazyManifest>, Error> {
    let path = manifest_path(root, id);
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(read_manifest(&path)?))
}
/// Merge immutable baseline metadata with confined CoW entries. This avoids
/// downloading every remote blob during the two-second capture scan.
pub(super) fn fingerprint(path: &Path) -> Result<Option<String>, Error> {
    let Some(id) = path.file_name().and_then(|s| s.to_str()).and_then(|s| Uuid::parse_str(s).ok()) else {
        return Ok(None);
    };
    let Some(kind) = path.parent().and_then(|p| p.file_name()).and_then(|s| s.to_str()) else { return Ok(None) };
    if kind != "mounts" && kind != "workspaces" {
        return Ok(None);
    }
    let root = path.parent().and_then(Path::parent).and_then(Path::parent).ok_or_else(Error::bad_request)?;
    let Some(man) = fingerprint_manifest(root, id)? else { return Ok(None) };
    let upper = root.join("workspace-service/uppers").join(id.to_string());
    let whiteout_file = upper.join(".rootyard-whiteouts.json");
    let whiteouts: BTreeSet<PathBuf> = if whiteout_file.exists() {
        serde_json::from_slice::<Vec<String>>(&fs::read(whiteout_file).map_err(Error::internal)?)
            .map_err(Error::internal)?
            .into_iter()
            .map(PathBuf::from)
            .collect()
    } else {
        BTreeSet::new()
    };
    let hidden = |p: &Path| whiteouts.iter().any(|w| p == w || p.starts_with(w));
    let mut entries = BTreeMap::<PathBuf, core::Entry>::new();
    for entry in man.entries {
        let path = core::decode_path(&entry.path_base64).map_err(Error::internal)?;
        if !hidden(&path) {
            entries.insert(path, entry);
        }
    }
    if upper.is_dir() {
        for entry in core::inventory(&upper).map_err(Error::internal)? {
            let rel = core::decode_path(&entry.path_base64).map_err(Error::internal)?;
            if !rel.as_os_str().as_encoded_bytes().starts_with(b".rootyard-whiteouts.") && !hidden(&rel) {
                entries.insert(rel, entry);
            }
        }
    }
    let raw = serde_json::to_vec(&entries.into_values().collect::<Vec<_>>()).map_err(Error::internal)?;
    Ok(Some(hex::encode(Sha256::digest(raw))))
}

pub(crate) struct Reader {
    entries: BTreeMap<PathBuf, (ObjectKey, u64)>,
    cache_root: PathBuf,
    store: RemoteObjectStore,
    runtime: &'static Runtime,
    checked: Mutex<HashSet<PathBuf>>,
    hydrate: Mutex<()>,
}
fn io_runtime() -> Result<&'static Runtime, Error> {
    static IO: OnceLock<Result<Runtime, String>> = OnceLock::new();
    IO.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("rootyard-lazy-io")
            .enable_all()
            .build()
            .map_err(|error| error.to_string())
    })
    .as_ref()
    .map_err(|error| Error::internal(error.clone()))
}
impl Reader {
    pub(super) fn open(state: &AppState, id: Uuid) -> Result<Option<Arc<Self>>, Error> {
        let Some(man) = fingerprint_manifest(&state.storage.root, id)? else { return Ok(None) };
        let mut entries = BTreeMap::new();
        for entry in man.entries {
            let rel = core::decode_path(&entry.path_base64).map_err(Error::internal)?;
            if entry.kind == "file" && !rel.starts_with(".git") {
                entries.insert(rel, (remote::key(man.tenant_id, &entry.sha256)?, entry.size));
            }
        }
        let cache_root = state.storage.root.join("workspace-service/lazy-cache").join(id.to_string());
        fs::create_dir_all(&cache_root).map_err(Error::internal)?;
        Ok(Some(Arc::new(Self {
            entries,
            cache_root,
            store: remote::remote_store(state)?,
            runtime: io_runtime()?,
            checked: Mutex::new(HashSet::new()),
            hydrate: Mutex::new(()),
        })))
    }
    pub(crate) fn file(&self, relative: &Path) -> io::Result<Option<File>> {
        let Some((key, size)) = self.entries.get(relative) else { return Ok(None) };
        let _guard = self.hydrate.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let dest = self.cache_root.join(&key.sha256);
        if !self.checked.lock().unwrap().contains(relative) {
            let valid = match OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(&dest) {
                Ok(mut file) if file.metadata()?.len() == *size => {
                    let mut hash = Sha256::new();
                    let mut buf = [0u8; 65536];
                    loop {
                        let n = file.read(&mut buf)?;
                        if n == 0 {
                            break;
                        }
                        hash.update(&buf[..n]);
                    }
                    hex::encode(hash.finalize()) == key.sha256
                }
                _ => false,
            };
            if !valid {
                let _ = fs::remove_file(&dest);
                let result = self.runtime.block_on(async {
                    tokio::time::timeout(
                        Duration::from_secs(8),
                        self.store.get_to_file(key, &dest, *size, tokio::time::Instant::now() + Duration::from_secs(8)),
                    )
                    .await
                });
                result.map_err(io::Error::other)?.map_err(io::Error::other)?;
            }
            self.checked.lock().unwrap().insert(relative.to_path_buf());
        }
        Ok(Some(OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW).open(dest)?))
    }
    pub(super) fn prewarm(&self, paths: &[PathBuf]) -> io::Result<(usize, u64)> {
        let mut count = 0;
        let mut bytes = 0;
        for path in paths {
            let Some((_, size)) = self.entries.get(path) else {
                return Err(io::Error::from_raw_os_error(libc::ENOENT));
            };
            self.file(path)?;
            count += 1;
            bytes += size;
        }
        Ok((count, bytes))
    }
}
