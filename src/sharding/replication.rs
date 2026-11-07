//! Pinned Git ref manifests, resumable bundle snapshots and framed transfer helpers.
//!
//! An initial snapshot is taken under a short exclusive barrier that records a
//! safe journal sequence, then the bundle itself is produced while ordinary
//! clients keep writing. The target installs exactly the recorded refs, not the
//! refs that happened to be current while a bundle was being generated.
use crate::{AppState, Error, journal, sharding::models::conflict};
use axum::body::{Body, BodyDataStream};
use bytes::Bytes;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::{Path as FsPath, PathBuf},
    time::Duration,
};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;

pub(crate) const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MAX_REFS: usize = 4096;
const SNAPSHOT_RETRIES: usize = 80;


#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RefEntry {
    pub(crate) oid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) symref: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct RefManifest {
    pub(crate) refs: BTreeMap<String, RefEntry>,
    pub(crate) head: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransferMeta {
    pub(crate) base: RefManifest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) final_refs: Option<RefManifest>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SnapshotBase {
    pub(crate) operation_id: Uuid,
    pub(crate) repository_id: Uuid,
    pub(crate) refs_sha256: String,
    pub(crate) journal_sequence: i64,
    pub(crate) source_route_epoch: i64,
    pub(crate) source_generation: i64,
    pub(crate) manifest: RefManifest,
}

pub(crate) async fn git_output(
    state: &AppState,
    args: &[&str],
    timeout: Duration,
) -> Result<Vec<u8>, Error> {
    let mut command = state.storage.git(&state.config);
    command.args(args);
    crate::git_http::collect_git_output(command, 16 * 1024 * 1024, timeout)
        .await
        .map_err(|_| conflict("Git bundle or verification failed"))
}

/// The lease is polled while Git runs. The shared process wrapper's Drop
/// synchronously kills and reaps the native process group on cancellation.
pub(crate) async fn git_output_lease(
    state: &AppState,
    args: &[&str],
    timeout: Duration,
    lease: &crate::storage::read_leases::Lease,
) -> Result<Vec<u8>, Error> {
    let mut command = state.storage.git(&state.config);
    command.args(args);
    lease
        .guard(crate::git_http::collect_git_output(command, 16 * 1024 * 1024, timeout))
        .await?
        .map_err(|_| conflict("Git bundle or verification failed"))
}

pub(crate) async fn refs_digest_lease(
    state: &AppState,
    repo: &FsPath,
    lease: &crate::storage::read_leases::Lease,
) -> Result<String, Error> {
    let manifest = read_manifest_lease(state, repo, lease).await?;
    Ok(manifest.digest())
}

pub(crate) async fn configure_target(
    state: &AppState,
    repo: &FsPath,
    repo_id: Uuid,
) -> Result<(), Error> {
    let path = repo.to_str().ok_or_else(Error::bad_request)?;
    let _ = git_output(
        state,
        &["--git-dir", path, "config", "--remove-section", "remote.origin"],
        state.config.git_timeout,
    )
    .await;
    let max_request = state.config.max_request_bytes.to_string();
    let settings = [
        ("rootyard.repositoryId", repo_id.to_string()),
        ("http.receivepack", "true".into()),
        ("http.getanyfile", "false".into()),
        ("receive.denyNonFastForwards", "true".into()),
        ("receive.denyDeleteCurrent", "true".into()),
        ("receive.fsckObjects", "true".into()),
        ("transfer.fsckObjects", "true".into()),
        ("receive.maxInputSize", max_request),
        ("uploadpack.allowFilter", "false".into()),
        ("uploadpack.allowAnySHA1InWant", "false".into()),
        ("uploadpack.allowTipSHA1InWant", "false".into()),
        ("uploadpack.allowReachableSHA1InWant", "false".into()),
        ("core.logAllRefUpdates", "true".into()),
        ("core.fsync", "committed".into()),
        ("core.fsyncMethod", "fsync".into()),
        ("gc.auto", "0".into()),
        ("maintenance.auto", "false".into()),
        ("pack.threads", "1".into()),
        ("pack.windowMemory", "32m".into()),
        ("pack.deltaCacheSize", "32m".into()),
    ];
    for (name, value) in settings {
        git_output(state, &["--git-dir", path, "config", name, &value], state.config.git_timeout)
            .await?;
    }
    Ok(())
}

pub(crate) fn valid_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64)
        && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl RefManifest {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.refs.is_empty() || self.refs.len() > MAX_REFS {
            return Err(conflict("source ref manifest is empty or too large"));
        }
        if !self.head.starts_with("refs/") || self.head.contains('\0') || self.head.contains('\n')
            || !journal::valid_ref(&self.head)
        {
            return Err(conflict("source ref manifest has an invalid HEAD"));
        }
        for (name, entry) in &self.refs {
            if !name.starts_with("refs/") || !journal::valid_ref(name) || !valid_oid(&entry.oid) {
                return Err(conflict("source ref manifest contains an invalid ref or object id"));
            }
            if let Some(target) = &entry.symref
                && (!target.starts_with("refs/") || !journal::valid_ref(target) || target == name)
            {
                return Err(conflict("source ref manifest contains an invalid symbolic ref"));
            }
        }
        Ok(())
    }

    pub(crate) fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"rootyard-shard-refs-v1\0");
        for (name, entry) in &self.refs {
            hasher.update(name.as_bytes());
            hasher.update(b" ");
            hasher.update(entry.oid.as_bytes());
            hasher.update(b"\n");
        }
        hasher.update(b"HEAD\0");
        hasher.update(self.head.as_bytes());
        hasher.update(b"\n");
        hex::encode(hasher.finalize())
    }
}

pub(crate) fn staging_root(state: &AppState) -> Result<PathBuf, Error> {
    let root = state.storage.root.join("shard-staging");
    fs::create_dir_all(&root).map_err(Error::internal)?;
    let meta = fs::symlink_metadata(&root).map_err(Error::internal)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(conflict("unsafe shard staging directory"));
    }
    Ok(root)
}

pub(crate) fn clean_staging(path: &FsPath) -> Result<(), Error> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {
            fs::remove_dir_all(path).map_err(Error::internal)
        }
        Ok(meta) if meta.is_file() && !meta.file_type().is_symlink() => {
            fs::remove_file(path).map_err(Error::internal)
        }
        Ok(_) => Err(conflict("unsafe existing shard staging path")),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(Error::internal(err)),
    }
}

pub(crate) fn sync_parent(path: &FsPath) -> Result<(), Error> {
    File::open(path).and_then(|file| file.sync_all()).map_err(Error::internal)
}

pub(crate) fn base_path(state: &AppState, operation_id: Uuid) -> Result<PathBuf, Error> {
    Ok(staging_root(state)?.join(format!("{operation_id}.base.json")))
}

pub(crate) fn read_base(
    state: &AppState,
    operation_id: Uuid,
    repository_id: Uuid,
) -> Result<Option<SnapshotBase>, Error> {
    let path = base_path(state, operation_id)?;
    if !journal::exists(&path).map_err(Error::internal)? {
        return Ok(None);
    }
    let bytes = journal::read(&path).map_err(Error::internal)?;
    let base: SnapshotBase = serde_json::from_slice(&bytes)
        .map_err(|_| conflict("corrupt shard snapshot manifest"))?;
    if base.operation_id != operation_id || base.repository_id != repository_id {
        return Err(conflict("shard snapshot manifest belongs to another operation"));
    }
    base.manifest.validate()?;
    if base.refs_sha256 != base.manifest.digest() || base.journal_sequence < 0 {
        return Err(conflict("shard snapshot manifest digest or sequence is invalid"));
    }
    Ok(Some(base))
}

fn write_base(state: &AppState, base: &SnapshotBase) -> Result<(), Error> {
    let path = base_path(state, base.operation_id)?;
    let bytes = serde_json::to_vec_pretty(base).map_err(Error::internal)?;
    journal::atomic(&path, &bytes, true).map_err(Error::internal)
}

pub(crate) async fn read_manifest_plain(state: &AppState, repo: &FsPath) -> Result<RefManifest, Error> {
    let path = repo.to_str().ok_or_else(Error::bad_request)?;
    let raw = git_output(state, &["--git-dir", path, "for-each-ref",
        "--format=%(refname)%00%(objectname)%00%(symref)"], state.config.git_timeout).await?;
    let mut refs = BTreeMap::new();
    for line in std::str::from_utf8(&raw).map_err(|_| conflict("non UTF-8 ref listing"))?.lines() {
        let mut fields = line.split('\0');
        let Some(name) = fields.next() else { continue };
        let oid = fields.next().ok_or_else(|| conflict("malformed ref listing"))?;
        let symref = fields.next().unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        refs.insert(name.to_owned(), RefEntry {
            oid: oid.to_owned(),
            symref: (!symref.is_empty()).then(|| symref.to_owned()),
        });
    }
    let head = git_output(state, &["--git-dir", path, "symbolic-ref", "HEAD"],
        state.config.git_timeout).await?;
    let head = std::str::from_utf8(&head).map_err(|_| conflict("non UTF-8 HEAD"))?.trim().to_owned();
    let manifest = RefManifest { refs, head };
    manifest.validate()?;
    Ok(manifest)
}

pub(crate) async fn read_manifest_lease(
    state: &AppState,
    repo: &FsPath,
    lease: &crate::storage::read_leases::Lease,
) -> Result<RefManifest, Error> {
    let path = repo.to_str().ok_or_else(Error::bad_request)?;
    let raw = git_output_lease(state, &["--git-dir", path, "for-each-ref",
        "--format=%(refname)%00%(objectname)%00%(symref)"], state.config.git_timeout, lease).await?;
    let mut refs = BTreeMap::new();
    for line in std::str::from_utf8(&raw).map_err(|_| conflict("non UTF-8 ref listing"))?.lines() {
        let mut fields = line.split('\0');
        let Some(name) = fields.next() else { continue };
        let oid = fields.next().ok_or_else(|| conflict("malformed ref listing"))?;
        let symref = fields.next().unwrap_or_default();
        if name.is_empty() {
            continue;
        }
        refs.insert(name.to_owned(), RefEntry {
            oid: oid.to_owned(),
            symref: (!symref.is_empty()).then(|| symref.to_owned()),
        });
    }
    let head = git_output_lease(state, &["--git-dir", path, "symbolic-ref", "HEAD"],
        state.config.git_timeout, lease).await?;
    let head = std::str::from_utf8(&head).map_err(|_| conflict("non UTF-8 HEAD"))?.trim().to_owned();
    let manifest = RefManifest { refs, head };
    manifest.validate()?;
    Ok(manifest)
}

fn journal_repository(state: &AppState, repository_id: Uuid) -> Result<PathBuf, Error> {
    let root = state.storage.root.join("journal");
    journal::mkdir(&root).map_err(Error::internal)?;
    let repo = root.join(repository_id.to_string());
    journal::mkdir(&repo).map_err(Error::internal)?;
    let counter = repo.join("sequence");
    if !journal::exists(&counter).map_err(Error::internal)? {
        journal::atomic(&counter, b"0", false).map_err(Error::internal)?;
    }
    Ok(repo)
}

fn sequence_lock(state: &AppState, repository_id: Uuid) -> Result<Option<File>, Error> {
    let repo = journal_repository(state, repository_id)?;
    let lock = OpenOptions::new().read(true).write(true).create(true).mode(0o600)
        .custom_flags(libc::O_NOFOLLOW).open(repo.join("sequence.lock")).map_err(Error::internal)?;
    match fs2::FileExt::try_lock_exclusive(&lock) {
        Ok(()) => Ok(Some(lock)),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(error) => Err(Error::internal(error)),
    }
}

fn unique_oids(manifest: &RefManifest) -> Vec<&str> {
    let mut seen = BTreeSet::new();
    manifest.refs.values().filter_map(|entry| {
        if seen.insert(entry.oid.as_str()) { Some(entry.oid.as_str()) } else { None }
    }).collect()
}

async fn bundle_create(
    state: &AppState,
    repo: &FsPath,
    bundle: &FsPath,
    manifest: &RefManifest,
    base: Option<&RefManifest>,
    lease: Option<&crate::storage::read_leases::Lease>,
) -> Result<(), Error> {
    let repo = repo.to_str().ok_or_else(Error::bad_request)?;
    let bundle = bundle.to_str().ok_or_else(Error::bad_request)?;
    let mut args = vec!["--git-dir", repo, "bundle", "create", bundle, "--all"];
    let oids = unique_oids(manifest);
    args.extend(oids.iter().copied());
    if let Some(base) = base {
        args.push("--not");
        args.extend(unique_oids(base));
    }
    match lease {
        Some(lease) => git_output_lease(state, &args, state.config.git_timeout, lease).await.map(|_| ()),
        None => git_output(state, &args, state.config.git_timeout).await.map(|_| ()),
    }
}

/// Capture a consistent ref manifest under a short exclusive barrier, then
/// build its bundle under a shared read lease so ordinary pushes continue. The
/// journal sequence is a safe lower bound: no native ref writer is live and the
/// journal admission lock holds until the counter and operation record agree.
pub(crate) async fn capture_source_snapshot(
    state: &AppState,
    repository_id: Uuid,
    operation_id: Uuid,
    source_route_epoch: i64,
    source_generation: i64,
) -> Result<SnapshotBase, Error> {
    let repo = state.storage.verify_path(repository_id).map_err(Error::internal)?;
    let stage = staging_root(state)?;
    let bundle = stage.join(format!("{operation_id}.bundle"));
    let mut last = conflict("source refs did not stabilize for a shard snapshot");
    for attempt in 0..SNAPSHOT_RETRIES {
        let guard = crate::sharding::locks::exclusive(state, repository_id).await?;
        let Some(admission) = sequence_lock(state, repository_id)? else {
            drop(guard);
            tokio::time::sleep(Duration::from_millis(20)).await;
            continue;
        };
        let pending = journal::pending(&state.storage.root, repository_id).map_err(Error::internal)?;
        if pending.iter().any(|operation| {
            journal::ActiveGuard::operation_is_live(operation).unwrap_or(true)
        }) {
            drop(admission);
            drop(guard);
            tokio::time::sleep(Duration::from_millis(50)).await;
            continue;
        }
        let sequence = journal::sequence(&state.storage.root, repository_id).map_err(Error::internal)?;
        let manifest = read_manifest_plain(state, &repo).await?;
        let digest = manifest.digest();
        drop(admission);
        drop(guard);
        clean_staging(&bundle)?;
        let lease = crate::storage::read_leases::shared(
            &state.pool, repository_id, tokio::time::Instant::now() + state.config.git_timeout,
        ).await?;
        let _read = state.storage.read_snapshot_lock(repository_id).await;
        if let Err(error) = bundle_create(state, &repo, &bundle, &manifest, None, Some(&lease)).await {
            last = error;
            drop(lease);
            if attempt + 1 < SNAPSHOT_RETRIES {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
            continue;
        }
        lease.ensure_active()?;
        File::open(&bundle).and_then(|file| file.sync_all()).map_err(Error::internal)?;
        sync_parent(&stage)?;
        let base = SnapshotBase {
            operation_id,
            repository_id,
            refs_sha256: digest,
            journal_sequence: sequence,
            source_route_epoch,
            source_generation,
            manifest,
        };
        write_base(state, &base)?;
        return Ok(base);
    }
    Err(last)
}

pub(crate) async fn create_delta_bundle(
    state: &AppState,
    repository_id: Uuid,
    operation_id: Uuid,
    base: &RefManifest,
    final_refs: &RefManifest,
) -> Result<Option<PathBuf>, Error> {
    if base == final_refs {
        return Ok(None);
    }
    let repo = state.storage.verify_path(repository_id).map_err(Error::internal)?;
    let stage = staging_root(state)?;
    let bundle = stage.join(format!("{operation_id}.delta.bundle"));
    clean_staging(&bundle)?;
    bundle_create(state, &repo, &bundle, final_refs, Some(base), None).await?;
    File::open(&bundle).and_then(|file| file.sync_all()).map_err(Error::internal)?;
    sync_parent(&stage)?;
    Ok(Some(bundle))
}

pub(crate) fn encode_meta(meta: &TransferMeta) -> Result<Vec<u8>, Error> {
    let json = serde_json::to_vec(meta).map_err(Error::internal)?;
    if json.is_empty() || json.len() > MAX_MANIFEST_BYTES {
        return Err(conflict("snapshot manifest exceeds transfer limit"));
    }
    let mut framed = Vec::with_capacity(8 + json.len());
    framed.extend_from_slice(&(json.len() as u64).to_be_bytes());
    framed.extend_from_slice(&json);
    Ok(framed)
}

pub(crate) struct FrameReader {
    stream: BodyDataStream,
    buffered: Vec<u8>,
}

impl FrameReader {
    pub(crate) fn new(body: Body) -> Self {
        Self { stream: body.into_data_stream(), buffered: Vec::new() }
    }

    async fn fill(&mut self) -> Result<(), Error> {
        match self.stream.next().await {
            Some(Ok(chunk)) => {
                if self.buffered.len().saturating_add(chunk.len()) > MAX_MANIFEST_BYTES * 2 {
                    return Err(conflict("snapshot framing exceeds limit"));
                }
                self.buffered.extend_from_slice(&chunk);
                Ok(())
            }
            Some(Err(_)) => Err(conflict("snapshot body stream failed")),
            None => Err(conflict("truncated snapshot frame")),
        }
    }

    pub(crate) async fn read_meta(&mut self) -> Result<TransferMeta, Error> {
        while self.buffered.len() < 8 {
            self.fill().await?;
        }
        let mut length = [0_u8; 8];
        length.copy_from_slice(&self.buffered[..8]);
        let length = u64::from_be_bytes(length) as usize;
        if length == 0 || length > MAX_MANIFEST_BYTES {
            return Err(conflict("snapshot manifest length is invalid"));
        }
        while self.buffered.len() < 8 + length {
            self.fill().await?;
        }
        let json = self.buffered[8..8 + length].to_vec();
        self.buffered.drain(..8 + length);
        let meta: TransferMeta = serde_json::from_slice(&json)
            .map_err(|_| conflict("corrupt snapshot manifest"))?;
        meta.base.validate()?;
        if let Some(final_refs) = &meta.final_refs { final_refs.validate()?; }
        Ok(meta)
    }

    /// Write the remaining bytes of the request body to `path` and return the
    /// measured size. The caller owns the newly-created private staging file.
    pub(crate) async fn write_bundle(
        &mut self,
        path: &FsPath,
        maximum: u64,
        allow_empty: bool,
    ) -> Result<u64, Error> {
        let file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)
            .map_err(Error::internal)?;
        let mut file = tokio::fs::File::from_std(file);
        let mut total = self.buffered.len() as u64;
        if total > maximum {
            return Err(conflict("snapshot bundle exceeds configured repository size"));
        }
        if !self.buffered.is_empty() {
            file.write_all(&self.buffered).await.map_err(Error::internal)?;
            self.buffered.clear();
        }
        while let Some(chunk) = self.stream.next().await {
            let chunk = chunk.map_err(|_| conflict("snapshot body stream failed"))?;
            total = total.saturating_add(chunk.len() as u64);
            if total > maximum {
                return Err(conflict("snapshot bundle exceeds configured repository size"));
            }
            file.write_all(&chunk).await.map_err(Error::internal)?;
        }
        file.sync_all().await.map_err(Error::internal)?;
        if total == 0 && !allow_empty {
            return Err(conflict("empty snapshot bundle"));
        }
        Ok(total)
    }
}

/// Apply an exact ref manifest to a staging or standby repository. Refs not in
/// the manifest are removed, so an older target cannot retain stale roots.
pub(crate) async fn apply_manifest(
    state: &AppState,
    repo: &FsPath,
    manifest: &RefManifest,
    lease: &crate::storage::read_leases::Lease,
) -> Result<(), Error> {
    manifest.validate()?;
    let path = repo.to_str().ok_or_else(Error::bad_request)?;
    let raw = git_output_lease(state, &["--git-dir", path, "for-each-ref",
        "--format=%(refname)%00%(symref)"], state.config.git_timeout, lease).await?;
    let mut current = BTreeMap::new();
    for line in std::str::from_utf8(&raw).map_err(|_| conflict("non UTF-8 ref listing"))?.lines() {
        let mut fields = line.split('\0');
        let Some(name) = fields.next() else { continue };
        let symref = fields.next().unwrap_or_default();
        if !name.is_empty() {
            current.insert(name.to_owned(), (!symref.is_empty()).then(|| symref.to_owned()));
        }
    }
    for (name, symref) in &current {
        if manifest.refs.contains_key(name) {
            continue;
        }
        if symref.is_some() {
            let _ = git_output_lease(state, &["--git-dir", path, "symbolic-ref", "--delete", name],
                state.config.git_timeout, lease).await;
        }
        git_output_lease(state, &["--git-dir", path, "update-ref", "--no-deref", "-d", name],
            state.config.git_timeout, lease).await?;
    }
    for (name, entry) in &manifest.refs {
        if let Some(target) = &entry.symref {
            git_output_lease(state, &["--git-dir", path, "symbolic-ref", name, target],
                state.config.git_timeout, lease).await?;
        } else {
            git_output_lease(state, &["--git-dir", path, "update-ref", "--no-deref", name, &entry.oid],
                state.config.git_timeout, lease).await?;
        }
    }
    git_output_lease(state, &["--git-dir", path, "symbolic-ref", "HEAD", &manifest.head],
        state.config.git_timeout, lease).await?;
    let observed = read_manifest_lease(state, repo, lease).await?;
    if &observed != manifest {
        return Err(conflict("target refs differ from the transferred manifest"));
    }
    Ok(())
}
