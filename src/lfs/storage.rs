//! Verified streaming object storage and atomic staging for Track 2B Git LFS.
use crate::storage::remote_objects::{ObjectKey, RemoteObjectStore};
use crate::{AppState, Error, journal, lfs::models, storage};
use anyhow::{Context, Result, ensure};
use axum::{body::Body, http::StatusCode};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};
use tokio::io::AsyncWriteExt;
use tokio::time::Instant;
use tokio_util::io::ReaderStream;
use uuid::Uuid;

fn remote_store(data_root: &Path) -> Result<Option<RemoteObjectStore>> {
    if std::env::var_os("ROOTYARD_OBJECT_STORE_ENDPOINT").is_none() {
        return Ok(None);
    }
    Ok(Some(RemoteObjectStore::from_env(
        data_root.join("remote-objects"),
    )?))
}

pub async fn publish_remote(
    state: &AppState,
    repo_id: Uuid,
    tenant_id: Uuid,
    oid: &str,
    size: u64,
) -> Result<(), Error> {
    let Some(store) = remote_store(&state.storage.root).map_err(Error::internal)? else {
        return Ok(());
    };
    let key = ObjectKey::new(tenant_id, "lfs", oid).map_err(Error::internal)?;
    let path = object_path(&state.storage.root, repo_id, oid).map_err(Error::internal)?;
    store
        .put_file(&key, &path, size, Instant::now() + state.config.git_timeout)
        .await
        .map_err(Error::internal)?;
    Ok(())
}

pub async fn ensure_readable(
    data_root: &Path,
    repo_id: Uuid,
    tenant_id: Uuid,
    oid: &str,
    size: u64,
    deadline: Instant,
) -> Result<bool> {
    let local_good = verify_local_until(data_root, repo_id, oid, size, deadline).await?;
    let Some(store) = remote_store(data_root)? else {
        return Ok(local_good);
    };
    let key = ObjectKey::new(tenant_id, "lfs", oid)?;
    if local_good {
        if store
            .head(&key, deadline)
            .await?
            .is_none_or(|head| head.size != size)
        {
            let path = object_path(data_root, repo_id, oid)?;
            store.put_file(&key, &path, size, deadline).await?;
        }
        return Ok(true);
    }
    if store
        .head(&key, deadline)
        .await?
        .is_none_or(|head| head.size != size)
    {
        return Ok(false);
    }
    hydrate_verified_remote(&store, &key, data_root, repo_id, oid, size, deadline).await
}

/// Downloads a remote object into a unique staging file inside this repository's
/// LFS directory, verifies digest, size, mode and link count, then atomically
/// renames it over the immutable oid path. The final path therefore only ever
/// holds complete, verified bytes, and concurrent cold readers stage
/// independently. Only this request's own staging file is removed on failure.
async fn hydrate_verified_remote(
    store: &RemoteObjectStore,
    key: &ObjectKey,
    data_root: &Path,
    repo_id: Uuid,
    oid: &str,
    size: u64,
    deadline: Instant,
) -> Result<bool> {
    let dir = ensure_repo_lfs_dir(data_root, repo_id)?;
    let final_path = object_path(data_root, repo_id, oid)?;
    let temp_path = dir.join(format!(".tmp-{}", Uuid::new_v4()));
    let mut guard = StagingFileGuard::new(temp_path.clone());

    store.get_to_file(key, &temp_path, size, deadline).await?;

    let staged = temp_path.clone();
    let staged_oid = oid.to_owned();
    let staged_ok = tokio::task::spawn_blocking(move || -> Result<bool> {
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o600))?;
        File::open(&staged)?.sync_all()?;
        verify_path_integrity_bounded(&staged, &staged_oid, size, deadline)
    })
    .await??;
    if !staged_ok {
        return Ok(false);
    }

    let rename_target = final_path;
    let dir_for_sync = dir;
    tokio::task::spawn_blocking(move || -> Result<()> {
        fs::rename(&temp_path, &rename_target).context("failed to publish hydrated LFS object")?;
        File::open(&dir_for_sync)?.sync_all()?;
        Ok(())
    })
    .await??;
    guard.disarm();
    verify_local_until(data_root, repo_id, oid, size, deadline).await
}

async fn verify_local_until(
    data_root: &Path,
    repo_id: Uuid,
    oid: &str,
    size: u64,
    deadline: Instant,
) -> Result<bool> {
    let root = data_root.to_path_buf();
    let oid = oid.to_owned();
    tokio::task::spawn_blocking(move || {
        verify_object_integrity_bounded(&root, repo_id, &oid, size, deadline)
    })
    .await?
}

/// RAII guard that removes the temporary `.tmp-<uuid>` upload file on drop unless disarmed.
pub struct StagingFileGuard {
    path: PathBuf,
    committed: bool,
}

impl StagingFileGuard {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            committed: false,
        }
    }

    pub fn disarm(&mut self) {
        self.committed = true;
    }
}

impl Drop for StagingFileGuard {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub fn lfs_root(data_root: &Path) -> PathBuf {
    data_root.join("lfs")
}

pub fn repo_lfs_dir(data_root: &Path, repo_id: Uuid) -> PathBuf {
    lfs_root(data_root).join(repo_id.to_string())
}

pub fn object_path(data_root: &Path, repo_id: Uuid, oid: &str) -> Result<PathBuf> {
    ensure!(models::valid_lfs_oid(oid), "invalid LFS object oid");
    Ok(repo_lfs_dir(data_root, repo_id).join(oid))
}

pub fn ensure_repo_lfs_dir(data_root: &Path, repo_id: Uuid) -> Result<PathBuf> {
    journal::safe_path(data_root)?;
    let root = lfs_root(data_root);
    journal::mkdir(&root)?;
    let dir = repo_lfs_dir(data_root, repo_id);
    journal::mkdir(&dir)?;
    Ok(dir)
}

pub fn object_exists_with_size(
    data_root: &Path,
    repo_id: Uuid,
    oid: &str,
    expected_size: u64,
) -> Result<bool> {
    let path = object_path(data_root, repo_id, oid)?;
    if !journal::exists(&path)? {
        return Ok(false);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.nlink() != 1 || (meta.mode() & 0o7777) != 0o600 {
        return Ok(false);
    }
    Ok(meta.len() == expected_size)
}

pub fn verify_object_integrity(
    data_root: &Path,
    repo_id: Uuid,
    oid: &str,
    expected_size: u64,
) -> Result<bool> {
    verify_object_integrity_bounded(
        data_root,
        repo_id,
        oid,
        expected_size,
        Instant::now() + Duration::from_secs(24 * 60 * 60),
    )
}

fn verify_object_integrity_bounded(
    data_root: &Path,
    repo_id: Uuid,
    oid: &str,
    expected_size: u64,
    deadline: Instant,
) -> Result<bool> {
    let path = object_path(data_root, repo_id, oid)?;
    verify_path_integrity_bounded(&path, oid, expected_size, deadline)
}

/// Verifies an object file (the immutable oid path or our own staging file)
/// against the expected digest, size, mode and link count.
fn verify_path_integrity_bounded(
    path: &Path,
    expected_oid: &str,
    expected_size: u64,
    deadline: Instant,
) -> Result<bool> {
    if !journal::exists(path)? {
        return Ok(false);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.nlink() != 1
        || (meta.mode() & 0o7777) != 0o600
        || meta.len() != expected_size
    {
        return Ok(false);
    }
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buf = [0u8; 64 * 1024];
    loop {
        ensure!(
            Instant::now() < deadline,
            "LFS integrity verification timed out"
        );
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n as u64);
        if total > expected_size {
            return Ok(false);
        }
        hasher.update(&buf[..n]);
    }
    if total != expected_size {
        return Ok(false);
    }
    let digest = hex::encode(hasher.finalize());
    Ok(digest == expected_oid)
}

pub async fn check_repo_quota(
    state: &AppState,
    repo_id: Uuid,
    additional_bytes: u64,
) -> Result<(), Error> {
    let repo_path = state
        .storage
        .verify_path(repo_id)
        .map_err(Error::internal)?;
    let lfs_dir = repo_lfs_dir(&state.storage.root, repo_id);
    let quota = state.config.max_repo_bytes;
    let used = tokio::task::spawn_blocking(move || -> Result<u64> {
        let mut sum = storage::disk_bytes(&repo_path, quota)?;
        if lfs_dir.exists() {
            sum = sum.saturating_add(storage::disk_bytes(&lfs_dir, quota)?);
        }
        Ok(sum)
    })
    .await
    .map_err(Error::internal)?
    .map_err(Error::internal)?;
    if used.saturating_add(additional_bytes) > quota {
        return Err(Error(
            StatusCode::INSUFFICIENT_STORAGE,
            "repository quota reached",
        ));
    }
    Ok(())
}

pub async fn stream_to_staging_and_publish(
    state: &AppState,
    repo_id: Uuid,
    expected_oid: &str,
    expected_size: u64,
    body: Body,
) -> Result<(), Error> {
    let repo_dir = ensure_repo_lfs_dir(&state.storage.root, repo_id).map_err(Error::internal)?;
    let temp_path = repo_dir.join(format!(".tmp-{}", Uuid::new_v4()));
    let mut guard = StagingFileGuard::new(temp_path.clone());

    let std_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temp_path)
        .map_err(Error::internal)?;
    let mut file = tokio::fs::File::from_std(std_file);

    let mut hasher = Sha256::new();
    let mut received: u64 = 0;
    let mut stream = body.into_data_stream();

    while let Some(chunk_res) = stream.next().await {
        let chunk = chunk_res.map_err(|_| {
            state.transfer_metrics.record_failure();
            Error::bad_request()
        })?;
        let chunk_len = chunk.len() as u64;
        received = received.saturating_add(chunk_len);
        state.transfer_metrics.add_received_bytes(chunk_len);

        if received > state.config.max_request_bytes {
            state.transfer_metrics.record_failure();
            return Err(Error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "request size limit exceeded",
            ));
        }
        if received > expected_size {
            state.transfer_metrics.record_failure();
            return Err(Error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "LFS object size mismatch",
            ));
        }
        hasher.update(&chunk);
        file.write_all(&chunk).await.map_err(Error::internal)?;
    }

    if received != expected_size {
        state.transfer_metrics.record_failure();
        return Err(Error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "LFS object size mismatch",
        ));
    }

    let actual_oid = hex::encode(hasher.finalize());
    if actual_oid != expected_oid {
        state.transfer_metrics.record_failure();
        return Err(Error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "LFS object SHA-256 mismatch",
        ));
    }

    file.flush().await.map_err(Error::internal)?;
    file.sync_all().await.map_err(Error::internal)?;
    drop(file);

    let final_path =
        object_path(&state.storage.root, repo_id, expected_oid).map_err(Error::internal)?;
    let temp_for_rename = temp_path.clone();
    let dir_for_sync = repo_dir.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        fs::rename(&temp_for_rename, &final_path).context("failed to publish LFS object")?;
        File::open(&dir_for_sync)?.sync_all()?;
        Ok(())
    })
    .await
    .map_err(Error::internal)?
    .map_err(Error::internal)?;

    guard.disarm();
    Ok(())
}

pub async fn open_verified_download_stream(
    state: &AppState,
    repo_id: Uuid,
    tenant_id: Uuid,
    oid: &str,
    expected_size: u64,
) -> Result<Body, Error> {
    let verified = ensure_readable(
        &state.storage.root,
        repo_id,
        tenant_id,
        oid,
        expected_size,
        Instant::now() + state.config.git_timeout,
    )
    .await
    .map_err(Error::internal)?;

    if !verified {
        state.transfer_metrics.record_failure();
        return Err(Error::internal("LFS object missing or corrupt on volume"));
    }

    let path = object_path(&state.storage.root, repo_id, oid).map_err(Error::internal)?;
    let std_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(Error::internal)?;
    let file = tokio::fs::File::from_std(std_file);
    let metrics = state.transfer_metrics.clone();
    let stream = ReaderStream::with_capacity(file, 64 * 1024).map(move |res| {
        if let Ok(ref bytes) = res {
            metrics.add_sent_bytes(bytes.len() as u64);
        }
        res
    });
    state.transfer_metrics.record_success();
    Ok(Body::from_stream(stream))
}
