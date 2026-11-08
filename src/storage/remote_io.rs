//! Legacy `RemoteObjectStore` read path: head, verified download and range read.
//!
//! Downloads keep the previous contract: stream into a unique staging file,
//! hash and length-check every byte (provider-declared size or ETag is not
//! proof), fsync, then atomically rename. Failures remove only this call's file.
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use futures_util::TryStreamExt;
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncWriteExt},
    time::Instant,
};
use uuid::Uuid;

use crate::storage::{
    remote_errors::RemoteOp,
    remote_local::{TempObject, local_file, local_head, local_read_range},
    remote_objects::{ObjectKey, RemoteObjectStore, StoredObject},
    remote_provider_errors::{deadline_error, object_error, observe_body_poll},
};

const MAX_RANGE_BYTES: u64 = 1024 * 1024;
const READ_CHUNK: usize = 64 * 1024;

impl RemoteObjectStore {
    pub async fn head(&self, key: &ObjectKey, deadline: Instant) -> Result<Option<StoredObject>> {
        let rel_path = key.path();
        let size = match self {
            Self::Local(root) => local_head(root, &rel_path).await?,
            Self::OpenDal(store) => store.head(&rel_path, deadline).await.map_err(object_error)?,
        };
        Ok(size.map(|size| StoredObject { sha256: key.sha256.clone(), size }))
    }

    pub async fn get_to_file(
        &self,
        key: &ObjectKey,
        destination: &Path,
        expected_size: u64,
        deadline: Instant,
    ) -> Result<()> {
        let parent = destination.parent().context("object destination parent missing")?;
        fs::create_dir_all(parent).await?;
        let temp = parent.join(format!(".rootyard-object-{}", Uuid::new_v4()));
        let _temp_guard = TempObject { path: temp.clone() };
        let result = async {
            let mut out = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temp).await?;
            let rel_path = key.path();
            let mut local = match self {
                Self::Local(root) => Some(local_file(root, &rel_path).await?),
                Self::OpenDal(_) => None,
            };
            let mut remote = match self {
                Self::Local(_) => None,
                Self::OpenDal(store) => Some(store.read_stream(&rel_path, deadline).await.map_err(object_error)?),
            };
            let mut buf = [0u8; READ_CHUNK];
            let mut hash = Sha256::new();
            let mut size = 0u64;
            loop {
                let chunk: Option<Bytes> = if let Some(file) = local.as_mut() {
                    let read = tokio::time::timeout_at(deadline, file.read(&mut buf)).await??;
                    if read == 0 { None } else { Some(Bytes::copy_from_slice(&buf[..read])) }
                } else if let Some(stream) = remote.as_mut() {
                    // Each poll opens its own observation scope: the lazy
                    // reader issues its HTTP request while being polled.
                    match tokio::time::timeout_at(deadline, observe_body_poll(RemoteOp::Get, stream.try_next()))
                        .await
                    {
                        Ok(Ok(chunk)) => chunk,
                        Ok(Err(error)) => return Err(object_error(error)),
                        Err(_) => return Err(object_error(deadline_error(RemoteOp::Get))),
                    }
                } else {
                    None
                };
                let Some(chunk) = chunk else { break };
                size = size.checked_add(chunk.len() as u64).context("object size overflow")?;
                ensure!(size <= expected_size, "stored object exceeds expected size");
                hash.update(&chunk);
                out.write_all(&chunk).await?;
            }
            ensure!(
                size == expected_size && hex::encode(hash.finalize()) == key.sha256,
                "stored object digest or size mismatch"
            );
            out.sync_all().await?;
            fs::rename(&temp, destination).await?;
            File::open(parent).await?.sync_all().await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;
        if result.is_err() {
            let _ = fs::remove_file(&temp).await;
        }
        result
    }

    pub async fn get_range(&self, key: &ObjectKey, start: u64, len: u64, deadline: Instant) -> Result<Vec<u8>> {
        ensure!(len <= MAX_RANGE_BYTES && len > 0, "object range exceeds limit");
        let _end = start.checked_add(len - 1).context("object range overflow")?;
        let rel_path = key.path();
        match self {
            Self::Local(root) => local_read_range(root, &rel_path, start, len, deadline).await,
            Self::OpenDal(store) => {
                let bytes = store.read_range(&rel_path, start, len, deadline).await.map_err(object_error)?;
                Ok(bytes)
            }
        }
    }
}
