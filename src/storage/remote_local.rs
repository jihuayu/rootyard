//! Local filesystem primitives for the legacy `RemoteObjectStore::Local`
//! fixture/development backend.
//!
//! This is an explicitly marked legacy/local mode. It is not a supported
//! production Blob profile and the standalone `BlobStore` never falls back to
//! it: missing or `fs`/`memory` blob configuration is rejected at startup.
//! Semantics preserved here: immutable content key via hard-link create,
//! digest/length verification, bounded streaming and exact-key delete.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncSeekExt},
    time::Instant,
};
use uuid::Uuid;

/// Removes a partially written staging object when dropped.
pub(crate) struct TempObject {
    pub(crate) path: PathBuf,
}

impl Drop for TempObject {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub(crate) async fn hash_file(path: &Path, deadline: Instant) -> Result<(String, u64)> {
    let mut file = File::open(path).await?;
    let mut hash = Sha256::new();
    let mut size = 0u64;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = tokio::time::timeout_at(deadline, file.read(&mut buf)).await??;
        if n == 0 {
            break;
        }
        size = size.checked_add(n as u64).context("object size overflow")?;
        hash.update(&buf[..n]);
    }
    Ok((hex::encode(hash.finalize()), size))
}

pub(crate) async fn local_put(root: &Path, rel_path: &str, source: &Path, deadline: Instant) -> Result<()> {
    let target = root.join(rel_path);
    let parent = target.parent().context("object parent missing")?;
    fs::create_dir_all(parent).await?;
    let temp = parent.join(format!(".tmp-{}", Uuid::new_v4()));
    let result = async {
        let mut input = File::open(source).await?;
        let mut output = fs::OpenOptions::new().write(true).create_new(true).open(&temp).await?;
        tokio::time::timeout_at(deadline, tokio::io::copy(&mut input, &mut output)).await??;
        output.sync_all().await?;
        match fs::hard_link(&temp, &target).await {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                let (digest, _) = hash_file(&target, deadline).await?;
                let expected = rel_path.rsplit('/').next().unwrap_or_default();
                ensure!(digest == expected, "immutable object key collision");
            }
            Err(e) => return Err(e.into()),
        }
        File::open(parent).await?.sync_all().await?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    let _ = fs::remove_file(&temp).await;
    result
}

pub(crate) async fn local_head(root: &Path, rel_path: &str) -> Result<Option<u64>> {
    match fs::metadata(root.join(rel_path)).await {
        Ok(meta) if meta.is_file() => Ok(Some(meta.len())),
        Ok(_) => anyhow::bail!("stored object is not a file"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub(crate) async fn local_file(root: &Path, rel_path: &str) -> Result<File> {
    Ok(File::open(root.join(rel_path)).await?)
}

pub(crate) async fn local_read_range(
    root: &Path,
    rel_path: &str,
    start: u64,
    len: u64,
    deadline: Instant,
) -> Result<Vec<u8>> {
    let mut file = File::open(root.join(rel_path)).await?;
    file.seek(std::io::SeekFrom::Start(start)).await?;
    let mut bytes = vec![0u8; len as usize];
    tokio::time::timeout_at(deadline, file.read_exact(&mut bytes)).await??;
    Ok(bytes)
}

pub(crate) async fn local_delete(root: &Path, rel_path: &str) -> Result<()> {
    match fs::remove_file(root.join(rel_path)).await {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}
