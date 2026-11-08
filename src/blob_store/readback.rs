//! Bounded verified download, safe range read, head and policy-gated delete.
//!
//! A length-only ranged GET cannot prove global SHA-256, so v1 range reads do a
//! full bounded download into a private temp file, verify SHA-256 + length, and
//! only then seek the requested slice. This is a cold read: cost is the whole
//! object. Objects above the strict configured ceiling are rejected with
//! `RangeUnsupported` until a chunk-hash manifest/cache proof exists. No listing
//! API exists: provider LIST is not an inventory. `head` proves length only.
//! Deletion is always disabled in this profile.

use std::{
    path::{Path, PathBuf},
    time::Instant,
};

use futures_util::TryStreamExt;
use opendal::ErrorKind;
use sha2::{Digest, Sha256};
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
};
use uuid::Uuid;

use super::{
    BlobError, BlobLocator,
    opendal::{BlobStore, MAX_RANGE_BYTES, map_provider_error},
};

/// Removes this call's private staging file on every exit path.
struct TempObject(PathBuf);

impl Drop for TempObject {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn tokio_deadline(deadline: Instant) -> tokio::time::Instant {
    tokio::time::Instant::from_std(deadline)
}

impl BlobStore {
    /// Stream provider bytes into `destination`, verifying SHA-256 and length
    /// before the atomic rename. Only this call's own staging file is removed.
    pub async fn get_to_file(
        &self,
        locator: &BlobLocator,
        destination: &Path,
        deadline: Instant,
    ) -> Result<(), BlobError> {
        self.validate_locator(locator)?;
        let parent = destination.parent().ok_or_else(|| BlobError::Config("blob destination parent missing".into()))?;
        fs::create_dir_all(parent)
            .await
            .map_err(|_| BlobError::Provider("blob destination directory failed".into()))?;
        let temp = parent.join(format!(".rootyard-blob-{}", Uuid::new_v4()));
        let _guard = TempObject(temp.clone());
        self.stream_verified_to(locator, &temp, deadline).await?;
        fs::rename(&temp, destination)
            .await
            .map_err(|_| BlobError::Provider("blob destination rename failed".into()))?;
        File::open(parent)
            .await
            .map_err(|_| BlobError::Provider("blob destination fsync failed".into()))?
            .sync_all()
            .await
            .map_err(|_| BlobError::Provider("blob destination fsync failed".into()))?;
        Ok(())
    }

    async fn stream_verified_to(&self, locator: &BlobLocator, temp: &Path, deadline: Instant) -> Result<(), BlobError> {
        let path = self.object_path(locator);
        let reader = match tokio::time::timeout_at(tokio_deadline(deadline), self.operator().reader(&path)).await {
            Ok(Ok(reader)) => reader,
            Ok(Err(error)) => return Err(map_provider_error(error)),
            Err(_) => return Err(BlobError::DeadlineExceeded),
        };
        let mut stream = match tokio::time::timeout_at(tokio_deadline(deadline), reader.into_bytes_stream(..)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => return Err(map_provider_error(error)),
            Err(_) => return Err(BlobError::DeadlineExceeded),
        };
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(temp)
            .await
            .map_err(|_| BlobError::Provider("blob staging file creation failed".into()))?;
        let mut hasher = Sha256::new();
        let mut seen = 0u64;
        loop {
            let next = match tokio::time::timeout_at(tokio_deadline(deadline), stream.try_next()).await {
                Ok(Ok(chunk)) => chunk,
                Ok(Err(error)) => return Err(crate::blob_store::opendal::map_stream_error(error)),
                Err(_) => return Err(BlobError::DeadlineExceeded),
            };
            let Some(chunk) = next else { break };
            seen = seen.saturating_add(chunk.len() as u64);
            if seen > locator.length() {
                return Err(BlobError::LengthMismatch { expected: locator.length(), actual: seen });
            }
            if Instant::now() >= deadline {
                return Err(BlobError::DeadlineExceeded);
            }
            hasher.update(&chunk);
            output.write_all(&chunk).await.map_err(|_| BlobError::Provider("blob staging write failed".into()))?;
        }
        if seen != locator.length() {
            return Err(BlobError::LengthMismatch { expected: locator.length(), actual: seen });
        }
        let actual = hex::encode(hasher.finalize());
        if actual != locator.sha256() {
            return Err(BlobError::DigestMismatch { expected: locator.sha256().to_owned(), actual });
        }
        output.sync_all().await.map_err(|_| BlobError::Provider("blob staging fsync failed".into()))?;
        Ok(())
    }

    /// Verified range read: full bounded download + SHA-256/length check, then
    /// seek. Never returns bytes that were not verified as part of a verified
    /// whole object. Cold-read cost is the full object size.
    pub async fn get_range(
        &self,
        locator: &BlobLocator,
        start: u64,
        len: u64,
        deadline: Instant,
    ) -> Result<Vec<u8>, BlobError> {
        self.validate_locator(locator)?;
        if len == 0 || len > MAX_RANGE_BYTES {
            return Err(BlobError::RangeExceedsLimit { requested: len, limit: MAX_RANGE_BYTES });
        }
        let end =
            start.checked_add(len).ok_or(BlobError::RangeExceedsLimit { requested: len, limit: MAX_RANGE_BYTES })?;
        if end > locator.length() {
            return Err(BlobError::LengthMismatch { expected: locator.length(), actual: end });
        }
        let ceiling = self.profile().range_full_get_max_bytes();
        if locator.length() > ceiling {
            return Err(BlobError::RangeUnsupported { length: locator.length(), limit: ceiling });
        }
        let temp = std::env::temp_dir().join(format!(".rootyard-range-{}", Uuid::new_v4()));
        let _guard = TempObject(temp.clone());
        self.stream_verified_to(locator, &temp, deadline).await?;
        let mut file =
            File::open(&temp).await.map_err(|_| BlobError::Provider("blob range staging open failed".into()))?;
        file.seek(std::io::SeekFrom::Start(start))
            .await
            .map_err(|_| BlobError::Provider("blob range seek failed".into()))?;
        let mut bytes = vec![0u8; len as usize];
        tokio::time::timeout_at(tokio_deadline(deadline), file.read_exact(&mut bytes))
            .await
            .map_err(|_| BlobError::DeadlineExceeded)?
            .map_err(|_| BlobError::Provider("blob range read failed".into()))?;
        Ok(bytes)
    }

    /// Length-only existence probe. Never returns or trusts a digest.
    pub async fn head(&self, locator: &BlobLocator, deadline: Instant) -> Result<Option<u64>, BlobError> {
        self.validate_locator(locator)?;
        let path = self.object_path(locator);
        match tokio::time::timeout_at(tokio_deadline(deadline), self.operator().stat(&path)).await {
            Ok(Ok(metadata)) => Ok(Some(metadata.content_length())),
            Ok(Err(error)) if error.kind() == ErrorKind::NotFound => Ok(None),
            Ok(Err(error)) => Err(map_provider_error(error)),
            Err(_) => Err(BlobError::DeadlineExceeded),
        }
    }

    /// Always disabled in the new profile. Persistent hold/root retirement
    /// claims (#113/#114) are not implemented, so no env flag may enable it.
    pub async fn delete(&self, _locator: &BlobLocator, _deadline: Instant) -> Result<(), BlobError> {
        Err(BlobError::DeleteDisabled)
    }
}
