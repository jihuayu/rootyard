//! Bounded download, range read, head and policy-gated exact delete.
//!
//! Downloads verify SHA-256 and length while streaming into a private temp file
//! and only then atomically rename it into place, so a destination path never
//! holds partial or unverified bytes. `head` returns a length only: the locator
//! digest is *not* proven by `stat`, and an ETag is never treated as SHA-256.
//! There is deliberately no listing API: a provider LIST is not an inventory.

use std::{
    path::{Path, PathBuf},
    time::Instant,
};

use opendal::ErrorKind;
use sha2::{Digest, Sha256};
use tokio::{
    fs::{self, File},
    io::AsyncWriteExt,
};
use uuid::Uuid;

use super::{
    BlobDeletePolicy, BlobError, BlobLocator,
    opendal::{BlobStore, MAX_RANGE_BYTES, bounded, map_provider_error},
};

/// Removes this attempt's staging file if the future is dropped or fails.
struct TempObject(PathBuf);

impl Drop for TempObject {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

macro_rules! next_chunk {
    ($deadline:expr, $reader:expr) => {
        match tokio::time::timeout_at($deadline, $reader.next()).await {
            Ok(Some(Ok(chunk))) => Some(chunk),
            Ok(Some(Err(error))) => return Err(map_provider_error(error)),
            Ok(None) => None,
            Err(_) => return Err(BlobError::DeadlineExceeded),
        }
    };
}

impl BlobStore {
    /// Stream provider bytes into `destination`, verifying digest and length
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
        let guard = TempObject(temp.clone());
        let result = self.stream_to_file(locator, &temp, deadline).await;
        if result.is_err() {
            let _ = fs::remove_file(&temp).await;
            return result;
        }
        fs::rename(&temp, destination)
            .await
            .map_err(|_| BlobError::Provider("blob destination rename failed".into()))?;
        std::mem::forget(guard);
        File::open(parent)
            .await
            .map_err(|_| BlobError::Provider("blob destination fsync failed".into()))?
            .sync_all()
            .await
            .map_err(|_| BlobError::Provider("blob destination fsync failed".into()))?;
        Ok(())
    }

    async fn stream_to_file(&self, locator: &BlobLocator, temp: &Path, deadline: Instant) -> Result<(), BlobError> {
        let path = self.object_path(locator);
        let mut reader = bounded!(deadline, self.operator().reader(&path));
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(temp)
            .await
            .map_err(|_| BlobError::Provider("blob staging file creation failed".into()))?;
        let mut hasher = Sha256::new();
        let mut seen = 0u64;
        while let Some(chunk) = next_chunk!(deadline, reader) {
            seen = seen.saturating_add(chunk.len() as u64);
            if seen > locator.length() {
                return Err(BlobError::LengthMismatch { expected: locator.length(), actual: seen });
            }
            if Instant::now() >= deadline {
                return Err(BlobError::DeadlineExceeded);
            }
            hasher.update(&*chunk);
            output
                .write_all(&chunk)
                .await
                .map_err(|_| BlobError::Provider("blob staging write failed".into()))?;
        }
        if seen != locator.length() {
            return Err(BlobError::LengthMismatch { expected: locator.length(), actual: seen });
        }
        let actual = hex::encode(hasher.finalize());
        if actual != locator.sha256() {
            return Err(BlobError::DigestMismatch { expected: locator.sha256().to_owned(), actual });
        }
        output
            .sync_all()
            .await
            .map_err(|_| BlobError::Provider("blob staging fsync failed".into()))?;
        Ok(())
    }

    /// Bounded range read (at most [`MAX_RANGE_BYTES`]); used by mount readers.
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
        let end = start.checked_add(len).ok_or_else(|| BlobError::RangeExceedsLimit { requested: len, limit: MAX_RANGE_BYTES })?;
        if end > locator.length() {
            return Err(BlobError::LengthMismatch { expected: locator.length(), actual: end });
        }
        let path = self.object_path(locator);
        let buffer = bounded!(deadline, self.operator().read_with(&path).range(start..end));
        if buffer.len() as u64 != len {
            return Err(BlobError::LengthMismatch { expected: len, actual: buffer.len() as u64 });
        }
        Ok(buffer.to_vec())
    }

    /// Length-only existence probe. Never returns or trusts a digest: proving
    /// content requires [`BlobStore::verify`].
    pub async fn head(&self, locator: &BlobLocator, deadline: Instant) -> Result<Option<u64>, BlobError> {
        self.validate_locator(locator)?;
        let path = self.object_path(locator);
        match tokio::time::timeout_at(deadline, self.operator().stat(&path)).await {
            Ok(Ok(metadata)) => Ok(Some(metadata.content_length())),
            Ok(Err(error)) if error.kind() == ErrorKind::NotFound => Ok(None),
            Ok(Err(error)) => Err(map_provider_error(error)),
            Err(_) => Err(BlobError::DeadlineExceeded),
        }
    }

    /// Delete exactly one already-resolved versioned locator. Disabled by
    /// default; no prefix/listing/GC sweep exists. A late delete targets this
    /// attempt path and can never touch a re-uploaded object.
    pub async fn delete(&self, locator: &BlobLocator, deadline: Instant) -> Result<(), BlobError> {
        if self.profile().delete_policy() == BlobDeletePolicy::Disabled {
            return Err(BlobError::DeleteDisabled);
        }
        if !self.capabilities().delete {
            return Err(BlobError::Config("provider does not support delete for this bucket".into()));
        }
        let path = self.object_path(locator);
        match tokio::time::timeout_at(deadline, self.operator().delete(&path)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) if error.kind() == ErrorKind::NotFound => Ok(()),
            Ok(Err(error)) => Err(map_provider_error(error)),
            Err(_) => Err(BlobError::DeadlineExceeded),
        }
    }
}
