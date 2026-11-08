//! Bounded streaming publish and provider read-back receipts.
//!
//! A receipt is issued only after re-reading the object from the provider and
//! hashing it locally: `stat`/ETag/provider checksum values are never accepted
//! as proof of content. Failed uploads are aborted (multipart abort included)
//! and the attempt-unique path is never reused.

use std::{path::Path, time::Instant};

use sha2::{Digest, Sha256};
use tokio::{fs::File, io::AsyncReadExt};

use super::{
    BLOB_LOCATOR_SCHEMA, BlobError, BlobLocator, BlobReceipt,
    opendal::{BlobStore, DOWNLOAD_CHUNK_BYTES, bounded, map_provider_error},
};

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

macro_rules! source_read {
    ($deadline:expr, $file:expr, $buf:expr) => {
        match tokio::time::timeout_at($deadline, $file.read($buf)).await {
            Ok(Ok(read)) => read,
            Ok(Err(_)) => return Err(BlobError::Provider("local blob source read failed".into())),
            Err(_) => return Err(BlobError::DeadlineExceeded),
        }
    };
}

impl BlobStore {
    /// Stream a local file into a fresh attempt-unique locator. The caller must
    /// already know the SHA-256 and length; mismatch after upload aborts the
    /// provider write and yields no receipt.
    pub async fn put_file(
        &self,
        locator: &BlobLocator,
        source: &Path,
        deadline: Instant,
    ) -> Result<BlobReceipt, BlobError> {
        self.validate_locator(locator)?;
        let expected = locator.length();
        let metadata = tokio::fs::metadata(source)
            .await
            .map_err(|_| BlobError::Provider("local blob source metadata failed".into()))?;
        if !metadata.is_file() || metadata.len() != expected {
            return Err(BlobError::LengthMismatch { expected, actual: metadata.len() });
        }
        let path = self.object_path(locator);
        let writer = self.operator().writer_with(&path).chunk(super::opendal::UPLOAD_CHUNK_BYTES);
        let writer = if self.capabilities().conditional_create { writer.if_none_match("*") } else { writer };
        let mut writer = bounded!(deadline, async { writer.await });
        let mut file = File::open(source)
            .await
            .map_err(|_| BlobError::Provider("local blob source open failed".into()))?;
        let mut buffer = vec![0u8; DOWNLOAD_CHUNK_BYTES];
        let mut hasher = Sha256::new();
        let mut sent = 0u64;
        loop {
            let read = source_read!(deadline, file, &mut buffer);
            if read == 0 {
                break;
            }
            sent = sent.saturating_add(read as u64);
            if sent > expected {
                let _ = tokio::time::timeout_at(deadline, writer.abort()).await;
                return Err(BlobError::LengthMismatch { expected, actual: sent });
            }
            hasher.update(&buffer[..read]);
            let chunk = bytes::Bytes::copy_from_slice(&buffer[..read]);
            bounded!(deadline, writer.write(chunk));
        }
        let actual_sha256 = hex::encode(hasher.finalize());
        if sent != expected {
            let _ = tokio::time::timeout_at(deadline, writer.abort()).await;
            return Err(BlobError::LengthMismatch { expected, actual: sent });
        }
        if actual_sha256 != locator.sha256() {
            let _ = tokio::time::timeout_at(deadline, writer.abort()).await;
            return Err(BlobError::DigestMismatch { expected: locator.sha256().to_owned(), actual: actual_sha256 });
        }
        bounded!(deadline, writer.close());
        self.verify(locator, deadline).await
    }

    /// Provider read-back verification used both after publish and to validate a
    /// receipt presented by another client.
    pub async fn verify(&self, locator: &BlobLocator, deadline: Instant) -> Result<BlobReceipt, BlobError> {
        self.verify_receipt(locator, locator.sha256(), locator.length(), deadline).await
    }

    pub async fn verify_receipt(
        &self,
        locator: &BlobLocator,
        expected_sha256: &str,
        expected_length: u64,
        deadline: Instant,
    ) -> Result<BlobReceipt, BlobError> {
        self.validate_locator(locator)?;
        if locator.sha256() != expected_sha256 || locator.length() != expected_length {
            return Err(BlobError::DigestMismatch {
                expected: locator.sha256().to_owned(),
                actual: expected_sha256.to_owned(),
            });
        }
        let path = self.object_path(locator);
        let metadata = bounded!(deadline, self.operator().stat(&path));
        if metadata.content_length() != expected_length {
            return Err(BlobError::LengthMismatch {
                expected: expected_length,
                actual: metadata.content_length(),
            });
        }
        let mut reader = bounded!(deadline, self.operator().reader(&path));
        let mut hasher = Sha256::new();
        let mut seen = 0u64;
        while let Some(chunk) = next_chunk!(deadline, reader) {
            seen = seen.saturating_add(chunk.len() as u64);
            if seen > expected_length {
                return Err(BlobError::LengthMismatch { expected: expected_length, actual: seen });
            }
            hasher.update(&*chunk);
        }
        let actual_sha256 = hex::encode(hasher.finalize());
        if seen != expected_length {
            return Err(BlobError::LengthMismatch { expected: expected_length, actual: seen });
        }
        if actual_sha256 != expected_sha256 {
            return Err(BlobError::DigestMismatch { expected: expected_sha256.to_owned(), actual: actual_sha256 });
        }
        Ok(BlobReceipt {
            schema: BLOB_LOCATOR_SCHEMA,
            locator: locator.clone(),
            provider: self.provider(),
            verified_sha256: actual_sha256,
            verified_length: seen,
        })
    }
}
