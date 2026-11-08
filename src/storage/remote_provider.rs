//! OpenDAL-backed provider for the **legacy** `RemoteObjectStore` layout.
//!
//! This adapter deliberately preserves the pre-existing content-addressed
//! paths, `anyhow` error surface, full read-back verification, idempotent
//! exact-key delete and deadline semantics of `crate::storage::remote_objects`.
//! It is not the standalone profile: new code must use `crate::blob_store`,
//! whose versioned locators also bind the publication attempt id.
//!
//! Hand-written SigV4 signing, XML multipart handling, retry and HTTP transport
//! are gone; OpenDAL owns those. Credentials are used only to construct the
//! operator and are never stored or debug-printed here.

use std::time::{Duration, Instant};

use opendal::{ErrorKind, Operator, Reader};
use opendal::layers::{ConcurrentLimitLayer, RetryLayer, TimeoutLayer};
use opendal::services::S3;
use reqwest::Url;
use sha2::{Digest, Sha256};
use tokio::{fs::File, io::AsyncReadExt};

use crate::blob_store::{BlobError, MAX_OBJECT_BYTES, opendal::map_provider_error};

const UPLOAD_CHUNK: usize = 4 * 1024 * 1024;
const READ_CHUNK: usize = 64 * 1024;
const CONCURRENCY: usize = 32;
const RETRY_MAX_TIMES: usize = 2;
const OBJECT_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(60);

pub struct LegacyS3Store {
    operator: Operator,
}

impl LegacyS3Store {
    /// Build one shared operator. The caller has already validated the endpoint
    /// origin, TLS exception, bucket and credentials.
    pub fn open(
        endpoint: &Url,
        bucket: &str,
        region: &str,
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
    ) -> Result<Self, BlobError> {
        let mut builder = S3::default();
        builder.bucket(bucket);
        builder.region(region);
        builder.endpoint(endpoint.as_str());
        builder.disable_config_load();
        builder.disable_ec2_metadata();
        builder.access_key_id(&access_key_id);
        builder.secret_access_key(&secret_access_key);
        if let Some(token) = session_token.as_deref() {
            builder.session_token(token);
        }
        let operator = Operator::new(builder)
            .map_err(map_provider_error)?
            .layer(
                TimeoutLayer::new().with_timeout(OBJECT_TIMEOUT).with_io_timeout(IO_TIMEOUT),
            )
            .layer(ConcurrentLimitLayer::new(CONCURRENCY))
            .layer(RetryLayer::new().with_max_times(RETRY_MAX_TIMES))
            .finish();
        let capability = operator.info().capability();
        if !(capability.stat && capability.read && capability.write && capability.delete) {
            return Err(BlobError::Config(
                "legacy object store provider lacks stat/read/write/delete capability".into(),
            ));
        }
        // Required to replace the old stat-then-overwrite path with a native
        // conditional create; without it we refuse to publish rather than fall
        // back to overwriting an immutable content key.
        if !capability.write_with_if_none_match {
            return Err(BlobError::Config(
                "legacy object store provider lacks conditional create (if-none-match)".into(),
            ));
        }
        Ok(Self { operator })
    }

    pub async fn put(
        &self,
        path: &str,
        source: &std::path::Path,
        expected_sha256: &str,
        expected_size: u64,
        deadline: Instant,
    ) -> Result<(), BlobError> {
        if expected_size > MAX_OBJECT_BYTES {
            return Err(BlobError::LengthMismatch { expected: MAX_OBJECT_BYTES, actual: expected_size });
        }
        let writer = self.operator.writer_with(path).chunk(UPLOAD_CHUNK).if_none_match("*");
        let mut writer = match tokio::time::timeout_at(deadline, writer).await {
            Ok(Ok(writer)) => writer,
            Ok(Err(error)) if matches!(error.kind(), ErrorKind::AlreadyExists | ErrorKind::ConditionNotMatch) => {
                return self.verify_content(path, expected_sha256, expected_size, deadline).await
            }
            Ok(Err(error)) => return Err(map_provider_error(error)),
            Err(_) => return Err(BlobError::DeadlineExceeded),
        };
        let mut file = File::open(source)
            .await
            .map_err(|_| BlobError::Provider("legacy object source open failed".into()))?;
        let mut buffer = vec![0u8; READ_CHUNK];
        let mut hasher = Sha256::new();
        let mut sent = 0u64;
        loop {
            let read = match tokio::time::timeout_at(deadline, file.read(&mut buffer)).await {
                Ok(Ok(read)) => read,
                Ok(Err(_)) => return Err(BlobError::Provider("legacy object source read failed".into())),
                Err(_) => return Err(BlobError::DeadlineExceeded),
            };
            if read == 0 {
                break;
            }
            sent = sent.saturating_add(read as u64);
            if sent > expected_size {
                let _ = tokio::time::timeout_at(deadline, writer.abort()).await;
                return Err(BlobError::LengthMismatch { expected: expected_size, actual: sent });
            }
            hasher.update(&buffer[..read]);
            let chunk = bytes::Bytes::copy_from_slice(&buffer[..read]);
            match tokio::time::timeout_at(deadline, writer.write(chunk)).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    let _ = tokio::time::timeout_at(deadline, writer.abort()).await;
                    return Err(map_provider_error(error));
                }
                Err(_) => {
                    let _ = tokio::time::timeout_at(deadline, writer.abort()).await;
                    return Err(BlobError::DeadlineExceeded);
                }
            }
        }
        let actual = hex::encode(hasher.finalize());
        if sent != expected_size || actual != expected_sha256 {
            let _ = tokio::time::timeout_at(deadline, writer.abort()).await;
            return Err(if sent != expected_size {
                BlobError::LengthMismatch { expected: expected_size, actual: sent }
            } else {
                BlobError::DigestMismatch { expected: expected_sha256.to_owned(), actual }
            });
        }
        match tokio::time::timeout_at(deadline, writer.close()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => return Err(map_provider_error(error)),
            Err(_) => return Err(BlobError::DeadlineExceeded),
        }
        self.verify_content(path, expected_sha256, expected_size, deadline).await
    }

    pub async fn verify_content(
        &self,
        path: &str,
        expected_sha256: &str,
        expected_size: u64,
        deadline: Instant,
    ) -> Result<(), BlobError> {
        let mut reader = self.reader(path, deadline).await?;
        let mut hasher = Sha256::new();
        let mut seen = 0u64;
        loop {
            let next = match tokio::time::timeout_at(deadline, reader.next()).await {
                Ok(Some(Ok(chunk))) => Some(chunk),
                Ok(Some(Err(error))) => return Err(map_provider_error(error)),
                Ok(None) => None,
                Err(_) => return Err(BlobError::DeadlineExceeded),
            };
            let Some(chunk) = next else { break };
            seen = seen.saturating_add(chunk.len() as u64);
            if seen > expected_size {
                return Err(BlobError::LengthMismatch { expected: expected_size, actual: seen });
            }
            hasher.update(&*chunk);
        }
        let actual = hex::encode(hasher.finalize());
        if seen != expected_size {
            return Err(BlobError::LengthMismatch { expected: expected_size, actual: seen });
        }
        if actual != expected_sha256 {
            return Err(BlobError::DigestMismatch { expected: expected_sha256.to_owned(), actual });
        }
        Ok(())
    }

    pub async fn head(&self, path: &str, deadline: Instant) -> Result<Option<u64>, BlobError> {
        match tokio::time::timeout_at(deadline, self.operator.stat(path)).await {
            Ok(Ok(metadata)) => Ok(Some(metadata.content_length())),
            Ok(Err(error)) if error.kind() == ErrorKind::NotFound => Ok(None),
            Ok(Err(error)) => Err(map_provider_error(error)),
            Err(_) => Err(BlobError::DeadlineExceeded),
        }
    }

    pub async fn reader(&self, path: &str, deadline: Instant) -> Result<Reader, BlobError> {
        match tokio::time::timeout_at(deadline, self.operator.reader(path)).await {
            Ok(Ok(reader)) => Ok(reader),
            Ok(Err(error)) => Err(map_provider_error(error)),
            Err(_) => Err(BlobError::DeadlineExceeded),
        }
    }

    pub async fn read_range(
        &self,
        path: &str,
        start: u64,
        len: u64,
        deadline: Instant,
    ) -> Result<Vec<u8>, BlobError> {
        let end = start
            .checked_add(len)
            .ok_or(BlobError::LengthMismatch { expected: u64::MAX, actual: len })?;
        let buffer = match tokio::time::timeout_at(deadline, self.operator.read_with(path).range(start..end)).await {
            Ok(Ok(buffer)) => buffer,
            Ok(Err(error)) => return Err(map_provider_error(error)),
            Err(_) => return Err(BlobError::DeadlineExceeded),
        };
        if buffer.len() as u64 != len {
            return Err(BlobError::LengthMismatch { expected: len, actual: buffer.len() as u64 });
        }
        Ok(buffer.to_vec())
    }

    /// Idempotent exact-key delete. There is no listing, prefix or GC sweep.
    pub async fn delete(&self, path: &str, deadline: Instant) -> Result<(), BlobError> {
        match tokio::time::timeout_at(deadline, self.operator.delete(path)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) if error.kind() == ErrorKind::NotFound => Ok(()),
            Ok(Err(error)) => Err(map_provider_error(error)),
            Err(_) => Err(BlobError::DeadlineExceeded),
        }
    }
}
