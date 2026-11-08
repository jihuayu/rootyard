//! OpenDAL-backed provider for the **legacy** `RemoteObjectStore` layout.
//!
//! This adapter preserves the pre-existing content-addressed paths, `anyhow`
//! error surface, full read-back verification, idempotent exact-key delete and
//! deadline semantics. It is not the standalone profile. Hand-written SigV4,
//! XML multipart handling, retry and HTTP transport are gone; OpenDAL owns
//! them. Credentials are used only to construct the operator and are never
//! stored or debug-printed here.

use std::time::Duration;
use tokio::time::Instant;

use opendal::layers::{ConcurrentLimitLayer, RetryLayer, TimeoutLayer};
use opendal::services::S3;
use opendal::{ErrorKind, FuturesBytesStream, Operator};
use reqwest::Url;

use crate::blob_store::{BlobError, MAX_OBJECT_BYTES, opendal::map_provider_error, upload::UploadGuard};

pub(crate) const READ_CHUNK: usize = 64 * 1024;
/// S3 multipart requires >=5 MiB parts; 8 MiB keeps every part compliant.
pub(crate) const UPLOAD_CHUNK: usize = 8 * 1024 * 1024;
pub(crate) const UPLOAD_CONCURRENCY: usize = 4;
const CONCURRENCY: usize = 32;
const RETRY_MAX_TIMES: usize = 2;
const OBJECT_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(60);
pub(crate) const ABORT_TIMEOUT: Duration = Duration::from_secs(5);

pub struct LegacyS3Store {
    operator: Operator,
}

pub(crate) fn tokio_deadline(deadline: Instant) -> tokio::time::Instant {
    deadline
}

impl LegacyS3Store {
    /// Build one shared operator. The caller already validated the endpoint
    /// origin, TLS exception, bucket and credentials.
    pub fn open(
        endpoint: &Url,
        bucket: &str,
        region: &str,
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
    ) -> Result<Self, BlobError> {
        crate::blob_store::opendal::ensure_crypto_provider();
        let mut builder = S3::default()
            .bucket(bucket)
            .region(region)
            .endpoint(endpoint.as_str())
            .disable_config_load()
            .disable_ec2_metadata()
            .access_key_id(&access_key_id)
            .secret_access_key(&secret_access_key);
        if let Some(token) = session_token.as_deref() {
            builder = builder.session_token(token);
        }
        let operator = Operator::new(builder)
            .map_err(map_provider_error)?
            .layer(TimeoutLayer::new().with_timeout(OBJECT_TIMEOUT).with_io_timeout(IO_TIMEOUT))
            .layer(ConcurrentLimitLayer::new(CONCURRENCY))
            .layer(RetryLayer::new().with_max_times(RETRY_MAX_TIMES))
            .finish();
        let capability = operator.info().full_capability();
        if !(capability.stat && capability.read && capability.write && capability.delete) {
            return Err(BlobError::Config(
                "legacy object store provider lacks stat/read/write/delete capability".into(),
            ));
        }
        if !capability.write_with_if_none_match {
            return Err(BlobError::Config(
                "legacy object store provider lacks conditional create (if-none-match)".into(),
            ));
        }
        Ok(Self { operator })
    }

    pub(crate) fn operator(&self) -> &Operator {
        &self.operator
    }

    pub(crate) fn upload_guard(&self, writer: opendal::Writer) -> UploadGuard {
        UploadGuard::new(writer, ABORT_TIMEOUT)
    }

    pub async fn head(&self, path: &str, deadline: Instant) -> Result<Option<u64>, BlobError> {
        match tokio::time::timeout_at(tokio_deadline(deadline), self.operator.stat(path)).await {
            Ok(Ok(metadata)) => Ok(Some(metadata.content_length())),
            Ok(Err(error)) if error.kind() == ErrorKind::NotFound => Ok(None),
            Ok(Err(error)) => Err(map_provider_error(error)),
            Err(_) => Err(BlobError::DeadlineExceeded),
        }
    }

    /// Bounded byte stream over the whole object. Callers hash every chunk and
    /// enforce the expected length; `stat`/ETag are never trusted as content.
    pub async fn read_stream(&self, path: &str, deadline: Instant) -> Result<FuturesBytesStream, BlobError> {
        let reader = match tokio::time::timeout_at(tokio_deadline(deadline), self.operator.reader(path)).await {
            Ok(Ok(reader)) => reader,
            Ok(Err(error)) => return Err(map_provider_error(error)),
            Err(_) => return Err(BlobError::DeadlineExceeded),
        };
        match tokio::time::timeout_at(tokio_deadline(deadline), reader.into_bytes_stream(..)).await {
            Ok(Ok(stream)) => Ok(stream),
            Ok(Err(error)) => Err(map_provider_error(error)),
            Err(_) => Err(BlobError::DeadlineExceeded),
        }
    }

    /// Legacy helper only: an exact bounded provider range. The standalone
    /// profile never treats a ranged response as digest verification.
    pub async fn read_range(&self, path: &str, start: u64, len: u64, deadline: Instant) -> Result<Vec<u8>, BlobError> {
        let end = start.checked_add(len).ok_or(BlobError::LengthMismatch { expected: u64::MAX, actual: len })?;
        let buffer =
            match tokio::time::timeout_at(tokio_deadline(deadline), self.operator.read_with(path).range(start..end))
                .await
            {
                Ok(Ok(buffer)) => buffer,
                Ok(Err(error)) => return Err(map_provider_error(error)),
                Err(_) => return Err(BlobError::DeadlineExceeded),
            };
        if buffer.len() as u64 != len {
            return Err(BlobError::LengthMismatch { expected: len, actual: buffer.len() as u64 });
        }
        Ok(buffer.to_vec())
    }

    /// Idempotent exact-key delete. No listing, prefix or GC sweep exists here.
    pub async fn delete(&self, path: &str, deadline: Instant) -> Result<(), BlobError> {
        match tokio::time::timeout_at(tokio_deadline(deadline), self.operator.delete(path)).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) if error.kind() == ErrorKind::NotFound => Ok(()),
            Ok(Err(error)) => Err(map_provider_error(error)),
            Err(_) => Err(BlobError::DeadlineExceeded),
        }
    }

    pub(crate) fn verify_ceiling(size: u64) -> Result<(), BlobError> {
        if size > MAX_OBJECT_BYTES {
            return Err(BlobError::LengthMismatch { expected: MAX_OBJECT_BYTES, actual: size });
        }
        Ok(())
    }
}
