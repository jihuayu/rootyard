//! Bounded streaming publish and provider read-back receipts.
//!
//! A receipt is issued only after re-reading the object from the provider and
//! hashing it locally: `stat`/ETag/provider checksum values are never accepted
//! as proof of content. Failed uploads attempt an explicit bounded abort and
//! the attempt-unique path is never reused.
//!
//! Each public method is bounded by the caller's absolute deadline as a whole:
//! local source open/metadata, upload-slot queueing, provider writer creation,
//! 64 KiB source reads, writes, close and the post-close read-back all share it.
//! The local source is opened with `O_NOFOLLOW|O_NONBLOCK` and must be a regular
//! file, so a symlink or FIFO can never turn a publish into a hanging read. An
//! open/read/fsync blocked inside the OS cannot be hard-cancelled by Tokio; the
//! deadline stops waiting for it, the write is aborted with its own bounded
//! budget and no receipt is issued.
//!
//! Uploads hold one process-wide upload slot; the slot is returned after
//! close/abort finished and before the post-close read-back, which needs a
//! reader slot instead. Read-back verification holds one reader slot for the
//! whole streamed download.

use std::{
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    time::Instant,
};

use futures_util::TryStreamExt;
use sha2::{Digest, Sha256};
use tokio::{fs::File, io::AsyncReadExt};

use super::{
    BlobError, BlobLocator, BlobReceipt, UploadIntent,
    opendal::{BlobStore, DOWNLOAD_CHUNK_BYTES, DOWNLOAD_CONCURRENCY, map_provider_error},
    upload::UploadGuard,
};

/// S3 multipart requires >=5 MiB parts; 8 MiB keeps every part compliant.
const UPLOAD_CONCURRENCY: usize = 4;

fn tokio_deadline(deadline: Instant) -> tokio::time::Instant {
    tokio::time::Instant::from_std(deadline)
}

/// Open the publish source without following symlinks or blocking on a FIFO,
/// then require a regular file. Returns the handle and its length.
fn open_regular_source(source: &Path) -> Result<(std::fs::File, u64), BlobError> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(source)
        .map_err(|_| BlobError::Provider("local blob source open failed".into()))?;
    let metadata = file.metadata().map_err(|_| BlobError::Provider("local blob source metadata failed".into()))?;
    if !metadata.is_file() {
        return Err(BlobError::Provider("local blob source is not a regular file".into()));
    }
    Ok((file, metadata.len()))
}

impl BlobStore {
    /// Stream a local file into the intent's fresh attempt-unique locator. The
    /// intent is consumed by value, so one attempt can never be published twice
    /// and a caller cannot replay a stored locator. The caller must already know
    /// the SHA-256 and length; a mismatch aborts the provider write and yields
    /// no receipt.
    pub async fn put_file(
        &self,
        intent: UploadIntent,
        source: &Path,
        deadline: Instant,
    ) -> Result<BlobReceipt, BlobError> {
        // Moving the private field is allowed only inside blob_store descendants.
        let UploadIntent { locator } = intent;
        let operation = self.put_file_bounded(&locator, source, deadline);
        match tokio::time::timeout_at(tokio_deadline(deadline), operation).await {
            Ok(result) => result,
            Err(_) => Err(BlobError::DeadlineExceeded),
        }
    }

    async fn put_file_bounded(
        &self,
        locator: &BlobLocator,
        source: &Path,
        deadline: Instant,
    ) -> Result<BlobReceipt, BlobError> {
        self.validate_locator(locator)?;
        let expected = locator.length();
        // Take the upload slot before opening the source: source opens are then
        // bounded by the process-wide upload budget, never an unbounded set of
        // detached blocking tasks. The blocking closure carries the lease back
        // so cancellation still keeps capacity charged until open/metadata ends.
        let upload_lease = self.resources().acquire_upload(deadline).await?;
        let owned_source: PathBuf = source.to_path_buf();
        let opened = tokio::time::timeout_at(
            tokio_deadline(deadline),
            tokio::task::spawn_blocking(move || {
                let opened = open_regular_source(&owned_source);
                (opened, upload_lease)
            }),
        )
        .await;
        let (opened, upload_lease) = match opened {
            Ok(joined) => joined.map_err(|_| BlobError::Provider("local blob source open task failed".into()))?,
            // The blocking task was detached by the timeout and still owns the
            // lease until the syscall returns, so capacity is not reported free.
            Err(_) => return Err(BlobError::DeadlineExceeded),
        };
        let (std_file, actual_length) = opened?;
        if actual_length != expected {
            return Err(BlobError::LengthMismatch { expected, actual: actual_length });
        }
        let path = self.object_path(locator);
        let writer =
            self.operator().writer_with(&path).chunk(super::opendal::UPLOAD_CHUNK_BYTES).concurrent(UPLOAD_CONCURRENCY);
        // Optional SDK defense only; address uniqueness comes from the intent.
        let writer = if self.capabilities().conditional_create { writer.if_not_exists(true) } else { writer };
        let writer = match tokio::time::timeout_at(tokio_deadline(deadline), async { writer.await }).await {
            Ok(Ok(writer)) => writer,
            Ok(Err(error)) => return Err(map_provider_error(error)),
            Err(_) => return Err(BlobError::DeadlineExceeded),
        };
        let mut guard = UploadGuard::new_with_lease(writer, self.profile().abort_timeout(), upload_lease);
        let mut file = File::from_std(std_file);
        let mut buffer = vec![0u8; DOWNLOAD_CHUNK_BYTES];
        let mut hasher = Sha256::new();
        let mut sent = 0u64;
        loop {
            let read = match tokio::time::timeout_at(tokio_deadline(deadline), file.read(&mut buffer)).await {
                Ok(Ok(read)) => read,
                Ok(Err(_)) => {
                    guard.abort_now().await;
                    return Err(BlobError::Provider("local blob source read failed".into()));
                }
                Err(_) => {
                    guard.abort_now().await;
                    return Err(BlobError::DeadlineExceeded);
                }
            };
            if read == 0 {
                break;
            }
            sent = sent.saturating_add(read as u64);
            if sent > expected {
                guard.abort_now().await;
                return Err(BlobError::LengthMismatch { expected, actual: sent });
            }
            hasher.update(&buffer[..read]);
            let chunk = bytes::Bytes::copy_from_slice(&buffer[..read]);
            match tokio::time::timeout_at(tokio_deadline(deadline), guard.writer().write(chunk)).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    let mapped = map_provider_error(error);
                    guard.abort_now().await;
                    return Err(mapped);
                }
                Err(_) => {
                    guard.abort_now().await;
                    return Err(BlobError::DeadlineExceeded);
                }
            }
        }
        let actual_sha256 = hex::encode(hasher.finalize());
        if sent != expected || actual_sha256 != locator.sha256() {
            guard.abort_now().await;
            return Err(if sent != expected {
                BlobError::LengthMismatch { expected, actual: sent }
            } else {
                BlobError::DigestMismatch { expected: locator.sha256().to_owned(), actual: actual_sha256 }
            });
        }
        guard.close(tokio_deadline(deadline)).await?;
        // The raw write is closed: hand the upload slot back *before* the
        // read-back, which needs a verified-reader slot of its own. `disarm`
        // consumes the guard and drops the slot; Drop must not abort.
        guard.disarm();
        self.verify(locator, deadline).await
    }

    /// Provider read-back verification used after publish and to re-present a
    /// receipt minted by another client.
    pub async fn verify(&self, locator: &BlobLocator, deadline: Instant) -> Result<BlobReceipt, BlobError> {
        let operation = self.verify_receipt_bounded(locator, locator.sha256(), locator.length(), deadline);
        match tokio::time::timeout_at(tokio_deadline(deadline), operation).await {
            Ok(result) => result,
            Err(_) => Err(BlobError::DeadlineExceeded),
        }
    }

    pub async fn verify_receipt(
        &self,
        locator: &BlobLocator,
        expected_sha256: &str,
        expected_length: u64,
        deadline: Instant,
    ) -> Result<BlobReceipt, BlobError> {
        let operation = self.verify_receipt_bounded(locator, expected_sha256, expected_length, deadline);
        match tokio::time::timeout_at(tokio_deadline(deadline), operation).await {
            Ok(result) => result,
            Err(_) => Err(BlobError::DeadlineExceeded),
        }
    }

    async fn verify_receipt_bounded(
        &self,
        locator: &BlobLocator,
        expected_sha256: &str,
        expected_length: u64,
        deadline: Instant,
    ) -> Result<BlobReceipt, BlobError> {
        self.validate_locator(locator)?;
        if locator.sha256() != expected_sha256 || locator.length() != expected_length {
            return Err(BlobError::LengthMismatch { expected: locator.length(), actual: expected_length });
        }
        // One reader slot for the whole streamed read-back; verification keeps no
        // staging file, so it leases zero staging bytes.
        let _reader_lease = self.resources().acquire_read(0, deadline).await?;
        let path = self.object_path(locator);
        let metadata = match tokio::time::timeout_at(tokio_deadline(deadline), self.operator().stat(&path)).await {
            Ok(Ok(metadata)) => metadata,
            Ok(Err(error)) => return Err(map_provider_error(error)),
            Err(_) => return Err(BlobError::DeadlineExceeded),
        };
        if metadata.content_length() != expected_length {
            return Err(BlobError::LengthMismatch { expected: expected_length, actual: metadata.content_length() });
        }
        let reader = tokio::time::timeout_at(
            tokio_deadline(deadline),
            self.operator().reader_with(&path).chunk(DOWNLOAD_CHUNK_BYTES).concurrent(DOWNLOAD_CONCURRENCY),
        )
        .await
        .map_err(|_| BlobError::DeadlineExceeded)?
        .map_err(map_provider_error)?;
        let mut stream = match tokio::time::timeout_at(tokio_deadline(deadline), reader.into_bytes_stream(..)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => return Err(map_provider_error(error)),
            Err(_) => return Err(BlobError::DeadlineExceeded),
        };
        let mut hasher = Sha256::new();
        let mut seen = 0u64;
        loop {
            let next = match tokio::time::timeout_at(tokio_deadline(deadline), stream.try_next()).await {
                Ok(Ok(chunk)) => chunk,
                Ok(Err(error)) => return Err(super::opendal::map_stream_error(error)),
                Err(_) => return Err(BlobError::DeadlineExceeded),
            };
            let Some(chunk) = next else { break };
            seen = seen.saturating_add(chunk.len() as u64);
            if seen > expected_length {
                return Err(BlobError::LengthMismatch { expected: expected_length, actual: seen });
            }
            hasher.update(&chunk);
        }
        let actual_sha256 = hex::encode(hasher.finalize());
        if seen != expected_length {
            return Err(BlobError::LengthMismatch { expected: expected_length, actual: seen });
        }
        if actual_sha256 != expected_sha256 {
            return Err(BlobError::DigestMismatch { expected: expected_sha256.to_owned(), actual: actual_sha256 });
        }
        Ok(BlobReceipt::new(locator.clone(), self.provider(), actual_sha256, seen))
    }
}
