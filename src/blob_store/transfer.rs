//! Bounded streaming publish and provider read-back receipts.
//!
//! A receipt is issued only after re-reading the object from the provider and
//! hashing it locally: `stat`/ETag/provider checksum values are never accepted
//! as proof of content. Failed uploads attempt an explicit bounded abort and
//! the attempt-unique path is never reused.
//!
//! The public wait is bounded by the caller's absolute deadline, while local
//! source open and 64 KiB reads run in an owned task. On timeout or caller drop
//! that task is detached, never aborted: it awaits each local operation fully,
//! checks the deadline afterwards, bounded-aborts the writer, and only then lets
//! the upload lease drop. Provider waits keep their own deadlines. The source is
//! opened with `O_NOFOLLOW|O_NONBLOCK` and must be a regular file, so a symlink
//! or FIFO cannot turn a publish into a hanging read. Kernel-blocked IO cannot be
//! hard-cancelled by Tokio, so a late close/abort can leave a committed object or
//! orphan multipart upload; no receipt is issued for late or unknown completion.
//!
//! Uploads hold one process-wide upload slot; the slot is returned after
//! close/abort finished and before the post-close read-back, which needs a
//! reader slot instead. Read-back verification holds one reader slot for the
//! whole streamed download.

#[cfg(test)]
use std::sync::Arc;
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
    budget::UploadLease,
    opendal::{BlobStore, DOWNLOAD_CHUNK_BYTES, DOWNLOAD_CONCURRENCY, map_provider_error},
    upload::UploadGuard,
};

/// S3 multipart requires >=5 MiB parts; 8 MiB keeps every part compliant.
const UPLOAD_CONCURRENCY: usize = 4;

fn tokio_deadline(deadline: Instant) -> tokio::time::Instant {
    tokio::time::Instant::from_std(deadline)
}

fn check_deadline(deadline: Instant) -> Result<(), BlobError> {
    if Instant::now() >= deadline { Err(BlobError::DeadlineExceeded) } else { Ok(()) }
}

/// Test-only deterministic gate in the owned upload task just before the first
/// local source read. It is keyed by the unique source path so parallel tests
/// cannot interfere, and proves an outer timeout detaches the task without
/// freeing the upload slot until the owned task aborts and settles.
#[cfg(test)]
pub(crate) struct UploadReadStall {
    source: PathBuf,
    entered: Arc<tokio::sync::Semaphore>,
    release: Arc<tokio::sync::Semaphore>,
}

#[cfg(test)]
static UPLOAD_READ_STALL: std::sync::OnceLock<std::sync::Mutex<Option<UploadReadStall>>> = std::sync::OnceLock::new();

#[cfg(test)]
pub(crate) fn install_upload_read_stall(source: PathBuf) -> (Arc<tokio::sync::Semaphore>, Arc<tokio::sync::Semaphore>) {
    let entered = Arc::new(tokio::sync::Semaphore::new(0));
    let release = Arc::new(tokio::sync::Semaphore::new(0));
    let stall = UploadReadStall { source, entered: Arc::clone(&entered), release: Arc::clone(&release) };
    let slot = UPLOAD_READ_STALL.get_or_init(|| std::sync::Mutex::new(None));
    *slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(stall);
    (entered, release)
}

#[cfg(test)]
pub(crate) fn clear_upload_read_stall() {
    if let Some(slot) = UPLOAD_READ_STALL.get() {
        *slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }
}

#[cfg(test)]
async fn stall_before_first_read(source: &Path) {
    let stall = {
        let slot = UPLOAD_READ_STALL.get_or_init(|| std::sync::Mutex::new(None));
        let guard = slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        guard
            .as_ref()
            .filter(|stall| stall.source.as_path() == source)
            .map(|stall| (Arc::clone(&stall.entered), Arc::clone(&stall.release)))
    };
    if let Some((entered, release)) = stall {
        entered.add_permits(1);
        let _ = release.acquire().await;
    }
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
        self.validate_locator(&locator)?;
        // Queueing is cancellable and completes before an owned task is spawned.
        let lease = self.resources().acquire_upload(deadline).await?;
        let store = self.clone();
        let source = source.to_path_buf();
        let handle = tokio::spawn(async move { store.put_file_owned(&locator, &source, lease, deadline).await });
        match tokio::time::timeout_at(tokio_deadline(deadline), handle).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(BlobError::Provider("blob upload task failed".into())),
            // Dropping a JoinHandle detaches; it never aborts the owned task.
            Err(_) => Err(BlobError::DeadlineExceeded),
        }
    }

    /// The whole local upload pipeline runs in this owned task. Local open/read
    /// are awaited fully and never timeout-cancelled; after each local call the
    /// absolute deadline is checked and the writer is bounded-aborted before the
    /// upload lease can drop. Provider waits keep their own deadlines.
    async fn put_file_owned(
        &self,
        locator: &BlobLocator,
        source: &Path,
        lease: UploadLease,
        deadline: Instant,
    ) -> Result<BlobReceipt, BlobError> {
        let expected = locator.length();
        let owned_source = source.to_path_buf();
        // Carry the lease through the blocking source open. A detached owner
        // therefore cannot report the upload slot free before the syscall ends.
        let opened = tokio::task::spawn_blocking(move || {
            let opened = open_regular_source(&owned_source);
            (opened, lease)
        })
        .await
        .map_err(|_| BlobError::Provider("local blob source open task failed".into()))?;
        let (opened, lease) = opened;
        let (std_file, actual_length) = opened?;
        if actual_length != expected {
            return Err(BlobError::LengthMismatch { expected, actual: actual_length });
        }
        check_deadline(deadline)?;
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
        let mut guard = UploadGuard::new_with_lease(writer, self.profile().abort_timeout(), lease);
        let mut file = File::from_std(std_file);
        let mut buffer = vec![0u8; DOWNLOAD_CHUNK_BYTES];
        let mut hasher = Sha256::new();
        let mut sent = 0u64;
        #[cfg(test)]
        stall_before_first_read(source).await;
        loop {
            // No timeout around the local read: cancelling a Tokio FS read can
            // leave its inner blocking read alive while capacity is freed.
            let read = match file.read(&mut buffer).await {
                Ok(read) => read,
                Err(_) => {
                    guard.abort_now().await;
                    return Err(BlobError::Provider("local blob source read failed".into()));
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
            if Instant::now() >= deadline {
                guard.abort_now().await;
                return Err(BlobError::DeadlineExceeded);
            }
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
        if Instant::now() >= deadline {
            guard.abort_now().await;
            return Err(BlobError::DeadlineExceeded);
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
        if Instant::now() >= deadline {
            // Close may have committed the object, but a late caller never gets
            // a receipt. The upload slot is released as the guard drops.
            return Err(BlobError::DeadlineExceeded);
        }
        // Hand the upload slot back before read-back, which needs a reader slot.
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
