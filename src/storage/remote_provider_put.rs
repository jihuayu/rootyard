//! Legacy publish path: bounded streaming upload, explicit abort attempts and
//! full provider read-back verification. Split from `remote_provider.rs` only
//! to keep each reviewable unit small.

use tokio::time::Instant;

use futures_util::TryStreamExt;
use sha2::{Digest, Sha256};
use tokio::{fs::File, io::AsyncReadExt};

use crate::blob_store::BlobError;
use crate::storage::remote_errors::RemoteOp;
use crate::storage::remote_provider::{LegacyS3Store, READ_CHUNK, UPLOAD_CHUNK, UPLOAD_CONCURRENCY, tokio_deadline};
use crate::storage::remote_provider_errors::{
    deadline_error, observe, observe_body_poll,
};

impl LegacyS3Store {
    pub async fn put(
        &self,
        path: &str,
        source: &std::path::Path,
        expected_sha256: &str,
        expected_size: u64,
        deadline: Instant,
    ) -> Result<(), BlobError> {
        Self::verify_ceiling(expected_size)?;
        let writer =
            self.operator().writer_with(path).chunk(UPLOAD_CHUNK).concurrent(UPLOAD_CONCURRENCY).if_not_exists(true);
        let writer = match tokio::time::timeout_at(tokio_deadline(deadline), observe(RemoteOp::Put, writer)).await {
            Ok(Ok(writer)) => writer,
            // Conditional-create conflict: immutable content keys stay
            // idempotent only through an independent full verification.
            Ok(Err(failure)) if failure.is_conflict() => {
                return self.verify_content(path, expected_sha256, expected_size, deadline).await;
            }
            Ok(Err(failure)) => return Err(BlobError::Remote(failure.into_error())),
            Err(_) => return Err(deadline_error(RemoteOp::Put)),
        };
        let mut guard = self.upload_guard(writer);
        let mut file =
            File::open(source).await.map_err(|_| BlobError::Provider("legacy object source open failed".into()))?;
        let mut buffer = vec![0u8; READ_CHUNK];
        let mut hasher = Sha256::new();
        let mut sent = 0u64;
        loop {
            let read = match tokio::time::timeout_at(tokio_deadline(deadline), file.read(&mut buffer)).await {
                Ok(Ok(read)) => read,
                Ok(Err(_)) => {
                    guard.abort_now().await;
                    return Err(BlobError::Provider("legacy object source read failed".into()));
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
            if sent > expected_size {
                guard.abort_now().await;
                return Err(BlobError::LengthMismatch { expected: expected_size, actual: sent });
            }
            hasher.update(&buffer[..read]);
            let chunk = bytes::Bytes::copy_from_slice(&buffer[..read]);
            match tokio::time::timeout_at(tokio_deadline(deadline), observe(RemoteOp::Put, guard.writer().write(chunk)))
                .await
            {
                Ok(Ok(())) => {}
                Ok(Err(failure)) => {
                    let mapped = BlobError::Remote(failure.into_error());
                    guard.abort_now().await;
                    return Err(mapped);
                }
                Err(_) => {
                    guard.abort_now().await;
                    return Err(deadline_error(RemoteOp::Put));
                }
            }
        }
        let actual = hex::encode(hasher.finalize());
        if sent != expected_size || actual != expected_sha256 {
            guard.abort_now().await;
            return Err(if sent != expected_size {
                BlobError::LengthMismatch { expected: expected_size, actual: sent }
            } else {
                BlobError::DigestMismatch { expected: expected_sha256.to_owned(), actual }
            });
        }
        match guard.close(tokio_deadline(deadline)).await {
            Ok(()) => {},
            Err(BlobError::AlreadyExists) => {
                // Conditional PUT conflicts can arrive only at multipart
                // completion. Legacy content-addressed retries remain
                // idempotent only after an independent full verification.
                return self.verify_content(path, expected_sha256, expected_size, deadline).await;
            },
            Err(error) => return Err(error),
        }
        guard.disarm();
        self.verify_content(path, expected_sha256, expected_size, deadline).await
    }

    pub async fn verify_content(
        &self,
        path: &str,
        expected_sha256: &str,
        expected_size: u64,
        deadline: Instant,
    ) -> Result<(), BlobError> {
        let mut stream = self.read_stream(path, deadline).await?;
        let mut hasher = Sha256::new();
        let mut seen = 0u64;
        loop {
            // Each poll opens its own observation scope: the lazy reader issues
            // its HTTP request while the stream is polled, not at construction.
            let next = match tokio::time::timeout_at(
                tokio_deadline(deadline),
                observe_body_poll(RemoteOp::Get, stream.try_next()),
            )
            .await
            {
                Ok(Ok(chunk)) => chunk,
                Ok(Err(error)) => return Err(error),
                Err(_) => return Err(deadline_error(RemoteOp::Get)),
            };
            let Some(chunk) = next else { break };
            seen = seen.saturating_add(chunk.len() as u64);
            if seen > expected_size {
                return Err(BlobError::LengthMismatch { expected: expected_size, actual: seen });
            }
            hasher.update(&chunk);
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
}
