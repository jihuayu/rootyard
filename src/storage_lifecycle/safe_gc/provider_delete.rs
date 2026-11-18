//! Real Apache OpenDAL S3 provider uploader & fenced deleter for Safe GC (#122).
//!
//! Performs real wire HTTP PUT/HEAD/DELETE operations through OpenDAL and
//! `BlobStore` (never touching test maps directly), verifies physical backend
//! identity parity, holds `ActiveDeleteFence` across the entire provider call,
//! and classifies provider terminal outcomes into `ConfirmedDeleted`,
//! `AlreadyAbsent`, and `OutcomeUnknown`.

use std::{path::Path, time::Duration};

use opendal::{
    ErrorKind, Operator,
    layers::{ConcurrentLimitLayer, RetryLayer, TimeoutLayer},
    services::S3,
};
use sha2::{Digest, Sha256};
use tokio::time::Instant;
use uuid::Uuid;

use crate::blob_store::{BlobLocator, BlobProvider, config::BlobProfile, opendal::BlobStore};

use super::{
    SafeGcError,
    anti_aba::PhysicalBlobKey,
    domain::{
        ActiveDeleteFence, BlobLocatorRecord, DeleteAuthorizationTicket, ProviderDeleteOutcome, RemotePresence,
        SafeGcCompactionUploader, SafeGcDeleteBackend, SafeGcFuture, UploadedCompactionPair,
    },
};

pub struct S3OperatorCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

#[derive(Clone)]
pub struct OpenDalS3GcProvider {
    store: BlobStore,
    operator: Operator,
}

impl OpenDalS3GcProvider {
    pub fn open_from_env(store: &BlobStore) -> Result<Self, SafeGcError> {
        let profile = BlobProfile::from_env()?;
        let access_key_id = std::env::var("ROOTYARD_BLOB_ACCESS_KEY_ID")
            .map_err(|_| SafeGcError::InvalidInput("missing ROOTYARD_BLOB_ACCESS_KEY_ID".into()))?;
        let secret_access_key = std::env::var("ROOTYARD_BLOB_SECRET_ACCESS_KEY")
            .map_err(|_| SafeGcError::InvalidInput("missing ROOTYARD_BLOB_SECRET_ACCESS_KEY".into()))?;
        let session_token = std::env::var("ROOTYARD_BLOB_SESSION_TOKEN").ok().filter(|s| !s.is_empty());
        Self::open_with_profile(
            store,
            &profile,
            S3OperatorCredentials { access_key_id, secret_access_key, session_token },
        )
    }

    pub fn open_with_profile(
        store: &BlobStore,
        profile: &BlobProfile,
        creds: S3OperatorCredentials,
    ) -> Result<Self, SafeGcError> {
        if profile.provider() != BlobProvider::S3 || store.provider() != BlobProvider::S3 {
            return Err(SafeGcError::InvalidInput("OpenDalS3GcProvider requires an S3 BlobProfile/BlobStore".into()));
        }
        let endpoint = profile
            .endpoint()
            .ok_or_else(|| SafeGcError::InvalidInput("BlobProfile missing remote S3 endpoint".into()))?;
        let region =
            profile.region().ok_or_else(|| SafeGcError::InvalidInput("BlobProfile missing S3 region".into()))?;
        crate::blob_store::opendal::ensure_crypto_provider();
        let mut builder = S3::default()
            .bucket(profile.bucket())
            .region(region)
            .endpoint(endpoint.as_str())
            .disable_config_load()
            .disable_ec2_metadata()
            .access_key_id(&creds.access_key_id)
            .secret_access_key(&creds.secret_access_key);
        if !profile.root().is_empty() {
            builder = builder.root(&format!("/{}", profile.root()));
        }
        if let Some(tok) = creds.session_token.as_deref() {
            builder = builder.session_token(tok);
        }
        let operator = Operator::new(builder)
            .map_err(|e| SafeGcError::Io(format!("opendal s3 init failed: {e}")))?
            .finish()
            .layer(TimeoutLayer::new().with_timeout(profile.object_timeout()).with_io_timeout(profile.io_timeout()))
            .layer(ConcurrentLimitLayer::new(profile.concurrency()))
            .layer(RetryLayer::new().with_max_times(profile.retry_max_times()));
        let cap = operator.info().full_capability();
        if !(cap.stat && cap.read && cap.write && cap.delete) {
            return Err(SafeGcError::InvalidInput("S3 operator lacks stat/read/write/delete capabilities".into()));
        }
        Ok(Self { store: store.clone(), operator })
    }

    pub async fn upload_pack_file(
        &self,
        tenant_id: Uuid,
        authority_id: Uuid,
        generation: i64,
        namespace: &str,
        source: &Path,
        deadline: std::time::Instant,
    ) -> Result<BlobLocator, SafeGcError> {
        let bytes = tokio::fs::read(source).await.map_err(|e| SafeGcError::Io(e.to_string()))?;
        let sha = hex::encode(Sha256::digest(&bytes));
        let loc =
            BlobLocator::new(tenant_id, authority_id, generation, Uuid::new_v4(), namespace, &sha, bytes.len() as u64)?;
        let dl = Instant::from_std(deadline);
        tokio::time::timeout_at(dl, self.operator.write(&loc.path(), bytes))
            .await
            .map_err(|_| SafeGcError::Io("OpenDAL S3 PUT timed out".into()))?
            .map_err(|e| SafeGcError::Io(format!("OpenDAL S3 PUT failed: {e}")))?;
        match self.store.head(&loc, deadline).await? {
            Some(actual) if actual == loc.length() => Ok(loc),
            Some(actual) => Err(SafeGcError::CompactionVerificationFailed(format!(
                "OpenDAL S3 uploaded length {actual} != expected {}",
                loc.length()
            ))),
            None => Err(SafeGcError::CompactionVerificationFailed("OpenDAL S3 PUT missing on immediate HEAD".into())),
        }
    }

    async fn execute_fenced_delete(
        &self,
        fence: &ActiveDeleteFence<'_>,
        ticket: &DeleteAuthorizationTicket,
        deadline: std::time::Instant,
    ) -> Result<ProviderDeleteOutcome, SafeGcError> {
        fence.verify_active_for_ticket(ticket)?;
        let loc = ticket.locator().to_locator()?;
        if loc.generation() != ticket.provider_generation() || loc.sha256() != ticket.object_sha256() {
            return Err(SafeGcError::StaleDeleterFenced("locator generation/digest mismatch"));
        }

        // 1. Pre-delete provider existence check via BlobStore::head.
        match self.store.head(&loc, deadline).await {
            Ok(None) => {
                fence.verify_active_for_ticket(ticket)?;
                return Ok(ProviderDeleteOutcome::AlreadyAbsent);
            }
            Ok(Some(len)) if len != loc.length() => {
                return Err(SafeGcError::CompactionVerificationFailed(format!(
                    "remote object length {len} disagrees with expected {} before delete",
                    loc.length()
                )));
            }
            Ok(Some(_)) => {}
            Err(err) => {
                return Ok(ProviderDeleteOutcome::OutcomeUnknown { reason: format!("pre-delete HEAD failed: {err}") });
            }
        }

        // 2. Re-verify fence immediately before issuing HTTP DELETE, and poll fence continuously while in flight.
        fence.verify_active_for_ticket(ticket)?;
        let rel_path = loc.path();
        let dl = Instant::from_std(deadline);
        let delete_fut = tokio::time::timeout_at(dl, self.operator.delete(&rel_path));
        tokio::pin!(delete_fut);
        let mut watch_tick = tokio::time::interval(Duration::from_millis(20));
        watch_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let _ = watch_tick.tick().await;

        let delete_res = loop {
            tokio::select! {
                res = &mut delete_fut => break res,
                _ = watch_tick.tick() => {
                    if let Err(fence_err) = fence.verify_active_for_ticket(ticket) {
                        return Ok(ProviderDeleteOutcome::OutcomeUnknown {
                            reason: format!("active delete fence lost mid-flight: {fence_err}"),
                        });
                    }
                }
            }
        };

        match delete_res {
            Ok(Ok(())) => {}
            Ok(Err(err)) if err.kind() == ErrorKind::NotFound => {}
            Ok(Err(err)) => {
                return Ok(ProviderDeleteOutcome::OutcomeUnknown {
                    reason: format!("OpenDAL S3 DELETE failed: {err}"),
                });
            }
            Err(_) => {
                return Ok(ProviderDeleteOutcome::OutcomeUnknown { reason: "OpenDAL S3 DELETE timed out".into() });
            }
        }

        // 3. Post-delete provider HEAD confirmation: never assume disappearance without stat proof.
        match self.store.head(&loc, deadline).await {
            Ok(None) => Ok(ProviderDeleteOutcome::ConfirmedDeleted),
            Ok(Some(rem_len)) => Ok(ProviderDeleteOutcome::OutcomeUnknown {
                reason: format!("object still visible ({rem_len} bytes) after DELETE"),
            }),
            Err(err) => {
                Ok(ProviderDeleteOutcome::OutcomeUnknown { reason: format!("post-delete HEAD indeterminate: {err}") })
            }
        }
    }
}

impl SafeGcCompactionUploader for OpenDalS3GcProvider {
    fn upload_compacted_pair<'a>(
        &'a self,
        _store: &'a BlobStore,
        scope: (Uuid, Uuid, i64),
        keys: (PhysicalBlobKey, PhysicalBlobKey),
        paths: (&'a Path, &'a Path),
        deadline: std::time::Instant,
    ) -> SafeGcFuture<'a, UploadedCompactionPair> {
        Box::pin(async move {
            let pk = self.upload_pack_file(scope.0, scope.1, scope.2, "packs", paths.0, deadline).await?;
            let ix = self.upload_pack_file(scope.0, scope.1, scope.2, "packs", paths.1, deadline).await?;
            Ok(UploadedCompactionPair {
                pack_locator: BlobLocatorRecord::from_locator(&pk),
                idx_locator: BlobLocatorRecord::from_locator(&ix),
                pack_key: keys.0,
                idx_key: keys.1,
            })
        })
    }
}

impl SafeGcDeleteBackend for OpenDalS3GcProvider {
    fn delete_authorized<'a>(
        &'a self,
        fence: &'a ActiveDeleteFence<'a>,
        ticket: &'a DeleteAuthorizationTicket,
        deadline: std::time::Instant,
    ) -> SafeGcFuture<'a, ProviderDeleteOutcome> {
        Box::pin(async move { self.execute_fenced_delete(fence, ticket, deadline).await })
    }

    fn probe_presence<'a>(
        &'a self,
        locator: &'a BlobLocatorRecord,
        deadline: std::time::Instant,
    ) -> SafeGcFuture<'a, RemotePresence> {
        Box::pin(async move {
            let loc = locator.to_locator()?;
            match self.store.head(&loc, deadline).await {
                Ok(Some(content_length)) => Ok(RemotePresence::Present { content_length }),
                Ok(None) => Ok(RemotePresence::Absent),
                Err(err) => Ok(RemotePresence::Unknown { reason: err.to_string() }),
            }
        })
    }
}
