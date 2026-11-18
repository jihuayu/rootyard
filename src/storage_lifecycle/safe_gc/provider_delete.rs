//! Real Apache OpenDAL S3 provider uploader & version-conditioned fenced deleter (#122).
//!
//! Performs real wire HTTP PUT/HEAD/DELETE operations through OpenDAL and
//! `BlobStore`, captures concrete remote object `(ETag, x-amz-version-id)` at
//! upload, verifies remote `(content_length, ETag, version_id)` pre-delete,
//! issues version-conditioned `DELETE ?versionId=<vid>` + `If-Match: <etag>`
//! (forbidding unconditional deletes), holds `ActiveDeleteFence` continuously,
//! and classifies terminal outcomes into `ConfirmedDeleted`, `AlreadyAbsent`,
//! and `OutcomeUnknown`.

use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::http::{HeaderValue, Method, Request, Response, StatusCode, header};
use opendal::{
    Buffer, Error as SdkError, ErrorKind, Operator, Result as SdkResult,
    layers::{ConcurrentLimitLayer, HttpClientLayer, RetryLayer, TimeoutLayer},
    raw::{HttpBody, HttpClient, HttpFetch},
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

type ArmedDeleteMap = Arc<Mutex<BTreeMap<String, (String, Option<String>)>>>;

struct ConditionalDeleteGuard {
    armed: ArmedDeleteMap,
    rel_path: String,
}

impl Drop for ConditionalDeleteGuard {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.armed.lock() {
            guard.remove(&self.rel_path);
        }
    }
}

/// HTTP transport wrapper enforcing `If-Match` and `?versionId=` on every S3 `DELETE`.
struct ConditionalDeleteFetch {
    inner: HttpClient,
    armed: ArmedDeleteMap,
}

impl HttpFetch for ConditionalDeleteFetch {
    async fn fetch(&self, mut request: Request<Buffer>) -> SdkResult<Response<HttpBody>> {
        if request.method() == Method::DELETE {
            let uri_path = request.uri().path().to_owned();
            let cond = {
                let guard = self.armed.lock().unwrap_or_else(|p| p.into_inner());
                guard.iter().find(|(rel, _)| uri_path.ends_with(rel.as_str())).map(|(_, v)| v.clone())
            };
            let Some((expected_etag, expected_vid)) = cond else {
                return Err(SdkError::new(
                    ErrorKind::ConditionNotMatch,
                    "unconditional S3 DELETE forbidden by Safe GC",
                ));
            };
            if expected_vid.is_some() && !request.uri().query().unwrap_or_default().contains("versionId=") {
                return Err(SdkError::new(
                    ErrorKind::ConditionNotMatch,
                    "S3 DELETE missing required versionId query parameter",
                ));
            }
            let hv = HeaderValue::from_str(&expected_etag).map_err(|_| {
                SdkError::new(ErrorKind::ConditionNotMatch, "invalid ETag header value for conditional DELETE")
            })?;
            request.headers_mut().insert(header::IF_MATCH, hv);
            let resp = self.inner.fetch(request).await?;
            if matches!(resp.status(), StatusCode::PRECONDITION_FAILED | StatusCode::CONFLICT | StatusCode::BAD_REQUEST)
            {
                return Err(SdkError::new(
                    ErrorKind::ConditionNotMatch,
                    format!("S3 conditional DELETE rejected with HTTP {}", resp.status().as_u16()),
                ));
            }
            return Ok(resp);
        }
        self.inner.fetch(request).await
    }
}

#[derive(Clone)]
pub struct OpenDalS3GcProvider {
    store: BlobStore,
    operator: Operator,
    armed_deletes: ArmedDeleteMap,
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
        let armed_deletes: ArmedDeleteMap = Arc::new(Mutex::new(BTreeMap::new()));
        let base_http = HttpClient::new().map_err(|e| SafeGcError::Io(format!("opendal HttpClient init: {e}")))?;
        let cond_http =
            HttpClient::with(ConditionalDeleteFetch { inner: base_http, armed: Arc::clone(&armed_deletes) });
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
            .layer(HttpClientLayer::new(cond_http))
            .finish()
            .layer(TimeoutLayer::new().with_timeout(profile.object_timeout()).with_io_timeout(profile.io_timeout()))
            .layer(ConcurrentLimitLayer::new(profile.concurrency()))
            .layer(RetryLayer::new().with_max_times(profile.retry_max_times()));
        let cap = operator.info().full_capability();
        if !(cap.stat && cap.read && cap.write && cap.delete && cap.delete_with_version) {
            return Err(SafeGcError::InvalidInput(
                "S3 operator lacks stat/read/write/delete_with_version capabilities".into(),
            ));
        }
        Ok(Self { store: store.clone(), operator, armed_deletes })
    }

    fn arm_conditional_delete(
        &self,
        rel_path: &str,
        expected_etag: &str,
        expected_version_id: Option<&str>,
    ) -> ConditionalDeleteGuard {
        let mut guard = self.armed_deletes.lock().unwrap_or_else(|p| p.into_inner());
        guard.insert(rel_path.to_owned(), (expected_etag.to_owned(), expected_version_id.map(str::to_owned)));
        ConditionalDeleteGuard { armed: Arc::clone(&self.armed_deletes), rel_path: rel_path.to_owned() }
    }

    pub async fn upload_pack_file(
        &self,
        tenant_id: Uuid,
        authority_id: Uuid,
        generation: i64,
        namespace: &str,
        source: &Path,
        deadline: std::time::Instant,
    ) -> Result<(BlobLocator, BlobLocatorRecord), SafeGcError> {
        let bytes = tokio::fs::read(source).await.map_err(|e| SafeGcError::Io(e.to_string()))?;
        let sha = hex::encode(Sha256::digest(&bytes));
        let loc =
            BlobLocator::new(tenant_id, authority_id, generation, Uuid::new_v4(), namespace, &sha, bytes.len() as u64)?;
        let rel_path = loc.path();
        let dl = Instant::from_std(deadline);
        tokio::time::timeout_at(dl, self.operator.write(&rel_path, bytes))
            .await
            .map_err(|_| SafeGcError::Io("OpenDAL S3 PUT timed out".into()))?
            .map_err(|e| SafeGcError::Io(format!("OpenDAL S3 PUT failed: {e}")))?;
        let meta = tokio::time::timeout_at(dl, self.operator.stat(&rel_path))
            .await
            .map_err(|_| SafeGcError::Io("OpenDAL S3 post-PUT stat timed out".into()))?
            .map_err(|e| SafeGcError::CompactionVerificationFailed(format!("OpenDAL S3 post-PUT stat failed: {e}")))?;
        if meta.content_length() != loc.length() {
            return Err(SafeGcError::CompactionVerificationFailed(format!(
                "OpenDAL S3 uploaded length {} != expected {}",
                meta.content_length(),
                loc.length()
            )));
        }
        let remote_etag = meta
            .etag()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| SafeGcError::CompactionVerificationFailed("OpenDAL S3 PUT stat missing ETag".into()))?
            .to_owned();
        let remote_version_id = meta.version().filter(|s| !s.is_empty()).map(str::to_owned);
        match self.store.head(&loc, deadline).await? {
            Some(actual) if actual == loc.length() => {}
            _ => {
                return Err(SafeGcError::CompactionVerificationFailed(
                    "BlobStore::head disagreed with OpenDAL S3 stat".into(),
                ));
            }
        }
        let rec = BlobLocatorRecord::from_locator_versioned(&loc, remote_etag, remote_version_id);
        Ok((loc, rec))
    }

    async fn execute_fenced_delete(
        &self,
        fence: &ActiveDeleteFence<'_>,
        ticket: &DeleteAuthorizationTicket,
        deadline: std::time::Instant,
    ) -> Result<ProviderDeleteOutcome, SafeGcError> {
        fence.verify_active_for_ticket(ticket)?;
        let loc_rec = ticket.locator();
        loc_rec.validate_version_binding()?;
        let loc = loc_rec.to_locator()?;
        if loc.generation() != ticket.provider_generation() || loc.sha256() != ticket.object_sha256() {
            return Err(SafeGcError::StaleDeleterFenced("locator generation/digest mismatch"));
        }
        let rel_path = loc.path();
        let dl = Instant::from_std(deadline);

        // 1. Pre-delete provider stat verifying exact (content_length, ETag, x-amz-version-id).
        match tokio::time::timeout_at(dl, self.operator.stat(&rel_path)).await {
            Ok(Err(err)) if err.kind() == ErrorKind::NotFound => {
                fence.verify_active_for_ticket(ticket)?;
                return Ok(ProviderDeleteOutcome::AlreadyAbsent);
            }
            Ok(Ok(meta)) => {
                if meta.content_length() != loc.length()
                    || meta.etag() != Some(loc_rec.remote_etag.as_str())
                    || (loc_rec.remote_version_id.is_some() && meta.version() != loc_rec.remote_version_id.as_deref())
                {
                    return Err(SafeGcError::CompactionVerificationFailed(
                        "remote object version/ETag/length drifted before delete; refusing delete".into(),
                    ));
                }
            }
            Ok(Err(err)) => {
                return Ok(ProviderDeleteOutcome::OutcomeUnknown { reason: format!("pre-delete stat failed: {err}") });
            }
            Err(_) => {
                return Ok(ProviderDeleteOutcome::OutcomeUnknown { reason: "pre-delete stat timed out".into() });
            }
        }

        // 2. Re-verify fence and issue version-conditioned DELETE (?versionId=... + If-Match: <etag>).
        fence.verify_active_for_ticket(ticket)?;
        let _cond_guard =
            self.arm_conditional_delete(&rel_path, &loc_rec.remote_etag, loc_rec.remote_version_id.as_deref());
        let expected_vid = loc_rec.remote_version_id.clone();
        let delete_call = async {
            if let Some(ref vid) = expected_vid {
                self.operator.delete_with(&rel_path).version(vid).await
            } else {
                self.operator.delete(&rel_path).await
            }
        };
        let delete_fut = tokio::time::timeout_at(dl, delete_call);
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
        drop(_cond_guard);

        match delete_res {
            Ok(Ok(())) => {}
            Ok(Err(err)) if err.kind() == ErrorKind::NotFound => {}
            Ok(Err(err)) if err.kind() == ErrorKind::ConditionNotMatch => {
                return Err(SafeGcError::CompactionVerificationFailed(format!(
                    "provider rejected conditional DELETE on versionId/ETag mismatch: {err}"
                )));
            }
            Ok(Err(err)) => {
                return Ok(ProviderDeleteOutcome::OutcomeUnknown {
                    reason: format!("OpenDAL S3 DELETE failed: {err}"),
                });
            }
            Err(_) => {
                return Ok(ProviderDeleteOutcome::OutcomeUnknown { reason: "OpenDAL S3 DELETE timed out".into() });
            }
        }

        // 3. Post-delete stat confirmation + post-delete exact epoch/fence check.
        match tokio::time::timeout_at(dl, self.operator.stat(&rel_path)).await {
            Ok(Err(err)) if err.kind() == ErrorKind::NotFound => {
                fence.verify_active_for_ticket(ticket)?;
                Ok(ProviderDeleteOutcome::ConfirmedDeleted)
            }
            Ok(Ok(meta)) => Ok(ProviderDeleteOutcome::OutcomeUnknown {
                reason: format!("object still visible ({} bytes) after DELETE", meta.content_length()),
            }),
            Ok(Err(err)) => {
                Ok(ProviderDeleteOutcome::OutcomeUnknown { reason: format!("post-delete stat indeterminate: {err}") })
            }
            Err(_) => Ok(ProviderDeleteOutcome::OutcomeUnknown { reason: "post-delete stat timed out".into() }),
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
            let (_, pack_locator) =
                self.upload_pack_file(scope.0, scope.1, scope.2, "packs", paths.0, deadline).await?;
            let (_, idx_locator) = self.upload_pack_file(scope.0, scope.1, scope.2, "packs", paths.1, deadline).await?;
            Ok(UploadedCompactionPair { pack_locator, idx_locator, pack_key: keys.0, idx_key: keys.1 })
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
