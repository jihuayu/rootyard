//! Real Apache OpenDAL driver for the standalone Blob profile.
//!
//! All provider protocol work (signing, TLS, multipart, abort, retry, timeout
//! and concurrency) is delegated to OpenDAL and its layers. This file builds
//! exactly one shared `Operator` per profile; the concurrency bound is a layer
//! on that live operator, never a fresh per-call semaphore. Credentials are
//! moved straight from configuration into the provider builder and are never
//! formatted into errors or logs.

use opendal::layers::{ConcurrentLimitLayer, RetryLayer, TimeoutLayer};
#[cfg(feature = "blob-azblob")]
use opendal::services::Azblob;
use opendal::services::S3;
use opendal::{ErrorKind, Operator};

use std::sync::Arc;

use uuid::Uuid;

use super::{
    BlobError, BlobLocator, BlobProvider, UploadIntent,
    budget::{self, ResourceContext},
    config::{BlobCredentials, BlobProfile},
};

/// Range reads stay small enough to be a bounded in-memory mount read.
pub const MAX_RANGE_BYTES: u64 = 1024 * 1024;
/// Upload window handed to OpenDAL; S3 multipart is decided by OpenDAL itself.
pub(crate) const UPLOAD_CHUNK_BYTES: usize = 8 * 1024 * 1024;
/// Download/hash window so read-back memory is bounded regardless of object size.
pub(crate) const DOWNLOAD_CHUNK_BYTES: usize = 64 * 1024;
/// One in-flight SDK read window per verified reader. The number of concurrent
/// verified downloads is bounded by the process-wide reader budget instead, so a
/// reader never multiplies its own staging/queue pressure behind our back.
pub(crate) const DOWNLOAD_CONCURRENCY: usize = 1;

/// Capability declaration reported by the provider. stat/read/write are a
/// startup gate, not proof of behaviour: every publish additionally performs a
/// real provider read-back and contract tests must run against a real service.
/// conditional_create is only an optional SDK defense hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobCapabilities {
    pub stat: bool,
    pub read: bool,
    pub write: bool,
    pub delete: bool,
    /// SDK-declared `write_with_if_not_exists` support. This is optional
    /// defense-in-depth only, never a provider guarantee and never a startup
    /// requirement: a fresh one-use attempt address is the fundamental
    /// publication contract. A true value does not prove conditional rejection
    /// end-to-end (multipart probes have shown it can be declared without
    /// being enforced).
    pub conditional_create: bool,
}

#[derive(Clone)]
pub struct BlobStore {
    profile: BlobProfile,
    operator: Operator,
    capabilities: BlobCapabilities,
    /// The one process-wide upload/reader/staging budget this store charges.
    resources: Arc<ResourceContext>,
}

impl BlobStore {
    /// Build the driver. Missing/unsupported configuration or a provider that
    /// cannot stat/read/write is rejected here, before any startup ACK.
    ///
    /// This registers (or joins) the single process-wide resource context. A
    /// second profile with different capacities is rejected with
    /// [`BlobError::CapacityConflict`] rather than silently reusing the first.
    pub fn open(profile: BlobProfile) -> Result<Self, BlobError> {
        let resources = budget::process_resources(profile.resource_limits())?;
        Self::open_with_resources(profile, resources)
    }

    /// Build the driver against an explicit context. Used by tests with private
    /// budgets and by [`BlobStore::open`] with the process-wide one.
    pub(crate) fn open_with_resources(
        profile: BlobProfile,
        resources: Arc<ResourceContext>,
    ) -> Result<Self, BlobError> {
        ensure_crypto_provider();
        let operator = build_operator(&profile)?;
        let capability = operator.info().full_capability();
        let capabilities = BlobCapabilities {
            stat: capability.stat,
            read: capability.read,
            write: capability.write,
            delete: capability.delete,
            conditional_create: capability.write_with_if_not_exists,
        };
        if !(capabilities.stat && capabilities.read && capabilities.write) {
            return Err(BlobError::Config(format!(
                "provider `{}` does not declare stat/read/write for this bucket",
                profile.provider().as_str()
            )));
        }
        Ok(Self { profile, operator, capabilities, resources })
    }

    /// Build a store over the in-process `memory` service for IO lifecycle unit
    /// tests only. Production start-up never takes this path: the strict profile
    /// rejects `memory` by name and this function is compiled under `cfg(test)`.
    #[cfg(test)]
    pub(crate) fn open_memory(profile: BlobProfile, resources: Arc<ResourceContext>) -> Self {
        let operator = Operator::new(opendal::services::Memory::default().root("/"))
            .expect("in-memory test operator")
            .finish();
        let capability = operator.info().full_capability();
        let capabilities = BlobCapabilities {
            stat: capability.stat,
            read: capability.read,
            write: capability.write,
            delete: capability.delete,
            conditional_create: capability.write_with_if_not_exists,
        };
        assert!(capabilities.stat && capabilities.read && capabilities.write);
        Self { profile, operator, capabilities, resources }
    }

    pub fn resources(&self) -> &Arc<ResourceContext> {
        &self.resources
    }

    pub fn capabilities(&self) -> BlobCapabilities {
        self.capabilities
    }

    pub fn profile(&self) -> &BlobProfile {
        &self.profile
    }

    pub fn provider(&self) -> BlobProvider {
        self.profile.provider()
    }

    pub(crate) fn operator(&self) -> &Operator {
        &self.operator
    }

    pub(crate) fn object_path(&self, locator: &BlobLocator) -> String {
        self.profile.object_path(locator)
    }

    /// Mint a fresh single-use publication intent. The random attempt id is
    /// generated here, never supplied by the caller and never derived from
    /// stored metadata. A reader locator cannot be converted into an intent,
    /// so a restart cannot reconstruct write authority.
    pub fn new_upload(
        &self,
        tenant_id: Uuid,
        authority_id: Uuid,
        generation: i64,
        namespace: &str,
        sha256: &str,
        length: u64,
    ) -> Result<UploadIntent, BlobError> {
        let locator = BlobLocator::new(
            tenant_id,
            authority_id,
            generation,
            Uuid::new_v4(),
            namespace,
            sha256,
            length,
        )?;
        self.validate_locator(&locator)?;
        Ok(UploadIntent::new(locator))
    }

    /// Reject a locator whose digest/length pair exceeds the configured ceiling
    /// before any provider request is made.
    pub(crate) fn validate_locator(&self, locator: &BlobLocator) -> Result<(), BlobError> {
        if locator.length() > self.profile.max_object_bytes() {
            return Err(BlobError::LengthMismatch {
                expected: self.profile.max_object_bytes(),
                actual: locator.length(),
            });
        }
        Ok(())
    }
}

/// Apply the shared mature layers to the one operator built for this profile.
/// The `OperatorBuilder` type is intentionally not named here.
macro_rules! finish_operator {
    ($builder:expr, $profile:expr) => {
        $builder
            .layer(TimeoutLayer::new().with_timeout($profile.object_timeout()).with_io_timeout($profile.io_timeout()))
            .layer(ConcurrentLimitLayer::new($profile.concurrency()))
            .layer(RetryLayer::new().with_max_times($profile.retry_max_times()))
            .finish()
    };
}

fn build_operator(profile: &BlobProfile) -> Result<Operator, BlobError> {
    match profile.provider() {
        BlobProvider::S3 => s3_operator(profile),
        #[cfg(feature = "blob-azblob")]
        BlobProvider::Azblob => azblob_operator(profile),
        #[cfg(not(feature = "blob-azblob"))]
        BlobProvider::Azblob => {
            Err(BlobError::Config("azblob provider was not compiled in (feature `blob-azblob`)".into()))
        }
    }
}

fn s3_operator(profile: &BlobProfile) -> Result<Operator, BlobError> {
    let BlobCredentials::S3 { access_key_id, secret_access_key, session_token } = profile.credentials() else {
        return Err(BlobError::Config("credential kind does not match the s3 provider".into()));
    };
    // Setters consume the builder in 0.57, so chain/reassign explicitly.
    let mut builder = S3::default()
        .bucket(profile.bucket())
        .root(profile.root())
        .disable_config_load()
        .disable_ec2_metadata()
        .access_key_id(access_key_id)
        .secret_access_key(secret_access_key);
    if let Some(region) = profile.region() {
        builder = builder.region(region);
    }
    if let Some(endpoint) = profile.endpoint() {
        builder = builder.endpoint(endpoint.as_str());
    }
    if let Some(token) = session_token.as_deref() {
        builder = builder.session_token(token);
    }
    let builder = Operator::new(builder).map_err(map_provider_error)?;
    Ok(finish_operator!(builder, profile))
}

#[cfg(feature = "blob-azblob")]
fn azblob_operator(profile: &BlobProfile) -> Result<Operator, BlobError> {
    let BlobCredentials::Azblob { account_name, account_key } = profile.credentials() else {
        return Err(BlobError::Config("credential kind does not match the azblob provider".into()));
    };
    let endpoint = profile.endpoint().ok_or_else(|| BlobError::Config("azblob needs an explicit endpoint".into()))?;
    let builder = Azblob::default()
        .container(profile.bucket())
        .root(profile.root())
        .account_name(account_name)
        .account_key(account_key)
        .endpoint(endpoint.as_str());
    let builder = Operator::new(builder).map_err(map_provider_error)?;
    Ok(finish_operator!(builder, profile))
}

/// Classify provider failures by stable kind only. The full OpenDAL error
/// Display/context can contain request URLs or key material, so it is never
/// formatted into a returned error, log line or debug output.
pub(crate) fn map_provider_error(error: opendal::Error) -> BlobError {
    match error.kind() {
        ErrorKind::NotFound => BlobError::NotFound,
        ErrorKind::AlreadyExists | ErrorKind::ConditionNotMatch => BlobError::AlreadyExists,
        other => BlobError::Provider(format!("provider error kind {other}")),
    }
}

pub(crate) fn ensure_crypto_provider() {
    // Reqwest 0.13's no-provider feature requires explicit installation, even
    // when Ring is the only compiled implementation. Respect an application's
    // existing choice; concurrent first-time installs are harmless.
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }
}

pub(crate) fn map_stream_error(error: std::io::Error) -> BlobError {
    BlobError::Provider(format!("provider byte stream error kind {:?}", error.kind()))
}
