//! Real Apache OpenDAL driver for the standalone Blob profile.
//!
//! All provider protocol work (signing, TLS, multipart, abort, retry, timeout
//! and concurrency) is delegated to OpenDAL and its layers. This file builds
//! exactly one shared `Operator` per profile; the concurrency bound is a layer
//! on that live operator, never a fresh per-call semaphore. Credentials are
//! moved straight from configuration into the provider builder and are never
//! formatted into errors or logs.

use opendal::{ErrorKind, Operator};
use opendal::layers::{ConcurrentLimitLayer, RetryLayer, TimeoutLayer};
use opendal::services::S3;
#[cfg(feature = "blob-azblob")]
use opendal::services::Azblob;

use super::{
    BlobDeletePolicy, BlobError, BlobLocator, BlobProvider,
    config::{BlobCredentials, BlobProfile},
};

/// Range reads stay small enough to be a bounded in-memory mount read.
pub const MAX_RANGE_BYTES: u64 = 1024 * 1024;
/// Upload window handed to OpenDAL; S3 multipart is decided by OpenDAL itself.
pub(crate) const UPLOAD_CHUNK_BYTES: usize = 4 * 1024 * 1024;
/// Download/hash window so read-back memory is bounded regardless of object size.
pub(crate) const DOWNLOAD_CHUNK_BYTES: usize = 64 * 1024;

/// Capability declaration reported by the provider. This is a startup gate,
/// not proof of behaviour: every publish additionally performs a real
/// provider read-back and contract tests must run against a real service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobCapabilities {
    pub stat: bool,
    pub read: bool,
    pub write: bool,
    pub delete: bool,
    pub conditional_create: bool,
}

pub struct BlobStore {
    profile: BlobProfile,
    operator: Operator,
    capabilities: BlobCapabilities,
}

impl BlobStore {
    /// Build the driver. Missing/unsupported configuration or a provider that
    /// cannot stat/read/write is rejected here, before any startup ACK.
    pub fn open(profile: BlobProfile) -> Result<Self, BlobError> {
        let operator = build_operator(&profile)?;
        let capability = operator.info().capability();
        let capabilities = BlobCapabilities {
            stat: capability.stat,
            read: capability.read,
            write: capability.write,
            delete: capability.delete,
            conditional_create: capability.write_with_if_none_match,
        };
        if !(capabilities.stat && capabilities.read && capabilities.write) {
            return Err(BlobError::Config(format!(
                "provider `{}` does not declare stat/read/write for this bucket",
                profile.provider().as_str()
            )));
        }
        if profile.delete_policy() == BlobDeletePolicy::ExactLocator && !capabilities.delete {
            return Err(BlobError::Config(
                "provider does not declare delete but blob delete policy is exact-locator".into(),
            ));
        }
        Ok(Self { profile, operator, capabilities })
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
    let mut builder = S3::default();
    builder.bucket(profile.bucket());
    builder.root(profile.root());
    // Featureless, deterministic auth: never load ~/.aws or instance metadata.
    builder.disable_config_load();
    builder.disable_ec2_metadata();
    builder.access_key_id(access_key_id);
    builder.secret_access_key(secret_access_key);
    if let Some(region) = profile.region() {
        builder.region(region);
    }
    if let Some(endpoint) = profile.endpoint() {
        builder.endpoint(endpoint.as_str());
    }
    if let Some(token) = session_token.as_deref() {
        builder.session_token(token);
    }
    let builder = Operator::new(builder).map_err(map_provider_error)?;
    Ok(finish_operator!(builder, profile))
}

#[cfg(feature = "blob-azblob")]
fn azblob_operator(profile: &BlobProfile) -> Result<Operator, BlobError> {
    let BlobCredentials::Azblob { account_name, account_key } = profile.credentials() else {
        return Err(BlobError::Config("credential kind does not match the azblob provider".into()));
    };
    let endpoint = profile
        .endpoint()
        .ok_or_else(|| BlobError::Config("azblob needs an explicit endpoint".into()))?;
    let mut builder = Azblob::default();
    builder.container(profile.bucket());
    builder.root(profile.root());
    builder.account_name(account_name);
    builder.account_key(account_key);
    builder.endpoint(endpoint.as_str());
    let builder = Operator::new(builder).map_err(map_provider_error)?;
    Ok(finish_operator!(builder, profile))
}


/// Classify provider failures without ever embedding credentials. Only the
/// error kind/context is surfaced; paths are immutable digests, not secrets.
pub(crate) fn map_provider_error(error: opendal::Error) -> BlobError {
    match error.kind() {
        ErrorKind::NotFound => BlobError::NotFound,
        ErrorKind::AlreadyExists | ErrorKind::ConditionNotMatch => BlobError::AlreadyExists,
        _ => BlobError::Provider(format!("{}: {}", error.kind(), error)),
    }
}

macro_rules! bounded {
    ($deadline:expr, $fut:expr) => {
        match tokio::time::timeout_at($deadline, $fut).await {
            Ok(Ok(value)) => value,
            Ok(Err(error)) => return Err(crate::blob_store::opendal::map_provider_error(error)),
            Err(_) => return Err(crate::blob_store::BlobError::DeadlineExceeded),
        }
    };
}
pub(crate) use bounded;
