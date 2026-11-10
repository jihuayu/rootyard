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
    BlobBackendIdentity, BlobError, BlobLocator, BlobProvider, UploadIntent,
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
    /// Immutable physical identity of the profile whose operator was opened.
    /// Cloned into every intent and receipt minted by this store; it is derived
    /// from the actual store mapping, never from a caller's logical scope.
    backend_identity: BlobBackendIdentity,
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
        // Derived from the profile whose operator was actually built above, so
        // the identity describes the store this handle will really talk to.
        let backend_identity = BlobBackendIdentity::from_profile(&profile);
        Ok(Self { profile, operator, capabilities, resources, backend_identity })
    }

    /// Build a store over the in-process `memory` service for IO lifecycle unit
    /// tests only. Production start-up never takes this path: the strict profile
    /// rejects `memory` by name and this function is compiled under `cfg(test)`.
    #[cfg(test)]
    pub(crate) fn open_memory(profile: BlobProfile, resources: Arc<ResourceContext>) -> Self {
        ensure_crypto_provider();
        let operator =
            Operator::new(opendal::services::Memory::default().root("/")).expect("in-memory test operator").finish();
        let capability = operator.info().full_capability();
        let capabilities = BlobCapabilities {
            stat: capability.stat,
            read: capability.read,
            write: capability.write,
            delete: capability.delete,
            conditional_create: capability.write_with_if_not_exists,
        };
        assert!(capabilities.stat && capabilities.read && capabilities.write);
        // A memory operator is not an S3/Azure realm. Give it its own fresh
        // realm identity instead of pretending the synthetic profile's mapping.
        let backend_identity = BlobBackendIdentity::memory_test_realm();
        Self { profile, operator, capabilities, resources, backend_identity }
    }

    pub fn resources(&self) -> &Arc<ResourceContext> {
        &self.resources
    }

    pub fn capabilities(&self) -> BlobCapabilities {
        self.capabilities
    }

    pub(super) fn profile(&self) -> &BlobProfile {
        &self.profile
    }

    pub fn provider(&self) -> BlobProvider {
        self.profile.provider()
    }

    /// Immutable physical backend identity of this opened store. Read-only
    /// data: it is not a write capability and cannot be built from stored hex.
    pub fn backend_identity(&self) -> &BlobBackendIdentity {
        &self.backend_identity
    }

    /// Raw operator access is sealed to the `blob_store` subtree. This is the
    /// only place a provider handle exists; no sibling subtree or service path
    /// can name it.
    pub(super) fn operator(&self) -> &Operator {
        &self.operator
    }

    /// Provider object path is sealed for the same reason as `operator`.
    pub(super) fn object_path(&self, locator: &BlobLocator) -> String {
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
        let locator = BlobLocator::new(tenant_id, authority_id, generation, Uuid::new_v4(), namespace, sha256, length)?;
        self.validate_locator(&locator)?;
        // The caller supplies the logical authority scope only; the physical
        // backend is always this opened store's own identity.
        Ok(UploadIntent::new(locator, self.backend_identity.clone()))
    }

    /// Sealed exact-locator intent for the offline same-coordinate restore.
    ///
    /// The normal [`Self::new_upload`] always mints a fresh random attempt and
    /// remains the only producer surface. This constructor accepts an already
    /// validated read-only [`BlobLocator`] (original tenant, authority,
    /// generation, attempt id, namespace, digest and length) and is reachable
    /// only from `blob_store::archive`, which requires the backup's opaque
    /// [`crate::backup::OfflineRestorePermit`]. It grants no authority on its
    /// own: the caller must already have held a restore permit, and the sealed
    /// writer still enforces this store's physical backend identity before any
    /// provider IO.
    pub(super) fn intent_for_locator(&self, locator: BlobLocator) -> Option<UploadIntent> {
        self.validate_locator(&locator).ok()?;
        Some(UploadIntent::new(locator, self.backend_identity.clone()))
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
        // Finish the statically composed builder first, then layer through
        // `Operator::layer`, which re-erases the accessor after every layer.
        // Layers kept on `OperatorBuilder` nest each monomorphized future
        // inside the next, and a 2 MiB Tokio worker overflowed its stack while
        // polling that layout during publication. Layer order, retries,
        // deadlines, concurrency and capabilities are unchanged; only the
        // composition boundary becomes dynamic.
        $builder
            .finish()
            .layer(TimeoutLayer::new().with_timeout($profile.object_timeout()).with_io_timeout($profile.io_timeout()))
            .layer(ConcurrentLimitLayer::new($profile.concurrency()))
            .layer(RetryLayer::new().with_max_times($profile.retry_max_times()))
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
    // A cfg-aware `match`, not `let ... else`: with `blob-azblob` off this enum
    // has exactly one variant, so an irrefutable `let` would make the `else`
    // clause unreachable (clippy `irrefutable_let_patterns`). Gating the
    // rejection arm on the feature keeps Azure-only credential mismatch refusal
    // when Azure is compiled in and keeps the match exhaustive in both feature
    // matrices, with no lint suppression.
    match profile.credentials() {
        BlobCredentials::S3 { access_key_id, secret_access_key, session_token } => {
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
        BlobCredentials::Azblob { .. } => {
            Err(BlobError::Config("credential kind does not match the s3 provider".into()))
        }
    }
}

#[cfg(feature = "blob-azblob")]
fn azblob_operator(profile: &BlobProfile) -> Result<Operator, BlobError> {
    // Same cfg-aware shape as `s3_operator`: both variants exist here because
    // this function is only compiled with `blob-azblob`, so the S3 arm is the
    // reachable credential-kind rejection instead of an unreachable `else`.
    match profile.credentials() {
        BlobCredentials::Azblob { account_name, account_key } => {
            let endpoint =
                profile.endpoint().ok_or_else(|| BlobError::Config("azblob needs an explicit endpoint".into()))?;
            let builder = Azblob::default()
                .container(profile.bucket())
                .root(profile.root())
                .account_name(account_name)
                .account_key(account_key)
                .endpoint(endpoint.as_str());
            let builder = Operator::new(builder).map_err(map_provider_error)?;
            Ok(finish_operator!(builder, profile))
        }
        BlobCredentials::S3 { .. } => {
            Err(BlobError::Config("credential kind does not match the azblob provider".into()))
        }
    }
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
