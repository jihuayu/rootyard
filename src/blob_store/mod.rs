//! Unified immutable Blob layer for design §4.1/§12/§17 (work package W1-B).
//!
//! This module owns only the provider-independent contract: a versioned, strong
//! typed locator, a verified receipt and the explicit delete policy. The
//! OpenDAL-backed driver lives in [`opendal`]; callers never see a provider
//! path, an HTTP signature, an ETag-as-digest shortcut or a `LIST` inventory.
//!
//! Two object layouts coexist deliberately:
//!
//! * `legacy` paths (`tenants/<tenant>/<namespace>/<sha256>` and the
//!   authority-scoped `tenants/<tenant>/authorities/<id>/g<n>/...` form) are the
//!   pre-OpenDAL layout used by LFS, Workspace, backups and the Pando PG
//!   retention path. The adapter in `crate::storage::remote_objects` keeps them
//!   byte-for-byte readable; readers and manifests must not silently change.
//! * `v1` paths below are the new standalone Blob profile. They always bind
//!   tenant, storage authority, authority generation and a unique attempt id so
//!   a cancelled publication attempt can never collide with, or overwrite, a
//!   later attempt for the same content digest.
//!
//! This file intentionally contains no destructive-GC or hold-ledger logic:
//! remote deletion for the new profile stays disabled until the persistent
//! hold/root protocols (#113/#114) are reviewed and enabled explicitly.

pub mod budget;
pub mod config;
pub mod opendal;
pub mod readback;
pub mod transfer;
pub mod upload;

#[cfg(test)]
mod budget_tests;
#[cfg(test)]
mod lifecycle_tests;
#[cfg(test)]
mod test_support;

use std::fmt;

use uuid::Uuid;

/// Schema of [`BlobLocator`]/[`BlobReceipt`]. Bump only with a migration.
pub const BLOB_LOCATOR_SCHEMA: u32 = 1;
pub const MAX_NAMESPACE_BYTES: usize = 48;
/// Explicit ceiling; providers enforce their own lower limits at startup.
pub const MAX_OBJECT_BYTES: u64 = 1 << 40;

/// Physical delete policy for the new Blob profile. `Disabled` is the default
/// and refuses every delete call. No listing, prefix delete or GC sweep exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobDeletePolicy {
    /// The only policy. Persistent hold/root retirement claims (#113/#114) do
    /// not exist yet, so no environment value may enable deletion.
    Disabled,
}

impl BlobDeletePolicy {
    pub fn parse(value: &str) -> Result<Self, BlobError> {
        match value {
            "disabled" | "" => Ok(Self::Disabled),
            "exact-locator" => Err(BlobError::Config(
                "blob deletion stays disabled until persistent hold/root retirement claims (#113/#114) exist".into(),
            )),
            _ => Err(BlobError::Config("unknown blob delete policy; only `disabled` is accepted".into())),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobProvider {
    S3,
    Azblob,
}

impl BlobProvider {
    pub fn parse(value: &str) -> Result<Self, BlobError> {
        match value {
            "s3" => Ok(Self::S3),
            #[cfg(feature = "blob-azblob")]
            "azblob" => Ok(Self::Azblob),
            #[cfg(not(feature = "blob-azblob"))]
            "azblob" => {
                Err(BlobError::Config("azblob provider was not compiled in (enable feature `blob-azblob`)".into()))
            }
            "fs" => Err(BlobError::UnsupportedService("fs".into())),
            "memory" => Err(BlobError::UnsupportedService("memory".into())),
            _ => Err(BlobError::UnsupportedService("<unrecognized service>".into())),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::S3 => "s3",
            Self::Azblob => "azblob",
        }
    }
}

/// Strong typed, immutable locator. Every field participates in the physical
/// path, so two publications of identical bytes by different attempts are
/// distinct objects and a stale writer cannot overwrite a newer acknowledged
/// object. The digest names the *expected* content; the receipt proves it.
#[derive(Clone, PartialEq, Eq)]
pub struct BlobLocator {
    schema: u32,
    tenant_id: Uuid,
    authority_id: Uuid,
    generation: i64,
    attempt_id: Uuid,
    namespace: String,
    sha256: String,
    length: u64,
}

impl BlobLocator {
    pub fn new(
        tenant_id: Uuid,
        authority_id: Uuid,
        generation: i64,
        attempt_id: Uuid,
        namespace: &str,
        sha256: &str,
        length: u64,
    ) -> Result<Self, BlobError> {
        if tenant_id.is_nil() || authority_id.is_nil() || attempt_id.is_nil() || generation <= 0 {
            return Err(BlobError::Config("blob locator needs tenant, authority, attempt and generation".into()));
        }
        if namespace.is_empty()
            || namespace.len() > MAX_NAMESPACE_BYTES
            || !namespace.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(BlobError::Config("invalid blob namespace".into()));
        }
        if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(BlobError::Config("invalid blob digest".into()));
        }
        if length > MAX_OBJECT_BYTES {
            return Err(BlobError::LengthMismatch { expected: MAX_OBJECT_BYTES, actual: length });
        }
        Ok(Self {
            schema: BLOB_LOCATOR_SCHEMA,
            tenant_id,
            authority_id,
            generation,
            attempt_id,
            namespace: namespace.to_owned(),
            sha256: sha256.to_owned(),
            length,
        })
    }

    pub fn schema(&self) -> u32 {
        self.schema
    }
    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }
    pub fn authority_id(&self) -> Uuid {
        self.authority_id
    }
    pub fn generation(&self) -> i64 {
        self.generation
    }
    pub fn attempt_id(&self) -> Uuid {
        self.attempt_id
    }
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    pub fn length(&self) -> u64 {
        self.length
    }

    /// Versioned, never-reused physical path. The `v1/` prefix cannot collide
    /// with legacy content-addressed keys, so existing readers are untouched.
    pub fn path(&self) -> String {
        format!(
            "v1/tenants/{}/authorities/{}/g{}/attempts/{}/{}/{}",
            self.tenant_id, self.authority_id, self.generation, self.attempt_id, self.namespace, self.sha256
        )
    }
}

impl fmt::Debug for BlobLocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Identifiers, attempt path and digest stay out of Debug/log output.
        f.debug_struct("BlobLocator")
            .field("schema", &self.schema)
            .field("namespace", &self.namespace)
            .field("length", &self.length)
            .field("owner", &"<redacted>")
            .field("attempt", &"<redacted>")
            .field("sha256", &"<redacted>")
            .finish()
    }
}

/// Single-use publication capability for exactly one fresh attempt.
///
/// Only [`opendal::BlobStore::new_upload`] mints one, and it always
/// allocates a random attempt id inside the byte layer. Callers cannot supply an
/// attempt id, clone the intent, deserialize it or turn a readable
/// [`BlobLocator`] back into write authority. A locator reconstructed from
/// stored metadata/checkpoints is therefore read-only, and a trusted resume
/// must verify that existing object or mint a completely new attempt rather
/// than recovering a write capability after a restart.
///
/// [`opendal::BlobStore::put_file`] consumes the intent by value. A
/// retry after an unknown outcome must verify the old read-only locator (no
/// overwrite) or mint a fresh intent/path. A process crash may leave an orphan
/// object, but its address can never be reused for a later publication.
///
/// ```compile_fail
/// fn clone_cap(x: rootyard::blob_store::UploadIntent) -> rootyard::blob_store::UploadIntent {
///     x.clone()
/// }
/// ```
///
/// ```compile_fail
/// fn forge(x: rootyard::blob_store::BlobLocator) -> rootyard::blob_store::UploadIntent {
///     rootyard::blob_store::UploadIntent { locator: x }
/// }
/// ```
pub struct UploadIntent {
    locator: BlobLocator,
}

impl UploadIntent {
    /// Read-only borrow of the attempt address before any bytes are written,
    /// suitable for a hold reservation. Borrowing does not duplicate the
    /// single-use write capability.
    pub fn locator(&self) -> &BlobLocator {
        &self.locator
    }

    /// Module-private mint point; `BlobStore::new_upload` is the only caller.
    fn new(locator: BlobLocator) -> Self {
        Self { locator }
    }
}

impl fmt::Debug for UploadIntent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UploadIntent").field("locator", &self.locator).finish()
    }
}

/// Durable acknowledgement of provider-held bytes. It is issued only after a
/// fresh provider read-back (not a `stat`, not an ETag, not the local file)
/// reproduced `sha256` and `length` exactly.
#[derive(Clone, PartialEq, Eq)]
pub struct BlobReceipt {
    schema: u32,
    locator: BlobLocator,
    provider: BlobProvider,
    verified_sha256: String,
    verified_length: u64,
}

impl BlobReceipt {
    /// Only the blob_store driver can mint a receipt, and only after a provider
    /// read-back. There is no `Deserialize`/public constructor, so an untrusted
    /// receipt cannot be forged into verification.
    pub(crate) fn new(
        locator: BlobLocator,
        provider: BlobProvider,
        verified_sha256: String,
        verified_length: u64,
    ) -> Self {
        Self { schema: BLOB_LOCATOR_SCHEMA, locator, provider, verified_sha256, verified_length }
    }

    pub fn schema(&self) -> u32 {
        self.schema
    }
    pub fn locator(&self) -> &BlobLocator {
        &self.locator
    }
    pub fn provider(&self) -> BlobProvider {
        self.provider
    }
    pub fn verified_sha256(&self) -> &str {
        &self.verified_sha256
    }
    pub fn verified_length(&self) -> u64 {
        self.verified_length
    }

    /// Metadata equality only. A receipt reloaded from an untrusted store must
    /// still pass [`BlobStore::verify_receipt`] against the provider before it
    /// is treated as proof of content.
    pub fn matches(&self, locator: &BlobLocator) -> bool {
        self.schema == BLOB_LOCATOR_SCHEMA
            && &self.locator == locator
            && self.verified_sha256 == locator.sha256
            && self.verified_length == locator.length
    }
}

impl fmt::Debug for BlobReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlobReceipt")
            .field("schema", &self.schema)
            .field("locator", &self.locator)
            .field("provider", &self.provider)
            .field("verified_sha256", &"<redacted>")
            .field("verified_length", &self.verified_length)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum BlobError {
    Config(String),
    /// `fs`/`memory` and unknown services never qualify for production.
    UnsupportedService(String),
    NotFound,
    AlreadyExists,
    LengthMismatch {
        expected: u64,
        actual: u64,
    },
    DigestMismatch {
        expected: String,
        actual: String,
    },
    RangeExceedsLimit {
        requested: u64,
        limit: u64,
    },
    /// A range would require a full verified download larger than the strict
    /// ceiling; no chunk-hash manifest/cache proof exists yet.
    RangeUnsupported {
        length: u64,
        limit: u64,
    },
    DeadlineExceeded,
    /// A staging lease larger than the whole process staging budget can never be
    /// granted; this is refused before any queue wait instead of hanging.
    StagingBudgetExceeded {
        requested: u64,
        limit: u64,
    },
    /// A second profile asked for different process-wide limits. First-wins
    /// silently would give two operators different beliefs about one budget.
    CapacityConflict,
    DeleteDisabled,
    Provider(String),
    /// Typed legacy remote-store failure. The legacy OpenDAL adapter must not
    /// flatten a provider failure into `Provider` text: worker diagnostics
    /// downcast to the parent `RemoteStoreError` to keep the bounded operation
    /// label and the numeric status of the response actually observed. The
    /// standalone Blob profile never produces this variant.
    Remote(crate::storage::remote_errors::RemoteStoreError),
}

impl fmt::Display for BlobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(m) => write!(f, "blob configuration rejected: {m}"),
            Self::UnsupportedService(s) => write!(f, "blob service `{s}` is not supported for the new profile"),
            Self::NotFound => write!(f, "blob object not found"),
            Self::AlreadyExists => write!(f, "blob locator already exists"),
            Self::LengthMismatch { expected, actual } => {
                write!(f, "blob length mismatch: expected {expected}, got {actual}")
            }
            Self::DigestMismatch { .. } => write!(f, "blob digest mismatch"),
            Self::RangeExceedsLimit { requested, limit } => {
                write!(f, "blob range read of {requested} bytes exceeds mount limit {limit}")
            }
            Self::RangeUnsupported { length, limit } => {
                write!(f, "verified range read needs a full {length}-byte download, above ceiling {limit}")
            }
            Self::DeadlineExceeded => write!(f, "blob operation deadline exceeded"),
            Self::StagingBudgetExceeded { requested, limit } => write!(
                f,
                "blob staging lease of {requested} bytes exceeds the process staging budget {limit}"
            ),
            Self::CapacityConflict => {
                write!(f, "blob resource limits conflict with the initialized process-wide context")
            }
            Self::DeleteDisabled => write!(f, "blob deletion is disabled for this profile"),
            Self::Provider(m) => write!(f, "blob provider error: {m}"),
            // `RemoteStoreError` has its own fixed, privacy-safe template.
            Self::Remote(remote) => write!(f, "{remote}"),
        }
    }
}

impl std::error::Error for BlobError {}

impl fmt::Debug for BlobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
