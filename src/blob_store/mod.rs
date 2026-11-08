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

pub mod config;
pub mod opendal;
pub mod readback;
pub mod transfer;

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
    Disabled,
    /// Delete exactly one versioned locator. Still gated by the hold/root
    /// protocol work in #113/#114 before an operator may enable it.
    ExactLocator,
}

impl BlobDeletePolicy {
    pub fn parse(value: &str) -> Result<Self, BlobError> {
        match value {
            "disabled" | "" => Ok(Self::Disabled),
            "exact-locator" => Ok(Self::ExactLocator),
            other => Err(BlobError::Config(format!("unknown blob delete policy `{other}`"))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::ExactLocator => "exact-locator",
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
            "azblob" => Err(BlobError::Config(
                "azblob provider was not compiled in (enable feature `blob-azblob`)".into(),
            )),
            "fs" | "memory" => Err(BlobError::UnsupportedService(value.into())),
            other => Err(BlobError::UnsupportedService(other.into())),
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

    /// Authority-free layout reserved for backup volumes that must stay
    /// readable by a restore which mints a new authority. Still attempt-unique.
    pub fn volume_path(&self) -> String {
        format!(
            "v1/volumes/tenants/{}/attempts/{}/{}/{}",
            self.tenant_id, self.attempt_id, self.namespace, self.sha256
        )
    }
}

impl fmt::Debug for BlobLocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlobLocator")
            .field("schema", &self.schema)
            .field("tenant_id", &self.tenant_id)
            .field("authority_id", &self.authority_id)
            .field("generation", &self.generation)
            .field("attempt_id", &self.attempt_id)
            .field("namespace", &self.namespace)
            .field("sha256", &self.sha256)
            .field("length", &self.length)
            .finish()
    }
}

/// Durable acknowledgement of provider-held bytes. It is issued only after a
/// fresh provider read-back (not a `stat`, not an ETag, not the local file)
/// reproduced `sha256` and `length` exactly.
#[derive(Clone, PartialEq, Eq)]
pub struct BlobReceipt {
    pub schema: u32,
    pub locator: BlobLocator,
    pub provider: BlobProvider,
    pub verified_sha256: String,
    pub verified_length: u64,
}

impl BlobReceipt {
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
            .field("verified_sha256", &self.verified_sha256)
            .field("verified_length", &self.verified_length)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlobError {
    Config(String),
    /// `fs`/`memory` and unknown services never qualify for production.
    UnsupportedService(String),
    NotFound,
    AlreadyExists,
    LengthMismatch { expected: u64, actual: u64 },
    DigestMismatch { expected: String, actual: String },
    RangeExceedsLimit { requested: u64, limit: u64 },
    DeadlineExceeded,
    DeleteDisabled,
    Provider(String),
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
            Self::DigestMismatch { expected, actual } => {
                write!(f, "blob digest mismatch: expected {expected}, got {actual}")
            }
            Self::RangeExceedsLimit { requested, limit } => {
                write!(f, "blob range read of {requested} bytes exceeds mount limit {limit}")
            }
            Self::DeadlineExceeded => write!(f, "blob operation deadline exceeded"),
            Self::DeleteDisabled => write!(f, "blob deletion is disabled for this profile"),
            Self::Provider(m) => write!(f, "blob provider error: {m}"),
        }
    }
}

impl std::error::Error for BlobError {}
