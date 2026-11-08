//! Strict environment profile for the standalone OpenDAL Blob layer.
//!
//! Unlike the legacy `RemoteObjectStore::from_env` adapter (which may return an
//! explicitly marked `Local` fixture store when `ROOTYARD_OBJECT_STORE_ENDPOINT`
//! is absent), this profile refuses to start without an explicit remote
//! service. `fs`, `memory` and unknown services are rejected by name: the new
//! profile never silently degrades to node-local or in-process storage.

use std::{fmt, time::Duration};

use reqwest::Url;
use uuid::Uuid;

use super::{BlobDeletePolicy, BlobError, BlobProvider, MAX_NAMESPACE_BYTES, MAX_OBJECT_BYTES};

pub const DEFAULT_OBJECT_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(60);
pub const DEFAULT_CONCURRENCY: usize = 16;
pub const DEFAULT_RETRY_MAX_TIMES: usize = 3;
const MAX_CONCURRENCY: usize = 256;
const MAX_RETRY_TIMES: usize = 10;

/// Provider credentials. Never implements `Debug` with secret material and is
/// never formatted into an error, log line or error chain.
#[derive(Clone)]
pub enum BlobCredentials {
    S3 { access_key_id: String, secret_access_key: String, session_token: Option<String> },
    #[cfg(feature = "blob-azblob")]
    Azblob { account_name: String, account_key: String },
}

impl BlobCredentials {
    fn describe(&self) -> &'static str {
        match self {
            Self::S3 { .. } => "s3 static credentials",
            #[cfg(feature = "blob-azblob")]
            Self::Azblob { .. } => "azblob shared-key credentials",
        }
    }
}

impl fmt::Debug for BlobCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlobCredentials").field("kind", &self.describe()).field("secret", &"<redacted>").finish()
    }
}

#[derive(Clone)]
pub struct BlobProfile {
    provider: BlobProvider,
    bucket: String,
    region: Option<String>,
    endpoint: Option<Url>,
    root: String,
    credentials: BlobCredentials,
    object_timeout: Duration,
    io_timeout: Duration,
    concurrency: usize,
    retry_max_times: usize,
    max_object_bytes: u64,
    delete_policy: BlobDeletePolicy,
}

impl fmt::Debug for BlobProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlobProfile")
            .field("provider", &self.provider)
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("endpoint", &self.endpoint.as_ref().map(Url::origin).map(|o| o.ascii_serialization()))
            .field("root", &self.root)
            .field("credentials", &self.credentials)
            .field("object_timeout", &self.object_timeout)
            .field("io_timeout", &self.io_timeout)
            .field("concurrency", &self.concurrency)
            .field("retry_max_times", &self.retry_max_times)
            .field("delete_policy", &self.delete_policy)
            .finish()
    }
}

impl BlobProfile {
    /// Production entry point. Any absent or unsafe setting is a hard error.
    pub fn from_env() -> Result<Self, BlobError> {
        if let Some(driver) = env_optional("ROOTYARD_BLOB_DRIVER")? {
            if driver != "opendal" {
                return Err(BlobError::UnsupportedService(format!("driver `{driver}`")));
            }
        }
        let provider = BlobProvider::parse(&env_required("ROOTYARD_BLOB_SERVICE")?)?;
        let bucket = env_required(if provider == BlobProvider::S3 { "ROOTYARD_BLOB_BUCKET" } else { "ROOTYARD_BLOB_CONTAINER" })?;
        validate_bucket(&bucket)?;
        let root = env_optional("ROOTYARD_BLOB_ROOT")?.unwrap_or_default();
        validate_root(&root)?;
        let endpoint = env_optional("ROOTYARD_BLOB_ENDPOINT")?.map(|raw| parse_origin(&raw)).transpose()?;
        let region = env_optional("ROOTYARD_BLOB_REGION")?;
        if provider == BlobProvider::S3 {
            if endpoint.is_none() && region.is_none() {
                return Err(BlobError::Config("s3 needs ROOTYARD_BLOB_REGION or an explicit endpoint".into()));
            }
            if let Some(region) = &region {
                validate_token(region, 64, "region")?;
            }
        }
        let credentials = match provider {
            BlobProvider::S3 => {
                let access_key_id = env_required("ROOTYARD_BLOB_ACCESS_KEY_ID")?;
                let secret_access_key = env_required("ROOTYARD_BLOB_SECRET_ACCESS_KEY")?;
                if access_key_id.is_empty() || secret_access_key.is_empty() {
                    return Err(BlobError::Config("s3 credentials are empty".into()));
                }
                BlobCredentials::S3 {
                    access_key_id,
                    secret_access_key,
                    session_token: env_optional("ROOTYARD_BLOB_SESSION_TOKEN")?,
                }
            }
            #[cfg(feature = "blob-azblob")]
            BlobProvider::Azblob => {
                if endpoint.is_none() {
                    return Err(BlobError::Config("azblob needs ROOTYARD_BLOB_ENDPOINT".into()));
                }
                let account_key = env_required("ROOTYARD_BLOB_ACCOUNT_KEY")?;
                if account_key.is_empty() {
                    return Err(BlobError::Config("azblob account key is empty".into()));
                }
                BlobCredentials::Azblob { account_name: env_required("ROOTYARD_BLOB_ACCOUNT_NAME")?, account_key }
            }
            #[cfg(not(feature = "blob-azblob"))]
            BlobProvider::Azblob => {
                return Err(BlobError::Config(
                    "azblob provider was not compiled in (enable feature `blob-azblob`)".into(),
                ));
            }
        };
        let max_object_bytes = match env_optional("ROOTYARD_BLOB_MAX_OBJECT_BYTES")? {
            Some(raw) => raw.parse::<u64>().map_err(|_| BlobError::Config("invalid blob object ceiling".into()))?,
            None => MAX_OBJECT_BYTES,
        };
        if max_object_bytes == 0 || max_object_bytes > MAX_OBJECT_BYTES {
            return Err(BlobError::Config("blob object ceiling is out of range".into()));
        }
        Ok(Self {
            provider,
            bucket,
            region,
            endpoint,
            root,
            credentials,
            object_timeout: duration_ms("ROOTYARD_BLOB_TIMEOUT_MS", DEFAULT_OBJECT_TIMEOUT)?,
            io_timeout: duration_ms("ROOTYARD_BLOB_IO_TIMEOUT_MS", DEFAULT_IO_TIMEOUT)?,
            concurrency: bounded_usize("ROOTYARD_BLOB_CONCURRENCY", DEFAULT_CONCURRENCY, 1, MAX_CONCURRENCY)?,
            retry_max_times: bounded_usize("ROOTYARD_BLOB_RETRY_MAX_TIMES", DEFAULT_RETRY_MAX_TIMES, 0, MAX_RETRY_TIMES)?,
            max_object_bytes,
            delete_policy: BlobDeletePolicy::parse(&env_optional("ROOTYARD_BLOB_DELETE")?.unwrap_or_default())?,
        })
    }

    pub fn provider(&self) -> BlobProvider {
        self.provider
    }
    pub fn bucket(&self) -> &str {
        &self.bucket
    }
    pub fn region(&self) -> Option<&str> {
        self.region.as_deref()
    }
    pub fn endpoint(&self) -> Option<&Url> {
        self.endpoint.as_ref()
    }
    pub fn root(&self) -> &str {
        &self.root
    }
    pub fn credentials(&self) -> &BlobCredentials {
        &self.credentials
    }
    pub fn object_timeout(&self) -> Duration {
        self.object_timeout
    }
    pub fn io_timeout(&self) -> Duration {
        self.io_timeout
    }
    pub fn concurrency(&self) -> usize {
        self.concurrency
    }
    pub fn retry_max_times(&self) -> usize {
        self.retry_max_times
    }
    pub fn max_object_bytes(&self) -> u64 {
        self.max_object_bytes
    }
    pub fn delete_policy(&self) -> BlobDeletePolicy {
        self.delete_policy
    }

    /// Full locator path with the configured prefix. The prefix is a trusted
    /// configuration value; the locator part is fixed-format ASCII.
    pub(crate) fn object_path(&self, locator: &super::BlobLocator) -> String {
        if self.root.is_empty() { locator.path() } else { format!("{}/{}", self.root, locator.path()) }
    }
}

fn env_required(name: &str) -> Result<String, BlobError> {
    env_optional(name)?.ok_or_else(|| BlobError::Config(format!("{name} is required for the standalone blob profile")))
}

fn env_optional(name: &str) -> Result<Option<String>, BlobError> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(BlobError::Config(format!("{name} is not valid UTF-8"))),
    }
}

fn duration_ms(name: &str, default: Duration) -> Result<Duration, BlobError> {
    let Some(raw) = env_optional(name)? else {
        return Ok(default);
    };
    let ms = raw.parse::<u64>().map_err(|_| BlobError::Config(format!("{name} is not a millisecond count")))?;
    if ms == 0 || ms > 24 * 60 * 60 * 1000 {
        return Err(BlobError::Config(format!("{name} is out of range")));
    }
    Ok(Duration::from_millis(ms))
}

fn bounded_usize(name: &str, default: usize, min: usize, max: usize) -> Result<usize, BlobError> {
    let Some(raw) = env_optional(name)? else {
        return Ok(default);
    };
    let value = raw.parse::<usize>().map_err(|_| BlobError::Config(format!("{name} is not a count")))?;
    if value < min || value > max {
        return Err(BlobError::Config(format!("{name} is out of range {min}..={max}")));
    }
    Ok(value)
}

fn validate_token(value: &str, max: usize, what: &str) -> Result<(), BlobError> {
    if value.is_empty()
        || value.len() > max
        || !value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    {
        return Err(BlobError::Config(format!("invalid blob {what}")));
    }
    Ok(())
}

pub(crate) fn validate_bucket(bucket: &str) -> Result<(), BlobError> {
    if !(3..=63).contains(&bucket.len())
        || !bucket.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
        || bucket.starts_with('.')
        || bucket.ends_with('.')
        || bucket.contains("..")
    {
        return Err(BlobError::Config("invalid blob bucket/container name".into()));
    }
    Ok(())
}

fn validate_root(root: &str) -> Result<(), BlobError> {
    if root.is_empty() {
        return Ok(());
    }
    if root.len() > 256 || root.starts_with('/') || root.ends_with('/') {
        return Err(BlobError::Config("invalid blob root prefix".into()));
    }
    for segment in root.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." || segment.len() > MAX_NAMESPACE_BYTES {
            return Err(BlobError::Config("invalid blob root prefix segment".into()));
        }
        if !segment.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.') {
            return Err(BlobError::Config("invalid blob root prefix character".into()));
        }
    }
    Ok(())
}

/// Origin-only endpoint validation: HTTPS is mandatory except for an explicit
/// loopback fixture. Credentials, query strings and fragments are rejected so a
/// bearer URL can never become storage configuration.
pub(crate) fn parse_origin(raw: &str) -> Result<Url, BlobError> {
    let url = Url::parse(raw).map_err(|_| BlobError::Config("invalid blob endpoint URL".into()))?;
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "::1" | "localhost"));
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(BlobError::Config("blob endpoint requires TLS (http only for loopback fixtures)".into()));
    }
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() {
        return Err(BlobError::Config("blob endpoint must be an origin URL without credentials, path, query or fragment".into()));
    }
    Ok(url)
}

/// Test/contract helper: parse a locator's attempt identity from explicit
/// fields without accepting caller-built strings.
pub fn attempt_locator(
    tenant: Uuid,
    authority: Uuid,
    generation: i64,
    namespace: &str,
    sha256: &str,
    length: u64,
) -> Result<super::BlobLocator, BlobError> {
    super::BlobLocator::new(tenant, authority, generation, Uuid::new_v4(), namespace, sha256, length)
}
