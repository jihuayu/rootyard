//! Strict environment profile for the standalone OpenDAL Blob layer.
//!
//! Unlike the legacy `RemoteObjectStore::from_env` adapter (which may return an
//! explicitly marked `Local` fixture store when `ROOTYARD_OBJECT_STORE_ENDPOINT`
//! is absent), this profile refuses to start without an explicit remote
//! service. `fs`, `memory` and unknown services are rejected by name: the new
//! profile never silently degrades to node-local or in-process storage.

use std::{fmt, time::Duration};

use reqwest::Url;

use super::{
    BlobDeletePolicy, BlobError, BlobProvider, MAX_NAMESPACE_BYTES, MAX_OBJECT_BYTES,
    budget::{
        DEFAULT_ACTIVE_READERS, DEFAULT_ACTIVE_UPLOADS, DEFAULT_STAGING_BYTES, LEASE_UNIT_BYTES, MAX_ACTIVE_SLOTS,
        MAX_STAGING_BYTES, ResourceLimits,
    },
};

pub const DEFAULT_OBJECT_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(60);
pub const DEFAULT_CONCURRENCY: usize = 16;
pub const DEFAULT_RETRY_MAX_TIMES: usize = 3;
/// Verified range reads currently require a full download; keep it strictly bounded.
pub const DEFAULT_RANGE_FULL_GET_MAX_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_RANGE_FULL_GET_MAX_BYTES: u64 = 256 * 1024 * 1024;
/// Independent budget for best-effort writer abort after a failed/aborted op.
pub const DEFAULT_ABORT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_CONCURRENCY: usize = 256;
const MAX_RETRY_TIMES: usize = 10;

/// Provider credentials. Never implements `Debug` with secret material and is
/// never formatted into an error, log line or error chain.
#[derive(Clone)]
pub enum BlobCredentials {
    S3 {
        access_key_id: String,
        secret_access_key: String,
        session_token: Option<String>,
    },
    #[cfg(feature = "blob-azblob")]
    Azblob {
        account_name: String,
        account_key: String,
    },
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
    range_full_get_max_bytes: u64,
    abort_timeout: Duration,
    delete_policy: BlobDeletePolicy,
    /// Shared upload/reader/staging capacities for the whole process.
    resources: ResourceLimits,
}

impl fmt::Debug for BlobProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlobProfile")
            .field("provider", &self.provider)
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("endpoint", &self.endpoint.as_ref().map(Url::origin).map(|o| o.ascii_serialization()))
            .field("root", &"<redacted>")
            .field("credentials", &self.credentials)
            .field("object_timeout", &self.object_timeout)
            .field("io_timeout", &self.io_timeout)
            .field("concurrency", &self.concurrency)
            .field("retry_max_times", &self.retry_max_times)
            .field("max_object_bytes", &self.max_object_bytes)
            .field("range_full_get_max_bytes", &self.range_full_get_max_bytes)
            .field("resources", &self.resources)
            .field("abort_timeout", &self.abort_timeout)
            .field("delete_policy", &self.delete_policy)
            .finish()
    }
}

impl BlobProfile {
    /// Production entry point. Any absent or unsafe setting is a hard error.
    pub fn from_env() -> Result<Self, BlobError> {
        if let Some(driver) = env_optional("ROOTYARD_BLOB_DRIVER")?
            && driver != "opendal"
        {
            return Err(BlobError::UnsupportedService(format!("driver `{driver}`")));
        }
        let provider = BlobProvider::parse(&env_required("ROOTYARD_BLOB_SERVICE")?)?;
        let bucket = env_required(if provider == BlobProvider::S3 {
            "ROOTYARD_BLOB_BUCKET"
        } else {
            "ROOTYARD_BLOB_CONTAINER"
        })?;
        validate_bucket(&bucket)?;
        let root = env_optional("ROOTYARD_BLOB_ROOT")?.unwrap_or_default();
        validate_root(&root)?;
        let endpoint = env_optional("ROOTYARD_BLOB_ENDPOINT")?.map(|raw| parse_origin(&raw)).transpose()?;
        let region = env_optional("ROOTYARD_BLOB_REGION")?;
        if endpoint.is_none() {
            return Err(BlobError::Config(
                "standalone blob profile needs an explicit remote ROOTYARD_BLOB_ENDPOINT".into(),
            ));
        }
        if provider == BlobProvider::S3 {
            let region = region.as_deref().ok_or_else(|| BlobError::Config("s3 needs ROOTYARD_BLOB_REGION".into()))?;
            validate_token(region, 64, "region")?;
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
        let resources = ResourceLimits::new(
            bounded_usize("ROOTYARD_BLOB_ACTIVE_UPLOADS", DEFAULT_ACTIVE_UPLOADS, 1, MAX_ACTIVE_SLOTS)?,
            bounded_usize("ROOTYARD_BLOB_ACTIVE_READERS", DEFAULT_ACTIVE_READERS, 1, MAX_ACTIVE_SLOTS)?,
            bounded_u64("ROOTYARD_BLOB_STAGING_BYTES", DEFAULT_STAGING_BYTES, LEASE_UNIT_BYTES, MAX_STAGING_BYTES)?,
        )?;
        // The default object ceiling follows the staging budget: this contract
        // only acknowledges objects it can also fetch back for verification.
        let max_object_bytes = match env_optional("ROOTYARD_BLOB_MAX_OBJECT_BYTES")? {
            Some(raw) => raw.parse::<u64>().map_err(|_| BlobError::Config("invalid blob object ceiling".into()))?,
            None => resources.staging_bytes().min(MAX_OBJECT_BYTES),
        };
        if max_object_bytes == 0 || max_object_bytes > MAX_OBJECT_BYTES {
            return Err(BlobError::Config("blob object ceiling is out of range".into()));
        }
        if max_object_bytes > resources.staging_bytes() {
            return Err(BlobError::Config(
                "blob object ceiling exceeds the staging budget and no alternative full-read API exists to verify it \
                 (raise ROOTYARD_BLOB_STAGING_BYTES up to 16 GiB or lower ROOTYARD_BLOB_MAX_OBJECT_BYTES)"
                    .into(),
            ));
        }
        // A small staging budget lowers the *default* range ceiling too; only an
        // explicit ceiling above the budget is a configuration error.
        let range_full_get_max_bytes = bounded_u64(
            "ROOTYARD_BLOB_RANGE_FULL_GET_MAX_BYTES",
            DEFAULT_RANGE_FULL_GET_MAX_BYTES.min(resources.staging_bytes()),
            1024 * 1024,
            MAX_RANGE_FULL_GET_MAX_BYTES,
        )?;
        if range_full_get_max_bytes > resources.staging_bytes() {
            return Err(BlobError::Config(
                "blob range full-get ceiling exceeds the staging budget; such a range could never be staged".into(),
            ));
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
            retry_max_times: bounded_usize(
                "ROOTYARD_BLOB_RETRY_MAX_TIMES",
                DEFAULT_RETRY_MAX_TIMES,
                0,
                MAX_RETRY_TIMES,
            )?,
            range_full_get_max_bytes,
            abort_timeout: duration_ms("ROOTYARD_BLOB_ABORT_TIMEOUT_MS", DEFAULT_ABORT_TIMEOUT)?,
            max_object_bytes,
            delete_policy: BlobDeletePolicy::parse(&env_optional("ROOTYARD_BLOB_DELETE")?.unwrap_or_default())?,
            resources,
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
    pub fn range_full_get_max_bytes(&self) -> u64 {
        self.range_full_get_max_bytes
    }
    pub fn abort_timeout(&self) -> Duration {
        self.abort_timeout
    }
    pub fn delete_policy(&self) -> BlobDeletePolicy {
        self.delete_policy
    }
    /// Process-wide upload/reader/staging capacities requested by this profile.
    /// `BlobStore::open` registers them once per process and rejects conflicts.
    pub fn resource_limits(&self) -> ResourceLimits {
        self.resources
    }

    /// Test-only profile for the in-process `memory` backend. It carries no real
    /// credentials and never reaches the production builder (see
    /// `BlobStore::open_memory`), so lifecycle unit tests need neither env vars
    /// nor a provider.
    #[cfg(test)]
    pub(crate) fn memory_profile(resources: ResourceLimits) -> Self {
        Self {
            provider: BlobProvider::S3,
            bucket: "blob-test-bucket".into(),
            region: Some("us-east-1".into()),
            endpoint: Url::parse("https://127.0.0.1:9").ok(),
            root: String::new(),
            credentials: BlobCredentials::S3 {
                access_key_id: "test-access-key".into(),
                secret_access_key: "test-secret-key".into(),
                session_token: None,
            },
            object_timeout: DEFAULT_OBJECT_TIMEOUT,
            io_timeout: DEFAULT_IO_TIMEOUT,
            concurrency: 2,
            retry_max_times: 0,
            max_object_bytes: resources.staging_bytes().min(MAX_OBJECT_BYTES),
            range_full_get_max_bytes: resources.staging_bytes().min(DEFAULT_RANGE_FULL_GET_MAX_BYTES),
            abort_timeout: Duration::from_millis(100),
            delete_policy: BlobDeletePolicy::Disabled,
            resources,
        }
    }

    /// Relative object path. `ROOTYARD_BLOB_ROOT` is applied exactly once by
    /// the operator builder root, never duplicated here.
    pub(crate) fn object_path(&self, locator: &super::BlobLocator) -> String {
        locator.path()
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

fn bounded_u64(name: &str, default: u64, min: u64, max: u64) -> Result<u64, BlobError> {
    let Some(raw) = env_optional(name)? else {
        return Ok(default);
    };
    let value = raw.parse::<u64>().map_err(|_| BlobError::Config(format!("{name} is not a byte count")))?;
    if value < min || value > max {
        return Err(BlobError::Config(format!("{name} is out of range {min}..={max}")));
    }
    Ok(value)
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
    if url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(BlobError::Config(
            "blob endpoint must be an origin URL without credentials, path, query or fragment".into(),
        ));
    }
    Ok(url)
}
