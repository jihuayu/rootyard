//! The real Blob backend of the suite: the operator's own S3-compatible profile
//! (`ROOTYARD_BLOB_*`) opened through the production `BlobProfile::from_env` and
//! `BlobStore::open`.
//!
//! `ROOTYARD_BLOB_ROOT` is a remote object *prefix*, not a local directory:
//! `validate_root` rejects absolute paths, and the S3 driver hands the value
//! straight to the bucket as `root`. The fixture therefore never guesses or
//! fabricates a prefix; [`db_run::owned_root`] pins exactly one random relative
//! prefix for the run, the launched service receives that same value, and the
//! store opened here resolves to the same physical objects. A description of
//! the opened profile never contains credentials, secrets, a session token or
//! the full endpoint.
use anyhow::{Result, anyhow, ensure};
use rootyard::blob_store::{BlobProvider, config::BlobProfile, opendal::BlobStore};

use super::db_run;

/// Open the real store both the test process and the service use.
pub fn open_store() -> Result<BlobStore> {
    root()?;
    let profile = BlobProfile::from_env().map_err(|error| anyhow!("ROOTYARD_BLOB_* profile rejected: {error}"))?;
    ensure!(profile.provider() == BlobProvider::S3, "ROOTYARD_BLOB_SERVICE must be s3 for this suite");
    ensure!(!profile.root().is_empty(), "the suite pinned no remote Blob prefix");
    BlobStore::open(profile).map_err(|error| anyhow!("configured Blob store rejected: {error}"))
}

/// The run-owned relative prefix, or the reason it cannot be used.
pub fn root() -> Result<&'static str> {
    let root = db_run::owned_root()?;
    validate(root)
}

/// The same structural rules `blob_store::config::validate_root` applies.
fn validate(root: &str) -> Result<&str> {
    ensure!(!root.starts_with('/'), "the Blob root must be a relative remote prefix, not a local path: {root}");
    ensure!(!root.ends_with('/') && root.len() <= 256, "the Blob root prefix is not a single relative prefix: {root}");
    for segment in root.split('/') {
        let valid = !segment.is_empty()
            && segment != "."
            && segment != ".."
            && segment.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
        ensure!(valid, "the Blob root prefix has an invalid segment: {:?}", segment);
    }
    Ok(root)
}

/// A service environment entry for the run-owned Blob prefix. The value is the
/// same `ROOTYARD_BLOB_ROOT` the test process uses; the service resolves it
/// against the operator's bucket exactly as this process does.
pub fn root_environment() -> Result<(&'static str, &'static str)> {
    Ok(("ROOTYARD_BLOB_ROOT", root()?))
}

/// Exactly the variables `blob_store::config::BlobProfile::from_env` reads, in
/// both provider arms. This is the whole inherited Blob profile an isolated
/// child service receives; nothing else from the parent environment is copied.
const PROFILE_KEYS: &[&str] = &[
    "ROOTYARD_BLOB_DRIVER",
    "ROOTYARD_BLOB_SERVICE",
    "ROOTYARD_BLOB_BUCKET",
    "ROOTYARD_BLOB_CONTAINER",
    "ROOTYARD_BLOB_ENDPOINT",
    "ROOTYARD_BLOB_REGION",
    "ROOTYARD_BLOB_ACCESS_KEY_ID",
    "ROOTYARD_BLOB_SECRET_ACCESS_KEY",
    "ROOTYARD_BLOB_SESSION_TOKEN",
    "ROOTYARD_BLOB_ACCOUNT_NAME",
    "ROOTYARD_BLOB_ACCOUNT_KEY",
    "ROOTYARD_BLOB_ACTIVE_UPLOADS",
    "ROOTYARD_BLOB_ACTIVE_READERS",
    "ROOTYARD_BLOB_STAGING_BYTES",
    "ROOTYARD_BLOB_MAX_OBJECT_BYTES",
    "ROOTYARD_BLOB_RANGE_FULL_GET_MAX_BYTES",
    "ROOTYARD_BLOB_TIMEOUT_MS",
    "ROOTYARD_BLOB_IO_TIMEOUT_MS",
    "ROOTYARD_BLOB_CONCURRENCY",
    "ROOTYARD_BLOB_RETRY_MAX_TIMES",
    "ROOTYARD_BLOB_ABORT_TIMEOUT_MS",
    "ROOTYARD_BLOB_DELETE",
];

/// The operator's real Blob profile as inherited by the launched service.
///
/// The service starts from an empty environment, so the profile this process
/// successfully opened would otherwise never reach it. Only [`PROFILE_KEYS`]
/// are carried over, unset keys stay unset; `ROOTYARD_BLOB_ROOT` is neither
/// inherited nor listed here, and the run-owned prefix is set separately so it
/// always wins. Values are never printed, logged or persisted.
pub fn profile_environment() -> Vec<(&'static str, std::ffi::OsString)> {
    PROFILE_KEYS.iter().filter_map(|name| std::env::var_os(name).map(|value| (*name, value))).collect()
}

/// A description of the opened profile for the report: provider, bucket/region
/// lengths, the loopback/located endpoint *shape* and the relative prefix. It
/// never contains an access key, secret, session token, user info or port.
pub fn describe() -> Result<String> {
    let profile = BlobProfile::from_env().map_err(|error| anyhow!("ROOTYARD_BLOB_* profile rejected: {error}"))?;
    let endpoint = profile.endpoint().map(|url| format!("{}://{}", url.scheme(), loopback_host(url.host_str())));
    Ok(format!(
        "provider={:?} bucket_len={} region_len={} endpoint={} root={} delete_policy={:?}",
        profile.provider(),
        profile.bucket().len(),
        profile.region().map(str::len).unwrap_or(0),
        endpoint.unwrap_or_else(|| "<none>".to_owned()),
        profile.root(),
        profile.delete_policy(),
    ))
}

fn loopback_host(host: Option<&str>) -> &'static str {
    match host {
        Some("127.0.0.1") => "127.0.0.1",
        Some("::1") => "[::1]",
        Some("localhost") => "localhost",
        _ => "<non-loopback>",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn absolute_local_directories_are_not_blob_prefixes() {
        // The start-up defect: a scratch directory joined onto a local path.
        let scratch = Path::new("/tmp/fixture-scratch");
        let local = scratch.join("blob-root");
        let value = local.to_string_lossy().into_owned();
        let error = validate(&value).expect_err("an absolute local directory must be refused");
        assert!(error.to_string().contains("relative remote prefix"), "{error}");

        assert!(validate("blob-gateway-suite/0123456789abcdef").is_ok());
        for invalid in ["/prefix", "prefix/", "a//b", "a/../b", "a/./b", "a/b c", "a:b"] {
            assert!(validate(invalid).is_err(), "{invalid:?} must not be a Blob prefix");
        }
    }

    #[test]
    fn endpoint_shape_never_echoes_port_or_credentials() {
        assert_eq!(loopback_host(Some("127.0.0.1")), "127.0.0.1");
        assert_eq!(loopback_host(Some("::1")), "[::1]");
        assert_eq!(loopback_host(Some("localhost")), "localhost");
        assert_eq!(loopback_host(Some("garage.example")), "<non-loopback>");
        assert_eq!(loopback_host(None), "<non-loopback>");
    }
}
