//! Explicit, file-based key set for repository session tokens (#174).
//!
//! A key is never derived from the database, the Blob profile, the Git binary
//! or any other ambient value, and no default or generated key is ever used in
//! production: the operator must point `ROOTYARD_SESSION_KEYRING` at a key set.
//!
//! Layout (one key set per file, mirroring the local-envelope KeyProvider's
//! posture — see `docs/key-provider.md`):
//!
//! * the keyring directory is absolute, a real directory (never a symlink),
//!   owned by the effective uid and mode exactly `0700`;
//! * `keyring.json` is a regular file, owner euid, mode exactly `0600`, at most
//!   16 KiB:
//!
//!   ```json
//!   { "schema": 1, "current": "v2", "lifetime_seconds": 300,
//!     "keys": [ { "key_id": "v1" }, { "key_id": "v2" } ] }
//!   ```
//!
//! * each `<key_id>.key` is a regular file, owner euid, mode exactly `0600`,
//!   containing exactly 32 bytes of private random key material.
//!
//! Key ids are assigned their one-byte encoding by list position, so a set has
//! at most 256 keys and an id keeps its encoding only while its position is
//! unchanged: appending keys is safe, removing or reordering one changes the
//! encodings after it. Rotation is "add a new id, make it `current`, keep the
//! old file for at most one `lifetime_seconds`"; retiring a key deletes its
//! file and restarts the service. Loading performs only bounded local reads
//! and never creates, repairs or replaces a key.
use std::{
    fs::File,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

use anyhow::{Result, anyhow, ensure};
use serde::Deserialize;

use crate::blob_git_gateway::repo_session::{
    MAX_LIFETIME_SECONDS, MIN_LIFETIME_SECONDS, SessionTokenCodec, SessionTokens,
};

pub(super) const KEYRING_ENV: &str = "ROOTYARD_SESSION_KEYRING";
const MANIFEST: &str = "keyring.json";
const MANIFEST_SCHEMA: u32 = 1;
const MAX_MANIFEST_BYTES: u64 = 16 * 1024;
const MAX_KEYS: usize = 256;
const KEY_BYTES: u64 = 32;
const MAX_KEY_ID_LEN: usize = 32;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: u32,
    current: String,
    lifetime_seconds: u32,
    keys: Vec<KeyEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyEntry {
    key_id: String,
}

/// Load the configured key set, or report the fixed reason it is unusable.
pub(super) fn from_environment(backend: &crate::blob_store::BlobBackendIdentity) -> Result<Option<SessionTokens>> {
    match std::env::var_os(KEYRING_ENV) {
        None => Ok(None),
        Some(directory) => load(Path::new(&directory), backend).map(Some),
    }
}

/// Load one keyring directory. A malformed directory is a hard start-up
/// failure, never a fallback to an unauthenticated or default key.
pub(super) fn load(directory: &Path, backend: &crate::blob_store::BlobBackendIdentity) -> Result<SessionTokens> {
    ensure!(directory.is_absolute(), "{KEYRING_ENV} must be an absolute directory");
    let metadata =
        std::fs::symlink_metadata(directory).map_err(|_| anyhow!("{KEYRING_ENV} directory is not accessible"))?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o777 == 0o700,
        "{KEYRING_ENV} must be a private directory owned by the service user (mode 0700)"
    );
    let manifest_bytes = read_private(&directory.join(MANIFEST), MAX_MANIFEST_BYTES)?;
    let manifest: Manifest =
        serde_json::from_slice(&manifest_bytes).map_err(|_| anyhow!("session keyring manifest is invalid"))?;
    ensure!(manifest.schema == MANIFEST_SCHEMA, "session keyring schema is unsupported");
    ensure!(
        (MIN_LIFETIME_SECONDS..=MAX_LIFETIME_SECONDS).contains(&manifest.lifetime_seconds),
        "session keyring lifetime_seconds is outside {MIN_LIFETIME_SECONDS}..={MAX_LIFETIME_SECONDS}"
    );
    ensure!(!manifest.keys.is_empty() && manifest.keys.len() <= MAX_KEYS, "session keyring key count is invalid");
    let mut keys = Vec::with_capacity(manifest.keys.len());
    let mut current = None;
    for (position, entry) in manifest.keys.iter().enumerate() {
        ensure!(valid_key_id(&entry.key_id), "session keyring key_id must be a lowercase file-safe id");
        if entry.key_id == manifest.current {
            current = Some(u8::try_from(position).map_err(|_| anyhow!("session keyring key count is invalid"))?);
        }
        let mut bytes = read_private(&directory.join(format!("{}.key", entry.key_id)), KEY_BYTES)?;
        ensure!(bytes.len() as u64 == KEY_BYTES, "session key is not exactly 32 bytes");
        let material: [u8; 32] =
            bytes.as_slice().try_into().map_err(|_| anyhow!("session key is not exactly 32 bytes"))?;
        bytes.fill(0);
        keys.push((u8::try_from(position).map_err(|_| anyhow!("session keyring key count is invalid"))?, material));
    }
    let current = current.ok_or_else(|| anyhow!("session keyring has no current key"))?;
    let codec = SessionTokenCodec::new(keys, current, backend, manifest.lifetime_seconds)
        .map_err(|_| anyhow!("session keyring key set is unusable"))?;
    Ok(SessionTokens::new(codec))
}

fn valid_key_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_KEY_ID_LEN
        && id.bytes().next().is_some_and(|byte| byte.is_ascii_alphanumeric())
        && id.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.')
        && !id.contains("..")
        && !id.ends_with(".key")
}

/// Bounded read of one regular file that is owned by the effective uid, not a
/// link, and has mode exactly `0600`.
fn read_private(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| anyhow!("session keyring file is not accessible"))?;
    let meta = file.metadata().map_err(|_| anyhow!("session keyring file is not accessible"))?;
    ensure!(
        meta.is_file()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.mode() & 0o777 == 0o600
            && meta.len() <= limit,
        "session keyring file must be a private regular file (mode 0600) inside its size bound"
    );
    // Re-check the descriptor is the directory entry that was named.
    let named = std::fs::symlink_metadata(path).map_err(|_| anyhow!("session keyring file is not accessible"))?;
    ensure!(
        named.is_file() && !named.file_type().is_symlink() && named.dev() == meta.dev() && named.ino() == meta.ino(),
        "session keyring file changed while it was opened"
    );
    let mut bytes = Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0));
    (&file).take(limit + 1).read_to_end(&mut bytes).map_err(|_| anyhow!("session keyring file is not readable"))?;
    ensure!(bytes.len() as u64 <= limit, "session keyring file exceeds its size bound");
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::{DirBuilderExt, PermissionsExt},
        path::PathBuf,
    };

    fn backend() -> crate::blob_store::BlobBackendIdentity {
        crate::blob_store::test_support::distinct_backend_identities().0
    }

    struct Keyring {
        _root: tempfile::TempDir,
        directory: PathBuf,
    }

    impl Keyring {
        fn new(manifest: serde_json::Value, keys: &[(&str, usize)]) -> Self {
            let root = tempfile::tempdir().expect("temp root");
            let directory = root.path().join("ring");
            std::fs::DirBuilder::new().mode(0o700).create(&directory).expect("directory");
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).expect("dir mode");
            let text = serde_json::to_vec(&manifest).expect("manifest");
            std::fs::write(directory.join(MANIFEST), text).expect("manifest write");
            std::fs::set_permissions(directory.join(MANIFEST), std::fs::Permissions::from_mode(0o600)).expect("mode");
            for (id, len) in keys {
                let path = directory.join(format!("{id}.key"));
                std::fs::write(&path, vec![9u8; *len]).expect("key write");
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("mode");
            }
            Self { _root: root, directory }
        }

        fn manifest(current: &str) -> serde_json::Value {
            serde_json::json!({"schema": 1, "current": current, "lifetime_seconds": 120,
                "keys": [{"key_id": "v1"}, {"key_id": "v2"}]})
        }
    }

    #[test]
    fn a_private_keyring_loads_with_rotation_overlap() {
        let ring = Keyring::new(Keyring::manifest("v2"), &[("v1", 32), ("v2", 32)]);
        let tokens = load(&ring.directory, &backend()).expect("valid keyring");
        assert_eq!(tokens.lifetime_seconds(), 120);
    }

    #[test]
    fn insecure_or_malformed_keyrings_are_refused() {
        let target = backend();
        // Wrong key length.
        let ring = Keyring::new(Keyring::manifest("v2"), &[("v1", 31), ("v2", 32)]);
        assert!(load(&ring.directory, &target).is_err());
        // Unknown current id.
        let ring = Keyring::new(Keyring::manifest("v3"), &[("v1", 32), ("v2", 32)]);
        assert!(load(&ring.directory, &target).is_err());
        // Unbounded lifetime.
        let mut manifest = Keyring::manifest("v2");
        manifest["lifetime_seconds"] = serde_json::json!(MAX_LIFETIME_SECONDS + 1);
        let ring = Keyring::new(manifest, &[("v1", 32), ("v2", 32)]);
        assert!(load(&ring.directory, &target).is_err());
        // World-readable key file.
        let ring = Keyring::new(Keyring::manifest("v2"), &[("v1", 32), ("v2", 32)]);
        std::fs::set_permissions(ring.directory.join("v2.key"), std::fs::Permissions::from_mode(0o644)).expect("mode");
        assert!(load(&ring.directory, &target).is_err());
        // A symlinked key file is never followed, even to a private target.
        let ring = Keyring::new(Keyring::manifest("v2"), &[("v1", 32)]);
        let outside = ring.directory.parent().expect("parent").join("outside.key");
        std::fs::write(&outside, [7u8; 32]).expect("outside");
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o600)).expect("mode");
        std::os::unix::fs::symlink(&outside, ring.directory.join("v2.key")).expect("symlink");
        assert!(load(&ring.directory, &target).is_err());
        // Group-accessible directory.
        let ring = Keyring::new(Keyring::manifest("v2"), &[("v1", 32), ("v2", 32)]);
        std::fs::set_permissions(&ring.directory, std::fs::Permissions::from_mode(0o750)).expect("mode");
        assert!(load(&ring.directory, &target).is_err());
        // Relative path.
        assert!(load(Path::new("ring"), &target).is_err());
        // Duplicate ids.
        let mut manifest = Keyring::manifest("v2");
        manifest["keys"] = serde_json::json!([{"key_id": "v1"}, {"key_id": "v1"}]);
        let ring = Keyring::new(manifest, &[("v1", 32)]);
        assert!(load(&ring.directory, &target).is_err());
        // Path-like ids are refused.
        let mut manifest = Keyring::manifest("v2");
        manifest["keys"] = serde_json::json!([{"key_id": "../escape"}]);
        let ring = Keyring::new(manifest, &[]);
        assert!(load(&ring.directory, &target).is_err());
    }

    #[test]
    fn the_keyring_environment_is_optional_but_explicit() {
        // Absent configuration means no session support at all, never a
        // generated or default key.
        let target = backend();
        let before = std::env::var_os(KEYRING_ENV);
        // SAFETY: unit tests in this module are the only readers of this
        // variable and the test harness runs them on one thread per test; the
        // variable is restored before returning.
        unsafe { std::env::remove_var(KEYRING_ENV) };
        assert!(from_environment(&target).expect("absent keyring").is_none());
        if let Some(value) = before {
            unsafe { std::env::set_var(KEYRING_ENV, value) };
        }
    }
}
