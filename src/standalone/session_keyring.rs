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
//!   { "schema": 2, "current": "v2", "lifetime_seconds": 300,
//!     "keys": [ { "key_id": "v1", "id": 17 }, { "key_id": "v2", "id": 42 } ] }
//!   ```
//!
//! * each `<key_id>.key` is a regular file, owner euid, mode exactly `0600`,
//!   containing exactly 32 bytes of private random key material. Every
//!   `key_id` may appear at most once: one file never carries two ids.
//!
//! Key bytes are read into `Zeroizing` buffers and moved into the codec as
//! `Zeroizing<[u8; 32]>` owners, so the loaded key lives in one owner buffer
//! that is wiped on drop. That is a buffer-lifetime guarantee only; it does not
//! claim that no register or HMAC-internal copy of the bytes ever exists.
//!
//! `id` is the **explicit, stable** one-byte key id that the signed token frame
//! carries, so it must be unique inside the manifest and is never derived from
//! the entry's list position. Writing an id is mandatory: a manifest that omits
//! it is refused (there is no positional fallback), and once assigned an id is
//! never reused for different key material. The list order is irrelevant.
//!
//! ## Rotation and retirement
//!
//! 1. Generate a fresh key file with a new `key_id` and an unused `id`.
//! 2. Add it to `keys` and point `current` at it; restart the service. Tokens
//!    signed by the old key still verify while it stays listed.
//! 3. Retire the old key: remove its entry from `keys`, keep the new `current`,
//!    restart. Tokens it signed are refused immediately at the next request
//!    (they are not accepted for "one more lifetime"), and because ids are
//!    explicit the new key keeps its own id and every new token stays valid.
//! 4. Delete the retired `<key_id>.key` file once no process serves with it.
//!
//! ## Migrating from schema 1 (positional ids)
//!
//! Schema 1 numbered keys by list position. In the schema 1 → 2 migration, give
//! entry *i* of the old list `id = i` (0, 1, 2, …), in the old order, and set
//! `current` to the old current entry's name. Every token issued by a schema 1
//! process then keeps verifying and every new token carries the id the old
//! code would have used, so no in-flight token is broken by the switch. From
//! then on list order is irrelevant. A schema 1 manifest is never
//! reinterpreted at runtime: serving from it is refused until it is migrated
//! explicitly, and there is no positional fallback.
//!
//! Never log, print or copy key bytes, and never assign a retired `id` to a
//! different key: a token still in flight under the retired id would then be
//! verified by unrelated material. Loading performs only bounded local reads
//! and never creates, repairs or replaces a key.
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};

use anyhow::{Result, anyhow, ensure};
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::blob_git_gateway::repo_session::{
    MAX_LIFETIME_SECONDS, MIN_LIFETIME_SECONDS, SessionTokenCodec, SessionTokens,
};

pub(crate) const KEYRING_ENV: &str = "ROOTYARD_SESSION_KEYRING";
const MANIFEST: &str = "keyring.json";
const MANIFEST_SCHEMA: u32 = 2;
const MAX_MANIFEST_BYTES: usize = 16 * 1024;
const MAX_KEYS: usize = 256;
const KEY_BYTES: usize = 32;
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
    /// Explicit stable one-byte key id carried by signed tokens.
    id: u8,
}

/// Load the configured key set, or report the fixed reason it is unusable.
pub(crate) fn from_environment(backend: &crate::blob_store::BlobBackendIdentity) -> Result<Option<SessionTokens>> {
    match std::env::var_os(KEYRING_ENV) {
        None => Ok(None),
        Some(directory) => load(Path::new(&directory), backend).map(Some),
    }
}

/// Load one keyring directory. A malformed directory is a hard start-up
/// failure, never a fallback to an unauthenticated or default key.
pub(crate) fn load(directory: &Path, backend: &crate::blob_store::BlobBackendIdentity) -> Result<SessionTokens> {
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
    let mut ids = HashSet::new();
    let mut ids_by_name = HashMap::new();
    let mut current = None;
    for entry in &manifest.keys {
        ensure!(valid_key_id(&entry.key_id), "session keyring key_id must be a lowercase file-safe id");
        // Two entries may never name the same key file: the current key would
        // then depend on list order, and one file would carry two ids.
        ensure!(!ids_by_name.contains_key(&entry.key_id), "session keyring key_id files must be unique");
        ensure!(ids.insert(entry.id), "session keyring key ids must be unique");
        if entry.key_id == manifest.current {
            current = Some(entry.id);
        }
        ids_by_name.insert(entry.key_id.clone(), entry.id);
        let bytes = read_private(&directory.join(format!("{}.key", entry.key_id)), KEY_BYTES)?;
        ensure!(bytes.len() == KEY_BYTES, "session key is not exactly 32 bytes");
        // The buffer is moved into its `Zeroizing` owner, so the key exists in
        // exactly one owner slot that wipes itself on drop. The codec copies it
        // once more into its own `Zeroizing` slot for that key id (that one
        // intermediate array is wiped immediately after the move).
        let mut material: Zeroizing<[u8; 32]> = Zeroizing::new([0u8; 32]);
        material.copy_from_slice(&bytes);
        keys.push((entry.id, material));
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
/// link, and has mode exactly `0600`. The returned buffer is a `Zeroizing`
/// owner from allocation to drop, so key bytes never live in an unwiped heap
/// copy.
fn read_private(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
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
            && meta.len() <= limit as u64,
        "session keyring file must be a private regular file (mode 0600) inside its size bound"
    );
    // Re-check the descriptor is the directory entry that was named.
    let named = std::fs::symlink_metadata(path).map_err(|_| anyhow!("session keyring file is not accessible"))?;
    ensure!(
        named.is_file() && !named.file_type().is_symlink() && named.dev() == meta.dev() && named.ino() == meta.ino(),
        "session keyring file changed while it was opened"
    );
    let mut bytes = Zeroizing::new(Vec::with_capacity(usize::try_from(meta.len()).unwrap_or(0).min(limit)));
    (&file)
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow!("session keyring file is not readable"))?;
    ensure!(bytes.len() <= limit, "session keyring file exceeds its size bound");
    Ok(bytes)
}

#[cfg(test)]
mod tests;
