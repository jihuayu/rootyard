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

pub(super) const KEYRING_ENV: &str = "ROOTYARD_SESSION_KEYRING";
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
mod tests {
    use super::*;
    use crate::{
        blob_git_gateway::repo_session::{
            SESSION_HEADER, SessionRealm, SessionTokenError, VersionComparison, presented_for_test as presented,
        },
        ref_store::GitObjectFormat,
    };
    use axum::http::{HeaderMap, HeaderName, HeaderValue};
    use std::{
        os::unix::fs::{DirBuilderExt, PermissionsExt},
        path::PathBuf,
    };
    use uuid::Uuid;

    /// One synthetic identity for the whole module: every `load` call may use
    /// it, because the MAC covers the backend digest and a per-call identity
    /// would silently differ between two loads of the same keyring.
    fn backend() -> crate::blob_store::BlobBackendIdentity {
        crate::blob_store::test_support::blob_backend_identity("session-keyring-tests")
    }

    struct Keyring {
        _root: tempfile::TempDir,
        directory: PathBuf,
    }

    impl Keyring {
        /// Synthetic fixtures only: key bytes are `fill`-derived, never real
        /// user material, and every file is created by the test itself.
        fn new(manifest: serde_json::Value, keys: &[(&str, u8, usize)]) -> Self {
            let root = tempfile::tempdir().expect("temp root");
            let directory = root.path().join("ring");
            std::fs::DirBuilder::new().mode(0o700).create(&directory).expect("directory");
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).expect("dir mode");
            let text = serde_json::to_vec(&manifest).expect("manifest");
            std::fs::write(directory.join(MANIFEST), text).expect("manifest write");
            std::fs::set_permissions(directory.join(MANIFEST), std::fs::Permissions::from_mode(0o600)).expect("mode");
            for (id, fill, len) in keys {
                write_key(&directory, id, *fill, *len);
            }
            Self { _root: root, directory }
        }

        fn manifest(current: &str) -> serde_json::Value {
            serde_json::json!({"schema": 2, "current": current, "lifetime_seconds": 120,
                "keys": [{"key_id": "v1", "id": 17}, {"key_id": "v2", "id": 42}]})
        }

        fn load(&self) -> Result<SessionTokens> {
            load(&self.directory, &backend())
        }
    }

    fn write_key(directory: &Path, id: &str, fill: u8, len: usize) {
        let path = directory.join(format!("{id}.key"));
        std::fs::write(&path, vec![fill; len]).expect("key write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("mode");
    }

    /// A token issued by the codec itself: its body is canonical base64url,
    /// unlike a `rs1.<arbitrary>.mac` header probe.
    fn issue(tokens: &SessionTokens, live: &SessionRealm, revision: i64) -> String {
        tokens.issue_for_test(live, revision).expect("issue").token().to_owned()
    }

    /// The gateway entry point: header in, `Option<VersionComparison>` out.
    fn verify_header(
        tokens: &SessionTokens,
        token: &str,
        live: &SessionRealm,
        revision: i64,
    ) -> Result<Option<VersionComparison>, SessionTokenError> {
        tokens.verify(&presented(&header_presented(token)).expect("presented"), live, revision)
    }

    fn realm() -> SessionRealm {
        SessionRealm::new(
            Uuid::from_bytes([1; 16]),
            Uuid::from_bytes([2; 16]),
            GitObjectFormat::Sha1,
            Uuid::from_bytes([3; 16]),
            1,
            1,
            Uuid::from_bytes([4; 16]),
        )
        .expect("realm")
    }

    /// Present one token exactly as the gateway will: through the request header.
    fn header_presented(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(HeaderName::from_static(SESSION_HEADER), HeaderValue::from_str(token).expect("header value"));
        headers
    }

    fn key_id_byte(token: &str) -> u8 {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        URL_SAFE_NO_PAD.decode(token.split('.').nth(1).expect("body")).expect("b64")[2]
    }

    #[test]
    fn a_private_keyring_loads_with_rotation_overlap() {
        let ring = Keyring::new(Keyring::manifest("v2"), &[("v1", 1, 32), ("v2", 2, 32)]);
        let tokens = ring.load().expect("valid keyring");
        assert_eq!(tokens.lifetime_seconds(), 120);
    }

    #[test]
    fn retiring_a_listed_key_keeps_the_ids_of_the_remaining_keys() {
        let live = realm();
        // The retired key v1 (id 17) is first in the list; v2 (id 42) is current
        // and m1 (id 200) is listed while it waits for its turn.
        let ring = Keyring::new(
            serde_json::json!({"schema": 2, "current": "v2", "lifetime_seconds": 120,
                "keys": [{"key_id": "v1", "id": 17}, {"key_id": "v2", "id": 42}, {"key_id": "m1", "id": 200}]}),
            &[("v1", 1, 32), ("v2", 2, 32), ("m1", 3, 32)],
        );
        let tokens = ring.load().expect("valid keyring");
        // The real v2-signed token issued before v1 is retired, and a real
        // v1-signed token over the same realm: same realm and bound, different
        // MAC, because each key signs with its own explicit id.
        let after = issue(&tokens, &live, 4);
        assert_eq!(key_id_byte(&after), 42, "current key carries its explicit id");
        let old = Keyring::new(
            serde_json::json!({"schema": 2, "current": "v1", "lifetime_seconds": 120,
                "keys": [{"key_id": "v1", "id": 17}, {"key_id": "v2", "id": 42}, {"key_id": "m1", "id": 200}]}),
            &[("v1", 1, 32), ("v2", 2, 32), ("m1", 3, 32)],
        );
        let before = issue(&old.load().expect("valid keyring"), &live, 4);
        assert_eq!(key_id_byte(&before), 17);
        assert_ne!(before, after);
        assert_eq!(verify_header(&tokens, &before, &live, 4), Ok(Some(VersionComparison::Satisfied { bound: 4 })));
        assert_eq!(verify_header(&tokens, &after, &live, 4), Ok(Some(VersionComparison::Satisfied { bound: 4 })));

        // Retire v1 (the first entry) and keep v2 current.
        let retired = Keyring::new(
            serde_json::json!({"schema": 2, "current": "v2", "lifetime_seconds": 120,
                "keys": [{"key_id": "v2", "id": 42}, {"key_id": "m1", "id": 200}]}),
            &[("v2", 2, 32), ("m1", 3, 32)],
        );
        let tokens = retired.load().expect("valid keyring");
        // The v1-signed token is refused at once, not after one lifetime.
        assert_eq!(
            verify_header(&tokens, &before, &live, 4),
            Err(SessionTokenError::Invalid),
            "retired key no longer verifies"
        );
        // The v2 token issued before v1 was retired still verifies: v2 keeps
        // id 42 instead of shifting into v1's freed first list position.
        assert_eq!(verify_header(&tokens, &after, &live, 4), Ok(Some(VersionComparison::Satisfied { bound: 4 })));
        let fresh = issue(&tokens, &live, 4);
        assert_eq!(key_id_byte(&fresh), 42);
        assert_eq!(verify_header(&tokens, &fresh, &live, 4), Ok(Some(VersionComparison::Satisfied { bound: 4 })));
        // The new token is also refused against a lagging authoritative gate.
        assert_eq!(verify_header(&tokens, &fresh, &live, 3), Ok(Some(VersionComparison::Behind { live_revision: 3 })));

        // Rotation by overlap: v2 (old current) and m1 (new current) both verify
        // the tokens they really signed, and only m1 signs new ones.
        let overlap = Keyring::new(
            serde_json::json!({"schema": 2, "current": "m1", "lifetime_seconds": 120,
                "keys": [{"key_id": "v2", "id": 42}, {"key_id": "m1", "id": 200}]}),
            &[("v2", 2, 32), ("m1", 3, 32)],
        );
        let overlap = overlap.load().expect("valid keyring");
        assert_eq!(verify_header(&overlap, &after, &live, 4), Ok(Some(VersionComparison::Satisfied { bound: 4 })));
        let current = issue(&overlap, &live, 4);
        assert_eq!(key_id_byte(&current), 200);
        assert_eq!(verify_header(&overlap, &current, &live, 4), Ok(Some(VersionComparison::Satisfied { bound: 4 })));
        // Once m1 is current, retiring v2 refuses the v2-signed token at once
        // and leaves the m1-signed one working.
        let no_v2 = Keyring::new(
            serde_json::json!({"schema": 2, "current": "m1", "lifetime_seconds": 120,
                "keys": [{"key_id": "m1", "id": 200}]}),
            &[("m1", 3, 32)],
        );
        let no_v2 = no_v2.load().expect("valid keyring");
        assert_eq!(verify_header(&no_v2, &after, &live, 4), Err(SessionTokenError::Invalid));
        assert_eq!(verify_header(&no_v2, &current, &live, 4), Ok(Some(VersionComparison::Satisfied { bound: 4 })));
    }

    #[test]
    fn a_duplicate_key_file_never_lets_list_order_pick_the_current_key() {
        let live = realm();
        // Two ids for one file, both claiming to be current. If order decided,
        // swapping the list would swap the signer; it must fail to load instead.
        for keys in [
            serde_json::json!([{"key_id": "v1", "id": 17}, {"key_id": "v2", "id": 42}, {"key_id": "v1", "id": 5}]),
            serde_json::json!([{"key_id": "v1", "id": 5}, {"key_id": "v2", "id": 42}, {"key_id": "v1", "id": 17}]),
        ] {
            let mut manifest = Keyring::manifest("v1");
            manifest["keys"] = keys;
            let ring = Keyring::new(manifest, &[("v1", 1, 32), ("v2", 2, 32)]);
            assert!(ring.load().is_err(), "a key file named twice must never load");
        }
        // A unique id per file still loads and signs with its explicit id.
        let ring = Keyring::new(
            serde_json::json!({"schema": 2, "current": "v1", "lifetime_seconds": 120,
                "keys": [{"key_id": "v1", "id": 5}, {"key_id": "v2", "id": 42}]}),
            &[("v1", 1, 32), ("v2", 2, 32)],
        );
        let tokens = ring.load().expect("valid keyring");
        assert_eq!(key_id_byte(&issue(&tokens, &live, 3)), 5);
    }

    #[test]
    fn a_retired_first_key_stops_verifying_while_the_new_current_key_keeps_its_id() {
        let live = realm();
        // v1 id 17 is first in the list and current; v2 id 42 is already
        // listed for rotation.
        let old = Keyring::new(
            serde_json::json!({"schema": 2, "current": "v1", "lifetime_seconds": 120,
                "keys": [{"key_id": "v1", "id": 17}, {"key_id": "v2", "id": 42}]}),
            &[("v1", 1, 32), ("v2", 2, 32)],
        );
        let old = old.load().expect("valid keyring");
        // The v1-signed token: real MAC by v1 over the same realm and bound.
        let v1_token = issue(&old, &live, 5);
        assert_eq!(key_id_byte(&v1_token), 17, "current key carries its explicit id");
        assert_eq!(verify_header(&old, &v1_token, &live, 5), Ok(Some(VersionComparison::Satisfied { bound: 5 })));

        // Rotate: v2 becomes current while v1 stays listed for overlap. The v2
        // token is a real MAC by v2 at the very same realm, bound and list.
        let rotated = Keyring::new(
            serde_json::json!({"schema": 2, "current": "v2", "lifetime_seconds": 120,
                "keys": [{"key_id": "v1", "id": 17}, {"key_id": "v2", "id": 42}]}),
            &[("v1", 1, 32), ("v2", 2, 32)],
        );
        let rotated = rotated.load().expect("valid keyring");
        let v2_token = issue(&rotated, &live, 5);
        assert_eq!(key_id_byte(&v2_token), 42, "v2 signs with its own id, never v1's list position");
        // Overlap really overlaps: both real tokens verify side by side.
        assert_eq!(verify_header(&rotated, &v1_token, &live, 5), Ok(Some(VersionComparison::Satisfied { bound: 5 })));
        assert_eq!(verify_header(&rotated, &v2_token, &live, 5), Ok(Some(VersionComparison::Satisfied { bound: 5 })));

        // Retire v1 (the first entry). v2 keeps id 42 — it does not shift into
        // the freed first position — so the v2 token still verifies, while the
        // v1 token is refused immediately (not after one more lifetime).
        let retired = Keyring::new(
            serde_json::json!({"schema": 2, "current": "v2", "lifetime_seconds": 120,
                "keys": [{"key_id": "v2", "id": 42}]}),
            &[("v2", 2, 32)],
        );
        let tokens = retired.load().expect("valid keyring");
        assert_eq!(verify_header(&tokens, &v2_token, &live, 5), Ok(Some(VersionComparison::Satisfied { bound: 5 })));
        assert_eq!(verify_header(&tokens, &v1_token, &live, 5), Err(SessionTokenError::Invalid));
        // A fresh token still says 42 and is valid; the live revision is still
        // scored for real, so a lagging authoritative gate is Behind.
        let fresh = issue(&tokens, &live, 6);
        assert_eq!(key_id_byte(&fresh), 42);
        assert_eq!(verify_header(&tokens, &fresh, &live, 6), Ok(Some(VersionComparison::Satisfied { bound: 6 })));
        assert_eq!(verify_header(&tokens, &fresh, &live, 5), Ok(Some(VersionComparison::Behind { live_revision: 5 })));
    }

    #[test]
    fn a_key_id_keeps_verifying_when_list_position_changes() {
        let live = realm();
        let first = Keyring::new(Keyring::manifest("v2"), &[("v1", 1, 32), ("v2", 2, 32)]);
        let issued = issue(&first.load().expect("valid"), &live, 2);
        // Reorder (v2 first) without changing ids: nothing re-labels.
        let reordered = Keyring::new(
            serde_json::json!({"schema": 2, "current": "v2", "lifetime_seconds": 120,
                "keys": [{"key_id": "v2", "id": 42}, {"key_id": "v1", "id": 17}]}),
            &[("v1", 1, 32), ("v2", 2, 32)],
        );
        let reordered = reordered.load().expect("valid");
        assert!(verify_header(&reordered, &issued, &live, 2).expect("verify").is_some());
        // A set that forgets v1's id refuses the same token.
        let without = Keyring::new(
            serde_json::json!({"schema": 2, "current": "v2", "lifetime_seconds": 120,
                "keys": [{"key_id": "v2", "id": 18}]}),
            &[("v2", 2, 32)],
        );
        let without = without.load().expect("valid");
        assert_eq!(verify_header(&without, &issued, &live, 2), Err(SessionTokenError::Invalid));
    }

    #[test]
    fn insecure_or_malformed_keyrings_are_refused() {
        let target = backend();
        // Wrong key length.
        let ring = Keyring::new(Keyring::manifest("v2"), &[("v1", 1, 31), ("v2", 2, 32)]);
        assert!(load(&ring.directory, &target).is_err());
        // Unknown current id.
        let ring = Keyring::new(Keyring::manifest("v3"), &[("v1", 1, 32), ("v2", 2, 32)]);
        assert!(load(&ring.directory, &target).is_err());
        // Unbounded lifetime.
        let mut manifest = Keyring::manifest("v2");
        manifest["lifetime_seconds"] = serde_json::json!(MAX_LIFETIME_SECONDS + 1);
        let ring = Keyring::new(manifest, &[("v1", 1, 32), ("v2", 2, 32)]);
        assert!(load(&ring.directory, &target).is_err());
        // World-readable key file.
        let ring = Keyring::new(Keyring::manifest("v2"), &[("v1", 1, 32), ("v2", 2, 32)]);
        std::fs::set_permissions(ring.directory.join("v2.key"), std::fs::Permissions::from_mode(0o644)).expect("mode");
        assert!(load(&ring.directory, &target).is_err());
        // A symlinked key file is never followed, even to a private target.
        let ring = Keyring::new(Keyring::manifest("v2"), &[("v1", 1, 32)]);
        let outside = ring.directory.parent().expect("parent").join("outside.key");
        std::fs::write(&outside, [7u8; 32]).expect("outside");
        std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o600)).expect("mode");
        std::os::unix::fs::symlink(&outside, ring.directory.join("v2.key")).expect("symlink");
        assert!(load(&ring.directory, &target).is_err());
        // Group-accessible directory.
        let ring = Keyring::new(Keyring::manifest("v2"), &[("v1", 1, 32), ("v2", 2, 32)]);
        std::fs::set_permissions(&ring.directory, std::fs::Permissions::from_mode(0o750)).expect("mode");
        assert!(load(&ring.directory, &target).is_err());
        // The keyring directory itself is never a symlink.
        let real = Keyring::new(Keyring::manifest("v2"), &[("v1", 1, 32), ("v2", 2, 32)]);
        let link = real.directory.parent().expect("parent").join("ring-link");
        std::os::unix::fs::symlink(&real.directory, &link).expect("symlink");
        assert!(load(&link, &target).is_err());
        // Relative path.
        assert!(load(Path::new("ring"), &target).is_err());
        // Duplicate ids.
        let mut manifest = Keyring::manifest("v2");
        manifest["keys"] = serde_json::json!([{"key_id": "v1", "id": 17}, {"key_id": "v2", "id": 17}]);
        let ring = Keyring::new(manifest, &[("v1", 1, 32), ("v2", 2, 32)]);
        assert!(load(&ring.directory, &target).is_err());
        // One key file may not be named by two entries: with ids 17 and 18 the
        // current key would depend on which duplicate happens to be listed
        // last, so this is refused whatever the order.
        for keys in [
            serde_json::json!([{"key_id": "v1", "id": 17}, {"key_id": "v2", "id": 18}, {"key_id": "v1", "id": 42}]),
            serde_json::json!([{"key_id": "v2", "id": 42}, {"key_id": "v2", "id": 18}, {"key_id": "v1", "id": 17}]),
        ] {
            let mut manifest = Keyring::manifest("v2");
            manifest["keys"] = keys;
            let ring = Keyring::new(manifest, &[("v1", 1, 32), ("v2", 2, 32)]);
            assert!(load(&ring.directory, &target).is_err(), "duplicate key_id file");
        }
        // Path-like ids are refused.
        let mut manifest = Keyring::manifest("v2");
        manifest["keys"] = serde_json::json!([{"key_id": "../escape", "id": 17}]);
        let ring = Keyring::new(manifest, &[]);
        assert!(load(&ring.directory, &target).is_err());
        // Schema 1 (the positional-id format) is not silently reinterpreted.
        let mut manifest = Keyring::manifest("v2");
        manifest["schema"] = serde_json::json!(1);
        let ring = Keyring::new(manifest, &[("v1", 1, 32), ("v2", 2, 32)]);
        assert!(load(&ring.directory, &target).is_err());
        // An entry without an explicit id has no positional fallback.
        let mut manifest = Keyring::manifest("v2");
        manifest["keys"] = serde_json::json!([{"key_id": "v1"}, {"key_id": "v2", "id": 42}]);
        let ring = Keyring::new(manifest, &[("v1", 1, 32), ("v2", 2, 32)]);
        assert!(load(&ring.directory, &target).is_err());
        // An id outside the one-byte range is refused.
        let mut manifest = Keyring::manifest("v2");
        manifest["keys"] = serde_json::json!([{"key_id": "v1", "id": 256}, {"key_id": "v2", "id": 42}]);
        let ring = Keyring::new(manifest, &[("v1", 1, 32), ("v2", 2, 32)]);
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
