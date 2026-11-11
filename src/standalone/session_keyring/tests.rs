//! Keyring loader tests: rotation, modes, symlinks and strict schemas.
use super::*;
use crate::{
    blob_git_gateway::repo_session::{
        AuthorityKind, SESSION_HEADER, SessionRealm, SessionRealmFields, SessionTokenError, VersionComparison,
        presented_for_test as presented,
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
    SessionRealm::new(SessionRealmFields {
        tenant_id: Uuid::from_bytes([1; 16]),
        repository_id: Uuid::from_bytes([2; 16]),
        object_format: GitObjectFormat::Sha1,
        history_incarnation: Uuid::from_bytes([3; 16]),
        authority: AuthorityKind::PgRefStore,
        authority_epoch: 1,
        group_id: 0,
        group_epoch: 1,
        cluster_incarnation: Uuid::from_bytes([4; 16]),
    })
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

#[test]
fn deny_unknown_fields_rejects_extra_manifest_and_key_entry_keys() {
    // The root manifest is a closed schema: an operator typo must fail startup
    // instead of being ignored while the service runs with a different policy.
    let mut manifest = Keyring::manifest("v2");
    manifest["unexpected_policy"] = serde_json::json!(true);
    let ring = Keyring::new(manifest, &[("v1", 1, 32), ("v2", 2, 32)]);
    assert!(load(&ring.directory, &backend()).is_err(), "unknown manifest field must be refused");

    // Each key entry is equally closed: an unknown per-key field cannot be
    // silently dropped from the signed-key configuration.
    let mut manifest = Keyring::manifest("v2");
    manifest["keys"][0]["unexpected_id_alias"] = serde_json::json!(9);
    let ring = Keyring::new(manifest, &[("v1", 1, 32), ("v2", 2, 32)]);
    assert!(load(&ring.directory, &backend()).is_err(), "unknown key-entry field must be refused");
}
