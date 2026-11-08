//! Contract tests for the independent local-envelope `KeyProvider` (#109).
//!
//! These tests are local and always run; they use temporary keyrings, no Vault,
//! no provider service and no ignored provider case.
use std::{
    ffi::CString,
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
};

use rootyard::blob_store::key_provider::{
    DATA_KEY_BYTES, KeyId, KeyProvider, KeyProviderError, LocalFileKeyProvider, WrapContext, WrappedKey,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

const ID_V1: &str = "v1";
const ID_V2: &str = "v2";

fn key(seed: u8) -> [u8; DATA_KEY_BYTES] {
    [seed; DATA_KEY_BYTES]
}

fn hex_digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    set_mode(path, 0o600);
}

struct KeyRingFixture {
    dir: TempDir,
}

impl KeyRingFixture {
    fn new(entries: &[(&str, &[u8])], current: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        set_mode(dir.path(), 0o700);
        write_keyring(dir.path(), entries, current);
        Self { dir }
    }

    fn path(&self) -> PathBuf {
        dir_path(&self.dir)
    }

    fn provider(&self) -> LocalFileKeyProvider {
        LocalFileKeyProvider::load(&self.path()).unwrap()
    }
}

fn dir_path(dir: &TempDir) -> PathBuf {
    std::path::absolute(dir.path()).unwrap()
}

fn write_keyring(dir: &Path, entries: &[(&str, &[u8])], current: &str) {
    let keys: Vec<Value> = entries
        .iter()
        .map(|(id, bytes)| json!({ "key_id": id, "sha256": hex_digest(bytes) }))
        .collect();
    let manifest = json!({ "schema": 1, "current": current, "keys": keys });
    write_private(&dir.join("keyring.json"), &serde_json::to_vec(&manifest).unwrap());
    for (id, bytes) in entries {
        write_private(&dir.join(format!("{id}.key")), bytes);
    }
}

fn context(namespace: &str, digest_byte: u8) -> WrapContext {
    let digest = format!("{digest_byte:02x}").repeat(32);
    WrapContext::new(
        Uuid::from_bytes([1; 16]),
        Uuid::from_bytes([2; 16]),
        7,
        Uuid::from_bytes([3; 16]),
        namespace,
        &digest,
    )
    .unwrap()
}

/// Context whose every fixed-width field is the ASCII byte `a`, so shifting one
/// byte between the key id and the namespace leaves a naive concatenation of
/// all fields byte-identical.
fn collision_context(namespace: &str) -> WrapContext {
    let fixed = [b'a'; 16];
    WrapContext::new(
        Uuid::from_bytes(fixed),
        Uuid::from_bytes(fixed),
        i64::from_be_bytes([b'a'; 8]),
        Uuid::from_bytes(fixed),
        namespace,
        &"ab".repeat(32),
    )
    .unwrap()
}

/// Deliberately length-blind transcript: key id, tenant, authority,
/// generation, attempt, namespace and content digest concatenated without any
/// field framing.
fn naive_aad(key_id: &str, namespace: &str) -> Vec<u8> {
    let fixed = [b'a'; 16];
    let mut transcript = key_id.as_bytes().to_vec();
    transcript.extend_from_slice(&fixed); // tenant
    transcript.extend_from_slice(&fixed); // authority
    transcript.extend_from_slice(&i64::from_be_bytes([b'a'; 8]).to_be_bytes()); // generation
    transcript.extend_from_slice(&fixed); // attempt
    transcript.extend_from_slice(namespace.as_bytes());
    transcript.extend_from_slice("ab".repeat(32).as_bytes()); // content digest
    transcript
}

fn metadata_value(wrapped: &WrappedKey) -> Value {
    serde_json::from_str(&wrapped.to_json().unwrap()).unwrap()
}

fn parse_metadata(value: &Value) -> WrappedKey {
    WrappedKey::from_json(&serde_json::to_vec(value).unwrap()).unwrap()
}

fn flip_hex(value: &Value, field: &str, index: usize) -> String {
    let mut bytes = hex::decode(value[field].as_str().unwrap()).unwrap();
    bytes[index] ^= 0x01;
    hex::encode(bytes)
}

#[test]
fn roundtrip_uses_current_key_and_fresh_nonces() {
    let fixture = KeyRingFixture::new(&[(ID_V1, &key(7))], ID_V1);
    let provider = fixture.provider();
    let wrap_context = context("lfs", 0xab);
    let data_key = key(0x42);

    assert_eq!(provider.current_key_id().as_str(), ID_V1);
    let capabilities = provider.capabilities();
    assert!(capabilities.local_envelope && capabilities.rewrap && capabilities.retained_key_versions);
    assert!(!capabilities.provider_managed && !capabilities.plaintext_fallback);

    let first = provider.wrap_data_key(&data_key, &wrap_context).unwrap();
    let second = provider.wrap_data_key(&data_key, &wrap_context).unwrap();
    assert_eq!(first.key_id().as_str(), ID_V1);
    assert_eq!(first.version(), 1);
    assert_ne!(first.nonce(), second.nonce(), "every wrap must use a fresh 96-bit nonce");
    assert_ne!(first.wrapped_dek(), second.wrapped_dek());
    assert_eq!(first.aad_digest(), second.aad_digest());

    let first_plain = provider.unwrap_data_key(&first, &wrap_context).unwrap();
    let second_plain = provider.unwrap_data_key(&second, &wrap_context).unwrap();
    assert_eq!(first_plain.expose_secret(), &data_key);
    assert_eq!(second_plain.expose_secret(), &data_key);

    let restored = WrappedKey::from_json(first.to_json().unwrap().as_bytes()).unwrap();
    assert_eq!(restored, first);
    assert_eq!(provider.unwrap_data_key(&restored, &wrap_context).unwrap().expose_secret(), &data_key);
}

#[test]
fn tampered_ciphertext_nonce_aad_and_version_fail_closed() {
    let fixture = KeyRingFixture::new(&[(ID_V1, &key(9))], ID_V1);
    let provider = fixture.provider();
    let wrap_context = context("lfs", 0xcd);
    let wrapped = provider.wrap_data_key(&key(0x33), &wrap_context).unwrap();
    let original = metadata_value(&wrapped);

    let mut tampered = original.clone();
    tampered["wrapped_dek"] = Value::String(flip_hex(&original, "wrapped_dek", 3));
    assert_eq!(
        provider.unwrap_data_key(&parse_metadata(&tampered), &wrap_context).unwrap_err(),
        KeyProviderError::AuthenticationFailed
    );

    let mut tampered = original.clone();
    tampered["nonce"] = Value::String(flip_hex(&original, "nonce", 0));
    assert_eq!(
        provider.unwrap_data_key(&parse_metadata(&tampered), &wrap_context).unwrap_err(),
        KeyProviderError::AuthenticationFailed
    );

    let mut tampered = original.clone();
    tampered["aad_digest"] = Value::String(flip_hex(&original, "aad_digest", 31));
    assert_eq!(
        provider.unwrap_data_key(&parse_metadata(&tampered), &wrap_context).unwrap_err(),
        KeyProviderError::ContextMismatch
    );

    let mut tampered = original.clone();
    tampered["version"] = json!(2);
    assert_eq!(
        WrappedKey::from_json(&serde_json::to_vec(&tampered).unwrap()).unwrap_err(),
        KeyProviderError::UnsupportedVersion(2)
    );

    let other_context = context("workspace", 0xcd);
    assert_eq!(
        provider.unwrap_data_key(&wrapped, &other_context).unwrap_err(),
        KeyProviderError::ContextMismatch
    );
}

#[test]
fn wrapped_metadata_validation_rejects_bad_lengths_ids_and_oversize() {
    let fixture = KeyRingFixture::new(&[(ID_V1, &key(11))], ID_V1);
    let provider = fixture.provider();
    let wrap_context = context("blob", 0x01);
    let original = metadata_value(&provider.wrap_data_key(&key(0x22), &wrap_context).unwrap());

    let mut value = original.clone();
    value["extra"] = json!(true);
    assert!(matches!(
        WrappedKey::from_json(&serde_json::to_vec(&value).unwrap()),
        Err(KeyProviderError::InvalidWrappedKey(_))
    ));

    for (field, bytes) in [("nonce", 11usize), ("wrapped_dek", 47), ("aad_digest", 31)] {
        let mut value = original.clone();
        value[field] = Value::String("00".repeat(bytes));
        assert!(
            matches!(
                WrappedKey::from_json(&serde_json::to_vec(&value).unwrap()),
                Err(KeyProviderError::InvalidWrappedKey(_))
            ),
            "short {field} must be rejected"
        );
    }

    let mut value = original.clone();
    value["key_id"] = json!("../escape");
    assert!(matches!(
        WrappedKey::from_json(&serde_json::to_vec(&value).unwrap()),
        Err(KeyProviderError::InvalidKeyId)
    ));

    let mut oversized = serde_json::to_vec(&original).unwrap();
    oversized.resize(1025, b' ');
    assert!(matches!(
        WrappedKey::from_json(&oversized),
        Err(KeyProviderError::InvalidWrappedKey("metadata exceeds the size limit"))
    ));

    let mut value = original;
    value["key_id"] = json!("v9");
    let missing = parse_metadata(&value);
    assert_eq!(
        provider.unwrap_data_key(&missing, &wrap_context).unwrap_err(),
        KeyProviderError::MissingKey(KeyId::parse("v9").unwrap())
    );
}

#[test]
fn wrong_key_and_missing_key_file_fail_closed_without_generation() {
    let first = KeyRingFixture::new(&[(ID_V1, &key(1))], ID_V1);
    let second = KeyRingFixture::new(&[(ID_V1, &key(2))], ID_V1);
    let wrap_context = context("checkpoint", 0x44);
    let wrapped = first.provider().wrap_data_key(&key(0x55), &wrap_context).unwrap();
    assert_eq!(
        second.provider().unwrap_data_key(&wrapped, &wrap_context).unwrap_err(),
        KeyProviderError::AuthenticationFailed,
        "the same key id with different bytes must not decrypt"
    );

    let dir = tempfile::tempdir().unwrap();
    set_mode(dir.path(), 0o700);
    let fingerprint = hex_digest(&key(3));
    let manifest = json!({ "schema": 1, "current": ID_V1, "keys": [{ "key_id": ID_V1, "sha256": fingerprint }] });
    write_private(&dir.path().join("keyring.json"), &serde_json::to_vec(&manifest).unwrap());
    let error = LocalFileKeyProvider::load(&dir_path(&dir)).unwrap_err();
    assert!(matches!(error, KeyProviderError::KeyFile(_)));
    assert!(!dir.path().join("v1.key").exists(), "loading must never generate a missing key");
}

#[test]
fn rotation_keeps_old_reads_rewraps_to_current_and_preserves_the_dek() {
    let old = KeyRingFixture::new(&[(ID_V1, &key(0x10))], ID_V1);
    let wrap_context = context("lfs", 0x77);
    let data_key = key(0x66);
    let old_wrapped = old.provider().wrap_data_key(&data_key, &wrap_context).unwrap();
    assert_eq!(old_wrapped.key_id().as_str(), ID_V1);

    let rotated = KeyRingFixture::new(&[(ID_V1, &key(0x10)), (ID_V2, &key(0x20))], ID_V2);
    let provider = rotated.provider();
    assert_eq!(provider.current_key_id().as_str(), ID_V2);
    assert_eq!(provider.unwrap_data_key(&old_wrapped, &wrap_context).unwrap().expose_secret(), &data_key);

    let new_wrapped = provider.wrap_data_key(&data_key, &wrap_context).unwrap();
    assert_eq!(new_wrapped.key_id().as_str(), ID_V2, "new wraps must use the current key");

    let rewrapped = provider.rewrap_data_key(&old_wrapped, &wrap_context).unwrap();
    assert_eq!(rewrapped.key_id().as_str(), ID_V2);
    assert_ne!(rewrapped.nonce(), old_wrapped.nonce());
    assert_ne!(rewrapped.wrapped_dek(), old_wrapped.wrapped_dek());
    assert_ne!(rewrapped.aad_digest(), old_wrapped.aad_digest());
    assert_eq!(provider.unwrap_data_key(&rewrapped, &wrap_context).unwrap().expose_secret(), &data_key);
    assert_eq!(
        provider.unwrap_data_key(&old_wrapped, &wrap_context).unwrap().expose_secret(),
        &data_key,
        "rewrap must not make the retained old key unreadable"
    );

    let only_new = KeyRingFixture::new(&[(ID_V2, &key(0x20))], ID_V2);
    assert_eq!(
        only_new.provider().unwrap_data_key(&old_wrapped, &wrap_context).unwrap_err(),
        KeyProviderError::MissingKey(KeyId::parse(ID_V1).unwrap()),
        "a removed old key must fail closed rather than selecting another version"
    );
}

#[test]
fn length_delimited_aad_prevents_adjacent_field_collisions() {
    let bytes = key(0x31);
    let fixture = KeyRingFixture::new(&[(ID_V1, &bytes), ("v1a", &bytes)], ID_V1);
    let provider = fixture.provider();
    let first_id = KeyId::parse(ID_V1).unwrap();
    let second_id = KeyId::parse("v1a").unwrap();
    let first_context = collision_context("aa");
    let second_context = collision_context("a");

    assert_eq!(
        naive_aad(first_id.as_str(), "aa"),
        naive_aad(second_id.as_str(), "a"),
        "the fixture must collide when all fields are concatenated without lengths"
    );
    assert_ne!(
        first_context.aad(&first_id),
        second_context.aad(&second_id),
        "length framing must separate the shifted key-id byte from the namespace"
    );
    assert_ne!(first_context.aad_digest(&first_id), second_context.aad_digest(&second_id));

    let wrapped = provider.wrap_data_key(&key(0x99), &first_context).unwrap();
    assert_eq!(wrapped.key_id().as_str(), ID_V1);
    // Both ids are configured with the same KEK bytes, so only the AAD binding
    // can reject a wrap that is replayed under the other id and context.
    let mut value = metadata_value(&wrapped);
    value["key_id"] = json!("v1a");
    value["aad_digest"] = json!(hex::encode(second_context.aad_digest(&second_id)));
    assert_eq!(
        provider.unwrap_data_key(&parse_metadata(&value), &second_context).unwrap_err(),
        KeyProviderError::AuthenticationFailed,
        "a forged consistent AAD digest must still fail AEAD authentication"
    );
}

#[test]
fn rejects_malformed_key_files_modes_symlinks_and_fifos() {
    for length in [31usize, 33] {
        let dir = tempfile::tempdir().unwrap();
        set_mode(dir.path(), 0o700);
        let bytes = vec![0x5a; length];
        write_keyring(dir.path(), &[(ID_V1, bytes.as_slice())], ID_V1);
        assert!(
            matches!(LocalFileKeyProvider::load(&dir_path(&dir)), Err(KeyProviderError::KeyFile(_))),
            "key file length {length} must be refused"
        );
    }

    let fixture = KeyRingFixture::new(&[(ID_V1, &key(0x61))], ID_V1);
    set_mode(&fixture.path().join("v1.key"), 0o640);
    assert!(matches!(LocalFileKeyProvider::load(&fixture.path()), Err(KeyProviderError::KeyFile(_))));

    let fixture = KeyRingFixture::new(&[(ID_V1, &key(0x62))], ID_V1);
    write_private(&fixture.path().join("real.key"), &key(0x62));
    fs::remove_file(fixture.path().join("v1.key")).unwrap();
    symlink("real.key", fixture.path().join("v1.key")).unwrap();
    assert!(matches!(LocalFileKeyProvider::load(&fixture.path()), Err(KeyProviderError::KeyFile(_))));

    let dir = tempfile::tempdir().unwrap();
    set_mode(dir.path(), 0o700);
    let manifest = json!({
        "schema": 1,
        "current": ID_V1,
        "keys": [{ "key_id": ID_V1, "sha256": hex_digest(&key(0x63)) }]
    });
    write_private(&dir.path().join("keyring.json"), &serde_json::to_vec(&manifest).unwrap());
    let fifo_path = dir.path().join("v1.key");
    let fifo_name = CString::new(fifo_path.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: the path is a valid NUL-terminated test-owned path and mode 0600.
    assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
    assert!(
        matches!(LocalFileKeyProvider::load(&dir_path(&dir)), Err(KeyProviderError::KeyFile(_))),
        "a FIFO must be refused without being read"
    );

    let fixture = KeyRingFixture::new(&[(ID_V1, &key(0x64))], ID_V1);
    write_private(&fixture.path().join("v1.key"), &key(0x65));
    assert_eq!(
        LocalFileKeyProvider::load(&fixture.path()).unwrap_err(),
        KeyProviderError::KeyIdentityMismatch(KeyId::parse(ID_V1).unwrap()),
        "different bytes behind an existing id must not be accepted silently"
    );
}

#[test]
fn rejects_unsafe_keyring_directory_and_manifest_shapes() {
    assert!(matches!(
        LocalFileKeyProvider::load(Path::new("relative-keyring")),
        Err(KeyProviderError::KeyRing(_))
    ));

    let fixture = KeyRingFixture::new(&[(ID_V1, &key(0x71))], ID_V1);
    set_mode(&fixture.path(), 0o750);
    assert!(matches!(LocalFileKeyProvider::load(&fixture.path()), Err(KeyProviderError::KeyRing(_))));

    let fixture = KeyRingFixture::new(&[(ID_V1, &key(0x72))], ID_V1);
    let parent = tempfile::tempdir().unwrap();
    let link = parent.path().join("keyring-link");
    symlink(fixture.path(), &link).unwrap();
    assert!(matches!(LocalFileKeyProvider::load(&link), Err(KeyProviderError::KeyRing(_))));

    let fixture = KeyRingFixture::new(&[(ID_V1, &key(0x73))], ID_V1);
    set_mode(&fixture.path().join("keyring.json"), 0o644);
    assert!(matches!(LocalFileKeyProvider::load(&fixture.path()), Err(KeyProviderError::KeyRing(_))));

    let fixture = KeyRingFixture::new(&[(ID_V1, &key(0x74))], ID_V1);
    fs::remove_file(fixture.path().join("keyring.json")).unwrap();
    assert!(matches!(LocalFileKeyProvider::load(&fixture.path()), Err(KeyProviderError::KeyRing(_))));

    let dir = tempfile::tempdir().unwrap();
    set_mode(dir.path(), 0o700);
    write_keyring(dir.path(), &[(ID_V1, &key(0x75))], ID_V2);
    assert!(
        matches!(LocalFileKeyProvider::load(&dir_path(&dir)), Err(KeyProviderError::KeyRing(_))),
        "an unlisted current key id must be refused"
    );

    let dir = tempfile::tempdir().unwrap();
    set_mode(dir.path(), 0o700);
    let duplicate = json!({
        "schema": 1,
        "current": ID_V1,
        "keys": [
            { "key_id": ID_V1, "sha256": hex_digest(&key(0x76)) },
            { "key_id": ID_V1, "sha256": hex_digest(&key(0x77)) }
        ]
    });
    write_private(&dir.path().join("keyring.json"), &serde_json::to_vec(&duplicate).unwrap());
    assert!(matches!(LocalFileKeyProvider::load(&dir_path(&dir)), Err(KeyProviderError::KeyRing(_))));

    let dir = tempfile::tempdir().unwrap();
    set_mode(dir.path(), 0o700);
    write_private(&dir.path().join("keyring.json"), &vec![b' '; 16 * 1024 + 1]);
    assert!(matches!(LocalFileKeyProvider::load(&dir_path(&dir)), Err(KeyProviderError::KeyRing(_))));
}

#[test]
fn debug_and_serialization_redact_all_key_material() {
    let kek = key(0x3c);
    let fixture = KeyRingFixture::new(&[(ID_V1, &kek)], ID_V1);
    let provider = fixture.provider();
    let wrap_context = context("workspace", 0x3c);
    let wrapped = provider.wrap_data_key(&key(0x4d), &wrap_context).unwrap();
    let data_key = provider.unwrap_data_key(&wrapped, &wrap_context).unwrap();
    let kek_hex = hex::encode(kek);
    let dek_hex = hex::encode(data_key.expose_secret());

    let provider_debug = format!("{provider:?}");
    assert!(provider_debug.contains("<redacted>"));
    assert!(!provider_debug.contains(&kek_hex));

    let wrapped_debug = format!("{wrapped:?}");
    for secret in [
        hex::encode(wrapped.nonce()),
        hex::encode(wrapped.wrapped_dek()),
        hex::encode(wrapped.aad_digest()),
        ID_V1.to_string(),
    ] {
        assert!(!wrapped_debug.contains(&secret), "wrapped Debug leaked {secret}");
    }

    assert_eq!(format!("{data_key:?}"), "DataKey(<redacted>)");
    assert!(!format!("{data_key:?}").contains(&dek_hex));

    let json = wrapped.to_json().unwrap();
    assert!(!json.contains(&kek_hex));
    assert!(!json.contains(&dek_hex));
    let value: Value = serde_json::from_str(&json).unwrap();
    let keys: std::collections::BTreeSet<&str> = value.as_object().unwrap().keys().map(String::as_str).collect();
    let expected: std::collections::BTreeSet<&str> =
        ["version", "key_id", "nonce", "wrapped_dek", "aad_digest"].into_iter().collect();
    assert_eq!(keys, expected);

    let error = provider.unwrap_data_key(&wrapped, &context("other", 0x3c)).unwrap_err();
    assert!(!format!("{error:?}").contains(&kek_hex));
    assert!(!format!("{error:?}").contains(&dek_hex));
    assert!(format!("{error}").contains("AAD"));
}
