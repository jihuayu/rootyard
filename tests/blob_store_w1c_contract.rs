//! Public crate-boundary contract tests for Issue #109 (`blob_store` W1-C):
//! explicit encryption configuration (without Vault dependency), replaceable
//! `KeyProvider` envelopes, fail-closed old-key/tampering rejection, and
//! isolated TTL-bounded disposable views.

use std::{
    fs::Permissions,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use rootyard::blob_store::{
    BlobLocator,
    disposable_view::{DisposableViewError, DisposableViewRoot},
    encryption_config::{BlobEncryptionConfig, BlobEncryptionMode, ENV_BLOB_ENCRYPTION_MODE, ENV_BLOB_KEYRING_DIR},
    envelope::{
        ENVELOPE_CHUNK_BYTES, EnvelopeMetadata, EnvelopeSpec, open_ciphertext_file_to_path, prepare_file_envelope,
        rewrap_envelope_metadata,
    },
    key_provider::{KeyProvider, KeyProviderError, LocalFileKeyProvider},
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct EnvResetGuard {
    saved_mode: Option<std::ffi::OsString>,
    saved_dir: Option<std::ffi::OsString>,
}

impl Drop for EnvResetGuard {
    fn drop(&mut self) {
        // SAFETY: serialized via ENV_LOCK for the test process.
        unsafe {
            match &self.saved_mode {
                Some(val) => std::env::set_var(ENV_BLOB_ENCRYPTION_MODE, val),
                None => std::env::remove_var(ENV_BLOB_ENCRYPTION_MODE),
            }
            match &self.saved_dir {
                Some(val) => std::env::set_var(ENV_BLOB_KEYRING_DIR, val),
                None => std::env::remove_var(ENV_BLOB_KEYRING_DIR),
            }
        }
    }
}

fn write_keyring(dir: &Path, current: &str, keys: &[(&str, [u8; 32])]) {
    std::fs::set_permissions(dir, Permissions::from_mode(0o700)).expect("chmod dir");
    let mut entries = Vec::new();
    for (id, secret) in keys {
        let key_path = dir.join(format!("{id}.key"));
        std::fs::write(&key_path, secret).expect("write key");
        std::fs::set_permissions(&key_path, Permissions::from_mode(0o600)).expect("chmod key");
        entries.push(serde_json::json!({ "key_id": id, "sha256": hex::encode(Sha256::digest(secret)) }));
    }
    let manifest = serde_json::json!({ "schema": 1, "current": current, "keys": entries });
    let manifest_path = dir.join("keyring.json");
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest).expect("json")).expect("write manifest");
    std::fs::set_permissions(&manifest_path, Permissions::from_mode(0o600)).expect("chmod manifest");
}

#[test]
fn env_encryption_policy_requires_no_vault_and_rejects_ambiguous_settings() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    let _reset = EnvResetGuard {
        saved_mode: std::env::var_os(ENV_BLOB_ENCRYPTION_MODE),
        saved_dir: std::env::var_os(ENV_BLOB_KEYRING_DIR),
    };
    let keyring = TempDir::new().expect("keyring");
    write_keyring(keyring.path(), "k1", &[("k1", [0x44u8; 32])]);

    // SAFETY: protected by ENV_LOCK across env-mutating tests.
    unsafe {
        std::env::set_var(ENV_BLOB_ENCRYPTION_MODE, "vault-transit");
        std::env::remove_var(ENV_BLOB_KEYRING_DIR);
    }
    assert!(BlobEncryptionConfig::from_env().is_err());
    assert!(BlobEncryptionConfig::from_env_strict().is_err());

    // SAFETY: protected by ENV_LOCK across env-mutating tests.
    unsafe {
        std::env::set_var(ENV_BLOB_ENCRYPTION_MODE, "local-envelope");
        std::env::set_var(ENV_BLOB_KEYRING_DIR, keyring.path());
    }
    let cfg = BlobEncryptionConfig::from_env_strict().expect("strict local-envelope");
    assert!(matches!(cfg.mode(), BlobEncryptionMode::LocalEnvelope { .. }));
    let provider = cfg.open_key_provider().expect("open kp").expect("local kp");
    assert_eq!(provider.current_key_id().as_str(), "k1");
}

#[test]
fn public_envelope_sealing_rotation_and_fail_closed_tamper_contract() {
    let keyring = TempDir::new().expect("keyring");
    write_keyring(keyring.path(), "k1", &[("k1", [0x12u8; 32])]);
    let kp_v1: Arc<dyn KeyProvider> = Arc::new(LocalFileKeyProvider::load(keyring.path()).expect("kp v1"));

    let work = TempDir::new().expect("work");
    let plaintext: Vec<u8> = (0..(ENVELOPE_CHUNK_BYTES + 511)).map(|i| (i % 251) as u8).collect();
    let src = work.path().join("archive.pack");
    std::fs::write(&src, &plaintext).expect("write src");

    let tenant = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let spec = EnvelopeSpec { tenant_id: tenant, authority_id: authority, generation: 9, namespace: "packs".into() };
    let prepared = prepare_file_envelope(&spec, &src, work.path(), 16 << 20).expect("prepare");
    let locator = BlobLocator::new(
        tenant,
        authority,
        9,
        Uuid::new_v4(),
        "packs",
        prepared.ciphertext_sha256(),
        prepared.ciphertext_length(),
    )
    .expect("locator");
    let sealed = prepared.bind_and_wrap(kp_v1.as_ref(), &locator).expect("wrap");
    let ct_path = work.path().join("sealed.ct");
    std::fs::copy(sealed.ciphertext_path(), &ct_path).expect("copy ct");
    let meta_v1 = sealed.metadata().clone();
    drop(sealed);

    // Rotate to k2 while keeping k1, rewrap metadata, then remove k1 completely.
    write_keyring(keyring.path(), "k2", &[("k1", [0x12u8; 32]), ("k2", [0x34u8; 32])]);
    let kp_both: Arc<dyn KeyProvider> = Arc::new(LocalFileKeyProvider::load(keyring.path()).expect("both"));
    let meta_v2_json = rewrap_envelope_metadata(&meta_v1, kp_both.as_ref()).expect("rewrap").to_json().expect("json");

    std::fs::remove_file(keyring.path().join("k1.key")).expect("retire k1");
    write_keyring(keyring.path(), "k2", &[("k2", [0x34u8; 32])]);
    let kp_v2: Arc<dyn KeyProvider> = Arc::new(LocalFileKeyProvider::load(keyring.path()).expect("v2"));

    assert!(matches!(
        open_ciphertext_file_to_path(&meta_v1, kp_v2.as_ref(), &ct_path, &work.path().join("fail.out")),
        Err(ref err) if matches!(err, rootyard::blob_store::envelope::EnvelopeError::KeyProvider(KeyProviderError::MissingKey(_)))
    ));

    let meta_v2 = EnvelopeMetadata::from_json(meta_v2_json.as_bytes()).expect("parse v2");
    let ok_out = work.path().join("ok.out");
    let verified = open_ciphertext_file_to_path(&meta_v2, kp_v2.as_ref(), &ct_path, &ok_out).expect("open v2");
    assert_eq!(verified.length(), plaintext.len() as u64);
    assert_eq!(std::fs::read(&ok_out).expect("read out"), plaintext);

    // Dispose view isolation check from public crate boundary.
    let views = TempDir::new().expect("views");
    let view_root = DisposableViewRoot::open(&views.path().join("scratch"), 2, 1 << 20, Duration::from_secs(30))
        .expect("open root");
    let lease =
        view_root.create_view("git-receive", tenant, authority, 4096, Some(Duration::from_millis(25))).expect("lease");
    std::thread::sleep(Duration::from_millis(60));
    assert!(matches!(lease.repo_path(), Err(DisposableViewError::Expired)));
}
