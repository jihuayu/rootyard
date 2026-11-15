//! Unit tests for explicit encryption policy, chunked AES-256-GCM
//! envelopes, key rotation / rewrap, and fail-closed verification.

use std::{collections::BTreeMap, fs::Permissions, os::unix::fs::PermissionsExt, path::Path, sync::Arc};

use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

use super::{
    BlobError,
    budget::ResourceLimits,
    config::BlobProfile,
    encryption_config::{BlobEncryptionConfig, BlobEncryptionMode, ENV_BLOB_ENCRYPTION_MODE, ENV_BLOB_KEYRING_DIR},
    envelope::{
        ENVELOPE_CHUNK_BYTES, EnvelopeError, EnvelopeMetadata, EnvelopeSpec, open_ciphertext_file_to_path,
        prepare_file_envelope, rewrap_envelope_metadata,
    },
    key_provider::{
        DATA_KEY_BYTES, DataKey, KeyId, KeyProvider, KeyProviderCapabilities, KeyProviderError, LocalFileKeyProvider,
        WrapContext, WrappedKey,
    },
    opendal::BlobStore,
    test_support::{deadline, distinct_backend_identities, payload, store, write_source},
};

fn write_keyring(dir: &Path, current: &str, keys: &[(&str, [u8; 32])]) {
    std::fs::set_permissions(dir, Permissions::from_mode(0o700)).expect("chmod dir");
    let mut entries = Vec::new();
    for (id, secret) in keys {
        let key_path = dir.join(format!("{id}.key"));
        std::fs::write(&key_path, secret).expect("write key");
        std::fs::set_permissions(&key_path, Permissions::from_mode(0o600)).expect("chmod key");
        let sha = hex::encode(Sha256::digest(secret));
        entries.push(serde_json::json!({ "key_id": id, "sha256": sha }));
    }
    let manifest = serde_json::json!({ "schema": 1, "current": current, "keys": entries });
    let manifest_path = dir.join("keyring.json");
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest).expect("json")).expect("write manifest");
    std::fs::set_permissions(&manifest_path, Permissions::from_mode(0o600)).expect("chmod manifest");
}

fn encrypted_memory_store(keyring_dir: &Path) -> BlobStore {
    let limits = ResourceLimits::new(2, 4, 8 << 20).expect("limits");
    let resources = Arc::new(super::budget::ResourceContext::new(limits));
    let profile = BlobProfile::memory_profile(limits)
        .with_encryption(BlobEncryptionConfig::local_envelope(keyring_dir.to_path_buf()).expect("enc cfg"));
    BlobStore::open_memory(profile, resources)
}

fn lookup_from<'a>(vars: &'a BTreeMap<&'a str, &'a str>) -> impl FnMut(&str) -> Result<Option<String>, BlobError> + 'a {
    move |name: &str| Ok(vars.get(name).map(|v| (*v).to_owned()))
}

#[derive(Debug)]
struct BadCapabilityProvider {
    key_id: KeyId,
    caps: KeyProviderCapabilities,
}

impl KeyProvider for BadCapabilityProvider {
    fn current_key_id(&self) -> &KeyId {
        &self.key_id
    }

    fn wrap_data_key(
        &self,
        _data_key: &[u8; DATA_KEY_BYTES],
        _ctx: &WrapContext,
    ) -> Result<WrappedKey, KeyProviderError> {
        Err(KeyProviderError::CipherSetup)
    }

    fn unwrap_data_key(&self, _wrapped: &WrappedKey, _ctx: &WrapContext) -> Result<DataKey, KeyProviderError> {
        Err(KeyProviderError::AuthenticationFailed)
    }

    fn capabilities(&self) -> KeyProviderCapabilities {
        self.caps
    }
}

#[derive(Debug)]
struct ReplaceableProviderAdapter {
    inner: Arc<dyn KeyProvider>,
    allow_rewrap: bool,
}

impl KeyProvider for ReplaceableProviderAdapter {
    fn current_key_id(&self) -> &KeyId {
        self.inner.current_key_id()
    }

    fn wrap_data_key(
        &self,
        data_key: &[u8; DATA_KEY_BYTES],
        ctx: &WrapContext,
    ) -> Result<WrappedKey, KeyProviderError> {
        self.inner.wrap_data_key(data_key, ctx)
    }

    fn unwrap_data_key(&self, wrapped: &WrappedKey, ctx: &WrapContext) -> Result<DataKey, KeyProviderError> {
        self.inner.unwrap_data_key(wrapped, ctx)
    }

    fn capabilities(&self) -> KeyProviderCapabilities {
        let mut caps = self.inner.capabilities();
        caps.rewrap = self.allow_rewrap;
        caps
    }
}

#[test]
fn encryption_config_enforces_explicit_modes_and_rejects_vault_or_plaintext() {
    let empty = BTreeMap::new();
    let compat = BlobEncryptionConfig::parse_with(lookup_from(&empty), false).expect("compat default");
    assert_eq!(compat.mode(), &BlobEncryptionMode::ProviderManaged);
    assert!(!compat.is_explicit());
    assert!(compat.require_explicit().is_err());
    assert!(BlobEncryptionConfig::parse_with(lookup_from(&empty), true).is_err());

    let explicit_pm = BTreeMap::from([(ENV_BLOB_ENCRYPTION_MODE, "provider-managed")]);
    let cfg = BlobEncryptionConfig::parse_with(lookup_from(&explicit_pm), true).expect("provider-managed");
    assert!(cfg.is_explicit());
    assert!(cfg.is_provider_managed());

    let keyring = TempDir::new().expect("tempdir");
    let dir_str = keyring.path().to_str().expect("utf8");
    let explicit_le = BTreeMap::from([(ENV_BLOB_ENCRYPTION_MODE, "local-envelope"), (ENV_BLOB_KEYRING_DIR, dir_str)]);
    let le_cfg = BlobEncryptionConfig::parse_with(lookup_from(&explicit_le), true).expect("local-envelope");
    assert!(le_cfg.is_local_envelope());

    for bad_mode in ["vault", "vault-transit", "plaintext", "none", "disabled", "", "custom"] {
        let vars = BTreeMap::from([(ENV_BLOB_ENCRYPTION_MODE, bad_mode)]);
        assert!(BlobEncryptionConfig::parse_with(lookup_from(&vars), false).is_err(), "mode `{bad_mode}` must fail");
    }

    let missing_dir = BTreeMap::from([(ENV_BLOB_ENCRYPTION_MODE, "local-envelope")]);
    assert!(BlobEncryptionConfig::parse_with(lookup_from(&missing_dir), true).is_err());

    let unexpected_dir =
        BTreeMap::from([(ENV_BLOB_ENCRYPTION_MODE, "provider-managed"), (ENV_BLOB_KEYRING_DIR, dir_str)]);
    assert!(BlobEncryptionConfig::parse_with(lookup_from(&unexpected_dir), true).is_err());

    let dangling_dir = BTreeMap::from([(ENV_BLOB_KEYRING_DIR, dir_str)]);
    assert!(BlobEncryptionConfig::parse_with(lookup_from(&dangling_dir), false).is_err());

    let rel_dir =
        BTreeMap::from([(ENV_BLOB_ENCRYPTION_MODE, "local-envelope"), (ENV_BLOB_KEYRING_DIR, "relative/keyring")]);
    assert!(BlobEncryptionConfig::parse_with(lookup_from(&rel_dir), true).is_err());
}

#[tokio::test]
async fn encrypted_upload_and_readback_roundtrips_empty_and_multichunk_payloads() {
    let keyring = TempDir::new().expect("keyring");
    write_keyring(keyring.path(), "k1", &[("k1", [0x11u8; 32])]);
    let blob = encrypted_memory_store(keyring.path());
    let kp = blob.profile().open_key_provider().expect("open kp").expect("local kp");

    let staging = TempDir::new().expect("staging");
    let out_dir = TempDir::new().expect("out");
    let tenant = Uuid::new_v4();
    let authority = Uuid::new_v4();

    for (idx, size) in [0usize, ENVELOPE_CHUNK_BYTES * 2 + 123].into_iter().enumerate() {
        let data = payload(size);
        let src = staging.path().join(format!("plain-{idx}.bin"));
        std::fs::write(&src, &data).expect("write src");

        let spec =
            EnvelopeSpec { tenant_id: tenant, authority_id: authority, generation: 3, namespace: "packs".into() };
        let prepared = prepare_file_envelope(&spec, &src, staging.path(), 8 << 20).expect("prepare");
        let intent = blob
            .new_upload(tenant, authority, 3, "packs", prepared.ciphertext_sha256(), prepared.ciphertext_length())
            .expect("intent");
        let sealed = prepared.bind_and_wrap(kp.as_ref(), intent.locator()).expect("wrap");
        let (receipt, metadata) = blob.put_encrypted_file(intent, sealed, deadline()).await.expect("put encrypted");

        let raw = blob.operator().read(&receipt.locator().path()).await.expect("raw read").to_bytes();
        assert_ne!(raw.as_ref(), data.as_slice(), "stored blob bytes must be ciphertext, not plaintext");

        let restored = out_dir.path().join(format!("restored-{idx}.bin"));
        let enc_receipt = blob
            .get_decrypted_to_file(receipt.locator(), &metadata, &kp, &restored, deadline())
            .await
            .expect("decrypt readback");
        assert_eq!(std::fs::read(&restored).expect("read restored"), data);
        assert_eq!(enc_receipt.plaintext_length(), data.len() as u64);
        assert_eq!(enc_receipt.key_id().as_str(), "k1");
    }
}

#[tokio::test]
async fn key_rotation_rewraps_metadata_and_retired_old_keys_fail_closed() {
    let keyring = TempDir::new().expect("keyring");
    write_keyring(keyring.path(), "k1", &[("k1", [0x21u8; 32])]);
    let blob = encrypted_memory_store(keyring.path());
    let kp_v1 = blob.profile().open_key_provider().expect("open kp v1").expect("kp");

    let work = TempDir::new().expect("work");
    let data = payload(ENVELOPE_CHUNK_BYTES + 77);
    let src = write_source(work.path(), &data);
    let tenant = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let spec = EnvelopeSpec { tenant_id: tenant, authority_id: authority, generation: 1, namespace: "packs".into() };
    let prepared = prepare_file_envelope(&spec, &src, work.path(), 8 << 20).expect("prepare");
    let intent = blob
        .new_upload(tenant, authority, 1, "packs", prepared.ciphertext_sha256(), prepared.ciphertext_length())
        .expect("intent");
    let sealed = prepared.bind_and_wrap(kp_v1.as_ref(), intent.locator()).expect("wrap");
    let (receipt, metadata_v1) = blob.put_encrypted_file(intent, sealed, deadline()).await.expect("upload");

    // Step 1: Rotate keyring to k2 while temporarily retaining k1, then rewrap metadata.
    write_keyring(keyring.path(), "k2", &[("k1", [0x21u8; 32]), ("k2", [0x42u8; 32])]);
    let kp_v1_and_v2: Arc<dyn KeyProvider> = Arc::new(LocalFileKeyProvider::load(keyring.path()).expect("load v1+v2"));
    let metadata_v2 = rewrap_envelope_metadata(&metadata_v1, kp_v1_and_v2.as_ref()).expect("rewrap");
    assert_eq!(metadata_v2.key_id().expect("key id").as_str(), "k2");
    assert_eq!(metadata_v2.ciphertext_sha256(), metadata_v1.ciphertext_sha256());

    // Step 2: Retire k1 completely. Rewrapped metadata succeeds; old v1 metadata MUST fail closed.
    std::fs::remove_file(keyring.path().join("k1.key")).expect("delete k1");
    write_keyring(keyring.path(), "k2", &[("k2", [0x42u8; 32])]);
    let kp_v2_only: Arc<dyn KeyProvider> = Arc::new(LocalFileKeyProvider::load(keyring.path()).expect("load v2"));

    let old_verify =
        blob.verify_encrypted_blob(receipt.locator(), &metadata_v1, &kp_v2_only, work.path(), deadline()).await;
    assert!(matches!(old_verify, Err(EnvelopeError::KeyProvider(KeyProviderError::MissingKey(_)))));

    let new_dest = work.path().join("after-rotate.bin");
    let ok = blob
        .get_decrypted_to_file(receipt.locator(), &metadata_v2, &kp_v2_only, &new_dest, deadline())
        .await
        .expect("v2 decrypt");
    assert_eq!(ok.key_id().as_str(), "k2");
    assert_eq!(std::fs::read(&new_dest).expect("read decrypted"), data);
}

#[tokio::test]
async fn corrupted_ciphertext_reordered_chunks_and_tampered_metadata_fail_closed() {
    let keyring = TempDir::new().expect("keyring");
    write_keyring(keyring.path(), "k1", &[("k1", [0x33u8; 32])]);
    let blob = encrypted_memory_store(keyring.path());
    let kp = blob.profile().open_key_provider().expect("open kp").expect("kp");

    let work = TempDir::new().expect("work");
    let data = payload(ENVELOPE_CHUNK_BYTES * 2 + 17);
    let src = write_source(work.path(), &data);
    let tenant = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let spec = EnvelopeSpec { tenant_id: tenant, authority_id: authority, generation: 2, namespace: "packs".into() };
    let prepared = prepare_file_envelope(&spec, &src, work.path(), 8 << 20).expect("prepare");
    let intent = blob
        .new_upload(tenant, authority, 2, "packs", prepared.ciphertext_sha256(), prepared.ciphertext_length())
        .expect("intent");
    let locator = intent.locator().clone();
    let sealed = prepared.bind_and_wrap(kp.as_ref(), &locator).expect("wrap");
    let ct_copy = work.path().join("local-ct.bin");
    std::fs::copy(sealed.ciphertext_path(), &ct_copy).expect("copy ct");
    let (_receipt, metadata) = blob.put_encrypted_file(intent, sealed, deadline()).await.expect("upload");

    // Wrong key bytes with matching metadata fails closed during unwrap/decrypt.
    let wrong_keyring = TempDir::new().expect("wrong keyring");
    write_keyring(wrong_keyring.path(), "k1", &[("k1", [0x99u8; 32])]);
    let wrong_kp: Arc<dyn KeyProvider> = Arc::new(LocalFileKeyProvider::load(wrong_keyring.path()).expect("wrong kp"));
    assert!(matches!(
        blob.verify_encrypted_blob(&locator, &metadata, &wrong_kp, work.path(), deadline()).await,
        Err(EnvelopeError::KeyProvider(KeyProviderError::AuthenticationFailed))
    ));

    // Reject unknown JSON fields in EnvelopeMetadata (#[serde(deny_unknown_fields)]).
    let mut json_val: serde_json::Value = serde_json::from_str(&metadata.to_json().expect("json")).expect("parse");
    json_val["unexpected"] = serde_json::Value::Bool(true);
    let raw_extra = serde_json::to_vec(&json_val).expect("serialize");
    assert!(matches!(EnvelopeMetadata::from_json(&raw_extra), Err(EnvelopeError::MetadataCorrupt(_))));

    // Tampered local ciphertext: bit flip, chunk swap, truncation, trailing garbage.
    let mut ct_bytes = std::fs::read(&ct_copy).expect("read ct");
    let bad_flip = work.path().join("flip.ct");
    let mut flipped = ct_bytes.clone();
    flipped[5] ^= 0xff;
    std::fs::write(&bad_flip, &flipped).expect("write flip");
    assert!(open_ciphertext_file_to_path(&metadata, kp.as_ref(), &bad_flip, &work.path().join("o1")).is_err());

    let chunk_stride = ENVELOPE_CHUNK_BYTES + 16;
    let mut swapped = ct_bytes.clone();
    let (first, rest) = swapped.split_at_mut(chunk_stride);
    first.swap_with_slice(&mut rest[..chunk_stride]);
    let bad_swap = work.path().join("swap.ct");
    std::fs::write(&bad_swap, &swapped).expect("write swap");
    assert!(open_ciphertext_file_to_path(&metadata, kp.as_ref(), &bad_swap, &work.path().join("o2")).is_err());

    ct_bytes.pop();
    let bad_trunc = work.path().join("trunc.ct");
    std::fs::write(&bad_trunc, &ct_bytes).expect("write trunc");
    assert!(open_ciphertext_file_to_path(&metadata, kp.as_ref(), &bad_trunc, &work.path().join("o3")).is_err());

    // Remote ciphertext corruption fails closed too.
    blob.operator().write(&locator.path(), flipped).await.expect("corrupt remote");
    assert!(blob.verify_encrypted_blob(&locator, &metadata, &kp, work.path(), deadline()).await.is_err());
}

#[tokio::test]
async fn policy_and_capability_guards_reject_plaintext_fallback_and_foreign_intents() {
    let keyring = TempDir::new().expect("keyring");
    write_keyring(keyring.path(), "k1", &[("k1", [0x55u8; 32])]);
    let enc_store = encrypted_memory_store(keyring.path());
    let (plain_store, _) = store(ResourceLimits::new(2, 4, 8 << 20).expect("limits"));
    let explicit_pm_store = {
        let limits = ResourceLimits::new(2, 4, 8 << 20).expect("limits");
        let resources = Arc::new(super::budget::ResourceContext::new(limits));
        BlobStore::open_memory(
            BlobProfile::memory_profile(limits).with_encryption(BlobEncryptionConfig::provider_managed()),
            resources,
        )
    };
    let kp = enc_store.profile().open_key_provider().expect("open kp").expect("kp");

    let work = TempDir::new().expect("work");
    let src = write_source(work.path(), &payload(100));
    let tenant = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let spec = EnvelopeSpec { tenant_id: tenant, authority_id: authority, generation: 1, namespace: "packs".into() };
    let prepared = prepare_file_envelope(&spec, &src, work.path(), 8 << 20).expect("prepare");

    // Plaintext fallback / non-envelope providers are rejected fail-closed.
    let bad_fallback: Arc<dyn KeyProvider> = Arc::new(BadCapabilityProvider {
        key_id: KeyId::parse("bad").expect("key id"),
        caps: KeyProviderCapabilities {
            local_envelope: true,
            rewrap: true,
            retained_key_versions: false,
            provider_managed: false,
            plaintext_fallback: true,
        },
    });
    assert!(matches!(
        enc_store
            .verify_encrypted_blob(
                &enc_store
                    .new_upload(
                        tenant,
                        authority,
                        1,
                        "packs",
                        prepared.ciphertext_sha256(),
                        prepared.ciphertext_length()
                    )
                    .expect("intent")
                    .locator()
                    .clone(),
                &{
                    let prep2 = prepare_file_envelope(&spec, &src, work.path(), 8 << 20).expect("prep2");
                    let int2 = enc_store
                        .new_upload(tenant, authority, 1, "packs", prep2.ciphertext_sha256(), prep2.ciphertext_length())
                        .expect("int2");
                    prep2.bind_and_wrap(kp.as_ref(), int2.locator()).expect("wrap").metadata().clone()
                },
                &bad_fallback,
                work.path(),
                deadline(),
            )
            .await,
        Err(EnvelopeError::EncryptionPolicyMismatch)
    ));

    // Foreign backend intent fails before provider IO.
    let foreign_intent = plain_store
        .new_upload(tenant, authority, 1, "packs", prepared.ciphertext_sha256(), prepared.ciphertext_length())
        .expect("foreign intent");
    let sealed = prepared.bind_and_wrap(kp.as_ref(), foreign_intent.locator()).expect("wrap");
    assert!(matches!(
        enc_store.put_encrypted_file(foreign_intent, sealed, deadline()).await,
        Err(EnvelopeError::ForeignBackend)
    ));

    // Store with explicit ProviderManaged policy refuses LocalEnvelope put/verify.
    let prep3 = prepare_file_envelope(&spec, &src, work.path(), 8 << 20).expect("prep3");
    let pm_intent = explicit_pm_store
        .new_upload(tenant, authority, 1, "packs", prep3.ciphertext_sha256(), prep3.ciphertext_length())
        .expect("pm intent");
    let pm_sealed = prep3.bind_and_wrap(kp.as_ref(), pm_intent.locator()).expect("wrap");
    assert!(matches!(
        explicit_pm_store.put_encrypted_file(pm_intent, pm_sealed, deadline()).await,
        Err(EnvelopeError::EncryptionPolicyMismatch)
    ));

    // Replaceable KeyProvider with rewrap: false refuses metadata rewrap cleanly.
    let no_rewrap: Arc<dyn KeyProvider> =
        Arc::new(ReplaceableProviderAdapter { inner: Arc::clone(&kp), allow_rewrap: false });
    let prep4 = prepare_file_envelope(&spec, &src, work.path(), 8 << 20).expect("prep4");
    let i4 = enc_store
        .new_upload(tenant, authority, 1, "packs", prep4.ciphertext_sha256(), prep4.ciphertext_length())
        .expect("i4");
    let s4 = prep4.bind_and_wrap(no_rewrap.as_ref(), i4.locator()).expect("wrap");
    assert!(matches!(rewrap_envelope_metadata(s4.metadata(), no_rewrap.as_ref()), Err(EnvelopeError::Config(_))));

    let _ = distinct_backend_identities();
}
