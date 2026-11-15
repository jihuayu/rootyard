//! Three-mode encryption policy matrix (`unset`, `provider-managed`,
//! `local-envelope`), zero-IO preflight proofs over a loopback listener,
//! single-read ciphertext verification, and ProtectedUploader hold alignment.

use std::{
    fs::Permissions,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::watch,
    task::JoinHandle,
};
use uuid::Uuid;

use crate::ref_store::core::artifact_hold::{HoldAck, HoldArtifactIdentity};

use super::{
    BlobError, BlobLocator, BlobProvider,
    budget::{ResourceContext, ResourceLimits},
    closure::{BlobClosureEncryption, BlobClosureError, BlobClosureSpec, ClosureArtifactRole, ClosureEntrySpec},
    config::BlobProfile,
    encrypted_transfer::preflight_prepared_against_holds,
    encryption_config::BlobEncryptionConfig,
    envelope::{EnvelopeError, EnvelopeMetadata, EnvelopeSpec, prepare_file_envelope},
    key_provider::{KeyProvider, LocalFileKeyProvider},
    opendal::BlobStore,
    protected::{ProtectedUploadError, ProtectedUploader},
    test_support::{deadline, digest, payload, store, upload, write_source},
};

struct Counting503Gate {
    endpoint: String,
    hits: Arc<AtomicUsize>,
    shutdown: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

impl Counting503Gate {
    async fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind 503 loopback");
        let addr = listener.local_addr().expect("loopback addr");
        let hits = Arc::new(AtomicUsize::new(0));
        let task_hits = Arc::clone(&hits);
        let (shutdown, mut rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((mut stream, _)) = accepted else { break; };
                        task_hits.fetch_add(1, Ordering::SeqCst);
                        tokio::spawn(async move {
                            let mut buf = [0u8; 2048];
                            let _ = tokio::time::timeout(Duration::from_millis(50), stream.read(&mut buf)).await;
                            let _ = stream
                                .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                                .await;
                            let _ = stream.shutdown().await;
                        });
                    }
                    changed = rx.changed() => {
                        if changed.is_err() || *rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });
        Self { endpoint: format!("http://{addr}"), hits, shutdown, task: Some(task) }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }

    fn reset(&self) {
        self.hits.store(0, Ordering::SeqCst);
    }

    fn open_s3_store(&self, enc: BlobEncryptionConfig) -> BlobStore {
        let limits = ResourceLimits::new(2, 4, 4 << 20).expect("limits");
        let resources = Arc::new(ResourceContext::new(limits));
        let profile = BlobProfile::memory_profile(limits)
            .with_test_endpoint(&self.endpoint)
            .expect("test endpoint")
            .with_encryption(enc);
        BlobStore::open_with_resources(profile, resources).expect("open loopback s3 store")
    }
}

impl Drop for Counting503Gate {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        if let Some(task) = self.task.take() {
            task.abort();
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

fn open_memory_with_enc(enc: BlobEncryptionConfig) -> BlobStore {
    let limits = ResourceLimits::new(2, 4, 8 << 20).expect("limits");
    let resources = Arc::new(ResourceContext::new(limits));
    BlobStore::open_memory(BlobProfile::memory_profile(limits).with_encryption(enc), resources)
}

fn seal_for_intent(
    store: &BlobStore,
    kp: &dyn KeyProvider,
    work: &Path,
    tenant: Uuid,
    authority: Uuid,
    generation: i64,
    bytes: &[u8],
) -> (super::UploadIntent, BlobLocator, super::envelope::SealedCiphertext, EnvelopeMetadata) {
    let src = work.join(format!("plain-{}.bin", Uuid::new_v4().simple()));
    std::fs::write(&src, bytes).expect("write plain");
    let spec = EnvelopeSpec { tenant_id: tenant, authority_id: authority, generation, namespace: "packs".into() };
    let prepared = prepare_file_envelope(&spec, &src, work, 8 << 20).expect("prepare");
    let intent = store
        .new_upload(tenant, authority, generation, "packs", prepared.ciphertext_sha256(), prepared.ciphertext_length())
        .expect("intent");
    let locator = intent.locator().clone();
    let sealed = prepared.bind_and_wrap(kp, &locator).expect("bind and wrap");
    let meta = sealed.metadata().clone();
    (intent, locator, sealed, meta)
}

#[tokio::test]
async fn three_mode_policy_matrix_enforces_fail_closed_zero_io_contract() {
    let gate = Counting503Gate::start().await;
    let keyring = TempDir::new().expect("keyring");
    write_keyring(keyring.path(), "k1", &[("k1", [0x5au8; 32])]);
    let kp: Arc<dyn KeyProvider> = Arc::new(LocalFileKeyProvider::load(keyring.path()).expect("kp"));

    let work = TempDir::new().expect("work");
    let plain_bytes = payload(4096);
    let plain_path = write_source(work.path(), &plain_bytes);
    let tenant = Uuid::new_v4();
    let authority = Uuid::new_v4();

    let store_unset = gate.open_s3_store(BlobEncryptionConfig::implicit_provider_managed());
    let store_pm = gate.open_s3_store(BlobEncryptionConfig::provider_managed());
    let store_le = gate.open_s3_store(BlobEncryptionConfig::local_envelope(keyring.path().to_path_buf()).expect("le"));
    assert_eq!(gate.hits(), 0, "opening stores must perform zero network IO");

    let pm_locator = BlobLocator::new(tenant, authority, 1, Uuid::new_v4(), "packs", &digest(&plain_bytes), 4096)
        .expect("pm locator");
    let pm_closure = BlobClosureSpec::new(
        tenant,
        authority,
        1,
        BlobClosureEncryption::ProviderManaged,
        vec![ClosureEntrySpec::provider_managed(ClosureArtifactRole::Archive, pm_locator.clone())],
    )
    .expect("pm closure");

    let (_, _, _, le_meta) = seal_for_intent(&store_le, kp.as_ref(), work.path(), tenant, authority, 1, &plain_bytes);
    let le_locator = le_meta_locator(&le_meta);
    let le_closure = BlobClosureSpec::new(
        tenant,
        authority,
        1,
        BlobClosureEncryption::LocalEnvelope,
        vec![
            ClosureEntrySpec::local_envelope(ClosureArtifactRole::Archive, le_locator.clone(), le_meta.clone())
                .expect("le entry"),
        ],
    )
    .expect("le closure");

    // 1. Non-local modes (`unset` and explicit `provider-managed`) allow plaintext
    //    operations while refusing ALL `local-envelope` paths with ZERO TCP IO.
    for store in [&store_unset, &store_pm] {
        assert!(ProtectedUploader::new(store.clone()).preflight_plain_upload_policy().is_ok());

        gate.reset();
        let raw_res = store.put_file(upload(store, "packs", &plain_bytes), &plain_path, deadline()).await;
        assert!(!matches!(raw_res, Err(BlobError::Config(_))), "raw put_file must not be blocked by policy");
        assert!(gate.hits() > 0, "permitted raw put_file should reach provider IO");

        gate.reset();
        let err = store.verify_closure(&pm_closure, None, None, deadline()).await.expect_err("503 fails closure");
        assert!(!matches!(err, BlobClosureError::EncryptionPolicyMismatch));
        assert!(gate.hits() > 0, "permitted provider-managed closure should reach provider IO");

        let (enc_intent, enc_loc, sealed, meta) =
            seal_for_intent(store, kp.as_ref(), work.path(), tenant, authority, 1, &plain_bytes);
        let ct_intent = store
            .new_upload(tenant, authority, 1, "packs", meta.ciphertext_sha256(), meta.ciphertext_length())
            .expect("ct intent");
        let ct_copy = work.path().join(format!("ct-{}.bin", Uuid::new_v4().simple()));
        std::fs::copy(sealed.ciphertext_path(), &ct_copy).expect("copy ct");

        gate.reset();
        assert!(matches!(store.put_ciphertext_file(ct_intent, &ct_copy, deadline()).await, Err(BlobError::Config(_))));
        assert_eq!(gate.hits(), 0, "put_ciphertext_file refused before IO");

        gate.reset();
        assert!(matches!(
            store.put_encrypted_file(enc_intent, sealed, deadline()).await,
            Err(EnvelopeError::EncryptionPolicyMismatch)
        ));
        assert_eq!(gate.hits(), 0, "put_encrypted_file refused before IO");

        gate.reset();
        assert!(matches!(
            store.get_decrypted_to_file(&enc_loc, &meta, &kp, &work.path().join("nope.out"), deadline()).await,
            Err(EnvelopeError::EncryptionPolicyMismatch)
        ));
        assert_eq!(gate.hits(), 0, "get_decrypted_to_file refused before IO");

        gate.reset();
        assert!(matches!(
            store.verify_encrypted_blob(&enc_loc, &meta, &kp, work.path(), deadline()).await,
            Err(EnvelopeError::EncryptionPolicyMismatch)
        ));
        assert_eq!(gate.hits(), 0, "verify_encrypted_blob refused before IO");

        gate.reset();
        assert!(matches!(
            store.verify_closure(&le_closure, Some(&kp), Some(work.path()), deadline()).await,
            Err(BlobClosureError::EncryptionPolicyMismatch)
        ));
        assert_eq!(gate.hits(), 0, "verify_closure(LocalEnvelope) refused before IO");
    }

    // 2. Explicit `local-envelope` refuses ALL raw plaintext paths BEFORE IO
    //    and allows encrypted/local-envelope operations to reach provider IO.
    assert!(matches!(
        ProtectedUploader::new(store_le.clone()).preflight_plain_upload_policy(),
        Err(ProtectedUploadError::EncryptionPolicyMismatch)
    ));

    gate.reset();
    let intent_plain = upload(&store_le, "packs", &plain_bytes);
    assert!(matches!(store_le.put_file(intent_plain, &plain_path, deadline()).await, Err(BlobError::Config(_))));
    assert_eq!(gate.hits(), 0, "raw put_file under local-envelope refused before IO");

    gate.reset();
    assert!(matches!(
        store_le.verify_closure(&pm_closure, None, None, deadline()).await,
        Err(BlobClosureError::EncryptionPolicyMismatch)
    ));
    assert_eq!(gate.hits(), 0, "provider-managed closure under local-envelope refused before IO");

    let (enc_intent, enc_loc, sealed, meta) =
        seal_for_intent(&store_le, kp.as_ref(), work.path(), tenant, authority, 1, &plain_bytes);
    let ct_intent = store_le
        .new_upload(tenant, authority, 1, "packs", meta.ciphertext_sha256(), meta.ciphertext_length())
        .expect("le ct intent");
    let ct_copy = work.path().join(format!("le-ct-{}.bin", Uuid::new_v4().simple()));
    std::fs::copy(sealed.ciphertext_path(), &ct_copy).expect("copy le ct");
    gate.reset();
    let ct_err = store_le.put_ciphertext_file(ct_intent, &ct_copy, deadline()).await.expect_err("503 fails ct put");
    assert!(!matches!(ct_err, BlobError::Config(_)));
    assert!(gate.hits() > 0, "permitted put_ciphertext_file reaches IO");

    gate.reset();
    let put_err = store_le.put_encrypted_file(enc_intent, sealed, deadline()).await.expect_err("503 fails put");
    assert!(!matches!(put_err, EnvelopeError::EncryptionPolicyMismatch | EnvelopeError::MetadataCorrupt(_)));
    assert!(gate.hits() > 0, "permitted put_encrypted_file reaches IO");

    gate.reset();
    let get_err = store_le
        .get_decrypted_to_file(&enc_loc, &meta, &kp, &work.path().join("out.bin"), deadline())
        .await
        .expect_err("503 fails get");
    assert!(!matches!(get_err, EnvelopeError::EncryptionPolicyMismatch));
    assert!(gate.hits() > 0, "permitted get_decrypted_to_file reaches IO");

    gate.reset();
    let vf_err = store_le.verify_encrypted_blob(&enc_loc, &meta, &kp, work.path(), deadline()).await.expect_err("503");
    assert!(!matches!(vf_err, EnvelopeError::EncryptionPolicyMismatch));
    assert!(gate.hits() > 0, "permitted verify_encrypted_blob reaches IO");

    gate.reset();
    let cl_err = store_le.verify_closure(&le_closure, Some(&kp), Some(work.path()), deadline()).await.expect_err("503");
    assert!(!matches!(cl_err, BlobClosureError::EncryptionPolicyMismatch));
    assert!(gate.hits() > 0, "permitted verify_closure(LocalEnvelope) reaches IO");
}

fn le_meta_locator(meta: &EnvelopeMetadata) -> BlobLocator {
    BlobLocator::new(
        meta.tenant_id(),
        meta.authority_id(),
        meta.generation(),
        meta.attempt_id(),
        meta.namespace(),
        meta.ciphertext_sha256(),
        meta.ciphertext_length(),
    )
    .expect("meta locator")
}

#[tokio::test]
async fn single_read_verified_receipt_and_three_mode_memory_roundtrips() {
    let keyring = TempDir::new().expect("keyring");
    write_keyring(keyring.path(), "k1", &[("k1", [0x7bu8; 32])]);
    let kp: Arc<dyn KeyProvider> = Arc::new(LocalFileKeyProvider::load(keyring.path()).expect("kp"));
    let work = TempDir::new().expect("work");
    let plain = payload(70 * 1024 + 9);
    let plain_path = write_source(work.path(), &plain);

    // Unset and explicit `provider-managed` permit `put_file` while rejecting `put_ciphertext_file`.
    let (unset_store, _) = store(ResourceLimits::new(2, 4, 8 << 20).expect("limits"));
    let pm_store = open_memory_with_enc(BlobEncryptionConfig::provider_managed());
    for mem in [&unset_store, &pm_store] {
        let intent = upload(mem, "packs", &plain);
        let receipt = mem.put_file(intent, &plain_path, deadline()).await.expect("raw put");
        assert_eq!(receipt.verified_length(), plain.len() as u64);

        let ct_intent = upload(mem, "packs", &plain);
        assert!(matches!(mem.put_ciphertext_file(ct_intent, &plain_path, deadline()).await, Err(BlobError::Config(_))));
    }

    // Explicit `local-envelope` rejects `put_file` before writing anything and
    // executes single-read ciphertext download + receipt minting cleanly.
    let le_store =
        open_memory_with_enc(BlobEncryptionConfig::local_envelope(keyring.path().to_path_buf()).expect("le"));
    let rejected_intent = upload(&le_store, "packs", &plain);
    let rejected_locator = rejected_intent.locator().clone();
    assert!(matches!(le_store.put_file(rejected_intent, &plain_path, deadline()).await, Err(BlobError::Config(_))));
    assert!(matches!(le_store.verify(&rejected_locator, deadline()).await, Err(BlobError::NotFound)));

    let tenant = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let spec = EnvelopeSpec { tenant_id: tenant, authority_id: authority, generation: 2, namespace: "packs".into() };
    let prepared = prepare_file_envelope(&spec, &plain_path, work.path(), 8 << 20).expect("prepare");
    let ct_intent = le_store
        .new_upload(tenant, authority, 2, "packs", prepared.ciphertext_sha256(), prepared.ciphertext_length())
        .expect("ct intent");
    let locator = ct_intent.locator().clone();
    let sealed = prepared.bind_and_wrap(kp.as_ref(), &locator).expect("wrap");
    let (receipt, metadata) = le_store.put_encrypted_file(ct_intent, sealed, deadline()).await.expect("put encrypted");
    assert!(receipt.matches(&locator));

    // Direct `get_to_file_verified_receipt` mints exact receipt from one streamed read
    // and fails closed before file creation when expected sha256/length mismatch.
    let mismatch_out = work.path().join("bad-ct.bin");
    assert!(matches!(
        le_store
            .get_to_file_verified_receipt(&locator, &mismatch_out, &"0".repeat(64), locator.length(), deadline())
            .await,
        Err(BlobError::DigestMismatch { .. })
    ));
    assert!(!mismatch_out.exists());

    let ct_out = work.path().join("ok-ct.bin");
    let single_receipt = le_store
        .get_to_file_verified_receipt(
            &locator,
            &ct_out,
            metadata.ciphertext_sha256(),
            metadata.ciphertext_length(),
            deadline(),
        )
        .await
        .expect("single read receipt");
    assert!(single_receipt.matches(&locator));
    assert_eq!(single_receipt.backend_identity().as_hex(), le_store.backend_identity().as_hex());

    let decrypted_out = work.path().join("plain-out.bin");
    let decrypted =
        le_store.get_decrypted_to_file(&locator, &metadata, &kp, &decrypted_out, deadline()).await.expect("decrypt");
    assert_eq!(decrypted.plaintext_sha256(), digest(&plain));
    assert_eq!(std::fs::read(&decrypted_out).expect("read out"), plain);

    let verified =
        le_store.verify_encrypted_blob(&locator, &metadata, &kp, work.path(), deadline()).await.expect("verify");
    assert_eq!(verified.plaintext_sha256(), digest(&plain));
}

#[test]
fn preflight_prepared_against_holds_validates_sorted_slots_and_rejects_mismatches() {
    let work = TempDir::new().expect("work");
    let tenant = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let generation = 5;
    let src0 = work.path().join("p0.bin");
    let src1 = work.path().join("p1.bin");
    std::fs::write(&src0, payload(1500)).expect("write p0");
    std::fs::write(&src1, payload(2500)).expect("write p1");

    let spec0 = EnvelopeSpec { tenant_id: tenant, authority_id: authority, generation, namespace: "packs".into() };
    let spec1 = EnvelopeSpec { tenant_id: tenant, authority_id: authority, generation, namespace: "idx".into() };
    let prep0 = prepare_file_envelope(&spec0, &src0, work.path(), 8 << 20).expect("prep0");
    let prep1 = prepare_file_envelope(&spec1, &src1, work.path(), 8 << 20).expect("prep1");

    let mk_hold = |slot: i32, prep: &super::envelope::PreparedCiphertext| HoldAck {
        hold_id: Uuid::new_v4(),
        slot,
        artifact: HoldArtifactIdentity {
            provider: BlobProvider::S3.as_str().to_owned(),
            backend_identity: "backend-hex".into(),
            tenant_id: prep.spec().tenant_id,
            authority_id: prep.spec().authority_id,
            authority_generation: prep.spec().generation,
            attempt_id: Uuid::new_v4(),
            namespace: prep.spec().namespace.clone(),
            sha256: prep.ciphertext_sha256().to_owned(),
            length: prep.ciphertext_length(),
        },
        declared_bytes: prep.ciphertext_length() as i64,
        logical_bytes: prep.plaintext_length() as i64,
    };

    // Unsorted hold order (`slot 1` then `slot 0`) must match sorted `prepared` (`[prep0, prep1]`).
    let hold0 = mk_hold(0, &prep0);
    let hold1 = mk_hold(1, &prep1);
    preflight_prepared_against_holds(&[hold1.clone(), hold0.clone()], &[prep0, prep1]).expect("aligned sorted slots");

    // Re-prepare clean instances for negative matrix.
    let prep0 = prepare_file_envelope(&spec0, &src0, work.path(), 8 << 20).expect("prep0");
    let prep1 = prepare_file_envelope(&spec1, &src1, work.path(), 8 << 20).expect("prep1");
    let holds = [hold1.clone(), hold0.clone()];

    // Wrong count.
    assert!(matches!(
        preflight_prepared_against_holds(&holds, std::slice::from_ref(&prep0)),
        Err(EnvelopeError::MetadataCorrupt(_))
    ));
    // Duplicate slot in holds.
    assert!(matches!(
        preflight_prepared_against_holds(&[hold0.clone(), hold0.clone()], &[prep0, prep1]),
        Err(EnvelopeError::MetadataCorrupt(_))
    ));

    let prep0 = prepare_file_envelope(&spec0, &src0, work.path(), 8 << 20).expect("prep0");
    let prep1 = prepare_file_envelope(&spec1, &src1, work.path(), 8 << 20).expect("prep1");
    // Swapped order (`[prep1, prep0]` against `[slot 0, slot 1]`).
    assert!(matches!(
        preflight_prepared_against_holds(&holds, &[prep1, prep0]),
        Err(EnvelopeError::MetadataCorrupt(_))
    ));

    // Mutate each HoldArtifactIdentity field one by one against single `prep0`.
    let prep0 = prepare_file_envelope(&spec0, &src0, work.path(), 8 << 20).expect("prep0");
    for mutate in [
        (|h: &mut HoldAck| h.artifact.tenant_id = Uuid::new_v4()) as fn(&mut HoldAck),
        |h| h.artifact.authority_id = Uuid::new_v4(),
        |h| h.artifact.authority_generation += 1,
        |h| h.artifact.namespace = "other".into(),
        |h| h.artifact.sha256 = "f".repeat(64),
        |h| h.artifact.length += 1,
    ] {
        let mut bad = hold0.clone();
        mutate(&mut bad);
        assert!(matches!(
            preflight_prepared_against_holds(&[bad], std::slice::from_ref(&prep0)),
            Err(EnvelopeError::MetadataCorrupt(_))
        ));
    }

    // Truncated temp ciphertext file fails preflight cleanly before any PG consume.
    std::fs::write(prep0.ciphertext_path(), b"short").expect("truncate ct");
    assert!(matches!(preflight_prepared_against_holds(&[hold0], &[prep0]), Err(EnvelopeError::MetadataCorrupt(_))));
}
