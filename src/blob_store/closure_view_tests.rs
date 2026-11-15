//! Unit tests for full Blob closure read-back proofs and discardable
//! temporary Git view isolation, deadlines, cleanup, and wipe recovery.

use std::{
    fs::Permissions,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use sha2::{Digest, Sha256};
use tempfile::TempDir;
use uuid::Uuid;

use super::{
    BlobLocator, BlobReceipt,
    budget::{ResourceContext, ResourceLimits},
    closure::{BlobClosureEncryption, BlobClosureError, BlobClosureSpec, ClosureArtifactRole, ClosureEntrySpec},
    config::BlobProfile,
    disposable_view::{DisposableViewError, DisposableViewRoot},
    encryption_config::BlobEncryptionConfig,
    envelope::{EnvelopeMetadata, EnvelopeSpec, prepare_file_envelope},
    key_provider::{KeyProvider, LocalFileKeyProvider},
    opendal::BlobStore,
    test_support::{deadline, delete_exact, digest, payload, store},
};

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

fn encrypted_store(keyring_dir: &Path) -> BlobStore {
    let limits = ResourceLimits::new(2, 4, 8 << 20).expect("limits");
    let resources = Arc::new(ResourceContext::new(limits));
    let profile = BlobProfile::memory_profile(limits)
        .with_encryption(BlobEncryptionConfig::local_envelope(keyring_dir.to_path_buf()).expect("enc cfg"));
    BlobStore::open_memory(profile, resources)
}

async fn publish_encrypted(
    blob: &BlobStore,
    kp: &dyn KeyProvider,
    tenant: Uuid,
    authority: Uuid,
    generation: i64,
    namespace: &str,
    staging_dir: &Path,
    bytes: &[u8],
) -> (BlobReceipt, EnvelopeMetadata) {
    let src = staging_dir.join(format!("plain-{}.bin", Uuid::new_v4().simple()));
    std::fs::write(&src, bytes).expect("write plain");
    let spec = EnvelopeSpec { tenant_id: tenant, authority_id: authority, generation, namespace: namespace.to_owned() };
    let prepared = prepare_file_envelope(&spec, &src, staging_dir, 8 << 20).expect("prepare");
    let intent = blob
        .new_upload(
            tenant,
            authority,
            generation,
            namespace,
            prepared.ciphertext_sha256(),
            prepared.ciphertext_length(),
        )
        .expect("intent");
    let sealed = prepared.bind_and_wrap(kp, intent.locator()).expect("wrap");
    blob.put_encrypted_file(intent, sealed, deadline()).await.expect("put encrypted")
}

#[tokio::test]
async fn encrypted_pack_closure_proof_verifies_complete_closure_and_rejects_gaps() {
    let keyring = TempDir::new().expect("keyring");
    write_keyring(keyring.path(), "k1", &[("k1", [0x61u8; 32])]);
    let blob = encrypted_store(keyring.path());
    let kp = blob.profile().open_key_provider().expect("open kp").expect("kp");

    let stage = TempDir::new().expect("stage");
    let tenant = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let pack_bytes = payload(70_000);
    let idx_bytes = payload(4_096);

    let (pack_receipt, pack_meta) =
        publish_encrypted(&blob, kp.as_ref(), tenant, authority, 4, "packs", stage.path(), &pack_bytes).await;
    let (idx_receipt, idx_meta) =
        publish_encrypted(&blob, kp.as_ref(), tenant, authority, 4, "pack-idx", stage.path(), &idx_bytes).await;

    let pack_entry =
        ClosureEntrySpec::local_envelope(ClosureArtifactRole::Pack, pack_receipt.locator().clone(), pack_meta.clone())
            .expect("pack entry")
            .with_expected_plaintext(&digest(&pack_bytes), pack_bytes.len() as u64)
            .expect("expected pack pt");
    let idx_entry = ClosureEntrySpec::local_envelope(
        ClosureArtifactRole::PackIndex,
        idx_receipt.locator().clone(),
        idx_meta.clone(),
    )
    .expect("idx entry")
    .with_expected_plaintext(&digest(&idx_bytes), idx_bytes.len() as u64)
    .expect("expected idx pt");

    // Incomplete pack-only closure fails pair gate.
    let pack_only =
        BlobClosureSpec::new(tenant, authority, 4, BlobClosureEncryption::LocalEnvelope, vec![pack_entry.clone()])
            .expect("spec");
    assert!(matches!(pack_only.require_git_pack_pair(), Err(BlobClosureError::IncompleteClosure(_))));

    // Complete pack + idx closure verifies via full read-back and decryption.
    let spec = BlobClosureSpec::new(
        tenant,
        authority,
        4,
        BlobClosureEncryption::LocalEnvelope,
        vec![pack_entry.clone(), idx_entry.clone()],
    )
    .expect("complete spec");
    spec.require_git_pack_pair().expect("complete pair");
    let proof = blob.verify_closure(&spec, Some(&kp), Some(stage.path()), deadline()).await.expect("closure proof");
    assert!(proof.has_git_pack_pair());
    assert_eq!(proof.backend_identity(), blob.backend_identity());
    assert_eq!(proof.artifacts().len(), 2);

    // Policy mismatch: LocalEnvelope store refuses ProviderManaged closure.
    let pm_entry = ClosureEntrySpec::provider_managed(ClosureArtifactRole::Pack, pack_receipt.locator().clone());
    let pm_spec = BlobClosureSpec::new(tenant, authority, 4, BlobClosureEncryption::ProviderManaged, vec![pm_entry])
        .expect("pm spec");
    assert!(matches!(
        blob.verify_closure(&pm_spec, None, None, deadline()).await,
        Err(BlobClosureError::EncryptionPolicyMismatch)
    ));

    // Wrong expected plaintext digest fails closed before proof issuance.
    let bad_pt_entry =
        ClosureEntrySpec::local_envelope(ClosureArtifactRole::Pack, pack_receipt.locator().clone(), pack_meta.clone())
            .expect("entry")
            .with_expected_plaintext(&"0".repeat(64), pack_bytes.len() as u64)
            .expect("bad pt");
    let bad_pt_spec =
        BlobClosureSpec::new(tenant, authority, 4, BlobClosureEncryption::LocalEnvelope, vec![bad_pt_entry])
            .expect("bad spec");
    assert!(matches!(
        blob.verify_closure(&bad_pt_spec, Some(&kp), Some(stage.path()), deadline()).await,
        Err(BlobClosureError::PlaintextMismatch(_))
    ));

    // Deleted remote idx fails closure read-back closed.
    delete_exact(&blob, idx_receipt.locator()).await.expect("delete idx");
    assert!(matches!(
        blob.verify_closure(&spec, Some(&kp), Some(stage.path()), deadline()).await,
        Err(BlobClosureError::Envelope(_))
    ));
}

#[tokio::test]
async fn provider_managed_closure_and_compute_dir_wipe_recovery() {
    // Part A: provider-managed closure succeeds with no KeyProvider.
    let (pm_blob, _) = store(ResourceLimits::new(2, 4, 4 << 20).expect("limits"));
    let stage = TempDir::new().expect("stage");
    let tenant = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let pack_bytes = payload(4096);
    let idx_bytes = payload(512);
    let p_src = stage.path().join("p.pack");
    let i_src = stage.path().join("p.idx");
    std::fs::write(&p_src, &pack_bytes).expect("write p");
    std::fs::write(&i_src, &idx_bytes).expect("write i");
    let p_int = pm_blob
        .new_upload(tenant, authority, 1, "packs", &digest(&pack_bytes), pack_bytes.len() as u64)
        .expect("p int");
    let i_int = pm_blob
        .new_upload(tenant, authority, 1, "pack-idx", &digest(&idx_bytes), idx_bytes.len() as u64)
        .expect("i int");
    let p_rcpt = pm_blob.put_file(p_int, &p_src, deadline()).await.expect("put p");
    let i_rcpt = pm_blob.put_file(i_int, &i_src, deadline()).await.expect("put i");
    let pm_spec = BlobClosureSpec::new(
        tenant,
        authority,
        1,
        BlobClosureEncryption::ProviderManaged,
        vec![
            ClosureEntrySpec::provider_managed(ClosureArtifactRole::Pack, p_rcpt.locator().clone()),
            ClosureEntrySpec::provider_managed(ClosureArtifactRole::PackIndex, i_rcpt.locator().clone()),
        ],
    )
    .expect("pm spec");
    let pm_proof = pm_blob.verify_closure(&pm_spec, None, None, deadline()).await.expect("pm proof");
    assert!(pm_proof.has_git_pack_pair());

    // Part B: Encrypted compute-dir wipe & fresh process/view recovery using Blob + keyring.
    let keyring = TempDir::new().expect("keyring");
    write_keyring(keyring.path(), "k1", &[("k1", [0x7au8; 32])]);
    let enc_blob = encrypted_store(keyring.path());
    let kp = enc_blob.profile().open_key_provider().expect("kp").expect("kp");

    let scratch_parent = TempDir::new().expect("scratch parent");
    let view_root_path = scratch_parent.path().join("views");
    let view_root =
        DisposableViewRoot::open(&view_root_path, 4, 1024 * 1024, Duration::from_secs(60)).expect("open root");
    let lease = view_root.create_view("receive", tenant, authority, 256 * 1024, None).expect("lease");
    let stage_in_view = lease.dir_path().expect("live view").to_path_buf();

    let (e_pack_rcpt, e_pack_meta) =
        publish_encrypted(&enc_blob, kp.as_ref(), tenant, authority, 2, "packs", &stage_in_view, &pack_bytes).await;
    let (e_idx_rcpt, e_idx_meta) =
        publish_encrypted(&enc_blob, kp.as_ref(), tenant, authority, 2, "pack-idx", &stage_in_view, &idx_bytes).await;
    let e_pack_loc = BlobLocator::new(
        tenant,
        authority,
        2,
        e_pack_rcpt.locator().attempt_id(),
        "packs",
        e_pack_rcpt.locator().sha256(),
        e_pack_rcpt.locator().length(),
    )
    .expect("rebuilt locator");
    let e_idx_loc = e_idx_rcpt.locator().clone();
    let e_pack_json = e_pack_meta.to_json().expect("meta json");
    let e_idx_json = e_idx_meta.to_json().expect("meta json");

    // Simulate complete wipe of compute-node scratch directory and restart with fresh keyring/view handles.
    drop(lease);
    drop(view_root);
    drop(kp);
    if view_root_path.exists() {
        std::fs::remove_dir_all(&view_root_path).expect("wipe compute view root");
    }
    assert!(!view_root_path.exists());

    let fresh_kp: Arc<dyn KeyProvider> = Arc::new(LocalFileKeyProvider::load(keyring.path()).expect("reload keyring"));
    let fresh_root =
        DisposableViewRoot::open(&view_root_path, 4, 1024 * 1024, Duration::from_secs(60)).expect("reopen root");
    let fresh_lease = fresh_root.create_view("fetch", tenant, authority, 256 * 1024, None).expect("fresh lease");
    let restored_pack_meta = EnvelopeMetadata::from_json(e_pack_json.as_bytes()).expect("reload pack meta");
    let restored_idx_meta = EnvelopeMetadata::from_json(e_idx_json.as_bytes()).expect("reload idx meta");

    let closure_spec = BlobClosureSpec::new(
        tenant,
        authority,
        2,
        BlobClosureEncryption::LocalEnvelope,
        vec![
            ClosureEntrySpec::local_envelope(ClosureArtifactRole::Pack, e_pack_loc.clone(), restored_pack_meta.clone())
                .expect("p"),
            ClosureEntrySpec::local_envelope(
                ClosureArtifactRole::PackIndex,
                e_idx_loc.clone(),
                restored_idx_meta.clone(),
            )
            .expect("i"),
        ],
    )
    .expect("reloaded closure spec");
    let recovered_proof = enc_blob
        .verify_closure(&closure_spec, Some(&fresh_kp), Some(fresh_lease.dir_path().expect("live")), deadline())
        .await
        .expect("recovered closure");
    assert!(recovered_proof.has_git_pack_pair());

    let out_pack = fresh_lease.resolve_repo_relative_path(Path::new("objects/pack/test.pack")).expect("safe path");
    let out_idx = fresh_lease.resolve_repo_relative_path(Path::new("objects/pack/test.idx")).expect("safe path");
    std::fs::create_dir_all(out_pack.parent().expect("parent")).expect("mkdir objects/pack");
    enc_blob
        .get_decrypted_to_file(&e_pack_loc, &restored_pack_meta, &fresh_kp, &out_pack, deadline())
        .await
        .expect("decrypt pack");
    enc_blob
        .get_decrypted_to_file(&e_idx_loc, &restored_idx_meta, &fresh_kp, &out_idx, deadline())
        .await
        .expect("decrypt idx");
    assert_eq!(std::fs::read(&out_pack).expect("pack"), pack_bytes);
    assert_eq!(std::fs::read(&out_idx).expect("idx"), idx_bytes);
}

#[test]
fn disposable_view_isolation_bounds_ttl_expiry_and_sweep() {
    let parent = TempDir::new().expect("parent");
    let root_path = parent.path().join("views");
    let root = DisposableViewRoot::open(&root_path, 2, 1024, Duration::from_secs(30)).expect("open");
    let tenant = Uuid::new_v4();
    let authority = Uuid::new_v4();

    // Enforce directory privacy (0o700) and reject symlinked root/children.
    let mode = std::fs::symlink_metadata(&root_path).expect("meta").mode() & 0o777;
    assert_eq!(mode, 0o700);
    let permissive = parent.path().join("bad-perms");
    std::fs::create_dir(&permissive).expect("mkdir");
    std::fs::set_permissions(&permissive, Permissions::from_mode(0o755)).expect("chmod 755");
    assert!(matches!(
        DisposableViewRoot::open(&permissive, 2, 1024, Duration::from_secs(10)),
        Err(DisposableViewError::UnsafePath(_))
    ));
    let sym_root = parent.path().join("sym-root");
    symlink(&root_path, &sym_root).expect("symlink root");
    assert!(matches!(
        DisposableViewRoot::open(&sym_root, 2, 1024, Duration::from_secs(10)),
        Err(DisposableViewError::UnsafePath(_))
    ));

    // Bounds: max views and max total reserved bytes, reclaimed cleanly on Drop.
    let l1 = root.create_view("clone", tenant, authority, 600, None).expect("l1");
    let d1 = l1.dir_path().expect("d1").to_path_buf();
    assert!(matches!(
        root.create_view("clone", tenant, authority, 500, None),
        Err(DisposableViewError::CapacityExceeded(_))
    ));
    let l2 = root.create_view("fetch", tenant, authority, 400, None).expect("l2");
    assert!(matches!(
        root.create_view("fetch", tenant, authority, 1, None),
        Err(DisposableViewError::CapacityExceeded(_))
    ));

    // Path traversal & symlink safety inside repo.git.
    assert!(matches!(l1.resolve_repo_relative_path(Path::new("../escape")), Err(DisposableViewError::UnsafePath(_))));
    assert!(matches!(l1.resolve_repo_relative_path(Path::new("/abs/path")), Err(DisposableViewError::UnsafePath(_))));
    let link_inside = l1.repo_path().expect("repo").join("evil");
    symlink(parent.path(), &link_inside).expect("symlink child");
    assert!(matches!(l1.resolve_repo_relative_path(Path::new("evil/secret")), Err(DisposableViewError::UnsafePath(_))));

    drop(l1);
    assert!(!d1.exists(), "dropped lease must delete view directory");
    assert_eq!(root.active_view_count(), 1);
    assert_eq!(root.total_reserved_bytes(), 400);

    // TTL expiration refuses operations fail-closed and sweep reclaims forgotten/restarted dirs.
    let short = root.create_view("ttl-probe", tenant, authority, 500, Some(Duration::from_millis(25))).expect("short");
    let short_dir: PathBuf = short.dir_path().expect("short dir").to_path_buf();
    std::mem::forget(short);
    std::thread::sleep(Duration::from_millis(60));

    let fresh_root = DisposableViewRoot::open(&root_path, 2, 1024, Duration::from_secs(30)).expect("fresh");
    let report = fresh_root.sweep_expired().expect("sweep");
    assert_eq!(report.removed_views, 1);
    assert_eq!(report.skipped_live_views, 1);
    assert_eq!(report.reclaimed_reserved_bytes, 500);
    assert!(!short_dir.exists());

    // Active handle whose TTL elapsed refuses access fail-closed.
    let expiring = fresh_root
        .create_view("expire-check", tenant, authority, 100, Some(Duration::from_millis(20)))
        .expect("expiring");
    std::thread::sleep(Duration::from_millis(45));
    assert!(matches!(expiring.repo_path(), Err(DisposableViewError::Expired)));
    assert!(matches!(expiring.resolve_repo_relative_path(Path::new("HEAD")), Err(DisposableViewError::Expired)));
    l2.reap();
}
