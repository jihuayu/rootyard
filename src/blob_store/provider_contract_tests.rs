//! Provider contract tests for the standalone OpenDAL Blob profile.
//!
//! These cases live inside the `blob_store` subtree (`#[cfg(test)]`) so they can
//! call the sealed raw writer directly. There is no feature-gated public
//! raw-write hook: every feature combination, including `pando-lab`, exposes only
//! the protected uploader, and production builds contain no raw-write entry
//! point outside this subtree.
//!
//! Provider-dependent tests are explicitly `#[ignore = "requires real
//! ROOTYARD_BLOB_* provider"]` and are mandatory-configured when invoked with
//! `--ignored`: a missing profile panics that case instead of being reported as
//! skipped or passed. Purely local assertions (strict profile parsing,
//! locator/layout invariants, backend-identity binding and foreign-intent
//! refusal) run as normal unit tests over the `cfg(test)` memory operator.

use futures_util::FutureExt;
use sha2::{Digest, Sha256};
use std::panic::AssertUnwindSafe;
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
    time::{Duration, Instant},
};
use uuid::Uuid;

use super::{
    BlobBackendIdentity, BlobDeletePolicy, BlobError, BlobLocator, BlobProvider,
    budget::{LEASE_UNIT_BYTES, ResourceLimits},
    config::BlobProfile,
    opendal::{BlobStore, MAX_RANGE_BYTES},
    test_support,
};
use crate::storage::remote_objects::ObjectKey;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(180)
}

fn sha256_file(path: &Path) -> String {
    let mut file = File::open(path).unwrap();
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).unwrap();
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    hex::encode(hash.finalize())
}

fn private_limits() -> ResourceLimits {
    ResourceLimits::new(1, 1, 4 * LEASE_UNIT_BYTES).expect("private test limits")
}

#[test]
fn strict_profile_rejects_fs_memory_and_unknown_services() {
    for rejected in ["fs", "memory", "local", "unknown-store", ""] {
        assert!(
            matches!(BlobProvider::parse(rejected), Err(BlobError::UnsupportedService(_))),
            "`{rejected}` must not qualify as a blob service"
        );
    }
    assert_eq!(BlobProvider::parse("s3").unwrap(), BlobProvider::S3);
    assert_eq!(BlobDeletePolicy::parse("").unwrap(), BlobDeletePolicy::Disabled);
    assert!(BlobDeletePolicy::parse("prefix-delete").is_err());
    assert!(BlobDeletePolicy::parse("exact-locator").is_err());
}

#[test]
fn locator_binds_tenant_authority_generation_attempt_and_keeps_legacy_paths() {
    let tenant = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let digest = "a".repeat(64);
    let first = BlobLocator::new(tenant, authority, 7, Uuid::new_v4(), "contract", &digest, 3).unwrap();
    let second = BlobLocator::new(tenant, authority, 7, Uuid::new_v4(), "contract", &digest, 3).unwrap();
    assert_ne!(first.attempt_id(), second.attempt_id());
    assert_ne!(first.path(), second.path(), "same digest/length attempts must not share a path");
    for part in [tenant.to_string(), authority.to_string(), "g7".to_string(), first.attempt_id().to_string()] {
        assert!(first.path().contains(&part), "locator path must bind {part}");
    }
    assert!(first.path().starts_with("v1/"), "new profile must not silently reuse legacy paths");
    assert!(BlobLocator::new(tenant, authority, 0, Uuid::new_v4(), "contract", &digest, 3).is_err());
    assert!(BlobLocator::new(tenant, Uuid::nil(), 1, Uuid::new_v4(), "contract", &digest, 3).is_err());
    assert!(BlobLocator::new(tenant, authority, 1, Uuid::new_v4(), "../escape", &digest, 3).is_err());

    // Legacy readers/manifests keep their frozen key layout.
    let legacy = ObjectKey::new(tenant, "lfs", &digest).unwrap();
    assert_eq!(legacy.path(), format!("tenants/{tenant}/lfs/{digest}"));
    let scoped = ObjectKey::scoped(tenant, authority, 7, "pando-pack", &digest).unwrap();
    assert_eq!(scoped.path(), format!("tenants/{tenant}/authorities/{authority}/g7/pando-pack/{digest}"));
}

#[test]
fn backend_identity_is_deterministic_canonical_hex() {
    let limits = private_limits();
    let profile = BlobProfile::memory_profile(limits);
    let first = BlobBackendIdentity::from_profile(&profile);
    let second = BlobBackendIdentity::from_profile(&profile);
    assert_eq!(first, second, "the same actual profile mapping must yield one identity");
    assert_eq!(first.as_hex().len(), 64);
    assert!(
        first.as_hex().bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "identity hex must be lowercase sha256"
    );
    let cloned = first.clone();
    assert_eq!(cloned.as_hex(), first.as_hex(), "cloning identity data must preserve its hex");

    // A cfg(test) memory operator is not an S3 realm: its identity is its own
    // fresh realm, never the synthetic profile's mapping.
    let (memory, _) = test_support::store(limits);
    assert_ne!(memory.backend_identity(), &first);
    assert_ne!(memory.backend_identity().as_hex(), first.as_hex());
}

#[tokio::test]
async fn receipt_and_intent_bind_the_actual_store_identity() {
    let limits = private_limits();
    let (blob, _) = test_support::store(limits);
    let bytes = b"backend identity binding";
    let dir = tempfile::tempdir().unwrap();
    let source = test_support::write_source(dir.path(), bytes);
    let intent = test_support::upload(&blob, "identity", bytes);
    let locator = intent.locator().clone();

    assert_eq!(intent.backend_identity(), blob.backend_identity());
    let receipt = blob.put_file(intent, &source, deadline()).await.expect("publish");
    assert!(receipt.matches(&locator), "metadata equality still works for compatibility");
    assert_eq!(receipt.backend_identity(), blob.backend_identity());
    assert_eq!(receipt.provider(), blob.provider());
}

#[tokio::test]
async fn foreign_backend_intent_is_rejected_before_source_io() {
    let limits = private_limits();
    let (mint_store, _) = test_support::store(limits);
    let (other_store, _) = test_support::store(limits);
    assert_ne!(mint_store.backend_identity(), other_store.backend_identity());

    let bytes = b"foreign backend";
    let intent = test_support::upload(&mint_store, "foreign", bytes);
    let locator = intent.locator().clone();
    assert_eq!(intent.backend_identity(), mint_store.backend_identity());

    // The source does not exist: reaching a source-open error instead of
    // ForeignBackend would prove the check ran too late.
    let missing = std::path::Path::new("/nonexistent/rootyard-foreign-source");
    assert!(matches!(other_store.put_file(intent, missing, deadline()).await, Err(BlobError::ForeignBackend)));
    assert_eq!(other_store.head(&locator, deadline()).await.unwrap(), None);
}

#[tokio::test]
#[ignore = "requires real ROOTYARD_BLOB_* provider"]
async fn real_provider_publish_verify_range_delete_contract() {
    // `--ignored` is mandatory-configured: a missing profile panics here and is
    // never reported as skipped or passed.
    let profile = BlobProfile::from_env().expect("real provider configuration is required");
    let store = BlobStore::open(profile.clone()).expect("configured real provider must pass startup capability gate");
    let raw = fixture_operator(&profile);
    let independent = BlobStore::open(profile).expect("independent client must pass the capability gate");
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let mut payload = vec![0u8; 21 * 1024 * 1024 + 3];
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte = (index % 251) as u8;
    }
    File::create(&source).unwrap().write_all(&payload).unwrap();
    let digest = sha256_file(&source);
    let size = payload.len() as u64;
    let tenant = Uuid::new_v4();
    let authority = Uuid::new_v4();

    // Fresh one-use intents: the attempt id is minted inside the byte layer, and
    // each intent is privately bound to this store's physical backend.
    let first_intent =
        store.new_upload(tenant, authority, 1, "contract", &digest, size).expect("first intent must be minted");
    // A read-only locator may be cloned from stored metadata before the write
    // capability is consumed; it cannot be converted back into an intent.
    let first = first_intent.locator().clone();
    let second_intent =
        store.new_upload(tenant, authority, 1, "contract", &digest, size).expect("second intent must be minted");
    let second = second_intent.locator().clone();
    assert_ne!(first.attempt_id(), second.attempt_id());
    assert_ne!(first.path(), second.path(), "fresh intents must never share an attempt path");
    assert_eq!(first_intent.backend_identity(), store.backend_identity());
    assert_eq!(second_intent.backend_identity(), store.backend_identity());

    let mut owned_keys = vec![first.path(), second.path()];
    let outcome = AssertUnwindSafe(async {
        let receipt = store.put_file(first_intent, &source, deadline()).await.expect("first attempt publish");
        assert!(receipt.matches(&first));
        assert_eq!(receipt.backend_identity(), store.backend_identity());
        assert_eq!(receipt.verified_sha256(), digest);
        assert_eq!(receipt.verified_length(), size);

        // A second, independently opened client re-reads the object from the
        // provider. Metadata equality alone is never accepted as proof.
        let reverified = independent
            .verify_receipt(&first, receipt.verified_sha256(), receipt.verified_length(), deadline())
            .await
            .expect("cross-client receipt re-verification");
        assert!(reverified.matches(&first));
        assert_eq!(reverified.backend_identity(), independent.backend_identity());

        // Publishing the same bytes under a fresh intent allocates a distinct
        // address; the old single-locator retry API no longer exists.
        let second_receipt = store.put_file(second_intent, &source, deadline()).await.expect("second attempt publish");
        assert!(second_receipt.matches(&second));
        independent.verify(&second, deadline()).await.expect("second attempt is independently readable");

        let roundtrip = dir.path().join("roundtrip");
        store.get_to_file(&first, &roundtrip, deadline()).await.expect("download");
        assert_eq!(sha256_file(&roundtrip), digest);
        let expected_range = &payload[100..100 + 4096];
        assert_eq!(store.get_range(&first, 100, 4096, deadline()).await.unwrap(), expected_range.to_vec());
        assert!(matches!(
            store.get_range(&first, 0, MAX_RANGE_BYTES + 1, deadline()).await,
            Err(BlobError::RangeExceedsLimit { .. })
        ));
        assert_eq!(store.head(&first, deadline()).await.unwrap(), Some(size));

        // A read-only locator reconstructed from metadata with a short length
        // must fail verification against the existing key and publish nothing.
        let short = BlobLocator::new(tenant, authority, 1, first.attempt_id(), "contract", &digest, size - 1).unwrap();
        let bad_destination = dir.path().join("bad");
        assert!(matches!(
            store.get_to_file(&short, &bad_destination, deadline()).await,
            Err(BlobError::LengthMismatch { .. })
        ));
        assert!(!bad_destination.exists());

        // A wrong source length is refused before the write; no object/ACK.
        let oversized_intent =
            store.new_upload(tenant, authority, 1, "contract", &digest, size + 1).expect("oversized intent");
        let oversized = oversized_intent.locator().clone();
        owned_keys.push(oversized.path());
        assert!(matches!(
            store.put_file(oversized_intent, &source, deadline()).await,
            Err(BlobError::LengthMismatch { .. })
        ));
        assert_eq!(store.head(&oversized, deadline()).await.unwrap(), None);

        // A wrong expected digest is detected while streaming; the attempt is
        // aborted and yields neither ACK nor a readable object.
        let wrong_digest = "b".repeat(64);
        let wrong_digest_intent =
            store.new_upload(tenant, authority, 1, "contract", &wrong_digest, size).expect("wrong digest intent");
        let wrong_digest_locator = wrong_digest_intent.locator().clone();
        owned_keys.push(wrong_digest_locator.path());
        assert!(matches!(
            store.put_file(wrong_digest_intent, &source, deadline()).await,
            Err(BlobError::DigestMismatch { .. })
        ));
        assert_eq!(store.head(&wrong_digest_locator, deadline()).await.unwrap(), None, "digest mismatch must not ACK");

        assert!(matches!(store.delete(&first, deadline()).await, Err(BlobError::DeleteDisabled)));

        // Only the test operator mutates its own exact, random fixture identities.
        raw.write(&first.path(), payload[..payload.len() - 1].to_vec())
            .await
            .unwrap_or_else(|e| panic!("fixture truncate failed ({})", e.kind()));
        assert!(matches!(independent.verify(&first, deadline()).await, Err(BlobError::LengthMismatch { .. })));
        assert!(matches!(
            independent.get_range(&first, 100, 4096, deadline()).await,
            Err(BlobError::LengthMismatch { .. })
        ));
        let mut corrupt = payload.clone();
        corrupt[0] ^= 0xff; // Outside the requested range: whole-object verification must catch it.
        raw.write(&first.path(), corrupt).await.unwrap_or_else(|e| panic!("fixture corruption failed ({})", e.kind()));
        assert!(matches!(independent.verify(&first, deadline()).await, Err(BlobError::DigestMismatch { .. })));
        assert!(matches!(
            independent.get_range(&first, 100, 4096, deadline()).await,
            Err(BlobError::DigestMismatch { .. })
        ));
        assert!(matches!(
            independent.get_to_file(&first, &bad_destination, deadline()).await,
            Err(BlobError::DigestMismatch { .. })
        ));
        assert!(!bad_destination.exists());
        raw.delete(&first.path()).await.unwrap_or_else(|e| panic!("fixture delete failed ({})", e.kind()));
        independent.verify(&second, deadline()).await.expect("late old-attempt delete must preserve the new attempt");
    })
    .catch_unwind()
    .await;
    let mut cleanup_ok = true;
    for key in owned_keys {
        if raw.delete(&key).await.is_err() {
            cleanup_ok = false;
        }
    }
    if let Err(error) = outcome {
        std::panic::resume_unwind(error);
    }
    assert!(cleanup_ok, "exact owned fixture cleanup failed");
}

fn fixture_operator(profile: &BlobProfile) -> opendal::Operator {
    use super::config::BlobCredentials;
    let result = match profile.credentials() {
        BlobCredentials::S3 { access_key_id, secret_access_key, session_token } => {
            let mut builder = opendal::services::S3::default()
                .bucket(profile.bucket())
                .root(profile.root())
                .endpoint(profile.endpoint().unwrap().as_str())
                .region(profile.region().unwrap_or("us-east-1"))
                .disable_config_load()
                .disable_ec2_metadata()
                .access_key_id(access_key_id)
                .secret_access_key(secret_access_key);
            if let Some(token) = session_token {
                builder = builder.session_token(token);
            }
            opendal::Operator::new(builder).map(|builder| builder.finish())
        }
        #[cfg(feature = "blob-azblob")]
        BlobCredentials::Azblob { account_name, account_key } => {
            let builder = opendal::services::Azblob::default()
                .container(profile.bucket())
                .root(profile.root())
                .endpoint(profile.endpoint().unwrap().as_str())
                .account_name(account_name)
                .account_key(account_key);
            opendal::Operator::new(builder).map(|builder| builder.finish())
        }
    };
    result.unwrap_or_else(|e| panic!("fixture operator construction failed ({})", e.kind()))
}
