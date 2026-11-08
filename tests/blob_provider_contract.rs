//! Provider contract tests for the standalone OpenDAL Blob profile.
//!
//! Provider-dependent tests run **only** when `ROOTYARD_BLOB_SERVICE` and the
//! rest of the `ROOTYARD_BLOB_*` profile are configured against a real service.
//! Without it they print `SKIPPED` and make no provider assertion: an absent
//! provider is never reported as a qualified provider. Purely local assertions
//! (strict profile parsing, locator/layout invariants) always run.
use futures_util::FutureExt;
use rootyard::{
    blob_store::{
        BlobDeletePolicy, BlobError, BlobLocator, BlobProvider,
        config::BlobProfile,
        opendal::{BlobStore, MAX_RANGE_BYTES},
    },
    storage::remote_objects::ObjectKey,
};
use sha2::{Digest, Sha256};
use std::panic::AssertUnwindSafe;
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
    time::{Duration, Instant},
};
use uuid::Uuid;

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

#[tokio::test]
#[ignore = "requires a disposable real ROOTYARD_BLOB_* provider and owned-key fault injection"]
async fn real_provider_publish_verify_range_delete_contract() {
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
    let first = BlobLocator::new(tenant, authority, 1, Uuid::new_v4(), "contract", &digest, size).unwrap();
    let second = BlobLocator::new(tenant, authority, 1, Uuid::new_v4(), "contract", &digest, size).unwrap();

    let mut owned_keys = vec![first.path(), second.path()];
    let outcome = AssertUnwindSafe(async {
        let receipt = store.put_file(&first, &source, deadline()).await.expect("first attempt publish");
        assert!(receipt.matches(&first));
        assert_eq!(receipt.verified_sha256(), digest);
        assert_eq!(receipt.verified_length(), size);
        let repeated = store.put_file(&first, &source, deadline()).await;
        assert!(matches!(repeated, Err(BlobError::AlreadyExists)), "duplicate immutable locator result: {repeated:?}");
        independent.verify(&first, deadline()).await.expect("duplicate write must leave the first bytes intact");
        store.put_file(&second, &source, deadline()).await.expect("second attempt publish same bytes");

        // Another client can re-present the receipt and require a provider read-back.
        let reverified = independent
            .verify_receipt(&first, receipt.verified_sha256(), receipt.verified_length(), deadline())
            .await
            .expect("cross-client receipt re-verification");
        assert!(reverified.matches(&first));

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

        // A short expectation must fail length verification and publish no destination.
        let short = BlobLocator::new(tenant, authority, 1, first.attempt_id(), "contract", &digest, size - 1).unwrap();
        let bad_destination = dir.path().join("bad");
        assert!(matches!(
            store.get_to_file(&short, &bad_destination, deadline()).await,
            Err(BlobError::LengthMismatch { .. })
        ));
        assert!(!bad_destination.exists());

        // A locator whose length disagrees with the source is rejected before upload.
        let oversized = BlobLocator::new(tenant, authority, 1, Uuid::new_v4(), "contract", &digest, size + 1).unwrap();
        owned_keys.push(oversized.path());
        assert!(matches!(store.put_file(&oversized, &source, deadline()).await, Err(BlobError::LengthMismatch { .. })));
        assert_eq!(store.head(&oversized, deadline()).await.unwrap(), None);

        assert!(matches!(store.delete(&first, deadline()).await, Err(BlobError::DeleteDisabled)));
        // Only the test operator mutates its own exact, random fixture identities.
        raw.write(&first.path(), payload[..payload.len() - 1].to_vec())
            .await
            .unwrap_or_else(|e| panic!("fixture truncate failed ({})", e.kind()));
        assert!(independent.verify(&first, deadline()).await.is_err());
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
    use rootyard::blob_store::config::BlobCredentials;
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
