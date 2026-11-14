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
//!
//! The cancellation checkpoint fronts the configured real HTTP-loopback S3
//! endpoint with a bounded owned pass-through gate. The gate forwards the real
//! signed request and withholds only the real backend's response; it never
//! synthesizes an S3 answer, opens deletion or records request paths, headers,
//! bodies or credentials. It retains only the request method, numeric response
//! status and arrival instant.

use futures_util::FutureExt;
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::{Read, Write},
    panic::AssertUnwindSafe,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
    task::JoinHandle,
    time::timeout,
};
use uuid::Uuid;

use super::{
    BlobBackendIdentity, BlobDeletePolicy, BlobError, BlobLocator, BlobProvider,
    budget::{LEASE_UNIT_BYTES, ResourceContext, ResourceLimits},
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

/// Timeout and caller-cancel isolation against the real provider.
///
/// A bounded owned pass-through gate sits in front of the configured HTTP
/// loopback S3 endpoint. It forwards the real signed PUT, records only the
/// request method, final numeric status and arrival instant, then withholds
/// that real response until the test releases it. Both cases stop the caller
/// after the real backend has answered, rather than merely interrupting a local
/// stall that never reached the provider.
///
/// The timeout case must return no receipt even though the backend committed;
/// the cancelled case must leave no caller-visible receipt at all. In both
/// cases a fresh attempt address stays absent until explicitly published, and
/// fixture-only exact cleanup of the old attempt after the new attempt exists
/// must not disturb the new object. Product deletion stays disabled.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires real ROOTYARD_BLOB_* provider"]
async fn real_provider_timeout_and_caller_cancel_isolate_late_completion() {
    let profile = BlobProfile::from_env().expect("real provider configuration is required");
    require_loopback_http_s3(&profile);
    let endpoint = profile.endpoint().expect("configured endpoint").clone();
    let raw = fixture_operator(&profile);
    let dir = tempfile::tempdir().unwrap();
    let payload_len = profile.max_object_bytes().clamp(1, 256 * 1024) as usize;
    let bytes: Vec<u8> = (0..payload_len).map(|index| (index % 251) as u8).collect();
    let source = dir.path().join("cancellation-source");
    File::create(&source).unwrap().write_all(&bytes).unwrap();
    let digest = sha256_file(&source);
    let size = bytes.len() as u64;
    let tenant = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let limits = profile.resource_limits();
    // The caller's absolute deadline must win over the SDK's own object/IO
    // timeout, otherwise the test would observe an SDK timeout instead of the
    // intended caller stop. Default profiles have 30s/60s; a deliberately tiny
    // fixture timeout is a hard setup error, not a flaky pass.
    let provider_wait = profile.object_timeout().min(profile.io_timeout());
    assert!(
        provider_wait >= Duration::from_secs(2),
        "this checkpoint needs at least two seconds of provider object/IO timeout"
    );
    let timeout_case_budget = (provider_wait / 2).min(Duration::from_secs(10));
    let mut owned_keys: Vec<String> = Vec::new();
    let mut contexts: Vec<Arc<ResourceContext>> = Vec::new();

    let outcome = AssertUnwindSafe(async {
        // --- Absolute deadline while the real backend PUT has already answered.
        let gate = RealProviderFaultGate::start(&endpoint).await;
        let resources = Arc::new(ResourceContext::new(limits));
        contexts.push(Arc::clone(&resources));
        let real = BlobStore::open_with_resources(profile.clone(), Arc::clone(&resources))
            .expect("real provider must pass the startup capability gate");
        let proxied = BlobStore::open_with_resources(
            profile.clone().with_test_endpoint(gate.endpoint()).expect("fault gate endpoint is a valid origin"),
            Arc::clone(&resources),
        )
        .expect("proxied provider must pass the startup capability gate");

        let timed_out_intent =
            proxied.new_upload(tenant, authority, 1, "cancel-contract", &digest, size).expect("timed-out intent");
        let timed_out = timed_out_intent.locator().clone();
        owned_keys.push(timed_out.path());
        let upload_deadline = Instant::now() + timeout_case_budget;
        let upload_source = source.clone();
        let upload = tokio::spawn(async move {
            let result = proxied.put_file(timed_out_intent, &upload_source, upload_deadline).await;
            (result, Instant::now())
        });
        let observed = gate.wait_observation(Duration::from_secs(30)).await;
        assert_eq!(observed.method, GateMethod::Put, "the real backend must receive the signed S3 PUT");
        assert!(
            (200..300).contains(&observed.status),
            "the real backend rejected the gated PUT with status {}",
            observed.status
        );
        let (result, stopped_at) = timeout(Duration::from_secs(30), upload)
            .await
            .expect("timed-out upload did not settle")
            .expect("timed-out upload task panicked");
        assert!(
            observed.at <= stopped_at,
            "the real backend answered only after the caller's deadline; this run does not prove the request reached it before cancellation"
        );
        assert!(
            gate.is_holding(),
            "the real backend response must still be withheld when the caller's deadline expires"
        );
        let error = match result {
            Ok(_) => panic!("a timed-out upload must not return a receipt"),
            Err(error) => error,
        };
        assert!(matches!(&error, BlobError::DeadlineExceeded), "expected a deadline failure, got {error}");
        assert_no_private_details(&error, &timed_out, profile.bucket(), profile.root());
        assert_eq!(
            real.head(&timed_out, deadline()).await.unwrap(),
            Some(size),
            "the real backend PUT observed before the timeout must have committed"
        );
        gate.release();
        assert!(
            settle_bounded(&resources, Duration::from_secs(30)).await,
            "timed-out upload cleanup did not settle its owned capacity"
        );

        // A fresh one-use attempt is not written by the timed-out attempt. The
        // stale exact fixture cleanup of the old attempt runs only after this
        // new attempt exists, so a prefix/old-at-least delete would be caught.
        let fresh_intent =
            real.new_upload(tenant, authority, 1, "cancel-contract", &digest, size).expect("fresh intent");
        let fresh = fresh_intent.locator().clone();
        owned_keys.push(fresh.path());
        assert!(timed_out.path() != fresh.path(), "a fresh intent must never reuse the stale attempt path");
        assert_eq!(
            real.head(&fresh, deadline()).await.unwrap(),
            None,
            "a timed-out attempt must not publish a fresh attempt address"
        );
        let fresh_receipt = real.put_file(fresh_intent, &source, deadline()).await.expect("fresh attempt publish");
        assert!(fresh_receipt.matches(&fresh));
        raw.delete(&timed_out.path())
            .await
            .unwrap_or_else(|error| panic!("fixture late cleanup failed ({})", error.kind()));
        let fresh_reverified = real
            .verify(&fresh, deadline())
            .await
            .expect("late exact cleanup of the old attempt must preserve the new attempt");
        assert!(fresh_reverified.matches(&fresh));
        let delete_error = real.delete(&fresh, deadline()).await.expect_err("product delete must stay disabled");
        assert_no_private_details(&delete_error, &fresh, profile.bucket(), profile.root());
        real.verify(&fresh, deadline()).await.expect("disabled product delete must not remove the new attempt");
        drop(gate);

        // --- Caller cancellation after the real backend PUT has already answered.
        let gate = RealProviderFaultGate::start(&endpoint).await;
        let resources = Arc::new(ResourceContext::new(limits));
        contexts.push(Arc::clone(&resources));
        let real = BlobStore::open_with_resources(profile.clone(), Arc::clone(&resources))
            .expect("real provider must pass the startup capability gate");
        let proxied = BlobStore::open_with_resources(
            profile.clone().with_test_endpoint(gate.endpoint()).expect("fault gate endpoint is a valid origin"),
            Arc::clone(&resources),
        )
        .expect("proxied provider must pass the startup capability gate");

        let cancelled_intent =
            proxied.new_upload(tenant, authority, 1, "cancel-contract", &digest, size).expect("cancelled intent");
        let cancelled = cancelled_intent.locator().clone();
        owned_keys.push(cancelled.path());
        let upload_source = source.clone();
        let upload = tokio::spawn(async move {
            proxied.put_file(cancelled_intent, &upload_source, Instant::now() + Duration::from_secs(120)).await
        });
        let observed = gate.wait_observation(Duration::from_secs(30)).await;
        assert_eq!(observed.method, GateMethod::Put, "the real backend must receive the cancelled signed S3 PUT");
        assert!(
            (200..300).contains(&observed.status),
            "the real backend rejected the gated PUT with status {}",
            observed.status
        );
        assert!(
            observed.at <= Instant::now(),
            "the real backend must answer before this caller is cancelled"
        );
        upload.abort();
        let join_error = match upload.await {
            Ok(_) => panic!("an aborted caller must not return a publication"),
            Err(error) => error,
        };
        assert!(join_error.is_cancelled(), "the outer caller must be reported as cancelled");
        assert!(gate.is_holding(), "the real backend response must still be withheld when the caller is cancelled");
        assert_no_private_text(&join_error.to_string(), &cancelled, profile.bucket(), profile.root());
        gate.release();
        assert!(
            settle_bounded(&resources, Duration::from_secs(30)).await,
            "cancelled upload's late completion did not settle its owned capacity"
        );
        assert_eq!(
            real.head(&cancelled, deadline()).await.unwrap(),
            Some(size),
            "a late real-backend commit is an orphan at the cancelled attempt's own path"
        );

        let replacement_intent =
            real.new_upload(tenant, authority, 1, "cancel-contract", &digest, size).expect("replacement intent");
        let replacement = replacement_intent.locator().clone();
        owned_keys.push(replacement.path());
        assert!(
            cancelled.path() != replacement.path(),
            "a fresh intent must never reuse the cancelled attempt path"
        );
        assert_eq!(
            real.head(&replacement, deadline()).await.unwrap(),
            None,
            "late completion must not publish a replacement attempt address"
        );
        let replacement_receipt =
            real.put_file(replacement_intent, &source, deadline()).await.expect("replacement attempt publish");
        assert!(replacement_receipt.matches(&replacement));
        raw.delete(&cancelled.path())
            .await
            .unwrap_or_else(|error| panic!("fixture stale cleanup failed ({})", error.kind()));
        let replacement_reverified = real
            .verify(&replacement, deadline())
            .await
            .expect("stale cleanup of the cancelled attempt must preserve the replacement attempt");
        assert!(replacement_reverified.matches(&replacement));
        assert_eq!(real.head(&replacement, deadline()).await.unwrap(), Some(size));
        drop(gate);
    })
    .catch_unwind()
    .await;

    // Gate drops release both held responses. Bound the late-task drain before
    // exact cleanup so a failed assertion cannot leave an upload rewriting a key.
    let mut settled = true;
    for resources in &contexts {
        if !settle_bounded(resources, Duration::from_secs(30)).await {
            settled = false;
        }
    }
    let mut cleanup_ok = true;
    for key in owned_keys {
        if raw.delete(&key).await.is_err() {
            cleanup_ok = false;
        }
    }
    if let Err(error) = outcome {
        std::panic::resume_unwind(error);
    }
    assert!(settled, "late cancellation cleanup did not release its owned capacity");
    assert!(cleanup_ok, "exact owned fixture cleanup failed");
}

/// Bounded owned pass-through gate for the real provider contract.
///
/// It never answers S3 itself: bytes are forwarded to the configured real
/// endpoint, and only the real backend's first final response is withheld. The
/// recorded observation is a request method, numeric status and arrival
/// instant; request paths, headers, bodies, credentials and locators are never
/// retained. Connection, header, byte and hold bounds keep a failed test from
/// hanging a fixture.
struct RealProviderFaultGate {
    endpoint: String,
    observed: watch::Receiver<Option<GateObservation>>,
    release: watch::Sender<bool>,
    holding: Arc<AtomicBool>,
    task: JoinHandle<()>,
}

impl RealProviderFaultGate {
    async fn start(upstream: &reqwest::Url) -> Self {
        let host = upstream.host_str().expect("real endpoint host").to_owned();
        let port = upstream.port_or_known_default().expect("real endpoint port");
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("fault gate loopback bind");
        let address = listener.local_addr().expect("fault gate local address");
        let (observed_tx, observed) = watch::channel::<Option<GateObservation>>(None);
        let (release_tx, release_rx) = watch::channel::<bool>(false);
        let holding = Arc::new(AtomicBool::new(false));
        let task_holding = Arc::clone(&holding);
        let task = tokio::spawn(async move {
            let mut admitted = 0usize;
            loop {
                let Ok((client, _)) = listener.accept().await else { break };
                if admitted >= GATE_MAX_CONNECTIONS {
                    drop(client);
                    continue;
                }
                admitted += 1;
                let host = host.clone();
                let observed = observed_tx.clone();
                let release = release_rx.clone();
                let holding = Arc::clone(&task_holding);
                tokio::spawn(async move {
                    let _ = proxy_connection(client, &host, port, observed, release, holding).await;
                });
            }
        });
        Self { endpoint: format!("http://{address}"), observed, release: release_tx, holding, task }
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn is_holding(&self) -> bool {
        self.holding.load(Ordering::SeqCst)
    }

    async fn wait_observation(&self, limit: Duration) -> GateObservation {
        let mut observed = self.observed.clone();
        timeout(limit, async move {
            loop {
                if let Some(observation) = *observed.borrow() {
                    return observation;
                }
                observed.changed().await.expect("fault gate observation sender was dropped");
            }
        })
        .await
        .expect("real backend never answered the gated upload")
    }

    fn release(&self) {
        let _ = self.release.send(true);
    }
}

impl Drop for RealProviderFaultGate {
    fn drop(&mut self) {
        let _ = self.release.send(true);
        self.task.abort();
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GateMethod {
    Put,
    Post,
    Other,
}

#[derive(Clone, Copy, Debug)]
struct GateObservation {
    method: GateMethod,
    status: u16,
    /// When the real backend's final response arrived at the gate. The test
    /// compares this with the caller's stop time so a backend that answered
    /// only after the deadline cannot be reported as pre-cancellation evidence.
    at: Instant,
}

/// Clears the "holding" marker on every exit path, including a dropped future,
/// a timeout or a broken client socket.
struct GateHolding(Arc<AtomicBool>);

impl Drop for GateHolding {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

const GATE_MAX_CONNECTIONS: usize = 8;
const GATE_MAX_HEADER_BYTES: usize = 64 * 1024;
const GATE_COPY_BYTES: usize = 16 * 1024;
const GATE_MAX_REQUEST_BYTES: u64 = 64 * 1024 * 1024;
const GATE_MAX_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;
const GATE_IO_TIMEOUT: Duration = Duration::from_secs(30);
const GATE_HOLD_TIMEOUT: Duration = Duration::from_secs(60);
const GATE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(180);

fn gate_timeout(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::TimedOut, message)
}

fn gate_invalid(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// Only the method is retained; the request target is deliberately dropped.
fn first_request_method(head: &[u8]) -> GateMethod {
    let line = head.split(|byte| *byte == b'\n').next().unwrap_or(b"");
    if line.starts_with(b"PUT ") {
        GateMethod::Put
    } else if line.starts_with(b"POST ") {
        GateMethod::Post
    } else {
        GateMethod::Other
    }
}

fn response_status(head: &[u8]) -> Option<u16> {
    let line = head.split(|byte| *byte == b'\n').next()?;
    let mut fields = line.split(|byte| *byte == b' ').filter(|field| !field.is_empty());
    let version = fields.next()?;
    if !version.starts_with(b"HTTP/") {
        return None;
    }
    std::str::from_utf8(fields.next()?).ok()?.parse().ok()
}

async fn proxy_connection(
    client: TcpStream,
    host: &str,
    port: u16,
    observed: watch::Sender<Option<GateObservation>>,
    release: watch::Receiver<bool>,
    holding: Arc<AtomicBool>,
) -> std::io::Result<()> {
    let upstream = match timeout(GATE_IO_TIMEOUT, TcpStream::connect((host, port))).await {
        Ok(Ok(upstream)) => upstream,
        Ok(Err(error)) => return Err(error),
        Err(_) => return Err(gate_timeout("fault gate upstream connect timed out")),
    };
    let (mut client_read, mut client_write) = client.into_split();
    let (mut upstream_read, mut upstream_write) = upstream.into_split();
    let (method_tx, method_rx) = watch::channel::<Option<GateMethod>>(None);

    let request = async move {
        let mut head = Vec::new();
        let mut method_observed = false;
        let mut buffer = vec![0u8; GATE_COPY_BYTES];
        let mut total = 0u64;
        loop {
            let read = match timeout(GATE_IO_TIMEOUT, client_read.read(&mut buffer)).await {
                Ok(Ok(read)) => read,
                Ok(Err(error)) => return Err(error),
                Err(_) => return Err(gate_timeout("fault gate client request read timed out")),
            };
            if read == 0 {
                break;
            }
            if total.saturating_add(read as u64) > GATE_MAX_REQUEST_BYTES {
                return Err(gate_invalid("fault gate client request exceeded its byte cap"));
            }
            if !method_observed && head.len() < GATE_MAX_HEADER_BYTES {
                let take = read.min(GATE_MAX_HEADER_BYTES - head.len());
                head.extend_from_slice(&buffer[..take]);
                if find_subsequence(&head, b"\r\n\r\n").is_some() || head.len() >= GATE_MAX_HEADER_BYTES {
                    let method = first_request_method(&head);
                    method_tx.send_if_modified(|slot| {
                        if slot.is_none() {
                            *slot = Some(method);
                            true
                        } else {
                            false
                        }
                    });
                    // Keep only the finite method; request headers can carry
                    // authorization material and are no longer needed.
                    head.clear();
                    method_observed = true;
                }
            }
            match timeout(GATE_IO_TIMEOUT, upstream_write.write_all(&buffer[..read])).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => return Err(error),
                Err(_) => return Err(gate_timeout("fault gate upstream request write timed out")),
            }
            total = total.saturating_add(read as u64);
        }
        let _ = upstream_write.shutdown().await;
        Ok(())
    };

    let response = async move {
        let mut head = Vec::new();
        let mut scanning = true;
        let mut buffer = vec![0u8; GATE_COPY_BYTES];
        let mut total = 0u64;
        loop {
            let read = match timeout(GATE_IO_TIMEOUT, upstream_read.read(&mut buffer)).await {
                Ok(Ok(read)) => read,
                Ok(Err(error)) => return Err(error),
                Err(_) => return Err(gate_timeout("fault gate upstream response read timed out")),
            };
            if read == 0 {
                break;
            }
            if total.saturating_add(read as u64) > GATE_MAX_RESPONSE_BYTES {
                return Err(gate_invalid("fault gate upstream response exceeded its byte cap"));
            }
            total = total.saturating_add(read as u64);
            if scanning {
                if head.len().saturating_add(read) > GATE_MAX_HEADER_BYTES {
                    return Err(gate_invalid("fault gate upstream response headers exceeded their byte cap"));
                }
                head.extend_from_slice(&buffer[..read]);
                let Some(end) = find_subsequence(&head, b"\r\n\r\n") else { continue };
                let status = response_status(&head[..end + 4])
                    .ok_or_else(|| gate_invalid("fault gate upstream response status was not HTTP/1.x"))?;
                let method = wait_gate_method(method_rx.clone()).await?;
                let candidate = GateObservation { method, status, at: Instant::now() };
                let mut claimed = false;
                observed.send_if_modified(|slot| {
                    if slot.is_none() {
                        *slot = Some(candidate);
                        claimed = true;
                        holding.store(true, Ordering::SeqCst);
                        true
                    } else {
                        false
                    }
                });
                scanning = false;
                if claimed {
                    let _holding = GateHolding(Arc::clone(&holding));
                    wait_gate_release(release.clone()).await?;
                }
                match timeout(GATE_IO_TIMEOUT, client_write.write_all(&head)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => return Err(error),
                    Err(_) => return Err(gate_timeout("fault gate client response write timed out")),
                }
                head.clear();
            } else {
                match timeout(GATE_IO_TIMEOUT, client_write.write_all(&buffer[..read])).await {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => return Err(error),
                    Err(_) => return Err(gate_timeout("fault gate client response write timed out")),
                }
            }
        }
        Ok(())
    };

    let _ = timeout(GATE_CONNECTION_TIMEOUT, async { tokio::join!(request, response) }).await;
    Ok(())
}

async fn wait_gate_method(mut method: watch::Receiver<Option<GateMethod>>) -> std::io::Result<GateMethod> {
    let wait = async move {
        loop {
            if let Some(method) = *method.borrow() {
                return Ok(method);
            }
            if method.changed().await.is_err() {
                return Err(gate_invalid("fault gate method channel closed"));
            }
        }
    };
    match timeout(GATE_IO_TIMEOUT, wait).await {
        Ok(result) => result,
        Err(_) => Err(gate_timeout("fault gate request method did not arrive")),
    }
}

async fn wait_gate_release(mut release: watch::Receiver<bool>) -> std::io::Result<()> {
    let wait = async move {
        loop {
            if *release.borrow() {
                return Ok(());
            }
            if release.changed().await.is_err() {
                return Err(gate_invalid("fault gate release channel closed"));
            }
        }
    };
    match timeout(GATE_HOLD_TIMEOUT, wait).await {
        Ok(result) => result,
        Err(_) => Err(gate_timeout("fault gate hold timed out")),
    }
}

fn require_loopback_http_s3(profile: &BlobProfile) {
    assert_eq!(profile.provider(), BlobProvider::S3, "this cancellation checkpoint qualifies the real S3 profile only");
    let endpoint = profile.endpoint().expect("standalone profile needs an explicit endpoint");
    assert_eq!(
        endpoint.scheme(),
        "http",
        "the owned fault gate requires a plain HTTP loopback S3 fixture; TLS is not terminated here"
    );
    assert!(
        matches!(endpoint.host_str(), Some("127.0.0.1" | "localhost" | "::1")),
        "the owned fault gate requires a loopback endpoint"
    );
}

async fn settle_bounded(resources: &ResourceContext, limit: Duration) -> bool {
    let limits = resources.limits();
    timeout(limit, async {
        loop {
            if resources.available_uploads() == limits.active_uploads()
                && resources.available_readers() == limits.active_readers()
                && resources.available_staging_bytes() == limits.staging_bytes()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .is_ok()
}

fn assert_no_private_details(error: &BlobError, locator: &BlobLocator, bucket: &str, root: &str) {
    assert_no_private_text(&format!("{error} {error:?}"), locator, bucket, root);
}

fn assert_no_private_text(text: &str, locator: &BlobLocator, bucket: &str, root: &str) {
    for private in [
        locator.path(),
        locator.sha256().to_owned(),
        locator.tenant_id().to_string(),
        locator.authority_id().to_string(),
        locator.attempt_id().to_string(),
    ] {
        assert!(!text.contains(private.as_str()), "error text leaked a private locator field");
    }
    // A short bucket/root can occur by chance in a fixed diagnostic sentence.
    // Long configured values are still checked for a literal leak.
    if bucket.len() >= 8 {
        assert!(!text.contains(bucket), "error text leaked the configured bucket/container");
    }
    if root.len() >= 8 {
        assert!(!text.contains(root), "error text leaked the configured root prefix");
    }
    let lower = text.to_ascii_lowercase();
    for marker in [
        "authorization",
        "credential",
        "secret",
        "signature",
        "session_token",
        "access_key",
        "x-amz-",
        "http://",
        "https://",
    ] {
        assert!(!lower.contains(marker), "error text leaked credential or transport context");
    }
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
