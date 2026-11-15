//! Public crate-boundary contract tests for Issue #109 (`blob_store` W1-C):
//! explicit encryption configuration (without Vault dependency), replaceable
//! `KeyProvider` envelopes, fail-closed old-key/tampering rejection, and
//! isolated TTL-bounded disposable views.

use std::{
    fs::Permissions,
    os::unix::fs::PermissionsExt,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant as StdInstant},
};

use anyhow::{Result, anyhow, ensure};
use deadpool_postgres::{Manager, Pool};
use rootyard::blob_store::{
    BlobLocator,
    closure::{BlobClosureEncryption, BlobClosureError, BlobClosureSpec, ClosureArtifactRole, ClosureEntrySpec},
    config::BlobProfile,
    disposable_view::{DisposableViewError, DisposableViewRoot},
    encrypted_transfer::ProtectedEncryptedUploadError,
    encryption_config::{BlobEncryptionConfig, BlobEncryptionMode, ENV_BLOB_ENCRYPTION_MODE, ENV_BLOB_KEYRING_DIR},
    envelope::{
        ENVELOPE_CHUNK_BYTES, EnvelopeError, EnvelopeMetadata, EnvelopeSpec, open_ciphertext_file_to_path,
        prepare_file_envelope, rewrap_envelope_metadata,
    },
    key_provider::{KeyProvider, KeyProviderError, LocalFileKeyProvider},
    opendal::BlobStore,
    protected::{ProtectedUploadError, ProtectedUploader, UploadSource},
};
use rootyard::db;
use rootyard::ref_store::artifact_hold::{
    AcquireArtifactHoldsRequest, AcquireOutcome, ArtifactHoldPurpose, ArtifactSpec, HoldScope, PgArtifactHoldStore,
};
use rootyard::ref_store::{
    CoreGateInit, GitObjectFormat, IssuerLane, OperationIdentity, OperationState, PgRefStore, PgRefStoreCore, RefName,
    RequestDigest,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::watch,
    task::JoinHandle,
    time::Instant as TokioInstant,
};
use uuid::Uuid;

static ENV_LOCK: Mutex<()> = Mutex::new(());

struct EnvResetGuard {
    saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
}

impl EnvResetGuard {
    fn capture(names: &[&'static str]) -> Self {
        let saved = names.iter().map(|&name| (name, std::env::var_os(name))).collect();
        Self { saved }
    }
}

impl Drop for EnvResetGuard {
    fn drop(&mut self) {
        // SAFETY: serialized via ENV_LOCK for the test process.
        unsafe {
            for (name, previous) in &self.saved {
                match previous {
                    Some(val) => std::env::set_var(name, val),
                    None => std::env::remove_var(name),
                }
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
    let _reset = EnvResetGuard::capture(&[ENV_BLOB_ENCRYPTION_MODE, ENV_BLOB_KEYRING_DIR]);
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

const BLOB_SET_ENV_DEFAULTS: &[(&str, &str)] = &[
    ("ROOTYARD_BLOB_DRIVER", "opendal"),
    ("ROOTYARD_BLOB_SERVICE", "s3"),
    ("ROOTYARD_BLOB_BUCKET", "w1c-contract-test-bucket"),
    ("ROOTYARD_BLOB_REGION", "us-east-1"),
    ("ROOTYARD_BLOB_ACCESS_KEY_ID", "fixture-access-key"),
    ("ROOTYARD_BLOB_SECRET_ACCESS_KEY", "fixture-secret-key"),
    ("ROOTYARD_BLOB_RETRY_MAX_TIMES", "0"),
    ("ROOTYARD_BLOB_TIMEOUT_MS", "5000"),
    ("ROOTYARD_BLOB_IO_TIMEOUT_MS", "5000"),
    ("ROOTYARD_BLOB_ABORT_TIMEOUT_MS", "500"),
    ("ROOTYARD_BLOB_MAX_OBJECT_BYTES", "1048576"),
];

const BLOB_REMOVE_ENV_KEYS: &[&str] = &[
    "ROOTYARD_BLOB_SESSION_TOKEN",
    "ROOTYARD_BLOB_ROOT",
    "ROOTYARD_BLOB_DELETE",
    "ROOTYARD_BLOB_STAGING_BYTES",
    "ROOTYARD_BLOB_ACTIVE_UPLOADS",
    "ROOTYARD_BLOB_ACTIVE_READERS",
    ENV_BLOB_ENCRYPTION_MODE,
    ENV_BLOB_KEYRING_DIR,
];

struct Counting503Endpoint {
    endpoint: String,
    hits: Arc<AtomicUsize>,
    shutdown: watch::Sender<bool>,
    task: Option<JoinHandle<()>>,
}

impl Counting503Endpoint {
    async fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
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
}

impl Drop for Counting503Endpoint {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

fn open_three_mode_stores(endpoint: &str, keyring: &Path) -> (BlobStore, BlobStore, BlobStore) {
    let _guard = ENV_LOCK.lock().expect("env lock");
    let mut watched: Vec<&'static str> =
        BLOB_SET_ENV_DEFAULTS.iter().map(|(k, _)| *k).chain(["ROOTYARD_BLOB_ENDPOINT"]).collect();
    watched.extend_from_slice(BLOB_REMOVE_ENV_KEYS);
    let _reset = EnvResetGuard::capture(&watched);
    // SAFETY: protected by ENV_LOCK across env-mutating tests.
    unsafe {
        for (key, value) in BLOB_SET_ENV_DEFAULTS {
            std::env::set_var(key, value);
        }
        std::env::set_var("ROOTYARD_BLOB_ENDPOINT", endpoint);
        for key in BLOB_REMOVE_ENV_KEYS {
            std::env::remove_var(key);
        }
    }
    let unset_profile = BlobProfile::from_env().expect("unset profile");
    let pm_profile = unset_profile.clone().with_encryption(BlobEncryptionConfig::provider_managed());
    let le_profile = unset_profile
        .clone()
        .with_encryption(BlobEncryptionConfig::local_envelope(keyring.to_path_buf()).expect("local envelope cfg"));
    (
        BlobStore::open(unset_profile).expect("open unset"),
        BlobStore::open(pm_profile).expect("open pm"),
        BlobStore::open(le_profile).expect("open le"),
    )
}

#[tokio::test]
async fn public_three_mode_policy_matrix_performs_zero_io_on_refusals() {
    let endpoint = Counting503Endpoint::start().await;
    let keyring = TempDir::new().expect("keyring");
    write_keyring(keyring.path(), "k1", &[("k1", [0x51u8; 32])]);
    let kp: Arc<dyn KeyProvider> = Arc::new(LocalFileKeyProvider::load(keyring.path()).expect("kp"));
    let (store_unset, store_pm, store_le) = open_three_mode_stores(&endpoint.endpoint, keyring.path());
    assert_eq!(endpoint.hits(), 0, "store open must not touch endpoint");

    let work = TempDir::new().expect("work");
    let plain = b"public-w1c-contract-payload";
    let src = work.path().join("pack.bin");
    std::fs::write(&src, plain).expect("write src");

    let tenant = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let spec = EnvelopeSpec { tenant_id: tenant, authority_id: authority, generation: 1, namespace: "packs".into() };
    let prep = prepare_file_envelope(&spec, &src, work.path(), 1048576).expect("prepare");
    let ct_loc = BlobLocator::new(
        tenant,
        authority,
        1,
        Uuid::new_v4(),
        "packs",
        prep.ciphertext_sha256(),
        prep.ciphertext_length(),
    )
    .expect("ct loc");
    let meta = prep.bind_and_wrap(kp.as_ref(), &ct_loc).expect("wrap").metadata().clone();

    let pm_loc = BlobLocator::new(
        tenant,
        authority,
        1,
        Uuid::new_v4(),
        "packs",
        &hex::encode(Sha256::digest(plain)),
        plain.len() as u64,
    )
    .expect("pm loc");
    let pm_closure = BlobClosureSpec::new(
        tenant,
        authority,
        1,
        BlobClosureEncryption::ProviderManaged,
        vec![ClosureEntrySpec::provider_managed(ClosureArtifactRole::Pack, pm_loc)],
    )
    .expect("pm closure");
    let le_closure = BlobClosureSpec::new(
        tenant,
        authority,
        1,
        BlobClosureEncryption::LocalEnvelope,
        vec![ClosureEntrySpec::local_envelope(ClosureArtifactRole::Pack, ct_loc.clone(), meta.clone()).expect("entry")],
    )
    .expect("le closure");

    let deadline = StdInstant::now() + Duration::from_secs(10);
    for store in [&store_unset, &store_pm] {
        assert!(ProtectedUploader::new(store.clone()).preflight_plain_upload_policy().is_ok());

        endpoint.reset();
        assert!(matches!(
            store.get_decrypted_to_file(&ct_loc, &meta, &kp, &work.path().join("nope.out"), deadline).await,
            Err(EnvelopeError::EncryptionPolicyMismatch)
        ));
        assert_eq!(endpoint.hits(), 0);

        endpoint.reset();
        assert!(matches!(
            store.verify_encrypted_blob(&ct_loc, &meta, &kp, work.path(), deadline).await,
            Err(EnvelopeError::EncryptionPolicyMismatch)
        ));
        assert_eq!(endpoint.hits(), 0);

        endpoint.reset();
        assert!(matches!(
            store.verify_closure(&le_closure, Some(&kp), Some(work.path()), deadline).await,
            Err(BlobClosureError::EncryptionPolicyMismatch)
        ));
        assert_eq!(endpoint.hits(), 0);

        endpoint.reset();
        let err = store.verify_closure(&pm_closure, None, None, deadline).await.expect_err("503 closure");
        assert!(!matches!(err, BlobClosureError::EncryptionPolicyMismatch));
        assert!(endpoint.hits() > 0);
    }

    assert!(matches!(
        ProtectedUploader::new(store_le.clone()).preflight_plain_upload_policy(),
        Err(ProtectedUploadError::EncryptionPolicyMismatch)
    ));
    endpoint.reset();
    assert!(matches!(
        store_le.verify_closure(&pm_closure, None, None, deadline).await,
        Err(BlobClosureError::EncryptionPolicyMismatch)
    ));
    assert_eq!(endpoint.hits(), 0);

    endpoint.reset();
    let le_err = store_le.verify_closure(&le_closure, Some(&kp), Some(work.path()), deadline).await.expect_err("503");
    assert!(!matches!(le_err, BlobClosureError::EncryptionPolicyMismatch));
    assert!(endpoint.hits() > 0);
}

async fn run_with_migrated_pg_schema<F, Fut>(f: F) -> Result<()>
where
    F: FnOnce(Pool) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let url = std::env::var("ROOTYARD_TEST_DATABASE_URL")
        .expect("ROOTYARD_TEST_DATABASE_URL must be set when running ignored PG tests");
    let admin = db::pool(&url)?;
    let schema = format!("w1c_contract_test_{}", Uuid::new_v4().simple());
    admin.get().await?.batch_execute(&format!("CREATE SCHEMA {schema}")).await?;
    let mut cfg: tokio_postgres::Config = url.parse()?;
    cfg.options(format!("-c search_path={schema} -c timezone=UTC -c statement_timeout=30000 -c lock_timeout=15000"));
    let pool = Pool::builder(Manager::new(cfg, tokio_postgres::NoTls))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .max_size(8)
        .build()?;
    let result = async {
        db::migrate(&pool).await?;
        f(pool.clone()).await
    }
    .await;
    drop(pool);
    let teardown = admin.get().await?.batch_execute(&format!("DROP SCHEMA {schema} CASCADE")).await;
    result?;
    teardown?;
    Ok(())
}

struct PgHoldFixture {
    tenant: Uuid,
    repo: Uuid,
    scope: HoldScope,
    gate: rootyard::ref_store::RequestDigest,
}

impl PgHoldFixture {
    async fn seed(pool: &Pool, pg_deadline: TokioInstant) -> Result<Self> {
        let tenant = Uuid::new_v4();
        let repo = Uuid::new_v4();
        let history = Uuid::new_v4();
        {
            let client = pool.get().await?;
            client
                .execute(
                    "INSERT INTO users(id,username) VALUES($1,$2)",
                    &[&tenant, &format!("w1c_{}", &tenant.simple().to_string()[..10])],
                )
                .await?;
            client
                .execute(
                    "INSERT INTO repositories(id,owner_id,name,state,object_format) VALUES($1,$2,$3,'provisioning','sha1')",
                    &[&repo, &tenant, &format!("repo_{}", &repo.simple().to_string()[..10])],
                )
                .await?;
        }
        let gate = {
            let init = CoreGateInit::new(
                repo,
                tenant,
                GitObjectFormat::Sha1,
                history,
                1,
                1,
                RefName::branch("refs/heads/main")?,
            )?;
            let mut client = pool.get().await?;
            *PgRefStoreCore.initialize(&mut client, &init, pg_deadline).await?.digest()
        };
        let scope = HoldScope::new(
            repo,
            tenant,
            tenant,
            ArtifactHoldPurpose::RefPublication,
            GitObjectFormat::Sha1,
            history,
            1,
            1,
        )?;
        Ok(Self { tenant, repo, scope, gate })
    }

    async fn acquire_holds(
        &self,
        pool: &Pool,
        store: &BlobStore,
        specs: Vec<ArtifactSpec>,
        seq: i64,
        pg_deadline: TokioInstant,
    ) -> Result<(Vec<Uuid>, rootyard::ref_store::artifact_hold::ArtifactGrant)> {
        let op = OperationIdentity::new(
            self.repo,
            self.tenant,
            IssuerLane::new("w1c-contract")?,
            seq,
            Uuid::new_v4(),
            RequestDigest::from_bytes([seq as u8; 32]),
        )?;
        {
            let mut client = pool.get().await?;
            let tx = client.transaction().await?;
            let begun = PgRefStore.begin(&tx, &op, pg_deadline).await?;
            ensure!(begun.record.state() == OperationState::Pending);
            tx.commit().await?;
        }
        let req = AcquireArtifactHoldsRequest::new(
            self.scope,
            op,
            Uuid::new_v4(),
            store.backend_identity().clone(),
            self.repo,
            1,
            self.gate,
            specs,
        )?;
        let mut client = pool.get().await?;
        match PgArtifactHoldStore.acquire(&mut client, store, &req, pg_deadline).await? {
            AcquireOutcome::Granted { ack, grant } => {
                let ids = ack.holds().iter().map(|h| h.hold_id).collect();
                Ok((ids, grant))
            }
            AcquireOutcome::Replayed { .. } => Err(anyhow!("unexpected acquire replay")),
        }
    }
}

#[tokio::test]
#[ignore = "requires PostgreSQL (ROOTYARD_TEST_DATABASE_URL)"]
async fn pg_protected_uploader_preflight_preserves_unconsumed_holds() -> Result<()> {
    run_with_migrated_pg_schema(|pool| async move { run_pg_preflight_suite(&pool).await }).await
}

async fn run_pg_preflight_suite(pool: &Pool) -> Result<()> {
    let endpoint = Counting503Endpoint::start().await;
    let keyring = TempDir::new()?;
    write_keyring(keyring.path(), "k1", &[("k1", [0x61u8; 32])]);
    let kp: Arc<dyn KeyProvider> = Arc::new(LocalFileKeyProvider::load(keyring.path())?);
    let (store_unset, store_pm, store_le) = open_three_mode_stores(&endpoint.endpoint, keyring.path());

    let pg_deadline = TokioInstant::now() + Duration::from_secs(20);
    let blob_deadline = StdInstant::now() + Duration::from_secs(20);
    let fixture = PgHoldFixture::seed(pool, pg_deadline).await?;
    let tenant = fixture.tenant;
    let repo = fixture.repo;

    let work = TempDir::new()?;
    let src = work.path().join("artifact.bin");
    let plain = b"protected-uploader-grant-preservation";
    std::fs::write(&src, plain)?;
    let spec = EnvelopeSpec { tenant_id: tenant, authority_id: repo, generation: 1, namespace: "packs".into() };

    let mut next_seq = 1i64;
    let fixture_ref = &fixture;
    let acquire_for = |store: BlobStore, art_spec: ArtifactSpec, seq: i64| async move {
        let (holds, grant) = fixture_ref.acquire_holds(pool, &store, vec![art_spec], seq, pg_deadline).await?;
        Ok::<_, anyhow::Error>((holds[0], grant))
    };

    // 1. Plain upload refused under `local-envelope` preserves unconsumed hold.
    let plain_spec = ArtifactSpec::new("packs", hex::encode(Sha256::digest(plain)), plain.len() as u64)?;
    let (hold_plain, grant_plain) = acquire_for(store_le.clone(), plain_spec, next_seq).await?;
    next_seq += 1;
    let res_plain = ProtectedUploader::new(store_le.clone())
        .consume_and_upload(pool, grant_plain, &[UploadSource::new(src.clone())], blob_deadline)
        .await;
    ensure!(matches!(res_plain, Err(ProtectedUploadError::EncryptionPolicyMismatch)), "unexpected: {res_plain:?}");

    // 2. Encrypted upload refused under `unset` and `provider-managed` preserves holds.
    for (idx, wrong_store) in [store_unset, store_pm].into_iter().enumerate() {
        let prep = prepare_file_envelope(&spec, &src, work.path(), 1048576)?;
        let ct_spec = ArtifactSpec::new("packs", prep.ciphertext_sha256(), prep.ciphertext_length())?;
        let (hold_id, grant) = acquire_for(wrong_store.clone(), ct_spec, next_seq).await?;
        next_seq += 1;
        let res = ProtectedUploader::new(wrong_store)
            .consume_and_upload_encrypted(pool, grant, vec![prep], &kp, blob_deadline)
            .await;
        ensure!(
            matches!(
                res,
                Err(ProtectedEncryptedUploadError::Envelope {
                    slot: None,
                    error: EnvelopeError::EncryptionPolicyMismatch
                })
            ),
            "mode {idx} returned unexpected error: {res:?}"
        );
        let state: String =
            pool.get().await?.query_one("SELECT state FROM artifact_holds WHERE hold_id=$1", &[&hold_id]).await?.get(0);
        ensure!(state == "active", "wrong-mode refusal must leave hold active, got {state}");
    }

    // 3. Encrypted upload under `local-envelope` with mismatched PreparedCiphertext preserves hold.
    let prep_real = prepare_file_envelope(&spec, &src, work.path(), 1048576)?;
    let ct_spec = ArtifactSpec::new("packs", prep_real.ciphertext_sha256(), prep_real.ciphertext_length())?;
    let (hold_mismatch, grant_mismatch) = acquire_for(store_le.clone(), ct_spec, next_seq).await?;
    let alt_src = work.path().join("other.bin");
    std::fs::write(&alt_src, b"different-ciphertext-bytes")?;
    let prep_mismatch = prepare_file_envelope(&spec, &alt_src, work.path(), 1048576)?;
    let res_mismatch = ProtectedUploader::new(store_le)
        .consume_and_upload_encrypted(pool, grant_mismatch, vec![prep_mismatch], &kp, blob_deadline)
        .await;
    ensure!(
        matches!(
            res_mismatch,
            Err(ProtectedEncryptedUploadError::Envelope { slot: None, error: EnvelopeError::MetadataCorrupt(_) })
        ),
        "mismatch returned unexpected error: {res_mismatch:?}"
    );

    let client = pool.get().await?;
    for id in [hold_plain, hold_mismatch] {
        let state: String = client.query_one("SELECT state FROM artifact_holds WHERE hold_id=$1", &[&id]).await?.get(0);
        ensure!(state == "active", "hold {id} unexpectedly consumed (state={state})");
    }
    let receipt_count: i64 = client.query_one("SELECT count(*) FROM artifact_hold_consume_receipts", &[]).await?.get(0);
    ensure!(receipt_count == 0, "expected 0 consume receipts, found {receipt_count}");
    ensure!(endpoint.hits() == 0, "expected zero HTTP IO across all preflight refusals, got {}", endpoint.hits());
    Ok(())
}

fn open_real_env_le_store(keyring: &Path) -> Result<BlobStore> {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let watched = [
        ENV_BLOB_ENCRYPTION_MODE,
        ENV_BLOB_KEYRING_DIR,
        "ROOTYARD_BLOB_MAX_OBJECT_BYTES",
        "ROOTYARD_BLOB_STAGING_BYTES",
        "ROOTYARD_BLOB_ACTIVE_UPLOADS",
        "ROOTYARD_BLOB_ACTIVE_READERS",
        "ROOTYARD_BLOB_RANGE_FULL_GET_MAX_BYTES",
        "ROOTYARD_BLOB_DELETE",
    ];
    let _reset = EnvResetGuard::capture(&watched);
    let endpoint = std::env::var("ROOTYARD_BLOB_ENDPOINT").unwrap_or_default();
    ensure!(!endpoint.trim().is_empty(), "ROOTYARD_BLOB_ENDPOINT must be set for real provider PG contract test");
    // SAFETY: protected by ENV_LOCK while tests mutate process-wide env.
    unsafe {
        std::env::set_var(ENV_BLOB_ENCRYPTION_MODE, "local-envelope");
        std::env::set_var(ENV_BLOB_KEYRING_DIR, keyring);
        // Align ResourceLimits with open_three_mode_stores in case both tests share a process.
        std::env::set_var("ROOTYARD_BLOB_MAX_OBJECT_BYTES", "1048576");
        for key in [
            "ROOTYARD_BLOB_STAGING_BYTES",
            "ROOTYARD_BLOB_ACTIVE_UPLOADS",
            "ROOTYARD_BLOB_ACTIVE_READERS",
            "ROOTYARD_BLOB_RANGE_FULL_GET_MAX_BYTES",
            "ROOTYARD_BLOB_DELETE",
        ] {
            std::env::remove_var(key);
        }
    }
    let profile = BlobProfile::from_env()?;
    ensure!(profile.encryption().is_local_envelope(), "expected local-envelope mode");
    Ok(BlobStore::open(profile)?)
}

#[tokio::test]
#[ignore = "requires PostgreSQL (ROOTYARD_TEST_DATABASE_URL) and controlled S3 (ROOTYARD_BLOB_*)"]
async fn pg_protected_uploader_consume_and_upload_encrypted_against_real_provider() -> Result<()> {
    run_with_migrated_pg_schema(|pool| async move { run_pg_real_provider_roundtrip(&pool).await }).await
}

async fn run_pg_real_provider_roundtrip(pool: &Pool) -> Result<()> {
    let keyring = TempDir::new()?;
    write_keyring(keyring.path(), "k1", &[("k1", [0x11u8; 32])]);
    let kp_v1: Arc<dyn KeyProvider> = Arc::new(LocalFileKeyProvider::load(keyring.path())?);
    let store = open_real_env_le_store(keyring.path())?;

    let pg_deadline = TokioInstant::now() + Duration::from_secs(20);
    let blob_deadline = StdInstant::now() + Duration::from_secs(20);
    let fixture = PgHoldFixture::seed(pool, pg_deadline).await?;
    let spec = EnvelopeSpec {
        tenant_id: fixture.tenant,
        authority_id: fixture.repo,
        generation: 1,
        namespace: "packs".into(),
    };

    let work = TempDir::new()?;
    let mut pack_bytes = b"ROOTYARD-W1C-PACK-PLAINTEXT-MARKER".to_vec();
    pack_bytes.resize(8192, 0x5Au8);
    let mut idx_bytes = b"ROOTYARD-W1C-IDX-PLAINTEXT-MARKER".to_vec();
    idx_bytes.resize(2048, 0xA5u8);
    let pack_src = work.path().join("pack.bin");
    let idx_src = work.path().join("pack.idx");
    std::fs::write(&pack_src, &pack_bytes)?;
    std::fs::write(&idx_src, &idx_bytes)?;

    let pack_sha = hex::encode(Sha256::digest(&pack_bytes));
    let idx_sha = hex::encode(Sha256::digest(&idx_bytes));
    let prep_pack = prepare_file_envelope(&spec, &pack_src, work.path(), 1048576)?;
    let prep_idx = prepare_file_envelope(&spec, &idx_src, work.path(), 1048576)?;
    let ct_pack_sha = prep_pack.ciphertext_sha256().to_owned();
    let ct_pack_len = prep_pack.ciphertext_length();
    let ct_idx_sha = prep_idx.ciphertext_sha256().to_owned();
    let ct_idx_len = prep_idx.ciphertext_length();
    ensure!(ct_pack_sha != pack_sha && ct_pack_len > pack_bytes.len() as u64, "pack envelope did not wrap");
    ensure!(ct_idx_sha != idx_sha && ct_idx_len > idx_bytes.len() as u64, "idx envelope did not wrap");

    let specs = vec![
        ArtifactSpec::new("packs", ct_pack_sha.as_str(), ct_pack_len)?,
        ArtifactSpec::new("packs", ct_idx_sha.as_str(), ct_idx_len)?,
    ];
    let (hold_ids, grant) = fixture.acquire_holds(pool, &store, specs, 1, pg_deadline).await?;
    ensure!(hold_ids.len() == 2, "expected 2 holds, got {}", hold_ids.len());

    {
        let client = pool.get().await?;
        let pre_count: i64 = client
            .query_one("SELECT count(*) FROM artifact_hold_consume_receipts WHERE hold_id = ANY($1)", &[&hold_ids])
            .await?
            .get(0);
        ensure!(pre_count == 0, "expected 0 consume receipts before consume, got {pre_count}");
    }

    let publication = ProtectedUploader::new(store.clone())
        .consume_and_upload_encrypted(pool, grant, vec![prep_pack, prep_idx], &kp_v1, blob_deadline)
        .await?;
    ensure!(publication.is_complete(), "publication should report complete");
    let receipts = publication.receipts();
    ensure!(receipts.len() == 2, "expected 2 encrypted receipts, got {}", receipts.len());
    ensure!(receipts[0].hold_id() == hold_ids[0] && receipts[0].slot() == 0, "slot 0 hold receipt mismatch");
    ensure!(receipts[1].hold_id() == hold_ids[1] && receipts[1].slot() == 1, "slot 1 hold receipt mismatch");
    ensure!(receipts[0].receipt().backend_identity() == store.backend_identity());
    ensure!(
        receipts[0].receipt().verified_sha256() == ct_pack_sha
            && receipts[0].receipt().verified_length() == ct_pack_len
    );
    ensure!(
        receipts[1].receipt().verified_sha256() == ct_idx_sha && receipts[1].receipt().verified_length() == ct_idx_len
    );
    ensure!(receipts[0].metadata().key_id()? == *kp_v1.current_key_id());

    {
        let client = pool.get().await?;
        let post_count: i64 = client
            .query_one(
                "SELECT count(*) FROM artifact_hold_consume_receipts WHERE consume_request_id = $1 AND hold_id = ANY($2)",
                &[&publication.consume_request_id(), &hold_ids],
            )
            .await?
            .get(0);
        ensure!(post_count == 2, "expected 2 durable consume receipts, got {post_count}");
        for id in &hold_ids {
            let state: String =
                client.query_one("SELECT state FROM artifact_holds WHERE hold_id = $1", &[id]).await?.get(0);
            ensure!(state == "active", "append-only artifact_holds state changed unexpectedly: {state}");
        }
    }

    let staging = TempDir::new()?;
    let verified = store
        .verify_encrypted_blob(
            receipts[0].receipt().locator(),
            receipts[0].metadata(),
            &kp_v1,
            staging.path(),
            blob_deadline,
        )
        .await?;
    ensure!(verified.plaintext_sha256() == pack_sha);
    ensure!(verified.plaintext_length() == pack_bytes.len() as u64);
    ensure!(verified.key_id() == kp_v1.current_key_id());

    let out_dir = TempDir::new()?;
    let out_pack = out_dir.path().join("roundtrip.pack");
    let dec_pack = store
        .get_decrypted_to_file(
            receipts[0].receipt().locator(),
            receipts[0].metadata(),
            &kp_v1,
            &out_pack,
            blob_deadline,
        )
        .await?;
    ensure!(dec_pack.plaintext_sha256() == pack_sha && std::fs::read(&out_pack)? == pack_bytes);

    let out_idx = out_dir.path().join("roundtrip.idx");
    let dec_idx = store
        .get_decrypted_to_file(receipts[1].receipt().locator(), receipts[1].metadata(), &kp_v1, &out_idx, blob_deadline)
        .await?;
    ensure!(dec_idx.plaintext_sha256() == idx_sha && std::fs::read(&out_idx)? == idx_bytes);

    write_keyring(keyring.path(), "k2", &[("k1", [0x11u8; 32]), ("k2", [0x22u8; 32])]);
    let kp_both: Arc<dyn KeyProvider> = Arc::new(LocalFileKeyProvider::load(keyring.path())?);
    let meta0_v2 = rewrap_envelope_metadata(receipts[0].metadata(), &*kp_both)?;
    let meta1_v2 = rewrap_envelope_metadata(receipts[1].metadata(), &*kp_both)?;
    let closure_spec = BlobClosureSpec::new(
        fixture.tenant,
        fixture.repo,
        1,
        BlobClosureEncryption::LocalEnvelope,
        vec![
            ClosureEntrySpec::local_envelope(
                ClosureArtifactRole::Pack,
                receipts[0].receipt().locator().clone(),
                meta0_v2,
            )?
            .with_expected_plaintext(&pack_sha, pack_bytes.len() as u64)?,
            ClosureEntrySpec::local_envelope(
                ClosureArtifactRole::PackIndex,
                receipts[1].receipt().locator().clone(),
                meta1_v2,
            )?
            .with_expected_plaintext(&idx_sha, idx_bytes.len() as u64)?,
        ],
    )?;
    closure_spec.require_git_pack_pair()?;
    let proof = store.verify_closure(&closure_spec, Some(&kp_both), Some(staging.path()), blob_deadline).await?;
    ensure!(proof.encryption() == BlobClosureEncryption::LocalEnvelope);
    ensure!(proof.has_git_pack_pair() && proof.artifacts().len() == 2);

    let wrong_keyring = TempDir::new()?;
    write_keyring(wrong_keyring.path(), "k2", &[("k2", [0x22u8; 32])]);
    let kp_k2_only: Arc<dyn KeyProvider> = Arc::new(LocalFileKeyProvider::load(wrong_keyring.path())?);
    let wrong_out = out_dir.path().join("wrong-key.pack");
    let wrong_get = store
        .get_decrypted_to_file(
            receipts[0].receipt().locator(),
            receipts[0].metadata(),
            &kp_k2_only,
            &wrong_out,
            blob_deadline,
        )
        .await;
    ensure!(
        matches!(wrong_get, Err(EnvelopeError::KeyProvider(KeyProviderError::MissingKey(_)))),
        "expected MissingKey error with wrong key provider, got {wrong_get:?}"
    );
    ensure!(!wrong_out.exists(), "decrypted output file must not exist on MissingKey failure");
    let wrong_verify = store
        .verify_encrypted_blob(
            receipts[0].receipt().locator(),
            receipts[0].metadata(),
            &kp_k2_only,
            staging.path(),
            blob_deadline,
        )
        .await;
    ensure!(
        matches!(wrong_verify, Err(EnvelopeError::KeyProvider(KeyProviderError::MissingKey(_)))),
        "expected MissingKey error in verify_encrypted_blob, got {wrong_verify:?}"
    );
    Ok(())
}
