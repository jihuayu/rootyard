//! Real PostgreSQL + loopback S3 integration contract tests for #77 Pando PITR
//! / metadata-clone bucket authority fencing, retention roots, and operator recovery.
use anyhow::{Context, Result, ensure};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri, header},
    response::Response,
};
use deadpool_postgres::{Manager, Pool};
use rootyard::{
    AppState,
    config::Config,
    db, dispatch, metrics,
    pando_gateway::{
        pack_store::{ArtifactReceipt, PackManifest},
        pitr_fence, retention,
        retention_roots::{self, RetentionRootKind},
    },
    storage::{
        Storage,
        encrypted_objects::Envelope,
        remote_authority::{AuthorityEpochProof, PROOF_VERSION},
        remote_objects::{ObjectKey, RemoteObjectStore},
    },
    storage_lifecycle::{
        jobs,
        models::Policy,
        pando_delete_gate::{self, DeleteGateDecision},
        scheduler, worker,
    },
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tempfile::TempDir;
use tokio::{net::TcpListener, sync::Semaphore, task::JoinHandle, time::Instant};
use uuid::Uuid;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(60)
}

#[derive(Default)]
struct S3MemoryState {
    objects: BTreeMap<String, Vec<u8>>,
    delete_requests: Vec<String>,
}

struct LoopbackS3 {
    endpoint: String,
    bucket: &'static str,
    region: &'static str,
    state: Arc<Mutex<S3MemoryState>>,
    server_task: JoinHandle<()>,
}

impl LoopbackS3 {
    async fn start() -> Result<Self> {
        let state = Arc::new(Mutex::new(S3MemoryState::default()));
        let app = Router::new().fallback(handle_s3).with_state(Arc::clone(&state));
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let server_task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(Self {
            endpoint: format!("http://127.0.0.1:{port}"),
            bucket: "pando-pitr-test-bucket",
            region: "garage",
            state,
            server_task,
        })
    }

    fn contains(&self, rel_key: &str) -> bool {
        let full = format!("{}/{}", self.bucket, rel_key);
        self.state.lock().unwrap().objects.contains_key(&full)
    }

    fn take_deletes(&self) -> Vec<String> {
        std::mem::take(&mut self.state.lock().unwrap().delete_requests)
    }

    fn insert_raw(&self, rel_key: &str, bytes: Vec<u8>) {
        let full = format!("{}/{}", self.bucket, rel_key);
        self.state.lock().unwrap().objects.insert(full, bytes);
    }
}

impl Drop for LoopbackS3 {
    fn drop(&mut self) {
        self.server_task.abort();
    }
}

fn s3_response(
    status: StatusCode,
    content_type: Option<&str>,
    etag: Option<&str>,
    len: Option<usize>,
    body: Body,
) -> Response {
    let mut builder = Response::builder().status(status);
    if let Some(ct) = content_type {
        builder = builder.header(header::CONTENT_TYPE, ct);
    }
    if let Some(tag) = etag {
        builder = builder.header(header::ETAG, tag);
    }
    if let Some(n) = len {
        builder = builder.header(header::CONTENT_LENGTH, n.to_string());
    }
    builder.body(body).unwrap()
}

fn xml_error(status: StatusCode, code: &str, message: &str) -> Response {
    let payload = format!("<Error><Code>{code}</Code><Message>{message}</Message></Error>");
    let bytes = payload.into_bytes();
    let len = bytes.len();
    s3_response(status, Some("application/xml"), None, Some(len), Body::from(bytes))
}

async fn handle_s3(
    State(state): State<Arc<Mutex<S3MemoryState>>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let raw = uri.path().trim_start_matches('/').to_owned();
    let (bucket, key) = raw.split_once('/').unwrap_or((raw.as_str(), ""));
    if bucket.is_empty() {
        return s3_response(
            StatusCode::OK,
            Some("application/xml"),
            None,
            None,
            Body::from("<ListAllMyBucketsResult/>"),
        );
    }
    if key.is_empty() && (method == Method::GET || method == Method::HEAD) {
        let xml = format!(
            "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>{bucket}</Name><KeyCount>0</KeyCount><IsTruncated>false</IsTruncated></ListBucketResult>"
        );
        let bytes = xml.into_bytes();
        let len = bytes.len();
        return s3_response(
            StatusCode::OK,
            Some("application/xml"),
            None,
            Some(len),
            if method == Method::HEAD { Body::empty() } else { Body::from(bytes) },
        );
    }

    let full_key = format!("{bucket}/{key}");
    match method {
        Method::PUT => {
            let if_none_match = headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) == Some("*");
            let mut guard = state.lock().unwrap();
            if if_none_match && guard.objects.contains_key(&full_key) {
                return xml_error(StatusCode::PRECONDITION_FAILED, "PreconditionFailed", "already exists");
            }
            let digest = hex::encode(Sha256::digest(&body));
            let etag = format!("\"{}\"", &digest[..32]);
            guard.objects.insert(full_key, body.to_vec());
            s3_response(StatusCode::OK, None, Some(&etag), Some(0), Body::empty())
        }
        Method::HEAD | Method::GET => {
            let maybe = state.lock().unwrap().objects.get(&full_key).cloned();
            let Some(stored) = maybe else {
                return if method == Method::HEAD {
                    s3_response(StatusCode::NOT_FOUND, Some("application/xml"), None, Some(0), Body::empty())
                } else {
                    xml_error(StatusCode::NOT_FOUND, "NoSuchKey", "missing")
                };
            };
            let digest = hex::encode(Sha256::digest(&stored));
            let etag = format!("\"{}\"", &digest[..32]);
            let len = stored.len();
            let payload = if method == Method::HEAD { Body::empty() } else { Body::from(stored) };
            s3_response(StatusCode::OK, Some("application/octet-stream"), Some(&etag), Some(len), payload)
        }
        Method::DELETE => {
            let mut guard = state.lock().unwrap();
            guard.delete_requests.push(full_key.clone());
            guard.objects.remove(&full_key);
            s3_response(StatusCode::NO_CONTENT, None, None, Some(0), Body::empty())
        }
        _ => s3_response(StatusCode::METHOD_NOT_ALLOWED, None, None, Some(0), Body::empty()),
    }
}

struct EnvGuard {
    saved: Vec<(&'static str, Option<String>)>,
}

impl EnvGuard {
    fn set(pairs: &[(&'static str, Option<&str>)]) -> Self {
        let mut saved = Vec::with_capacity(pairs.len());
        for &(key, next) in pairs {
            saved.push((key, std::env::var(key).ok()));
            match next {
                Some(v) => unsafe { std::env::set_var(key, v) },
                None => unsafe { std::env::remove_var(key) },
            }
        }
        Self { saved }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, prev) in self.saved.drain(..).rev() {
            match prev {
                Some(v) => unsafe { std::env::set_var(key, v) },
                None => unsafe { std::env::remove_var(key) },
            }
        }
    }
}

fn schema_pool(url: &str, schema: &str) -> Result<Pool> {
    let mut cfg: tokio_postgres::Config = url.parse()?;
    cfg.options(format!("-c search_path={schema} -c timezone=UTC -c statement_timeout=10000 -c lock_timeout=5000"));
    Ok(Pool::builder(Manager::new(cfg, tokio_postgres::NoTls))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .max_size(8)
        .build()?)
}

fn test_config(database_url: String, data_dir: PathBuf) -> Config {
    Config {
        database_url,
        data_dir,
        bind: "127.0.0.1:0".parse().unwrap(),
        git: PathBuf::from("/usr/bin/git"),
        max_request_bytes: 64 * 1024 * 1024,
        max_output_bytes: 64 * 1024 * 1024,
        max_concurrent_git: 2,
        git_timeout: Duration::from_secs(60),
        git_memory_bytes: 512 * 1024 * 1024,
        max_repo_bytes: 512 * 1024 * 1024,
        max_pending_deliveries: 1000,
        outbox_worker: false,
        metrics_bind: None,
    }
}

fn app_state(config: Config, pool: Pool) -> Result<Arc<AppState>> {
    let storage = Storage::open(&config)?;
    Ok(Arc::new(AppState {
        mirror_primary: None,
        dispatch: dispatch::Signals::default(),
        config,
        pool,
        storage,
        hooks: None,
        transfer_metrics: Arc::new(metrics::TransferCounters::default()),
        git_slots: Arc::new(Semaphore::new(2)),
    }))
}

fn test_policy() -> Policy {
    Policy {
        enabled: true,
        poll: Duration::from_secs(1),
        lease_seconds: 5,
        loose_threshold: 10,
        pack_threshold: 10,
        stage_age_seconds: 1,
        cache_max_age_seconds: 60,
        tombstone_grace_seconds: 1,
        scan_period_seconds: 1,
        quiescence_seconds: 1,
        max_attempts: 1,
    }
}

struct SeededManifest {
    id: Uuid,
    pack_cipher_key: ObjectKey,
    pack_env_key: ObjectKey,
    idx_cipher_key: ObjectKey,
    idx_env_key: ObjectKey,
}

fn receipt(tag: &str, tmp_dir: &Path) -> Result<(ArtifactReceipt, PathBuf, String, u64, PathBuf, String, u64)> {
    let plain = format!("plaintext-{tag}").into_bytes();
    let cipher = format!("ciphertext-{tag}").into_bytes();
    let p_sha = hex::encode(Sha256::digest(&plain));
    let c_sha = hex::encode(Sha256::digest(&cipher));
    let c_path = tmp_dir.join(format!("cipher-{tag}.bin"));
    std::fs::write(&c_path, &cipher)?;
    let env_struct = Envelope {
        version: 1,
        generation: 1,
        object_id: Uuid::new_v4(),
        cipher: "aes-256-gcm".into(),
        provider: "vault-transit".into(),
        key_name: "pando".into(),
        wrapped_key: "vault:v1:synthetic-test-key".into(),
        plaintext_sha256: p_sha.clone(),
        plaintext_bytes: plain.len() as u64,
        ciphertext_sha256: c_sha.clone(),
        ciphertext_bytes: cipher.len() as u64,
        chunk_bytes: 65536,
    };
    let env_bytes = serde_json::to_vec(&env_struct)?;
    let e_sha = hex::encode(Sha256::digest(&env_bytes));
    let e_path = tmp_dir.join(format!("env-{tag}.json"));
    std::fs::write(&e_path, &env_bytes)?;
    let ar = ArtifactReceipt {
        plaintext_sha256: p_sha,
        plaintext_bytes: plain.len() as u64,
        ciphertext_sha256: c_sha.clone(),
        ciphertext_bytes: cipher.len() as u64,
        envelope_sha256: e_sha.clone(),
        envelope_bytes: env_bytes.len() as u64,
        envelope: env_struct,
    };
    Ok((ar, c_path, c_sha, cipher.len() as u64, e_path, e_sha, env_bytes.len() as u64))
}

async fn seed_manifest(
    pool: &Pool,
    remote: &RemoteObjectStore,
    work_dir: &Path,
    repo_id: Uuid,
    tenant_id: Uuid,
    authority_id: Uuid,
    tag: &str,
) -> Result<SeededManifest> {
    let manifest_id = Uuid::new_v4();
    let (pack_ar, pc_path, pc_sha, pc_len, pe_path, pe_sha, pe_len) = receipt(&format!("{tag}-p"), work_dir)?;
    let (idx_ar, ic_path, ic_sha, ic_len, ie_path, ie_sha, ie_len) = receipt(&format!("{tag}-i"), work_dir)?;

    let (pc_slot, pe_slot, ic_slot, ie_slot) = {
        let mut client = pool.get().await?;
        let tx = client.transaction().await?;
        let (pc_slot, pe_slot) = retention::reserve_pair(&*tx, tenant_id, Some(manifest_id), &pc_sha, &pe_sha).await?;
        let (ic_slot, ie_slot) = retention::reserve_pair(&*tx, tenant_id, Some(manifest_id), &ic_sha, &ie_sha).await?;
        tx.commit().await?;
        (pc_slot, pe_slot, ic_slot, ie_slot)
    };

    remote.put_file(pc_slot.key(), &pc_path, pc_len, deadline()).await?;
    remote.put_file(pe_slot.key(), &pe_path, pe_len, deadline()).await?;
    remote.put_file(ic_slot.key(), &ic_path, ic_len, deadline()).await?;
    remote.put_file(ie_slot.key(), &ie_path, ie_len, deadline()).await?;

    let manifest = PackManifest {
        version: 1,
        id: manifest_id,
        repository_id: repo_id,
        tenant_id,
        storage_generation: 1,
        object_format: "sha1".into(),
        pack: pack_ar,
        index: idx_ar,
    };
    let manifest_json = serde_json::to_value(&manifest)?;

    let mut client = pool.get().await?;
    let tx = client.transaction().await?;
    ensure!(retention::activate(&*tx, tenant_id, "pando-cipher", &pc_sha, pc_len, &pc_slot).await?, "pc activate");
    ensure!(retention::activate(&*tx, tenant_id, "pando-envelope", &pe_sha, pe_len, &pe_slot).await?, "pe activate");
    ensure!(retention::activate(&*tx, tenant_id, "pando-cipher", &ic_sha, ic_len, &ic_slot).await?, "ic activate");
    ensure!(retention::activate(&*tx, tenant_id, "pando-envelope", &ie_sha, ie_len, &ie_slot).await?, "ie activate");
    tx.execute(
        "INSERT INTO pando_pack_manifests(id,repository_id,tenant_id,storage_generation,object_format,manifest) \
         VALUES($1,$2,$3,1,'sha1',$4)",
        &[&manifest_id, &repo_id, &tenant_id, &manifest_json],
    )
    .await?;
    retention::record_manifest(&*tx, &manifest, authority_id).await?;
    tx.execute("DELETE FROM pando_publication_fences WHERE manifest_id=$1", &[&manifest_id]).await?;
    tx.commit().await?;

    Ok(SeededManifest {
        id: manifest_id,
        pack_cipher_key: pc_slot.key().clone(),
        pack_env_key: pe_slot.key().clone(),
        idx_cipher_key: ic_slot.key().clone(),
        idx_env_key: ie_slot.key().clone(),
    })
}

async fn drain_worker(state: &Arc<AppState>, policy: &Policy) -> Result<()> {
    for _ in 0..32 {
        match Box::pin(worker::run_once(state, policy, Uuid::new_v4())).await? {
            Some(_) => {}
            None => return Ok(()),
        }
    }
    anyhow::bail!("worker loop did not drain");
}

async fn clone_schema_metadata(admin: &Pool, src: &str, dst: &str) -> Result<()> {
    let client = admin.get().await?;
    let sql = format!(
        "INSERT INTO {dst}.users SELECT * FROM {src}.users; \
         INSERT INTO {dst}.repositories SELECT * FROM {src}.repositories; \
         INSERT INTO {dst}.pando_repository_states SELECT * FROM {src}.pando_repository_states; \
         INSERT INTO {dst}.pando_pack_manifests SELECT * FROM {src}.pando_pack_manifests; \
         UPDATE {dst}.pando_storage_authorities d SET \
           authority_id = s.authority_id, \
           generation = s.generation, \
           restore_generation = s.restore_generation, \
           authority_epoch = s.authority_epoch, \
           deployment_id = s.deployment_id, \
           volume_id = s.volume_id, \
           db_system_identifier = s.db_system_identifier, \
           db_database_oid = s.db_database_oid, \
           db_schema_oid = s.db_schema_oid, \
           pg_timeline_id = s.pg_timeline_id, \
           backend_identity = s.backend_identity, \
           proof_nonce = s.proof_nonce, \
           remote_delete_fenced = s.remote_delete_fenced, \
           remote_delete_fence_reason = s.remote_delete_fence_reason, \
           attested_at = s.attested_at \
         FROM {src}.pando_storage_authorities s WHERE d.singleton AND s.singleton; \
         INSERT INTO {dst}.pando_remote_artifacts SELECT * FROM {src}.pando_remote_artifacts; \
         INSERT INTO {dst}.pando_manifest_artifacts SELECT * FROM {src}.pando_manifest_artifacts; \
         INSERT INTO {dst}.pando_retention_roots SELECT * FROM {src}.pando_retention_roots; \
         INSERT INTO {dst}.pando_retention_root_manifests SELECT * FROM {src}.pando_retention_root_manifests;"
    );
    client.batch_execute(&sql).await?;
    Ok(())
}

struct PrimaryRefs<'a> {
    pool: &'a Pool,
    state: &'a Arc<AppState>,
    policy: &'a Policy,
    remote: &'a RemoteObjectStore,
    s3: &'a LoopbackS3,
    owner: Uuid,
    repo: Uuid,
}

async fn verify_retention_roots_and_pruning(
    primary: &PrimaryRefs<'_>,
    m_keep: &SeededManifest,
    m_pinned: &SeededManifest,
    m_drop: &SeededManifest,
    legacy_key: &ObjectKey,
    foreign_key: &ObjectKey,
) -> Result<()> {
    let pool_a = primary.pool;
    let state_a = primary.state;
    let policy = primary.policy;
    let remote = primary.remote;
    let s3 = primary.s3;
    let owner = primary.owner;
    let repo = primary.repo;
    // Pin a PITR recovery root while m_pinned is live (advances epoch 1 -> 2),
    // then drop m_pinned from pando_repository_states.pack_ids and prove retention root preserves it.
    let pin = Box::pin(retention_roots::pin_recovery_root(
        pool_a,
        &state_a.storage.root,
        remote,
        owner,
        Some(repo),
        RetentionRootKind::PitrRecoveryPoint,
        Some("pre-gc-checkpoint"),
        Some(3600),
        &[],
        deadline(),
    ))
    .await?;
    ensure!(pin.manifest_count == 2, "expected m_keep and m_pinned captured in retention root");
    ensure!(pitr_fence::load_authority_state(&**pool_a.get().await?).await?.authority_epoch == 2);

    let remaining_packs: &[Uuid] = &[m_keep.id];
    pool_a
        .get()
        .await?
        .execute("UPDATE pando_repository_states SET pack_ids=$2 WHERE repository_id=$1", &[&repo, &remaining_packs])
        .await?;

    Box::pin(scheduler::schedule_once(state_a, policy)).await?;
    drain_worker(state_a, policy).await?;

    // Force m_drop's retired rows past tombstone grace and verify remote delete advances epoch 2 -> 3
    // while keeping m_keep, m_pinned, legacy_key, and foreign_key intact.
    pool_a
        .get()
        .await?
        .execute(
            "UPDATE pando_remote_artifacts SET delete_after=clock_timestamp()-interval '10 seconds' WHERE state='retired'",
            &[],
        )
        .await?;
    pool_a.get().await?.execute("UPDATE storage_maintenance_repo_state SET last_scan_at=NULL", &[]).await?;
    s3.take_deletes();
    Box::pin(scheduler::schedule_once(state_a, policy)).await?;
    drain_worker(state_a, policy).await?;

    let post_del_epoch = pitr_fence::load_authority_state(&**pool_a.get().await?).await?.authority_epoch;
    ensure!(post_del_epoch == 3, "expected epoch advance 2 -> 3 on real remote deletion");
    let deleted_keys = s3.take_deletes();
    ensure!(deleted_keys.len() == 4, "expected only m_drop's 4 artifacts deleted, got {deleted_keys:?}");
    for k in [&m_drop.pack_cipher_key, &m_drop.pack_env_key, &m_drop.idx_cipher_key, &m_drop.idx_env_key] {
        ensure!(!s3.contains(&k.path()), "expected dropped object {} removed", k.path());
    }
    for k in [&m_keep.pack_cipher_key, &m_pinned.pack_cipher_key, &m_pinned.idx_env_key, legacy_key, foreign_key] {
        ensure!(s3.contains(&k.path()), "retained object {} was deleted unexpectedly", k.path());
    }

    // Release recovery root -> m_pinned becomes eligible, retires, and deletes after grace.
    ensure!(retention_roots::release_recovery_root(pool_a, pin.id).await?);
    pool_a.get().await?.execute("UPDATE storage_maintenance_repo_state SET last_scan_at=NULL", &[]).await?;
    Box::pin(scheduler::schedule_once(state_a, policy)).await?;
    drain_worker(state_a, policy).await?;
    pool_a
        .get()
        .await?
        .execute(
            "UPDATE pando_remote_artifacts SET delete_after=clock_timestamp()-interval '10 seconds' WHERE state='retired'",
            &[],
        )
        .await?;
    pool_a.get().await?.execute("UPDATE storage_maintenance_repo_state SET last_scan_at=NULL", &[]).await?;
    Box::pin(scheduler::schedule_once(state_a, policy)).await?;
    drain_worker(state_a, policy).await?;
    ensure!(pitr_fence::load_authority_state(&**pool_a.get().await?).await?.authority_epoch == 4);
    ensure!(!s3.contains(&m_pinned.pack_cipher_key.path()), "expected released pin pack removed");
    ensure!(s3.contains(&m_keep.pack_cipher_key.path()), "m_keep must remain preserved");
    ensure!(s3.contains(&legacy_key.path()), "legacy v1 object must stay preserved");
    ensure!(s3.contains(&foreign_key.path()), "foreign authority object must stay preserved");
    Ok(())
}

struct CloneTarget<'a> {
    db_url: &'a str,
    schemas: (&'a str, &'a str),
    data_a: &'a Path,
    data_b: PathBuf,
    work_dir: &'a Path,
    pool_b: &'a Pool,
    auth_a: &'a pitr_fence::AuthorityState,
}

async fn verify_clone_fencing_and_isolate(
    primary: &PrimaryRefs<'_>,
    admin: &Pool,
    m_keep: &SeededManifest,
    target: CloneTarget<'_>,
) -> Result<SeededManifest> {
    let CloneTarget { db_url, schemas: (schema_a, schema_b), data_a, data_b, work_dir, pool_b, auth_a } = target;
    // Out-of-band PG metadata clone sharing the SAME bucket (and even identical
    // copied local markers) MUST detect mismatched schema/cluster coordinates,
    // latch remote_delete_fenced=true, and issue ZERO S3 DELETEs.
    let m_protected = Box::pin(seed_manifest(
        primary.pool,
        primary.remote,
        work_dir,
        primary.repo,
        primary.owner,
        auth_a.authority_id,
        "protected",
    ))
    .await?;
    clone_schema_metadata(admin, schema_a, schema_b).await?;
    pool_b
        .get()
        .await?
        .execute(
            "UPDATE pando_remote_artifacts SET state='retired', delete_after=clock_timestamp()-interval '60 seconds' \
             WHERE sha256=$1",
            &[&m_protected.pack_cipher_key.sha256],
        )
        .await?;
    let state_b = app_state(test_config(db_url.to_owned(), data_b.clone()), pool_b.clone())?;
    std::fs::copy(data_a.join(".volume-id"), data_b.join(".volume-id"))?;
    std::fs::copy(data_a.join(".pando-deployment-id"), data_b.join(".pando-deployment-id"))?;

    primary.s3.take_deletes();
    let sched_decision = Box::pin(pando_delete_gate::check_scheduler_gate(&state_b, deadline())).await?;
    ensure!(
        matches!(sched_decision, DeleteGateDecision::Fenced { .. }),
        "expected scheduler gate to fence PG schema clone"
    );
    let auth_b = pitr_fence::load_authority_state(&**pool_b.get().await?).await?;
    ensure!(auth_b.remote_delete_fenced, "clone authority row must latch remote_delete_fenced=true");
    jobs::enqueue(pool_b, primary.repo, primary.owner, 1, "pando_tombstone_delete").await?;
    drain_worker(&state_b, primary.policy).await?;
    let clone_job_state: String = pool_b
        .get()
        .await?
        .query_one("SELECT state FROM storage_maintenance_jobs WHERE kind='pando_tombstone_delete' ORDER BY created_at DESC LIMIT 1", &[])
        .await?
        .get(0);
    ensure!(clone_job_state == "failed", "fenced delete job must fail closed, got {clone_job_state}");
    ensure!(primary.s3.take_deletes().is_empty(), "fenced clone issued remote DELETE");
    ensure!(primary.s3.contains(&m_protected.pack_cipher_key.path()), "clone damaged shared production object");
    ensure!(
        pitr_fence::ensure_not_fenced(&**pool_b.get().await?).await.is_err(),
        "fenced clone must refuse new mutations"
    );

    // Explicit isolate_cloned_authority mints a fresh authority_id, bumps restore_generation,
    // clears remote_delete_fenced, and never deletes old authority objects.
    let isolated =
        Box::pin(pitr_fence::isolate_cloned_authority(pool_b, &state_b.storage.root, primary.remote, deadline()))
            .await?;
    ensure!(isolated.authority_id != auth_a.authority_id);
    ensure!(isolated.restore_generation == auth_a.restore_generation + 1);
    ensure!(isolated.authority_epoch == 1 && !isolated.remote_delete_fenced);
    ensure!(
        primary.s3.contains(&format!("pando-authorities/{}/epochs/00000000000000000001.json", isolated.authority_id))
    );
    ensure!(primary.s3.contains(&m_protected.pack_cipher_key.path()));
    ensure!(primary.s3.contains(&m_keep.pack_cipher_key.path()));

    // Verify all 4 scoped artifacts of live m_keep re-registered under isolated.authority_id
    // and can be hydrated from an empty local cache directory without touching auth_a's keys.
    let hydrate_dir = work_dir.join("isolated-hydrate-check");
    std::fs::create_dir_all(&hydrate_dir)?;
    {
        let client_b = pool_b.get().await?;
        for (idx, (ns, old_key)) in [
            (retention::NAMESPACE_CIPHER, &m_keep.pack_cipher_key),
            (retention::NAMESPACE_ENVELOPE, &m_keep.pack_env_key),
            (retention::NAMESPACE_CIPHER, &m_keep.idx_cipher_key),
            (retention::NAMESPACE_ENVELOPE, &m_keep.idx_env_key),
        ]
        .into_iter()
        .enumerate()
        {
            let resolved = retention::resolve_artifact(&**client_b, primary.owner, ns, &old_key.sha256).await?;
            ensure!(resolved.registered, "isolated live artifact must remain registered");
            ensure!(
                resolved.key.authority == Some((isolated.authority_id, 1)),
                "isolated live artifact resolved under wrong authority: {:?}",
                resolved.key.authority
            );
            ensure!(resolved.key.path() != old_key.path(), "isolated key must differ from source authority path");
            let head = primary
                .remote
                .head(&resolved.key, deadline())
                .await?
                .context("isolated remote artifact missing in object store")?;
            let dest = hydrate_dir.join(format!("art-{idx}.bin"));
            primary.remote.get_to_file(&resolved.key, &dest, head.size, deadline()).await?;
        }
    }

    // Fail-closed check: if a live manifest's artifact was already marked deleted, isolate MUST refuse
    // without rotating authority_id.
    pool_b
        .get()
        .await?
        .execute(
            "UPDATE pando_remote_artifacts SET state='deleted', deleted_at=clock_timestamp() \
             WHERE authority_id=$1 AND sha256=$2",
            &[&isolated.authority_id, &m_keep.pack_cipher_key.sha256],
        )
        .await?;
    let blocked_isolate =
        Box::pin(pitr_fence::isolate_cloned_authority(pool_b, &state_b.storage.root, primary.remote, deadline())).await;
    ensure!(blocked_isolate.is_err(), "isolate must fail closed when a live manifest artifact is deleted");
    ensure!(
        pitr_fence::load_authority_state(&**pool_b.get().await?).await?.authority_id == isolated.authority_id,
        "failed isolate must not rotate authority_id"
    );

    Ok(m_protected)
}

async fn verify_pitr_rollback_and_split_brain(
    primary: &PrimaryRefs<'_>,
    db_url: &str,
    data_c: PathBuf,
    pool_c: &Pool,
    m_protected: &SeededManifest,
) -> Result<()> {
    // Simulate PostgreSQL PITR rollback on primary schema_a (epoch rewound behind external epoch 4 proof).
    primary
        .pool
        .get()
        .await?
        .execute("UPDATE pando_storage_authorities SET authority_epoch = authority_epoch - 1 WHERE singleton", &[])
        .await?;
    primary
        .pool
        .get()
        .await?
        .execute(
            "UPDATE pando_remote_artifacts SET state='retired', delete_after=clock_timestamp()-interval '60 seconds' \
             WHERE sha256=$1",
            &[&m_protected.pack_cipher_key.sha256],
        )
        .await?;
    primary.s3.take_deletes();
    let rollback_gate = Box::pin(pando_delete_gate::check_scheduler_gate(primary.state, deadline())).await?;
    ensure!(matches!(rollback_gate, DeleteGateDecision::Fenced { .. }), "PITR epoch rollback must fence");
    ensure!(pitr_fence::load_authority_state(&**primary.pool.get().await?).await?.remote_delete_fenced);
    jobs::enqueue(primary.pool, primary.repo, primary.owner, 1, "pando_tombstone_delete").await?;
    drain_worker(primary.state, primary.policy).await?;
    ensure!(primary.s3.take_deletes().is_empty(), "PITR-rolled-back DB issued remote DELETE");
    ensure!(primary.s3.contains(&m_protected.pack_cipher_key.path()));

    // Split-brain epoch-1 creation race fails closed on S3 If-None-Match 412 conflict.
    let state_c = app_state(test_config(db_url.to_owned(), data_c), pool_c.clone())?;
    let auth_c_initial = pitr_fence::load_authority_state(&**pool_c.get().await?).await?;
    let rival_proof = AuthorityEpochProof {
        version: PROOF_VERSION,
        authority_id: auth_c_initial.authority_id,
        epoch: 1,
        restore_generation: 0,
        generation: 1,
        deployment_id: Uuid::new_v4(),
        volume_id: Uuid::new_v4(),
        db_system_identifier: "9999999999999999".into(),
        db_database_oid: 12345,
        db_schema_oid: 2200,
        pg_timeline_id: 1,
        backend_identity: primary.remote.backend_identity()?,
        proof_nonce: Uuid::new_v4(),
        operation: "attest".into(),
    };
    primary.s3.insert_raw(
        &format!("pando-authorities/{}/epochs/00000000000000000001.json", auth_c_initial.authority_id),
        serde_json::to_vec(&rival_proof)?,
    );
    let split_res =
        Box::pin(pitr_fence::verify_or_attest(pool_c, &state_c.storage.root, primary.remote, deadline(), "attest"))
            .await;
    ensure!(split_res.is_err(), "pre-claimed epoch-1 object must fence split-brain runtime");
    ensure!(pitr_fence::load_authority_state(&**pool_c.get().await?).await?.remote_delete_fenced);
    Ok(())
}

#[tokio::test]
async fn pando_pitr_authority_fencing_and_retention_roots() -> Result<()> {
    let Some(db_url) = std::env::var("ROOTYARD_TEST_DATABASE_URL").ok().filter(|v| !v.is_empty()) else {
        eprintln!("pando_pitr_fencing skipped: ROOTYARD_TEST_DATABASE_URL is unset");
        return Ok(());
    };

    let admin = db::pool(&db_url)?;
    let suffix = Uuid::new_v4().simple().to_string();
    let schema_a = format!("pitr_a_{suffix}");
    let schema_b = format!("pitr_b_{suffix}");
    let schema_c = format!("pitr_c_{suffix}");
    for s in [&schema_a, &schema_b, &schema_c] {
        admin.get().await?.batch_execute(&format!("CREATE SCHEMA {s}")).await?;
    }

    let admin_task = admin.clone();
    let schema_a_task = schema_a.clone();
    let schema_b_task = schema_b.clone();
    let schema_c_task = schema_c.clone();
    let result = tokio::spawn(Box::pin(async move {
        let admin = admin_task;
        let schema_a = schema_a_task;
        let schema_b = schema_b_task;
        let schema_c = schema_c_task;
        let s3 = LoopbackS3::start().await?;
        let tmp = TempDir::new()?;
        let data_a = tmp.path().join("data-a");
        let data_b = tmp.path().join("data-b");
        let data_c = tmp.path().join("data-c");
        let work_dir = tmp.path().join("work");
        std::fs::create_dir_all(&work_dir)?;

        let _env = EnvGuard::set(&[
            ("ROOTYARD_OBJECT_STORE_ENDPOINT", Some(&s3.endpoint)),
            ("ROOTYARD_OBJECT_STORE_BUCKET", Some(s3.bucket)),
            ("ROOTYARD_OBJECT_STORE_REGION", Some(s3.region)),
            ("ROOTYARD_OBJECT_STORE_ACCESS_KEY", Some("pitr-test-ak")),
            ("ROOTYARD_OBJECT_STORE_SECRET_KEY", Some("pitr-test-sk")),
            ("ROOTYARD_OBJECT_STORE_SESSION_TOKEN", None),
            ("ROOTYARD_PANDO_REMOTE_DELETE", Some("invalid-value")),
        ]);

        // 1. Fail-closed strict validation of ROOTYARD_PANDO_REMOTE_DELETE.
        ensure!(
            pando_delete_gate::remote_delete_env_enabled().is_err(),
            "bogus ROOTYARD_PANDO_REMOTE_DELETE value must fail closed"
        );
        unsafe { std::env::set_var("ROOTYARD_PANDO_REMOTE_DELETE", "true") };

        let pool_a = schema_pool(&db_url, &schema_a)?;
        let pool_b = schema_pool(&db_url, &schema_b)?;
        let pool_c = schema_pool(&db_url, &schema_c)?;
        db::migrate(&pool_a).await?;
        db::migrate(&pool_b).await?;
        db::migrate(&pool_c).await?;

        let state_a = app_state(test_config(db_url.clone(), data_a.clone()), pool_a.clone())?;
        let policy = test_policy();
        let remote = RemoteObjectStore::from_env(work_dir.clone())?;

        // 2. Startup check writes external epoch-1 proof and binds PG + local volume coordinates.
        Box::pin(pitr_fence::startup_check(&pool_a, &state_a.storage.root)).await?;
        let auth_a = pitr_fence::load_authority_state(&**pool_a.get().await?).await?;
        ensure!(auth_a.attested_at.is_some(), "expected attested authority after startup_check");
        ensure!(auth_a.authority_epoch == 1 && auth_a.restore_generation == 0 && !auth_a.remote_delete_fenced);
        ensure!(s3.contains(&format!("pando-authorities/{}/epochs/00000000000000000001.json", auth_a.authority_id)));

        let owner = Uuid::new_v4();
        let repo = Uuid::new_v4();
        let slug = format!("u{}", &owner.simple().to_string()[..12]);
        {
            let client = pool_a.get().await?;
            client.execute("INSERT INTO users(id,username) VALUES($1,$2)", &[&owner, &slug]).await?;
            client
                .execute(
                    "INSERT INTO repositories(id,owner_id,name,state,storage_backend,transition_state,storage_generation) \
                     VALUES($1,$2,'pitr-repo','ready','pando','stable',1)",
                    &[&repo, &owner],
                )
                .await?;
            client
                .execute(
                    "INSERT INTO pando_repository_states(repository_id,tenant_id,storage_generation,state,object_format,pack_ids) \
                     VALUES($1,$2,1,'serving','sha1','{}')",
                    &[&repo, &owner],
                )
                .await?;
        }

        let m_keep = Box::pin(seed_manifest(&pool_a, &remote, &work_dir, repo, owner, auth_a.authority_id, "keep")).await?;
        let m_pinned = Box::pin(seed_manifest(&pool_a, &remote, &work_dir, repo, owner, auth_a.authority_id, "pin")).await?;
        let m_drop = Box::pin(seed_manifest(&pool_a, &remote, &work_dir, repo, owner, auth_a.authority_id, "drop")).await?;

        let initial_packs: &[Uuid] = &[m_keep.id, m_pinned.id];
        pool_a
            .get()
            .await?
            .execute("UPDATE pando_repository_states SET pack_ids=$2 WHERE repository_id=$1", &[&repo, &initial_packs])
            .await?;

        let legacy_bytes = b"legacy-v1-unregistered-bytes";
        let legacy_sha = hex::encode(Sha256::digest(legacy_bytes));
        let legacy_file = work_dir.join("legacy.bin");
        std::fs::write(&legacy_file, legacy_bytes)?;
        let legacy_key = ObjectKey::new(owner, "pando-cipher", &legacy_sha)?;
        remote.put_file(&legacy_key, &legacy_file, legacy_bytes.len() as u64, deadline()).await?;
        let foreign_auth = Uuid::new_v4();
        let foreign_key = ObjectKey::scoped(owner, foreign_auth, 1, "pando-cipher", &legacy_sha)?;
        s3.insert_raw(&foreign_key.path(), legacy_bytes.to_vec());

        ensure!(
            pando_delete_gate::validate_scoped_delete_target(
                auth_a.authority_id,
                auth_a.authority_id,
                owner,
                1,
                "pando-cipher",
                &legacy_sha,
                &legacy_key.path(),
            )
            .is_err()
        );
        ensure!(
            pando_delete_gate::validate_scoped_delete_target(
                auth_a.authority_id,
                foreign_auth,
                owner,
                1,
                "pando-cipher",
                &legacy_sha,
                &foreign_key.path(),
            )
            .is_err()
        );
        ensure!(
            pando_delete_gate::validate_scoped_delete_target(
                auth_a.authority_id,
                auth_a.authority_id,
                owner,
                1,
                "pando-cipher",
                &legacy_sha,
                &format!("pando-authorities/{}/epochs/00000000000000000001.json", auth_a.authority_id),
            )
            .is_err()
        );

        let primary = PrimaryRefs {
            pool: &pool_a,
            state: &state_a,
            policy: &policy,
            remote: &remote,
            s3: &s3,
            owner,
            repo,
        };
        Box::pin(verify_retention_roots_and_pruning(
            &primary,
            &m_keep,
            &m_pinned,
            &m_drop,
            &legacy_key,
            &foreign_key,
        ))
        .await?;

        let m_protected = Box::pin(verify_clone_fencing_and_isolate(
            &primary,
            &admin,
            &m_keep,
            CloneTarget {
                db_url: &db_url,
                schemas: (&schema_a, &schema_b),
                data_a: &data_a,
                data_b,
                work_dir: &work_dir,
                pool_b: &pool_b,
                auth_a: &auth_a,
            },
        ))
        .await?;

        Box::pin(verify_pitr_rollback_and_split_brain(&primary, &db_url, data_c, &pool_c, &m_protected)).await?;

        Ok::<(), anyhow::Error>(())
    }))
    .await
    .context("pando_pitr_fencing test task panicked");

    for s in [&schema_a, &schema_b, &schema_c] {
        let _ = admin.get().await?.batch_execute(&format!("DROP SCHEMA IF EXISTS {s} CASCADE")).await;
    }

    result??;
    Ok(())
}
