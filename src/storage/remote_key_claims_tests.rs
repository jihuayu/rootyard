//! PG-backed and mock-S3 fault-injection regression tests for remote key claims (#85).
use crate::storage::{
    remote_key_claims::{
        DEFAULT_DELETE_CLAIM_LEASE_SECS, execute_locked_claimed_delete, has_active_delete_claim, lock_object_key,
        sweep_expired_claims_with_stores, upsert_delete_claim, valid_claim_target, wait_or_clear_delete_claim,
    },
    remote_objects::{ObjectKey, RemoteObjectStore},
    remote_provider::LegacyS3Store,
};
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Method, StatusCode, header},
    response::Response,
};
use deadpool_postgres::Pool;
use reqwest::Url;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{net::TcpListener, sync::Notify, time::Instant};
use uuid::Uuid;

struct MockDeleteS3 {
    objects: Mutex<HashMap<String, Vec<u8>>>,
    gate_first_delete: AtomicBool,
    fail_deletes_500: AtomicBool,
    first_delete_entered: Notify,
    release_first_delete: Notify,
    first_delete_finished: Notify,
}

impl MockDeleteS3 {
    fn new() -> Self {
        Self {
            objects: Mutex::new(HashMap::new()),
            gate_first_delete: AtomicBool::new(false),
            fail_deletes_500: AtomicBool::new(false),
            first_delete_entered: Notify::new(),
            release_first_delete: Notify::new(),
            first_delete_finished: Notify::new(),
        }
    }
}

fn empty_resp(status: StatusCode) -> Response {
    Response::builder().status(status).header(header::CONTENT_LENGTH, "0").body(Body::empty()).unwrap()
}

async fn handle_mock_s3(
    State(state): State<Arc<MockDeleteS3>>,
    method: Method,
    uri: axum::http::Uri,
    body: axum::body::Bytes,
) -> Response {
    let key = uri.path().trim_start_matches('/').to_owned();
    match method {
        Method::PUT => {
            state.objects.lock().unwrap().insert(key, body.to_vec());
            Response::builder()
                .status(StatusCode::OK)
                .header(header::ETAG, "\"mock-etag\"")
                .header(header::CONTENT_LENGTH, "0")
                .body(Body::empty())
                .unwrap()
        }
        Method::HEAD => {
            let len = state.objects.lock().unwrap().get(&key).map(|v| v.len());
            match len {
                Some(n) => Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_LENGTH, n.to_string())
                    .body(Body::empty())
                    .unwrap(),
                None => empty_resp(StatusCode::NOT_FOUND),
            }
        }
        Method::GET => {
            let data = state.objects.lock().unwrap().get(&key).cloned();
            match data {
                Some(bytes) => Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_LENGTH, bytes.len().to_string())
                    .body(Body::from(bytes))
                    .unwrap(),
                None => empty_resp(StatusCode::NOT_FOUND),
            }
        }
        Method::DELETE => {
            if state.gate_first_delete.swap(false, Ordering::SeqCst) {
                let st = Arc::clone(&state);
                let del_key = key.clone();
                tokio::spawn(async move {
                    let release = st.release_first_delete.notified();
                    st.first_delete_entered.notify_one();
                    release.await;
                    st.objects.lock().unwrap().remove(&del_key);
                    st.first_delete_finished.notify_one();
                });
                return std::future::pending::<Response>().await;
            }
            if state.fail_deletes_500.load(Ordering::SeqCst) {
                return empty_resp(StatusCode::INTERNAL_SERVER_ERROR);
            }
            state.objects.lock().unwrap().remove(&key);
            empty_resp(StatusCode::NO_CONTENT)
        }
        _ => empty_resp(StatusCode::METHOD_NOT_ALLOWED),
    }
}

async fn start_mock_s3(state: Arc<MockDeleteS3>) -> (RemoteObjectStore, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().fallback(handle_mock_s3).with_state(state);
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let endpoint = Url::parse(&format!("http://{addr}")).unwrap();
    let s3 =
        LegacyS3Store::open(&endpoint, "claim-test", "us-east-1", "test-ak".to_owned(), "test-sk".to_owned(), None)
            .unwrap();
    (RemoteObjectStore::OpenDal(s3), server)
}

async fn setup_claims_pool() -> Option<Pool> {
    let base = std::env::var("ROOTYARD_TEST_DATABASE_URL").ok()?;
    let admin = crate::db::pool(&base).unwrap();
    let schema = format!("claims_{}", Uuid::new_v4().simple());
    admin.get().await.unwrap().batch_execute(&format!("CREATE SCHEMA {schema}")).await.unwrap();
    let mut url = reqwest::Url::parse(&base).unwrap();
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let pool = crate::db::pool(url.as_str()).unwrap();
    let c = pool.get().await.unwrap();
    c.batch_execute(
        "CREATE TABLE namespaces(id uuid PRIMARY KEY); \
         CREATE TABLE repositories(id uuid PRIMARY KEY, owner_id uuid NOT NULL REFERENCES namespaces(id)); \
         CREATE TABLE lfs_objects(tenant_id uuid NOT NULL, repository_id uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE, oid text NOT NULL, PRIMARY KEY(tenant_id, repository_id, oid)); \
         CREATE TABLE workspace_checkpoints(id uuid PRIMARY KEY, repository_id uuid NOT NULL, manifest_digest text); \
         CREATE TABLE workspace_remote_staging_objects(checkpoint_id uuid NOT NULL, tenant_id uuid NOT NULL, digest text NOT NULL); \
         CREATE TABLE remote_object_delete_claims( \
           tenant_id uuid NOT NULL, namespace text NOT NULL, digest text NOT NULL, \
           claim_generation bigint NOT NULL DEFAULT 1, deleting boolean NOT NULL DEFAULT true, \
           delete_uncertain boolean NOT NULL DEFAULT false, lease_until timestamptz NOT NULL, \
           claimed_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(tenant_id, namespace, digest))",
    )
    .await
    .unwrap();
    Some(pool)
}

#[test]
fn valid_claim_target_and_default_lease_invariants() {
    let ok = "a".repeat(64);
    assert!(valid_claim_target("lfs", &ok).is_ok());
    assert!(valid_claim_target("workspace", &ok).is_ok());
    assert!(valid_claim_target("pando", &ok).is_err());
    assert!(valid_claim_target("lfs", "short").is_err());
    assert!(valid_claim_target("lfs", &"A".repeat(64)).is_err());
    const {
        assert!(DEFAULT_DELETE_CLAIM_LEASE_SECS >= 60);
    }
}

#[tokio::test]
async fn expired_claim_flushes_unshared_stale_bytes_and_preserves_live_refs() {
    let Some(pool) = setup_claims_pool().await else {
        return;
    };
    let c = pool.get().await.unwrap();
    let dir = std::env::temp_dir().join(format!("ry-claim-test-{}", Uuid::new_v4()));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let store = RemoteObjectStore::Local(dir.join("remote"));
    let tenant = Uuid::new_v4();
    let repo = Uuid::new_v4();
    c.execute("INSERT INTO namespaces(id) VALUES($1)", &[&tenant]).await.unwrap();
    c.execute("INSERT INTO repositories(id, owner_id) VALUES($1, $2)", &[&repo, &tenant]).await.unwrap();

    let payload = b"stale-purge-payload";
    let oid = hex::encode(Sha256::digest(payload));
    let staged_file = dir.join("stale.bin");
    tokio::fs::write(&staged_file, payload).await.unwrap();
    let key = ObjectKey::new(tenant, "lfs", &oid).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    store.put_file(&key, &staged_file, payload.len() as u64, deadline).await.unwrap();

    let mut c_mut = pool.get().await.unwrap();
    let tx = c_mut.transaction().await.unwrap();
    let claim = upsert_delete_claim(&tx, tenant, "lfs", &oid, 1).await.unwrap();
    assert_eq!(claim.claim_generation, 1);
    tx.commit().await.unwrap();

    c.execute(
        "UPDATE remote_object_delete_claims SET lease_until = clock_timestamp() - interval '1 second' \
         WHERE tenant_id=$1 AND namespace='lfs' AND digest=$2",
        &[&tenant, &oid],
    )
    .await
    .unwrap();
    wait_or_clear_delete_claim(&pool, Some(&store), tenant, "lfs", &oid, deadline).await.unwrap();
    assert!(store.head(&key, deadline).await.unwrap().is_none());

    store.put_file(&key, &staged_file, payload.len() as u64, deadline).await.unwrap();
    c.execute("INSERT INTO lfs_objects(tenant_id, repository_id, oid) VALUES($1,$2,$3)", &[&tenant, &repo, &oid])
        .await
        .unwrap();
    c.execute(
        "UPDATE remote_object_delete_claims SET deleting=true, lease_until=clock_timestamp()-interval '1 second' \
         WHERE tenant_id=$1 AND namespace='lfs' AND digest=$2",
        &[&tenant, &oid],
    )
    .await
    .unwrap();
    let swept = sweep_expired_claims_with_stores(&pool, Some(&store), None, deadline).await.unwrap();
    assert_eq!(swept, 1);
    assert!(store.head(&key, deadline).await.unwrap().is_some());
    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[tokio::test]
async fn blocked_first_delete_timeout_and_500_fail_closed_across_recovery() {
    let Some(pool) = setup_claims_pool().await else {
        return;
    };
    let mock = Arc::new(MockDeleteS3::new());
    let (raw_store, server) = start_mock_s3(mock.clone()).await;
    let store = Arc::new(raw_store);
    let dir = std::env::temp_dir().join(format!("ry-claim-s3-{}", Uuid::new_v4()));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let c = pool.get().await.unwrap();
    let tenant = Uuid::new_v4();
    let repo = Uuid::new_v4();
    c.execute("INSERT INTO namespaces(id) VALUES($1)", &[&tenant]).await.unwrap();
    c.execute("INSERT INTO repositories(id, owner_id) VALUES($1, $2)", &[&repo, &tenant]).await.unwrap();

    let payload = b"blocked-delete-interleaving-payload";
    let oid = hex::encode(Sha256::digest(payload));
    let oid_err = hex::encode(Sha256::digest(b"http-500-delete-payload"));
    let file_path = dir.join("obj.bin");
    tokio::fs::write(&file_path, payload).await.unwrap();
    let key = ObjectKey::new(tenant, "lfs", &oid).unwrap();
    let key_err = ObjectKey::new(tenant, "lfs", &oid_err).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    store.put_file(&key, &file_path, payload.len() as u64, deadline).await.unwrap();

    // 1. Block 1st DELETE inside mock S3 -> client timeout/cancel -> run recovery -> attempt publish (MUST fail closed 503) -> finally release 1st DELETE.
    let mut c_mut = pool.get().await.unwrap();
    let tx = c_mut.transaction().await.unwrap();
    let claim = upsert_delete_claim(&tx, tenant, "lfs", &oid, 60).await.unwrap();
    tx.commit().await.unwrap();

    mock.gate_first_delete.store(true, Ordering::SeqCst);
    let entered = mock.first_delete_entered.notified();
    let pool_a = pool.clone();
    let store_a = Arc::clone(&store);
    let claim_a = claim.clone();
    let mut deleter = tokio::spawn(async move {
        execute_locked_claimed_delete(&pool_a, store_a.as_ref(), &claim_a, Instant::now() + Duration::from_secs(30))
            .await
    });
    entered.await;
    assert!(tokio::time::timeout(Duration::from_millis(80), &mut deleter).await.is_err());
    deleter.abort();
    let _ = deleter.await;

    c.execute(
        "UPDATE remote_object_delete_claims SET lease_until = clock_timestamp() - interval '10 seconds' \
         WHERE tenant_id=$1 AND namespace='lfs' AND digest=$2",
        &[&tenant, &oid],
    )
    .await
    .unwrap();
    assert_eq!(sweep_expired_claims_with_stores(&pool, Some(store.as_ref()), None, deadline).await.unwrap(), 0);
    let pub_err =
        wait_or_clear_delete_claim(&pool, Some(store.as_ref()), tenant, "lfs", &oid, deadline).await.unwrap_err();
    assert_eq!(pub_err.0, StatusCode::SERVICE_UNAVAILABLE);
    let mut c_chk = pool.get().await.unwrap();
    let tx_chk = c_chk.transaction().await.unwrap();
    assert!(has_active_delete_claim(&tx_chk, tenant, "lfs", &oid).await.unwrap());
    tx_chk.commit().await.unwrap();

    let finished = mock.first_delete_finished.notified();
    mock.release_first_delete.notify_one();
    finished.await;
    assert!(store.head(&key, deadline).await.unwrap().is_none());
    assert_eq!(
        wait_or_clear_delete_claim(&pool, Some(store.as_ref()), tenant, "lfs", &oid, deadline).await.unwrap_err().0,
        StatusCode::SERVICE_UNAVAILABLE
    );

    // 2. HTTP 500 on DELETE also leaves delete_uncertain=true permanently fenced across recovery & expiry.
    store.put_file(&key_err, &file_path, payload.len() as u64, deadline).await.unwrap();
    let mut c_mut2 = pool.get().await.unwrap();
    let tx2 = c_mut2.transaction().await.unwrap();
    let claim2 = upsert_delete_claim(&tx2, tenant, "lfs", &oid_err, 60).await.unwrap();
    tx2.commit().await.unwrap();
    mock.fail_deletes_500.store(true, Ordering::SeqCst);
    assert!(execute_locked_claimed_delete(&pool, store.as_ref(), &claim2, deadline).await.is_err());
    c.execute(
        "UPDATE remote_object_delete_claims SET lease_until = clock_timestamp() - interval '10 seconds' \
         WHERE tenant_id=$1 AND namespace='lfs' AND digest=$2",
        &[&tenant, &oid_err],
    )
    .await
    .unwrap();
    assert_eq!(sweep_expired_claims_with_stores(&pool, Some(store.as_ref()), None, deadline).await.unwrap(), 0);
    assert_eq!(
        wait_or_clear_delete_claim(&pool, Some(store.as_ref()), tenant, "lfs", &oid_err, deadline).await.unwrap_err().0,
        StatusCode::SERVICE_UNAVAILABLE
    );

    server.abort();
    let _ = tokio::fs::remove_dir_all(&dir).await;
}
