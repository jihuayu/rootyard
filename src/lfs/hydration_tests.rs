use super::*;
use crate::{lfs::verification::test_serial, storage::remote_provider::LegacyS3Store};
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Method, StatusCode, header},
    response::Response,
};
use reqwest::Url;
use sha2::{Digest, Sha256};
use std::{
    os::unix::fs::MetadataExt,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::Duration,
};
use tokio::{net::TcpListener, sync::Notify};

struct MockS3State {
    expected_suffix: String,
    payload: Vec<u8>,
    gate_first_get: AtomicBool,
    fail_all_gets_502: AtomicBool,
    gets: AtomicUsize,
    heads: AtomicUsize,
    first_get_entered: Notify,
    release_first_get: Notify,
}

async fn handle_mock_s3(
    State(state): State<Arc<MockS3State>>,
    method: Method,
    uri: axum::http::Uri,
) -> Response {
    if !uri.path().ends_with(&state.expected_suffix) {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header(header::CONTENT_LENGTH, "0")
            .body(Body::empty())
            .unwrap();
    }
    match method {
        Method::HEAD => {
            state.heads.fetch_add(1, Ordering::SeqCst);
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_LENGTH, state.payload.len().to_string())
                .body(Body::empty())
                .unwrap()
        }
        Method::GET => {
            state.gets.fetch_add(1, Ordering::SeqCst);
            if state.gate_first_get.swap(false, Ordering::SeqCst) {
                state.first_get_entered.notify_waiters();
                state.release_first_get.notified().await;
            }
            if state.fail_all_gets_502.load(Ordering::SeqCst) {
                return Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .header(header::CONTENT_LENGTH, "0")
                    .body(Body::empty())
                    .unwrap();
            }
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_LENGTH, state.payload.len().to_string())
                .body(Body::from(state.payload.clone()))
                .unwrap()
        }
        _ => Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header(header::CONTENT_LENGTH, "0")
            .body(Body::empty())
            .unwrap(),
    }
}

async fn start_mock_s3(state: Arc<MockS3State>) -> (Arc<RemoteObjectStore>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().fallback(handle_mock_s3).with_state(state);
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let endpoint = Url::parse(&format!("http://{addr}")).unwrap();
    let s3 = LegacyS3Store::open(
        &endpoint,
        "rootyard-hydration-test",
        "us-east-1",
        "test-access".to_owned(),
        "test-secret".to_owned(),
        None,
    )
    .unwrap();
    (Arc::new(RemoteObjectStore::OpenDal(s3)), server)
}

async fn wait_until(what: &str, mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !predicate() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn short_deadline_hydration_initiator_timeout_does_not_poison_healthy_follower() {
    let _serial = test_serial().await;
    let base = std::env::temp_dir().canonicalize().unwrap();
    let root = base.join(format!("rootyard-lfs-hydrate-{}", Uuid::new_v4()));
    fs::create_dir_all(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let repo_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let payload = vec![0xA7u8; 256 * 1024];
    let size = payload.len() as u64;
    let oid = hex::encode(Sha256::digest(&payload));

    let mock_state = Arc::new(MockS3State {
        expected_suffix: format!("/tenants/{tenant_id}/lfs/{oid}"),
        payload: payload.clone(),
        gate_first_get: AtomicBool::new(true),
        fail_all_gets_502: AtomicBool::new(false),
        gets: AtomicUsize::new(0),
        heads: AtomicUsize::new(0),
        first_get_entered: Notify::new(),
        release_first_get: Notify::new(),
    });
    let (store, server) = start_mock_s3(mock_state.clone()).await;
    let followers_before = hydration_follower_count();
    assert_eq!(active_hydration_flights(), 0);

    let entered = mock_state.first_get_entered.notified();
    tokio::pin!(entered);
    entered.as_mut().enable();

    // Short-deadline initiator starts hydration and blocks inside the gated first GET.
    let root_initiator = root.clone();
    let oid_initiator = oid.clone();
    let store_initiator = store.clone();
    let mut initiator = tokio::spawn(async move {
        ensure_readable_with_store(
            &root_initiator,
            repo_id,
            tenant_id,
            &oid_initiator,
            size,
            Instant::now() + Duration::from_millis(250),
            store_initiator,
        )
        .await
    });
    tokio::select! {
        res = tokio::time::timeout(Duration::from_secs(5), &mut entered) => {
            res.expect("initiator never issued S3 GET");
        }
        early = &mut initiator => {
            panic!("initiator exited before S3 GET (heads={}): {early:?}", mock_state.heads.load(Ordering::SeqCst));
        }
    }
    assert_eq!(active_hydration_flights(), 1);

    // Two healthy-deadline followers join the in-flight hydration before the initiator expires.
    let mut followers = Vec::new();
    for _ in 0..2 {
        let root_f = root.clone();
        let oid_f = oid.clone();
        let store_f = store.clone();
        followers.push(tokio::spawn(async move {
            ensure_readable_with_store(
                &root_f,
                repo_id,
                tenant_id,
                &oid_f,
                size,
                Instant::now() + Duration::from_secs(30),
                store_f,
            )
            .await
        }));
    }
    wait_until("followers to attach to initiator flight", || hydration_follower_count() == followers_before + 2).await;

    // Initiator times out on its 220ms budget while the first GET remains gated.
    let initiator_err = initiator.await.unwrap().expect_err("short-deadline initiator must time out");
    assert!(
        format!("{initiator_err:#}").contains("timed out") || format!("{initiator_err:#}").contains("hydration failed"),
        "{initiator_err:#}"
    );

    // Surviving followers take over on a fresh flight with their 30s deadline and succeed.
    for follower in followers {
        assert!(follower.await.unwrap().unwrap(), "healthy-deadline follower must complete hydration");
    }
    mock_state.release_first_get.notify_waiters();

    let final_path = object_path(&root, repo_id, &oid).unwrap();
    assert_eq!(fs::read(&final_path).unwrap(), payload);
    assert_eq!(final_path.metadata().unwrap().mode() & 0o7777, 0o600);
    assert_eq!(mock_state.gets.load(Ordering::SeqCst), 2, "one gated timed-out GET + one takeover GET");
    wait_until("hydration flights map to drain", || active_hydration_flights() == 0).await;

    // Non-timeout HTTP 502 must still fail waiters explicitly without auto-retrying.
    let oid_bad = "c".repeat(64);
    let bad_state = Arc::new(MockS3State {
        expected_suffix: format!("/tenants/{tenant_id}/lfs/{oid_bad}"),
        payload: vec![1u8; 1024],
        gate_first_get: AtomicBool::new(false),
        fail_all_gets_502: AtomicBool::new(true),
        gets: AtomicUsize::new(0),
        heads: AtomicUsize::new(0),
        first_get_entered: Notify::new(),
        release_first_get: Notify::new(),
    });
    let (bad_store, bad_server) = start_mock_s3(bad_state).await;
    let bad_err = ensure_readable_with_store(
        &root,
        repo_id,
        tenant_id,
        &oid_bad,
        1024,
        Instant::now() + Duration::from_secs(15),
        bad_store,
    )
    .await
    .expect_err("502 remote failure must fail closed");
    let remote = bad_err
        .chain()
        .find_map(|cause| cause.downcast_ref::<RemoteStoreError>())
        .expect("typed RemoteStoreError retained in source chain");
    assert_eq!(remote.http_status(), Some(502));
    assert_eq!(active_hydration_flights(), 0);

    server.abort();
    bad_server.abort();
    fs::remove_dir_all(root).unwrap();
}

struct RepairMockS3 {
    objects: std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
    gate_head: AtomicBool,
    head_entered: Notify,
    release_head: Notify,
}

async fn handle_repair_s3(
    State(state): State<Arc<RepairMockS3>>,
    method: Method,
    uri: axum::http::Uri,
    body: axum::body::Bytes,
) -> Response {
    let key = uri.path().trim_start_matches('/').to_owned();
    match method {
        Method::HEAD => {
            if state.gate_head.swap(false, Ordering::SeqCst) {
                let release = state.release_head.notified();
                state.head_entered.notify_one();
                release.await;
            }
            match state.objects.lock().unwrap().get(&key).map(Vec::len) {
                Some(n) => Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_LENGTH, n.to_string())
                    .body(Body::empty())
                    .unwrap(),
                None => Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .header(header::CONTENT_LENGTH, "0")
                    .body(Body::empty())
                    .unwrap(),
            }
        }
        Method::PUT => {
            state.objects.lock().unwrap().insert(key, body.to_vec());
            Response::builder()
                .status(StatusCode::OK)
                .header(header::ETAG, "\"mock-etag\"")
                .header(header::CONTENT_LENGTH, "0")
                .body(Body::empty())
                .unwrap()
        }
        Method::GET => match state.objects.lock().unwrap().get(&key).cloned() {
            Some(bytes) => Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_LENGTH, bytes.len().to_string())
                .body(Body::from(bytes))
                .unwrap(),
            None => Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(header::CONTENT_LENGTH, "0")
                .body(Body::empty())
                .unwrap(),
        },
        _ => Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header(header::CONTENT_LENGTH, "0")
            .body(Body::empty())
            .unwrap(),
    }
}

#[tokio::test]
async fn delayed_repair_holds_write_admission_and_rechecks_live_tenant() {
    let Ok(base) = std::env::var("ROOTYARD_TEST_DATABASE_URL") else {
        return;
    };
    let admin = crate::db::pool(&base).unwrap();
    let schema = format!("lfs_repair_{}", Uuid::new_v4().simple());
    admin.get().await.unwrap().batch_execute(&format!("CREATE SCHEMA {schema}")).await.unwrap();
    let mut url = Url::parse(&base).unwrap();
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let pool = crate::db::pool(url.as_str()).unwrap();
    let c = pool.get().await.unwrap();
    c.batch_execute(
        "CREATE TABLE namespaces(id uuid PRIMARY KEY); \
         CREATE TABLE repositories( \
           id uuid PRIMARY KEY, owner_id uuid NOT NULL REFERENCES namespaces(id), \
           storage_generation bigint NOT NULL DEFAULT 1, state text NOT NULL DEFAULT 'ready', \
           gc_epoch bigint NOT NULL DEFAULT 0, gc_owner uuid, gc_lease_until timestamptz, \
           deleted_at timestamptz, archived_at timestamptz, transition_state text NOT NULL DEFAULT 'stable'); \
         CREATE TABLE storage_write_admissions( \
           id uuid PRIMARY KEY, repository_id uuid NOT NULL, gc_epoch bigint NOT NULL, \
           owner uuid NOT NULL, kind text NOT NULL, state text NOT NULL DEFAULT 'active', \
           heartbeat_at timestamptz NOT NULL DEFAULT clock_timestamp(), \
           lease_until timestamptz NOT NULL, finished_at timestamptz, detail text); \
         CREATE TABLE repository_transfers(id uuid PRIMARY KEY, repository_id uuid NOT NULL, state text NOT NULL); \
         CREATE TABLE lfs_objects( \
           tenant_id uuid NOT NULL, repository_id uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE, \
           oid text NOT NULL, size bigint NOT NULL, state text NOT NULL, PRIMARY KEY(tenant_id, repository_id, oid)); \
         CREATE TABLE remote_object_delete_claims( \
           tenant_id uuid NOT NULL, namespace text NOT NULL, digest text NOT NULL, \
           claim_generation bigint NOT NULL DEFAULT 1, deleting boolean NOT NULL DEFAULT false, \
           delete_uncertain boolean NOT NULL DEFAULT false, lease_until timestamptz NOT NULL, \
           claimed_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(tenant_id, namespace, digest))",
    )
    .await
    .unwrap();

    let owner_a = Uuid::new_v4();
    let owner_b = Uuid::new_v4();
    let repo_id = Uuid::new_v4();
    let payload = b"lfs-repair-payload-bytes";
    let oid = hex::encode(Sha256::digest(payload));
    let root = std::env::temp_dir().join(format!("ry-repair-test-{}", Uuid::new_v4()));
    let local = object_path(&root, repo_id, &oid).unwrap();
    fs::create_dir_all(local.parent().unwrap()).unwrap();
    fs::write(&local, payload).unwrap();

    c.execute("INSERT INTO namespaces(id) VALUES($1),($2)", &[&owner_a, &owner_b]).await.unwrap();
    c.execute("INSERT INTO repositories(id, owner_id) VALUES($1,$2)", &[&repo_id, &owner_a]).await.unwrap();
    c.execute(
        "INSERT INTO lfs_objects(tenant_id, repository_id, oid, size, state) VALUES($1,$2,$3,$4,'ready')",
        &[&owner_a, &repo_id, &oid, &(payload.len() as i64)],
    )
    .await
    .unwrap();

    let mock = Arc::new(RepairMockS3 {
        objects: std::sync::Mutex::new(std::collections::HashMap::new()),
        gate_head: AtomicBool::new(true),
        head_entered: Notify::new(),
        release_head: Notify::new(),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().fallback(handle_repair_s3).with_state(mock.clone());
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let endpoint = Url::parse(&format!("http://{addr}")).unwrap();
    let store = RemoteObjectStore::OpenDal(
        LegacyS3Store::open(&endpoint, "repair-test", "us-east-1", "ak".into(), "sk".into(), None).unwrap(),
    );

    let entered = mock.head_entered.notified();
    let pool_r = pool.clone();
    let root_r = root.clone();
    let oid_r = oid.clone();
    let store_arc = Arc::new(store);
    let store_r = Arc::clone(&store_arc);
    let handle = tokio::spawn(async move {
        repair_remote_object_with_store(
            &pool_r, &root_r, store_r.as_ref(), repo_id, &oid_r, payload.len() as u64,
            Instant::now() + Duration::from_secs(30),
        )
        .await
    });
    entered.await;
    let active: i64 = c
        .query_one(
            "SELECT count(*) FROM storage_write_admissions WHERE repository_id=$1 AND kind='lfs_repair' AND state='active'",
            &[&repo_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(active, 1, "active admission blocks transfer drain while repair runs");
    mock.release_head.notify_one();
    handle.await.unwrap().unwrap();
    assert!(mock.objects.lock().unwrap().keys().any(|k| k.ends_with(&format!("tenants/{owner_a}/lfs/{oid}"))));

    // After ownership transfer completes to owner_b, repair must target owner_b and skip while transferring.
    let xfer = Uuid::new_v4();
    c.execute("UPDATE repositories SET owner_id=$2 WHERE id=$1", &[&repo_id, &owner_b]).await.unwrap();
    c.execute("UPDATE lfs_objects SET tenant_id=$2 WHERE repository_id=$1", &[&repo_id, &owner_b]).await.unwrap();
    c.execute("INSERT INTO repository_transfers(id, repository_id, state) VALUES($1,$2,'copying_remote')", &[&xfer, &repo_id])
        .await
        .unwrap();
    repair_remote_object_with_store(
        &pool, &root, store_arc.as_ref(), repo_id, &oid, payload.len() as u64,
        Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap();
    assert!(!mock.objects.lock().unwrap().keys().any(|k| k.ends_with(&format!("tenants/{owner_b}/lfs/{oid}"))));
    c.execute("UPDATE repository_transfers SET state='completed' WHERE id=$1", &[&xfer]).await.unwrap();
    repair_remote_object_with_store(
        &pool, &root, store_arc.as_ref(), repo_id, &oid, payload.len() as u64,
        Instant::now() + Duration::from_secs(10),
    )
    .await
    .unwrap();
    assert!(mock.objects.lock().unwrap().keys().any(|k| k.ends_with(&format!("tenants/{owner_b}/lfs/{oid}"))));

    server.abort();
    fs::remove_dir_all(root).unwrap();
}
