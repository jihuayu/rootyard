//! PG17 + MockS3 deterministic concurrency tests for Pando purge fencing (#3)
//! and transfer rollback destination cleanup (#4).
use super::{
    purge_exec::delete_pando_artifact_fenced, transfer_model::CopiedRemoteObject,
    transfer_remote::cleanup_rollback_objects_with_stores,
};
use crate::{
    pando_gateway::retention,
    storage::{
        remote_key_claims::{has_active_delete_claim, wait_or_clear_delete_claim},
        remote_objects::{ObjectKey, RemoteObjectStore},
        remote_provider::LegacyS3Store,
    },
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

pub(super) struct MockRemoteS3 {
    objects: Mutex<HashMap<String, Vec<u8>>>,
    pub(super) gate_first_delete: AtomicBool,
    pub(super) fail_deletes_500: AtomicBool,
    pub(super) first_delete_entered: Notify,
    pub(super) release_first_delete: Notify,
}

impl MockRemoteS3 {
    pub(super) fn new() -> Self {
        Self {
            objects: Mutex::new(HashMap::new()),
            gate_first_delete: AtomicBool::new(false),
            fail_deletes_500: AtomicBool::new(false),
            first_delete_entered: Notify::new(),
            release_first_delete: Notify::new(),
        }
    }
}

fn empty_resp(status: StatusCode) -> Response {
    Response::builder().status(status).header(header::CONTENT_LENGTH, "0").body(Body::empty()).unwrap()
}

async fn handle_s3(
    State(state): State<Arc<MockRemoteS3>>,
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
        Method::HEAD => match state.objects.lock().unwrap().get(&key).map(Vec::len) {
            Some(n) => Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_LENGTH, n.to_string())
                .body(Body::empty())
                .unwrap(),
            None => empty_resp(StatusCode::NOT_FOUND),
        },
        Method::GET => match state.objects.lock().unwrap().get(&key).cloned() {
            Some(bytes) => Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_LENGTH, bytes.len().to_string())
                .body(Body::from(bytes))
                .unwrap(),
            None => empty_resp(StatusCode::NOT_FOUND),
        },
        Method::DELETE => {
            if state.gate_first_delete.swap(false, Ordering::SeqCst) {
                let release = state.release_first_delete.notified();
                state.first_delete_entered.notify_one();
                release.await;
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

pub(super) async fn start_s3(state: Arc<MockRemoteS3>) -> (Arc<RemoteObjectStore>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = Router::new().fallback(handle_s3).with_state(state);
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    let endpoint = Url::parse(&format!("http://{addr}")).unwrap();
    let s3 = LegacyS3Store::open(&endpoint, "xfer-test", "us-east-1", "ak".into(), "sk".into(), None).unwrap();
    (Arc::new(RemoteObjectStore::OpenDal(s3)), server)
}

async fn setup_repo_and_pando_schema() -> Option<(Pool, Uuid)> {
    let base = std::env::var("ROOTYARD_TEST_DATABASE_URL").ok()?;
    let admin = crate::db::pool(&base).unwrap();
    let schema = format!("xfer_pando_{}", Uuid::new_v4().simple());
    admin.get().await.unwrap().batch_execute(&format!("CREATE SCHEMA {schema}")).await.unwrap();
    let mut url = Url::parse(&base).unwrap();
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let pool = crate::db::pool(url.as_str()).unwrap();
    let auth_id = Uuid::new_v4();
    let c = pool.get().await.unwrap();
    c.batch_execute(
        "CREATE TABLE namespaces(id uuid PRIMARY KEY, slug text NOT NULL UNIQUE); \
         CREATE TABLE repositories( \
           id uuid PRIMARY KEY, owner_id uuid NOT NULL REFERENCES namespaces(id), \
           UNIQUE(id, owner_id)); \
         CREATE TABLE repository_transfers( \
           id uuid PRIMARY KEY, repository_id uuid NOT NULL, state text NOT NULL, \
           lease_owner text, lease_until timestamptz, lease_epoch bigint NOT NULL DEFAULT 0); \
         CREATE TABLE lfs_objects( \
           tenant_id uuid NOT NULL, repository_id uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE, \
           oid text NOT NULL, size bigint NOT NULL DEFAULT 0, state text NOT NULL DEFAULT 'ready', \
           PRIMARY KEY(tenant_id, repository_id, oid)); \
         CREATE TABLE workspace_checkpoints(id uuid PRIMARY KEY, repository_id uuid NOT NULL, manifest_digest text); \
         CREATE TABLE workspace_remote_staging_objects( \
           checkpoint_id uuid NOT NULL, tenant_id uuid NOT NULL, digest text NOT NULL, size bigint NOT NULL DEFAULT 0); \
         CREATE TABLE remote_object_delete_claims( \
           tenant_id uuid NOT NULL, namespace text NOT NULL, digest text NOT NULL, \
           claim_generation bigint NOT NULL DEFAULT 1, deleting boolean NOT NULL DEFAULT true, \
           delete_uncertain boolean NOT NULL DEFAULT false, lease_until timestamptz NOT NULL, \
           claimed_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(tenant_id, namespace, digest)); \
         CREATE TABLE pando_storage_authorities( \
           singleton boolean PRIMARY KEY DEFAULT true, authority_id uuid NOT NULL UNIQUE, \
           generation bigint NOT NULL DEFAULT 1, created_at timestamptz NOT NULL DEFAULT clock_timestamp(), \
           rotated_at timestamptz); \
         CREATE TABLE pando_remote_artifacts( \
           authority_id uuid NOT NULL REFERENCES pando_storage_authorities(authority_id), \
           tenant_id uuid NOT NULL, namespace text NOT NULL, sha256 text NOT NULL, \
           size bigint NOT NULL DEFAULT 0, object_generation bigint NOT NULL, remote_path text NOT NULL, \
           state text NOT NULL DEFAULT 'reserved', reserved_owner uuid, lease_until timestamptz, \
           claim_generation bigint NOT NULL DEFAULT 0, claimed_by uuid, delete_after timestamptz, \
           attempts integer NOT NULL DEFAULT 0, last_error text, deleted_at timestamptz, \
           created_at timestamptz NOT NULL DEFAULT clock_timestamp(), \
           updated_at timestamptz NOT NULL DEFAULT clock_timestamp(), \
           PRIMARY KEY(authority_id, tenant_id, namespace, sha256)); \
         CREATE TABLE pando_pack_manifests( \
           id uuid PRIMARY KEY, repository_id uuid NOT NULL, tenant_id uuid NOT NULL); \
         CREATE TABLE pando_manifest_artifacts( \
           manifest_id uuid NOT NULL REFERENCES pando_pack_manifests(id) ON DELETE CASCADE, \
           repository_id uuid NOT NULL, authority_id uuid NOT NULL, tenant_id uuid NOT NULL, \
           namespace text NOT NULL, sha256 text NOT NULL, artifact_role text NOT NULL, \
           PRIMARY KEY(manifest_id, artifact_role)); \
         CREATE TABLE pando_publication_fences( \
           manifest_id uuid NOT NULL, authority_id uuid NOT NULL, tenant_id uuid NOT NULL, \
           namespace text NOT NULL, sha256 text NOT NULL, lease_until timestamptz NOT NULL, \
           PRIMARY KEY(manifest_id, namespace, sha256))",
    )
    .await
    .unwrap();
    c.execute("INSERT INTO pando_storage_authorities(singleton, authority_id) VALUES(true, $1)", &[&auth_id])
        .await
        .unwrap();
    Some((pool, auth_id))
}

#[tokio::test]
async fn pando_purge_fenced_against_concurrent_reserve_and_link() {
    let Some((pool, auth_id)) = setup_repo_and_pando_schema().await else {
        return;
    };
    let mock = Arc::new(MockRemoteS3::new());
    let (store, server) = start_s3(mock.clone()).await;
    let dir = std::env::temp_dir().join(format!("ry-pando-fence-{}", Uuid::new_v4()));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let payload_path = dir.join("pack.bin");
    tokio::fs::write(&payload_path, b"cipher-bytes").await.unwrap();

    let tenant = Uuid::new_v4();
    let repo_other = Uuid::new_v4();
    let sha = hex::encode(Sha256::digest(b"cipher-bytes"));
    let deadline = Instant::now() + Duration::from_secs(30);
    let c = pool.get().await.unwrap();
    c.execute("INSERT INTO namespaces(id, slug) VALUES($1, 'alice')", &[&tenant]).await.unwrap();
    c.execute("INSERT INTO repositories(id, owner_id) VALUES($1, $2)", &[&repo_other, &tenant]).await.unwrap();

    let key_g1 = ObjectKey::scoped(tenant, auth_id, 1, retention::NAMESPACE_CIPHER, &sha).unwrap();
    store.put_file(&key_g1, &payload_path, 12, deadline).await.unwrap();
    c.execute(
        "INSERT INTO pando_remote_artifacts \
         (authority_id, tenant_id, namespace, sha256, size, object_generation, remote_path, state) \
         VALUES($1,$2,$3,$4,12,1,$5,'active')",
        &[&auth_id, &tenant, &retention::NAMESPACE_CIPHER, &sha, &key_g1.path()],
    )
    .await
    .unwrap();

    // 1. Active publication fence blocks delete_pando_artifact_fenced completely.
    let manifest_id = Uuid::new_v4();
    c.execute(
        "INSERT INTO pando_publication_fences(manifest_id, authority_id, tenant_id, namespace, sha256, lease_until) \
         VALUES($1,$2,$3,$4,$5,clock_timestamp() + interval '60 seconds')",
        &[&manifest_id, &auth_id, &tenant, &retention::NAMESPACE_CIPHER, &sha],
    )
    .await
    .unwrap();
    let blocked = delete_pando_artifact_fenced(
        &pool,
        store.as_ref(),
        auth_id,
        tenant,
        retention::NAMESPACE_CIPHER,
        &sha,
        Some(1),
        deadline,
    )
    .await
    .unwrap();
    assert!(!blocked);
    assert!(store.head(&key_g1, deadline).await.unwrap().is_some());
    c.execute("DELETE FROM pando_publication_fences WHERE manifest_id = $1", &[&manifest_id]).await.unwrap();

    // 2. While g1 delete holds state='deleting' during store.delete, concurrent reserve bumps generation to g2.
    mock.gate_first_delete.store(true, Ordering::SeqCst);
    let entered = mock.first_delete_entered.notified();
    let pool_d = pool.clone();
    let store_d = Arc::clone(&store);
    let sha_d = sha.clone();
    let deleter = tokio::spawn(async move {
        delete_pando_artifact_fenced(
            &pool_d,
            store_d.as_ref(),
            auth_id,
            tenant,
            retention::NAMESPACE_CIPHER,
            &sha_d,
            Some(1),
            deadline,
        )
        .await
    });
    entered.await;

    let mut c_res = pool.get().await.unwrap();
    let tx_res = c_res.transaction().await.unwrap();
    let env_sha = hex::encode(Sha256::digest(b"envelope-bytes"));
    let (slot, _) = retention::reserve_pair(&*tx_res, tenant, None, &sha, &env_sha).await.unwrap();
    let retention::Slot::Reserved { .. } = slot else {
        panic!("expected generation bump Slot::Reserved while state='deleting', got {slot:?}");
    };
    let key_g2 = slot.key().clone();
    assert_eq!(key_g2.authority, Some((auth_id, 2)));
    store.put_file(&key_g2, &payload_path, 12, deadline).await.unwrap();
    assert!(retention::activate(&*tx_res, tenant, retention::NAMESPACE_CIPHER, &sha, 12, &slot).await.unwrap());
    tx_res.commit().await.unwrap();

    mock.release_first_delete.notify_one();
    assert!(deleter.await.unwrap().unwrap());
    assert!(store.head(&key_g1, deadline).await.unwrap().is_none(), "old generation deleted");
    assert!(store.head(&key_g2, deadline).await.unwrap().is_some(), "new generation must survive");
    let live_gen: (String, i64) = {
        let r = c
            .query_one(
                "SELECT state, object_generation FROM pando_remote_artifacts WHERE authority_id=$1 AND tenant_id=$2 AND sha256=$3",
                &[&auth_id, &tenant, &sha],
            )
            .await
            .unwrap();
        (r.get(0), r.get(1))
    };
    assert_eq!(live_gen, ("active".to_owned(), 2));

    server.abort();
    let _ = tokio::fs::remove_dir_all(&dir).await;
}

#[tokio::test]
async fn rollback_cleanup_preserves_concurrent_publish_and_fences_uncertain_delete() {
    let Some((pool, auth_id)) = setup_repo_and_pando_schema().await else {
        return;
    };
    let mock = Arc::new(MockRemoteS3::new());
    let (store, server) = start_s3(mock.clone()).await;
    let dir = std::env::temp_dir().join(format!("ry-rollback-clean-{}", Uuid::new_v4()));
    tokio::fs::create_dir_all(&dir).await.unwrap();
    let payload_path = dir.join("obj.bin");
    let fail_payload_path = dir.join("obj-fail.bin");
    tokio::fs::write(&payload_path, b"rollback-bytes").await.unwrap();
    tokio::fs::write(&fail_payload_path, b"fail-delete-bytes").await.unwrap();
    let sha = hex::encode(Sha256::digest(b"rollback-bytes"));
    let oid_fail = hex::encode(Sha256::digest(b"fail-delete-bytes"));
    let deadline = Instant::now() + Duration::from_secs(30);

    let from_owner = Uuid::new_v4();
    let to_owner = Uuid::new_v4();
    let repo_xfer = Uuid::new_v4();
    let repo_sibling = Uuid::new_v4();
    let xfer_id = Uuid::new_v4();
    let c = pool.get().await.unwrap();
    c.execute("INSERT INTO namespaces(id, slug) VALUES($1,'from'),($2,'to')", &[&from_owner, &to_owner]).await.unwrap();
    c.execute(
        "INSERT INTO repositories(id, owner_id) VALUES($1,$2),($3,$4)",
        &[&repo_xfer, &from_owner, &repo_sibling, &to_owner],
    )
    .await
    .unwrap();
    c.execute(
        "INSERT INTO repository_transfers(id, repository_id, state, lease_owner, lease_until, lease_epoch) \
         VALUES($1,$2,'rolling_back','w1',clock_timestamp()+interval '60 seconds',3)",
        &[&xfer_id, &repo_xfer],
    )
    .await
    .unwrap();

    // Scenario A: Sibling publishes to_owner LFS ref + Pando manifest link concurrently; rollback preserves bytes!
    let lfs_keep = ObjectKey::new(to_owner, "lfs", &sha).unwrap();
    let pando_keep = ObjectKey::scoped(to_owner, auth_id, 1, retention::NAMESPACE_CIPHER, &sha).unwrap();
    store.put_file(&lfs_keep, &payload_path, 14, deadline).await.unwrap();
    store.put_file(&pando_keep, &payload_path, 14, deadline).await.unwrap();
    c.execute(
        "INSERT INTO lfs_objects(tenant_id, repository_id, oid, size, state) VALUES($1,$2,$3,14,'ready')",
        &[&to_owner, &repo_sibling, &sha],
    )
    .await
    .unwrap();
    c.execute(
        "INSERT INTO pando_remote_artifacts(authority_id, tenant_id, namespace, sha256, size, object_generation, remote_path, state) \
         VALUES($1,$2,$3,$4,14,1,$5,'active')",
        &[&auth_id, &to_owner, &retention::NAMESPACE_CIPHER, &sha, &pando_keep.path()],
    )
    .await
    .unwrap();
    let m_id = Uuid::new_v4();
    c.execute(
        "INSERT INTO pando_pack_manifests(id, repository_id, tenant_id) VALUES($1,$2,$3)",
        &[&m_id, &repo_sibling, &to_owner],
    )
    .await
    .unwrap();
    c.execute(
        "INSERT INTO pando_manifest_artifacts(manifest_id, repository_id, authority_id, tenant_id, namespace, sha256, artifact_role) \
         VALUES($1,$2,$3,$4,$5,$6,'pack-cipher')",
        &[&m_id, &repo_sibling, &auth_id, &to_owner, &retention::NAMESPACE_CIPHER, &sha],
    )
    .await
    .unwrap();

    let copied_keep = vec![
        CopiedRemoteObject {
            kind: "lfs".into(),
            from_key: ObjectKey::new(from_owner, "lfs", &sha).unwrap().path(),
            to_key: lfs_keep.path(),
            size: 14,
            sha256: Some(sha.clone()),
        },
        CopiedRemoteObject {
            kind: retention::NAMESPACE_CIPHER.into(),
            from_key: ObjectKey::scoped(from_owner, auth_id, 1, retention::NAMESPACE_CIPHER, &sha).unwrap().path(),
            to_key: pando_keep.path(),
            size: 14,
            sha256: Some(sha.clone()),
        },
    ];
    cleanup_rollback_objects_with_stores(
        &pool,
        xfer_id,
        "w1",
        3,
        repo_xfer,
        to_owner,
        &copied_keep,
        Some(store.as_ref()),
        store.as_ref(),
        Some(store.as_ref()),
        deadline,
    )
    .await
    .unwrap();
    assert!(store.head(&lfs_keep, deadline).await.unwrap().is_some());
    assert!(store.head(&pando_keep, deadline).await.unwrap().is_some());

    // Scenario B: Failed rollback DELETE leaves delete_uncertain=true + propagates Err -> destination publish 503.
    let lfs_fail = ObjectKey::new(to_owner, "lfs", &oid_fail).unwrap();
    store.put_file(&lfs_fail, &fail_payload_path, b"fail-delete-bytes".len() as u64, deadline).await.unwrap();
    mock.fail_deletes_500.store(true, Ordering::SeqCst);
    let copied_fail = vec![CopiedRemoteObject {
        kind: "lfs".into(),
        from_key: ObjectKey::new(from_owner, "lfs", &oid_fail).unwrap().path(),
        to_key: lfs_fail.path(),
        size: b"fail-delete-bytes".len() as u64,
        sha256: Some(oid_fail.clone()),
    }];
    assert!(
        cleanup_rollback_objects_with_stores(
            &pool,
            xfer_id,
            "w1",
            3,
            repo_xfer,
            to_owner,
            &copied_fail,
            Some(store.as_ref()),
            store.as_ref(),
            Some(store.as_ref()),
            deadline,
        )
        .await
        .is_err()
    );
    let pub_err = wait_or_clear_delete_claim(&pool, Some(store.as_ref()), to_owner, "lfs", &oid_fail, deadline)
        .await
        .unwrap_err();
    assert_eq!(pub_err.0, StatusCode::SERVICE_UNAVAILABLE);
    let mut c_tx = pool.get().await.unwrap();
    let tx = c_tx.transaction().await.unwrap();
    assert!(has_active_delete_claim(&tx, to_owner, "lfs", &oid_fail).await.unwrap());
    tx.commit().await.unwrap();

    server.abort();
    let _ = tokio::fs::remove_dir_all(&dir).await;
}
