//! Isolated PostgreSQL 17 schema + LoopbackS3 OpenDAL `BlobStore` + production
//! `rootyard::blob_git_gateway::router` harness for Issue #185 end-to-end tests.

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use anyhow::{Result, anyhow, ensure};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use deadpool_postgres::{Manager, Pool};
use rootyard::{
    blob_git_gateway::{BlobGitConfig, BlobGitState, router},
    blob_store::{config::BlobProfile, opendal::BlobStore},
    browse::packfile_uri::GatewayPackfileOffload,
    db,
    ref_store::{
        GitObjectFormat,
        core::decision_commit::{PgDecisionProtocol, RealmExpectation},
        serving::lookup,
    },
};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::time::Instant;
use uuid::Uuid;

#[derive(Default)]
struct S3MemState {
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
}

pub struct LoopbackS3 {
    endpoint: String,
}

static SHARED_S3: OnceLock<LoopbackS3> = OnceLock::new();
static ENV_LOCK: Mutex<()> = Mutex::new(());

impl LoopbackS3 {
    pub fn shared() -> &'static Self {
        SHARED_S3.get_or_init(|| {
            let st = Arc::new(S3MemState::default());
            let std_l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            std_l.set_nonblocking(true).unwrap();
            let port = std_l.local_addr().unwrap().port();
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            std::thread::spawn(move || {
                tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap().block_on(
                    async move {
                        let _ = tx.send(());
                        let _ = axum::serve(
                            tokio::net::TcpListener::from_std(std_l).unwrap(),
                            Router::new().fallback(handle_s3).with_state(st),
                        )
                        .await;
                    },
                );
            });
            rx.recv().unwrap();
            Self { endpoint: format!("http://127.0.0.1:{port}") }
        })
    }

    pub fn open_store(&self) -> Result<BlobStore> {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let pairs = "DRIVER=opendal,SERVICE=s3,BUCKET=packfile-uri-bucket,REGION=us-east-1,ROOT=packfile-uri-it,ACCESS_KEY_ID=test-ak,SECRET_ACCESS_KEY=test-sk,ENCRYPTION_MODE=provider-managed,RETRY_MAX_TIMES=3,MAX_OBJECT_BYTES=67108864";
        // SAFETY: serialized under ENV_LOCK inside integration test process.
        unsafe {
            for kv in pairs.split(',') {
                let (k, v) = kv.split_once('=').unwrap();
                std::env::set_var(format!("ROOTYARD_BLOB_{k}"), v);
            }
            std::env::set_var("ROOTYARD_BLOB_ENDPOINT", &self.endpoint);
            std::env::remove_var("ROOTYARD_BLOB_KEYRING_DIR");
        }
        Ok(BlobStore::open(BlobProfile::from_env()?)?)
    }
}

async fn handle_s3(
    State(st): State<Arc<S3MemState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let key = uri.path().trim_start_matches('/').to_owned();
    if !key.contains('/') {
        return ([(header::CONNECTION, "close")], Body::from("<ListBucketResult/>")).into_response();
    }
    match method {
        Method::PUT => {
            let mut guard = st.objects.lock().unwrap_or_else(|p| p.into_inner());
            if headers.get(header::IF_NONE_MATCH).is_some_and(|v| v == "*") && guard.contains_key(&key) {
                return (StatusCode::PRECONDITION_FAILED, [(header::CONNECTION, "close")], Body::empty())
                    .into_response();
            }
            let tag = format!("\"{}\"", &hex::encode(Sha256::digest(&body))[..32]);
            guard.insert(key, body.to_vec());
            (
                [(header::ETAG, tag), (header::CONTENT_LENGTH, "0".into()), (header::CONNECTION, "close".into())],
                Body::empty(),
            )
                .into_response()
        }
        Method::HEAD | Method::GET => {
            let data = st.objects.lock().unwrap_or_else(|p| p.into_inner()).get(&key).cloned();
            let Some(d) = data else {
                return (
                    StatusCode::NOT_FOUND,
                    [(header::CONTENT_LENGTH, "0"), (header::CONNECTION, "close")],
                    Body::empty(),
                )
                    .into_response();
            };
            let tag = format!("\"{}\"", &hex::encode(Sha256::digest(&d))[..32]);
            if method == Method::GET
                && let Some(r_str) = headers.get(header::RANGE).and_then(|v| v.to_str().ok())
                && let Some((s, e)) = r_str.strip_prefix("bytes=").and_then(|x| x.split_once('-'))
                && let Ok(start) = s.parse::<usize>()
                && start < d.len()
            {
                let end = e.parse::<usize>().unwrap_or(d.len() - 1).min(d.len() - 1);
                let slice = d[start..=end].to_vec();
                return (
                    StatusCode::PARTIAL_CONTENT,
                    [
                        (header::ETAG, tag),
                        (header::CONTENT_LENGTH, slice.len().to_string()),
                        (header::CONTENT_RANGE, format!("bytes {start}-{end}/{}", d.len())),
                        (header::CONNECTION, "close".into()),
                    ],
                    Body::from(slice),
                )
                    .into_response();
            }
            (
                [
                    (header::ETAG, tag),
                    (header::CONTENT_LENGTH, d.len().to_string()),
                    (header::CONNECTION, "close".into()),
                ],
                if method == Method::HEAD { Body::empty() } else { Body::from(d) },
            )
                .into_response()
        }
        Method::DELETE => {
            st.objects.lock().unwrap_or_else(|p| p.into_inner()).remove(&key);
            (StatusCode::NO_CONTENT, [(header::CONNECTION, "close")], Body::empty()).into_response()
        }
        _ => (StatusCode::METHOD_NOT_ALLOWED, [(header::CONNECTION, "close")], Body::empty()).into_response(),
    }
}

pub struct IsolatedPgDb {
    admin: Pool,
    pub pool: Pool,
    schema: String,
}

impl IsolatedPgDb {
    pub async fn setup() -> Result<Self> {
        let url = std::env::var("ROOTYARD_TEST_DATABASE_URL")
            .unwrap_or_else(|_| "postgres://postgres:postgres@127.0.0.1:5432/rootyard_test".to_owned());
        let schema = format!("packfile_uri_{}", Uuid::new_v4().simple());
        let admin = db::pool(&url)?;
        admin.get().await?.batch_execute(&format!("CREATE SCHEMA IF NOT EXISTS {schema}")).await?;
        let mut cfg: tokio_postgres::Config = url.parse()?;
        cfg.options(format!(
            "{} -c search_path={schema} -c timezone=UTC -c statement_timeout=30000 -c lock_timeout=15000",
            cfg.get_options().unwrap_or("")
        ));
        let pool = Pool::builder(Manager::new(cfg, tokio_postgres::NoTls))
            .runtime(deadpool_postgres::Runtime::Tokio1)
            .max_size(12)
            .build()?;
        db::migrate(&pool).await?;
        Ok(Self { admin, pool, schema })
    }

    pub async fn finish(self, outcome: Result<()>) -> Result<()> {
        let teardown = async {
            let client = self.admin.get().await?;
            client.batch_execute(&format!("DROP SCHEMA {} CASCADE", self.schema)).await?;
            Ok::<(), anyhow::Error>(())
        };
        match outcome {
            Ok(()) => teardown.await,
            Err(err) => {
                let _ = teardown.await;
                Err(err)
            }
        }
    }
}

pub struct TestActor {
    pub identity: db::Identity,
    pub token: String,
    pub username: String,
}

pub async fn issue_owner_actor(pool: &Pool) -> Result<TestActor> {
    let username = format!("pfowner{}", &Uuid::new_v4().simple().to_string()[..10]);
    let val = db::issue_token(pool, &username, true, false).await?;
    let token = val["token"].as_str().ok_or_else(|| anyhow!("missing token"))?.to_owned();
    let mut headers = HeaderMap::new();
    headers.insert(header::AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {token}"))?);
    let identity = rootyard::auth::authenticate(pool, &headers).await.map_err(|e| anyhow!("auth failed: {}", e.1))?;
    Ok(TestActor { identity, token, username })
}

pub async fn spawn_gateway(
    pool: Pool,
    store: BlobStore,
    git_binary: &Path,
    scratch_root: &Path,
    offload: Option<Arc<GatewayPackfileOffload>>,
) -> Result<(SocketAddr, Arc<BlobGitState>, tokio::task::JoinHandle<()>)> {
    std::fs::create_dir_all(scratch_root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(scratch_root, std::fs::Permissions::from_mode(0o700))?;
    }
    let mut state = BlobGitState::new(BlobGitConfig {
        pool,
        store,
        git_binary: git_binary.to_path_buf(),
        scratch_root: scratch_root.to_path_buf(),
        max_concurrent_requests: 8,
        max_request_bytes: 16 * 1024 * 1024,
        max_response_bytes: 64 * 1024 * 1024,
        max_inflight_bytes: 64 * 1024 * 1024,
        operation_deadline: Duration::from_secs(60),
        native_limits: Default::default(),
    })?;
    if let Some(off) = offload {
        state = state.with_packfile_offload(off);
    }
    let state = Arc::new(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let app = router(Arc::clone(&state));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((addr, state, task))
}

pub async fn create_and_provision_repo(
    gw_addr: SocketAddr,
    pool: &Pool,
    state: &BlobGitState,
    owner: &TestActor,
    name: &str,
    fmt: GitObjectFormat,
) -> Result<Uuid> {
    let resp = reqwest::Client::new()
        .post(format!("http://{gw_addr}/api/repos"))
        .bearer_auth(&owner.token)
        .json(&json!({ "name": name, "object_format": fmt.as_str() }))
        .send()
        .await?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await?;
    ensure!(status.is_success(), "POST /api/repos failed ({status}): {body}");
    let dl = Instant::now() + Duration::from_secs(30);
    let serving = lookup(pool, &owner.identity, &owner.username, name, true, state.store().backend_identity(), dl)
        .await
        .map_err(|e| anyhow!("lookup failed: {}", e.1))?;
    let gate = serving.gate;
    let exp = RealmExpectation::new(
        gate.repository_id(),
        gate.tenant_id(),
        gate.object_format(),
        gate.history_incarnation(),
        gate.authority_epoch(),
        gate.group_epoch(),
    )?;
    let mut client = pool.get().await?;
    PgDecisionProtocol.provision(&mut client, &exp, dl).await?;
    Ok(gate.repository_id())
}
