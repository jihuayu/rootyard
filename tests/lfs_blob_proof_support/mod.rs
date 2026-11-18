//! LoopbackS3 (`RETRY_MAX_TIMES=3`, `Connection: close`), PG17 schema, and stock `git-lfs` harness (`Refs #145`).

pub mod adversarial;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use axum::{
    Router,
    body::{Body, Bytes},
    extract::State,
    http::{Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use deadpool_postgres::{Manager, Pool};
use rootyard::blob_store::{BlobLocator, config::BlobProfile, opendal::BlobStore};
use rootyard::db;
use rootyard::lfs::blob_proof_publication::{
    LfsBlobProofService, LfsBlobRuntimeGate, PgLfsBlobStore, init_lfs_blob_proof_tables, lfs_blob_proof_router,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::task::JoinHandle;
use uuid::Uuid;

#[derive(Default)]
pub struct S3MemState {
    pub objects: Mutex<BTreeMap<String, Vec<u8>>>,
    pub fail_503: AtomicBool,
}

pub struct LoopbackS3 {
    pub endpoint: String,
    pub state: Arc<S3MemState>,
}

static SHARED_S3: OnceLock<LoopbackS3> = OnceLock::new();
static ENV_LOCK: Mutex<()> = Mutex::new(());

impl LoopbackS3 {
    pub fn shared() -> &'static Self {
        SHARED_S3.get_or_init(|| {
            let state = Arc::new(S3MemState::default());
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind LoopbackS3");
            listener.set_nonblocking(true).expect("nonblocking");
            let port = listener.local_addr().expect("addr").port();
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            let srv_state = Arc::clone(&state);
            std::thread::spawn(move || {
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
                    .expect("s3 rt")
                    .block_on(async move {
                        let _ = tx.send(());
                        let app = Router::new().fallback(handle_s3).with_state(srv_state);
                        let _ = axum::serve(tokio::net::TcpListener::from_std(listener).unwrap(), app).await;
                    });
            });
            rx.recv().expect("LoopbackS3 ready");
            Self { endpoint: format!("http://127.0.0.1:{port}"), state }
        })
    }

    pub fn open_store(&self, root_prefix: &str) -> Result<BlobStore> {
        let _g = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        set_blob_env(&self.endpoint, root_prefix);
        Ok(BlobStore::open(BlobProfile::from_env()?)?)
    }

    pub fn set_fail_503(&self, fail: bool) {
        self.state.fail_503.store(fail, Ordering::SeqCst);
    }

    pub fn object_key(root_prefix: &str, loc: &BlobLocator) -> String {
        format!("lfs-proof-bucket/{root_prefix}/{}", loc.path())
    }

    pub fn take_raw(&self, root_prefix: &str, loc: &BlobLocator) -> Option<Vec<u8>> {
        self.state.objects.lock().unwrap().remove(&Self::object_key(root_prefix, loc))
    }

    pub fn restore_raw(&self, root_prefix: &str, loc: &BlobLocator, bytes: Vec<u8>) {
        self.state.objects.lock().unwrap().insert(Self::object_key(root_prefix, loc), bytes);
    }
}

pub fn set_blob_env(endpoint: &str, root_prefix: &str) {
    let pairs = [
        ("DRIVER", "opendal"),
        ("SERVICE", "s3"),
        ("BUCKET", "lfs-proof-bucket"),
        ("REGION", "us-east-1"),
        ("ROOT", root_prefix),
        ("ACCESS_KEY_ID", "lfs-test-ak"),
        ("SECRET_ACCESS_KEY", "lfs-test-sk"),
        ("ENCRYPTION_MODE", "provider-managed"),
        ("RETRY_MAX_TIMES", "3"),
    ];
    // SAFETY: guarded by `ENV_LOCK` across tests in this integration binary.
    unsafe {
        for (k, v) in pairs {
            std::env::set_var(format!("ROOTYARD_BLOB_{k}"), v);
        }
        std::env::set_var("ROOTYARD_BLOB_ENDPOINT", endpoint);
        std::env::remove_var("ROOTYARD_BLOB_KEYRING_DIR");
    }
}

async fn handle_s3(State(st): State<Arc<S3MemState>>, method: Method, uri: Uri, body: Bytes) -> Response {
    if st.fail_503.load(Ordering::SeqCst) {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::CONNECTION, "close"), (header::CONTENT_TYPE, "application/xml")],
            Body::from("<Error><Code>ServiceUnavailable</Code></Error>"),
        )
            .into_response();
    }
    let key = uri.path().trim_start_matches('/').to_owned();
    if !key.contains('/') {
        return (StatusCode::OK, [(header::CONNECTION, "close")], Body::from("<ListBucketResult/>")).into_response();
    }
    match method {
        Method::PUT => {
            let etag = format!("\"{}\"", &hex::encode(Sha256::digest(&body))[..32]);
            st.objects.lock().unwrap().insert(key, body.to_vec());
            (
                StatusCode::OK,
                [(header::ETAG, etag), (header::CONTENT_LENGTH, "0".into()), (header::CONNECTION, "close".into())],
                Body::empty(),
            )
                .into_response()
        }
        Method::HEAD | Method::GET => match st.objects.lock().unwrap().get(&key).cloned() {
            Some(bytes) => {
                let etag = format!("\"{}\"", &hex::encode(Sha256::digest(&bytes))[..32]);
                let len = bytes.len().to_string();
                (
                    StatusCode::OK,
                    [(header::ETAG, etag), (header::CONTENT_LENGTH, len), (header::CONNECTION, "close".into())],
                    if method == Method::HEAD { Body::empty() } else { Body::from(bytes) },
                )
                    .into_response()
            }
            None => {
                (StatusCode::NOT_FOUND, [(header::CONTENT_LENGTH, "0"), (header::CONNECTION, "close")], Body::empty())
                    .into_response()
            }
        },
        Method::DELETE => (
            StatusCode::FORBIDDEN,
            [(header::CONNECTION, "close")],
            Body::from("<Error><Code>AccessDenied</Code></Error>"),
        )
            .into_response(),
        _ => (StatusCode::METHOD_NOT_ALLOWED, [(header::CONNECTION, "close")], Body::empty()).into_response(),
    }
}

pub struct RunningLfsServer {
    pub base_url: String,
    pub svc: Arc<LfsBlobProofService>,
    pub scratch_dir: TempDir,
    handle: JoinHandle<()>,
}

impl Drop for RunningLfsServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl RunningLfsServer {
    pub async fn start(gate: LfsBlobRuntimeGate, pg: PgLfsBlobStore) -> Result<Self> {
        let scratch_dir = TempDir::new()?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let base_url = format!("http://127.0.0.1:{port}");
        let svc = Arc::new(LfsBlobProofService::new(
            gate,
            pg,
            scratch_dir.path().to_path_buf(),
            base_url.clone(),
            Duration::from_secs(20),
        ));
        let app = lfs_blob_proof_router(Arc::clone(&svc));
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(Self { base_url, svc, scratch_dir, handle })
    }
}

pub async fn run_with_migrated_pg_schema<F, Fut>(f: F) -> Result<()>
where
    F: FnOnce(Pool) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    let url = std::env::var("ROOTYARD_TEST_DATABASE_URL")
        .context("ROOTYARD_TEST_DATABASE_URL must be set for ignored PG17 tests")?;
    let admin = db::pool(&url)?;
    let schema = format!("lfs145_test_{}", Uuid::new_v4().simple());
    admin.get().await?.batch_execute(&format!("CREATE SCHEMA {schema}")).await?;
    let mut cfg: tokio_postgres::Config = url.parse()?;
    cfg.options(format!("-c search_path={schema} -c timezone=UTC -c statement_timeout=30000 -c lock_timeout=15000"));
    let pool = Pool::builder(Manager::new(cfg, tokio_postgres::NoTls))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .max_size(8)
        .build()?;
    let res = async {
        db::migrate(&pool).await?;
        init_lfs_blob_proof_tables(&pool).await?;
        f(pool.clone()).await
    }
    .await;
    pool.close();
    drop(pool);
    let teardown = admin.get().await?.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE")).await;
    admin.close();
    res?;
    teardown?;
    Ok(())
}

pub fn init_bare_git_repo(dir: &Path, fmt_str: &str) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let out = Command::new("git")
        .args(["init", "--bare", "--initial-branch=main", &format!("--object-format={fmt_str}")])
        .arg(dir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .output()?;
    ensure!(out.status.success(), "git init --bare failed: {}", String::from_utf8_lossy(&out.stderr));
    Ok(())
}

pub fn init_git_lfs_home(home: &Path) -> Result<()> {
    std::fs::create_dir_all(home)?;
    let out = Command::new("git")
        .args(["lfs", "install", "--skip-repo"])
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .context("git lfs must be installed on PATH")?;
    ensure!(out.status.success(), "git lfs install failed: {}", String::from_utf8_lossy(&out.stderr));
    for (k, v) in [("user.name", "Rootyard LFS Test"), ("user.email", "lfs@rootyard.test"), ("protocol.version", "2")] {
        let cfg = Command::new("git")
            .args(["config", "--global", k, v])
            .env("HOME", home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()?;
        ensure!(cfg.status.success(), "git config {k} failed");
    }
    Ok(())
}

pub fn run_git_raw(cwd: &Path, home: &Path, args: &[&str]) -> Result<Output> {
    Ok(Command::new("git")
        .args(["-c", "commit.gpgsign=false", "-c", "tag.gpgsign=false"])
        .args(args)
        .current_dir(cwd)
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "/bin/false")
        .output()?)
}

pub fn run_git_ok(cwd: &Path, home: &Path, args: &[&str]) -> Result<String> {
    let out = run_git_raw(cwd, home, args)?;
    if !out.status.success() {
        bail!(
            "git {:?} failed (code {:?}):\nstdout: {}\nstderr: {}",
            args,
            out.status.code(),
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}
