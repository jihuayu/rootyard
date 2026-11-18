//! LoopbackS3 (`RETRY_MAX_TIMES=3`, RFC 7233 `Range`, `Connection: close`) and serialized
//! real `rootyard::browse::policy::validate_hook` execution helper (`Refs #145`).

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};

use anyhow::Result;
use axum::{
    Router,
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use rootyard::{
    blob_store::{BlobLocator, config::BlobProfile, opendal::BlobStore},
    journal::{Operation, RefChange},
};
use sha2::{Digest, Sha256};

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

/// Executes Rootyard's real production `browse::policy::validate_hook` pre-receive gate on a
/// dedicated OS thread with the exact child hook environment (`ROOTYARD_DATABASE_URL`,
/// `ROOTYARD_GIT_PATH`, `ROOTYARD_GIT_DIR`, `ROOTYARD_DATA_ROOT`, `GIT_OBJECT_DIRECTORY`,
/// `GIT_ALTERNATE_OBJECT_DIRECTORIES`) serialized under `ENV_LOCK`.
pub fn run_real_validate_hook(
    db_url: &str,
    git_bin: &Path,
    git_dir: &Path,
    data_root: &Path,
    git_obj_dir: Option<&str>,
    git_alt_dirs: Option<&str>,
    op: &Operation,
    changes: &[RefChange],
) -> Result<()> {
    let db_url = db_url.to_owned();
    let git_bin = git_bin.to_path_buf();
    let git_dir = git_dir.to_path_buf();
    let data_root = data_root.to_path_buf();
    let git_obj_dir = git_obj_dir.map(str::to_owned);
    let git_alt_dirs = git_alt_dirs.map(str::to_owned);
    let op = op.clone();
    let changes = changes.to_vec();

    std::thread::spawn(move || {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: serialized across this test binary by `ENV_LOCK`.
        unsafe {
            std::env::set_var("ROOTYARD_DATABASE_URL", &db_url);
            std::env::set_var("ROOTYARD_GIT_PATH", &git_bin);
            std::env::set_var("ROOTYARD_GIT_DIR", &git_dir);
            std::env::set_var("ROOTYARD_DATA_ROOT", &data_root);
            std::env::set_var("ROOTYARD_GIT_TIMEOUT_SECONDS", "20");
            match &git_obj_dir {
                Some(v) => std::env::set_var("GIT_OBJECT_DIRECTORY", v),
                None => std::env::remove_var("GIT_OBJECT_DIRECTORY"),
            }
            match &git_alt_dirs {
                Some(v) => std::env::set_var("GIT_ALTERNATE_OBJECT_DIRECTORIES", v),
                None => std::env::remove_var("GIT_ALTERNATE_OBJECT_DIRECTORIES"),
            }
        }
        let res = rootyard::browse::policy::validate_hook(&op, &changes);
        // SAFETY: serialized across this test binary by `ENV_LOCK`.
        unsafe {
            std::env::remove_var("GIT_OBJECT_DIRECTORY");
            std::env::remove_var("GIT_ALTERNATE_OBJECT_DIRECTORIES");
        }
        res
    })
    .join()
    .map_err(|_| anyhow::anyhow!("validate_hook thread panicked"))?
}

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

fn parse_byte_range(hdr: &str, total: usize) -> Option<(usize, usize)> {
    let spec = hdr.trim().strip_prefix("bytes=")?;
    let (s_raw, e_raw) = spec.split_once('-')?;
    let start: usize = s_raw.parse().ok()?;
    if total == 0 || start >= total {
        return None;
    }
    let end = if e_raw.is_empty() { total - 1 } else { e_raw.parse::<usize>().ok()?.min(total - 1) };
    (start <= end).then_some((start, end))
}

async fn handle_s3(
    State(st): State<Arc<S3MemState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
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
                if method == Method::GET
                    && let Some(r_str) = headers.get(header::RANGE).and_then(|v| v.to_str().ok())
                {
                    let Some((start, end)) = parse_byte_range(r_str, bytes.len()) else {
                        return (
                            StatusCode::RANGE_NOT_SATISFIABLE,
                            [
                                (header::CONTENT_RANGE, format!("bytes */{}", bytes.len())),
                                (header::CONNECTION, "close".into()),
                            ],
                            Body::empty(),
                        )
                            .into_response();
                    };
                    let slice = bytes[start..=end].to_vec();
                    return (
                        StatusCode::PARTIAL_CONTENT,
                        [
                            (header::ETAG, etag),
                            (header::CONTENT_RANGE, format!("bytes {start}-{end}/{}", bytes.len())),
                            (header::CONTENT_LENGTH, slice.len().to_string()),
                            (header::CONNECTION, "close".into()),
                        ],
                        Body::from(slice),
                    )
                        .into_response();
                }
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
