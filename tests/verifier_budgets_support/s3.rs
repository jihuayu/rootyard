//! In-process loopback S3 HTTP server with Range read support and per-key delay injection.

use anyhow::{Result, anyhow};
use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri, header};
use axum::response::Response;
use bytes::Bytes;
use rootyard::blob_store::config::BlobProfile;
use rootyard::blob_store::opendal::BlobStore;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

#[derive(Default)]
struct S3Stats {
    get_requests: AtomicU64,
    get_bytes: AtomicU64,
    head_requests: AtomicU64,
    put_requests: AtomicU64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct S3Counters {
    pub get_requests: u64,
    pub get_bytes: u64,
    pub head_requests: u64,
    pub put_requests: u64,
}

impl S3Counters {
    pub fn delta_since(self, earlier: Self) -> Self {
        Self {
            get_requests: self.get_requests.saturating_sub(earlier.get_requests),
            get_bytes: self.get_bytes.saturating_sub(earlier.get_bytes),
            head_requests: self.head_requests.saturating_sub(earlier.head_requests),
            put_requests: self.put_requests.saturating_sub(earlier.put_requests),
        }
    }
}

#[derive(Default)]
struct S3State {
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
    delays: Mutex<Vec<(u64, String, Duration)>>,
    next_delay_id: AtomicU64,
    stats: S3Stats,
}

impl S3State {
    fn find_delay(&self, key: &str) -> Duration {
        let guard = self.delays.lock().unwrap();
        guard
            .iter()
            .filter(|(_, substr, _)| key.contains(substr.as_str()))
            .map(|(_, _, delay)| *delay)
            .max()
            .unwrap_or(Duration::ZERO)
    }
}

pub struct DelayGuard {
    id: u64,
    state: Arc<S3State>,
}

impl Drop for DelayGuard {
    fn drop(&mut self) {
        let mut guard = self.state.delays.lock().unwrap();
        guard.retain(|(id, _, _)| *id != self.id);
    }
}

pub struct LoopbackS3 {
    endpoint: String,
    bucket: &'static str,
    region: &'static str,
    state: Arc<S3State>,
}

static SHARED_S3: OnceLock<LoopbackS3> = OnceLock::new();

impl LoopbackS3 {
    /// Start (once) a dedicated OS thread with its own permanent Tokio runtime
    /// so `LoopbackS3` never shuts down when individual `#[tokio::test]` runtimes drop.
    pub fn shared() -> &'static Self {
        SHARED_S3.get_or_init(|| {
            let state = Arc::new(S3State::default());
            let server_state = Arc::clone(&state);
            let std_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback S3 listener");
            std_listener.set_nonblocking(true).expect("set nonblocking loopback S3 listener");
            let port = std_listener.local_addr().expect("loopback local_addr").port();
            let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel::<()>(1);
            std::thread::Builder::new()
                .name("verifier-loopback-s3".to_owned())
                .spawn(move || {
                    let runtime = tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(2)
                        .enable_all()
                        .build()
                        .expect("build loopback S3 runtime");
                    runtime.block_on(async move {
                        let listener =
                            tokio::net::TcpListener::from_std(std_listener).expect("convert loopback S3 listener");
                        let app = Router::new().fallback(handle_s3).with_state(server_state);
                        let _ = ready_tx.send(());
                        let _ = axum::serve(listener, app).await;
                    });
                })
                .expect("spawn loopback S3 thread");
            ready_rx.recv().expect("wait for loopback S3 server startup");
            Self {
                endpoint: format!("http://127.0.0.1:{port}"),
                bucket: "verifier-budget-bucket",
                region: "garage",
                state,
            }
        })
    }

    pub fn add_get_delay(&self, key_substring: impl Into<String>, delay: Duration) -> DelayGuard {
        let id = self.state.next_delay_id.fetch_add(1, Ordering::Relaxed);
        let substr = key_substring.into();
        self.state.delays.lock().unwrap().push((id, substr, delay));
        DelayGuard { id, state: Arc::clone(&self.state) }
    }

    pub fn counters(&self) -> S3Counters {
        S3Counters {
            get_requests: self.state.stats.get_requests.load(Ordering::Relaxed),
            get_bytes: self.state.stats.get_bytes.load(Ordering::Relaxed),
            head_requests: self.state.stats.head_requests.load(Ordering::Relaxed),
            put_requests: self.state.stats.put_requests.load(Ordering::Relaxed),
        }
    }

    pub fn open_blob_store(&self) -> Result<(BlobStore, EnvGuard)> {
        let env = EnvGuard::set(&[
            ("ROOTYARD_BLOB_DRIVER", Some("opendal")),
            ("ROOTYARD_BLOB_SERVICE", Some("s3")),
            ("ROOTYARD_BLOB_BUCKET", Some(self.bucket)),
            ("ROOTYARD_BLOB_ROOT", Some("verifier-budgets")),
            ("ROOTYARD_BLOB_ENDPOINT", Some(&self.endpoint)),
            ("ROOTYARD_BLOB_REGION", Some(self.region)),
            ("ROOTYARD_BLOB_ACCESS_KEY_ID", Some("verifier-budget-ak")),
            ("ROOTYARD_BLOB_SECRET_ACCESS_KEY", Some("verifier-budget-sk")),
            ("ROOTYARD_BLOB_SESSION_TOKEN", None),
            ("ROOTYARD_BLOB_ENCRYPTION_MODE", Some("provider-managed")),
            ("ROOTYARD_BLOB_KEYRING_DIR", None),
            ("ROOTYARD_BLOB_ACTIVE_UPLOADS", None),
            ("ROOTYARD_BLOB_ACTIVE_READERS", None),
            ("ROOTYARD_BLOB_STAGING_BYTES", None),
            ("ROOTYARD_BLOB_MAX_OBJECT_BYTES", None),
            ("ROOTYARD_BLOB_RANGE_FULL_GET_MAX_BYTES", None),
            ("ROOTYARD_BLOB_TIMEOUT_MS", None),
            ("ROOTYARD_BLOB_IO_TIMEOUT_MS", None),
            ("ROOTYARD_BLOB_CONCURRENCY", None),
            ("ROOTYARD_BLOB_RETRY_MAX_TIMES", None),
            ("ROOTYARD_BLOB_DELETE", None),
        ]);
        let profile = BlobProfile::from_env().map_err(|e| anyhow!("loopback BlobProfile failed: {e}"))?;
        let store = BlobStore::open(profile).map_err(|e| anyhow!("loopback BlobStore::open failed: {e}"))?;
        Ok((store, env))
    }
}

pub struct EnvGuard {
    saved: Vec<(&'static str, Option<String>)>,
}

impl EnvGuard {
    pub fn set(pairs: &[(&'static str, Option<&str>)]) -> Self {
        let mut saved = Vec::with_capacity(pairs.len());
        for &(key, next) in pairs {
            saved.push((key, std::env::var(key).ok()));
            match next {
                Some(value) => unsafe { std::env::set_var(key, value) },
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
                Some(value) => unsafe { std::env::set_var(key, value) },
                None => unsafe { std::env::remove_var(key) },
            }
        }
    }
}

fn s3_response(
    status: StatusCode,
    content_type: Option<&str>,
    etag: Option<&str>,
    len: Option<usize>,
    content_range: Option<&str>,
    body: Body,
) -> Response {
    let mut builder = Response::builder().status(status).header(header::ACCEPT_RANGES, "bytes");
    if let Some(ct) = content_type {
        builder = builder.header(header::CONTENT_TYPE, ct);
    }
    if let Some(tag) = etag {
        builder = builder.header(header::ETAG, tag);
    }
    if let Some(range) = content_range {
        builder = builder.header(header::CONTENT_RANGE, range);
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
    s3_response(status, Some("application/xml"), None, Some(len), None, Body::from(bytes))
}

fn parse_byte_range(raw: &str, total: usize) -> Option<(usize, usize)> {
    let spec = raw.strip_prefix("bytes=")?;
    if total == 0 || spec.contains(',') {
        return None;
    }
    let (start_s, end_s) = spec.split_once('-')?;
    if start_s.is_empty() {
        let suffix = end_s.parse::<usize>().ok()?;
        if suffix == 0 {
            return None;
        }
        let start = total.saturating_sub(suffix);
        return Some((start, total - 1));
    }
    let start = start_s.parse::<usize>().ok()?;
    if start >= total {
        return None;
    }
    let end = if end_s.is_empty() { total - 1 } else { end_s.parse::<usize>().ok()?.min(total - 1) };
    (start <= end).then_some((start, end))
}

async fn handle_s3(
    State(state): State<Arc<S3State>>,
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
            None,
            if method == Method::HEAD { Body::empty() } else { Body::from(bytes) },
        );
    }

    let full_key = format!("{bucket}/{key}");
    match method {
        Method::PUT => {
            let if_none_match = headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) == Some("*");
            let mut objects = state.objects.lock().unwrap();
            if if_none_match && objects.contains_key(&full_key) {
                return xml_error(StatusCode::PRECONDITION_FAILED, "PreconditionFailed", "already exists");
            }
            let digest = hex::encode(Sha256::digest(&body));
            let etag = format!("\"{}\"", &digest[..32]);
            objects.insert(full_key, body.to_vec());
            state.stats.put_requests.fetch_add(1, Ordering::Relaxed);
            s3_response(StatusCode::OK, None, Some(&etag), Some(0), None, Body::empty())
        }
        Method::HEAD => {
            let maybe = state.objects.lock().unwrap().get(&full_key).cloned();
            let Some(stored) = maybe else {
                return s3_response(StatusCode::NOT_FOUND, Some("application/xml"), None, Some(0), None, Body::empty());
            };
            state.stats.head_requests.fetch_add(1, Ordering::Relaxed);
            let digest = hex::encode(Sha256::digest(&stored));
            let etag = format!("\"{}\"", &digest[..32]);
            s3_response(
                StatusCode::OK,
                Some("application/octet-stream"),
                Some(&etag),
                Some(stored.len()),
                None,
                Body::empty(),
            )
        }
        Method::GET => {
            let delay = state.find_delay(&full_key);
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            let maybe = state.objects.lock().unwrap().get(&full_key).cloned();
            let Some(stored) = maybe else {
                return xml_error(StatusCode::NOT_FOUND, "NoSuchKey", "missing");
            };
            state.stats.get_requests.fetch_add(1, Ordering::Relaxed);
            let digest = hex::encode(Sha256::digest(&stored));
            let etag = format!("\"{}\"", &digest[..32]);
            if let Some(range_raw) = headers.get(header::RANGE).and_then(|v| v.to_str().ok()) {
                let Some((start, end)) = parse_byte_range(range_raw, stored.len()) else {
                    return s3_response(StatusCode::RANGE_NOT_SATISFIABLE, None, None, Some(0), None, Body::empty());
                };
                let slice = stored[start..=end].to_vec();
                state.stats.get_bytes.fetch_add(slice.len() as u64, Ordering::Relaxed);
                let cr = format!("bytes {start}-{end}/{}", stored.len());
                return s3_response(
                    StatusCode::PARTIAL_CONTENT,
                    Some("application/octet-stream"),
                    Some(&etag),
                    Some(slice.len()),
                    Some(&cr),
                    Body::from(slice),
                );
            }
            state.stats.get_bytes.fetch_add(stored.len() as u64, Ordering::Relaxed);
            let len = stored.len();
            s3_response(
                StatusCode::OK,
                Some("application/octet-stream"),
                Some(&etag),
                Some(len),
                None,
                Body::from(stored),
            )
        }
        Method::DELETE => {
            state.objects.lock().unwrap().remove(&full_key);
            s3_response(StatusCode::NO_CONTENT, None, None, Some(0), None, Body::empty())
        }
        _ => s3_response(StatusCode::METHOD_NOT_ALLOWED, None, None, Some(0), None, Body::empty()),
    }
}
