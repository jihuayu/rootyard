//! In-process loopback S3 for the W8-A paired backup/restore suite.
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri, header};
use axum::response::Response;
use bytes::Bytes;
use sha2::{Digest, Sha256};

const BUCKET: &str = "w8a-paired-bucket";
const REGION: &str = "garage";
static ENV_LOCK: Mutex<()> = Mutex::new(());
static SHARED: OnceLock<LoopbackS3> = OnceLock::new();

#[derive(Default)]
struct State {
    objects: Mutex<BTreeMap<String, Vec<u8>>>,
}

pub struct LoopbackS3 {
    endpoint: String,
    state: Arc<State>,
}

impl LoopbackS3 {
    pub fn shared() -> &'static Self {
        SHARED.get_or_init(|| {
            let state = Arc::new(State::default());
            let server = Arc::clone(&state);
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let port = listener.local_addr().unwrap().port();
            let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
            std::thread::Builder::new()
                .name("w8a-loopback-s3".into())
                .spawn(move || {
                    let runtime =
                        tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
                    runtime.block_on(async move {
                        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                        let app = Router::new().fallback(handle).with_state(server);
                        ready_tx.send(()).unwrap();
                        axum::serve(listener, app).await.unwrap();
                    });
                })
                .unwrap();
            ready_rx.recv().unwrap();
            Self { endpoint: format!("http://127.0.0.1:{port}"), state }
        })
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn bucket(&self) -> &'static str {
        BUCKET
    }

    pub fn region(&self) -> &'static str {
        REGION
    }

    pub fn clear(&self) {
        self.state.objects.lock().unwrap().clear();
    }
}

/// Serializes every process-environment mutation in this suite and restores the
/// previous values on drop. This is the only `unsafe` surface in the W8-A tests.
pub struct EnvGuard {
    _lock: MutexGuard<'static, ()>,
    saved: Vec<(&'static str, Option<String>)>,
}

impl EnvGuard {
    pub fn set(pairs: &[(&'static str, Option<&str>)]) -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        let mut saved = Vec::with_capacity(pairs.len());
        for &(key, next) in pairs {
            saved.push((key, std::env::var(key).ok()));
            match next {
                Some(value) => unsafe { std::env::set_var(key, value) },
                None => unsafe { std::env::remove_var(key) },
            }
        }
        Self { _lock: lock, saved }
    }

    pub fn update(&mut self, key: &'static str, value: &str) {
        if !self.saved.iter().any(|(saved, _)| *saved == key) {
            self.saved.push((key, std::env::var(key).ok()));
        }
        unsafe { std::env::set_var(key, value) };
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, previous) in self.saved.drain(..).rev() {
            match previous {
                Some(value) => unsafe { std::env::set_var(key, value) },
                None => unsafe { std::env::remove_var(key) },
            }
        }
    }
}

fn response(status: StatusCode, len: Option<usize>, extra: &[(&str, &str)], body: Body) -> Response {
    let mut builder =
        Response::builder().status(status).header(header::ACCEPT_RANGES, "bytes").header(header::CONNECTION, "close");
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    if let Some(len) = len {
        builder = builder.header(header::CONTENT_LENGTH, len.to_string());
    }
    builder.body(body).unwrap()
}

fn error(status: StatusCode, code: &str) -> Response {
    let body = format!("<Error><Code>{code}</Code></Error>").into_bytes();
    let len = body.len();
    response(status, Some(len), &[("content-type", "application/xml")], Body::from(body))
}

fn etag(bytes: &[u8]) -> String {
    format!("\"{}\"", hex::encode(&Sha256::digest(bytes)[..16]))
}

fn range(raw: &str, total: usize) -> Option<(usize, usize)> {
    let spec = raw.strip_prefix("bytes=")?;
    if total == 0 || spec.contains(',') {
        return None;
    }
    let (start, end) = spec.split_once('-')?;
    if start.is_empty() {
        let suffix = end.parse::<usize>().ok()?;
        return (suffix > 0).then_some((total.saturating_sub(suffix), total - 1));
    }
    let start = start.parse::<usize>().ok()?;
    if start >= total {
        return None;
    }
    let end = if end.is_empty() { total - 1 } else { end.parse::<usize>().ok()?.min(total - 1) };
    (start <= end).then_some((start, end))
}

async fn handle(
    State(state): State<Arc<State>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = uri.path().trim_start_matches('/').to_owned();
    let (bucket, key) = path.split_once('/').unwrap_or((path.as_str(), ""));
    if bucket.is_empty() {
        return response(StatusCode::OK, None, &[], Body::from("<ListAllMyBucketsResult/>"));
    }
    if key.is_empty() && matches!(method, Method::GET | Method::HEAD) {
        let body = format!(
            "<ListBucketResult><Name>{bucket}</Name><KeyCount>0</KeyCount><IsTruncated>false</IsTruncated></ListBucketResult>"
        );
        return response(StatusCode::OK, None, &[("content-type", "application/xml")], Body::from(body));
    }
    let full = format!("{bucket}/{key}");
    match method {
        Method::PUT => {
            let mut objects = state.objects.lock().unwrap();
            if headers.get(header::IF_NONE_MATCH).and_then(|value| value.to_str().ok()) == Some("*")
                && objects.contains_key(&full)
            {
                return error(StatusCode::PRECONDITION_FAILED, "PreconditionFailed");
            }
            let tag = etag(&body);
            objects.insert(full, body.to_vec());
            response(StatusCode::OK, Some(0), &[("etag", tag.as_str())], Body::empty())
        }
        Method::HEAD => {
            let stored = state.objects.lock().unwrap().get(&full).cloned();
            let Some(stored) = stored else { return response(StatusCode::NOT_FOUND, Some(0), &[], Body::empty()) };
            let tag = etag(&stored);
            let len = stored.len();
            response(
                StatusCode::OK,
                Some(len),
                &[("content-type", "application/octet-stream"), ("etag", tag.as_str())],
                Body::empty(),
            )
        }
        Method::GET => {
            let stored = state.objects.lock().unwrap().get(&full).cloned();
            let Some(stored) = stored else { return error(StatusCode::NOT_FOUND, "NoSuchKey") };
            let tag = etag(&stored);
            if let Some(raw) = headers.get(header::RANGE).and_then(|value| value.to_str().ok()) {
                let Some((start, end)) = range(raw, stored.len()) else {
                    return response(StatusCode::RANGE_NOT_SATISFIABLE, Some(0), &[], Body::empty());
                };
                let slice = stored[start..=end].to_vec();
                let cr = format!("bytes {start}-{end}/{}", stored.len());
                let len = slice.len();
                return response(
                    StatusCode::PARTIAL_CONTENT,
                    Some(len),
                    &[
                        ("content-type", "application/octet-stream"),
                        ("content-range", cr.as_str()),
                        ("etag", tag.as_str()),
                    ],
                    Body::from(slice),
                );
            }
            let len = stored.len();
            response(
                StatusCode::OK,
                Some(len),
                &[("content-type", "application/octet-stream"), ("etag", tag.as_str())],
                Body::from(stored),
            )
        }
        Method::DELETE => {
            state.objects.lock().unwrap().remove(&full);
            response(StatusCode::NO_CONTENT, Some(0), &[], Body::empty())
        }
        _ => response(StatusCode::METHOD_NOT_ALLOWED, Some(0), &[], Body::empty()),
    }
}
