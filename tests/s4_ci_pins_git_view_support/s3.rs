//! Minimal in-process S3 endpoint used by the S4 acceptance harness.
use anyhow::Result;
use axum::{
    Router,
    body::Body,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri, header},
    response::Response,
};
use bytes::Bytes;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex as StdMutex},
};
use tokio::{net::TcpListener, task::JoinHandle};

/// Parse the `bytes=start-end` / `bytes=start-` forms the S3 reader emits.
/// A bare `-suffix` range is deliberately not supported: the reader never asks
/// for it, and refusing it keeps every accepted range explicit.
fn parse_range(value: &str) -> Option<(usize, usize)> {
    let spec = value.strip_prefix("bytes=")?;
    let (start, end) = spec.split_once('-')?;
    let start: usize = start.parse().ok()?;
    if end.is_empty() {
        return Some((start, usize::MAX));
    }
    Some((start, end.parse().ok()?))
}

#[derive(Default)]
struct S3State {
    objects: BTreeMap<String, Vec<u8>>,
}

pub struct LoopbackS3 {
    pub endpoint: String,
    task: JoinHandle<()>,
}

impl LoopbackS3 {
    pub async fn start() -> Result<Self> {
        let state = Arc::new(StdMutex::new(S3State::default()));
        let app = Router::new().fallback(handle).with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(Self { endpoint, task })
    }
}

impl Drop for LoopbackS3 {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn reply(status: StatusCode, body: Body, content_type: Option<&str>, length: Option<usize>) -> Response {
    let mut builder = Response::builder().status(status).header(header::CONNECTION, "close");
    if let Some(content_type) = content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    if let Some(length) = length {
        builder = builder.header(header::CONTENT_LENGTH, length.to_string());
    }
    builder.body(body).unwrap_or_else(|_| Response::new(Body::empty()))
}

async fn handle(
    State(state): State<Arc<StdMutex<S3State>>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let raw = uri.path().trim_start_matches('/').to_owned();
    let (bucket, key) = raw.split_once('/').unwrap_or((raw.as_str(), ""));
    if bucket.is_empty() {
        return reply(StatusCode::OK, Body::from("<ListAllMyBucketsResult/>"), Some("application/xml"), None);
    }
    if key.is_empty() && matches!(method, Method::GET | Method::HEAD) {
        let listing =
            format!("<ListBucketResult><Name>{bucket}</Name><KeyCount>0</KeyCount><IsTruncated>false</IsTruncated></ListBucketResult>");
        let length = listing.len();
        return reply(StatusCode::OK, Body::from(listing), Some("application/xml"), Some(length));
    }
    let full = format!("{bucket}/{key}");
    match method {
        Method::PUT => {
            let exists = state.lock().map(|s| s.objects.contains_key(&full)).unwrap_or(false);
            if headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) == Some("*") && exists {
                return reply(StatusCode::PRECONDITION_FAILED, Body::empty(), None, None);
            }
            if let Ok(mut guard) = state.lock() {
                guard.objects.insert(full, body.to_vec());
            }
            reply(StatusCode::OK, Body::empty(), None, None)
        }
        Method::GET | Method::HEAD => {
            let stored = state.lock().ok().and_then(|s| s.objects.get(&full).cloned());
            let Some(stored) = stored else {
                return reply(StatusCode::NOT_FOUND, Body::empty(), None, None);
            };
            if method == Method::GET
                && let Some((start, end)) = headers
                    .get(header::RANGE)
                    .and_then(|value| value.to_str().ok())
                    .and_then(parse_range)
            {
                if start >= stored.len() || end < start {
                    return reply(StatusCode::RANGE_NOT_SATISFIABLE, Body::empty(), None, None);
                }
                let end = end.min(stored.len() - 1);
                let slice = stored[start..=end].to_vec();
                let length = slice.len();
                return Response::builder()
                    .status(StatusCode::PARTIAL_CONTENT)
                    .header(header::CONNECTION, "close")
                    .header(header::CONTENT_TYPE, "application/octet-stream")
                    .header(header::CONTENT_LENGTH, length.to_string())
                    .header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{}", stored.len()))
                    .body(Body::from(slice))
                    .unwrap_or_else(|_| Response::new(Body::empty()));
            }
            let length = stored.len();
            let payload = if method == Method::HEAD { Body::empty() } else { Body::from(stored) };
            reply(StatusCode::OK, payload, Some("application/octet-stream"), Some(length))
        }
        Method::DELETE => {
            if let Ok(mut guard) = state.lock() {
                guard.objects.remove(&full);
            }
            reply(StatusCode::NO_CONTENT, Body::empty(), None, None)
        }
        _ => reply(StatusCode::METHOD_NOT_ALLOWED, Body::empty(), None, None),
    }
}
