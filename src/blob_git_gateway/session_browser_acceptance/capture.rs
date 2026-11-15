//! Same-origin capture adapter in front of the child.
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex, PoisonError},
};

use anyhow::Result;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderName, HeaderValue, StatusCode, header},
    response::Response,
    routing::any,
};
use bytes::Bytes;

mod record;
pub(super) use record::{DenialPath, Recorded, Route};
use record::{denial_of, marker, record, route_of};

use super::http_client;

const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone)]
pub(super) struct Fixture {
    pub owner: String,
    pub name: String,
    pub oid: String,
    pub file: String,
    pub second_file: String,
    pub upstream: String,
}

impl Fixture {
    pub(super) fn alias_prefix(&self) -> String {
        format!("/web/blob/api/repos/{}/{}/", self.owner, self.name)
    }

    pub(super) fn read_path(&self, tail: &str) -> String {
        format!("{}{tail}", self.alias_prefix())
    }

    pub(super) fn git_info_refs(&self) -> String {
        format!("/git/{}/{}.git/info/refs", self.owner, self.name)
    }

    pub(super) fn requests_git_info_refs(&self, query: &str) -> bool {
        query == "service=git-upload-pack"
    }
}

#[derive(Clone, Default)]
pub(super) struct Capture(Arc<Mutex<Vec<Recorded>>>);

impl Capture {
    pub(super) fn snapshot(&self) -> Vec<Recorded> {
        std::mem::take(&mut *self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }

    fn push(&self, record: Recorded) {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).push(record);
    }
}

#[derive(Clone)]
struct Adapter {
    capture: Capture,
    fixture: Fixture,
}

pub(super) async fn serve_adapter(capture: Capture, fixture: Fixture) -> Result<SocketAddr> {
    let adapter = Arc::new(Adapter { capture, fixture });
    let app = Router::new().fallback(any(forward)).with_state(adapter);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(address)
}

async fn forward(State(adapter): State<Arc<Adapter>>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let route = route_of(&adapter.fixture.alias_prefix(), parts.uri.path());
    if route == Route::Other {
        let mut captured = record(&adapter.fixture, &parts, route, 400, None);
        captured.forwarding_failure = true;
        adapter.capture.push(captured);
        return failure(StatusCode::BAD_REQUEST, "unclassified page request");
    }
    match relay(&adapter, &parts, body).await {
        Ok(Ok((status, headers, bytes))) => {
            let mut captured = record(&adapter.fixture, &parts, route, status.as_u16(), Some(&headers));
            marker(&adapter.fixture, &bytes, route, &mut captured);
            adapter.capture.push(captured);
            answered(status, &headers, bytes)
        }
        Ok(Err(())) | Err(()) => failed(&adapter, &parts, route),
    }
}

fn failed(adapter: &Adapter, parts: &axum::http::request::Parts, route: Route) -> Response {
    if let Some(denial) = denial_of(&adapter.fixture, parts) {
        let mut captured = record(&adapter.fixture, parts, route, StatusCode::BAD_GATEWAY.as_u16(), None);
        captured.denial_path = Some(denial);
        captured.forwarding_failure = true;
        adapter.capture.push(captured);
    }
    failure(StatusCode::BAD_GATEWAY, "upstream unavailable")
}

async fn relay(
    adapter: &Adapter,
    parts: &axum::http::request::Parts,
    body: Body,
) -> Result<Result<(StatusCode, axum::http::HeaderMap, Bytes), ()>, ()> {
    let body = to_bytes(body, MAX_BODY_BYTES).await.map_err(|_| ())?;
    let upstream_origin = adapter.fixture.upstream.as_str();
    let target = format!("{upstream_origin}{}", parts.uri.path_and_query().map_or("/", |target| target.as_str()));
    let client = http_client().map_err(|_| ())?;
    let mut outbound = client.request(parts.method.clone(), target).body(body.to_vec());
    let origins: Vec<&HeaderValue> = parts.headers.get_all(header::ORIGIN).iter().collect();
    for (name, value) in parts.headers.iter() {
        if !is_hop_by_hop(name) && name != header::HOST && name != header::ORIGIN {
            outbound = outbound.header(name, value);
        }
    }
    if !origins.is_empty() {
        outbound = outbound.header(header::ORIGIN, upstream_origin);
    }
    let upstream = outbound.send().await.map_err(|_| ())?;
    let status = upstream.status();
    let headers = upstream.headers().clone();
    let bytes = upstream.bytes().await.map_err(|_| ())?;
    Ok(Ok((status, headers, bytes)))
}

fn answered(status: StatusCode, headers: &axum::http::HeaderMap, bytes: Bytes) -> Response {
    let mut answer = Response::new(Body::from(bytes));
    *answer.status_mut() = status;
    for (name, value) in headers.iter() {
        if !is_hop_by_hop(name) {
            answer.headers_mut().append(name.clone(), value.clone());
        }
    }
    answer
}

fn failure(status: StatusCode, reason: &'static str) -> Response {
    let mut answer = Response::new(Body::from(reason));
    *answer.status_mut() = status;
    answer
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}
