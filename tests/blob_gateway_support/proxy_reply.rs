//! A forwarded backend answer reaches the client unchanged: the real status,
//! body and end-to-end headers (challenge, `Content-Type`, operation),
//! including when the request was held at the barrier first.
//!
//! This is a test-only child module of [`super`] (`proxy`), so it can read the
//! private listener address. Each case runs the real `Proxy` listener in front
//! of a loopback backend and speaks raw HTTP/1.1 to the proxy's own address; it
//! is not the stock Git client, and only the proxy's public methods drive the
//! barrier.

use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};

// `blob_gateway_support` is both the crate root (as `mod
// blob_gateway_support`) and `crate::proxy`'s parent, so `wire` outside `super`
// is ambiguous there; name it through its defining module instead.
use crate::blob_gateway_support::wire::{self, Bounds};

use super::{Limits, Proxy, loopback};

const TIMEOUT: Duration = Duration::from_secs(5);

/// A backend listener on a kernel-assigned loopback port with nothing accepted
/// yet, so it is guaranteed to be live and bound.
async fn backend_listener() -> Result<TcpListener> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    ensure!(loopback(listener.local_addr()?), "backend must be loopback");
    Ok(listener)
}

/// Read one request head and bounded body from a backend connection.
async fn read_request<R: AsyncBufReadExt + Unpin>(reader: &mut R) -> Result<(String, Vec<(String, String)>, Vec<u8>)> {
    // `read_head` leaves its error type open, so name it for `context`.
    let head: Vec<u8> = wire::read_head(reader, TIMEOUT).await?.context("the backend saw no request")?;
    let (method, _target, headers) = wire::parse_head(&head)?;
    let limits = Limits::default();
    let bounds = Bounds { max_body: limits.max_body, max_response: limits.max_response, idle: &TIMEOUT };
    let body = wire::read_body(reader, &headers, &bounds).await?;
    Ok((method, headers, body))
}

/// Answer the single backend connection to `listener` with `response`
/// verbatim. When `operation` is given, the backend asserts that the proxy
/// forwarded exactly that `X-Rootyard-Operation`; when it is `None`, the case
/// sends no operation at all and the backend asserts its absence.
fn answer_backend(
    listener: TcpListener,
    operation: Option<&'static str>,
    response: &'static [u8],
) -> JoinHandle<Result<()>> {
    tokio::spawn(async move {
        let (mut stream, _) = timeout(TIMEOUT, listener.accept()).await??;
        {
            let mut reader = BufReader::new(&mut stream);
            let (method, headers, body) = read_request(&mut reader).await?;
            ensure!(method == "POST", "the backend only ever sees a receive-pack POST, saw {method}");
            ensure!(body == b"0000", "the backend receives the client body byte for byte");
            ensure!(
                wire::header(&headers, "x-rootyard-operation") == operation,
                "the backend saw operation {:?}, not {operation:?}",
                wire::header(&headers, "x-rootyard-operation"),
            );
        }
        stream.write_all(response).await?;
        stream.shutdown().await?;
        Ok(())
    })
}

/// One raw receive-pack POST over a fresh connection to the proxy's own
/// listener; returns the status, lowercase headers and body the client sees.
async fn through_proxy(
    proxy: &Proxy,
    target: &str,
    operation: Option<&str>,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    through_address(proxy.address, target, operation).await
}

/// [`through_proxy`] over one explicit listener address, so a client task owns
/// no borrow of the proxy. `operation`, when given, is sent as the
/// `X-Rootyard-Operation` request header exactly as a stock Git client would.
async fn through_address(
    address: SocketAddr,
    target: &str,
    operation: Option<&str>,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    ensure!(loopback(address), "the proxy must listen on loopback");
    let stream = timeout(TIMEOUT, TcpStream::connect(address)).await??;
    let (read, mut write) = stream.into_split();
    let operation_header =
        operation.map(|operation| format!("X-Rootyard-Operation: {operation}\r\n")).unwrap_or_default();
    write
        .write_all(
            format!(
                "POST {target} HTTP/1.1\r\n\
                 Host: {address}\r\n\
                 Content-Type: application/x-git-receive-pack-request\r\n\
                 {operation_header}\
                 Content-Length: 4\r\n\r\n\
                 0000"
            )
            .as_bytes(),
        )
        .await?;
    write.flush().await?;
    let mut reader = BufReader::new(read);
    let (_, status, headers) = wire::read_backend_head(&mut reader, tokio::time::Instant::now() + TIMEOUT).await?;
    let bounds = Bounds { max_body: 64 * 1024, max_response: 64 * 1024, idle: &TIMEOUT };
    let (body, truncated) = wire::read_backend(&mut reader, &headers, &bounds).await?;
    ensure!(!truncated, "the proxy answer ended before its declared length");
    Ok((status, headers, body))
}

/// Every occurrence of `name` in the headers the client observed.
fn header_values<'a>(headers: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    headers.iter().filter(|(key, _)| key == name).map(|(_, value)| value.as_str()).collect()
}

fn header_names(headers: &[(String, String)]) -> Vec<&str> {
    headers.iter().map(|(name, _)| name.as_str()).collect()
}

#[tokio::test]
async fn forwarded_backend_challenge_reaches_the_client_unchanged() -> Result<()> {
    const OPERATION: &str = "550e8400-e29b-41d4-a716-446655440042";
    let listener = backend_listener().await?;
    let backend = listener.local_addr()?;
    let backend_task = answer_backend(
        listener,
        Some(OPERATION),
        b"HTTP/1.1 401 Unauthorized\r\n\
          WWW-Authenticate: Basic realm=\"rootyard\"\r\n\
          Content-Type: application/x-git-receive-pack-result\r\n\
          X-Rootyard-Operation: 550e8400-e29b-41d4-a716-446655440042\r\n\
          Content-Length: 0\r\n\r\n",
    );
    let proxy = Proxy::start(backend, Limits::default()).await?;
    // This case names the operation explicitly: as a header and in the query.
    let observed = through_proxy(
        &proxy,
        &format!("/git/alice/demo.git/git-receive-pack?operation={OPERATION}"),
        Some(OPERATION),
    )
    .await;
    let records = proxy.records().await;
    let failure = proxy.failure();
    proxy.stop().await?;
    let (status, headers, body) = observed?;
    backend_task.await??;
    ensure!(failure.is_none(), "proxy recorded a failure: {failure:?}");

    // Status, body and every end-to-end header reach the client unchanged.
    assert_eq!(status, 401);
    assert!(body.is_empty());
    assert_eq!(wire::header(&headers, "www-authenticate"), Some("Basic realm=\"rootyard\""));
    assert_eq!(wire::header(&headers, "content-type"), Some("application/x-git-receive-pack-result"));
    assert_eq!(wire::header(&headers, "x-rootyard-operation"), Some(OPERATION));

    let record = records.first().context("the proxy recorded no exchange")?;
    assert_eq!(record.method, "POST");
    assert_eq!(record.path, "/git/alice/demo.git/git-receive-pack");
    assert_eq!(record.status, Some(401));
    assert_eq!(record.request_bytes, 4);
    assert_eq!(record.request_sha256, super::sha256(b"0000"));
    Ok(())
}

#[tokio::test]
async fn held_backend_headers_are_saved_and_forwarded() -> Result<()> {
    let listener = backend_listener().await?;
    let backend = listener.local_addr()?;
    // The held case sends no operation header, so the backend must see none.
    let backend_task = answer_backend(
        listener,
        None,
        b"HTTP/1.1 200 OK\r\n\
          Content-Type: application/x-git-receive-pack-result\r\n\
          X-Rootyard-Operation: held-1\r\n\
          Set-Cookie: rootyard=held; Path=/\r\n\
          Transfer-Encoding: chunked\r\n\
          Connection: keep-alive\r\n\
          Keep-Alive: timeout=5\r\n\r\n\
          4\r\n0000\r\n0\r\n\r\n",
    );
    let proxy = Proxy::start(backend, Limits::default()).await?;
    proxy.hold_connection(1).await?;
    let target = "/git/alice/demo.git/git-receive-pack";
    // The child test module reads the private listener address; the client task
    // then owns no borrow of the proxy.
    let client = tokio::spawn(async move { through_address(proxy.address, target, None).await });

    let held = async {
        proxy.await_held(1).await?;
        ensure!(!client.is_finished(), "the held request was answered before the barrier opened");
        proxy.resolve_held().await
    }
    .await;
    // Always join the client and the backend and stop the proxy, even when the
    // barrier failed.
    let observed = client.await.context("the client task panicked")?;
    let failure = proxy.failure();
    proxy.stop().await?;
    backend_task.await??;
    held?;
    let (status, headers, body) = observed?;
    ensure!(failure.is_none(), "proxy recorded a failure: {failure:?}");

    assert_eq!(status, 200);
    assert_eq!(body, b"0000");
    assert_eq!(wire::header(&headers, "content-type"), Some("application/x-git-receive-pack-result"));
    assert_eq!(wire::header(&headers, "x-rootyard-operation"), Some("held-1"));
    // End-to-end headers are kept, so the saved observation retains them.
    assert_eq!(wire::header(&headers, "set-cookie"), Some("rootyard=held; Path=/"));
    let names = header_names(&headers);
    assert!(names.contains(&"content-type"), "observed headers: {names:?}");
    assert!(names.contains(&"x-rootyard-operation"), "observed headers: {names:?}");
    // The decoded body is delimited once: connection-specific headers are
    // removed (including those named by Connection) and replaced, never doubled.
    assert_eq!(header_values(&headers, "content-length"), ["4"]);
    assert_eq!(header_values(&headers, "connection"), ["close"]);
    assert_eq!(header_values(&headers, "transfer-encoding"), Vec::<&str>::new());
    assert_eq!(header_values(&headers, "keep-alive"), Vec::<&str>::new());
    Ok(())
}
