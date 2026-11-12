//! Typed privacy bridge between the OpenDAL adapter and the ref-store
//! `RemoteStoreError` diagnostics surface.
//!
//! OpenDAL 0.57 exposes only an `ErrorKind` through its public error API. It
//! does not expose the numeric HTTP status. Parsing `Display`/`Debug` text or
//! inventing a status from an `ErrorKind` is therefore forbidden here.
//!
//! The SDK's own [`HttpFetch`] client is wrapped at the exact request
//! boundary. Signing, TLS, connection pooling, redirects, retries, multipart
//! and successful-response parsing remain inside the SDK. For every observed
//! non-2xx response the wrapper reads the error body with a strict 64 KiB
//! bound, feeds that body to the pinned upstream S3 parser
//! (`opendal_service_s3::parse_error_response`) so provider codes retain their
//! real semantics, then discards the provider message/context and returns an
//! `opendal::Error` whose private source is a [`HttpFailure`] carrying only the
//! numeric status, the finite [`RemoteOp`] and the bounded SDK classification.
//!
//! Successful response heads pass through untouched, so an HTTP 200 carrying an
//! embedded provider error document is still parsed by the SDK and reported
//! with no HTTP status, while any mid-body or truncation failure after a 2xx
//! head is stripped of provider URLs and marked permanent so OpenDAL's
//! `RetryReader` never silently restarts a partially-streamed request.
//! Attribution is per request: a retry that ends in a transport failure, or a
//! later 200 decode failure, can never report status from an earlier 503.
//! Concurrent multipart requests each carry their own marker. No URL, path,
//! query value, header, credential or body is stored, logged or formatted.
//! Error classification walks only the bounded `std::error::Error` source chain
//! and private marker types; it never parses source text.

use std::error::Error as StdError;
use std::fmt;
use std::future::{Future, IntoFuture};
use std::pin::Pin;
use std::sync::Mutex;
use std::task::{Context, Poll};

// `http` is not a direct dependency of this crate (the root owns `Cargo.toml`)
// and `axum` re-exports the same `http` 1.x crate that `opendal-core` uses, so
// these are the exact request/response types of the `HttpFetch` trait.
use axum::http::{Method, Request, Response, Uri};
use bytes::{Bytes, BytesMut};
use futures_util::Stream;
use opendal::raw::oio::Read as _;
use opendal::raw::{HttpBody, HttpClient, HttpFetch};
use opendal::{Buffer, ErrorKind, Result as SdkResult};
use opendal_service_s3::parse_error_response;

use crate::blob_store::BlobError;

use super::remote_errors::{RemoteOp, RemoteSdkKind, RemoteStoreError};

/// Bounded source-chain walk. OpenDAL nests at most an SDK error plus one
/// transport/body error; a finite limit also stops a hostile cyclic chain.
const MAX_CAUSE_DEPTH: usize = 8;
/// Strict ceiling for an error-response body. Only a failed response is read
/// here, and never beyond this many bytes.
const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;
const HTTP_FAILURE_MESSAGE: &str = "remote object store request failed";
const TRANSPORT_FAILURE_MESSAGE: &str = "remote object store transport failed";
const STREAM_FAILURE_MESSAGE: &str = "remote object store stream failed";

/// Private marker attached to the exact failing HTTP response. It holds only
/// finite values: a numeric status, an operation label and the bounded SDK
/// classification derived by the upstream parser.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HttpFailure {
    status: u16,
    op: RemoteOp,
    kind: RemoteSdkKind,
    temporary: bool,
}

impl fmt::Display for HttpFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Fixed text only; status/op are bounded values, never request data.
        write!(formatter, "http status {} at {}", self.status, self.op.as_str())
    }
}

impl StdError for HttpFailure {}

/// Finite transport classification for a request that produced no HTTP
/// response at all. It deliberately stores no SDK error: OpenDAL's public API
/// does not let us extract an owned URL-free underlying cause, and its error
/// text/context may contain the request URL. Keeping only the kind and
/// temporary flag is the strongest privacy-preserving contract possible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TransportCause {
    kind: RemoteSdkKind,
    temporary: bool,
}

struct NetworkFailure {
    op: RemoteOp,
    cause: TransportCause,
}

impl fmt::Display for NetworkFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("network request failed")
    }
}

impl fmt::Debug for NetworkFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NetworkFailure(<redacted>)")
    }
}

impl StdError for NetworkFailure {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        // No original SDK error and no URL-bearing provider context is kept.
        None
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cause {
    Http { status: u16, op: RemoteOp, kind: RemoteSdkKind, temporary: bool },
    Transport { op: RemoteOp, cause: TransportCause },
}

/// Walk the bounded source chain for private markers only.
fn exact_cause(error: &(dyn StdError + 'static)) -> Option<Cause> {
    let mut next = error.source();
    for _ in 0..MAX_CAUSE_DEPTH {
        let source = next?;
        if let Some(http) = source.downcast_ref::<HttpFailure>() {
            return Some(Cause::Http { status: http.status, op: http.op, kind: http.kind, temporary: http.temporary });
        }
        if let Some(network) = source.downcast_ref::<NetworkFailure>() {
            return Some(Cause::Transport { op: network.op, cause: network.cause });
        }
        next = source.source();
    }
    None
}

/// Keep the upstream parser's kind and retry flags, but replace its provider
/// message/context with fixed text and an exact request marker. The parsed
/// error is dropped immediately, so no XML body, resource path or URL survives.
fn parsed_http_failure(parsed: opendal::Error, status: u16, op: RemoteOp) -> opendal::Error {
    let kind = parsed.kind();
    let temporary = parsed.is_temporary();
    let persistent = parsed.is_persistent();
    let sdk_kind = sdk_kind(kind);
    drop(parsed);

    let mut error = opendal::Error::new(kind, HTTP_FAILURE_MESSAGE).set_source(HttpFailure {
        status,
        op,
        kind: sdk_kind,
        temporary,
    });
    if temporary {
        error = error.set_temporary();
    } else if persistent {
        error = error.set_persistent();
    }
    error
}

/// An unreadable or oversized body supplies no safe provider code. Reuse the
/// pinned parser with an empty body to preserve its status-only retry and
/// precondition defaults, then discard its message/context as usual.
fn unparsed_http_failure(status: u16, op: RemoteOp) -> opendal::Error {
    let response =
        Response::builder().status(status).body(Buffer::new()).expect("an observed response has a valid HTTP status");
    parsed_http_failure(parse_error_response(response), status, op)
}

/// Convert one SDK transport failure into a finite marker. The original error
/// may carry a URL-bearing context, so it is dropped rather than retained.
fn network_failure(error: opendal::Error, op: RemoteOp) -> opendal::Error {
    let kind = error.kind();
    let temporary = error.is_temporary();
    let persistent = error.is_persistent();
    let cause = TransportCause { kind: sdk_kind(kind), temporary };
    drop(error);

    let mut wrapped = opendal::Error::new(kind, TRANSPORT_FAILURE_MESSAGE).set_source(NetworkFailure { op, cause });
    if temporary {
        wrapped = wrapped.set_temporary();
    } else if persistent {
        wrapped = wrapped.set_persistent();
    }
    wrapped
}

/// Read at most [`MAX_ERROR_BODY_BYTES`] from an error response. The SDK's
/// `HttpBody` stream is polled directly; `to_buffer` (which is unbounded and
/// would retain an arbitrary provider body) is never used.
async fn collect_error_body(mut body: HttpBody) -> Option<Buffer> {
    let mut collected = BytesMut::with_capacity(4 * 1024);
    loop {
        let chunk = body.read().await.ok()?;
        if chunk.is_empty() {
            break;
        }
        if collected.len().checked_add(chunk.len())? > MAX_ERROR_BODY_BYTES {
            return None;
        }
        collected.extend_from_slice(&chunk.to_bytes());
    }
    Some(Buffer::from(collected.freeze()))
}

fn query_has_key(uri: &Uri, key: &str) -> bool {
    uri.query().is_some_and(|query| query.split('&').any(|pair| pair.split('=').next() == Some(key)))
}

/// Derive the finite operation stage from the request method and the presence
/// of fixed multipart query keys. Query values, paths and headers are never
/// read or retained.
fn request_stage(method: &Method, uri: &Uri) -> RemoteOp {
    if method == Method::GET {
        return RemoteOp::Get;
    }
    if method == Method::HEAD {
        return RemoteOp::Head;
    }
    if method == Method::DELETE {
        return if query_has_key(uri, "uploadId") { RemoteOp::MultipartAbort } else { RemoteOp::Delete };
    }
    if method == Method::POST {
        if query_has_key(uri, "uploads") {
            return RemoteOp::MultipartInitiate;
        }
        if query_has_key(uri, "uploadId") {
            return RemoteOp::MultipartComplete;
        }
        return RemoteOp::Put;
    }
    if method == Method::PUT {
        return if query_has_key(uri, "uploadId") && query_has_key(uri, "partNumber") {
            RemoteOp::MultipartPart
        } else {
            RemoteOp::Put
        };
    }
    RemoteOp::Put
}

type BodyReadFuture = Pin<Box<dyn Future<Output = (HttpBody, SdkResult<Buffer>)> + Send>>;

enum BodyStreamState {
    Idle(HttpBody),
    Reading(BodyReadFuture),
    Done,
}

/// Stream wrapper over a 2xx [`HttpBody`] that delegates chunk reads and
/// `Content-Length` EOF checks to `HttpBody::read`, then strips temporary
/// retryability and URL-bearing provider context from any mid-body error.
struct NonRetryingBodyStream {
    state: Mutex<BodyStreamState>,
}

impl NonRetryingBodyStream {
    fn new(body: HttpBody) -> Self {
        Self { state: Mutex::new(BodyStreamState::Idle(body)) }
    }
}

/// Convert a post-2xx body read failure into a permanent, source-free SDK
/// error. Once 2xx response headers have been accepted, OpenDAL's
/// `RetryReader` must not silently issue a ranged second `GET`, and no
/// `reqwest` or `HttpBody` message/context (which may carry the request URL)
/// may survive.
fn stream_body_failure(error: opendal::Error) -> opendal::Error {
    let kind = error.kind();
    drop(error);
    opendal::Error::new(kind, STREAM_FAILURE_MESSAGE).set_persistent()
}

impl Stream for NonRetryingBodyStream {
    type Item = SdkResult<Buffer>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let state = self.get_mut().state.get_mut().expect("unpoisoned exclusive stream state");
        loop {
            match std::mem::replace(state, BodyStreamState::Done) {
                BodyStreamState::Idle(mut body) => {
                    *state = BodyStreamState::Reading(Box::pin(async move {
                        let chunk = body.read().await;
                        (body, chunk)
                    }));
                }
                BodyStreamState::Reading(mut future) => match future.as_mut().poll(cx) {
                    Poll::Pending => {
                        *state = BodyStreamState::Reading(future);
                        return Poll::Pending;
                    }
                    Poll::Ready((body, Ok(chunk))) if chunk.is_empty() => {
                        drop(body);
                        return Poll::Ready(None);
                    }
                    Poll::Ready((body, Ok(chunk))) => {
                        *state = BodyStreamState::Idle(body);
                        return Poll::Ready(Some(Ok(chunk)));
                    }
                    Poll::Ready((body, Err(error))) => {
                        drop(body);
                        return Poll::Ready(Some(Err(stream_body_failure(error))));
                    }
                },
                BodyStreamState::Done => return Poll::Ready(None),
            }
        }
    }
}

fn non_retrying_success_body(body: HttpBody) -> HttpBody {
    HttpBody::new(NonRetryingBodyStream::new(body), None)
}

/// Exact-request HTTP wrapper: successful response heads pass through with
/// non-retrying body classification, and every observed non-2xx response is
/// classified by the upstream S3 parser.
struct StatusAttributingFetch {
    inner: HttpClient,
}

impl HttpFetch for StatusAttributingFetch {
    async fn fetch(&self, request: Request<Buffer>) -> SdkResult<Response<HttpBody>> {
        let op = request_stage(request.method(), request.uri());
        let response = match self.inner.fetch(request).await {
            Ok(response) => response,
            Err(error) => return Err(network_failure(error, op)),
        };
        if response.status().is_success() {
            return Ok(response.map(non_retrying_success_body));
        }

        let status = response.status().as_u16();
        let (parts, body) = response.into_parts();
        match collect_error_body(body).await {
            Some(buffer) => {
                let parsed = parse_error_response(Response::from_parts(parts, buffer));
                Err(parsed_http_failure(parsed, status, op))
            }
            None => Err(unparsed_http_failure(status, op)),
        }
    }
}

/// HTTP client for the legacy adapter: the SDK's own client behind the
/// exact-response classifier. Nothing else in the operator stack changes.
pub(crate) fn classifying_http_client() -> SdkResult<HttpClient> {
    Ok(HttpClient::with(StatusAttributingFetch { inner: HttpClient::new()? }))
}

/// One classified SDK failure. It keeps the provider's bounded error kind so
/// callers retain their `NotFound`/`AlreadyExists` control flow, plus the
/// privacy-safe typed error for diagnostics.
pub(crate) struct RemoteFailure {
    kind: ErrorKind,
    error: RemoteStoreError,
}

impl RemoteFailure {
    fn classify(error: opendal::Error, fallback_op: RemoteOp) -> Self {
        let kind = error.kind();
        let cause = exact_cause(&error);
        let error = match cause {
            // Exact status, request stage and upstream S3 classification of
            // the response that failed.
            Some(Cause::Http { status, op, kind, temporary }) => {
                RemoteStoreError::http_typed(op, status, kind, temporary)
            }
            Some(Cause::Transport { op, cause }) => RemoteStoreError::transport_typed(op, cause.kind, cause.temporary),
            // The SDK dropped its source or parsed an embedded 200 error:
            // retain only the bounded kind, never an invented status.
            None => RemoteStoreError::sdk(fallback_op, sdk_kind(kind)),
        };
        Self { kind, error }
    }

    pub(crate) fn is_not_found(&self) -> bool {
        self.kind == ErrorKind::NotFound
    }

    /// Conditional-create conflict. Kept separate from every other failure so
    /// the legacy immutable-key policy stays idempotent-verify, not overwrite.
    pub(crate) fn is_conflict(&self) -> bool {
        matches!(self.kind, ErrorKind::AlreadyExists | ErrorKind::ConditionNotMatch)
    }

    pub(crate) fn into_error(self) -> RemoteStoreError {
        self.error
    }
}

/// Run exactly one SDK operation. `Ok` values pass through unchanged; a
/// provider failure is classified from the error instance it was returned
/// with, never from a process- or task-global "last observed status".
pub(crate) async fn observe<T, F>(op: RemoteOp, future: F) -> Result<T, RemoteFailure>
where
    F: IntoFuture<Output = SdkResult<T>>,
{
    future.into_future().await.map_err(|error| RemoteFailure::classify(error, op))
}

/// One body-stream poll. A lazy reader issues its GET while being polled, so
/// an initial non-2xx response keeps its exact HTTP marker. A body that fails
/// after a successful 200 instead carries a finite transport/stream error with
/// no HTTP status; an earlier status is never reused.
pub(crate) async fn observe_body_poll<S>(op: RemoteOp, poll: S) -> Result<Option<Bytes>, BlobError>
where
    S: Future<Output = Result<Option<Bytes>, std::io::Error>>,
{
    match poll.await {
        Ok(Some(chunk)) => Ok(Some(chunk)),
        Ok(None) => Ok(None),
        Err(error) => Err(BlobError::Remote(classify_io_error(op, error))),
    }
}

fn classify_io_error(op: RemoteOp, error: std::io::Error) -> RemoteStoreError {
    match exact_cause(&error) {
        Some(Cause::Http { status, op, kind, temporary }) => RemoteStoreError::http_typed(op, status, kind, temporary),
        Some(Cause::Transport { op, cause }) => RemoteStoreError::transport_typed(op, cause.kind, cause.temporary),
        // Body I/O without one of our markers: keep only the bounded Stream
        // family. No opaque source that might contain a provider URL survives.
        None => RemoteStoreError::sdk(op, RemoteSdkKind::Stream),
    }
}

/// Deadline exhaustion is local to the caller and never retried or invented:
/// it keeps the parent's typed `timeout(op)` classification.
pub(crate) fn deadline_error(op: RemoteOp) -> BlobError {
    BlobError::Remote(RemoteStoreError::timeout(op))
}

/// Close (single PUT or multipart completion) failures stay typed: an exact
/// HTTP marker supplies both the request stage and status, a conditional
/// conflict keeps its `AlreadyExists` control flow, and everything else keeps
/// the bounded SDK family.
pub(crate) fn close_error(failure: RemoteFailure) -> BlobError {
    if failure.is_conflict() { BlobError::AlreadyExists } else { BlobError::Remote(failure.into_error()) }
}

/// Lift a store failure to `anyhow` while keeping the typed cause reachable:
/// `lfs::hydration` and the worker diagnostics downcast to `RemoteStoreError`,
/// so it must stay the outermost error rather than a nested source.
pub(crate) fn object_error(error: BlobError) -> anyhow::Error {
    match error {
        BlobError::Remote(remote) => anyhow::Error::new(remote),
        other => anyhow::Error::new(other),
    }
}

fn sdk_kind(kind: ErrorKind) -> RemoteSdkKind {
    match kind {
        ErrorKind::NotFound => RemoteSdkKind::NotFound,
        ErrorKind::PermissionDenied => RemoteSdkKind::PermissionDenied,
        ErrorKind::RateLimited => RemoteSdkKind::RateLimited,
        ErrorKind::AlreadyExists => RemoteSdkKind::AlreadyExists,
        ErrorKind::ConditionNotMatch => RemoteSdkKind::ConditionNotMatch,
        ErrorKind::RangeNotSatisfied => RemoteSdkKind::RangeNotSatisfied,
        ErrorKind::Unsupported => RemoteSdkKind::Unsupported,
        ErrorKind::ConfigInvalid => RemoteSdkKind::ConfigInvalid,
        _ => RemoteSdkKind::Other,
    }
}

#[cfg(test)]
#[path = "remote_provider_errors_tests.rs"]
mod tests;
