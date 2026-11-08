//! Typed privacy bridge between the OpenDAL adapter and the ref-store
//! `RemoteStoreError` diagnostics surface.
//!
//! OpenDAL 0.57 does not expose a numeric response status through its public
//! error API. Parsing `Display`/`Debug` text or inventing a code from an
//! `ErrorKind` is therefore forbidden here.
//!
//! Instead the SDK's own [`HttpFetch`] client is wrapped at the exact request
//! boundary. Signing, TLS, connection pooling, redirects, retries, multipart
//! and response parsing remain inside the SDK. For every observed non-2xx
//! response the wrapper returns an `opendal::Error` whose private source is a
//! [`HttpFailure`] carrying only the numeric status and one finite [`RemoteOp`]
//! derived from the request method and fixed query keys. Successful responses
//! pass through untouched, so an HTTP 200 carrying an embedded provider error
//! is still parsed by the SDK and reported with no HTTP status.
//!
//! Attribution is therefore per request: a retry that ends in a transport
//! failure, or a later 200 decode failure, can never report status from an
//! earlier 503. Concurrent multipart requests each carry their own marker.
//! No URL, path, query value, header, credential or body is stored, logged or
//! formatted. Error classification walks only the bounded `std::error::Error`
//! source chain and private marker types; it never parses source text.

use std::error::Error as StdError;
use std::fmt;
use std::future::{Future, IntoFuture};

// `http` is not a direct dependency of this crate (the root owns `Cargo.toml`)
// and `axum` re-exports the same `http` 1.x crate that `opendal-core` uses, so
// these are the exact request/response types of the `HttpFetch` trait.
use axum::http::{Method, Request, Response, Uri};
use bytes::Bytes;
use opendal::raw::{HttpBody, HttpClient, HttpFetch};
use opendal::{Buffer, ErrorKind, Result as SdkResult};

use crate::blob_store::BlobError;

use super::remote_errors::{RemoteOp, RemoteSdkKind, RemoteStoreError};

/// Bounded source-chain walk. OpenDAL nests at most an SDK error plus one
/// transport/body error; a finite limit also stops a hostile cyclic chain.
const MAX_CAUSE_DEPTH: usize = 8;
const HTTP_FAILURE_MESSAGE: &str = "remote object store request failed";
const TRANSPORT_FAILURE_MESSAGE: &str = "remote object store transport failed";

/// Private marker attached to the exact failing HTTP response. It holds only
/// a numeric status and a finite operation label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct HttpFailure {
    status: u16,
    op: RemoteOp,
}

impl fmt::Display for HttpFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Fixed text only; status/op are bounded values, never request data.
        write!(formatter, "http status {} at {}", self.status, self.op.as_str())
    }
}

impl StdError for HttpFailure {}

/// Private marker for a request that produced no HTTP response at all. The
/// original SDK error is retained as an opaque source so the provider error
/// chain survives; `Display`/`Debug` never format it.
struct NetworkFailure(Box<dyn StdError + Send + Sync>);

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
        Some(self.0.as_ref())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cause {
    Http { status: u16, op: RemoteOp },
    Transport,
}

/// Walk the bounded source chain for private markers only.
fn exact_cause(error: &(dyn StdError + 'static)) -> Option<Cause> {
    let mut next = error.source();
    for _ in 0..MAX_CAUSE_DEPTH {
        let source = next?;
        if let Some(http) = source.downcast_ref::<HttpFailure>() {
            return Some(Cause::Http { status: http.status, op: http.op });
        }
        if source.downcast_ref::<NetworkFailure>().is_some() {
            return Some(Cause::Transport);
        }
        next = source.source();
    }
    None
}

/// Map an observed HTTP status to the SDK's bounded control-flow kind. This
/// preserves the same `NotFound`/precondition classifications the S3 service
/// would derive, without parsing a provider body or retaining its text.
fn http_kind(status: u16) -> (ErrorKind, bool) {
    match status {
        403 => (ErrorKind::PermissionDenied, false),
        404 => (ErrorKind::NotFound, false),
        304 | 412 => (ErrorKind::ConditionNotMatch, false),
        // Conditional create conflict: keep the SDK's retryable conflict
        // classification so the caller's idempotent-verify path still runs.
        409 => (ErrorKind::ConditionNotMatch, true),
        499 => (ErrorKind::Unexpected, true),
        500 | 502 | 503 | 504 => (ErrorKind::Unexpected, true),
        429 => (ErrorKind::RateLimited, true),
        _ => (ErrorKind::Unexpected, false),
    }
}

fn http_failure(status: u16, op: RemoteOp) -> opendal::Error {
    let (kind, temporary) = http_kind(status);
    let mut error = opendal::Error::new(kind, HTTP_FAILURE_MESSAGE).set_source(HttpFailure { status, op });
    if temporary {
        error = error.set_temporary();
    }
    error
}

fn network_failure(error: opendal::Error) -> opendal::Error {
    let kind = error.kind();
    let temporary = error.is_temporary();
    let persistent = error.is_persistent();
    let mut wrapped = opendal::Error::new(kind, TRANSPORT_FAILURE_MESSAGE).set_source(NetworkFailure(Box::new(error)));
    if temporary {
        wrapped = wrapped.set_temporary();
    } else if persistent {
        wrapped = wrapped.set_persistent();
    }
    wrapped
}

/// True for an SDK-level body/transport failure that did not pass through our
/// request marker (for example the response body fails after a 200 head).
fn is_sdk_transport(error: &opendal::Error) -> bool {
    error.kind() == ErrorKind::Unexpected && error.source().is_some()
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

/// Exact-request HTTP wrapper: successful responses pass through, every
/// observed non-2xx response becomes an SDK error with a private marker.
struct StatusAttributingFetch {
    inner: HttpClient,
}

impl HttpFetch for StatusAttributingFetch {
    async fn fetch(&self, request: Request<Buffer>) -> SdkResult<Response<HttpBody>> {
        let op = request_stage(request.method(), request.uri());
        let response = match self.inner.fetch(request).await {
            Ok(response) => response,
            Err(error) => return Err(network_failure(error)),
        };
        if response.status().is_success() {
            return Ok(response);
        }
        Err(http_failure(response.status().as_u16(), op))
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
        let sdk_transport = cause.is_none() && is_sdk_transport(&error);
        let error = match cause {
            // Exact status and request stage of the response that failed.
            Some(Cause::Http { status, op }) => RemoteStoreError::http(op, status),
            Some(Cause::Transport) => RemoteStoreError::transport(fallback_op, Box::new(error)),
            // A body/transport failure after a successful head response: no
            // HTTP status may be attributed to it.
            None if sdk_transport => RemoteStoreError::transport(fallback_op, Box::new(error)),
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
/// after a successful 200 instead carries a transport/stream error with no
/// HTTP status; an earlier status is never reused.
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
        Some(Cause::Http { status, op }) => RemoteStoreError::http(op, status),
        Some(Cause::Transport) => RemoteStoreError::transport(op, Box::new(error)),
        None if error.source().is_some() => RemoteStoreError::transport(op, Box::new(error)),
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
mod tests {
    use super::*;

    fn classify(error: opendal::Error) -> RemoteStoreError {
        RemoteFailure::classify(error, RemoteOp::Put).into_error()
    }

    #[test]
    fn exact_failed_response_keeps_status_and_request_stage() {
        let part = classify(http_failure(503, RemoteOp::MultipartPart));
        assert_eq!(part.http_status(), Some(503));
        assert_eq!(part.op(), RemoteOp::MultipartPart);

        let complete = classify(http_failure(412, RemoteOp::MultipartComplete));
        assert_eq!(complete.http_status(), Some(412));
        assert_eq!(complete.op(), RemoteOp::MultipartComplete);
    }

    #[test]
    fn observed_status_preserves_control_flow_and_temporary_flags() {
        assert_eq!(http_failure(404, RemoteOp::Get).kind(), ErrorKind::NotFound);

        let precondition = http_failure(412, RemoteOp::MultipartComplete);
        assert_eq!(precondition.kind(), ErrorKind::ConditionNotMatch);
        assert!(!precondition.is_temporary());

        let conflict = http_failure(409, RemoteOp::MultipartComplete);
        assert_eq!(conflict.kind(), ErrorKind::ConditionNotMatch);
        assert!(conflict.is_temporary());

        let unavailable = http_failure(503, RemoteOp::MultipartPart);
        assert_eq!(unavailable.kind(), ErrorKind::Unexpected);
        assert!(unavailable.is_temporary());

        let limited = http_failure(429, RemoteOp::Get);
        assert_eq!(limited.kind(), ErrorKind::RateLimited);
        assert!(limited.is_temporary());
    }

    #[test]
    fn a_prior_503_is_not_reused_for_a_later_transport_failure() {
        let stale = classify(http_failure(503, RemoteOp::Get));
        assert_eq!(stale.http_status(), Some(503));

        let transport = opendal::Error::new(ErrorKind::Unexpected, "request failed")
            .set_source(NetworkFailure(Box::new(opendal::Error::new(ErrorKind::Unexpected, "connection reset"))));
        let later = classify(transport);
        assert_eq!(later.http_status(), None);
        assert_eq!(later.op(), RemoteOp::Put);
        assert!(later.to_string().contains("transport failed"));
    }

    #[test]
    fn a_prior_503_is_not_reused_for_a_200_embedded_provider_error() {
        let stale = classify(http_failure(503, RemoteOp::Get));
        assert_eq!(stale.http_status(), Some(503));

        // The SDK parsed an error document carried by HTTP 200: no source and
        // no numeric response status are available.
        let embedded = classify(opendal::Error::new(ErrorKind::Unexpected, "provider error document"));
        assert_eq!(embedded.http_status(), None);
        assert!(embedded.to_string().contains("provider kind other"));
    }

    #[test]
    fn concurrent_requests_keep_their_own_status_and_stage() {
        // Deliberately classify in reverse completion order: each marker is
        // bound to its own request, so no operation-global state can leak.
        let complete = classify(http_failure(429, RemoteOp::MultipartComplete));
        let part = classify(http_failure(403, RemoteOp::MultipartPart));
        assert_eq!((complete.http_status(), complete.op()), (Some(429), RemoteOp::MultipartComplete));
        assert_eq!((part.http_status(), part.op()), (Some(403), RemoteOp::MultipartPart));
    }

    #[test]
    fn initial_body_get_failure_keeps_the_exact_http_tag() {
        let error = std::io::Error::new(std::io::ErrorKind::Interrupted, http_failure(503, RemoteOp::Get));
        let typed = classify_io_error(RemoteOp::Get, error);
        assert_eq!(typed.http_status(), Some(503));
        assert_eq!(typed.op(), RemoteOp::Get);
    }

    #[test]
    fn mid_body_failure_after_200_has_no_http_status() {
        let inner = opendal::Error::new(ErrorKind::Unexpected, "read body")
            .set_source(std::io::Error::other("connection reset"));
        let error = std::io::Error::new(std::io::ErrorKind::Interrupted, inner);
        let typed = classify_io_error(RemoteOp::Get, error);
        assert_eq!(typed.http_status(), None);
        assert!(typed.to_string().contains("transport failed"));
    }

    #[test]
    fn dropped_sdk_source_uses_a_bounded_unknown_kind() {
        let typed = classify(opendal::Error::new(ErrorKind::Unexpected, "no source"));
        assert_eq!(typed.http_status(), None);
        assert!(typed.to_string().contains("provider kind other"));
    }

    #[test]
    fn request_stage_uses_method_and_fixed_query_keys_only() {
        let uri = |raw: &'static str| raw.parse::<Uri>().expect("test uri");
        assert_eq!(request_stage(&Method::GET, &uri("https://example.invalid/secret/path")), RemoteOp::Get);
        assert_eq!(request_stage(&Method::HEAD, &uri("https://example.invalid/secret/path")), RemoteOp::Head);
        assert_eq!(request_stage(&Method::DELETE, &uri("https://example.invalid/secret/path")), RemoteOp::Delete);
        assert_eq!(
            request_stage(&Method::DELETE, &uri("https://example.invalid/secret/path?uploadId=private-value")),
            RemoteOp::MultipartAbort
        );
        assert_eq!(
            request_stage(&Method::POST, &uri("https://example.invalid/secret/path?uploads")),
            RemoteOp::MultipartInitiate
        );
        assert_eq!(
            request_stage(&Method::POST, &uri("https://example.invalid/secret/path?uploadId=private-value")),
            RemoteOp::MultipartComplete
        );
        assert_eq!(
            request_stage(
                &Method::PUT,
                &uri("https://example.invalid/secret/path?partNumber=1&uploadId=private-value")
            ),
            RemoteOp::MultipartPart
        );
        assert_eq!(request_stage(&Method::PUT, &uri("https://example.invalid/secret/path")), RemoteOp::Put);
    }

    #[test]
    fn safe_diagnostics_never_format_a_source_url_or_path() {
        let source = opendal::Error::new(ErrorKind::Unexpected, "request failed")
            .with_context("url", "https://user:secret@example.invalid/private/object?token=secret")
            .set_source(std::io::Error::other("connection reset at https://example.invalid/private/object"));
        let typed = classify(source);
        let display = typed.to_string();
        let debug = format!("{typed:?}");
        for rendered in [display, debug] {
            assert!(!rendered.contains("://"));
            assert!(!rendered.contains("secret"));
            assert!(!rendered.contains("/private/object"));
            assert!(!rendered.contains("token"));
        }
    }
}
