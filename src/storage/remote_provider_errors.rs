//! Typed privacy bridge between the OpenDAL legacy adapter and the ref-store
//! `RemoteStoreError` diagnostics surface.
//!
//! OpenDAL 0.57 does not expose the numeric response status through its public
//! error API: `Error::kind()` is the only observation point, `Display`/`Debug`
//! can carry request URLs, and the error context is private. Parsing that text
//! or inventing a code from an `ErrorKind` is therefore forbidden here.
//!
//! Instead a *passive* [`HttpFetch`] wrapper is installed around the SDK's own
//! HTTP client. It delegates every request unchanged to OpenDAL, so signing,
//! TLS, connection pooling, redirects, retries and multipart stay inside the
//! SDK, and it records only the numeric status of responses the SDK actually
//! received. No URL, header, query, body or credential is read, stored, logged
//! or formatted.
//!
//! Attribution rules (each operation gets its own [`tokio::task_local!`] slot,
//! never a process-global "last status"):
//!
//! * only `4xx`/`5xx` responses are candidates for a failure status, so a later
//!   or concurrent `2xx` can never be reported as the cause of a failure;
//! * two *different* failure statuses in one operation are treated as
//!   unattributable and reported as `None` rather than guessed;
//! * when nothing was observed (transport failure, or an SDK task that does not
//!   inherit the per-operation scope) the failure keeps a bounded
//!   [`RemoteSdkKind`] and `http_status()` stays `None`.
//!
//! The observation scope is opened around each SDK call *and* around each body
//! poll, because a lazily constructed reader issues its first HTTP request only
//! when the stream is first polled.

use std::future::{Future, IntoFuture};
use std::sync::{Arc, Mutex};

// `http` is not a direct dependency of this crate (the root owns `Cargo.toml`)
// and `axum` re-exports the same `http` 1.x crate that `opendal-core` uses, so
// these are the exact request/response types of the `HttpFetch` trait.
use axum::http::{Request, Response};
use bytes::Bytes;
use opendal::Buffer;
use opendal::raw::{HttpBody, HttpClient, HttpFetch};
use opendal::{ErrorKind, Result as SdkResult};

use crate::blob_store::BlobError;

use super::remote_errors::{RemoteOp, RemoteSdkKind, RemoteStoreError};

/// Bounded, attribution-aware record of the traffic one operation generated.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Observed {
    /// First `4xx`/`5xx` status observed by this operation.
    failure_status: Option<u16>,
    /// A second, different failure status was observed: the cause is ambiguous.
    ambiguous: bool,
}

impl Observed {
    fn record_response(&mut self, status: u16) {
        if status < 400 {
            // Successes are never a failure cause; in particular a concurrent
            // or retried `200` must never be reported for a failing request.
            return;
        }
        match self.failure_status {
            None => self.failure_status = Some(status),
            Some(previous) if previous == status => {}
            Some(_) => self.ambiguous = true,
        }
    }

    /// Exact status to report for a failed operation, if it is attributable.
    fn failure_status(self) -> Option<u16> {
        if self.ambiguous { None } else { self.failure_status }
    }
}

#[derive(Default)]
struct ObservedTraffic {
    observed: Mutex<Observed>,
}

impl ObservedTraffic {
    fn record_response(&self, status: u16) {
        if let Ok(mut observed) = self.observed.lock() {
            observed.record_response(status);
        }
    }

    fn snapshot(&self) -> Observed {
        self.observed.lock().map(|observed| *observed).unwrap_or_default()
    }
}

tokio::task_local! {
    static OBSERVED_TRAFFIC: Arc<ObservedTraffic>;
}

/// Passive fetch wrapper: identical delegation, status observation only.
struct StatusObservingFetch {
    inner: HttpClient,
}

impl HttpFetch for StatusObservingFetch {
    async fn fetch(&self, request: Request<Buffer>) -> SdkResult<Response<HttpBody>> {
        let response = match self.inner.fetch(request).await {
            Ok(response) => response,
            // No response exists for this request, so no status may be
            // attributed to it; the classification falls back to the SDK kind.
            Err(error) => return Err(error),
        };
        let status = response.status().as_u16();
        let _ = OBSERVED_TRAFFIC.try_with(|traffic| traffic.record_response(status));
        Ok(response)
    }
}

/// HTTP client for the legacy adapter: the SDK's own client behind the passive
/// observer. Nothing else in the operator stack changes.
pub(crate) fn observing_http_client() -> SdkResult<HttpClient> {
    Ok(HttpClient::with(StatusObservingFetch { inner: HttpClient::new()? }))
}

/// One classified SDK failure. It keeps the provider's bounded error kind so
/// callers retain their `NotFound`/`AlreadyExists` control flow, plus the
/// privacy-safe typed error for diagnostics.
pub(crate) struct RemoteFailure {
    kind: ErrorKind,
    error: RemoteStoreError,
}

impl RemoteFailure {
    fn classify(error: opendal::Error, op: RemoteOp, observed: Observed) -> Self {
        let kind = error.kind();
        let error = match observed.failure_status() {
            // Exact status of a failed response this operation received.
            Some(status) => RemoteStoreError::http(op, status),
            // No attributable response: a bounded SDK family, never a fake code.
            None => RemoteStoreError::sdk(op, sdk_kind(kind)),
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

/// Run exactly one SDK operation inside its own observation scope. `Ok` values
/// pass through unchanged; a provider failure becomes a typed [`RemoteFailure`].
pub(crate) async fn observe<T, F>(op: RemoteOp, future: F) -> Result<T, RemoteFailure>
where
    F: IntoFuture<Output = SdkResult<T>>,
{
    let traffic = Arc::new(ObservedTraffic::default());
    let result = OBSERVED_TRAFFIC.scope(traffic.clone(), future.into_future()).await;
    result.map_err(|error| RemoteFailure::classify(error, op, traffic.snapshot()))
}

/// One body-stream poll inside its own observation scope. The lazy reader issues
/// its HTTP request during this poll, so the scope must wrap the poll itself and
/// not only the reader construction. A body failure has no attributable HTTP
/// status (the head/GET that produced the reader is a different response), so it
/// is classified as the bounded `Stream` family with `http_status() == None`.
pub(crate) async fn observe_body_poll<S>(op: RemoteOp, poll: S) -> Result<Option<Bytes>, BlobError>
where
    S: Future<Output = Result<Option<Bytes>, std::io::Error>>,
{
    let traffic = Arc::new(ObservedTraffic::default());
    match OBSERVED_TRAFFIC.scope(traffic.clone(), poll).await {
        Ok(Some(chunk)) => Ok(Some(chunk)),
        Ok(None) => Ok(None),
        Err(_error) => {
            let observed = traffic.snapshot();
            let error = match observed.failure_status() {
                Some(status) => RemoteStoreError::http(op, status),
                None => RemoteStoreError::sdk(op, RemoteSdkKind::Stream),
            };
            Err(BlobError::Remote(error))
        }
    }
}

/// Deadline exhaustion is local to the caller and never retried or invented:
/// it keeps the parent's typed `timeout(op)` classification.
pub(crate) fn deadline_error(op: RemoteOp) -> BlobError {
    BlobError::Remote(RemoteStoreError::timeout(op))
}

/// Close (multipart completion) failures stay typed: a conditional-create
/// conflict keeps its `AlreadyExists` control flow, everything else keeps the
/// observed status or the bounded SDK family.
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

    #[test]
    fn success_statuses_are_never_a_failure_cause() {
        let mut observed = Observed::default();
        observed.record_response(200);
        observed.record_response(204);
        assert_eq!(observed.failure_status(), None);
    }

    #[test]
    fn a_later_success_cannot_mask_an_observed_failure_status() {
        let mut observed = Observed::default();
        observed.record_response(503);
        // A concurrent or retried subrequest succeeded afterwards.
        observed.record_response(200);
        assert_eq!(observed.failure_status(), Some(503));
    }

    #[test]
    fn two_different_failure_statuses_are_unattributable() {
        let mut observed = Observed::default();
        observed.record_response(429);
        observed.record_response(503);
        assert_eq!(observed.failure_status(), None);
    }

    #[test]
    fn repeated_identical_failure_status_stays_attributable() {
        let mut observed = Observed::default();
        observed.record_response(403);
        observed.record_response(403);
        assert_eq!(observed.failure_status(), Some(403));
    }

    #[test]
    fn a_transport_failure_records_no_status_at_all() {
        // Nothing was observed as a response, so the snapshot stays empty and
        // classification falls back to the bounded SDK kind (`None` status).
        let observed = Observed::default();
        assert_eq!(observed.failure_status(), None);
    }

    #[test]
    fn typed_error_keeps_op_and_never_invents_a_status() {
        let error = RemoteStoreError::sdk(RemoteOp::Get, RemoteSdkKind::Stream);
        assert_eq!(error.op(), RemoteOp::Get);
        assert_eq!(error.http_status(), None);
        assert!(!error.to_string().contains("://"));
    }
}
