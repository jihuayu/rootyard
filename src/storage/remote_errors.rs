//! Typed object-store failures with fixed privacy-safe diagnostic fields.
use reqwest::Method;

/// Fixed operation stages for remote object-store failures. Only this bounded
/// discriminant and a numeric status are retained for diagnosis; URLs, object
/// keys, query strings, headers, credentials and payloads are never captured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteOp {
    Get,
    Head,
    Put,
    Delete,
    MultipartInitiate,
    MultipartPart,
    MultipartComplete,
    MultipartAbort,
}

impl RemoteOp {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Head => "head",
            Self::Put => "put",
            Self::Delete => "delete",
            Self::MultipartInitiate => "multipart_initiate",
            Self::MultipartPart => "multipart_part",
            Self::MultipartComplete => "multipart_complete",
            Self::MultipartAbort => "multipart_abort",
        }
    }

    pub(super) fn method(self) -> Method {
        match self {
            Self::Get => Method::GET,
            Self::Head => Method::HEAD,
            Self::Put | Self::MultipartPart => Method::PUT,
            Self::Delete | Self::MultipartAbort => Method::DELETE,
            Self::MultipartInitiate | Self::MultipartComplete => Method::POST,
        }
    }
}

/// Bounded provider-SDK failure labels. OpenDAL 0.57 exposes only
/// [`opendal::ErrorKind`] publicly, so when no HTTP response was observed the
/// kind is retained as a fixed label instead of inventing a status code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteSdkKind {
    NotFound,
    PermissionDenied,
    RateLimited,
    AlreadyExists,
    ConditionNotMatch,
    RangeNotSatisfied,
    /// A provider byte-stream failure (for example a truncated body). At that
    /// point no HTTP response exists to report a status for.
    Stream,
    Unsupported,
    ConfigInvalid,
    Other,
}

impl RemoteSdkKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "not_found",
            Self::PermissionDenied => "permission_denied",
            Self::RateLimited => "rate_limited",
            Self::AlreadyExists => "already_exists",
            Self::ConditionNotMatch => "condition_not_match",
            Self::RangeNotSatisfied => "range_not_satisfied",
            Self::Stream => "stream",
            Self::Unsupported => "unsupported",
            Self::ConfigInvalid => "config_invalid",
            Self::Other => "other",
        }
    }
}

enum RemoteFailure {
    /// A response the S3 client classified as a failed HTTP status.
    Http(u16),
    /// A transport failure. The `reqwest::Error` is retained as the error
    /// source so callers can inspect its safe status/kind, but it is never
    /// formatted into a message or a log event.
    Transport(reqwest::Error),
    Timeout,
    /// No numeric status was observed for this failure; only the bounded SDK
    /// family is known. It is never rendered as a pseudo HTTP code.
    Sdk(RemoteSdkKind),
    /// Defensive fallback for a retry loop that recorded no cause. The loop
    /// cannot normally reach this state because timeouts return immediately.
    NoRecordedCause,
}

/// Finite, privacy-safe object-store failure. `Display` is a fixed template
/// that never formats the transport source, URL, headers, query or body.
pub struct RemoteStoreError {
    op: RemoteOp,
    failure: RemoteFailure,
}

impl RemoteStoreError {
    pub(crate) fn http(op: RemoteOp, status: u16) -> Self {
        Self { op, failure: RemoteFailure::Http(status) }
    }

    pub(crate) fn transport(op: RemoteOp, error: reqwest::Error) -> Self {
        Self { op, failure: RemoteFailure::Transport(error) }
    }

    pub(crate) fn timeout(op: RemoteOp) -> Self {
        Self { op, failure: RemoteFailure::Timeout }
    }

    pub(crate) fn sdk(op: RemoteOp, kind: RemoteSdkKind) -> Self {
        Self { op, failure: RemoteFailure::Sdk(kind) }
    }

    pub(super) fn no_recorded_cause(op: RemoteOp) -> Self {
        Self { op, failure: RemoteFailure::NoRecordedCause }
    }

    pub(crate) fn op(&self) -> RemoteOp {
        self.op
    }

    /// Safe numeric HTTP status, if the failure was a completed response.
    pub(crate) fn http_status(&self) -> Option<u16> {
        match &self.failure {
            RemoteFailure::Http(status) => Some(*status),
            _ => None,
        }
    }
}

impl std::fmt::Display for RemoteStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Fixed safe text only: op is a bounded enum and http_status a u16.
        match &self.failure {
            RemoteFailure::Http(status) => {
                write!(formatter, "remote object store {} failed with status {status}", self.op.as_str())
            }
            RemoteFailure::Transport(_) => {
                write!(formatter, "remote object store {} transport failed", self.op.as_str())
            }
            RemoteFailure::Timeout => write!(formatter, "remote object store {} timed out", self.op.as_str()),
            RemoteFailure::Sdk(kind) => write!(
                formatter,
                "remote object store {} failed with provider kind {}",
                self.op.as_str(),
                kind.as_str()
            ),
            RemoteFailure::NoRecordedCause => {
                write!(formatter, "remote object store {} failed without a recorded cause", self.op.as_str())
            }
        }
    }
}

impl std::fmt::Debug for RemoteStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Debug must stay as safe as Display; never derive over reqwest::Error.
        std::fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for RemoteStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.failure {
            RemoteFailure::Transport(error) => Some(error),
            _ => None,
        }
    }
}
