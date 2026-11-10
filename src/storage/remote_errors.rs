//! Typed object-store failures with fixed privacy-safe diagnostic fields.
//!
//! Only bounded operation labels and a numeric HTTP status are ever retained.
//! A provider error source is kept as an opaque boxed `std::error::Error` so
//! the OpenDAL error chain survives without this crate depending on the
//! SDK's private `reqwest` version. `Display`/`Debug` never format a source.

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
    /// A response the SDK classified as a failed HTTP status.
    #[cfg(test)]
    Http(u16),
    /// A failed HTTP response plus the bounded classification derived by the
    /// upstream S3 parser. No provider body, resource path or URL survives.
    HttpTyped {
        status: u16,
        kind: RemoteSdkKind,
        temporary: bool,
    },
    /// An opaque transport/SDK error source. It is retained so the complete
    /// OpenDAL error chain survives, but it is never formatted into a message
    /// or a log event. Legacy `remote_objects` callers keep this variant.
    #[cfg(test)]
    Transport(Box<dyn std::error::Error + Send + Sync>),
    /// A finite, source-free transport classification. It retains only the
    /// bounded SDK kind and temporary flag: no URL, provider body or nested
    /// error object is stored, so `source()` stays empty.
    TransportTyped {
        kind: RemoteSdkKind,
        temporary: bool,
    },
    Timeout,
    /// No numeric status was observed for this failure; only the bounded SDK
    /// family is known. It is never rendered as a pseudo HTTP code.
    Sdk(RemoteSdkKind),
}

/// Finite, privacy-safe object-store failure. `Display` is a fixed template
/// that never formats the transport source, URL, headers, query or body.
pub struct RemoteStoreError {
    op: RemoteOp,
    failure: RemoteFailure,
}

impl RemoteStoreError {
    #[cfg(test)]
    pub(crate) fn http(op: RemoteOp, status: u16) -> Self {
        Self { op, failure: RemoteFailure::Http(status) }
    }

    pub(crate) fn http_typed(op: RemoteOp, status: u16, kind: RemoteSdkKind, temporary: bool) -> Self {
        Self { op, failure: RemoteFailure::HttpTyped { status, kind, temporary } }
    }

    #[cfg(test)]
    pub(crate) fn transport(op: RemoteOp, error: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Self { op, failure: RemoteFailure::Transport(error) }
    }

    /// Source-free transport classification for SDK failures that may carry a
    /// private provider URL. Only finite values survive.
    pub(crate) fn transport_typed(op: RemoteOp, kind: RemoteSdkKind, temporary: bool) -> Self {
        Self { op, failure: RemoteFailure::TransportTyped { kind, temporary } }
    }

    pub(crate) fn timeout(op: RemoteOp) -> Self {
        Self { op, failure: RemoteFailure::Timeout }
    }

    pub(crate) fn sdk(op: RemoteOp, kind: RemoteSdkKind) -> Self {
        Self { op, failure: RemoteFailure::Sdk(kind) }
    }

    pub(crate) fn op(&self) -> RemoteOp {
        self.op
    }

    /// Safe numeric HTTP status, if the failure was a completed response.
    pub(crate) fn http_status(&self) -> Option<u16> {
        match &self.failure {
            #[cfg(test)]
            RemoteFailure::Http(status) => Some(*status),
            RemoteFailure::HttpTyped { status, .. } => Some(*status),
            _ => None,
        }
    }
}

impl std::fmt::Display for RemoteStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Fixed safe text only: op is a bounded enum and http_status a u16.
        match &self.failure {
            #[cfg(test)]
            RemoteFailure::Http(status) => {
                write!(formatter, "remote object store {} failed with status {status}", self.op.as_str())
            }
            RemoteFailure::HttpTyped { status, kind, temporary } => write!(
                formatter,
                "remote object store {} failed with status {status} provider kind {} {}",
                self.op.as_str(),
                kind.as_str(),
                if *temporary { "temporary" } else { "permanent" }
            ),
            #[cfg(test)]
            RemoteFailure::Transport(_) => {
                write!(formatter, "remote object store {} transport failed", self.op.as_str())
            }
            RemoteFailure::TransportTyped { kind, temporary } => write!(
                formatter,
                "remote object store {} transport failed provider kind {} {}",
                self.op.as_str(),
                kind.as_str(),
                if *temporary { "temporary" } else { "permanent" }
            ),
            RemoteFailure::Timeout => write!(formatter, "remote object store {} timed out", self.op.as_str()),
            RemoteFailure::Sdk(kind) => write!(
                formatter,
                "remote object store {} failed with provider kind {}",
                self.op.as_str(),
                kind.as_str()
            ),
        }
    }
}

impl std::fmt::Debug for RemoteStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Debug must stay as safe as Display; never derive over the source.
        std::fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for RemoteStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.failure {
            #[cfg(test)]
            RemoteFailure::Transport(error) => Some(error.as_ref()),
            // Typed transport causes are finite values, not nested errors.
            _ => None,
        }
    }
}
