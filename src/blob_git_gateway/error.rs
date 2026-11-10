//! Fixed, privacy-safe HTTP refusal vocabulary of the Blob Git gateway.
//!
//! No variant carries provider text, Git argv/stderr, a locator, a token, a
//! path or a SQL message. Every dynamic failure is collapsed into one of these
//! literals so a transport error can never echo a credential or a client pack.
use axum::{
    Json,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};

/// One typed gateway refusal. `Internal` is deliberately opaque.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayError {
    Unauthorized,
    Forbidden(&'static str),
    NotFound,
    BadRequest(&'static str),
    Unsupported(&'static str),
    NotImplemented(&'static str),
    Conflict(&'static str),
    OutcomeUnknown,
    TooLarge,
    Timeout,
    Unavailable(&'static str),
    Internal(&'static str),
}

impl GatewayError {
    pub fn status(self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::BadRequest(_) | Self::Unsupported(_) => StatusCode::BAD_REQUEST,
            Self::NotImplemented(_) => StatusCode::NOT_IMPLEMENTED,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::OutcomeUnknown => StatusCode::SERVICE_UNAVAILABLE,
            Self::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::Timeout => StatusCode::GATEWAY_TIMEOUT,
            Self::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::Unauthorized => "valid credentials required",
            Self::Forbidden(reason)
            | Self::BadRequest(reason)
            | Self::Unsupported(reason)
            | Self::NotImplemented(reason)
            | Self::Conflict(reason)
            | Self::Unavailable(reason)
            | Self::Internal(reason) => reason,
            Self::NotFound => "not found",
            Self::OutcomeUnknown => "publication outcome is unknown; query the operation or inspect refs",
            Self::TooLarge => "request exceeds the configured Git gateway byte limit",
            Self::Timeout => "Git gateway request exceeded its bounded deadline",
        }
    }
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let status = self.status();
        let mut response = (status, Json(serde_json::json!({"error": self.message()}))).into_response();
        response.headers_mut().insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
        if status == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                header::HeaderValue::from_static("Basic realm=\"Rootyard\", charset=\"UTF-8\""),
            );
        }
        response
    }
}

/// Map the shared application error without copying its message.
impl From<crate::Error> for GatewayError {
    fn from(error: crate::Error) -> Self {
        match error.0 {
            StatusCode::UNAUTHORIZED => Self::Unauthorized,
            StatusCode::FORBIDDEN => Self::Forbidden("write permission required"),
            StatusCode::NOT_FOUND => Self::NotFound,
            StatusCode::CONFLICT => Self::Conflict("repository state changed; retry"),
            StatusCode::PAYLOAD_TOO_LARGE => Self::TooLarge,
            StatusCode::REQUEST_TIMEOUT | StatusCode::GATEWAY_TIMEOUT => Self::Timeout,
            StatusCode::SERVICE_UNAVAILABLE => Self::Unavailable("service temporarily unavailable"),
            _ => Self::Internal("Gateway request was refused"),
        }
    }
}

/// Ref-store refusals collapse into the fixed gateway vocabulary. In particular
/// an unprovisioned realm is an explicit unsupported refusal, never a fake
/// commit, and a pending/unknown operation is a queryable unknown outcome rather
/// than a conflict or a Git `ng`.
impl From<crate::ref_store::RefStoreError> for GatewayError {
    fn from(error: crate::ref_store::RefStoreError) -> Self {
        use crate::ref_store::RefStoreError as Ref;
        match error {
            Ref::Timeout => Self::Timeout,
            Ref::RepositoryNotFound => Self::NotFound,
            Ref::Unsupported(reason) => Self::Unsupported(reason),
            // A durable pending row is an unknown outcome. The client must query
            // the same operation id; it must never be reported as a ref result.
            Ref::OperationPending { .. } | Ref::CommitUnknown { .. } => Self::OutcomeUnknown,
            Ref::DigestConflict => Self::Conflict("request identity was already used differently"),
            Ref::IdentityConflict => Self::Conflict("operation identity conflicts with a durable record"),
            Ref::CancellationConflict => Self::Conflict("cancellation tombstone conflicts with this operation"),
            // A cancellation without a decoded terminal is a definite no-effect
            // refusal but not a Git report; the caller resolves it by operation.
            Ref::Cancelled { .. } => Self::Conflict("operation is durably cancelled"),
            Ref::TerminalImmutable => Self::Conflict("operation result is already terminal"),
            Ref::MetadataGateVersionMismatch => Self::Conflict("repository gate changed; retry"),
            Ref::UnknownOperation { .. } => Self::Internal("metadata operation was refused"),
            _ => Self::Internal("metadata operation was refused"),
        }
    }
}

/// Pack-commit refusals; the stable `PackCommitRejectCode` is not leaked to the
/// wire, only the fact that the sealed ledger refused. None of these is rendered
/// as an `ng` by the receive handler.
impl From<crate::ref_store::core::pack_commit::PackCommitError> for GatewayError {
    fn from(error: crate::ref_store::core::pack_commit::PackCommitError) -> Self {
        use crate::ref_store::core::pack_commit::PackCommitError as Pack;
        match error {
            Pack::RefStore(error) => error.into(),
            Pack::Invalid(_) => Self::BadRequest("publication plan is invalid"),
            Pack::Capacity { .. } => Self::TooLarge,
            Pack::Rejected(_) => Self::Conflict("publication was rejected by the core ledger"),
            Pack::ProofUnavailable(_) => Self::Unsupported("native pack verification is unavailable"),
            Pack::CommitUnknown { .. } => Self::OutcomeUnknown,
        }
    }
}
