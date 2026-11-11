//! Fixed, privacy-safe HTTP refusal vocabulary of the Blob Git gateway.
//!
//! No variant carries provider text, Git argv/stderr, a locator, a token, a
//! path or a SQL message. Every dynamic failure is collapsed into one of these
//! literals so a transport error can never echo a credential or a client pack.
//!
//! A `401` carries no challenge on its own. The challenge names the credential
//! scheme of the route that refused, so it is rendered explicitly by each
//! handler ([`Challenge::Bearer`] for every JSON/API answer, [`Challenge::Basic`]
//! for Smart HTTP); rendering an error alone never advertises either.
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

/// The credential scheme one protocol advertises on its `401`.
///
/// The variant is chosen by the route protocol, never by the failure: the same
/// [`GatewayError::Unauthorized`] is a Relay refusal on the JSON/API path and a
/// Smart HTTP refusal on `/git`, and only the latter may ask the client for
/// Basic credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Challenge {
    /// The standard Smart HTTP Git challenge; a native Git client retries with
    /// the Basic credential it was configured with.
    Basic,
    /// The JSON/API challenge. API tokens are preemptively sent as
    /// `Authorization: Bearer`, so a Basic challenge (which a browser `fetch`
    /// answers with an interactive auth prompt) is never sent here.
    Bearer,
}

impl Challenge {
    pub fn value(self) -> &'static str {
        match self {
            Self::Basic => "Basic realm=\"Rootyard\", charset=\"UTF-8\"",
            Self::Bearer => "Bearer realm=\"Rootyard\"",
        }
    }
}

/// Give `response` the `challenge` of its protocol when, and only when, it is a
/// `401` that advertises no scheme yet.
///
/// The refusal comes from a gateway handler that renders no challenge, so a
/// bare `401` is this route's own denial. A `401` that already names a scheme
/// belongs to another authority (for example the shared sign-in helper) and is
/// never rewritten or joined. Status, body and every other header are the
/// response's own.
pub(super) fn with_challenge(mut response: Response, challenge: Challenge) -> Response {
    if response.status() == StatusCode::UNAUTHORIZED && !response.headers().contains_key(header::WWW_AUTHENTICATE) {
        response.headers_mut().insert(header::WWW_AUTHENTICATE, header::HeaderValue::from_static(challenge.value()));
    }
    response
}

/// Render one handler failure with the challenge its protocol advertises.
fn challenged(error: GatewayError, challenge: Challenge) -> Response {
    with_challenge(error.into_response(), challenge)
}

impl GatewayError {
    /// The JSON/API refusal of every `/api` handler and `/web/blob/api` alias.
    pub(super) fn api(self) -> Response {
        challenged(self, Challenge::Bearer)
    }

    /// The Smart HTTP refusal of `info/refs`, `git-upload-pack` and
    /// `git-receive-pack`.
    pub(super) fn git(self) -> Response {
        challenged(self, Challenge::Basic)
    }
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let status = self.status();
        let mut response = (status, Json(serde_json::json!({"error": self.message()}))).into_response();
        response.headers_mut().insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn challenge(response: &Response) -> Option<&str> {
        response.headers().get(header::WWW_AUTHENTICATE).map(|value| value.to_str().expect("challenge is text"))
    }

    /// Rendering an unauthorized error by itself never guesses a scheme; the
    /// handler of the route applies exactly one (`api` / `git`).
    #[test]
    fn an_unauthorized_error_alone_carries_no_challenge() {
        let response = GatewayError::Unauthorized.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(challenge(&response), None);
    }

    #[test]
    fn each_protocol_renders_its_own_challenge_scheme() {
        let api = GatewayError::Unauthorized.api();
        assert_eq!(
            challenge(&api),
            Some("Bearer realm=\"Rootyard\""),
            "the JSON/API 401 must never start a browser Basic auth prompt"
        );
        let smart = GatewayError::Unauthorized.git();
        assert_eq!(
            challenge(&smart),
            Some("Basic realm=\"Rootyard\", charset=\"UTF-8\""),
            "Smart HTTP keeps the standard Git Basic challenge"
        );
    }

    /// A `401` that already names a scheme is another authority's answer (for
    /// example the shared sign-in refusal): its challenge, every repeated value
    /// and their order included, is kept exactly; nothing is rewritten or joined.
    #[test]
    fn an_existing_challenge_is_never_rewritten_or_joined() {
        let values = |response: &Response| -> Vec<_> {
            response.headers().get_all(header::WWW_AUTHENTICATE).iter().cloned().collect()
        };
        // A fresh handler refusal carrying another authority's challenge, as
        // rendered; `Response<Body>` is not cloneable, so each assertion builds
        // its own fixture.
        let existing = || {
            let mut existing = GatewayError::Unauthorized.into_response();
            existing
                .headers_mut()
                .append(header::WWW_AUTHENTICATE, header::HeaderValue::from_static("Bearer realm=\"Rootyard\""));
            existing
        };
        for challenge in [Challenge::Basic, Challenge::Bearer] {
            let before = existing();
            let expected = values(&before);
            assert_eq!(expected.len(), 1, "precondition: one existing challenge");
            let rendered = with_challenge(before, challenge);
            assert_eq!(rendered.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(values(&rendered), expected, "an existing challenge is preserved and never joined");
        }
        // The shared sign-in refusal keeps its own Basic challenge.
        let sign_in = crate::Error::unauthorized().into_response();
        assert_eq!(challenge(&sign_in), Some("Basic realm=\"Rootyard\", charset=\"UTF-8\""));
    }

    /// The challenge changes the header only: status, content type and the
    /// fixed refusal text are the same on both protocols.
    #[test]
    fn the_challenge_does_not_change_status_or_body() {
        let plain = GatewayError::Unauthorized.into_response();
        let api = GatewayError::Unauthorized.api();
        let smart = GatewayError::Unauthorized.git();
        assert_eq!(api.status(), plain.status());
        assert_eq!(smart.status(), plain.status());
        let content_type = plain.headers().get(header::CONTENT_TYPE);
        assert_eq!(content_type.and_then(|value| value.to_str().ok()), Some("application/json"));
        for response in [&api, &smart] {
            assert_eq!(response.headers().get(header::CONTENT_TYPE), content_type);
            assert_eq!(
                response.headers().get(header::CACHE_CONTROL).map(|value| value.to_str().expect("text")),
                Some("no-store")
            );
        }
        assert_eq!(GatewayError::Unauthorized.message(), "valid credentials required");
    }

    /// A non-unauthorized refusal is never challenged, whichever scheme the
    /// route protocol would have applied to a `401`.
    #[test]
    fn only_unauthorized_refusals_are_challenged() {
        for error in [
            GatewayError::Forbidden("write permission required"),
            GatewayError::NotFound,
            GatewayError::BadRequest("invalid request"),
            GatewayError::Internal("Gateway request was refused"),
        ] {
            for response in [error.api(), error.git()] {
                assert_eq!(response.status(), error.status());
                assert_ne!(response.status(), StatusCode::UNAUTHORIZED);
                assert_eq!(response.headers().get(header::WWW_AUTHENTICATE), None);
            }
        }
    }
}
