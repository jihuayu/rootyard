//! Fixed, privacy-safe HTTP refusal vocabulary of the Blob Git gateway.
//!
//! No variant carries provider text, Git argv/stderr, a locator, a token, a
//! path or a SQL message. Every dynamic failure is collapsed into one of these
//! literals so a transport error can never echo a credential or a client pack.
//!
//! A `401` carries no challenge when rendered. The challenge names the
//! credential scheme of the route protocol that refused, so the gateway-owned
//! `/api/repos` route boundary adds [`Challenge::Bearer`] and the Smart HTTP
//! boundary adds [`Challenge::Basic`]; rendering an error alone never advertises
//! either. The merged shared `/api/tokens` and `/api/sessions` routes do not use
//! this vocabulary and keep `crate::Error`'s pre-existing Basic challenge.
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
/// [`GatewayError::Unauthorized`] is a JSON/API refusal on `/api` and a Smart
/// HTTP refusal on `/git`, and only the latter may ask the client for Basic
/// credentials.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Challenge {
    /// The standard Smart HTTP Git challenge; a native Git client retries with
    /// the Basic credential it was configured with.
    Basic,
    /// The gateway-owned `/api/repos` challenge. API tokens are preemptively
    /// sent as `Authorization: Bearer`, so a Basic challenge (which a browser
    /// `fetch` answers with an interactive auth prompt) is never sent here. The
    /// separately merged token/session management routes are outside this
    /// vocabulary and retain their application-level Basic challenge.
    Bearer,
}

impl Challenge {
    const fn value(self) -> &'static str {
        match self {
            Self::Basic => "Basic realm=\"Rootyard\", charset=\"UTF-8\"",
            Self::Bearer => "Bearer realm=\"Rootyard\"",
        }
    }
}

/// Give `response` the `challenge` of its protocol when, and only when, it is a
/// `401` that advertises no scheme yet.
///
/// The gateway handlers render no challenge, so a bare `401` is this route's
/// own denial. A `401` that already names a scheme belongs to another authority
/// (for example the shared sign-in helper) and is never rewritten or joined.
/// Status, body and every other header are the response's own.
pub(super) fn with_challenge(mut response: Response, challenge: Challenge) -> Response {
    if response.status() == StatusCode::UNAUTHORIZED && !response.headers().contains_key(header::WWW_AUTHENTICATE) {
        response.headers_mut().insert(header::WWW_AUTHENTICATE, header::HeaderValue::from_static(challenge.value()));
    }
    response
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
            // Post-capture pack materialization refusals are never a client
            // verdict. A missing/unreadable/corrupted registered artifact is a
            // transient 503, and unusable materialization metadata is an opaque
            // 500. An unprovisioned/`metadata_only` repository keeps the
            // explicit `400 Unsupported` below.
            Ref::Unsupported("native materialized read verification is unavailable")
            | Ref::Unsupported("materialized read PostgreSQL pool is unavailable") => {
                Self::Unavailable("verified pack snapshot is unavailable")
            }
            Ref::Unsupported("materialized read metadata is not valid")
            | Ref::Unsupported("unknown materialized pack id") => {
                Self::Internal("verified pack snapshot could not be materialized")
            }
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
            // A registered artifact that cannot be re-verified is a transient
            // server-side failure, never a client bad request.
            Pack::ProofUnavailable(_) => Self::Unavailable("native pack verification is unavailable"),
            Pack::CommitUnknown { .. } => Self::OutcomeUnknown,
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::{
        body::to_bytes,
        http::{HeaderMap, StatusCode, header},
        response::IntoResponse,
    };

    use super::{Challenge, GatewayError, with_challenge};
    use crate::{blob_git_gateway::snapshot, ref_store::RefStoreError};

    async fn render(error: GatewayError) -> (StatusCode, HeaderMap, String) {
        let response = error.into_response();
        let status = response.status();
        let headers = response.headers().clone();
        let body = to_bytes(response.into_body(), 8 * 1024).await.expect("gateway body");
        (status, headers, String::from_utf8(body.to_vec()).expect("gateway body is UTF-8"))
    }

    async fn assert_opaque_server_error(error: GatewayError, expected: StatusCode, expected_body: &str) {
        let (status, headers, body) = render(error).await;
        assert_eq!(status, expected);
        assert!(status.is_server_error(), "a failed materialization must never be a client verdict");
        assert_eq!(body, expected_body);
        assert_eq!(headers.get(header::CACHE_CONTROL).and_then(|value| value.to_str().ok()), Some("no-store"));
        assert!(headers.get("x-rootyard-session").is_none(), "a refused materialization must not issue a session");
        assert!(!body.contains("s3://") && !body.contains("secret-key"), "provider details leaked: {body}");
    }

    #[tokio::test]
    async fn missing_or_unreadable_pack_proof_is_an_opaque_service_unavailable() {
        for reason in
            ["native materialized read verification is unavailable", "materialized read PostgreSQL pool is unavailable"]
        {
            let direct = GatewayError::from(RefStoreError::Unsupported(reason));
            assert_eq!(direct.status(), StatusCode::SERVICE_UNAVAILABLE, "{reason}");
            let boundary = snapshot::materialize_error(RefStoreError::Unsupported(reason));
            assert_eq!(boundary.status(), StatusCode::SERVICE_UNAVAILABLE, "{reason}");
            assert_opaque_server_error(
                boundary,
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"verified pack snapshot is unavailable"}"#,
            )
            .await;
        }
    }

    #[tokio::test]
    async fn post_capture_materializer_refusals_are_never_bad_requests() {
        for reason in [
            "materialized read metadata is not valid",
            "unknown materialized pack id",
            "materialized view exceeds its workspace bound",
            "native materialized read verification is unavailable",
        ] {
            let mapped = snapshot::materialize_error(RefStoreError::Unsupported(reason));
            assert!(mapped.status().is_server_error(), "{reason} mapped to {}", mapped.status());
        }
        for reason in ["materialized read metadata is not valid", "unknown materialized pack id"] {
            assert_opaque_server_error(
                snapshot::materialize_error(RefStoreError::Unsupported(reason)),
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"verified pack snapshot could not be materialized"}"#,
            )
            .await;
        }
        // The ref-view capture keeps the explicit 400 for an uninitialized core
        // gate (the production literal in `serving_read_sql.rs`); the
        // post-capture boundary still fails closed with 500 if such a refusal
        // ever reached it.
        let uninitialized = "repository has no initialized core gate";
        assert_eq!(GatewayError::from(RefStoreError::Unsupported(uninitialized)).status(), StatusCode::BAD_REQUEST);
        assert_opaque_server_error(
            snapshot::materialize_error(RefStoreError::Unsupported(uninitialized)),
            StatusCode::INTERNAL_SERVER_ERROR,
            r#"{"error":"verified pack snapshot could not be materialized"}"#,
        )
        .await;

        // A post-capture lookup can still observe either durable refusal.
        // Neither may leak as a 404/409 after the refs were already sealed.
        let missing = RefStoreError::RepositoryNotFound;
        assert_eq!(GatewayError::from(missing.clone()).status(), StatusCode::NOT_FOUND);
        assert_opaque_server_error(
            snapshot::materialize_error(missing),
            StatusCode::INTERNAL_SERVER_ERROR,
            r#"{"error":"verified pack snapshot could not be materialized"}"#,
        )
        .await;
        let moved = RefStoreError::MetadataGateVersionMismatch;
        assert_eq!(GatewayError::from(moved.clone()).status(), StatusCode::CONFLICT);
        assert_opaque_server_error(
            snapshot::materialize_error(moved),
            StatusCode::INTERNAL_SERVER_ERROR,
            r#"{"error":"verified pack snapshot could not be materialized"}"#,
        )
        .await;
    }

    #[tokio::test]
    async fn database_errors_do_not_leak_provider_details() {
        let error = RefStoreError::Database("s3://bucket/secret-key".into());
        assert_opaque_server_error(
            snapshot::materialize_error(error.clone()),
            StatusCode::INTERNAL_SERVER_ERROR,
            r#"{"error":"metadata operation was refused"}"#,
        )
        .await;
        assert_eq!(GatewayError::from(error).status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn an_unauthorized_refusal_renders_no_implicit_challenge() {
        let (status, headers, body) = render(GatewayError::Unauthorized).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(headers.get(header::WWW_AUTHENTICATE), None);
        assert_eq!(headers.get(header::CACHE_CONTROL).and_then(|value| value.to_str().ok()), Some("no-store"));
        assert_eq!(body, r#"{"error":"valid credentials required"}"#);
    }

    #[tokio::test]
    async fn the_route_boundary_fills_only_a_bare_unauthorized_response() {
        for (challenge, expected) in [
            (Challenge::Bearer, "Bearer realm=\"Rootyard\""),
            (Challenge::Basic, "Basic realm=\"Rootyard\", charset=\"UTF-8\""),
        ] {
            let response = with_challenge(GatewayError::Unauthorized.into_response(), challenge);
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(
                response.headers().get(header::WWW_AUTHENTICATE).and_then(|value| value.to_str().ok()),
                Some(expected)
            );
        }

        let mut existing = GatewayError::Unauthorized.into_response();
        existing.headers_mut().append(header::WWW_AUTHENTICATE, "Negotiate".parse().expect("static challenge"));
        let response = with_challenge(existing, Challenge::Bearer);
        let values = response
            .headers()
            .get_all(header::WWW_AUTHENTICATE)
            .iter()
            .map(|value| value.to_str().expect("challenge is text"))
            .collect::<Vec<_>>();
        assert_eq!(values, ["Negotiate"], "a foreign challenge is never rewritten or joined");

        let response =
            with_challenge(GatewayError::Forbidden("write permission required").into_response(), Challenge::Basic);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(response.headers().get(header::WWW_AUTHENTICATE), None);
    }
}
