use axum::{
    body::to_bytes,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};

use super::{Challenge, GatewayError, with_challenge};
use crate::{blob_git_gateway::snapshot, ref_store::RefStoreError};

fn challenge(response: &Response) -> Option<&str> {
    response.headers().get(header::WWW_AUTHENTICATE).map(|value| value.to_str().expect("challenge is text"))
}

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
    let uninitialized = "repository has no initialized core gate";
    assert_eq!(GatewayError::from(RefStoreError::Unsupported(uninitialized)).status(), StatusCode::BAD_REQUEST);
    assert_opaque_server_error(
        snapshot::materialize_error(RefStoreError::Unsupported(uninitialized)),
        StatusCode::INTERNAL_SERVER_ERROR,
        r#"{"error":"verified pack snapshot could not be materialized"}"#,
    )
    .await;

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

#[test]
fn an_existing_challenge_is_never_rewritten_or_joined() {
    let values = |response: &Response| -> Vec<_> {
        response.headers().get_all(header::WWW_AUTHENTICATE).iter().cloned().collect()
    };
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
    let sign_in = crate::Error::unauthorized().into_response();
    assert_eq!(challenge(&sign_in), Some("Basic realm=\"Rootyard\", charset=\"UTF-8\""));
}

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
