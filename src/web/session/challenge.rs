//! Protocol-scoped `401` challenges for web session middleware refusals.
use axum::{
    http::{HeaderValue, StatusCode, header},
    response::Response,
};

/// The exact read-alias namespace of the Blob gateway browser UI: the index
/// `GET /web/blob/api/repos` and every read below it.
const BLOB_API_ALIAS: &str = "/web/blob/api/repos";

/// The credential scheme one web-session refusal advertises.
pub(super) const PAGE_CHALLENGE: &str = "Basic realm=\"Rootyard\", charset=\"UTF-8\"";

/// The JSON/API challenge of the Blob gateway aliases, identical to
/// `crate::blob_git_gateway::error::Challenge::Bearer`.
pub(super) const API_CHALLENGE: &str = "Bearer realm=\"Rootyard\"";

/// True only for the Blob gateway read aliases: exactly `/web/blob/api/repos`
/// and its descendants in whole path segments. Every other `/web` path (the
/// login/logout pages, the `/web/blob` page navigation, sibling `/web/*` pages)
/// and every `/git/*` path keeps the page challenge.
pub(super) fn is_blob_api_alias(path: &str) -> bool {
    let Some(rest) = path.strip_prefix(BLOB_API_ALIAS) else {
        return false;
    };
    rest.is_empty() || rest.starts_with('/')
}

/// Choose the challenge of a `401` the session middleware itself answers.
///
/// The API alias namespace advertises the JSON/API `Bearer` scheme, so a
/// cookie-only browser `fetch` that resolves promptly itself (no network
/// delay) can never start the Basic HTTP-auth exchange a browser would
/// otherwise leave pending. Every other path keeps the page `Basic` challenge.
///
/// Only a `401` carrying [`PAGE_CHALLENGE`] is rewritten. Status, body and every
/// other header (cookies and repeated headers included) stay intact.
pub(super) fn session_challenge(mut response: Response, path: &str) -> Response {
    if response.status() == StatusCode::UNAUTHORIZED
        && response.headers().get(header::WWW_AUTHENTICATE).is_some_and(|value| value == PAGE_CHALLENGE)
    {
        let challenge = if is_blob_api_alias(path) { API_CHALLENGE } else { PAGE_CHALLENGE };
        response.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static(challenge));
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Error,
        application::MetadataState,
        web::session::{SESSION_PREFIX, session_parent, validate_session},
    };
    use axum::{
        body::{Body, to_bytes},
        http::{HeaderMap, HeaderValue, StatusCode, header},
        response::{IntoResponse, Response},
    };

    fn challenges(response: &Response) -> Vec<&str> {
        response.headers().get_all(header::WWW_AUTHENTICATE).iter().map(|v| v.to_str().unwrap()).collect()
    }

    fn page_refusal() -> Response {
        Error::unauthorized().into_response()
    }

    #[test]
    fn only_the_blob_api_alias_namespace_is_scoped() {
        for path in [
            "/web/blob/api/repos",
            "/web/blob/api/repos/",
            "/web/blob/api/repos/owner/name",
            "/web/blob/api/repos/owner/name/refs",
            "/web/blob/api/repos/owner/name/tree/abc",
        ] {
            assert!(is_blob_api_alias(path), "{path} is a Blob API read alias");
        }
        for path in [
            "/web/login",
            "/web/logout",
            "/web/blob",
            "/web/blob/",
            "/web/blob/repos/owner/name",
            "/web/app.js",
            "/web/repos",
            "/web/settings/tokens",
            "/web/blob/api/repository",
            "/web/blob/api/repositories",
            "/web/blob/api/reposx",
            "/web/blob/api",
            "/web/blob/api/",
            "/git/owner/name.git/info/refs",
            "/api/repos",
            "",
        ] {
            assert!(!is_blob_api_alias(path), "{path} is not a Blob API read alias");
        }
    }

    #[test]
    fn an_alias_unauthorized_advertises_exactly_the_bearer_challenge() {
        assert_eq!(challenges(&page_refusal()), [PAGE_CHALLENGE], "precondition: the shared refusal is Basic");
        for path in ["/web/blob/api/repos", "/web/blob/api/repos/owner/name/refs"] {
            let response = session_challenge(page_refusal(), path);
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(challenges(&response), [API_CHALLENGE], "{path}");
        }
    }

    #[test]
    fn page_login_and_other_routes_keep_the_basic_challenge() {
        for path in ["/web/login", "/web/logout", "/web/blob", "/web/blob/repos/o/n", "/web/repos", "/git/o/n.git"] {
            let response = session_challenge(page_refusal(), path);
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(challenges(&response), [PAGE_CHALLENGE], "{path}");
        }
    }

    #[test]
    fn a_non_unauthorized_answer_is_unchanged() {
        for status in [StatusCode::OK, StatusCode::FORBIDDEN, StatusCode::NOT_FOUND, StatusCode::SERVICE_UNAVAILABLE] {
            for path in ["/web/blob/api/repos", "/web/blob/api/repos/owner/name", "/web/login", "/web/repos"] {
                let expected: HeaderMap = (status, "body").into_response().headers().clone();
                let response = session_challenge((status, "body").into_response(), path);
                assert_eq!(response.status(), status, "{path}");
                assert_eq!(response.headers(), &expected, "{path}");
            }
        }
    }

    #[test]
    fn the_challenge_rewrite_preserves_status_body_and_other_headers() {
        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        let fixture = || -> Response {
            let mut parts =
                (StatusCode::UNAUTHORIZED, [("x-fixture", "cookie-and-header-holder")]).into_response().into_parts().0;
            parts.headers.insert(header::WWW_AUTHENTICATE, HeaderValue::from_static(PAGE_CHALLENGE));
            parts.headers.insert(header::SET_COOKIE, HeaderValue::from_static("rootyard_session=; Max-Age=0"));
            parts.headers.append(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            parts.headers.append(header::CACHE_CONTROL, HeaderValue::from_static("private"));
            Response::from_parts(parts, Body::from(r#"{"error":"valid credentials required"}"#))
        };
        let original = fixture();
        let response = session_challenge(fixture(), "/web/blob/api/repos/owner/name");
        assert_eq!(challenges(&original), [PAGE_CHALLENGE]);
        assert_eq!(challenges(&response), [API_CHALLENGE]);
        let (mut response, mut original) = (response, original);
        response.headers_mut().remove(header::WWW_AUTHENTICATE);
        original.headers_mut().remove(header::WWW_AUTHENTICATE);
        assert_eq!(response.status(), original.status());
        assert_eq!(response.headers(), original.headers());
        let read = |response: Response| {
            runtime.block_on(async move {
                let (parts, body) = response.into_parts();
                (parts.status, to_bytes(body, usize::MAX).await.unwrap())
            })
        };
        assert_eq!(read(response), read(original));
    }

    #[test]
    fn an_unauthorized_without_the_page_challenge_is_passed_through() {
        let bare = Response::builder().status(StatusCode::UNAUTHORIZED).body(Body::empty()).unwrap();
        let foreign = Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header(header::WWW_AUTHENTICATE, "Negotiate")
            .body(Body::empty())
            .unwrap();
        for response in [bare.into_response(), foreign] {
            let existing: Vec<String> =
                challenges(&response).into_iter().map(|challenge| challenge.to_owned()).collect();
            let after = session_challenge(response, "/web/blob/api/repos");
            let after: Vec<&str> = challenges(&after);
            assert_eq!(after, existing.iter().map(String::as_str).collect::<Vec<_>>());
        }
    }

    #[tokio::test]
    async fn a_validate_session_rejection_is_bearer_challenged_on_alias_reads() {
        let (state, _scratch) = offline_metadata();
        let secret = format!("{SESSION_PREFIX}{}", "zz".repeat(32));
        assert_eq!(session_parent(&secret), None);
        let Err(rejected) = validate_session(&state, &secret, None).await else {
            panic!("a session without a decodable parent id must not validate");
        };
        let (status, challenge) = owned_snapshot(*rejected);
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(challenge.as_deref(), Some(PAGE_CHALLENGE), "precondition: validate_session renders Basic");
        let response = session_challenge(Error::unauthorized().into_response(), "/web/blob/api/repos");
        assert_eq!(response.status(), status);
        assert_eq!(challenges(&response), [API_CHALLENGE]);
        let response = session_challenge(Error::unauthorized().into_response(), "/web/blob");
        assert_eq!(response.status(), status);
        assert_eq!(challenges(&response), [PAGE_CHALLENGE]);
    }

    fn owned_snapshot(response: Response) -> (StatusCode, Option<String>) {
        let (parts, _body) = response.into_parts();
        let challenge = parts.headers.get(header::WWW_AUTHENTICATE).map(|value| value.to_str().unwrap().to_owned());
        (parts.status, challenge)
    }

    fn offline_metadata() -> (MetadataState, tempfile::TempDir) {
        let config: tokio_postgres::Config =
            "host=127.0.0.1 port=1 user=rootyard dbname=rootyard".parse().expect("static connection string");
        let pool = deadpool_postgres::Pool::builder(deadpool_postgres::Manager::new(config, tokio_postgres::NoTls))
            .runtime(deadpool_postgres::Runtime::Tokio1)
            .max_size(1)
            .build()
            .expect("offline pool");
        (MetadataState { pool }, tempfile::tempdir().expect("scratch"))
    }

    #[test]
    fn both_session_short_circuits_use_the_challenge_helper() {
        let source = include_str!("../session.rs");
        let middleware = source
            .split_once("pub async fn middleware(")
            .and_then(|(_, rest)| rest.split_once("\n}\n"))
            .map(|(body, _)| body)
            .expect("the middleware body");
        assert!(middleware.contains("Err(response) => return session_challenge(*response, &path)"));
        assert_eq!(middleware.matches("session_challenge(*response, &path)").count(), 2);
        assert!(middleware.contains("login_redirect(&path, query.as_deref(), &headers)"));
        assert!(!middleware.contains("WWW_AUTHENTICATE"), "the middleware never writes the header itself");
    }
}
