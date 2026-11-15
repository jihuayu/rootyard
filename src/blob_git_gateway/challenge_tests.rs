//! Route-boundary tests for protocol-scoped `401` challenges (#174).
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use axum::{
    http::{StatusCode, header},
    response::IntoResponse,
};
use base64::Engine;
use deadpool_postgres::{Manager, Runtime};

use super::{
    BlobGitConfig, BlobGitState, GatewayError,
    error::{Challenge, with_challenge},
    router,
};
use crate::blob_store::{budget::ResourceLimits, test_support::store};

const BEARER: &str = "Bearer realm=\"Rootyard\"";
const BASIC: &str = "Basic realm=\"Rootyard\", charset=\"UTF-8\"";

fn offline_state() -> (Arc<BlobGitState>, tempfile::TempDir) {
    let config: tokio_postgres::Config =
        "host=127.0.0.1 port=1 user=rootyard dbname=rootyard".parse().expect("static connection string");
    let pool = deadpool_postgres::Pool::builder(Manager::new(config, tokio_postgres::NoTls))
        .runtime(Runtime::Tokio1)
        .max_size(1)
        .build()
        .expect("offline pool");
    let (blob, _) = store(ResourceLimits::new(2, 2, 1 << 20).expect("test budget"));
    let scratch = tempfile::tempdir().expect("scratch root");
    let state = Arc::new(
        BlobGitState::new(BlobGitConfig {
            pool,
            store: blob,
            git_binary: PathBuf::from("/bin/true"),
            scratch_root: scratch.path().to_path_buf(),
            max_concurrent_requests: 1,
            max_request_bytes: 64 * 1024,
            max_response_bytes: 64 * 1024,
            max_inflight_bytes: 64 * 1024,
            operation_deadline: Duration::from_secs(30),
            native_limits: Default::default(),
        })
        .expect("gateway state"),
    );
    (state, scratch)
}

struct Gateway {
    address: SocketAddr,
    server: tokio::task::JoinHandle<Result<(), std::io::Error>>,
}

impl Gateway {
    async fn start(state: &Arc<BlobGitState>) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("loopback listener");
        let address = listener.local_addr().expect("listener address");
        let service = router(state.clone()).into_make_service();
        let server = tokio::spawn(async move { axum::serve(listener, service).await });
        Self { address, server }
    }

    async fn send(
        &self,
        method: &str,
        target: &str,
        headers: &[(&str, &str)],
        body: &'static [u8],
    ) -> (StatusCode, Vec<String>, Option<String>, bool) {
        let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
        let mut request = match method {
            "GET" => client.get(format!("http://{}{target}", self.address)),
            "POST" => client.post(format!("http://{}{target}", self.address)),
            "DELETE" => client.delete(format!("http://{}{target}", self.address)),
            other => panic!("unsupported test method {other}"),
        };
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = request.body(body).send().await.expect("loopback request");
        let status = StatusCode::from_u16(response.status().as_u16()).expect("valid status");
        let challenges = response
            .headers()
            .get_all(header::WWW_AUTHENTICATE)
            .iter()
            .map(|value| value.to_str().unwrap().to_owned())
            .collect();
        let cache =
            response.headers().get(header::CACHE_CONTROL).and_then(|value| value.to_str().ok()).map(str::to_owned);
        let session = response.headers().contains_key("x-rootyard-session");
        (status, challenges, cache, session)
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn rpc_content_type(uri: &str) -> &'static str {
    if uri.ends_with("/git-upload-pack") {
        "application/x-git-upload-pack-request"
    } else {
        "application/x-git-receive-pack-request"
    }
}

#[tokio::test]
async fn owner107_historical_routes_advertise_bearer_without_a_session() {
    let (state, _scratch) = offline_state();
    let gateway = Gateway::start(&state).await;
    let snapshot = "11111111-1111-4111-8111-111111111111";
    let oid = "1".repeat(40);
    let routes: Vec<(&str, String, Vec<(&str, &str)>, &'static [u8])> = vec![
        (
            "POST",
            "/api/repos/owner/name/operations/11111111-1111-4111-8111-111111111111/cancel".to_owned(),
            vec![],
            b"",
        ),
        (
            "POST",
            "/api/repos/owner/name/snapshots".to_owned(),
            vec![("content-type", "application/json")],
            br#"{"idempotency_key":"create-unauth","lease_seconds":60}"#,
        ),
        ("GET", format!("/api/repos/owner/name/snapshots/{snapshot}"), vec![], b""),
        (
            "POST",
            format!("/api/repos/owner/name/snapshots/{snapshot}/renew"),
            vec![("content-type", "application/json")],
            br#"{"idempotency_key":"renew-unauth","expected_generation":1,"lease_seconds":60}"#,
        ),
        (
            "DELETE",
            format!("/api/repos/owner/name/snapshots/{snapshot}"),
            vec![("content-type", "application/json")],
            br#"{"idempotency_key":"release-unauth","expected_generation":1}"#,
        ),
        ("GET", format!("/api/repos/owner/name/snapshots/{snapshot}/tree"), vec![], b""),
        ("GET", format!("/api/repos/owner/name/snapshots/{snapshot}/blob/{oid}"), vec![], b""),
    ];
    for (method, target, headers, body) in routes {
        let (status, challenges, cache, session) = gateway.send(method, &target, &headers, body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {target} was not a tokenless denial");
        assert_eq!(challenges, [BEARER], "{method} {target} must advertise only the API Bearer challenge");
        assert_eq!(cache.as_deref(), Some("no-store"), "{method} {target} must stay no-store");
        assert!(!session, "{method} {target} must not issue a session header on denial");
    }
}

#[tokio::test]
async fn top_level_api_and_its_aliases_advertise_bearer() {
    let (state, _scratch) = offline_state();
    let gateway = Gateway::start(&state).await;
    let rejected: [&[(&str, &str)]; 3] = [
        &[],
        &[("authorization", "Bearer not-a-credential")],
        &[("authorization", "Basic b3duZXI6bm90LWEtY3JlZGVudGlhbA==")],
    ];
    let routes = [
        ("GET", "/api/repos"),
        ("GET", "/api/repos/owner/name"),
        ("GET", "/api/repos/owner/name/refs"),
        ("GET", "/api/repos/owner/name/commits"),
        ("GET", "/api/repos/owner/name/commits/0000000000000000000000000000000000000000"),
        ("GET", "/api/repos/owner/name/tree"),
        ("GET", "/api/repos/owner/name/blob?path=README.md"),
        ("GET", "/api/repos/owner/name/compare?base=HEAD&head=HEAD"),
        ("GET", "/api/repos/owner/name/operations/00000000-0000-0000-0000-000000000001"),
        ("POST", "/api/repos"),
        ("GET", "/web/blob/api/repos"),
        ("GET", "/web/blob/api/repos/owner/name"),
        ("GET", "/web/blob/api/repos/owner/name/refs"),
        ("GET", "/web/blob/api/repos/owner/name/commits"),
        ("GET", "/web/blob/api/repos/owner/name/commits/0000000000000000000000000000000000000000"),
        ("GET", "/web/blob/api/repos/owner/name/tree"),
        ("GET", "/web/blob/api/repos/owner/name/blob?path=README.md"),
    ];
    for (method, uri) in routes {
        for headers in rejected {
            let (headers, body): (Vec<(&str, &str)>, &'static [u8]) = if (method, uri) == ("POST", "/api/repos") {
                let mut headers = headers.to_vec();
                headers.push(("content-type", "application/json"));
                (headers, br#"{"name":"name"}"#)
            } else {
                (headers.to_vec(), b"")
            };
            let (status, challenges, _, _) = gateway.send(method, uri, &headers, body).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {uri} was not an unauthenticated denial");
            assert_eq!(challenges, [BEARER], "{method} {uri} must not enter a browser Basic auth exchange");
        }
    }
}

#[tokio::test]
async fn non_session_cookie_is_ignored_like_no_cookie() {
    let (state, _scratch) = offline_state();
    let gateway = Gateway::start(&state).await;
    let cookie = format!("rootyard_session=ryt_{}", "zz".repeat(32));
    for uri in ["/web/blob/api/repos", "/web/blob/api/repos/owner/name", "/web/blob/api/repos/owner/name/refs"] {
        let (status, challenges, _, _) = gateway.send("GET", uri, &[("cookie", cookie.as_str())], &[]).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "GET {uri} was not the gateway's denial");
        assert_eq!(challenges, [BEARER], "GET {uri} must not start a browser Basic auth exchange");
    }
    let (status, challenges, _, _) = gateway.send("GET", "/web/login", &[("cookie", cookie.as_str())], &[]).await;
    assert_eq!(status, StatusCode::OK, "the sign-in page renders without a session");
    assert!(challenges.is_empty(), "the sign-in page must not challenge an anonymous render");
    let (status, challenges, _, _) =
        gateway.send("GET", "/git/owner/name.git/info/refs?service=git-upload-pack", &[("cookie", &cookie)], &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(challenges, [BASIC]);
}

#[tokio::test]
async fn unsupported_merge_refuses_without_a_challenge() {
    let (state, _scratch) = offline_state();
    let gateway = Gateway::start(&state).await;
    let rejected: [&[(&str, &str)]; 3] = [
        &[],
        &[("authorization", "Bearer not-a-credential")],
        &[("authorization", "Basic b3duZXI6bm90LWEtY3JlZGVudGlhbA==")],
    ];
    let uri = "/api/repos/owner/name/merges";
    for headers in rejected {
        let (status, challenges, _, _) = gateway.send("POST", uri, headers, b"").await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "POST {uri} must stay an explicit not-implemented refusal");
        assert!(challenges.is_empty(), "POST {uri} must not challenge: it never authenticates");
    }
}

#[tokio::test]
async fn smart_http_denials_advertise_basic() {
    let (state, _scratch) = offline_state();
    let gateway = Gateway::start(&state).await;
    let routes = [
        ("GET", "/git/owner/name.git/info/refs?service=git-upload-pack"),
        ("GET", "/git/owner/name.git/info/refs?service=git-receive-pack"),
        ("POST", "/git/owner/name.git/git-upload-pack"),
        ("POST", "/git/owner/name.git/git-receive-pack"),
    ];
    let rejected: [&[(&str, &str)]; 2] = [&[], &[("authorization", "Bearer not-a-credential")]];
    for (method, uri) in routes {
        for headers in rejected {
            let mut all = headers.to_vec();
            if method == "POST" {
                all.push(("content-type", rpc_content_type(uri)));
            }
            let (status, challenges, _, _) = gateway.send(method, uri, &all, &[]).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {uri} was not an unauthenticated denial");
            assert_eq!(challenges, [BASIC], "{method} {uri} must keep the Git Basic challenge");
        }
    }
}

#[tokio::test]
async fn syntax_accepted_credentials_reach_the_offline_authority() {
    let (state, _scratch) = offline_state();
    let gateway = Gateway::start(&state).await;
    let token = format!("ryt_{}", "ab".repeat(32));
    let basic = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("owner:{token}")));
    let bearer = format!("Bearer {token}");
    for uri in ["/api/repos", "/web/blob/api/repos"] {
        for credential in [basic.as_str(), bearer.as_str()] {
            let (status, challenges, _, _) = gateway.send("GET", uri, &[("authorization", credential)], &[]).await;
            assert_ne!(status, StatusCode::UNAUTHORIZED, "GET {uri} rejected the syntactically valid credential");
            assert!(challenges.is_empty(), "GET {uri} must not challenge a syntax-accepted credential");
            assert_ne!(status, StatusCode::OK, "GET {uri} cannot succeed while the authority is offline");
        }
    }
}

#[test]
fn shared_mappings_use_the_route_challenge() {
    let unauthorized: GatewayError = crate::Error::unauthorized().into();
    assert_eq!(unauthorized, GatewayError::Unauthorized);
    let value = |response: &axum::response::Response| -> Vec<String> {
        response
            .headers()
            .get_all(header::WWW_AUTHENTICATE)
            .iter()
            .map(|value| value.to_str().expect("challenge is text").to_owned())
            .collect()
    };
    let bare = GatewayError::Unauthorized.into_response();
    assert_eq!(bare.status(), StatusCode::UNAUTHORIZED);
    assert!(value(&bare).is_empty());
    assert_eq!(value(&unauthorized.api()), [BEARER.to_owned()]);
    assert_eq!(value(&unauthorized.git()), [BASIC.to_owned()]);
    assert_eq!(
        value(&with_challenge(GatewayError::Unauthorized.into_response(), Challenge::Bearer)),
        [BEARER.to_owned()]
    );
    let existing = crate::Error::unauthorized().into_response();
    assert_eq!(existing.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(value(&existing), [BASIC.to_owned()]);
    let kept = with_challenge(existing, Challenge::Bearer);
    assert_eq!(kept.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(value(&kept), [BASIC.to_owned()]);
    let not_found = with_challenge(GatewayError::NotFound.into_response(), Challenge::Bearer);
    assert_eq!(not_found.status(), StatusCode::NOT_FOUND);
    assert!(value(&not_found).is_empty());
}
