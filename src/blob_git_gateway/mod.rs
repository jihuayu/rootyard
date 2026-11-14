//! Blob-only Git gateway (#144/#109): a real Smart-HTTP vertical over the
//! PostgreSQL RefStore core and protected OpenDAL Blob bytes.
//!
//! What this module owns:
//!
//! * a small create/list/get JSON API, where creation goes through the shared
//!   `ref_store::serving` provision authority (never legacy Pando/GitFS);
//! * `GET .../info/refs?service=git-upload-pack|git-receive-pack`;
//! * `POST .../git-upload-pack` (bounded native streaming);
//! * `POST .../git-receive-pack` (quarantine spool -> real native ingestion ->
//!   A3 protected Blob upload -> A4 registration -> decision-gated
//!   prepare/select/verify/commit -> a real `report-status` from the durable
//!   terminal).
//!
//! What it deliberately does not own: a permanent bare repository, a legacy
//! data-directory authority, an LFS media service or a merge producer.
//! Those routes refuse explicitly (`501`) instead of
//! pretending success.
//!
//! Local bare Git exists only as a per-request computed view. Durable refs live
//! in the core and durable bytes in Blob, so the RAII deletion of a compute view
//! can never lose an already acknowledged ref or byte.
//!
//! An unauthenticated request is challenged per protocol (#174): every JSON/API
//! route in the `/api/repos` group advertises `Bearer realm="Rootyard"`, while
//! the Smart HTTP `/git` group keeps the Git
//! `Basic realm="Rootyard", charset="UTF-8"` challenge. The challenge adds no
//! cookie, session or browser-navigation behavior to either group.
mod api;
mod browse;
mod config;
mod error;
mod history;
mod metadata;
mod native;
mod operation;
mod process_guard;
mod protocol;
mod publish;
mod read_session;
mod receive;
pub(crate) mod repo_session;
mod resource;
mod serving;
mod session;
mod smart_http;
mod snapshot;
mod state;

#[cfg(test)]
mod session_http_acceptance;

use std::sync::Arc;

use axum::{
    Router,
    extract::Request,
    middleware::{self, Next},
    response::Response,
    routing::{any, get, post},
};

pub use config::{BlobGitConfig, BlobGitConfigError, BlobGitLimits, BlobGitNativeLimits};
pub use error::GatewayError;
pub use repo_session::SessionTokens;
pub use state::BlobGitState;

use error::{Challenge, with_challenge};

/// Mount the Blob Git gateway. The caller owns the listener and the real Blob
/// store; no `AppState`, legacy `Storage` authority or permanent bare repo is
/// consulted.
///
/// Token/session routes are merged here from the shared token module. They see
/// only the PostgreSQL pool (`MetadataState` via `FromRef<Arc<BlobGitState>>`);
/// the real token/session service and its token-scoped authorization are reused
/// unchanged. The broad request deadline below covers their handler awaits too.
pub fn router(state: Arc<BlobGitState>) -> Router {
    let api = Router::new()
        .route("/api/repos", post(api::create_repo).get(api::list_repos))
        .route("/api/repos/{owner}/{name}", get(api::get_repo))
        .route("/api/repos/{owner}/{name}/operations/{operation}", get(api::get_operation))
        .route("/api/repos/{owner}/{name}/merges", post(api::unsupported_merge))
        .route("/api/repos/{owner}/{name}/tree", get(browse::tree))
        .route("/api/repos/{owner}/{name}/tree/{oid}", get(browse::tree_by_oid))
        .route("/api/repos/{owner}/{name}/blob", get(browse::blob))
        .route("/api/repos/{owner}/{name}/blob/{oid}", get(browse::blob_by_oid))
        .route("/api/repos/{owner}/{name}/refs", get(history::refs))
        .route("/api/repos/{owner}/{name}/commits", get(history::commits))
        .route("/api/repos/{owner}/{name}/commits/{oid}", get(history::commit))
        .route("/api/repos/{owner}/{name}/compare", get(history::compare))
        .route_layer(middleware::from_fn(api_challenge));
    let git = Router::new()
        .route("/git/{owner}/{name}/info/refs", get(smart_http::info_refs))
        .route("/git/{owner}/{name}/git-upload-pack", post(smart_http::upload_pack))
        .route("/git/{owner}/{name}/git-receive-pack", post(receive::receive_pack))
        .route("/git/{owner}/{name}/info/lfs/{*rest}", any(api::unsupported_lfs))
        .route_layer(middleware::from_fn(git_challenge));
    Router::new()
        .route("/health/live", get(|| async { "ok" }))
        .route("/health/ready", get(metadata_ready))
        .merge(api)
        .merge(git)
        .merge(crate::token_management::routes())
        .layer(middleware::from_fn_with_state(state.clone(), request_deadline))
        .with_state(state)
}

/// JSON/API route boundary: a bare `401` from any handler in this group asks
/// for a Bearer token. A browser `fetch` must never enter the Basic auth prompt
/// of the Git challenge; authority and member hiding are unchanged.
async fn api_challenge(request: Request, next: Next) -> Response {
    with_challenge(next.run(request).await, Challenge::Bearer)
}

/// Smart HTTP route boundary: `info/refs`, `upload-pack` and `receive-pack`
/// keep the standard Git Basic challenge, so real Git clients retry exactly as
/// before. The LFS refusal in this group is a `501` and is never challenged.
async fn git_challenge(request: Request, next: Next) -> Response {
    with_challenge(next.run(request).await, Challenge::Basic)
}

// One deadline starts before authentication and capacity admission. Every local
// stage reads that same task-scoped value; streaming producers receive it by value.
async fn request_deadline(
    axum::extract::State(state): axum::extract::State<Arc<BlobGitState>>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let deadline = state.deadline();
    let operation = if request.method() == axum::http::Method::POST
        && request.uri().path().starts_with("/git/")
        && request.uri().path().ends_with("/git-receive-pack")
    {
        match session::operation_id(request.headers(), request.uri()) {
            Ok(id) => {
                let value = match axum::http::HeaderValue::from_str(&id.to_string()) {
                    Ok(value) => value,
                    Err(_) => return GatewayError::BadRequest("invalid operation identifier").into_response(),
                };
                request.headers_mut().insert("x-rootyard-operation", value.clone());
                Some(value)
            }
            Err(error) => return error.into_response(),
        }
    } else {
        None
    };
    let mut response =
        match tokio::time::timeout_at(deadline, state::REQUEST_DEADLINE.scope(deadline, next.run(request))).await {
            Ok(response) => response,
            Err(_) => GatewayError::Timeout.into_response(),
        };
    if let Some(operation) = operation {
        response.headers_mut().insert("x-rootyard-operation", operation);
    }
    response
}

// Metadata readiness only: Blob availability/closure is verified on actual
// operations. This endpoint makes no bucket integrity or durability claim.
async fn metadata_ready(
    axum::extract::State(state): axum::extract::State<Arc<BlobGitState>>,
) -> Result<&'static str, GatewayError> {
    if !process_guard::healthy() {
        return Err(GatewayError::Unavailable("native process cleanup requires service restart"));
    }
    let deadline = state.deadline().min(tokio::time::Instant::now() + std::time::Duration::from_secs(2));
    tokio::time::timeout_at(deadline, async {
        state
            .pooled(deadline)
            .await?
            .simple_query("SELECT 1")
            .await
            .map_err(|_| GatewayError::Unavailable("metadata is unavailable"))?;
        Ok("ready")
    })
    .await
    .map_err(|_| GatewayError::Timeout)?
}

/// Route-boundary regression for the `401` challenge (#174).
///
/// Each case starts the real [`router`] on an ephemeral loopback listener and
/// drives it with an ordinary HTTP client, so route selection, the protocol
/// challenge layers and handlers are all exercised as deployed. Authentication
/// is the only live dependency: the pool points at a closed loopback port, and
/// every request below is answered by the credential parser before PostgreSQL,
/// Blob or native Git is needed.
#[cfg(test)]
mod challenge_tests {
    use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

    use axum::http::{HeaderMap, StatusCode, header};

    use super::{BlobGitConfig, BlobGitState, router};
    use crate::blob_store::{budget::ResourceLimits, test_support::store};

    const BEARER: &str = "Bearer realm=\"Rootyard\"";
    const BASIC: &str = "Basic realm=\"Rootyard\", charset=\"UTF-8\"";
    const UNAUTHORIZED_BODY: &str = r#"{"error":"valid credentials required"}"#;

    #[derive(Clone, Copy)]
    struct Route {
        method: &'static str,
        target: &'static str,
        content_type: Option<&'static str>,
        body: &'static [u8],
    }

    const API_ROUTES: [Route; 10] = [
        Route { method: "GET", target: "/api/repos", content_type: None, body: b"" },
        Route {
            method: "POST",
            target: "/api/repos",
            content_type: Some("application/json"),
            body: br#"{"name":"repo","object_format":"sha1"}"#,
        },
        Route { method: "GET", target: "/api/repos/owner/name", content_type: None, body: b"" },
        Route { method: "GET", target: "/api/repos/owner/name/refs", content_type: None, body: b"" },
        Route { method: "GET", target: "/api/repos/owner/name/tree", content_type: None, body: b"" },
        Route { method: "GET", target: "/api/repos/owner/name/blob?path=README.md", content_type: None, body: b"" },
        Route { method: "GET", target: "/api/repos/owner/name/commits", content_type: None, body: b"" },
        Route {
            method: "GET",
            target: "/api/repos/owner/name/compare?base=HEAD&head=HEAD",
            content_type: None,
            body: b"",
        },
        Route {
            method: "GET",
            target: "/api/repos/owner/name/operations/00000000-0000-0000-0000-000000000001",
            content_type: None,
            body: b"",
        },
        Route { method: "GET", target: "/api/repos/owner/name/tree/HEAD", content_type: None, body: b"" },
    ];

    const GIT_ROUTES: [Route; 4] = [
        Route {
            method: "GET",
            target: "/git/owner/name.git/info/refs?service=git-upload-pack",
            content_type: None,
            body: b"",
        },
        Route {
            method: "GET",
            target: "/git/owner/name.git/info/refs?service=git-receive-pack",
            content_type: None,
            body: b"",
        },
        Route {
            method: "POST",
            target: "/git/owner/name.git/git-upload-pack",
            content_type: Some("application/x-git-upload-pack-request"),
            body: b"",
        },
        Route {
            method: "POST",
            target: "/git/owner/name.git/git-receive-pack",
            content_type: Some("application/x-git-receive-pack-request"),
            body: b"",
        },
    ];

    /// An immutable gateway state whose pool points at a closed loopback port.
    fn offline_state() -> (Arc<BlobGitState>, tempfile::TempDir) {
        let config: tokio_postgres::Config =
            "host=127.0.0.1 port=1 user=rootyard dbname=rootyard".parse().expect("static connection string");
        let pool = deadpool_postgres::Pool::builder(deadpool_postgres::Manager::new(config, tokio_postgres::NoTls))
            .runtime(deadpool_postgres::Runtime::Tokio1)
            .max_size(1)
            .build()
            .expect("offline pool");
        // The `cfg(test)` memory store; only its backend identity is consulted,
        // and only after the request authenticated.
        let (blob, _) = store(ResourceLimits::new(2, 2, 1 << 20).expect("test budget"));
        // The scratch root must outlive every request served by this state.
        let scratch = tempfile::tempdir().expect("scratch root");
        let state = BlobGitState::new(BlobGitConfig {
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
        .expect("gateway state");
        (Arc::new(state), scratch)
    }

    /// The real router served over an ephemeral loopback listener. Dropping it
    /// aborts the serving task.
    struct Gateway {
        address: SocketAddr,
        server: tokio::task::JoinHandle<Result<(), std::io::Error>>,
    }

    struct Reply {
        status: StatusCode,
        challenges: Vec<String>,
        set_cookie: Vec<String>,
        session: Vec<String>,
        location: Option<String>,
        cache_control: Option<String>,
        body: String,
    }

    impl Gateway {
        async fn start(state: &Arc<BlobGitState>) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("loopback listener");
            let address = listener.local_addr().expect("listener address");
            let app = router(state.clone());
            let server = tokio::spawn(async move { axum::serve(listener, app).await });
            Self { address, server }
        }

        async fn send(&self, route: Route, headers: &[(&str, &str)]) -> Reply {
            let client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(5))
                .build()
                .expect("loopback client");
            let url = format!("http://{}{}", self.address, route.target);
            let mut request = match route.method {
                "GET" => client.get(url),
                "POST" => client.post(url),
                method => panic!("unsupported test method {method}"),
            };
            if let Some(content_type) = route.content_type {
                request = request.header("content-type", content_type);
            }
            for (name, value) in headers {
                request = request.header(*name, *value);
            }
            let response = request.body(route.body).send().await.expect("loopback request");
            let status = StatusCode::from_u16(response.status().as_u16()).expect("valid response status");
            let challenges = header_values(response.headers(), "www-authenticate");
            let set_cookie = header_values(response.headers(), "set-cookie");
            let mut session = header_values(response.headers(), "x-rootyard-session");
            session.extend(header_values(response.headers(), "x-rootyard-session-revision"));
            let location = response
                .headers()
                .get(header::LOCATION)
                .map(|value| value.to_str().expect("location is text").to_owned());
            let cache_control = response
                .headers()
                .get(header::CACHE_CONTROL)
                .map(|value| value.to_str().expect("cache control is text").to_owned());
            let body = response.text().await.expect("loopback body");
            Reply { status, challenges, set_cookie, session, location, cache_control, body }
        }
    }

    impl Drop for Gateway {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    fn header_values(headers: &HeaderMap, name: &'static str) -> Vec<String> {
        headers.get_all(name).iter().map(|value| value.to_str().expect("response header is text").to_owned()).collect()
    }

    fn assert_refused(reply: &Reply, route: Route, challenge: &str) {
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{} {} was not refused", route.method, route.target);
        assert_eq!(
            reply.challenges,
            [challenge],
            "{} {} advertised the wrong protocol challenge",
            route.method,
            route.target
        );
        assert_eq!(reply.body, UNAUTHORIZED_BODY, "{} {} changed the fixed refusal body", route.method, route.target);
        assert_eq!(reply.cache_control.as_deref(), Some("no-store"));
        assert!(reply.set_cookie.is_empty(), "{} {} set a cookie", route.method, route.target);
        assert!(reply.session.is_empty(), "{} {} issued a repository session", route.method, route.target);
        assert!(reply.location.is_none(), "{} {} redirected a browser", route.method, route.target);
    }

    #[tokio::test]
    async fn api_denials_advertise_bearer() {
        let (state, _scratch) = offline_state();
        let gateway = Gateway::start(&state).await;
        let rejected: [&[(&str, &str)]; 3] = [
            &[],
            &[("authorization", "Bearer not-a-credential")],
            &[("authorization", "Basic b3duZXI6bm90LWEtY3JlZGVudGlhbA==")],
        ];
        for route in API_ROUTES {
            for headers in rejected {
                let reply = gateway.send(route, headers).await;
                assert_refused(&reply, route, BEARER);
            }
        }
    }

    #[tokio::test]
    async fn smart_http_denials_keep_basic() {
        let (state, _scratch) = offline_state();
        let gateway = Gateway::start(&state).await;
        let rejected: [&[(&str, &str)]; 3] = [
            &[],
            &[("authorization", "Bearer not-a-credential")],
            &[("authorization", "Basic b3duZXI6bm90LWEtY3JlZGVudGlhbA==")],
        ];
        for route in GIT_ROUTES {
            for headers in rejected {
                let reply = gateway.send(route, headers).await;
                assert_refused(&reply, route, BASIC);
            }
        }
    }

    /// A plausible browser session cookie is not a credential on either route
    /// group: it is ignored, the request is refused, and no browser/session
    /// behavior (redirect, cookie or repository session) is enabled.
    #[tokio::test]
    async fn cookie_only_requests_stay_rejected_without_browser_behavior() {
        let (state, _scratch) = offline_state();
        let gateway = Gateway::start(&state).await;
        let cookie = format!("rootyard_session=ryt_{}", "ab".repeat(32));
        let headers = [("cookie", cookie.as_str())];
        for route in [API_ROUTES[0], API_ROUTES[3]] {
            let reply = gateway.send(route, &headers).await;
            assert_refused(&reply, route, BEARER);
        }
        for route in [GIT_ROUTES[0], GIT_ROUTES[3]] {
            let reply = gateway.send(route, &headers).await;
            assert_refused(&reply, route, BASIC);
        }
    }

    /// The same route table proves the challenge is protocol-relative, not a
    /// single global header: a closed-pool authority failure that is not a
    /// `401` is still rendered without any challenge.
    #[tokio::test]
    async fn authority_failures_are_not_challenged() {
        let (state, _scratch) = offline_state();
        let gateway = Gateway::start(&state).await;
        let token = format!("Bearer ryt_{}", "ab".repeat(32));
        let reply = gateway.send(API_ROUTES[0], &[("authorization", token.as_str())]).await;
        assert_ne!(reply.status, StatusCode::UNAUTHORIZED);
        assert_ne!(reply.status, StatusCode::OK);
        assert!(reply.challenges.is_empty(), "a non-401 refusal must not advertise a scheme");
    }
}
