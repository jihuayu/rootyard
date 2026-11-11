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
//! An unauthenticated request is answered per protocol (#174): every `/api`
//! JSON route and its `/web/blob/api` alias advertises `Bearer realm="Rootyard"`,
//! while the three Smart HTTP `/git` endpoints keep the Git
//! `Basic realm="Rootyard", charset="UTF-8"` challenge. The challenge is
//! rendered once by the route's own handler (`GatewayError::api` / `GatewayError::git`), so
//! the two routes that share a handler can never disagree.
mod api;
mod browse;
mod browser_ui;
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
#[path = "../../tests/blob_gateway_support/mod.rs"]
mod session_acceptance_support;
#[cfg(test)]
mod session_browser_acceptance;
#[cfg(test)]
mod session_http_acceptance;

use std::sync::Arc;

use axum::{
    Router,
    routing::{any, get, post},
};

pub use config::{BlobGitConfig, BlobGitConfigError, BlobGitLimits, BlobGitNativeLimits};
pub use error::GatewayError;
pub use repo_session::SessionTokens;
pub use state::BlobGitState;

/// The browser-only `/web` subtree: the shared sign-in/session pages and the
/// read-only Blob SPA with its GET-only read aliases, all behind the existing
/// `web::session` middleware (cookie validation, Origin/CSRF for mutations and
/// navigation handling) with the [`BlobGitState`] metadata extraction.
///
/// It is merged once here and never wraps `/api` or `/git`, so those keep their
/// bearer-only behaviour unchanged. Cookie authentication is added only for the
/// GET-only `/web/blob/api/...` reads, where the validated session cookie is
/// translated into the `Authorization` header the gateway handlers read; an
/// unauthorized answer of those aliases is the same challenged JSON refusal the
/// top-level `/api` route renders.
fn web_router(state: Arc<BlobGitState>) -> Router<Arc<BlobGitState>> {
    Router::new()
        .nest("/web", browser_ui::router())
        .layer(axum::middleware::from_fn_with_state(state, crate::web::session::middleware))
}

/// Mount the Blob Git gateway. The caller owns the listener and the real Blob
/// store; no `AppState`, legacy `Storage` authority or permanent bare repo is
/// consulted.
///
/// Token/session routes are merged here from the shared token module. They see
/// only the PostgreSQL pool (`MetadataState` via `FromRef<Arc<BlobGitState>>`);
/// the real token/session service and its token-scoped authorization are reused
/// unchanged. The broad request deadline below covers their handler awaits too.
pub fn router(state: Arc<BlobGitState>) -> Router {
    Router::new()
        .route("/health/live", get(|| async { "ok" }))
        .route("/health/ready", get(metadata_ready))
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
        .route("/git/{owner}/{name}/info/refs", get(smart_http::info_refs))
        .route("/git/{owner}/{name}/git-upload-pack", post(smart_http::upload_pack))
        .route("/git/{owner}/{name}/git-receive-pack", post(receive::receive_pack))
        .route("/git/{owner}/{name}/info/lfs/{*rest}", any(api::unsupported_lfs))
        // The browser subtree is merged before the shared token routes, so a
        // path both would register keeps the established token API handler.
        .merge(web_router(state.clone()))
        .merge(crate::token_management::routes())
        .layer(axum::middleware::from_fn_with_state(state.clone(), request_deadline))
        .with_state(state)
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

/// Route-boundary tests for the `401` challenge (#174).
///
/// These serve the real `router()` with `axum::serve` on an ephemeral loopback
/// listener and drive it over ordinary HTTP with the already-direct `reqwest`
/// client, so each request goes through the same socket, route binding,
/// middleware and handler as production (no `tower` test service is needed).
/// Only authentication differs: the pool points at a never-listening loopback
/// port, so the shared `auth::authenticate` answers its own `401`. Every route
/// below decides on that credential after its extractors and its own
/// pre-authentication validation and before it needs PostgreSQL, the Blob store
/// or native Git, so these tests need none of them.
///
/// Each request is shaped so that authentication, not an earlier path, query,
/// body or content-type rejection, is what answers. Smart HTTP names the
/// `.git` repository (`repository_name` -> `404` otherwise) and a valid service
/// query; the RPCs carry their wire content type; `POST /api/repos` carries a
/// syntactically valid JSON body because its `Json` extractor runs before the
/// handler. `read_blob` rejects an empty path before it authenticates, so the
/// blob reads name a file path. History queries are validated before
/// `BrowseSession::open`, so `compare` uses valid revisions.
#[cfg(test)]
mod challenge_tests {
    use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

    use axum::{
        ServiceExt,
        http::{HeaderValue, StatusCode, header},
    };
    use base64::Engine;
    use deadpool_postgres::{Manager, Runtime};

    use super::{BlobGitConfig, BlobGitState, GatewayError, router};
    use crate::blob_store::{budget::ResourceLimits, test_support::store};

    const BEARER: &str = "Bearer realm=\"Rootyard\"";
    const BASIC: &str = "Basic realm=\"Rootyard\", charset=\"UTF-8\"";

    /// An immutable gateway state whose pool points at a closed loopback port,
    /// returned with the scratch [`tempfile::TempDir`] it was built on. The
    /// caller must keep that guard bound for the whole test so the root
    /// outlives every request served by the state.
    fn offline_state() -> (Arc<BlobGitState>, tempfile::TempDir) {
        let config: tokio_postgres::Config =
            "host=127.0.0.1 port=1 user=rootyard dbname=rootyard".parse().expect("static connection string");
        let pool = deadpool_postgres::Pool::builder(Manager::new(config, tokio_postgres::NoTls))
            .runtime(Runtime::Tokio1)
            .max_size(1)
            .build()
            .expect("offline pool");
        // The `cfg(test)` memory store; only its backend identity is consulted,
        // and only after the request authenticated.
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

    /// The real `router()` served through the normal HTTP entrypoint on an
    /// ephemeral loopback listener. Dropping it aborts the serving task.
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

        /// One plain HTTP request carrying exactly `headers` and `body`. The
        /// response is reduced to its status and every `WWW-Authenticate` value
        /// (in order), as owned strings.
        async fn send(
            &self,
            method: &str,
            target: &str,
            headers: &[(&str, &str)],
            body: &'static [u8],
        ) -> (StatusCode, Vec<String>) {
            let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build().unwrap();
            let mut request = match method {
                "GET" => client.get(format!("http://{}{target}", self.address)),
                "POST" => client.post(format!("http://{}{target}", self.address)),
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
            (status, challenges)
        }
    }

    impl Drop for Gateway {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    /// The wire `Content-Type` of one Smart HTTP RPC request.
    fn rpc_content_type(uri: &str) -> &'static str {
        if uri.ends_with("/git-upload-pack") {
            "application/x-git-upload-pack-request"
        } else {
            "application/x-git-receive-pack-request"
        }
    }

    /// Every JSON/API route, with or without a rejected credential, answers its
    /// unauthenticated denial with the Bearer challenge, never the Basic one a
    /// same-origin browser `fetch` would turn into a hanging auth exchange. The
    /// `/web/blob/api` aliases answer exactly like their top-level route.
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
            ("GET", "/api/repos/owner/name/tree"),
            // `read_blob` refuses an empty path before it authenticates, so the
            // blob read names one file.
            ("GET", "/api/repos/owner/name/blob?path=README.md"),
            ("GET", "/api/repos/owner/name/compare?base=HEAD&head=HEAD"),
            ("GET", "/api/repos/owner/name/operations/00000000-0000-0000-0000-000000000001"),
            ("POST", "/api/repos"),
            // The shared token routes merged into the same router.
            ("GET", "/api/tokens"),
            ("GET", "/api/sessions"),
            ("GET", "/web/blob/api/repos"),
            ("GET", "/web/blob/api/repos/owner/name"),
            ("GET", "/web/blob/api/repos/owner/name/refs"),
            ("GET", "/web/blob/api/repos/owner/name/tree"),
            ("GET", "/web/blob/api/repos/owner/name/blob?path=README.md"),
            // The Blob API aliases are same-path names of the `/web/blob` tree,
            // registered at `/web/blob/api/...` only.
            ("GET", "/web/blob/repos"),
            ("GET", "/web/blob/repos/owner/name"),
            ("GET", "/web/blob/repos/owner/name/refs"),
        ];
        for (method, uri) in routes {
            for headers in rejected {
                // `create_repo` extracts `Json<CreateRepository>` before the
                // handler authenticates, so only this route needs a valid JSON
                // body; every other route has no body extractor and takes the
                // empty body.
                let (headers, body): (Vec<(&str, &str)>, &'static [u8]) = if (method, uri) == ("POST", "/api/repos") {
                    let mut headers = headers.to_vec();
                    headers.push(("content-type", "application/json"));
                    (headers, br#"{"name":"name"}"#)
                } else {
                    (headers.to_vec(), b"")
                };
                let (status, challenges) = gateway.send(method, uri, &headers, body).await;
                assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {uri} was not an unauthenticated denial");
                assert_eq!(challenges, [BEARER], "{method} {uri} must not enter a browser Basic auth exchange");
            }
        }
    }

    /// A cookie that is not a session secret at all (`session_token` requires a
    /// lowercase-hex `ryt_` value) is treated as no cookie. Anonymous browser
    /// reads of the alias and of the page subtree therefore answer exactly as
    /// they do without the cookie: the alias read is the gateway's Bearer `401`,
    /// while the pages render their own status (`/web/blob/api/repos` is JSON,
    /// `GET /web/login` renders the sign-in form). This is not a stale or
    /// revoked database session; that path needs the order-bound acceptance
    /// suite, and the middleware's exact Basic -> Bearer mapping is covered by
    /// `session_challenge` and its wiring test in `web::session`.
    #[tokio::test]
    async fn a_non_session_cookie_is_ignored_like_no_cookie() {
        let (state, _scratch) = offline_state();
        let gateway = Gateway::start(&state).await;
        let cookie = format!("rootyard_session=ryt_{}", "zz".repeat(32));
        for uri in ["/web/blob/api/repos", "/web/blob/api/repos/owner/name", "/web/blob/api/repos/owner/name/refs"] {
            let (status, challenges) = gateway.send("GET", uri, &[("cookie", cookie.as_str())], &[]).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "GET {uri} was not the gateway's denial");
            assert_eq!(challenges, [BEARER], "GET {uri} must not start a browser Basic auth exchange");
        }
        let (status, challenges) = gateway.send("GET", "/web/login", &[("cookie", cookie.as_str())], &[]).await;
        assert_eq!(status, StatusCode::OK, "the sign-in page renders without a session");
        assert!(challenges.is_empty(), "the sign-in page must not challenge an anonymous render");
        // Smart HTTP never sees the session middleware: Git Basic negotiation
        // is unchanged, and a browser cookie is not a Git credential here.
        let (status, challenges) = gateway
            .send("GET", "/git/owner/name.git/info/refs?service=git-upload-pack", &[("cookie", &cookie)], &[])
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(challenges, [BASIC]);
    }

    /// `unsupported_merge` (`POST /api/repos/{owner}/{name}/merges`) answers its
    /// `501 Not Implemented` refusal before it looks at any credential, so it is
    /// not an unauthenticated route and must not advertise a scheme challenge.
    /// It has no body, form or query extractor, so the refusal is the same for
    /// every rejected credential on an empty body.
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
            let (status, challenges) = gateway.send("POST", uri, headers, b"").await;
            assert_eq!(status, StatusCode::NOT_IMPLEMENTED, "POST {uri} must stay an explicit not-implemented refusal");
            assert!(challenges.is_empty(), "POST {uri} must not challenge: it never authenticates");
        }
    }

    /// All three Smart HTTP endpoints (as registered in [`router`]) keep the
    /// current Git Basic challenge on an unauthenticated advertisement and on
    /// both RPCs.
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
                let (status, challenges) = gateway.send(method, uri, &all, &[]).await;
                assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {uri} was not an unauthenticated denial");
                assert_eq!(challenges, [BASIC], "{method} {uri} must keep the Git Basic challenge");
            }
        }
    }

    /// Credential parsing is not narrowed: a syntactically well-formed Basic or
    /// Bearer credential passes the shared parser and is challenged by the
    /// gateway's own handler with the route scheme. The offline pool cannot
    /// check the credential, so the shared authority fails closed: nothing is
    /// ever accepted here, and no silent success can hide behind it.
    #[tokio::test]
    async fn syntax_accepted_credentials_still_reach_the_authority() {
        let (state, _scratch) = offline_state();
        let gateway = Gateway::start(&state).await;
        let token = format!("ryt_{}", "ab".repeat(32));
        let basic = format!("Basic {}", base64::engine::general_purpose::STANDARD.encode(format!("owner:{token}")));
        let bearer = format!("Bearer {token}");
        for uri in ["/api/repos", "/web/blob/api/repos"] {
            for credential in [basic.as_str(), bearer.as_str()] {
                let (status, challenges) = gateway.send("GET", uri, &[("authorization", credential)], &[]).await;
                assert_eq!(challenges, [BEARER], "{uri} must render its own handler's challenge");
                assert_ne!(status, StatusCode::OK, "{uri} accepted a credential the offline authority cannot verify");
            }
        }
    }

    /// The shared `Error` mapping keeps the route protocol as the challenge
    /// owner, and a refusal already challenged elsewhere is left untouched.
    #[test]
    fn shared_mappings_use_the_route_challenge() {
        let unauthorized: GatewayError = crate::Error::unauthorized().into();
        assert_eq!(unauthorized, GatewayError::Unauthorized);
        let value = |response: axum::response::Response| -> Vec<String> {
            response
                .headers()
                .get_all(header::WWW_AUTHENTICATE)
                .iter()
                .map(|value| value.to_str().expect("challenge is text").to_owned())
                .collect()
        };
        assert_eq!(value(unauthorized.api()), [BEARER]);
        assert_eq!(value(unauthorized.git()), [BASIC]);
        // A refusal already challenged elsewhere is never rewritten or joined.
        let mut sign_in = GatewayError::Unauthorized.into_response();
        sign_in.headers_mut().append(header::WWW_AUTHENTICATE, HeaderValue::from_static("Negotiate"));
        assert_eq!(value(sign_in.git()), ["Negotiate"]);
        assert_eq!(value(GatewayError::Unauthorized.into_response()), []);
    }
}
