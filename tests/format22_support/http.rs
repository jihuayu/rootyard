//! Real HTTP ownership of the collaborator grant (issue #169).
//!
//! The pack producer is a second real token user on a repository it does not
//! own, so the decision-gated `select` resolves its effective role from live
//! `repository_collaborators` rows. The fixture never writes that grant as SQL:
//! it calls the owning production route
//! `POST /api/repos/{owner}/{name}/collaborators` as the owner, and reads it
//! back through the production `GET` with the producer's own token.
//!
//! ## The served router
//!
//! [`Http::open`] binds `rootyard::router` -- the same merges an operator
//! serves (`members::routes()`, the authentication/admission middleware, the Git
//! transport catch-all) -- over one `AppState` for this fixture's schema and data
//! directory. Each request is an actual hyper `http1` exchange on an in-memory
//! duplex "connection" (no socket, no listener, no address) carrying the
//! loopback `ConnectInfo` the main listener installs, so the production
//! admission and handlers run unchanged.
//!
//! This is the production router answering real HTTP requests in process; it
//! is not, and does not claim to be, a deployed native listener.
//!
//! ## Credentials
//!
//! Only HTTP status codes and the JSON bodies the API itself returns are
//! inspected. Tokens never leave this module.
use anyhow::{Result, anyhow, ensure};
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use base64::Engine as _;
use hyper::body::Incoming;
use hyper::service::Service;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as Connection;
use rootyard::members::models::Role;
use rootyard::{AppState, config, dispatch, metrics, router, storage};
use serde_json::Value;
use std::net::SocketAddr;
use std::path::Path;
use uuid::Uuid;

use super::db::Db;

/// Upper bound of one fixture HTTP exchange, including handler time.
const EXCHANGE_SECONDS: u64 = 60;
/// Upper bound of a response body read by this fixture.
const BODY_LIMIT: usize = 1 << 20;

/// The production router over one application state.
pub struct Http {
    state: Arc<AppState>,
}

impl Http {
    /// Bind the production router to `db`'s schema and the fixture data
    /// directory `data_dir` (where `.volume-id` already lives).
    pub async fn open(db: &Db, git: &Path, data_dir: &Path) -> Result<Self> {
        let mut database: tokio_postgres::Config = db.database_url().parse()?;
        database.options(&format!(
            "-c search_path={} -c timezone=UTC -c statement_timeout=30000 -c lock_timeout=15000",
            db.schema()
        ));
        let config = config::Config {
            // A parsed config renders its fields (host, port, user, session
            // options); it is never a password-bearing URL.
            database_url: format!("{database:?}"),
            data_dir: data_dir.to_path_buf(),
            bind: SocketAddr::from(([127, 0, 0, 1], 0)),
            git: git.to_path_buf(),
            max_request_bytes: 128 * 1024 * 1024,
            max_output_bytes: 128 * 1024 * 1024,
            max_concurrent_git: 2,
            git_timeout: Duration::from_secs(120),
            git_memory_bytes: 1024 * 1024 * 1024,
            max_repo_bytes: 1024 * 1024 * 1024,
            max_pending_deliveries: 10_000,
            // Not a server: no outbox dispatcher, no metrics listener, no Git.
            outbox_worker: false,
            metrics_bind: None,
        };
        let storage =
            storage::Storage::open(&config).map_err(|_| anyhow!("the fixture data directory is not usable"))?;
        let state = Arc::new(AppState {
            mirror_primary: None,
            dispatch: dispatch::Signals::default(),
            storage,
            config,
            pool: db.pool.clone(),
            hooks: None,
            transfer_metrics: Arc::new(metrics::TransferCounters::default()),
            git_slots: Arc::new(tokio::sync::Semaphore::new(2)),
        });
        Ok(Self { state })
    }

    /// `GET /api/auth/whoami` through the served router: the real identity of
    /// the token's user.
    pub async fn whoami(&self, token: &str) -> Result<(Uuid, String)> {
        let (status, body) = self.call(Method::GET, "/api/auth/whoami".to_owned(), token, None).await?;
        ensure!(status == StatusCode::OK, "the whoami probe answered {status}");
        match (body["id"].as_str().and_then(|value| Uuid::parse_str(value).ok()), body["username"].as_str()) {
            (Some(user_id), Some(username)) => Ok((user_id, username.to_owned())),
            _ => Err(anyhow!("the whoami probe did not return a real identity")),
        }
    }

    /// `POST /api/repos/{owner}/{name}/collaborators` as `token`'s user.
    pub async fn post_collaborator(
        &self,
        token: &str,
        owner: &str,
        repository: &str,
        username: &str,
        role: Role,
    ) -> Result<(StatusCode, Value)> {
        let body = serde_json::json!({ "username": username, "role": role }).to_string();
        self.call(Method::POST, format!("/api/repos/{owner}/{repository}/collaborators"), token, Some(body)).await
    }

    /// `GET /api/repos/{owner}/{name}/collaborators/{username}` as `token`'s user.
    pub async fn get_collaborator(
        &self,
        token: &str,
        owner: &str,
        repository: &str,
        username: &str,
    ) -> Result<(StatusCode, Value)> {
        self.call(Method::GET, format!("/api/repos/{owner}/{repository}/collaborators/{username}"), token, None).await
    }

    async fn call(
        &self,
        method: Method,
        path: String,
        token: &str,
        body: Option<String>,
    ) -> Result<(StatusCode, Value)> {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .body(body.map_or_else(Body::empty, Body::from))
            .map_err(|_| anyhow!("the fixture HTTP request could not be built"))?;
        *request.headers_mut() = headers(token, body.is_some())?;

        let (server_io, client_io) = tokio::io::duplex(64 * 1024);
        let served = Served { app: router(self.state.clone()), peer: loopback() };
        let connection = tokio::spawn(async move {
            let mut builder = Connection::new(TokioExecutor);
            builder.http1().timer(hyper_util::rt::TokioTimer::new()).keep_alive(false);
            builder.serve_connection(TokioIo::new(server_io), served).await.map(|_| ())
        });
        let (mut sender, driving) = hyper::client::conn::http1::Builder::new()
            .handshake::<_, Body>(TokioIo::new(client_io))
            .await
            .map_err(|_| anyhow!("the in-memory client handshake failed"))?;
        let client_task = tokio::spawn(async move { driving.await });
        let response =
            match tokio::time::timeout(Duration::from_secs(EXCHANGE_SECONDS), sender.send_request(request)).await {
                Ok(Ok(response)) => response,
                Ok(Err(_)) => return Err(anyhow!("the production router did not answer the fixture request")),
                Err(_) => return Err(anyhow!("the fixture HTTP request timed out")),
            };
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), BODY_LIMIT)
            .await
            .map_err(|_| anyhow!("the API response body could not be read"))?;
        drop(sender);
        let _ = client_task.await;
        let _ = connection.await;
        Ok((status, serde_json::from_slice(&bytes).unwrap_or(Value::Null)))
    }
}

/// The production router as the hyper service of one in-memory connection. The
/// loopback `ConnectInfo` is the extension the main listener installs per
/// connection; every other production extension is the router's own.
struct Served {
    app: axum::Router,
    peer: SocketAddr,
}

impl<Payload> Service<Request<Payload>> for Served {
    type Response = axum::response::Response;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<axum::response::Response, Infallible>> + Send>>;

    fn call(&self, request: Request<Payload>) -> Self::Future {
        let (mut parts, body) = request.into_parts();
        parts.extensions.insert(ConnectInfo(self.peer));
        // `Router<()>` already implements `tower_service::Service`; call it
        // directly so the fixture adds no test-only `tower` dependency.
        let future = Service::call(&self.app, Request::from_parts(parts, axum::body::Body::new(body)));
        Box::pin(async move { Ok(future.await.unwrap_or_else(|never| match never {})) })
    }
}

/// `Basic` credentials carrying only the `ryt_` token as password, the form the
/// production `auth::credentials` accepts.
fn headers(token: &str, json: bool) -> Result<HeaderMap> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!(":{token}"));
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Basic {encoded}")).map_err(|_| anyhow!("the token header was refused"))?,
    );
    headers.insert(header::HOST, HeaderValue::from_static("fixture.invalid"));
    if json {
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    }
    Ok(headers)
}

/// A fresh loopback peer per connection, as the served listener supplies.
fn loopback() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], (Uuid::new_v4().as_u128() % 60_000 + 1_024) as u16))
}

/// The owner grant must be a fresh `201` for exactly this user and role.
pub fn ensure_created(body: &Value, username: &str, role: Role) -> Result<()> {
    ensure!(body["username"].as_str() == Some(username), "the created collaborator is another user");
    ensure!(body["role"].as_str() == Some(role.as_str()), "the created collaborator has another role");
    ensure!(
        body["user_id"].as_str().is_some_and(|id| Uuid::parse_str(id).is_ok()),
        "the created collaborator carries no real user id"
    );
    Ok(())
}

/// A read-back through the production `GET` reports the same actual user/role.
pub fn ensure_read_back(body: &Value, user_id: Uuid, username: &str, role: Role) -> Result<()> {
    let expected = user_id.to_string();
    ensure!(body["user_id"].as_str() == Some(expected.as_str()), "the stored collaborator is another user");
    ensure!(body["username"].as_str() == Some(username), "the stored collaborator has another username");
    ensure!(body["role"].as_str() == Some(role.as_str()), "the stored collaborator has another role");
    Ok(())
}
