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
//! directory. The router is served exactly as the deployed listener serves it,
//! `axum::serve` over `into_make_service_with_connect_info::<SocketAddr>()`, on a
//! `127.0.0.1` ephemeral-port `TcpListener`, so every request is a real HTTP/1.1
//! exchange over loopback and the production admission and handlers run
//! unchanged. Only the direct `axum`, `reqwest` and `tokio` dependencies are
//! used: no test-only `hyper`, `hyper-util` or `tower` declaration is needed or
//! added.
//!
//! This is the production router answering real HTTP requests in process on a
//! loopback socket; it is not, and does not claim to be, a deployed public
//! listener. The server task is owned by [`Http`] and aborted when it drops.
//!
//! ## Credentials
//!
//! Only HTTP status codes and the JSON bodies the API itself returns are
//! inspected. Tokens never leave this module: they are sent only to the loopback
//! fixture origin that issued the listener, never rendered in errors.
use anyhow::{Result, anyhow, ensure};
use std::error::Error as StdError;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use reqwest::StatusCode;
use rootyard::members::models::Role;
use rootyard::{AppState, config, dispatch, metrics, router, storage};
use serde_json::Value;
use uuid::Uuid;

use super::db::Db;

/// Upper bound of one fixture HTTP exchange, including handler time.
const EXCHANGE_SECONDS: u64 = 60;
/// Upper bound of the response body read by this fixture.
const BODY_LIMIT: usize = 1 << 20;

/// The production router over one application state, served on loopback HTTP.
pub struct Http {
    /// Fixture origin, always `http://127.0.0.1:{port}` of the owned listener.
    origin: String,
    client: reqwest::Client,
    /// The owned `axum::serve` task; aborted by [`Http`]'s `Drop`.
    server: tokio::task::JoinHandle<()>,
}

impl Drop for Http {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Http {
    /// Bind the production router to `db`'s schema and the fixture data
    /// directory `data_dir` (where `.volume-id` already lives), and start
    /// serving it on a loopback ephemeral port.
    pub async fn open(db: &Db, git: &Path, data_dir: &Path) -> Result<Self> {
        let mut database: tokio_postgres::Config = db.database_url().parse()?;
        database.options(format!(
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
            // Not a deployment: no outbox dispatcher, no metrics listener, no Git.
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
        // Loopback only: never a wildcard or non-loopback address.
        let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .map_err(|_| anyhow!("the fixture could not bind a loopback listener"))?;
        let address = listener.local_addr().map_err(|_| anyhow!("the fixture listener has no address"))?;
        ensure!(address.ip().is_loopback(), "the fixture listener is not on loopback");
        // The same admission requirement the deployed `main` installs: every
        // request carries the real loopback `ConnectInfo` peer.
        let served = axum::serve(listener, router(state).into_make_service_with_connect_info::<SocketAddr>());
        let server = tokio::spawn(async move {
            // `axum::serve` never completes; the task ends when aborted.
            let _ = served.await;
        });
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(Duration::from_secs(EXCHANGE_SECONDS))
            .build()
            .map_err(|_| anyhow!("the fixture HTTP client could not be built"))?;
        Ok(Self { origin: format!("http://{address}"), client, server })
    }

    /// `GET /api/auth/whoami` through the served router: the real identity of
    /// the token's user.
    pub async fn whoami(&self, token: &str) -> Result<(Uuid, String)> {
        let (status, body) = self.call(reqwest::Method::GET, "/api/auth/whoami".to_owned(), token, None).await?;
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
        self.call(reqwest::Method::POST, format!("/api/repos/{owner}/{repository}/collaborators"), token, Some(body))
            .await
    }

    /// `GET /api/repos/{owner}/{name}/collaborators/{username}` as `token`'s user.
    pub async fn get_collaborator(
        &self,
        token: &str,
        owner: &str,
        repository: &str,
        username: &str,
    ) -> Result<(StatusCode, Value)> {
        self.call(
            reqwest::Method::GET,
            format!("/api/repos/{owner}/{repository}/collaborators/{username}"),
            token,
            None,
        )
        .await
    }

    async fn call(
        &self,
        method: reqwest::Method,
        path: String,
        token: &str,
        body: Option<String>,
    ) -> Result<(StatusCode, Value)> {
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.origin))
            .header(reqwest::header::AUTHORIZATION, authorization(token)?);
        if let Some(body) = body {
            request = request.header(reqwest::header::CONTENT_TYPE, "application/json").body(body);
        }
        let response = match tokio::time::timeout(Duration::from_secs(EXCHANGE_SECONDS), request.send()).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => return Err(transport(&error)),
            Err(_) => return Err(anyhow!("the fixture HTTP request timed out")),
        };
        let status = response.status();
        // Bounded read: the body is refused once it exceeds `BODY_LIMIT`.
        let mut response = response;
        let mut bytes = Vec::new();
        loop {
            match tokio::time::timeout(Duration::from_secs(EXCHANGE_SECONDS), response.chunk()).await {
                Ok(Ok(Some(chunk))) => {
                    ensure!(
                        bytes.len() + chunk.len() <= BODY_LIMIT,
                        "the API response body exceeded the fixture limit"
                    );
                    bytes.extend_from_slice(&chunk);
                }
                Ok(Ok(None)) => break,
                Ok(Err(error)) => return Err(transport(&error)),
                Err(_) => return Err(anyhow!("the fixture HTTP response timed out")),
            }
        }
        Ok((status, serde_json::from_slice(&bytes).unwrap_or(Value::Null)))
    }
}

/// A transport failure without its URL, headers, body or credentials.
fn transport(error: &reqwest::Error) -> anyhow::Error {
    match error.source() {
        Some(cause) => anyhow!("the production router did not answer the fixture request ({cause})"),
        None => anyhow!("the production router did not answer the fixture request"),
    }
}

/// `Basic` credentials carrying only the `ryt_` token as password, the form the
/// production `auth::credentials` accepts.
fn authorization(token: &str) -> Result<reqwest::header::HeaderValue> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!(":{token}"));
    reqwest::header::HeaderValue::from_str(&format!("Basic {encoded}"))
        .map_err(|_| anyhow!("the token header was refused"))
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
