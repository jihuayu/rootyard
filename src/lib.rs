#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

pub mod auth;
pub mod backup;
pub mod config;
pub mod db;
pub mod dispatch;
pub mod events;
pub mod git_http;
pub mod journal;
pub mod maintenance;
pub mod metrics;
pub mod reliability;
pub mod storage;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use deadpool_postgres::Pool;
use serde::Deserialize;
use std::sync::Arc;
use tokio::sync::Semaphore;
use uuid::Uuid;

pub struct AppState {
    pub dispatch: dispatch::Signals,
    pub config: config::Config,
    pub pool: Pool,
    pub storage: storage::Storage,
    pub hooks: reliability::HookInstallation,
    pub transfer_metrics: Arc<metrics::TransferCounters>,
    pub git_slots: Arc<Semaphore>,
}

#[derive(Debug)]
pub struct Error(pub StatusCode, pub &'static str);
impl Error {
    pub fn internal(_error: impl std::fmt::Display) -> Self {
        // Do not print DB URLs, tokens, raw headers, Git stderr or client content.
        eprintln!("rootyard: internal operation failed");
        Self(
            StatusCode::SERVICE_UNAVAILABLE,
            "service temporarily unavailable",
        )
    }
    pub fn unauthorized() -> Self {
        Self(StatusCode::UNAUTHORIZED, "valid credentials required")
    }
    pub fn not_found() -> Self {
        Self(StatusCode::NOT_FOUND, "not found")
    }
    pub fn bad_request() -> Self {
        Self(StatusCode::BAD_REQUEST, "invalid request")
    }
    pub fn timeout() -> Self {
        Self(StatusCode::GATEWAY_TIMEOUT, "Git request timed out")
    }
}
impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let mut response = (self.0, Json(serde_json::json!({"error":self.1}))).into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
        if self.0 == StatusCode::UNAUTHORIZED {
            response.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                "Basic realm=\"Rootyard\", charset=\"UTF-8\""
                    .parse()
                    .unwrap(),
            );
        }
        response
    }
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health/live", get(|| async { "ok" }))
        .route("/health/ready", get(ready))
        .route("/api/repos", post(create_repo).get(list_repos))
        .route("/api/repos/{owner}/{name}", get(get_repo))
        .route(
            "/api/repos/{owner}/{name}/operations",
            get(reliability::operations),
        )
        .route(
            "/api/repos/{owner}/{name}/resolutions",
            get(reliability::resolutions),
        )
        .route(
            "/api/repos/{owner}/{name}/events",
            get(reliability::event_list),
        )
        .fallback(|State(state): State<Arc<AppState>>, request| async move {
            git_http::handle(state, request).await
        })
        .layer(DefaultBodyLimit::max(16 * 1024))
        .with_state(state)
}
async fn ready(State(state): State<Arc<AppState>>) -> Result<&'static str, Error> {
    state
        .pool
        .get()
        .await
        .map_err(Error::internal)?
        .simple_query("SELECT 1")
        .await
        .map_err(Error::internal)?;
    if !state.storage.root.join("repos").is_dir() {
        return Err(Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "storage unavailable",
        ));
    }
    reliability::verify_hooks(&state).map_err(Error::internal)?;
    Ok("ready")
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateRepo {
    name: String,
}
async fn create_repo(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(input): Json<CreateRepo>,
) -> Result<Response, Error> {
    let identity = auth::authenticate(&state.pool, &headers).await?;
    auth::writable(&identity)?;
    if !db::valid_name(&input.name) {
        return Err(Error(StatusCode::BAD_REQUEST, "invalid repository name"));
    }
    let client = state.pool.get().await.map_err(Error::internal)?;
    let id = Uuid::new_v4();
    let created=client.execute("INSERT INTO repositories (id,owner_id,name) VALUES ($1,$2,$3) ON CONFLICT (owner_id,name) DO NOTHING",&[&id,&identity.id,&input.name]).await.map_err(Error::internal)?==1;
    let row = client
        .query_one(
            &format!("{} WHERE r.owner_id=$1 AND r.name=$2", db::REPO_SELECT),
            &[&identity.id, &input.name],
        )
        .await
        .map_err(Error::internal)?;
    let mut repo = db::Repository::from_row(&row);
    drop(client);
    if repo.state == "provisioning" {
        let _slot = state.git_slots.try_acquire().map_err(|_| {
            Error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Git capacity exhausted; retry later",
            )
        })?;
        if state
            .storage
            .provision(&state.config, repo.id)
            .await
            .is_ok()
        {
            state
                .pool
                .get()
                .await
                .map_err(Error::internal)?
                .execute(
                    "UPDATE repositories SET state='ready' WHERE id=$1 AND state='provisioning'",
                    &[&repo.id],
                )
                .await
                .map_err(Error::internal)?;
            repo.state = "ready".into();
        } else {
            eprintln!("rootyard: repository {} provisioning pending", repo.id);
        }
    }
    let status = if repo.state != "ready" {
        StatusCode::ACCEPTED
    } else if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, [(header::CACHE_CONTROL, "no-store")], Json(repo)).into_response())
}
async fn list_repos(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let identity = auth::authenticate(&state.pool, &headers).await?;
    let rows = state
        .pool
        .get()
        .await
        .map_err(Error::internal)?
        .query(
            &format!(
                "{} WHERE r.owner_id=$1 ORDER BY r.name LIMIT 1000",
                db::REPO_SELECT
            ),
            &[&identity.id],
        )
        .await
        .map_err(Error::internal)?;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(
            rows.iter()
                .map(db::Repository::from_row)
                .collect::<Vec<_>>(),
        ),
    )
        .into_response())
}
async fn get_repo(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let identity = auth::authenticate(&state.pool, &headers).await?;
    if owner != identity.username || !db::valid_name(&name) {
        return Err(Error::not_found());
    }
    let row = state
        .pool
        .get()
        .await
        .map_err(Error::internal)?
        .query_opt(
            &format!("{} WHERE r.owner_id=$1 AND r.name=$2", db::REPO_SELECT),
            &[&identity.id, &name],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    Ok((
        [(header::CACHE_CONTROL, "no-store")],
        Json(db::Repository::from_row(&row)),
    )
        .into_response())
}

pub async fn recover(state: &AppState) -> anyhow::Result<usize> {
    // The metadata row itself is a durable, idempotent provisioning job. There is
    // no memory-only enqueue window and no second authority for refs or objects.
    let rows = state
        .pool
        .get()
        .await?
        .query(
            "SELECT id FROM repositories WHERE state='provisioning' AND next_retry_at <= clock_timestamp() ORDER BY next_retry_at, created_at LIMIT 64",
            &[],
        )
        .await?;
    let mut recovered = 0;
    for row in rows {
        let id: Uuid = row.get(0);
        let Ok(_slot) = state.git_slots.try_acquire() else {
            break;
        };
        state.pool.get().await?.execute("UPDATE repositories SET next_retry_at=clock_timestamp()+interval '30 seconds', provision_attempts=provision_attempts+1 WHERE id=$1 AND state='provisioning'", &[&id]).await?;
        match state.storage.provision(&state.config, id).await {
            Ok(()) => {
                state.pool.get().await?.execute("UPDATE repositories SET state='ready' WHERE id=$1 AND state='provisioning'",&[&id]).await?;
                recovered += 1;
            }
            Err(_) => eprintln!("rootyard: repository {id} provisioning requires retry"),
        }
    }
    Ok(recovered)
}
