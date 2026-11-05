//! Minimal private-owner Issue API. No organization or collaborator permissions
//! are implied. Every query carries tenant/repository scope, every request fences
//! token revocation and repository ownership with PostgreSQL row locks.
use crate::{
    AppState, Error,
    auth::{self, Role, authorize_repo_with_role as authorize, finish_tx as finish, idempotency_key},
    db,
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use deadpool_postgres::Transaction;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use tokio_postgres::Row;
use uuid::Uuid;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route(
            "/api/repos/{owner}/{name}/issues",
            get(list_issues).post(create_issue),
        )
        .route(
            "/api/repos/{owner}/{name}/issues/{number}",
            get(get_issue).patch(update_issue),
        )
        .route(
            "/api/repos/{owner}/{name}/issues/{number}/comments",
            get(list_comments).post(create_comment),
        )
        .route(
            "/api/repos/{owner}/{name}/issues/{number}/comments/{comment_number}",
            get(get_comment).patch(update_comment),
        )
        .route(
            "/api/repos/{owner}/{name}/backend",
            get(get_backend).patch(set_backend),
        )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewIssue {
    title: String,
    #[serde(default)]
    body: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuePatch {
    expected_version: i64,
    title: Option<String>,
    body: Option<String>,
    state: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewComment {
    body: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommentPatch {
    expected_version: i64,
    body: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    after: Option<i64>,
    limit: Option<i64>,
}
impl Page {
    fn bounds(&self) -> Result<(i64, i64), Error> {
        let after = self.after.unwrap_or(0);
        let limit = self.limit.unwrap_or(50);
        if after < 0 || !(1..=100).contains(&limit) {
            return Err(Error::bad_request());
        }
        Ok((after, limit))
    }
}
// Issue filtering has its own extractor so comment lists still reject `state`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuePage {
    after: Option<i64>,
    limit: Option<i64>,
    state: Option<IssueState>,
}
impl IssuePage {
    fn bounds(&self) -> Result<(i64, i64), Error> {
        Page {
            after: self.after,
            limit: self.limit,
        }
        .bounds()
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum IssueState {
    Open,
    Closed,
}
impl IssueState {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
        }
    }
}

#[derive(Serialize)]
struct Issue {
    repository_id: Uuid,
    number: i64,
    author_id: Uuid,
    title: String,
    body: String,
    state: String,
    version: i64,
    created_at: String,
    updated_at: String,
}
impl Issue {
    fn row(row: &Row) -> Self {
        Self {
            repository_id: row.get("repository_id"),
            number: row.get("number"),
            author_id: row.get("author_id"),
            title: row.get("title"),
            body: row.get("body"),
            state: row.get("state"),
            version: row.get("version"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }
    }
}
#[derive(Serialize)]
struct Comment {
    repository_id: Uuid,
    issue_number: i64,
    number: i64,
    author_id: Uuid,
    body: String,
    version: i64,
    created_at: String,
    updated_at: String,
}
impl Comment {
    fn row(row: &Row) -> Self {
        Self {
            repository_id: row.get("repository_id"),
            issue_number: row.get("issue_number"),
            number: row.get("number"),
            author_id: row.get("author_id"),
            body: row.get("body"),
            version: row.get("version"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }
    }
}
const ISSUE_FIELDS: &str =
    "repository_id,number,author_id,title,body,state,version,created_at::text,updated_at::text";
const COMMENT_FIELDS: &str =
    "repository_id,issue_number,number,author_id,body,version,created_at::text,updated_at::text";

fn json(status: StatusCode, value: impl Serialize) -> Response {
    (status, [(header::CACHE_CONTROL, "no-store")], Json(value)).into_response()
}
fn positive(number: i64) -> Result<(), Error> {
    if number <= 0 {
        Err(Error::bad_request())
    } else {
        Ok(())
    }
}
fn title_valid(title: &str) -> bool {
    !title.trim().is_empty() && title.len() <= 256 && !title.chars().any(char::is_control)
}
fn body_valid(body: &str, required: bool) -> bool {
    body.len() <= 8192
        && (!required || !body.trim().is_empty())
        && !body
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
}

async fn creation_replay(
    tx: &Transaction<'_>,
    actor: Uuid,
    repo: Uuid,
    key: &str,
    request: &Value,
) -> Result<Option<Value>, Error> {
    // The unique key serializes competing creators, including across processes.
    // Its placeholder, resource, allocation and saved response commit together.
    // If the first creator aborts, an INSERT waiter can become the new creator.
    let inserted = tx.execute(
        "INSERT INTO forge_creation_requests (tenant_id,repository_id,idempotency_key,request) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING",
        &[&actor, &repo, &key, &request],
    ).await.map_err(Error::internal)?;
    if inserted == 1 {
        return Ok(None);
    }
    // Separate READ COMMITTED statement observes the winner after the INSERT
    // conflict wait. Never allocate again if a stored record is incomplete.
    let row = tx.query_one(
        "SELECT request,response FROM forge_creation_requests WHERE tenant_id=$1 AND repository_id=$2 AND idempotency_key=$3",
        &[&actor, &repo, &key],
    ).await.map_err(Error::internal)?;
    if row.get::<_, Value>("request") != *request {
        return Err(Error(StatusCode::CONFLICT, "idempotency key conflict"));
    }
    row.get::<_, Option<Value>>("response")
        .map(Some)
        .ok_or_else(|| Error::internal("incomplete creation record"))
}

async fn record_creation(
    tx: &Transaction<'_>,
    actor: Uuid,
    repo: Uuid,
    key: Option<&str>,
    response: &Value,
) -> Result<(), Error> {
    if let Some(key) = key {
        let changed = tx.execute(
            "UPDATE forge_creation_requests SET response=$4 WHERE tenant_id=$1 AND repository_id=$2 AND idempotency_key=$3 AND response IS NULL",
            &[&actor, &repo, &key, &response],
        ).await.map_err(Error::internal)?;
        if changed != 1 {
            return Err(Error::internal("creation record was not finalized"));
        }
    }
    Ok(())
}
async fn issue_exists(
    tx: &Transaction<'_>,
    actor: Uuid,
    repo: Uuid,
    number: i64,
) -> Result<(), Error> {
    tx.query_opt(
        "SELECT number FROM forge_issues WHERE tenant_id=$1 AND repository_id=$2 AND number=$3",
        &[&actor, &repo, &number],
    )
    .await
    .map_err(Error::internal)?
    .ok_or_else(Error::not_found)?;
    Ok(())
}

pub async fn create_issue(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<NewIssue>,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    if !title_valid(&input.title) || !body_valid(&input.body, false) {
        return Err(Error::bad_request());
    }
    let key = idempotency_key(&headers)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = authorize(&tx, &actor, &owner, &name, Role::Triage).await?;
    let (repo, tenant_id) = (access.repo_id, access.owner_id);
    if let Some(key) = key {
        let request =
            serde_json::json!({"operation":"issue", "title":input.title, "body":input.body});
        if let Some(response) = creation_replay(&tx, tenant_id, repo, key, &request).await? {
            finish(tx, &actor, true).await?;
            return Ok(json(StatusCode::CREATED, response));
        }
    }
    tx.execute("INSERT INTO forge_issue_counters (tenant_id,repository_id) VALUES($1,$2) ON CONFLICT DO NOTHING", &[&tenant_id, &repo]).await.map_err(Error::internal)?;
    let number: i64 = tx.query_one("UPDATE forge_issue_counters SET next_number=next_number+1 WHERE tenant_id=$1 AND repository_id=$2 RETURNING next_number-1", &[&tenant_id, &repo]).await.map_err(Error::internal)?.get(0);
    let row = tx.query_one(&format!("INSERT INTO forge_issues (tenant_id,repository_id,number,author_id,title,body) VALUES($1,$2,$3,$4,$5,$6) RETURNING {ISSUE_FIELDS}"), &[&tenant_id, &repo, &number, &actor.id, &input.title, &input.body]).await.map_err(Error::internal)?;
    let issue = serde_json::to_value(Issue::row(&row)).map_err(Error::internal)?;
    record_creation(&tx, tenant_id, repo, key, &issue).await?;
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::CREATED, issue))
}

pub async fn list_issues(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    Query(page): Query<IssuePage>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let (after, limit) = page.bounds()?;
    let filter = page.state.as_ref().map(IssueState::as_str);
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = authorize(&tx, &actor, &owner, &name, Role::Read).await?;
    let (repo, tenant_id) = (access.repo_id, access.owner_id);
    let rows = tx.query(&format!("SELECT {ISSUE_FIELDS} FROM forge_issues WHERE tenant_id=$1 AND repository_id=$2 AND number>$3 AND ($5::text IS NULL OR state=$5) ORDER BY number LIMIT $4"), &[&tenant_id, &repo, &after, &(limit+1), &filter]).await.map_err(Error::internal)?;
    let more = rows.len() > limit as usize;
    let items: Vec<_> = rows.iter().take(limit as usize).map(Issue::row).collect();
    let next_after = if more {
        items.last().map(|i| i.number)
    } else {
        None
    };
    finish(tx, &actor, false).await?;
    Ok(json(
        StatusCode::OK,
        serde_json::json!({"items":items,"next_after":next_after}),
    ))
}

pub async fn get_issue(
    State(state): State<Arc<AppState>>,
    Path((owner, name, number)): Path<(String, String, i64)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    positive(number)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = authorize(&tx, &actor, &owner, &name, Role::Read).await?;
    let (repo, tenant_id) = (access.repo_id, access.owner_id);
    let row = tx.query_opt(&format!("SELECT {ISSUE_FIELDS} FROM forge_issues WHERE tenant_id=$1 AND repository_id=$2 AND number=$3"), &[&tenant_id,&repo,&number]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let issue = Issue::row(&row);
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, issue))
}

pub async fn update_issue(
    State(state): State<Arc<AppState>>,
    Path((owner, name, number)): Path<(String, String, i64)>,
    headers: HeaderMap,
    Json(input): Json<IssuePatch>,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    positive(number)?;
    positive(input.expected_version)?;
    if input.title.as_ref().is_some_and(|v| !title_valid(v))
        || input.body.as_ref().is_some_and(|v| !body_valid(v, false))
        || input
            .state
            .as_ref()
            .is_some_and(|v| !matches!(v.as_str(), "open" | "closed"))
        || (input.title.is_none() && input.body.is_none() && input.state.is_none())
    {
        return Err(Error::bad_request());
    }
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = authorize(&tx, &actor, &owner, &name, Role::Triage).await?;
    let (repo, tenant_id) = (access.repo_id, access.owner_id);
    issue_exists(&tx, tenant_id, repo, number).await?;
    let row = tx.query_opt(&format!("UPDATE forge_issues SET title=COALESCE($5,title),body=COALESCE($6,body),state=COALESCE($7,state),version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 AND version=$4 RETURNING {ISSUE_FIELDS}"), &[&tenant_id,&repo,&number,&input.expected_version,&input.title,&input.body,&input.state]).await.map_err(Error::internal)?.ok_or(Error(StatusCode::CONFLICT,"issue version conflict"))?;
    let issue = Issue::row(&row);
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, issue))
}

pub async fn create_comment(
    State(state): State<Arc<AppState>>,
    Path((owner, name, number)): Path<(String, String, i64)>,
    headers: HeaderMap,
    Json(input): Json<NewComment>,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    positive(number)?;
    if !body_valid(&input.body, true) {
        return Err(Error::bad_request());
    }
    let key = idempotency_key(&headers)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = authorize(&tx, &actor, &owner, &name, Role::Triage).await?;
    let (repo, tenant_id) = (access.repo_id, access.owner_id);
    if let Some(key) = key {
        let request =
            serde_json::json!({"operation":"comment", "issue_number":number, "body":input.body});
        if let Some(response) = creation_replay(&tx, tenant_id, repo, key, &request).await? {
            finish(tx, &actor, true).await?;
            return Ok(json(StatusCode::CREATED, response));
        }
    }
    let comment_number: i64 = tx.query_opt("UPDATE forge_issues SET next_comment_number=next_comment_number+1 WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 RETURNING next_comment_number-1", &[&tenant_id,&repo,&number]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?.get(0);
    let row = tx.query_one(&format!("INSERT INTO forge_issue_comments (tenant_id,repository_id,issue_number,number,author_id,body) VALUES($1,$2,$3,$4,$5,$6) RETURNING {COMMENT_FIELDS}"), &[&tenant_id,&repo,&number,&comment_number,&actor.id,&input.body]).await.map_err(Error::internal)?;
    let comment = serde_json::to_value(Comment::row(&row)).map_err(Error::internal)?;
    record_creation(&tx, tenant_id, repo, key, &comment).await?;
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::CREATED, comment))
}

pub async fn list_comments(
    State(state): State<Arc<AppState>>,
    Path((owner, name, number)): Path<(String, String, i64)>,
    Query(page): Query<Page>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    positive(number)?;
    let (after, limit) = page.bounds()?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = authorize(&tx, &actor, &owner, &name, Role::Read).await?;
    let (repo, tenant_id) = (access.repo_id, access.owner_id);
    issue_exists(&tx, tenant_id, repo, number).await?;
    let rows = tx.query(&format!("SELECT {COMMENT_FIELDS} FROM forge_issue_comments WHERE tenant_id=$1 AND repository_id=$2 AND issue_number=$3 AND number>$4 ORDER BY number LIMIT $5"), &[&tenant_id,&repo,&number,&after,&(limit+1)]).await.map_err(Error::internal)?;
    let more = rows.len() > limit as usize;
    let items: Vec<_> = rows.iter().take(limit as usize).map(Comment::row).collect();
    let next_after = if more {
        items.last().map(|i| i.number)
    } else {
        None
    };
    finish(tx, &actor, false).await?;
    Ok(json(
        StatusCode::OK,
        serde_json::json!({"items":items,"next_after":next_after}),
    ))
}

pub async fn get_comment(
    State(state): State<Arc<AppState>>,
    Path((owner, name, number, comment_number)): Path<(String, String, i64, i64)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    positive(number)?;
    positive(comment_number)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = authorize(&tx, &actor, &owner, &name, Role::Read).await?;
    let (repo, tenant_id) = (access.repo_id, access.owner_id);
    let row = tx.query_opt(&format!("SELECT {COMMENT_FIELDS} FROM forge_issue_comments WHERE tenant_id=$1 AND repository_id=$2 AND issue_number=$3 AND number=$4"), &[&tenant_id,&repo,&number,&comment_number]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let comment = Comment::row(&row);
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, comment))
}

pub async fn update_comment(
    State(state): State<Arc<AppState>>,
    Path((owner, name, number, comment_number)): Path<(String, String, i64, i64)>,
    headers: HeaderMap,
    Json(input): Json<CommentPatch>,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    positive(number)?;
    positive(comment_number)?;
    positive(input.expected_version)?;
    if !body_valid(&input.body, true) {
        return Err(Error::bad_request());
    }
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = authorize(&tx, &actor, &owner, &name, Role::Triage).await?;
    let (repo, tenant_id) = (access.repo_id, access.owner_id);
    tx.query_opt("SELECT number FROM forge_issue_comments WHERE tenant_id=$1 AND repository_id=$2 AND issue_number=$3 AND number=$4", &[&tenant_id,&repo,&number,&comment_number]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let row = tx.query_opt(&format!("UPDATE forge_issue_comments SET body=$6,version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND repository_id=$2 AND issue_number=$3 AND number=$4 AND version=$5 RETURNING {COMMENT_FIELDS}"), &[&tenant_id,&repo,&number,&comment_number,&input.expected_version,&input.body]).await.map_err(Error::internal)?.ok_or(Error(StatusCode::CONFLICT,"comment version conflict"))?;
    let comment = Comment::row(&row);
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, comment))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendPatch {
    pub storage_backend: String,
    pub expected_storage_generation: Option<i64>,
    #[serde(default)]
    pub write_paused: bool,
    #[serde(default)]
    pub pando_ready: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageBackendMarker {
    pub storage_backend: String,
    pub storage_generation: i64,
    #[serde(default)]
    pub write_paused: bool,
    #[serde(default)]
    pub pando_ready: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackendStatusResponse {
    pub repository_id: Uuid,
    pub owner: String,
    pub name: String,
    pub storage_backend: String,
    pub storage_generation: i64,
    pub state: String,
    pub gateway_route: String,
    pub read_backend: String,
    pub write_backend: String,
    pub write_paused: bool,
    pub pando_ready: bool,
    pub gitfs_ready: bool,
}

pub(crate) fn read_repo_git_config_backend(repo_path: &std::path::Path) -> (Option<String>, bool) {
    let Ok(cfg_text) = std::fs::read_to_string(repo_path.join("config")) else { return (None, false); };
    let (mut in_ry, mut backend, mut paused) = (false, None, false);
    for raw in cfg_text.lines() {
        let line = raw.trim();
        if line.starts_with('[') && line.ends_with(']') {
            in_ry = line[1..line.len() - 1].trim().eq_ignore_ascii_case("rootyard");
        } else if in_ry {
            if let Some((k, v)) = line.split_once('=') {
                let (k, v) = (k.trim(), v.trim().trim_matches('"'));
                if k.eq_ignore_ascii_case("storagebackend") && matches!(v, "gitfs" | "pando") {
                    backend = Some(v.to_owned());
                } else if k.eq_ignore_ascii_case("writepaused") {
                    paused = v.eq_ignore_ascii_case("true") || v == "1" || v.eq_ignore_ascii_case("yes");
                }
            }
        }
    }
    (backend, paused)
}

pub(crate) fn read_repo_backend_marker(repo_path: &std::path::Path) -> Option<StorageBackendMarker> {
    serde_json::from_slice(&std::fs::read(repo_path.join("rootyard-storage-backend.json")).ok()?).ok()
}

fn write_repo_backend_marker(repo_path: &std::path::Path, marker: &StorageBackendMarker) -> std::io::Result<()> {
    let tmp = repo_path.join(format!(".rootyard-storage-backend.tmp-{}", Uuid::new_v4()));
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
    std::io::Write::write_all(&mut f, &serde_json::to_vec_pretty(marker)?)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, repo_path.join("rootyard-storage-backend.json"))?;
    std::fs::File::open(repo_path)?.sync_all()
}

pub(crate) fn build_backend_status(
    state: &AppState, repository_id: Uuid, owner: String, name: String, repo_state: String, db_backend: &str, storage_generation: i64,
) -> BackendStatusResponse {
    let repo_path = state.storage.repo_path(repository_id);
    let gitfs_ready = repo_state == "ready" && state.storage.verify_path(repository_id).is_ok();
    let marker = read_repo_backend_marker(&repo_path);
    let (cfg_backend, cfg_paused) = read_repo_git_config_backend(&repo_path);
    let is_pando = db_backend == "pando" || marker.as_ref().is_some_and(|m| m.storage_backend == "pando") || cfg_backend.as_deref() == Some("pando");
    let storage_backend = if is_pando { "pando".to_owned() } else { "gitfs".to_owned() };
    let write_paused = marker.as_ref().map(|m| m.write_paused).unwrap_or(cfg_paused);
    let gateway_route = if is_pando { "pando_gateway".to_owned() } else { "gitfs_local".to_owned() };
    let pando_ready = repo_state == "ready" && (is_pando || marker.as_ref().is_some_and(|m| m.pando_ready) || state.storage.root.join("pando").join("objects").join(repository_id.to_string()).is_dir());
    BackendStatusResponse {
        repository_id, owner, name, read_backend: storage_backend.clone(), write_backend: storage_backend.clone(),
        storage_backend, storage_generation, state: repo_state, gateway_route, write_paused, pando_ready, gitfs_ready,
    }
}

pub async fn get_backend(
    State(state): State<Arc<AppState>>, Path((owner, name)): Path<(String, String)>, headers: HeaderMap,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let repo_id = auth::authorize_repo(&tx, &actor, &owner, &name, false).await?;
    let row = tx.query_one("SELECT r.name, r.state, r.storage_backend, r.storage_generation, u.username FROM repositories r JOIN users u ON u.id = r.owner_id WHERE r.id = $1", &[&repo_id]).await.map_err(Error::internal)?;
    let status = build_backend_status(&state, repo_id, row.get("username"), row.get("name"), row.get("state"), row.get::<_, &str>("storage_backend"), row.get("storage_generation"));
    finish(tx, &actor, false).await?;
    Ok(json(StatusCode::OK, status))
}

pub async fn set_backend(
    State(state): State<Arc<AppState>>, Path((owner, name)): Path<(String, String)>, headers: HeaderMap, Json(input): Json<BackendPatch>,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    if !matches!(input.storage_backend.as_str(), "gitfs" | "pando") { return Err(Error::bad_request()); }
    if let Some(expected) = input.expected_storage_generation { positive(expected)?; }
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = authorize(&tx, &actor, &owner, &name, Role::Admin).await?;
    let repo_id = access.repo_id;
    let _write_guard = state.storage.write_lock(repo_id).await;
    let row = tx.query_one("SELECT r.name, r.state, r.storage_backend, r.storage_generation, u.username FROM repositories r JOIN users u ON u.id = r.owner_id WHERE r.id = $1 FOR UPDATE OF r", &[&repo_id]).await.map_err(Error::internal)?;
    let current_gen: i64 = row.get("storage_generation");
    if input.expected_storage_generation.is_some_and(|exp| exp != current_gen) {
        return Err(Error(StatusCode::CONFLICT, "storage generation conflict"));
    }
    let updated = tx.query_one("UPDATE repositories SET storage_generation = storage_generation + 1 WHERE id = $1 RETURNING state, storage_generation", &[&repo_id]).await.map_err(Error::internal)?;
    let (new_gen, repo_state): (i64, String) = (updated.get("storage_generation"), updated.get("state"));
    let repo_path = state.storage.verify_path(repo_id).map_err(Error::internal)?;
    let marker = StorageBackendMarker { storage_backend: input.storage_backend.clone(), storage_generation: new_gen, write_paused: input.write_paused, pando_ready: input.pando_ready.unwrap_or(input.storage_backend == "pando") };
    write_repo_backend_marker(&repo_path, &marker).map_err(Error::internal)?;
    let (gen_str, paused_str) = (new_gen.to_string(), if input.write_paused { "true" } else { "false" });
    let receive_pack = if !input.write_paused && input.storage_backend == "gitfs" { "true" } else { "false" };
    for (k, v) in [("rootyard.storageBackend", input.storage_backend.as_str()), ("rootyard.storageGeneration", gen_str.as_str()), ("rootyard.writePaused", paused_str), ("http.receivepack", receive_pack)] {
        let out = state.storage.git(&state.config).arg("--git-dir").arg(&repo_path).args(["config", k, v]).output().await.map_err(Error::internal)?;
        if !out.status.success() { return Err(Error::internal("failed to update repository backend config")); }
    }
    crate::members::audit::record_audit_event(&tx, access.owner_id, repo_id, &actor, "repository.storage_backend.changed", "repository", &name, serde_json::json!({"storage_backend": input.storage_backend, "old_storage_generation": current_gen, "new_storage_generation": new_gen})).await?;
    let status = build_backend_status(&state, repo_id, row.get("username"), row.get("name"), repo_state, &input.storage_backend, new_gen);
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, status))
}


#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn issue_filter_query_contract() {
        for (query, expected) in [
            ("", None),
            ("?state=open", Some("open")),
            ("?state=closed&after=4&limit=2", Some("closed")),
        ] {
            let uri = format!("/issues{query}").parse().unwrap();
            let Query(page) = Query::<IssuePage>::try_from_uri(&uri).unwrap();
            assert_eq!(page.state.as_ref().map(IssueState::as_str), expected);
            assert!(page.bounds().is_ok());
        }
        for query in [
            "?state=",
            "?state=all",
            "?state=Open",
            "?state=open&state=closed",
            "?state=open&state=open",
            "?state=open&unknown=1",
        ] {
            let uri = format!("/issues{query}").parse().unwrap();
            assert!(Query::<IssuePage>::try_from_uri(&uri).is_err());
        }
        let uri = "/comments?state=open".parse().unwrap();
        assert!(Query::<Page>::try_from_uri(&uri).is_err());
        for query in [
            "?state=open&after=-1",
            "?state=closed&limit=0",
            "?state=open&limit=101",
        ] {
            let uri = format!("/issues{query}").parse().unwrap();
            let Query(page) = Query::<IssuePage>::try_from_uri(&uri).unwrap();
            assert!(page.bounds().is_err());
        }
    }

    #[test]
    fn idempotency_header_boundaries() {
        let mut headers = HeaderMap::new();
        assert_eq!(idempotency_key(&headers).unwrap(), None);
        for key in ["a".to_owned(), "A9._:-".to_owned(), "x".repeat(128)] {
            headers.insert("idempotency-key", key.parse().unwrap());
            assert_eq!(idempotency_key(&headers).unwrap(), Some(key.as_str()));
        }
        for key in [
            "".to_owned(),
            "x".repeat(129),
            "two words".to_owned(),
            "x,y".to_owned(),
            "x/y".to_owned(),
        ] {
            headers.insert("idempotency-key", key.parse().unwrap());
            assert!(idempotency_key(&headers).is_err());
        }
        headers.insert("idempotency-key", "one".parse().unwrap());
        headers.append("idempotency-key", "one".parse().unwrap());
        assert!(idempotency_key(&headers).is_err());
        headers.clear();
        headers.insert(
            "idempotency-key",
            axum::http::HeaderValue::from_bytes(b"nonascii\xff").unwrap(),
        );
        assert!(idempotency_key(&headers).is_err());
    }

    #[test]
    fn input_and_pagination_boundaries() {
        assert!(title_valid(&"a".repeat(256)));
        for bad in [
            "".into(),
            "  \t".into(),
            "a\nb".into(),
            "a\0b".into(),
            "a".repeat(257),
            "界".repeat(86),
        ] {
            assert!(!title_valid(&bad));
        }
        assert!(body_valid("", false));
        assert!(body_valid("line\n\ttwo\r\n", true));
        assert!(body_valid(&"x".repeat(8192), true));
        assert!(!body_valid(&"x".repeat(8193), true));
        assert!(!body_valid(" \n\t", true));
        assert!(!body_valid("bad\0value", false));
        assert_eq!(
            Page {
                after: None,
                limit: None
            }
            .bounds()
            .unwrap(),
            (0, 50)
        );
        for page in [
            Page {
                after: Some(-1),
                limit: None,
            },
            Page {
                after: None,
                limit: Some(0),
            },
            Page {
                after: None,
                limit: Some(101),
            },
        ] {
            assert!(page.bounds().is_err());
        }
    }
}
