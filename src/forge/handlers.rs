//! Issue models, validation, and transactional handlers.
use crate::{AppState, Error, auth::{self, finish_tx as finish, idempotency_key}};
use axum::{Json, extract::{Path, Query, State}, http::{HeaderMap, StatusCode, header}, response::{IntoResponse, Response}};
use deadpool_postgres::Transaction;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use tokio_postgres::Row;
use uuid::Uuid;

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
    pub(super) body: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommentPatch {
    pub(super) expected_version: i64,
    pub(super) body: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    pub(super) after: Option<i64>,
    pub(super) limit: Option<i64>,
}
impl Page {
    pub(super) fn bounds(&self) -> Result<(i64, i64), Error> {
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
    pub(super) after: Option<i64>,
    pub(super) limit: Option<i64>,
    pub(super) state: Option<IssueState>,
}
impl IssuePage {
    pub(super) fn bounds(&self) -> Result<(i64, i64), Error> {
        Page {
            after: self.after,
            limit: self.limit,
        }
        .bounds()
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub(super) enum IssueState {
    Open,
    Closed,
}
impl IssueState {
    pub(super) fn as_str(&self) -> &'static str {
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
pub(super) struct Comment {
    repository_id: Uuid,
    issue_number: i64,
    pub(super) number: i64,
    author_id: Uuid,
    body: String,
    version: i64,
    created_at: String,
    updated_at: String,
}
impl Comment {
    pub(super) fn row(row: &Row) -> Self {
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
pub(super) const COMMENT_FIELDS: &str =
    "repository_id,issue_number,number,author_id,body,version,created_at::text,updated_at::text";

pub(super) fn json(status: StatusCode, value: impl Serialize) -> Response {
    (status, [(header::CACHE_CONTROL, "no-store")], Json(value)).into_response()
}
pub(super) fn positive(number: i64) -> Result<(), Error> {
    if number <= 0 {
        Err(Error::bad_request())
    } else {
        Ok(())
    }
}
pub(super) fn title_valid(title: &str) -> bool {
    !title.trim().is_empty() && title.len() <= 256 && !title.chars().any(char::is_control)
}
pub(super) fn body_valid(body: &str, required: bool) -> bool {
    body.len() <= 8192
        && (!required || !body.trim().is_empty())
        && !body
            .chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
}

pub(super) async fn creation_replay(
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

pub(super) async fn record_creation(
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
pub(super) async fn issue_exists(
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
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, auth::Role::Triage, crate::token_scopes::RepoAction::IssuesWrite).await?;
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
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, auth::Role::Read, crate::token_scopes::RepoAction::IssuesRead).await?;
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
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, auth::Role::Read, crate::token_scopes::RepoAction::IssuesRead).await?;
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
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, auth::Role::Triage, crate::token_scopes::RepoAction::IssuesWrite).await?;
    let (repo, tenant_id) = (access.repo_id, access.owner_id);
    issue_exists(&tx, tenant_id, repo, number).await?;
    let row = tx.query_opt(&format!("UPDATE forge_issues SET title=COALESCE($5,title),body=COALESCE($6,body),state=COALESCE($7,state),version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 AND version=$4 RETURNING {ISSUE_FIELDS}"), &[&tenant_id,&repo,&number,&input.expected_version,&input.title,&input.body,&input.state]).await.map_err(Error::internal)?.ok_or(Error(StatusCode::CONFLICT,"issue version conflict"))?;
    let issue = Issue::row(&row);
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, issue))
}

