//! Repository, Issue, and Pull Request subscription endpoints (`forge_subscriptions`).

use crate::{
    AppState, Error,
    auth::{self, finish_tx as finish},
    members::models::Role,
    pulls::models::{pull_exists, repo_tenant_id},
    token_scopes::RepoAction,
};
use axum::{
    Json,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use deadpool_postgres::Transaction;
use serde::{Deserialize, Serialize};
use serde_json::json as sjson;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Subscription {
    pub repository_id: Uuid,
    pub user_id: Uuid,
    pub target_type: String,
    pub target_number: i64,
    pub state: String,
    pub version: i64,
    pub created_at: String,
    pub updated_at: String,
}

impl Subscription {
    pub fn row(row: &tokio_postgres::Row) -> Self {
        Self {
            repository_id: row.get("repository_id"),
            user_id: row.get("user_id"),
            target_type: row.get("target_type"),
            target_number: row.get("target_number"),
            state: row.get("state"),
            version: row.get("version"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubscriptionInput {
    pub state: String,
    pub expected_version: Option<i64>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptionalVersionQuery {
    pub expected_version: Option<i64>,
}

fn json(status: StatusCode, value: impl Serialize) -> Response {
    (status, [(header::CACHE_CONTROL, "no-store")], Json(value)).into_response()
}

pub(crate) async fn load_subscription_state(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repo_id: Uuid,
    user_id: Uuid,
    target_type: &str,
    target_number: i64,
) -> Result<Option<Subscription>, Error> {
    let sql = concat!(
        "SELECT repository_id,user_id,target_type,target_number,state,version,",
        "created_at::text,updated_at::text ",
        "FROM forge_subscriptions ",
        "WHERE tenant_id=$1 AND repository_id=$2 AND user_id=$3 AND target_type=$4 AND target_number=$5"
    );
    let row = tx
        .query_opt(sql, &[&tenant_id, &repo_id, &user_id, &target_type, &target_number])
        .await
        .map_err(Error::internal)?;
    Ok(row.as_ref().map(Subscription::row))
}

async fn ensure_target_exists(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repo_id: Uuid,
    target_type: &str,
    target_number: i64,
) -> Result<(), Error> {
    match target_type {
        "repository" => Ok(()),
        "issue" => {
            tx.query_opt(
                "SELECT number FROM forge_issues WHERE tenant_id=$1 AND repository_id=$2 AND number=$3",
                &[&tenant_id, &repo_id, &target_number],
            )
            .await
            .map_err(Error::internal)?
            .ok_or_else(Error::not_found)?;
            Ok(())
        }
        "pull" => pull_exists(tx, tenant_id, repo_id, target_number).await,
        _ => Err(Error::bad_request()),
    }
}

pub(crate) async fn upsert_subscription_tx(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repo_id: Uuid,
    user_id: Uuid,
    target_type: &str,
    target_number: i64,
    input: &SubscriptionInput,
) -> Result<Subscription, Error> {
    if !matches!(input.state.as_str(), "subscribed" | "ignored") {
        return Err(Error::bad_request());
    }
    if let Some(ev) = input.expected_version
        && ev <= 0
    {
        return Err(Error::bad_request());
    }
    ensure_target_exists(tx, tenant_id, repo_id, target_type, target_number).await?;
    let existing = tx
        .query_opt(
            "SELECT version FROM forge_subscriptions WHERE tenant_id=$1 AND repository_id=$2 AND user_id=$3 AND target_type=$4 AND target_number=$5 FOR UPDATE",
            &[&tenant_id, &repo_id, &user_id, &target_type, &target_number],
        )
        .await
        .map_err(Error::internal)?;
    if let Some(expected) = input.expected_version {
        let cur: Option<i64> = existing.as_ref().map(|r| r.get(0));
        if cur != Some(expected) {
            return Err(Error(StatusCode::CONFLICT, "subscription version conflict"));
        }
    }
    let sql = concat!(
        "INSERT INTO forge_subscriptions (tenant_id,repository_id,user_id,target_type,target_number,state) ",
        "VALUES ($1,$2,$3,$4,$5,$6) ",
        "ON CONFLICT (tenant_id,repository_id,user_id,target_type,target_number) ",
        "DO UPDATE SET state=EXCLUDED.state,version=forge_subscriptions.version+1,updated_at=clock_timestamp() ",
        "RETURNING repository_id,user_id,target_type,target_number,state,version,created_at::text,updated_at::text"
    );
    let row = tx
        .query_one(
            sql,
            &[&tenant_id, &repo_id, &user_id, &target_type, &target_number, &input.state],
        )
        .await
        .map_err(Error::internal)?;
    Ok(Subscription::row(&row))
}

pub(crate) async fn delete_subscription_tx(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repo_id: Uuid,
    user_id: Uuid,
    target_type: &str,
    target_number: i64,
    expected_version: Option<i64>,
) -> Result<(), Error> {
    if let Some(ev) = expected_version
        && ev <= 0
    {
        return Err(Error::bad_request());
    }
    ensure_target_exists(tx, tenant_id, repo_id, target_type, target_number).await?;
    if let Some(ev) = expected_version {
        let deleted = tx
            .execute(
                "DELETE FROM forge_subscriptions WHERE tenant_id=$1 AND repository_id=$2 AND user_id=$3 AND target_type=$4 AND target_number=$5 AND version=$6",
                &[&tenant_id, &repo_id, &user_id, &target_type, &target_number, &ev],
            )
            .await
            .map_err(Error::internal)?;
        if deleted == 0 {
            return Err(Error(StatusCode::CONFLICT, "subscription version conflict"));
        }
    } else {
        tx.execute(
            "DELETE FROM forge_subscriptions WHERE tenant_id=$1 AND repository_id=$2 AND user_id=$3 AND target_type=$4 AND target_number=$5",
            &[&tenant_id, &repo_id, &user_id, &target_type, &target_number],
        )
        .await
        .map_err(Error::internal)?;
    }
    Ok(())
}

async fn get_subscription_inner(
    state: Arc<AppState>,
    headers: HeaderMap,
    owner: String,
    name: String,
    target_type: &'static str,
    target_number: i64,
    action: RepoAction,
) -> Result<Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    if target_type != "repository" && target_number <= 0 {
        return Err(Error::bad_request());
    }
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Read, action).await?;
    let tenant_id = repo_tenant_id(&tx, access.repo_id).await?;
    ensure_target_exists(&tx, tenant_id, access.repo_id, target_type, target_number).await?;
    let sub = load_subscription_state(&tx, tenant_id, access.repo_id, actor.id, target_type, target_number).await?;
    finish(tx, &actor, false).await?;
    Ok(json(
        StatusCode::OK,
        sjson!({ "subscribed": sub.as_ref().is_some_and(|s| s.state == "subscribed"), "subscription": sub }),
    ))
}

async fn put_subscription_inner(
    state: Arc<AppState>,
    headers: HeaderMap,
    repo: (String, String),
    target: (&'static str, i64),
    action: RepoAction,
    input: SubscriptionInput,
) -> Result<Response, Error> {
    let (owner, name) = repo;
    let (target_type, target_number) = target;
    if target_type != "repository" && target_number <= 0 {
        return Err(Error::bad_request());
    }
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, true).await?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Read, action).await?;
    let tenant_id = repo_tenant_id(&tx, access.repo_id).await?;
    let sub = upsert_subscription_tx(&tx, tenant_id, access.repo_id, actor.id, target_type, target_number, &input).await?;
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, sub))
}

async fn delete_subscription_inner(
    state: Arc<AppState>,
    headers: HeaderMap,
    repo: (String, String),
    target: (&'static str, i64),
    action: RepoAction,
    expected_version: Option<i64>,
) -> Result<Response, Error> {
    let (owner, name) = repo;
    let (target_type, target_number) = target;
    if target_type != "repository" && target_number <= 0 {
        return Err(Error::bad_request());
    }
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, true).await?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Read, action).await?;
    let tenant_id = repo_tenant_id(&tx, access.repo_id).await?;
    delete_subscription_tx(&tx, tenant_id, access.repo_id, actor.id, target_type, target_number, expected_version).await?;
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, sjson!({ "unsubscribed": true })))
}

pub async fn get_repo_subscription(State(state): State<Arc<AppState>>, Path((owner, name)): Path<(String, String)>, headers: HeaderMap) -> Result<Response, Error> {
    get_subscription_inner(state, headers, owner, name, "repository", 0, RepoAction::RepoRead).await
}
pub async fn put_repo_subscription(State(state): State<Arc<AppState>>, Path((owner, name)): Path<(String, String)>, headers: HeaderMap, Json(input): Json<SubscriptionInput>) -> Result<Response, Error> {
    put_subscription_inner(state, headers, (owner, name), ("repository", 0), RepoAction::RepoRead, input).await
}
pub async fn delete_repo_subscription(State(state): State<Arc<AppState>>, Path((owner, name)): Path<(String, String)>, Query(q): Query<OptionalVersionQuery>, headers: HeaderMap) -> Result<Response, Error> {
    delete_subscription_inner(state, headers, (owner, name), ("repository", 0), RepoAction::RepoRead, q.expected_version).await
}

pub async fn get_issue_subscription(State(state): State<Arc<AppState>>, Path((owner, name, number)): Path<(String, String, i64)>, headers: HeaderMap) -> Result<Response, Error> {
    get_subscription_inner(state, headers, owner, name, "issue", number, RepoAction::IssuesRead).await
}
pub async fn put_issue_subscription(State(state): State<Arc<AppState>>, Path((owner, name, number)): Path<(String, String, i64)>, headers: HeaderMap, Json(input): Json<SubscriptionInput>) -> Result<Response, Error> {
    put_subscription_inner(state, headers, (owner, name), ("issue", number), RepoAction::IssuesRead, input).await
}
pub async fn delete_issue_subscription(State(state): State<Arc<AppState>>, Path((owner, name, number)): Path<(String, String, i64)>, Query(q): Query<OptionalVersionQuery>, headers: HeaderMap) -> Result<Response, Error> {
    delete_subscription_inner(state, headers, (owner, name), ("issue", number), RepoAction::IssuesRead, q.expected_version).await
}

pub async fn get_pull_subscription(State(state): State<Arc<AppState>>, Path((owner, name, number)): Path<(String, String, i64)>, headers: HeaderMap) -> Result<Response, Error> {
    get_subscription_inner(state, headers, owner, name, "pull", number, RepoAction::PullsRead).await
}
pub async fn put_pull_subscription(State(state): State<Arc<AppState>>, Path((owner, name, number)): Path<(String, String, i64)>, headers: HeaderMap, Json(input): Json<SubscriptionInput>) -> Result<Response, Error> {
    put_subscription_inner(state, headers, (owner, name), ("pull", number), RepoAction::PullsRead, input).await
}
pub async fn delete_pull_subscription(State(state): State<Arc<AppState>>, Path((owner, name, number)): Path<(String, String, i64)>, Query(q): Query<OptionalVersionQuery>, headers: HeaderMap) -> Result<Response, Error> {
    delete_subscription_inner(state, headers, (owner, name), ("pull", number), RepoAction::PullsRead, q.expected_version).await
}
