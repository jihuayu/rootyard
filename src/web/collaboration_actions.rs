//! Web UI collaboration action handlers (POST/form-compatible under session + CSRF).

use super::{
    collaboration::{render_labels_html_for, web_prefix},
    collaboration_views::{
        WebAssigneesForm, WebCommentEditForm, WebCommentModerateForm, WebLabelsForm,
        WebNewLabelForm, WebNewReviewCommentForm, WebSubscriptionForm, WebUpdateLabelForm,
        WebVersionForm,
    },
    handlers::{load_header_ctx, normalize_web_headers},
    models::RepoHeaderCtx,
    templates::html_response,
};
use crate::{
    AppState, Error,
    auth::{self, finish_tx as finish, idempotency_key},
    db::Identity,
    forge::{
        assignees::apply_target_assignees_tx,
        comments::update_issue_comment_tx,
        handlers::{body_valid, creation_replay, json, record_creation},
        label_targets::apply_target_labels_tx,
        labels::{
            create_label_tx, normalize_label_color, normalize_label_name,
            validate_label_description,
        },
        moderation::{
            ModerateCommentInput, delete_issue_comment_tx, moderate_issue_comment_tx,
        },
        notifications::{ReadAllInput, mark_all_notifications_read_tx, mark_notification_read_tx},
        subscriptions::{SubscriptionInput, delete_subscription_tx, upsert_subscription_tx},
    },
    members::{audit, models::{self as member_models, RepoAccess, Role}},
    pulls::{
        models::{positive, repo_tenant_id},
        review_comments::{NewPullReviewComment, create_review_comment},
    },
    token_scopes::RepoAction,
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, Uri},
    response::Response,
};
use deadpool_postgres::Transaction;
use serde_json::json as sjson;
use std::sync::Arc;
use uuid::Uuid;

type App = State<Arc<AppState>>;
type Res = Result<Response, Error>;

pub(in crate::web) async fn auth_web_actor(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(HeaderMap, Identity), Error> {
    member_models::ensure_schema(&state.pool).await?;
    let norm = normalize_web_headers(headers);
    let actor = auth::authenticate(&state.pool, &norm).await?;
    Ok((norm, actor))
}

pub(in crate::web) async fn authorize_web_repo_tx(
    tx: &Transaction<'_>,
    actor: &Identity,
    repo: (&str, &str),
    min_role: Role,
    action: RepoAction,
) -> Result<(RepoAccess, RepoHeaderCtx), Error> {
    let (owner, name) = repo;
    let access = auth::authorize_repo_with_role(tx, actor, owner, name, min_role, action).await?;
    let header_ctx = load_header_ctx(tx, owner, name, actor, access).await?;
    Ok((access, header_ctx))
}

fn split_csv(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

pub(in crate::web) async fn mark_read_web(
    State(state): App,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Res {
    let (_norm, actor) = auth_web_actor(&state, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, true).await?;
    let (notification, already_read) = mark_notification_read_tx(&tx, &actor, id).await?;
    finish(tx, &actor, true).await?;
    Ok(json(
        StatusCode::OK,
        sjson!({ "notification": notification, "already_read": already_read }),
    ))
}

pub(in crate::web) async fn mark_all_read_web(State(state): App, headers: HeaderMap) -> Res {
    let (_norm, actor) = auth_web_actor(&state, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, true).await?;
    let updated_count =
        mark_all_notifications_read_tx(&tx, &actor, &ReadAllInput::default()).await?;
    finish(tx, &actor, true).await?;
    Ok(json(
        StatusCode::OK,
        sjson!({ "updated_count": updated_count }),
    ))
}

async fn subscription_web_inner(
    state: Arc<AppState>,
    headers: HeaderMap,
    repo: (String, String),
    target: (&'static str, i64),
    action: RepoAction,
    input: WebSubscriptionForm,
) -> Res {
    let (owner, name) = repo;
    let (target_type, target_number) = target;
    let (_norm, actor) = auth_web_actor(&state, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, true).await?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Read, action).await?;
    let tenant_id = repo_tenant_id(&tx, access.repo_id).await?;
    let payload = match input.action.as_str() {
        "subscribe" | "subscribed" => {
            let sub = upsert_subscription_tx(
                &tx,
                tenant_id,
                access.repo_id,
                actor.id,
                target_type,
                target_number,
                &SubscriptionInput {
                    state: "subscribed".to_owned(),
                    expected_version: input.expected_version,
                },
            )
            .await?;
            serde_json::to_value(sub).map_err(Error::internal)?
        }
        "ignore" | "ignored" => {
            let sub = upsert_subscription_tx(
                &tx,
                tenant_id,
                access.repo_id,
                actor.id,
                target_type,
                target_number,
                &SubscriptionInput {
                    state: "ignored".to_owned(),
                    expected_version: input.expected_version,
                },
            )
            .await?;
            serde_json::to_value(sub).map_err(Error::internal)?
        }
        "unsubscribe" | "delete" => {
            delete_subscription_tx(
                &tx,
                tenant_id,
                access.repo_id,
                actor.id,
                target_type,
                target_number,
                input.expected_version,
            )
            .await?;
            sjson!({ "unsubscribed": true })
        }
        _ => return Err(Error::bad_request()),
    };
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, payload))
}

pub(in crate::web) async fn repo_subscription_web(State(s): App, Path((o, n)): Path<(String, String)>, h: HeaderMap, Json(i): Json<WebSubscriptionForm>) -> Res {
    subscription_web_inner(s, h, (o, n), ("repository", 0), RepoAction::RepoRead, i).await
}
pub(in crate::web) async fn issue_subscription_web(State(s): App, Path((o, n, num)): Path<(String, String, i64)>, h: HeaderMap, Json(i): Json<WebSubscriptionForm>) -> Res {
    positive(num)?;
    subscription_web_inner(s, h, (o, n), ("issue", num), RepoAction::IssuesRead, i).await
}
pub(in crate::web) async fn pull_subscription_web(State(s): App, Path((o, n, num)): Path<(String, String, i64)>, h: HeaderMap, Json(i): Json<WebSubscriptionForm>) -> Res {
    positive(num)?;
    subscription_web_inner(s, h, (o, n), ("pull", num), RepoAction::PullsRead, i).await
}

pub(in crate::web) async fn create_label_web(
    State(state): App,
    Path((owner, name)): Path<(String, String)>,
    uri: Uri,
    headers: HeaderMap,
    Json(input): Json<WebNewLabelForm>,
) -> Res {
    let prefix = web_prefix(&uri);
    let (norm, actor) = auth_web_actor(&state, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let (access, header_ctx) =
        authorize_web_repo_tx(&tx, &actor, (&owner, &name), Role::Triage, RepoAction::IssuesWrite).await?;
    let new_label = crate::forge::labels::NewLabel {
        name: input.name,
        color: input.color,
        description: input.description,
    };
    let key = idempotency_key(&norm)?;
    if let Some(k) = key {
        let req = sjson!({ "operation": "web_label", "name": new_label.name, "color": new_label.color, "description": new_label.description });
        if creation_replay(&tx, access.owner_id, access.repo_id, k, &req).await?.is_some() {
            let html = render_labels_html_for(&tx, prefix, &header_ctx).await?;
            finish(tx, &actor, true).await?;
            return Ok(html_response(StatusCode::CREATED, html));
        }
    }
    let created = create_label_tx(&tx, access.owner_id, access.repo_id, &actor, &new_label).await?;
    let val = serde_json::to_value(&created).map_err(Error::internal)?;
    record_creation(&tx, access.owner_id, access.repo_id, key, &val).await?;
    let html = render_labels_html_for(&tx, prefix, &header_ctx).await?;
    finish(tx, &actor, true).await?;
    Ok(html_response(StatusCode::CREATED, html))
}

pub(in crate::web) async fn update_label_web(
    State(state): App,
    Path((owner, name, label)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
    Json(input): Json<WebUpdateLabelForm>,
) -> Res {
    let cur = normalize_label_name(&label)?;
    positive(input.expected_version)?;
    let new_name = input.name.as_deref().map(normalize_label_name).transpose()?;
    let new_color = input.color.as_deref().map(normalize_label_color).transpose()?;
    if let Some(ref desc) = input.description {
        validate_label_description(desc)?;
    }
    let prefix = web_prefix(&uri);
    let (_norm, actor) = auth_web_actor(&state, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let (access, header_ctx) =
        authorize_web_repo_tx(&tx, &actor, (&owner, &name), Role::Triage, RepoAction::IssuesWrite).await?;
    let updated = tx
        .execute(
            "UPDATE forge_labels SET name=COALESCE($5,name),color=COALESCE($6,color),description=COALESCE($7,description),version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND repository_id=$2 AND name=$3 AND version=$4",
            &[&access.owner_id, &access.repo_id, &cur, &input.expected_version, &new_name, &new_color, &input.description],
        )
        .await
        .map_err(Error::internal)?;
    if updated == 0 {
        return Err(Error(StatusCode::CONFLICT, "label version conflict"));
    }
    let html = render_labels_html_for(&tx, prefix, &header_ctx).await?;
    finish(tx, &actor, true).await?;
    Ok(html_response(StatusCode::OK, html))
}

pub(in crate::web) async fn delete_label_web(
    State(state): App,
    Path((owner, name, label)): Path<(String, String, String)>,
    uri: Uri,
    headers: HeaderMap,
    Json(input): Json<WebVersionForm>,
) -> Res {
    let cur = normalize_label_name(&label)?;
    positive(input.expected_version)?;
    let prefix = web_prefix(&uri);
    let (_norm, actor) = auth_web_actor(&state, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let (access, header_ctx) =
        authorize_web_repo_tx(&tx, &actor, (&owner, &name), Role::Triage, RepoAction::IssuesWrite).await?;
    let deleted = tx
        .execute(
            "DELETE FROM forge_labels WHERE tenant_id=$1 AND repository_id=$2 AND name=$3 AND version=$4",
            &[&access.owner_id, &access.repo_id, &cur, &input.expected_version],
        )
        .await
        .map_err(Error::internal)?;
    if deleted == 0 {
        return Err(Error(StatusCode::CONFLICT, "label version conflict"));
    }
    audit::record_audit_event(&tx, access.owner_id, access.repo_id, &actor, "label.deleted", "label", &cur, sjson!({})).await?;
    let html = render_labels_html_for(&tx, prefix, &header_ctx).await?;
    finish(tx, &actor, true).await?;
    Ok(html_response(StatusCode::OK, html))
}

async fn target_labels_web(state: Arc<AppState>, headers: HeaderMap, repo: (String, String), target: (&'static str, i64), action: RepoAction, input: WebLabelsForm) -> Res {
    let (owner, name) = repo;
    let (kind, number) = target;
    let (_norm, actor) = auth_web_actor(&state, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let (access, _) = authorize_web_repo_tx(&tx, &actor, (&owner, &name), Role::Triage, action).await?;
    let labels = split_csv(&input.labels);
    let (label_version, items) = apply_target_labels_tx(&tx, (access.owner_id, access.repo_id), &actor, (kind, number), true, input.expected_version, &labels).await?;
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, sjson!({ "label_version": label_version, "items": items })))
}

async fn target_assignees_web(state: Arc<AppState>, headers: HeaderMap, repo: (String, String), target: (&'static str, i64), action: RepoAction, input: WebAssigneesForm) -> Res {
    let (owner, name) = repo;
    let (kind, number) = target;
    let (_norm, actor) = auth_web_actor(&state, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let (access, _) = authorize_web_repo_tx(&tx, &actor, (&owner, &name), Role::Triage, action).await?;
    let assignees = split_csv(&input.assignees);
    let (assignee_version, items) = apply_target_assignees_tx(&tx, (access.owner_id, access.repo_id), &actor, (kind, number), true, input.expected_version, &assignees).await?;
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, sjson!({ "assignee_version": assignee_version, "items": items })))
}

pub(in crate::web) async fn issue_labels_web(State(s): App, Path((o, n, num)): Path<(String, String, i64)>, h: HeaderMap, Json(i): Json<WebLabelsForm>) -> Res {
    target_labels_web(s, h, (o, n), ("issue", num), RepoAction::IssuesWrite, i).await
}
pub(in crate::web) async fn pull_labels_web(State(s): App, Path((o, n, num)): Path<(String, String, i64)>, h: HeaderMap, Json(i): Json<WebLabelsForm>) -> Res {
    target_labels_web(s, h, (o, n), ("pull", num), RepoAction::PullsWrite, i).await
}
pub(in crate::web) async fn issue_assignees_web(State(s): App, Path((o, n, num)): Path<(String, String, i64)>, h: HeaderMap, Json(i): Json<WebAssigneesForm>) -> Res {
    target_assignees_web(s, h, (o, n), ("issue", num), RepoAction::IssuesWrite, i).await
}
pub(in crate::web) async fn pull_assignees_web(State(s): App, Path((o, n, num)): Path<(String, String, i64)>, h: HeaderMap, Json(i): Json<WebAssigneesForm>) -> Res {
    target_assignees_web(s, h, (o, n), ("pull", num), RepoAction::PullsWrite, i).await
}

pub(in crate::web) async fn edit_issue_comment_web(State(state): App, Path((owner, name, number, comment_number)): Path<(String, String, i64, i64)>, headers: HeaderMap, Json(input): Json<WebCommentEditForm>) -> Res {
    positive(number)?;
    positive(comment_number)?;
    positive(input.expected_version)?;
    if !body_valid(&input.body, true) {
        return Err(Error::bad_request());
    }
    let (_norm, actor) = auth_web_actor(&state, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let (access, _) = authorize_web_repo_tx(&tx, &actor, (&owner, &name), Role::Triage, RepoAction::IssuesWrite).await?;
    let comment = update_issue_comment_tx(&tx, (access.owner_id, access.repo_id), &actor, access.role, (number, comment_number), (input.expected_version, &input.body)).await?;
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, comment))
}

pub(in crate::web) async fn delete_issue_comment_web(State(state): App, Path((owner, name, number, comment_number)): Path<(String, String, i64, i64)>, headers: HeaderMap, Json(input): Json<WebVersionForm>) -> Res {
    let (_norm, actor) = auth_web_actor(&state, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let (access, _) = authorize_web_repo_tx(&tx, &actor, (&owner, &name), Role::Triage, RepoAction::IssuesWrite).await?;
    let comment = delete_issue_comment_tx(&tx, (access.owner_id, access.repo_id), &actor, access.role, (number, comment_number), input.expected_version).await?;
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, comment))
}

pub(in crate::web) async fn moderate_issue_comment_web(State(state): App, Path((owner, name, number, comment_number)): Path<(String, String, i64, i64)>, headers: HeaderMap, Json(input): Json<WebCommentModerateForm>) -> Res {
    let (_norm, actor) = auth_web_actor(&state, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let (access, _) = authorize_web_repo_tx(&tx, &actor, (&owner, &name), Role::Maintain, RepoAction::IssuesWrite).await?;
    let comment = moderate_issue_comment_tx(&tx, access.owner_id, access.repo_id, &actor, number, comment_number, &ModerateCommentInput { expected_version: input.expected_version, action: input.action, reason: input.reason }).await?;
    finish(tx, &actor, true).await?;
    Ok(json(StatusCode::OK, comment))
}

pub(in crate::web) async fn create_review_comment_web(State(state): App, Path((owner, name, number)): Path<(String, String, i64)>, headers: HeaderMap, Json(input): Json<WebNewReviewCommentForm>) -> Res {
    let norm = normalize_web_headers(&headers);
    create_review_comment(
        State(state),
        Path((owner, name, number)),
        norm,
        Json(NewPullReviewComment {
            path: input.path,
            side: input.side,
            line: input.line,
            body: input.body,
            commit_oid: input.commit_oid,
            base_oid: input.base_oid,
            review_number: input.review_number,
            in_reply_to_number: input.in_reply_to_number,
        }),
    )
    .await
}

pub(in crate::web) async fn edit_review_comment_web(State(state): App, Path((owner, name, number, comment_number)): Path<(String, String, i64, i64)>, headers: HeaderMap, Json(input): Json<WebCommentEditForm>) -> Res {
    let norm = normalize_web_headers(&headers);
    crate::pulls::review_comment_actions::update_review_comment(
        State(state),
        Path((owner, name, number, comment_number)),
        norm,
        Json(crate::pulls::review_comment_actions::PatchPullReviewComment { expected_version: input.expected_version, body: input.body }),
    )
    .await
}

pub(in crate::web) async fn delete_review_comment_web(State(state): App, Path((owner, name, number, comment_number)): Path<(String, String, i64, i64)>, headers: HeaderMap, Json(input): Json<WebVersionForm>) -> Res {
    let norm = normalize_web_headers(&headers);
    crate::pulls::review_comment_actions::delete_review_comment(
        State(state),
        Path((owner, name, number, comment_number)),
        axum::extract::Query(crate::forge::moderation::ExpectedVersionQuery { expected_version: input.expected_version }),
        norm,
    )
    .await
}

pub(in crate::web) async fn moderate_review_comment_web(State(state): App, Path((owner, name, number, comment_number)): Path<(String, String, i64, i64)>, headers: HeaderMap, Json(input): Json<WebCommentModerateForm>) -> Res {
    let norm = normalize_web_headers(&headers);
    crate::pulls::review_comment_actions::moderate_review_comment(
        State(state),
        Path((owner, name, number, comment_number)),
        norm,
        Json(ModerateCommentInput { expected_version: input.expected_version, action: input.action, reason: input.reason }),
    )
    .await
}
