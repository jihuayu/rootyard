//! Web UI collaboration pages (`/web/*` and `/ui/*`) and detail enrichment hooks.

use super::{
    collaboration_actions as actions,
    collaboration_views::{
        WebNotificationQuery, WebSearchQuery, inject_before_main_end, render_issue_collab_html,
        render_labels_view, render_notifications_view, render_overview_collab_html,
        render_pull_collab_html, render_search_view,
    },
    handlers::{authenticate_web, normalize_web_headers},
    models::{CommentViewItem, IssueViewItem, OverviewViewData, PullDetailViewData, RepoHeaderCtx},
    templates::{self, html_response},
};
use crate::{
    AppState, Error,
    auth::{self, finish_tx as finish},
    db::Identity,
    forge::{
        assignees::load_target_assignees,
        labels::{load_repo_labels, load_target_labels},
        notifications::{NotificationQuery, NotifySpec, emit_repo_notifications, load_notifications_page},
        search::{SearchQuery, SearchScope, SearchSort, execute_search},
        subscriptions::load_subscription_state,
    },
    members::models::Role,
    pulls::{
        models::PullRequest,
        review_comments::{PullReviewComment, REVIEW_COMMENT_FIELDS},
    },
    token_scopes::RepoAction,
};
use axum::{
    Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, Uri},
    response::Response,
    routing::{get, post},
};
use deadpool_postgres::Transaction;
use std::sync::Arc;
use uuid::Uuid;

type App = State<Arc<AppState>>;
type Res = Result<Response, Error>;

pub(in crate::web) fn web_prefix(uri: &Uri) -> &'static str {
    if uri.path().starts_with("/ui") { "/ui" } else { "/web" }
}

pub(in crate::web) fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/web/search", get(search_global_web))
        .route("/ui/search", get(search_global_web))
        .route("/web/notifications", get(notifications_web))
        .route("/ui/notifications", get(notifications_web))
        .route("/web/notifications/read-all", post(actions::mark_all_read_web))
        .route("/ui/notifications/read-all", post(actions::mark_all_read_web))
        .route("/web/notifications/{id}/read", post(actions::mark_read_web))
        .route("/ui/notifications/{id}/read", post(actions::mark_read_web))
        .merge(repo_pages("/web"))
        .merge(repo_pages("/ui"))
}

fn repo_pages(prefix: &str) -> Router<Arc<AppState>> {
    let p = |tail: &str| format!("{prefix}/repos/{{owner}}/{{name}}{tail}");
    Router::new()
        .route(&p("/search"), get(search_repo_web))
        .route(&p("/labels"), get(labels_page_web).post(actions::create_label_web))
        .route(&p("/labels/{label}/update"), post(actions::update_label_web))
        .route(&p("/labels/{label}/delete"), post(actions::delete_label_web))
        .route(&p("/subscription"), post(actions::repo_subscription_web))
        .route(&p("/issues/{number}/subscription"), post(actions::issue_subscription_web))
        .route(&p("/issues/{number}/labels"), post(actions::issue_labels_web))
        .route(&p("/issues/{number}/assignees"), post(actions::issue_assignees_web))
        .route(&p("/issues/{number}/comments/{comment_number}/edit"), post(actions::edit_issue_comment_web))
        .route(&p("/issues/{number}/comments/{comment_number}/delete"), post(actions::delete_issue_comment_web))
        .route(&p("/issues/{number}/comments/{comment_number}/moderate"), post(actions::moderate_issue_comment_web))
        .route(&p("/pulls/{number}/subscription"), post(actions::pull_subscription_web))
        .route(&p("/pulls/{number}/labels"), post(actions::pull_labels_web))
        .route(&p("/pulls/{number}/assignees"), post(actions::pull_assignees_web))
        .route(&p("/pulls/{number}/review-comments"), post(actions::create_review_comment_web))
        .route(&p("/pulls/{number}/review-comments/{comment_number}/edit"), post(actions::edit_review_comment_web))
        .route(&p("/pulls/{number}/review-comments/{comment_number}/delete"), post(actions::delete_review_comment_web))
        .route(&p("/pulls/{number}/review-comments/{comment_number}/moderate"), post(actions::moderate_review_comment_web))
}

pub(in crate::web) async fn on_web_issue_created(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repo_id: Uuid,
    actor_id: Uuid,
    number: i64,
    title: &str,
    body: &str,
) -> Result<(), Error> {
    emit_repo_notifications(
        tx,
        NotifySpec {
            tenant_id,
            repository_id: repo_id,
            actor_id,
            target_type: "issue",
            target_number: number,
            thread_type: "issue",
            thread_number: number,
            event_kind: "issue_opened",
            delivery_key: &format!("issue:{repo_id}:{number}:opened"),
            title: &format!("Issue #{number}: {title}"),
            body_excerpt: body,
            extra_recipients: &[],
        },
    )
    .await
}

pub(in crate::web) async fn on_web_comment_created(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repo_id: Uuid,
    actor_id: Uuid,
    issue_number: i64,
    comment_number: i64,
    body: &str,
) -> Result<(), Error> {
    emit_repo_notifications(
        tx,
        NotifySpec {
            tenant_id,
            repository_id: repo_id,
            actor_id,
            target_type: "issue",
            target_number: issue_number,
            thread_type: "issue",
            thread_number: issue_number,
            event_kind: "issue_commented",
            delivery_key: &format!("issue:{repo_id}:{issue_number}:comment:{comment_number}"),
            title: &format!("Comment #{comment_number} on issue #{issue_number}"),
            body_excerpt: body,
            extra_recipients: &[],
        },
    )
    .await
}

pub(in crate::web) async fn render_labels_html_for(
    tx: &Transaction<'_>,
    prefix: &str,
    header: &RepoHeaderCtx,
) -> Result<String, Error> {
    let (labels, _) = load_repo_labels(tx, header.owner_id, header.repository_id, "", 100).await?;
    Ok(render_labels_view(prefix, header, &labels))
}

pub(in crate::web) async fn render_repo_overview(
    state: &Arc<AppState>,
    actor: &Identity,
    data: &OverviewViewData,
) -> Result<String, Error> {
    let base_html = templates::render_repo_overview(data);
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let label_count: i64 = tx
        .query_one(
            "SELECT count(*) FROM forge_labels WHERE tenant_id=$1 AND repository_id=$2",
            &[&data.header.owner_id, &data.header.repository_id],
        )
        .await
        .map_err(Error::internal)?
        .get(0);
    let sub = load_subscription_state(
        &tx,
        data.header.owner_id,
        data.header.repository_id,
        actor.id,
        "repository",
        0,
    )
    .await?;
    finish(tx, actor, false).await?;
    Ok(inject_before_main_end(
        base_html,
        &render_overview_collab_html(&data.header, label_count as usize, sub.as_ref()),
    ))
}

pub(in crate::web) async fn render_issue_detail(
    state: &Arc<AppState>,
    actor: &Identity,
    header: &RepoHeaderCtx,
    item: &IssueViewItem,
    comments: &[CommentViewItem],
) -> Result<String, Error> {
    let base_html = templates::render_issue_detail_view(header, item, comments);
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let ver_row = tx
        .query_one(
            "SELECT label_version, assignee_version FROM forge_issues WHERE tenant_id=$1 AND repository_id=$2 AND number=$3",
            &[&header.owner_id, &header.repository_id, &item.issue.number],
        )
        .await
        .map_err(Error::internal)?;
    let label_ver: i64 = ver_row.get("label_version");
    let assignee_ver: i64 = ver_row.get("assignee_version");
    let labels = load_target_labels(&tx, header.owner_id, header.repository_id, "issue", item.issue.number).await?;
    let assignees = load_target_assignees(&tx, header.owner_id, header.repository_id, "issue", item.issue.number).await?;
    let sub = load_subscription_state(&tx, header.owner_id, header.repository_id, actor.id, "issue", item.issue.number).await?;
    finish(tx, actor, false).await?;
    Ok(inject_before_main_end(
        base_html,
        &render_issue_collab_html(
            header,
            item.issue.number,
            (label_ver, assignee_ver),
            &labels,
            &assignees,
            sub.as_ref(),
            comments,
        ),
    ))
}

pub(in crate::web) async fn render_pull_detail(
    state: &Arc<AppState>,
    actor: &Identity,
    header: &RepoHeaderCtx,
    data: &PullDetailViewData,
) -> Result<String, Error> {
    let base_html = templates::render_pull_detail_view(header, data);
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let pull: &PullRequest = &data.pull;
    let labels = load_target_labels(&tx, header.owner_id, header.repository_id, "pull", pull.number).await?;
    let assignees = load_target_assignees(&tx, header.owner_id, header.repository_id, "pull", pull.number).await?;
    let sub = load_subscription_state(&tx, header.owner_id, header.repository_id, actor.id, "pull", pull.number).await?;
    let rc_sql = format!(
        "SELECT {REVIEW_COMMENT_FIELDS}, (SELECT username FROM users WHERE id=author_id) AS author_username \
         FROM forge_pull_review_comments \
         WHERE tenant_id=$1 AND repository_id=$2 AND pull_number=$3 ORDER BY number ASC LIMIT 100"
    );
    let rows = tx
        .query(&rc_sql, &[&header.owner_id, &header.repository_id, &pull.number])
        .await
        .map_err(Error::internal)?;
    let review_comments: Vec<(PullReviewComment, String)> = rows
        .iter()
        .map(|r| {
            let author: Option<String> = r.get("author_username");
            (
                PullReviewComment::row_for_pull(r, &pull.head_oid, &pull.base_oid),
                author.unwrap_or_else(|| "unknown".to_owned()),
            )
        })
        .collect();
    finish(tx, actor, false).await?;
    Ok(inject_before_main_end(
        base_html,
        &render_pull_collab_html(
            header,
            pull,
            &data.reviews,
            &labels,
            &assignees,
            sub.as_ref(),
            &review_comments,
        ),
    ))
}

async fn search_global_web(State(state): App, uri: Uri, Query(q): Query<WebSearchQuery>, headers: HeaderMap) -> Res {
    let norm = normalize_web_headers(&headers);
    let actor = authenticate_web(&state.pool, &norm).await?;
    let scope = q.scope.unwrap_or(SearchScope::All);
    let sort = q.sort.unwrap_or(SearchSort::Updated);
    let (hits, next_cursor) = if let Some(ref raw) = q.q
        && !raw.trim().is_empty()
    {
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        auth::verify_token(&tx, &actor, false).await?;
        let sq = SearchQuery { q: raw.clone(), scope: Some(scope), sort: Some(sort), cursor: q.cursor.clone(), limit: q.limit };
        let res = execute_search(&tx, &actor, None, &sq).await?;
        finish(tx, &actor, false).await?;
        res
    } else {
        (Vec::new(), None)
    };
    Ok(html_response(
        StatusCode::OK,
        render_search_view(web_prefix(&uri), &actor.username, None, q.q.as_deref(), (scope.as_str(), sort.as_str()), &hits, next_cursor.as_deref()),
    ))
}

async fn search_repo_web(State(state): App, Path((owner, name)): Path<(String, String)>, uri: Uri, Query(q): Query<WebSearchQuery>, headers: HeaderMap) -> Res {
    let (_norm, actor) = actions::auth_web_actor(&state, &headers).await?;
    let scope = q.scope.unwrap_or(SearchScope::All);
    let sort = q.sort.unwrap_or(SearchSort::Updated);
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let (access, header_ctx) = actions::authorize_web_repo_tx(&tx, &actor, (&owner, &name), Role::Read, RepoAction::RepoRead).await?;
    let (hits, next_cursor) = if let Some(ref raw) = q.q
        && !raw.trim().is_empty()
    {
        let sq = SearchQuery { q: raw.clone(), scope: Some(scope), sort: Some(sort), cursor: q.cursor.clone(), limit: q.limit };
        execute_search(&tx, &actor, Some(access.repo_id), &sq).await?
    } else {
        (Vec::new(), None)
    };
    finish(tx, &actor, false).await?;
    Ok(html_response(
        StatusCode::OK,
        render_search_view(web_prefix(&uri), &actor.username, Some(&header_ctx), q.q.as_deref(), (scope.as_str(), sort.as_str()), &hits, next_cursor.as_deref()),
    ))
}

async fn notifications_web(State(state): App, uri: Uri, Query(q): Query<WebNotificationQuery>, headers: HeaderMap) -> Res {
    let norm = normalize_web_headers(&headers);
    let actor = authenticate_web(&state.pool, &norm).await?;
    let unread_only = matches!(q.unread_only.as_deref(), Some("true" | "1" | "on"));
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, false).await?;
    let nq = NotificationQuery { unread_only: Some(unread_only), owner: None, repo: None, cursor: q.cursor.clone(), limit: q.limit };
    let (items, next_cursor) = load_notifications_page(&tx, &actor, &nq).await?;
    finish(tx, &actor, false).await?;
    Ok(html_response(
        StatusCode::OK,
        render_notifications_view(web_prefix(&uri), &actor.username, &items, unread_only, next_cursor.as_deref()),
    ))
}

async fn labels_page_web(State(state): App, Path((owner, name)): Path<(String, String)>, uri: Uri, headers: HeaderMap) -> Res {
    let (_norm, actor) = actions::auth_web_actor(&state, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let (_access, header_ctx) = actions::authorize_web_repo_tx(&tx, &actor, (&owner, &name), Role::Read, RepoAction::RepoRead).await?;
    let html = render_labels_html_for(&tx, web_prefix(&uri), &header_ctx).await?;
    finish(tx, &actor, false).await?;
    Ok(html_response(StatusCode::OK, html))
}

#[cfg(test)]
#[path = "collaboration_tests.rs"]
mod tests;
