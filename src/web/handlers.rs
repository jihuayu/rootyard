//! HTTP handlers for Part II Track 1 Web UI (`F33` & `F34`).
//! Enforces 5-role RBAC (`Role::Read` .. `Role::Admin`), read-only token fencing,
//! O(1)-memory streaming preview for large/binary blobs, and strict HTML security headers.
use crate::{
    AppState, Error,
    auth::{self, finish_tx as finish, idempotency_key},
    browse::{git_read, models::{self as browse_models, MAX_DIFF_BYTES}},
    db::Identity,
    members::{
        audit,
        models::{self as member_models, AUDIT_FIELDS, AuditEntry, AuditPage, AuditQuery, RepoAccess, Role},
        rbac,
    },
    pulls::{
        handlers as pull_handlers, merge as pull_merge,
        models::{
            CHECK_FIELDS, CheckRun, MergeInput, NewPull, NewReview, PULL_FIELDS, PullDiffResponse,
            PullPatch, PullRequest, PullReview, PullStateFilter, REVIEW_FIELDS, creation_replay,
            merge_base, positive, record_creation, valid_oid,
        },
        rules,
    },
    web::{
        models::{
            BlobPreview, COMMENT_FIELDS, CommentViewItem, ISSUE_FIELDS, IssueViewItem,
            OverviewViewData, PullDetailViewData, RepoHeaderCtx, WebBlobQuery, WebCheckPanelQuery,
            WebComment, WebCommitsQuery, WebCompareQuery, WebIssue, WebIssueFilterQuery,
            WebIssuePatch, WebNewComment, WebNewIssue, WebPullFilterQuery, WebTreeQuery,
        },
        sanitize::{self, DEFAULT_WEB_BLOB_PREVIEW_BYTES, render_safe_markdown},
        templates::{self, html_response},
    },
};
use axum::{
    Json, extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::Response,
};
use deadpool_postgres::{Pool, Transaction};
use serde_json::json as sjson;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use uuid::Uuid;

type App = State<Arc<AppState>>;
type RepoPath = Path<(String, String)>;
type OidPath = Path<(String, String, String)>;
type NumPath = Path<(String, String, i64)>;
type Res = Result<Response, Error>;

fn extract_cookie_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        if let Some(val) = part.trim().strip_prefix("rootyard_token=").or_else(|| part.trim().strip_prefix("token=")) {
            let clean = val.trim().trim_matches('"');
            if !clean.is_empty() {
                return Some(clean.to_owned());
            }
        }
    }
    None
}

pub fn normalize_web_headers(headers: &HeaderMap) -> HeaderMap {
    if headers.contains_key(header::AUTHORIZATION) {
        return headers.clone();
    }
    let token_opt = super::session::session_token(headers).or_else(|| headers.get("x-rootyard-token").and_then(|v| v.to_str().ok()).map(str::trim).filter(|s| !s.is_empty()).map(str::to_owned)).or_else(|| extract_cookie_token(headers));
    let mut out = headers.clone();
    if let Some(tok) = token_opt {
        let bearer = if tok.starts_with("Bearer ") || tok.starts_with("Basic ") { tok } else { format!("Bearer {tok}") };
        if let Ok(hv) = HeaderValue::from_str(&bearer) {
            out.insert(header::AUTHORIZATION, hv);
        }
    }
    out
}

pub async fn authenticate_web(pool: &Pool, headers: &HeaderMap) -> Result<Identity, Error> {
    auth::authenticate(pool, &normalize_web_headers(headers)).await
}

async fn load_header_ctx(tx: &Transaction<'_>, owner: &str, name: &str, actor: &Identity, access: RepoAccess) -> Result<RepoHeaderCtx, Error> {
    let row = tx.query_one("SELECT storage_backend, storage_generation, state FROM repositories WHERE id = $1", &[&access.repo_id]).await.map_err(Error::internal)?;
    Ok(RepoHeaderCtx {
        owner: owner.to_owned(),
        name: name.to_owned(),
        repository_id: access.repo_id,
        owner_id: access.owner_id,
        effective_role: access.role,
        actor_username: actor.username.clone(),
        storage_backend: row.get("storage_backend"),
        storage_generation: row.get("storage_generation"),
        repo_state: row.get("state"),
    })
}

pub async fn authorize_web_repo(state: &AppState, headers: &HeaderMap, owner: &str, name: &str, min_role: Role) -> Result<(Identity, RepoAccess, RepoHeaderCtx), Error> {
    member_models::ensure_schema(&state.pool).await?;
    let actor = authenticate_web(&state.pool, headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, owner, name, min_role).await?;
    let header_ctx = load_header_ctx(&tx, owner, name, &actor, access).await?;
    finish(tx, &actor, min_role >= Role::Triage).await?;
    Ok((actor, access, header_ctx))
}

async fn resolve_web_commit_or_tree_oid(state: &AppState, repo_id: Uuid, spec_opt: Option<&str>) -> Result<String, Error> {
    let spec = spec_opt.unwrap_or("HEAD");
    if !browse_models::valid_revision_spec(spec) {
        return Err(Error::bad_request());
    }
    if browse_models::valid_non_zero_oid(spec) {
        if !matches!(git_read::object_type(state, repo_id, spec).await?.as_deref(), Some("commit" | "tree")) {
            return Err(Error::not_found());
        }
        return Ok(spec.to_owned());
    }
    git_read::resolve_commit_oid(state, repo_id, spec).await
}

pub async fn read_web_blob_preview(state: &AppState, repo_id: Uuid, oid_or_spec: Option<&str>, rel_path: Option<&str>, max_bytes: usize) -> Result<BlobPreview, Error> {
    let _slot = state.git_slots.clone().try_acquire_owned().map_err(|_| Error(StatusCode::SERVICE_UNAVAILABLE, "Git capacity exhausted; retry later"))?;
    let clean_path = browse_models::normalize_rel_path(rel_path)?;
    let blob_oid = if !clean_path.is_empty() {
        let root_oid = resolve_web_commit_or_tree_oid(state, repo_id, oid_or_spec).await?;
        let spec = format!("{root_oid}:{clean_path}");
        let out = git_read::run_git(state, repo_id, &["rev-parse", "--verify", "--quiet", &spec], 128).await?;
        String::from_utf8_lossy(&out).trim().to_owned()
    } else {
        let raw_oid = oid_or_spec.ok_or_else(Error::bad_request)?;
        if !browse_models::valid_non_zero_oid(raw_oid) {
            return Err(Error::bad_request());
        }
        raw_oid.to_owned()
    };
    if !browse_models::valid_non_zero_oid(&blob_oid) || git_read::object_type(state, repo_id, &blob_oid).await?.as_deref() != Some("blob") {
        return Err(Error::not_found());
    }
    let size_out = git_read::run_git(state, repo_id, &["cat-file", "-s", &blob_oid], 64).await?;
    let total_size: u64 = String::from_utf8_lossy(&size_out).trim().parse().map_err(|_| Error::not_found())?;

    let mut cmd = git_read::git_cmd(state, repo_id)?;
    cmd.args(["cat-file", "blob", &blob_oid])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    let mut child = cmd.spawn().map_err(Error::internal)?;
    let mut stdout = child.stdout.take().ok_or_else(|| Error::internal("missing git stdout"))?;
    let mut raw_prefix = Vec::with_capacity(max_bytes.min(64 * 1024) + 1);
    tokio::time::timeout(state.config.git_timeout, async {
        (&mut stdout).take(max_bytes as u64 + 1).read_to_end(&mut raw_prefix).await.map_err(Error::internal)
    })
    .await
    .map_err(|_| Error::timeout())??;
    let _ = child.start_kill();
    let _ = child.wait().await;
    Ok(sanitize::build_blob_preview(&blob_oid, &clean_path, total_size, &raw_prefix, max_bytes))
}

async fn query_commit_checks(tx: &Transaction<'_>, tenant_id: Uuid, repo_id: Uuid, commit_oid: &str, after: i64, limit: i64) -> Result<Vec<CheckRun>, Error> {
    let q = format!("SELECT {CHECK_FIELDS} FROM forge_check_runs WHERE tenant_id=$1 AND repository_id=$2 AND commit_oid=$3 ORDER BY context ASC OFFSET $4 LIMIT $5");
    let rows = tx.query(&q, &[&tenant_id, &repo_id, &commit_oid, &after, &limit]).await.map_err(Error::internal)?;
    Ok(rows.iter().map(CheckRun::row).collect())
}

async fn lookup_username(tx: &Transaction<'_>, user_id: Uuid) -> Result<String, Error> {
    Ok(tx.query_opt("SELECT username FROM users WHERE id=$1", &[&user_id]).await.map_err(Error::internal)?.map(|u| u.get(0)).unwrap_or_else(|| "unknown".to_owned()))
}

pub async fn repo_overview(State(state): App, Path((owner, name)): RepoPath, headers: HeaderMap) -> Res {
    let (actor, access, header_ctx) = authorize_web_repo(&state, &headers, &owner, &name, Role::Read).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let open_issues: i64 = tx.query_one("SELECT count(*) FROM forge_issues WHERE tenant_id=$1 AND repository_id=$2 AND state='open'", &[&access.owner_id, &access.repo_id]).await.map_err(Error::internal)?.get(0);
    let open_pulls: i64 = tx.query_one("SELECT count(*) FROM forge_pulls WHERE tenant_id=$1 AND repository_id=$2 AND state='open'", &[&access.owner_id, &access.repo_id]).await.map_err(Error::internal)?.get(0);
    finish(tx, &actor, false).await?;
    drop(client);

    let (head, refs) = git_read::read_head_and_refs(&state, access.repo_id).await?;
    let branches: Vec<_> = refs.iter().filter(|r| r.kind == "branch").cloned().collect();
    let tags: Vec<_> = refs.iter().filter(|r| r.kind == "tag").cloned().collect();
    let (latest_commit, tree, readme_html) = if let Some(ref oid) = head.oid {
        let summary = git_read::read_commit_summary(&state, access.repo_id, oid).await.ok();
        let root_tree = git_read::read_tree(&state, access.repo_id, Some(oid), "", None, 100).await.ok();
        let mut readme = None;
        if let Some(ref t) = root_tree {
            if let Some(entry) = t.items.iter().find(|e| e.kind == "blob" && matches!(e.name.to_ascii_lowercase().as_str(), "readme.md" | "readme.markdown" | "readme.txt" | "readme")) {
                if let Ok(preview) = read_web_blob_preview(&state, access.repo_id, Some(&entry.oid), None, DEFAULT_WEB_BLOB_PREVIEW_BYTES).await {
                    readme = preview.text_preview.map(|txt| render_safe_markdown(&txt));
                }
            }
        }
        (summary, root_tree, readme)
    } else {
        (None, None, None)
    };
    let data = OverviewViewData { header: header_ctx, head, branches, tags, latest_commit, tree, readme_html, open_issues, open_pulls };
    Ok(html_response(StatusCode::OK, templates::render_repo_overview(&data)))
}

pub async fn tree_view(State(state): App, Path((owner, name)): RepoPath, Query(query): Query<WebTreeQuery>, headers: HeaderMap) -> Res {
    let (_, access, header_ctx) = authorize_web_repo(&state, &headers, &owner, &name, Role::Read).await?;
    let (spec, rel_path, after, limit) = query.resolve_spec_and_validate(None)?;
    let _slot = state.git_slots.clone().try_acquire_owned().map_err(|_| Error(StatusCode::SERVICE_UNAVAILABLE, "Git capacity exhausted; retry later"))?;
    let tree = git_read::read_tree(&state, access.repo_id, spec, &rel_path, after, limit).await?;
    Ok(html_response(StatusCode::OK, templates::render_tree_view(&header_ctx, &tree)))
}

pub async fn tree_by_oid_view(State(state): App, Path((owner, name, oid)): OidPath, Query(query): Query<WebTreeQuery>, headers: HeaderMap) -> Res {
    let (_, access, header_ctx) = authorize_web_repo(&state, &headers, &owner, &name, Role::Read).await?;
    let (spec, rel_path, after, limit) = query.resolve_spec_and_validate(Some(&oid))?;
    let _slot = state.git_slots.clone().try_acquire_owned().map_err(|_| Error(StatusCode::SERVICE_UNAVAILABLE, "Git capacity exhausted; retry later"))?;
    let tree = git_read::read_tree(&state, access.repo_id, spec, &rel_path, after, limit).await?;
    Ok(html_response(StatusCode::OK, templates::render_tree_view(&header_ctx, &tree)))
}

pub async fn blob_view(State(state): App, Path((owner, name)): RepoPath, Query(query): Query<WebBlobQuery>, headers: HeaderMap) -> Res {
    let (_, access, header_ctx) = authorize_web_repo(&state, &headers, &owner, &name, Role::Read).await?;
    let preview = read_web_blob_preview(&state, access.repo_id, query.resolve_spec(None)?, query.path.as_deref(), query.validate_max_bytes()?).await?;
    Ok(html_response(StatusCode::OK, templates::render_blob_view(&header_ctx, &preview)))
}

pub async fn blob_by_oid_view(State(state): App, Path((owner, name, oid)): OidPath, Query(query): Query<WebBlobQuery>, headers: HeaderMap) -> Res {
    let (_, access, header_ctx) = authorize_web_repo(&state, &headers, &owner, &name, Role::Read).await?;
    let preview = read_web_blob_preview(&state, access.repo_id, query.resolve_spec(Some(&oid))?, query.path.as_deref(), query.validate_max_bytes()?).await?;
    Ok(html_response(StatusCode::OK, templates::render_blob_view(&header_ctx, &preview)))
}

pub async fn commits_view(State(state): App, Path((owner, name)): RepoPath, Query(query): Query<WebCommitsQuery>, headers: HeaderMap) -> Res {
    let (_, access, header_ctx) = authorize_web_repo(&state, &headers, &owner, &name, Role::Read).await?;
    let (spec, after, limit) = query.validate()?;
    let _slot = state.git_slots.clone().try_acquire_owned().map_err(|_| Error(StatusCode::SERVICE_UNAVAILABLE, "Git capacity exhausted; retry later"))?;
    let commits = git_read::list_commits(&state, access.repo_id, spec, after, limit).await?;
    Ok(html_response(StatusCode::OK, templates::render_commits_view(&header_ctx, spec, &commits)))
}

pub async fn commit_detail_view(State(state): App, Path((owner, name, oid)): OidPath, headers: HeaderMap) -> Res {
    let (actor, access, header_ctx) = authorize_web_repo(&state, &headers, &owner, &name, Role::Read).await?;
    let detail = git_read::get_commit_detail(&state, access.repo_id, &oid).await?;
    let diff_raw = git_read::run_git(&state, access.repo_id, &["show", "--format=", "--patch", "--no-color", "--no-ext-diff", &oid], MAX_DIFF_BYTES).await.unwrap_or_default();
    let diff = String::from_utf8_lossy(&diff_raw).into_owned();
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let checks = query_commit_checks(&tx, access.owner_id, access.repo_id, &oid, 0, 50).await?;
    finish(tx, &actor, false).await?;
    Ok(html_response(StatusCode::OK, templates::render_commit_detail_view(&header_ctx, &detail, &checks, &diff)))
}

pub async fn commit_checks_view(State(state): App, Path((owner, name, oid)): OidPath, Query(query): Query<WebCheckPanelQuery>, headers: HeaderMap) -> Res {
    if !valid_oid(&oid) {
        return Err(Error::bad_request());
    }
    let (after, limit) = query.validate()?;
    let (actor, access, header_ctx) = authorize_web_repo(&state, &headers, &owner, &name, Role::Read).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let checks = query_commit_checks(&tx, access.owner_id, access.repo_id, &oid, after, limit).await?;
    finish(tx, &actor, false).await?;
    Ok(html_response(StatusCode::OK, templates::render_check_runs_panel(&header_ctx, &oid, None, &checks)))
}

pub async fn compare_view(State(state): App, Path((owner, name)): RepoPath, Query(query): Query<WebCompareQuery>, headers: HeaderMap) -> Res {
    let (_, access, header_ctx) = authorize_web_repo(&state, &headers, &owner, &name, Role::Read).await?;
    let (base, head) = query.validate()?;
    let _slot = state.git_slots.clone().try_acquire_owned().map_err(|_| Error(StatusCode::SERVICE_UNAVAILABLE, "Git capacity exhausted; retry later"))?;
    let cmp = git_read::compare_commits(&state, access.repo_id, base, head).await?;
    Ok(html_response(StatusCode::OK, templates::render_compare_view(&header_ctx, base, head, &cmp)))
}

pub async fn issues_list_view(State(state): App, Path((owner, name)): RepoPath, Query(query): Query<WebIssueFilterQuery>, headers: HeaderMap) -> Res {
    let (filter_state, after, limit) = query.validate()?;
    let (actor, access, header_ctx) = authorize_web_repo(&state, &headers, &owner, &name, Role::Read).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let q = format!("SELECT {ISSUE_FIELDS} FROM forge_issues WHERE tenant_id=$1 AND repository_id=$2 AND number>$3 AND ($5::text IS NULL OR state=$5) ORDER BY number ASC LIMIT $4");
    let rows = tx.query(&q, &[&access.owner_id, &access.repo_id, &after, &(limit + 1), &filter_state]).await.map_err(Error::internal)?;
    let more = rows.len() > limit as usize;
    let mut items = Vec::with_capacity(rows.len().min(limit as usize));
    for r in rows.iter().take(limit as usize) {
        let issue = WebIssue::from_row(r);
        let author_username = lookup_username(&tx, issue.author_id).await?;
        let comment_count: i64 = tx.query_one("SELECT count(*) FROM forge_issue_comments WHERE tenant_id=$1 AND repository_id=$2 AND issue_number=$3", &[&access.owner_id, &access.repo_id, &issue.number]).await.map_err(Error::internal)?.get(0);
        items.push(IssueViewItem { issue, author_username, comment_count });
    }
    let next_after = if more { items.last().map(|i| i.issue.number) } else { None };
    finish(tx, &actor, false).await?;
    Ok(html_response(StatusCode::OK, templates::render_issues_list_view(&header_ctx, &items, filter_state, next_after)))
}

pub async fn create_issue_web(State(state): App, Path((owner, name)): RepoPath, headers: HeaderMap, Json(input): Json<WebNewIssue>) -> Res {
    tokio::spawn(auth::web_scope(async move {
        input.validate()?;
        member_models::ensure_schema(&state.pool).await?;
        let norm_headers = normalize_web_headers(&headers);
        let actor = auth::authenticate(&state.pool, &norm_headers).await?;
        let key = idempotency_key(&norm_headers)?;
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Triage).await?;
        let header_ctx = load_header_ctx(&tx, &owner, &name, &actor, access).await?;
        let (repo, tenant_id) = (access.repo_id, access.owner_id);
        if let Some(key) = key {
            let req = sjson!({"operation": "issue", "title": input.title, "body": input.body});
            if let Some(saved) = creation_replay(&tx, tenant_id, repo, key, &req).await? {
                let issue: WebIssue = serde_json::from_value(saved).map_err(Error::internal)?;
                finish(tx, &actor, true).await?;
                let item = IssueViewItem { issue, author_username: actor.username, comment_count: 0 };
                return Ok(html_response(StatusCode::CREATED, templates::render_issue_detail_view(&header_ctx, &item, &[])));
            }
        }
        tx.execute("INSERT INTO forge_issue_counters (tenant_id,repository_id) VALUES($1,$2) ON CONFLICT DO NOTHING", &[&tenant_id, &repo]).await.map_err(Error::internal)?;
        let number: i64 = tx.query_one("UPDATE forge_issue_counters SET next_number=next_number+1 WHERE tenant_id=$1 AND repository_id=$2 RETURNING next_number-1", &[&tenant_id, &repo]).await.map_err(Error::internal)?.get(0);
        let row = tx.query_one(&format!("INSERT INTO forge_issues (tenant_id,repository_id,number,author_id,title,body) VALUES($1,$2,$3,$4,$5,$6) RETURNING {ISSUE_FIELDS}"), &[&tenant_id, &repo, &number, &actor.id, &input.title, &input.body]).await.map_err(Error::internal)?;
        let issue = WebIssue::from_row(&row);
        let val = serde_json::to_value(&issue).map_err(Error::internal)?;
        record_creation(&tx, tenant_id, repo, key, &val).await?;
        audit::record_audit_event(&tx, tenant_id, repo, &actor, "issue.created", "issue", &number.to_string(), sjson!({"title": issue.title})).await?;
        finish(tx, &actor, true).await?;
        let item = IssueViewItem { issue, author_username: actor.username, comment_count: 0 };
        Ok(html_response(StatusCode::CREATED, templates::render_issue_detail_view(&header_ctx, &item, &[])))
    }))
    .await
    .map_err(Error::internal)?
}

async fn load_issue_and_comments(tx: &Transaction<'_>, tenant_id: Uuid, repo_id: Uuid, number: i64) -> Result<(IssueViewItem, Vec<CommentViewItem>), Error> {
    let q = format!("SELECT {ISSUE_FIELDS} FROM forge_issues WHERE tenant_id=$1 AND repository_id=$2 AND number=$3");
    let row = tx.query_opt(&q, &[&tenant_id, &repo_id, &number]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let issue = WebIssue::from_row(&row);
    let author_username = lookup_username(tx, issue.author_id).await?;
    let cq = format!("SELECT {COMMENT_FIELDS} FROM forge_issue_comments WHERE tenant_id=$1 AND repository_id=$2 AND issue_number=$3 ORDER BY number ASC LIMIT 100");
    let c_rows = tx.query(&cq, &[&tenant_id, &repo_id, &number]).await.map_err(Error::internal)?;
    let mut comments = Vec::with_capacity(c_rows.len());
    for cr in &c_rows {
        let comment = WebComment::from_row(cr);
        let c_author = lookup_username(tx, comment.author_id).await?;
        comments.push(CommentViewItem { comment, author_username: c_author });
    }
    let item = IssueViewItem { issue, author_username, comment_count: comments.len() as i64 };
    Ok((item, comments))
}

pub async fn issue_detail_view(State(state): App, Path((owner, name, number)): NumPath, headers: HeaderMap) -> Res {
    positive(number)?;
    let (actor, access, header_ctx) = authorize_web_repo(&state, &headers, &owner, &name, Role::Read).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let (item, comments) = load_issue_and_comments(&tx, access.owner_id, access.repo_id, number).await?;
    finish(tx, &actor, false).await?;
    Ok(html_response(StatusCode::OK, templates::render_issue_detail_view(&header_ctx, &item, &comments)))
}

pub async fn update_issue_web(State(state): App, Path((owner, name, number)): NumPath, headers: HeaderMap, Json(input): Json<WebIssuePatch>) -> Res {
    positive(number)?;
    input.validate()?;
    member_models::ensure_schema(&state.pool).await?;
    let norm_headers = normalize_web_headers(&headers);
    let actor = auth::authenticate(&state.pool, &norm_headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Triage).await?;
    let header_ctx = load_header_ctx(&tx, &owner, &name, &actor, access).await?;
    let (repo, tenant_id) = (access.repo_id, access.owner_id);
    tx.query_opt("SELECT number FROM forge_issues WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 FOR UPDATE", &[&tenant_id, &repo, &number]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let upd = format!("UPDATE forge_issues SET title=COALESCE($5,title),body=COALESCE($6,body),state=COALESCE($7,state),version=version+1,updated_at=clock_timestamp() WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 AND version=$4 RETURNING {ISSUE_FIELDS}");
    tx.query_opt(&upd, &[&tenant_id, &repo, &number, &input.expected_version, &input.title, &input.body, &input.state]).await.map_err(Error::internal)?.ok_or(Error(StatusCode::CONFLICT, "issue version conflict"))?;
    let (item, comments) = load_issue_and_comments(&tx, tenant_id, repo, number).await?;
    finish(tx, &actor, true).await?;
    Ok(html_response(StatusCode::OK, templates::render_issue_detail_view(&header_ctx, &item, &comments)))
}

pub async fn create_issue_comment_web(State(state): App, Path((owner, name, number)): NumPath, headers: HeaderMap, Json(input): Json<WebNewComment>) -> Res {
    positive(number)?;
    input.validate()?;
    member_models::ensure_schema(&state.pool).await?;
    let norm_headers = normalize_web_headers(&headers);
    let actor = auth::authenticate(&state.pool, &norm_headers).await?;
    let key = idempotency_key(&norm_headers)?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access = auth::authorize_repo_with_role(&tx, &actor, &owner, &name, Role::Triage).await?;
    let header_ctx = load_header_ctx(&tx, &owner, &name, &actor, access).await?;
    let (repo, tenant_id) = (access.repo_id, access.owner_id);
    if let Some(key) = key {
        let req = sjson!({"operation": "comment", "issue_number": number, "body": input.body});
        if creation_replay(&tx, tenant_id, repo, key, &req).await?.is_some() {
            let (item, comments) = load_issue_and_comments(&tx, tenant_id, repo, number).await?;
            finish(tx, &actor, true).await?;
            return Ok(html_response(StatusCode::CREATED, templates::render_issue_detail_view(&header_ctx, &item, &comments)));
        }
    }
    let next_row = tx.query_opt("UPDATE forge_issues SET next_comment_number=next_comment_number+1 WHERE tenant_id=$1 AND repository_id=$2 AND number=$3 RETURNING next_comment_number-1", &[&tenant_id, &repo, &number]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let comment_number: i64 = next_row.get(0);
    let row = tx.query_one(&format!("INSERT INTO forge_issue_comments (tenant_id,repository_id,issue_number,number,author_id,body) VALUES($1,$2,$3,$4,$5,$6) RETURNING {COMMENT_FIELDS}"), &[&tenant_id, &repo, &number, &comment_number, &actor.id, &input.body]).await.map_err(Error::internal)?;
    let comment = serde_json::to_value(WebComment::from_row(&row)).map_err(Error::internal)?;
    record_creation(&tx, tenant_id, repo, key, &comment).await?;
    let (item, comments) = load_issue_and_comments(&tx, tenant_id, repo, number).await?;
    finish(tx, &actor, true).await?;
    Ok(html_response(StatusCode::CREATED, templates::render_issue_detail_view(&header_ctx, &item, &comments)))
}

pub async fn pulls_list_view(State(state): App, Path((owner, name)): RepoPath, Query(query): Query<WebPullFilterQuery>, headers: HeaderMap) -> Res {
    let (filter_enum, after, limit) = query.validate()?;
    let filter_str = filter_enum.as_ref().map(PullStateFilter::as_str);
    let (actor, access, header_ctx) = authorize_web_repo(&state, &headers, &owner, &name, Role::Read).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let q = format!("SELECT {PULL_FIELDS} FROM forge_pulls WHERE tenant_id=$1 AND repository_id=$2 AND number>$3 AND ($5::text IS NULL OR state=$5) ORDER BY number ASC LIMIT $4");
    let rows = tx.query(&q, &[&access.owner_id, &access.repo_id, &after, &(limit + 1), &filter_str]).await.map_err(Error::internal)?;
    let more = rows.len() > limit as usize;
    let items: Vec<_> = rows.iter().take(limit as usize).map(PullRequest::row).collect();
    let next_after = if more { items.last().map(|p| p.number) } else { None };
    finish(tx, &actor, false).await?;
    Ok(html_response(StatusCode::OK, templates::render_pulls_list_view(&header_ctx, &items, filter_str, next_after)))
}

async fn render_pull_detail_for_number(state: &Arc<AppState>, owner: &str, name: &str, number: i64, headers: &HeaderMap, status: StatusCode) -> Res {
    positive(number)?;
    let (actor, access, header_ctx) = authorize_web_repo(state, headers, owner, name, Role::Read).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let q = format!("SELECT {PULL_FIELDS} FROM forge_pulls WHERE tenant_id=$1 AND repository_id=$2 AND number=$3");
    let row = tx.query_opt(&q, &[&access.owner_id, &access.repo_id, &number]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let pull = PullRequest::row(&row);
    let author_username = lookup_username(&tx, pull.author_id).await?;
    let rq = format!("SELECT {REVIEW_FIELDS} FROM forge_pull_reviews WHERE tenant_id=$1 AND repository_id=$2 AND pull_number=$3 ORDER BY number ASC LIMIT 100");
    let r_rows = tx.query(&rq, &[&access.owner_id, &access.repo_id, &number]).await.map_err(Error::internal)?;
    let reviews: Vec<_> = r_rows.iter().map(PullReview::row).collect();
    let checks = query_commit_checks(&tx, access.owner_id, access.repo_id, &pull.head_oid, 0, 50).await?;
    let policy = rules::evaluate_branch_policy(&tx, access.owner_id, access.repo_id, pull.number, &pull.base_ref, &pull.head_oid).await?;
    let disallow_self = rules::is_self_approval_disallowed(&tx, access.owner_id, access.repo_id, &pull.base_ref, pull.author_id).await?;
    let can_approve = rbac::check_review_permission(&tx, &access, actor.id, pull.author_id, &pull.base_ref, "approved", disallow_self).await.is_ok() && !actor.read_only;
    let can_merge = access.role >= Role::Write && !actor.read_only && policy.allowed && pull.state == "open";
    finish(tx, &actor, false).await?;
    drop(client);

    let merge_base_oid = merge_base(state, access.repo_id, &pull.base_oid, &pull.head_oid).await.ok().flatten();
    let fast_forward = merge_base_oid.as_deref() == Some(pull.base_oid.as_str());
    let diff_raw = git_read::run_git(state, access.repo_id, &["diff", "--no-color", "--no-ext-diff", &pull.base_oid, &pull.head_oid], MAX_DIFF_BYTES).await.unwrap_or_default();
    let diff = PullDiffResponse { pull_number: pull.number, base_ref: pull.base_ref.clone(), head_ref: pull.head_ref.clone(), base_oid: pull.base_oid.clone(), head_oid: pull.head_oid.clone(), merge_base_oid, fast_forward, diff: String::from_utf8_lossy(&diff_raw).into_owned() };
    let view_data = PullDetailViewData { pull, author_username, reviews, checks, policy, diff, disallow_self_approval: disallow_self, can_approve, can_merge };
    Ok(html_response(status, templates::render_pull_detail_view(&header_ctx, &view_data)))
}

pub async fn create_pull_web(State(state): App, Path((owner, name)): RepoPath, headers: HeaderMap, Json(input): Json<NewPull>) -> Res {
    member_models::ensure_schema(&state.pool).await?;
    let norm = normalize_web_headers(&headers);
    let api_resp = pull_handlers::create_pull(State(state.clone()), Path((owner.clone(), name.clone())), norm.clone(), Json(input)).await?;
    let status = api_resp.status();
    let body_bytes = axum::body::to_bytes(api_resp.into_body(), 256 * 1024).await.map_err(Error::internal)?;
    let pr: PullRequest = serde_json::from_slice(&body_bytes).map_err(Error::internal)?;
    render_pull_detail_for_number(&state, &owner, &name, pr.number, &norm, status).await
}

pub async fn pull_detail_view(State(state): App, Path((owner, name, number)): NumPath, headers: HeaderMap) -> Res {
    render_pull_detail_for_number(&state, &owner, &name, number, &headers, StatusCode::OK).await
}

pub async fn update_pull_web(State(state): App, Path((owner, name, number)): NumPath, headers: HeaderMap, Json(input): Json<PullPatch>) -> Res {
    member_models::ensure_schema(&state.pool).await?;
    let norm = normalize_web_headers(&headers);
    let api_resp = pull_handlers::update_pull(State(state.clone()), Path((owner.clone(), name.clone(), number)), norm.clone(), Json(input)).await?;
    render_pull_detail_for_number(&state, &owner, &name, number, &norm, api_resp.status()).await
}

pub async fn pull_diff_view(State(state): App, Path((owner, name, number)): NumPath, headers: HeaderMap) -> Res {
    render_pull_detail_for_number(&state, &owner, &name, number, &headers, StatusCode::OK).await
}

pub async fn pull_reviews_view(State(state): App, Path((owner, name, number)): NumPath, headers: HeaderMap) -> Res {
    render_pull_detail_for_number(&state, &owner, &name, number, &headers, StatusCode::OK).await
}

pub async fn create_review_web(State(state): App, Path((owner, name, number)): NumPath, headers: HeaderMap, Json(input): Json<NewReview>) -> Res {
    member_models::ensure_schema(&state.pool).await?;
    let norm = normalize_web_headers(&headers);
    let api_resp = pull_handlers::create_review(State(state.clone()), Path((owner.clone(), name.clone(), number)), norm.clone(), Json(input)).await?;
    render_pull_detail_for_number(&state, &owner, &name, number, &norm, api_resp.status()).await
}

pub async fn pull_checks_view(State(state): App, Path((owner, name, number)): NumPath, Query(query): Query<WebCheckPanelQuery>, headers: HeaderMap) -> Res {
    positive(number)?;
    let (after, limit) = query.validate()?;
    let (actor, access, header_ctx) = authorize_web_repo(&state, &headers, &owner, &name, Role::Read).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let row = tx.query_opt("SELECT head_oid FROM forge_pulls WHERE tenant_id=$1 AND repository_id=$2 AND number=$3", &[&access.owner_id, &access.repo_id, &number]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let head_oid: String = row.get(0);
    let checks = query_commit_checks(&tx, access.owner_id, access.repo_id, &head_oid, after, limit).await?;
    finish(tx, &actor, false).await?;
    Ok(html_response(StatusCode::OK, templates::render_check_runs_panel(&header_ctx, &head_oid, Some(number), &checks)))
}

pub async fn merge_pull_web(State(state): App, Path((owner, name, number)): NumPath, headers: HeaderMap, Json(input): Json<MergeInput>) -> Res {
    member_models::ensure_schema(&state.pool).await?;
    let norm = normalize_web_headers(&headers);
    let api_resp = pull_merge::merge_pull(State(state.clone()), Path((owner.clone(), name.clone(), number)), norm.clone(), Json(input)).await?;
    render_pull_detail_for_number(&state, &owner, &name, number, &norm, api_resp.status()).await
}

pub async fn audit_view(State(state): App, Path((owner, name)): RepoPath, Query(query): Query<AuditQuery>, headers: HeaderMap) -> Res {
    let (after, limit) = query.validate()?;
    let (actor, access, header_ctx) = authorize_web_repo(&state, &headers, &owner, &name, Role::Maintain).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let rows = tx.query(&format!("SELECT {AUDIT_FIELDS} FROM repository_audit_log WHERE tenant_id=$1 AND repository_id=$2 AND id>$3 AND ($4::text IS NULL OR actor_name=$4) AND ($5::text IS NULL OR action=$5) AND ($6::bigint IS NULL OR created_unix>=$6) AND ($7::bigint IS NULL OR created_unix<=$7) ORDER BY id ASC LIMIT $8"), &[&access.owner_id, &access.repo_id, &after, &query.actor, &query.action, &query.since, &query.until, &(limit + 1)]).await.map_err(Error::internal)?;
    let more = rows.len() > limit as usize;
    let items: Vec<AuditEntry> = rows.iter().take(limit as usize).map(AuditEntry::row).collect();
    let next_after = if more { items.last().map(|e| e.id) } else { None };
    finish(tx, &actor, false).await?;
    let page = AuditPage { items, next_after };
    Ok(html_response(StatusCode::OK, templates::render_audit_view(&header_ctx, &page)))
}
