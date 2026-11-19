use super::handlers;
use crate::{
    AppState, Error, auth, db::Identity, members::models::Role, storage::read_leases, token_scopes::RepoAction,
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path as FsPath, PathBuf},
    process::Command,
    sync::Arc,
};
use uuid::Uuid;

#[rustfmt::skip]
#[path = "s4_git_view.rs"]
pub(super) mod s4_git_view;

#[rustfmt::skip]
#[path = "s4_git_proc.rs"]
pub(crate) mod s4_git_proc;

#[rustfmt::skip]
#[path = "s4_git_proc_reverse.rs"]
pub(crate) mod s4_git_proc_reverse;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateView {
    pub mount_path: String,
    pub subdir: String,
}
#[derive(Serialize)]
pub struct View {
    pub id: Uuid,
    pub namespace_id: Uuid,
    pub repository_id: Uuid,
    pub mount_path: String,
    pub subdir: String,
    pub source_oid: String,
    pub projected_oid: String,
    pub epoch: i64,
}
#[derive(Serialize)]
pub struct ViewHistoryEntry {
    pub epoch: i64,
    pub source_oid: String,
    pub projected_oid: String,
}
#[derive(Serialize)]
pub struct ViewHistory {
    pub view: View,
    pub mappings: Vec<ViewHistoryEntry>,
}

struct DirGuard(Option<PathBuf>);
impl DirGuard {
    fn disarm(&mut self) {
        self.0 = None;
    }
}
impl Drop for DirGuard {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = fs::remove_dir_all(path);
        }
    }
}

struct FileGuard(Option<PathBuf>);
impl Drop for FileGuard {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = fs::remove_file(path);
        }
    }
}
fn view(row: &tokio_postgres::Row) -> View {
    View {
        id: row.get(0),
        namespace_id: row.get(1),
        repository_id: row.get(2),
        mount_path: row.get(3),
        subdir: row.get(4),
        source_oid: row.get(5),
        projected_oid: row.get(6),
        epoch: row.get(7),
    }
}
fn git(repo: &FsPath, args: &[&str]) -> Result<String, Error> {
    let out = Command::new("git")
        .arg("-c")
        .arg("core.hooksPath=/dev/null")
        .arg("--no-replace-objects")
        .arg("-C")
        .arg(repo)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("FILTER_BRANCH_SQUELCH_WARNING", "1")
        .output()
        .map_err(Error::internal)?;
    if !out.status.success() {
        return Err(Error(StatusCode::CONFLICT, "Git view projection failed"));
    }
    String::from_utf8(out.stdout).map_err(Error::internal)
}
fn clone(source: &FsPath, dest: &FsPath, branch: Option<&str>) -> Result<(), Error> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(Error::internal)?;
    }
    let mut cmd = Command::new("git");
    cmd.args(["-c", "core.hooksPath=/dev/null", "clone", "--no-local", "--no-hardlinks", "--no-tags"]);
    if let Some(branch) = branch {
        cmd.args(["--single-branch", "--branch", branch]);
    }
    let out = cmd
        .arg("--")
        .arg(source)
        .arg(dest)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .map_err(Error::internal)?;
    if !out.status.success() {
        return Err(Error(StatusCode::CONFLICT, "Git view clone failed"));
    }
    Ok(())
}
pub(super) fn projection_root(state: &AppState) -> PathBuf {
    state.storage.root.join("workspace-service/views")
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<CreateView>,
) -> Result<(StatusCode, Json<View>), Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let ns = handlers::load_for_actor(&state, &actor, id).await?;
    if !input.subdir.is_empty()
        && (input.subdir.starts_with('-')
            || crate::browse::models::normalize_rel_path(Some(&input.subdir))? != input.subdir
            || !input.subdir.bytes().all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b)))
    {
        return Err(Error::bad_request());
    }
    let mount = ns.mounts.iter().find(|m| m.path == input.mount_path).ok_or_else(Error::not_found)?;
    let access = {
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let access = auth::authorize_repo_with_role(
            &tx,
            &actor,
            &mount.owner,
            &mount.repository,
            Role::Read,
            RepoAction::ContentsRead,
        )
        .await?;
        auth::finish_tx(tx, &actor, false).await?;
        access
    };
    // A `pg_refstore` repository has no local GitFS clone: its view is a durable
    // retention root plus a `s4_ci_retention.git_view_bindings` row.
    if s4_git_view::is_refstore(&state, access.repo_id).await? {
        return s4_git_view::create(&state, &actor, id, &input, mount, access.repo_id).await;
    }
    let vid = Uuid::new_v4();
    let temp = projection_root(&state).join(format!("stage-{vid}"));
    let final_path = projection_root(&state).join(vid.to_string());
    let mut temp_guard = DirGuard(Some(temp.clone()));
    let mut final_guard = DirGuard(Some(final_path.clone()));
    {
        let source_lease =
            read_leases::shared(&state.pool, access.repo_id, tokio::time::Instant::now() + state.config.git_timeout)
                .await?;
        let _local = tokio::time::timeout(state.config.git_timeout, state.storage.read_snapshot_lock(access.repo_id))
            .await
            .map_err(|_| Error::timeout())?;
        source_lease.ensure_active()?;
        auth::verify_active(&state.pool, &actor, access.repo_id, RepoAction::ContentsRead, Role::Read).await?;
        let source = state.storage.verify_path(access.repo_id).map_err(Error::internal)?;
        clone(&source, &temp, None)?;
        source_lease.ensure_active()?;
        // A durable namespace pin can outlive the branch that advertised it. The
        // ordinary clone will not fetch an unreachable commit, so fetch the exact
        // pinned OID from the local source before projecting it.
        if git(&temp, &["cat-file", "-e", &mount.base_oid]).is_err() {
            let source = source.to_str().ok_or_else(Error::bad_request)?;
            git(&temp, &["-c", "uploadpack.allowAnySHA1InWant=true", "fetch", "--no-tags", source, &mount.base_oid])?;
            git(&temp, &["cat-file", "-e", &mount.base_oid])?;
        }
        source_lease.ensure_active()?;
    }
    git(&temp, &["checkout", "--force", &mount.base_oid])?;
    let projected = if input.subdir.is_empty() {
        mount.base_oid.clone()
    } else {
        let kind = git(&temp, &["cat-file", "-t", &format!("{}^{{tree}}:{}", mount.base_oid, input.subdir)])
            .map_err(|_| Error::bad_request())?;
        if kind.trim() != "tree" {
            return Err(Error::bad_request());
        }
        git(&temp, &["filter-branch", "--subdirectory-filter", &input.subdir, "--", "HEAD"])?;
        git(&temp, &["rev-parse", "HEAD"])?.trim().to_owned()
    };
    git(&temp, &["update-ref", "refs/heads/projected", &projected])?;
    clone(&temp, &final_path, Some("projected"))?;
    let _ = temp_guard.0.take().map(fs::remove_dir_all);
    let head = git(&final_path, &["rev-parse", "HEAD"])?;
    if head.trim() != projected {
        return Err(Error::internal("view head mismatch"));
    }
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let refreshed = auth::authorize_repo_with_role(
        &tx,
        &actor,
        &mount.owner,
        &mount.repository,
        Role::Read,
        RepoAction::ContentsRead,
    )
    .await?;
    if refreshed.repo_id != access.repo_id {
        return Err(Error::not_found());
    }
    tx.execute("INSERT INTO workspace_views(id,namespace_id,repository_id,mount_path,subdir,source_oid,projected_oid,creator_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", &[&vid,&id,&access.repo_id,&input.mount_path,&input.subdir,&mount.base_oid,&projected,&actor.id]).await.map_err(Error::internal)?;
    tx.execute(
        "INSERT INTO workspace_view_history(view_id,source_oid,projected_oid,epoch) VALUES($1,$2,$3,1)",
        &[&vid, &mount.base_oid, &projected],
    )
    .await
    .map_err(Error::internal)?;
    auth::finish_tx(tx, &actor, false).await?;
    final_guard.disarm();
    Ok((
        StatusCode::CREATED,
        Json(View {
            id: vid,
            namespace_id: id,
            repository_id: access.repo_id,
            mount_path: input.mount_path,
            subdir: input.subdir,
            source_oid: mount.base_oid.clone(),
            projected_oid: projected,
            epoch: 1,
        }),
    ))
}

pub(super) async fn load_row(state: &AppState, id: Uuid) -> Result<View, Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let row = client
        .query_opt(
            "SELECT id,namespace_id,repository_id,mount_path,subdir,source_oid,projected_oid,epoch FROM workspace_views WHERE id=$1",
            &[&id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    Ok(view(&row))
}

pub(super) async fn load_for_actor(state: &AppState, actor: &Identity, id: Uuid) -> Result<View, Error> {
    let result = load_row(state, id).await?;
    let ns = handlers::load_for_actor(state, actor, result.namespace_id).await?;
    if !ns.mounts.iter().any(|m| m.path == result.mount_path) {
        return Err(Error::not_found());
    }
    Ok(result)
}

pub(super) async fn load(state: &AppState, headers: &HeaderMap, id: Uuid) -> Result<View, Error> {
    let actor = auth::authenticate(&state.pool, headers).await?;
    load_for_actor(state, &actor, id).await
}

pub async fn get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, Error> {
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(load(&state, &headers, id).await?)))
}

pub async fn history(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let view = load_for_actor(&state, &actor, id).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    auth::verify_token(&tx, &actor, false).await?;
    let rows = tx
        .query(
            "SELECT epoch,source_oid,projected_oid FROM workspace_view_history WHERE view_id=$1 ORDER BY epoch ASC, source_oid ASC",
            &[&id],
        )
        .await
        .map_err(Error::internal)?;
    let mappings = rows
        .into_iter()
        .map(|row| ViewHistoryEntry { epoch: row.get(0), source_oid: row.get(1), projected_oid: row.get(2) })
        .collect();
    auth::finish_tx(tx, &actor, false).await?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(ViewHistory { view, mappings })))
}

pub async fn bundle(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<axum::response::Response, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let view = load_for_actor(&state, &actor, id).await?;
    // `pg_refstore` views are never materialized under `workspace-service/views`.
    if s4_git_view::is_refstore(&state, view.repository_id).await? {
        let (headers, bytes) = s4_git_view::bundle(&state, &view, id).await?;
        load_for_actor(&state, &actor, view.id).await?;
        return Ok((headers, bytes).into_response());
    }
    let root = projection_root(&state).join(id.to_string());
    let path = root.parent().ok_or_else(Error::not_found)?.join(format!("{id}-{}.bundle", Uuid::new_v4()));
    let _guard = FileGuard(Some(path.clone()));
    git(&root, &["bundle", "create", path.to_str().ok_or_else(Error::bad_request)?, "--all"])?;
    let bytes = fs::read(&path).map_err(Error::internal)?;
    if bytes.len() > 32 * 1024 * 1024 {
        return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "view bundle too large"));
    }
    load_for_actor(&state, &actor, view.id).await?;
    Ok(([(header::CONTENT_TYPE, "application/x-git-bundle"), (header::CACHE_CONTROL, "no-store")], bytes)
        .into_response())
}
