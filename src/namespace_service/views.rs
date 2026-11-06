use super::handlers;
use crate::{AppState, Error, auth, members::models::Role, storage::read_leases};
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
    cmd.args([
        "-c",
        "core.hooksPath=/dev/null",
        "clone",
        "--no-local",
        "--no-hardlinks",
        "--no-tags",
    ]);
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
fn projection_root(state: &AppState) -> PathBuf {
    state.storage.root.join("workspace-service/views")
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<CreateView>,
) -> Result<(StatusCode, Json<View>), Error> {
    let ns = handlers::load(&state, &headers, id).await?;
    if !input.subdir.is_empty()
        && (crate::browse::models::normalize_rel_path(Some(&input.subdir))? != input.subdir
            || !input
                .subdir
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b)))
    {
        return Err(Error::bad_request());
    }
    let mount = ns
        .mounts
        .iter()
        .find(|m| m.path == input.mount_path)
        .ok_or_else(Error::not_found)?;
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let access =
        auth::authorize_repo_with_role(&tx, &actor, &mount.owner, &mount.repository, Role::Read)
            .await?;
    let source_lease = read_leases::shared(
        &state.pool,
        access.repo_id,
        tokio::time::Instant::now() + state.config.git_timeout,
    )
    .await?;
    let refreshed =
        auth::authorize_repo_with_role(&tx, &actor, &mount.owner, &mount.repository, Role::Read)
            .await?;
    if refreshed.repo_id != access.repo_id {
        return Err(Error::not_found());
    }
    let source = state
        .storage
        .verify_path(access.repo_id)
        .map_err(Error::internal)?;
    let vid = Uuid::new_v4();
    let temp = projection_root(&state).join(format!("stage-{vid}"));
    let final_path = projection_root(&state).join(vid.to_string());
    clone(&source, &temp, None)?;
    source_lease.ensure_active()?;
    git(&temp, &["checkout", "--force", &mount.base_oid])?;
    let projected = if input.subdir.is_empty() {
        mount.base_oid.clone()
    } else {
        git(
            &temp,
            &[
                "filter-branch",
                "--subdirectory-filter",
                &input.subdir,
                "--",
                "HEAD",
            ],
        )?;
        git(&temp, &["rev-parse", "HEAD"])?.trim().to_owned()
    };
    git(&temp, &["update-ref", "refs/heads/projected", &projected])?;
    clone(&temp, &final_path, Some("projected"))?;
    let _ = fs::remove_dir_all(&temp);
    let head = git(&final_path, &["rev-parse", "HEAD"])?;
    if head.trim() != projected {
        return Err(Error::internal("view head mismatch"));
    }
    tx.execute("INSERT INTO workspace_views(id,namespace_id,repository_id,mount_path,subdir,source_oid,projected_oid,creator_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", &[&vid,&id,&access.repo_id,&input.mount_path,&input.subdir,&mount.base_oid,&projected,&actor.id]).await.map_err(Error::internal)?;
    tx.execute("INSERT INTO workspace_view_history(view_id,source_oid,projected_oid,epoch) VALUES($1,$2,$3,1)", &[&vid,&mount.base_oid,&projected]).await.map_err(Error::internal)?;
    tx.commit().await.map_err(Error::internal)?;
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

pub(super) async fn load(state: &AppState, headers: &HeaderMap, id: Uuid) -> Result<View, Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let row=client.query_opt("SELECT id,namespace_id,repository_id,mount_path,subdir,source_oid,projected_oid,epoch FROM workspace_views WHERE id=$1", &[&id]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let result = view(&row);
    handlers::load(state, headers, result.namespace_id).await?;
    Ok(result)
}
pub async fn get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<View>, Error> {
    Ok(Json(load(&state, &headers, id).await?))
}
pub async fn bundle(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<impl IntoResponse, Error> {
    load(&state, &headers, id).await?;
    let root = projection_root(&state).join(id.to_string());
    let path = root
        .parent()
        .ok_or_else(Error::not_found)?
        .join(format!("{id}.bundle"));
    git(
        &root,
        &[
            "bundle",
            "create",
            path.to_str().ok_or_else(Error::bad_request)?,
            "--all",
        ],
    )?;
    let bytes = fs::read(&path).map_err(Error::internal)?;
    let _ = fs::remove_file(path);
    if bytes.len() > 32 * 1024 * 1024 {
        return Err(Error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "view bundle too large",
        ));
    }
    Ok((
        [
            (header::CONTENT_TYPE, "application/x-git-bundle"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        bytes,
    ))
}
