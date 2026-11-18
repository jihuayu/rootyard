//! Smart HTTP transport for `pg_refstore` Namespace Git Views.
//!
//! A projected view has no `workspace-service/views` directory. Every request
//! rebuilds the retained source root into a disposable `0o700` tree, re-runs the
//! recorded projection, and serves a bare clone that contains only
//! `refs/heads/projected`; nothing durable and no unprojected sibling path is
//! ever exposed.
use super::views;
use crate::{
    AppState, Error, auth, db::Identity, members::models::Role,
    ref_store::core::retention_root::{PgRetentionRoots, RootRef},
    token_scopes::RepoAction,
};
use axum::{
    body::Body,
    http::{HeaderMap, HeaderName, StatusCode, header},
    response::Response,
};
use std::{
    fs,
    path::{Path as FsPath, PathBuf},
    process::Stdio,
};
use tokio::{process::Command, time::Instant};
use uuid::Uuid;

/// Disposable tree removed before the response is returned.
struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn create() -> Result<Self, Error> {
        let root = std::env::temp_dir().join(format!("rootyard-s4-view-http-{}", Uuid::new_v4()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().recursive(true).mode(0o700).create(&root).map_err(Error::internal)?;
        }
        #[cfg(not(unix))]
        fs::create_dir_all(&root).map_err(Error::internal)?;
        Ok(Self { root })
    }

    fn work(&self) -> PathBuf {
        self.root.join("work")
    }

    fn bare(&self) -> PathBuf {
        self.root.join("repo.git")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

async fn git(dir: &FsPath, args: &[&str]) -> Result<Vec<u8>, Error> {
    let out = Command::new("git")
        .args(["-c", "core.hooksPath=/dev/null", "--no-replace-objects", "-C"])
        .arg(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env_remove("GIT_PROTOCOL")
        .output()
        .await
        .map_err(Error::internal)?;
    if !out.status.success() {
        return Err(Error(StatusCode::CONFLICT, "Git view projection failed"));
    }
    Ok(out.stdout)
}

async fn git_clone(source: &FsPath, dest: &FsPath, extra: &[&str]) -> Result<(), Error> {
    let out = Command::new("git")
        .args(["-c", "core.hooksPath=/dev/null", "clone"])
        .args(extra)
        .arg("--")
        .arg(source)
        .arg(dest)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env_remove("GIT_PROTOCOL")
        .output()
        .await
        .map_err(Error::internal)?;
    if !out.status.success() {
        return Err(Error(StatusCode::CONFLICT, "Git view clone failed"));
    }
    Ok(())
}

/// Re-prove the recorded view binding, the live repository authority and the
/// retained root before a single object is served.
pub(super) async fn verify_active_binding(
    state: &AppState,
    view: &views::View,
    id: Uuid,
) -> Result<Uuid, Error> {
    crate::ci_pins::s4_schema::ensure_s4_schema(&state.pool).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let cluster_inc = crate::ci_pins::s4_authority::require_cluster_incarnation_nowait(&tx).await?;
    let row = tx
        .query_opt(
            "SELECT b.retention_root_id, b.state, b.owner_tenant_id, r.owner_id, r.state, \
                    b.cluster_incarnation \
             FROM s4_ci_retention.git_view_bindings b JOIN repositories r ON r.id=b.repository_id \
             JOIN ref_store_core_gates cg ON cg.repository_id=b.repository_id \
             WHERE b.view_id=$1 AND b.repository_id=$2 \
               AND cg.authority_epoch=b.authority_epoch \
               AND cg.history_incarnation=b.history_incarnation AND cg.group_epoch=b.group_epoch",
            &[&id, &view.repository_id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let root_id: Uuid = row.get(0);
    if row.get::<_, Uuid>(5) != cluster_inc {
        return Err(Error(StatusCode::CONFLICT, "cluster authority rotated"));
    }
    if row.get::<_, String>(1) != "active" {
        return Err(Error(StatusCode::CONFLICT, "view binding is released"));
    }
    if row.get::<_, String>(4) != "ready" || Some(row.get::<_, Uuid>(3)) != row.get::<_, Option<Uuid>>(2) {
        return Err(Error::not_found());
    }
    let root = RootRef::new(view.repository_id, root_id, 1)
        .map_err(|_| Error(StatusCode::CONFLICT, "retained root unavailable or released"))?;
    let record = PgRetentionRoots::root_record_in_tx(&tx, root)
        .await
        .map_err(|_| Error(StatusCode::CONFLICT, "retained root unavailable or released"))?;
    if !record.is_some_and(|record| record.is_active()) {
        return Err(Error(StatusCode::CONFLICT, "retained root unavailable or released"));
    }
    let _ = tx.rollback().await;
    Ok(root_id)
}

/// Rebuild the retained root, re-run the projection and clone only the
/// `projected` branch into a fresh bare repository.
async fn materialize_projected_bare(
    state: &AppState,
    view: &views::View,
    root_id: Uuid,
    scratch: &Scratch,
    deadline: Instant,
) -> Result<PathBuf, Error> {
    let producer = crate::ci_pins::s4_pin::Producer::open(state)?;
    let holder = crate::ci_pins::s4_transport::materialize(
        state,
        &producer.store,
        view.repository_id,
        root_id,
        &view.source_oid,
        deadline,
    )
    .await?;
    git_clone(holder.path(), &scratch.work(), &["--no-local", "--no-hardlinks", "--no-tags"]).await?;
    let projected = views::s4_git_view::project(&scratch.work(), &view.source_oid, &view.subdir)?;
    if projected != view.projected_oid {
        return Err(Error(StatusCode::CONFLICT, "view projection no longer matches its recorded head"));
    }
    let bare = scratch.bare();
    git_clone(
        &scratch.work(),
        &bare,
        &["--bare", "--no-local", "--no-hardlinks", "--no-tags", "--single-branch", "--branch", "projected"],
    )
    .await?;
    git(&bare, &["symbolic-ref", "HEAD", "refs/heads/projected"]).await?;
    git(&bare, &["config", "uploadpack.allowAnySHA1InWant", "false"]).await?;
    git(&bare, &["config", "uploadpack.allowReachableSHA1InWant", "false"]).await?;
    Ok(bare)
}

fn reply(status: StatusCode, content_type: &'static str, body: Vec<u8>) -> Result<Response, Error> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .header(HeaderName::from_static("x-content-type-options"), "nosniff")
        .body(Body::from(body))
        .map_err(Error::internal)
}

/// `GET /git/views/{id}.git/info/refs`
pub(super) async fn info_refs(
    state: &AppState,
    actor: &Identity,
    view: &views::View,
    protocol: Option<&str>,
) -> Result<Response, Error> {
    let _slot = state
        .git_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error(StatusCode::SERVICE_UNAVAILABLE, "Git capacity exhausted; retry later"))?;
    let deadline = Instant::now() + state.config.git_timeout;
    let advertised = super::run_bounded(deadline, async {
        let root_id = verify_active_binding(state, view, view.id).await?;
        let scratch = Scratch::create()?;
        let bare = materialize_projected_bare(state, view, root_id, &scratch, deadline).await?;
        let mut cmd = state.storage.git(&state.config);
        cmd.args(["-c", "core.hooksPath=/dev/null", "--no-replace-objects"]);
        if let Some(proto) = protocol {
            cmd.env("GIT_PROTOCOL", proto);
        } else {
            cmd.env_remove("GIT_PROTOCOL");
        }
        cmd.args(["upload-pack", "--stateless-rpc", "--advertise-refs"]).arg(&bare);
        let timeout = super::remaining_timeout(deadline)?;
        let advertised = crate::git_http::collect_git_output(cmd, super::ADVERTISE_LIMIT, timeout)
            .await
            .map_err(|_| Error(StatusCode::SERVICE_UNAVAILABLE, "projected Git view unavailable"))?;
        views::load_for_actor(state, actor, view.id).await?;
        auth::verify_active(&state.pool, actor, view.repository_id, RepoAction::ContentsRead, Role::Read).await?;
        verify_active_binding(state, view, view.id).await?;
        Ok(advertised)
    })
    .await?;
    let mut body = super::service_prefix("git-upload-pack");
    body.extend_from_slice(&advertised);
    reply(StatusCode::OK, "application/x-git-upload-pack-advertisement", body)
}

/// `POST /git/views/{id}.git/git-upload-pack`
pub(super) async fn upload_pack(
    state: &AppState,
    actor: &Identity,
    view: &views::View,
    headers: &HeaderMap,
    body: Body,
) -> Result<Response, Error> {
    let max_req = state.config.max_request_bytes.min(super::UPLOAD_BODY_LIMIT as u64);
    let (gzipped, protocol) = super::validate_upload_headers(headers, max_req)?;
    let _slot = state
        .git_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error(StatusCode::SERVICE_UNAVAILABLE, "Git capacity exhausted; retry later"))?;
    let deadline = Instant::now() + state.config.git_timeout;
    let pack = super::run_bounded(deadline, async {
        let scratch = Scratch::create()?;
        let (req_file, _tmp_guard) =
            super::spool_body_to_temp(&scratch.root, view.id, body, gzipped, max_req, deadline).await?;
        let root_id = verify_active_binding(state, view, view.id).await?;
        let bare = materialize_projected_bare(state, view, root_id, &scratch, deadline).await?;
        let mut cmd = state.storage.git(&state.config);
        cmd.args(["-c", "core.hooksPath=/dev/null", "--no-replace-objects"]);
        if let Some(proto) = protocol.as_deref() {
            cmd.env("GIT_PROTOCOL", proto);
        } else {
            cmd.env_remove("GIT_PROTOCOL");
        }
        cmd.args(["upload-pack", "--stateless-rpc"]).arg(&bare);
        let max_out = usize::try_from(state.config.max_output_bytes)
            .unwrap_or(super::UPLOAD_RESULT_CAP)
            .min(super::UPLOAD_RESULT_CAP);
        let pack = crate::git_http::collect_git_output_input(
            cmd,
            max_out,
            super::remaining_timeout(deadline)?,
            Stdio::from(req_file),
        )
        .await
        .map_err(|_| {
            if Instant::now() >= deadline {
                Error::timeout()
            } else {
                Error(StatusCode::BAD_REQUEST, "invalid or unauthorized Git object request")
            }
        })?;
        if pack.get(4..).is_some_and(|rest| rest.starts_with(b"ERR ")) {
            return Err(Error(StatusCode::BAD_REQUEST, "invalid or unauthorized Git object request"));
        }
        views::load_for_actor(state, actor, view.id).await?;
        auth::verify_active(&state.pool, actor, view.repository_id, RepoAction::ContentsRead, Role::Read).await?;
        verify_active_binding(state, view, view.id).await?;
        Ok(pack)
    })
    .await?;
    reply(StatusCode::OK, "application/x-git-upload-pack-result", pack)
}
