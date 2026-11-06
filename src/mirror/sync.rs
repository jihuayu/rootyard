//! Snapshot sync, preparation, and filesystem primitives for CI read mirrors.
use crate::{
    AppState, Error, auth, db, git_http, members::models::Role,
    ci_checkouts::authority::IntegrationScope,
    mirror::{Snapshot, eviction, limiter, observability, views},
};
use anyhow::{Context, Result, bail};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path as FsPath,
    sync::Arc,
};
use tokio::process::Command;
use uuid::Uuid;

/// Only a configured trusted primary receives the caller's existing token.
/// Redirects, credential helpers and arbitrary Git transports are disabled.
pub(crate) fn primary_origin(value: &str) -> Result<String> {
    let uri: Uri = value.parse().context("invalid ROOTYARD_PRIMARY_URL")?;
    let authority = uri.authority().context("primary URL requires authority")?;
    let host = authority.host();
    if authority.as_str().contains('@')
        || !matches!(uri.path(), "" | "/")
        || uri.query().is_some()
        || value.contains('#')
        || !(uri.scheme_str() == Some("https")
            || (uri.scheme_str() == Some("http")
                && matches!(host, "127.0.0.1" | "[::1]" | "localhost")))
    {
        bail!(
            "primary must be an HTTPS origin (HTTP allowed only on loopback), without credentials or path"
        );
    }
    Ok(format!("{}://{}", uri.scheme_str().unwrap(), authority))
}

pub(crate) async fn repository(
    state: &AppState,
    headers: &HeaderMap,
    owner: &str,
    name: &str,
) -> Result<db::Repository, Error> {
    let identity = auth::authenticate(&state.pool, headers).await?;
    if !db::valid_name(owner) || !db::valid_name(name) {
        return Err(Error::not_found());
    }
    let mut client=state.pool.get().await.map_err(Error::internal)?;
    let tx=client.transaction().await.map_err(Error::internal)?;
    let access=auth::authorize_repo_with_role(&tx,&identity,owner,name,Role::Read).await
        .map_err(|error| if error.0 == StatusCode::CONFLICT && error.1 == "repository is not ready" {
            Error(StatusCode::SERVICE_UNAVAILABLE, "repository not ready")
        } else { error })?;
    let row=tx.query_one(&format!("{} WHERE r.id=$1",db::REPO_SELECT),&[&access.repo_id])
        .await.map_err(Error::internal)?;
    let repo = db::Repository::from_row(&row);
    auth::finish_tx(tx,&identity,false).await?;
    if repo.state != "ready" {
        return Err(Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "repository not ready",
        ));
    }
    Ok(repo)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrepareRequest {
    target_oid: String,
    storage_generation: i64,
}

pub(crate) async fn prepare(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
    Json(input): Json<PrepareRequest>,
) -> Result<Response, Error> {
    tokio::spawn(async move {
        if !crate::ci_pins::valid_oid(&input.target_oid) || input.storage_generation <= 0 {
            return Err(Error::bad_request());
        }
        let repo = repository(&state, &headers, &owner, &name).await?;
        if repo.storage_generation != input.storage_generation {
            return Err(Error(StatusCode::CONFLICT, "repository generation changed"));
        }
        let _slot = state.git_slots.clone().try_acquire_owned().map_err(|_| {
            Error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Git capacity exhausted; retry later",
            )
        })?;
        let pin = views::pinned_path(&state, &repo, &input.target_oid).await?;
        let root = state.storage.root.join("repos").join(repo.id.to_string());
        let snapshot: Snapshot = serde_json::from_slice(
            &read_regular(
                &root.join(format!(
                    "pin-{}-{}.json",
                    input.storage_generation, input.target_oid
                )),
                4096,
            )
            .map_err(Error::internal)?,
        )
        .map_err(Error::internal)?;
        if snapshot.repository_id != repo.id
            || snapshot.storage_generation != repo.storage_generation
        {
            return Err(Error::internal("mirror pin identity changed"));
        }
        views::validate_pin(
            &pin,
            &input.target_oid,
            &root.join(snapshot.snapshot.to_string()),
        )
        .map_err(Error::internal)?;
        // Explicit readiness rechecks the actual commit after restart, rather
        // than trusting a receipt alone. Snapshot fsck was completed at sync.
        let mut cmd = mirror_git(&state);
        cmd.arg("--git-dir")
            .arg(&pin)
            .args(["cat-file", "-t", &input.target_oid]);
        if git_http::collect_git_output(cmd, 128, state.config.git_timeout)
            .await
            .map_err(Error::internal)?
            != b"commit\n"
        {
            return Err(Error::internal("prepared mirror target is not a commit"));
        }
        let mut cmd = mirror_git(&state);
        cmd.arg("--git-dir").arg(&pin).args([
            "fsck",
            "--full",
            "--strict",
            "--no-reflogs",
            "--no-dangling",
        ]);
        git_http::collect_git_output(cmd, 64 * 1024, state.config.git_timeout)
            .await
            .map_err(Error::internal)?;
        let current = repository(&state, &headers, &owner, &name).await?;
        if current.id != repo.id || current.storage_generation != repo.storage_generation {
            return Err(Error(StatusCode::CONFLICT, "repository generation changed"));
        }
        observability::for_state(&state).record_prepare_success();
        Ok((
            [(header::CACHE_CONTROL, "no-store")],
            Json(serde_json::json!({
                "repository_id":repo.id, "storage_generation":repo.storage_generation,
                "object_format":"sha1", "target_oid":input.target_oid, "snapshot":snapshot.snapshot,
                "clone_path":format!("/ci/{}/git/{owner}/{name}.git",input.target_oid)
            })),
        )
            .into_response())
    })
    .await
    .map_err(Error::internal)?
}

pub(crate) async fn sync(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    // Keep cleanup and locks alive even if the HTTP caller disconnects.
    tokio::spawn(async move { sync_snapshot(state, owner, name, headers, None).await })
        .await
        .map_err(Error::internal)?
}

pub(crate) async fn sync_scoped(state:Arc<AppState>,owner:String,name:String,
    headers:HeaderMap,scope:IntegrationScope)->Result<Response,Error>{
    tokio::spawn(async move {sync_snapshot(state,owner,name,headers,Some(scope)).await})
        .await.map_err(Error::internal)?
}

async fn sync_snapshot(
    state: Arc<AppState>,
    owner: String,
    name: String,
    headers: HeaderMap,
    scope: Option<IntegrationScope>,
) -> Result<Response, Error> {
    let repo = repository(&state, &headers, &owner, &name).await?;
    if let Some(scope)=&scope {scope.validate_source(&state,repo.id).await?;}
    let mut sync_permit = limiter::for_state(&state).try_acquire_sync(&state, repo.id)?;
    let _permit = state.git_slots.clone().try_acquire_owned().map_err(|_| {
        Error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Git capacity exhausted; retry later",
        )
    })?;
    let _lock = tokio::time::timeout(state.config.git_timeout, state.storage.write_lock(repo.id))
        .await
        .map_err(|_| Error::timeout())?;
    let root = state.storage.root.join("repos").join(repo.id.to_string());
    private_directory(&root).map_err(Error::internal)?;
    let snapshot = Snapshot {
        repository_id: repo.id,
        storage_generation: repo.storage_generation,
        snapshot: Uuid::new_v4(),
    };
    let stage = root.join(format!(".{}.staging", snapshot.snapshot));
    let final_path = root.join(snapshot.snapshot.to_string());
    let result = async {
        private_directory(&stage)?;
        let bare = stage.join("repository.git");
        if let Some(scope)=&scope {scope.validate_source(&state,repo.id).await
            .map_err(|_|anyhow::anyhow!("CI source grant revoked"))?;}
        let url = format!(
            "{}/git/{owner}/{name}.git",
            state.mirror_primary.as_ref().context("not a mirror")?
        );
        let authorization = headers
            .get(header::AUTHORIZATION)
            .context("missing auth")?
            .to_str()?;
        let mut command = mirror_git(&state);
        command
            .args([
                "-c",
                "http.followRedirects=false",
                "-c",
                "credential.helper=",
                "-c",
                "protocol.allow=never",
                "-c",
                "protocol.http.allow=always",
                "-c",
                "protocol.https.allow=always",
                "-c",
                "fetch.fsckObjects=true",
                "-c",
                "core.hooksPath=/dev/null",
            ])
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", format!("http.{url}.extraHeader"))
            .env(
                "GIT_CONFIG_VALUE_0",
                format!("Authorization: {authorization}"),
            )
            .args(["clone", "--mirror", "--no-local", "--template=", "--"])
            .arg(&url)
            .arg(&bare);
        git_http::collect_git_output(command, 4096, state.config.git_timeout).await?;
        let mut command = mirror_git(&state);
        command
            .arg("--git-dir")
            .arg(&bare)
            .args(["fsck", "--full", "--strict", "--no-reflogs"]);
        git_http::collect_git_output(command, 64 * 1024, state.config.git_timeout).await?;
        if crate::storage::disk_bytes(&stage, state.config.max_repo_bytes)?
            >= state.config.max_repo_bytes
        {
            bail!("mirror snapshot size limit reached");
        }
        let mut command = mirror_git(&state);
        command
            .arg("--git-dir")
            .arg(&bare)
            .args(["rev-parse", "--show-object-format"]);
        if git_http::collect_git_output(command, 128, state.config.git_timeout).await? != b"sha1\n"
        {
            bail!("mirror supports only SHA-1 repositories");
        }
        // Do not retain credential helpers, source remotes, or writable transport settings.
        std::fs::write(bare.join("config"), bare_config())?;
        private_directory(&stage.join("pins"))?;
        let sync_stage = stage.clone();
        tokio::task::spawn_blocking(move || crate::storage::sync_tree(&sync_stage)).await??;
        // Fresh authority check also catches revocation or generation changes during copying.
        let current = repository(&state, &headers, &owner, &name)
            .await
            .map_err(|_| anyhow::anyhow!("authorization or repository changed"))?;
        if current.id != repo.id || current.storage_generation != repo.storage_generation {
            bail!("repository generation changed");
        }
        if let Some(scope)=&scope {scope.validate_source(&state,repo.id).await
            .map_err(|_|anyhow::anyhow!("CI source grant revoked"))?;}
        std::fs::rename(&stage, &final_path)?;
        File::open(&root)?.sync_all()?;
        atomic_file(&root, "current.json", &serde_json::to_vec(&snapshot)?)?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    if result.is_err() {
        observability::for_state(&state).record_sync_failure();
        // Only this invocation's unpublished tree. Published snapshots are never pruned here.
        let _ = std::fs::remove_dir_all(&stage);
    }
    result.map_err(Error::internal)?;
    sync_permit.mark_completed();
    observability::for_state(&state).record_sync_success();
    eviction::enforce_watermark_locked(&state, &repo).await;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(snapshot)).into_response())
}

pub(crate) fn bare_config() -> &'static str {
    "[core]\n\tbare = true\n\thooksPath = /dev/null\n[http]\n\treceivepack = false\n\tgetanyfile = false\n[uploadpack]\n\tallowFilter = false\n\tallowAnySHA1InWant = false\n\tallowTipSHA1InWant = false\n\tallowReachableSHA1InWant = false\n[gc]\n\tauto = 0\n[maintenance]\n\tauto = false\n[pack]\n\tthreads = 1\n\twindowMemory = 32m\n\tdeltaCacheSize = 32m\n"
}

pub(crate) fn private_directory(path: &FsPath) -> Result<()> {
    match std::fs::create_dir(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    if !std::fs::symlink_metadata(path)?.is_dir() {
        bail!("expected real private directory");
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    File::open(path)?.sync_all()?;
    File::open(path.parent().context("directory needs parent")?)?.sync_all()?;
    Ok(())
}

pub(crate) fn atomic_file(root: &FsPath, name: &str, bytes: &[u8]) -> Result<()> {
    let temporary = root.join(format!(".{}.tmp", Uuid::new_v4()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, root.join(name))?;
    File::open(root)?.sync_all()?;
    Ok(())
}

pub(crate) fn verify_directory(path: &FsPath) -> Result<()> {
    if !std::fs::symlink_metadata(path)?.is_dir() || path.canonicalize()? != path {
        bail!("mirror directory must be real and contained");
    }
    Ok(())
}

pub(crate) fn read_regular(path: &FsPath, maximum: u64) -> Result<Vec<u8>> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > maximum {
        bail!("invalid mirror metadata file");
    }
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        bail!("oversized mirror metadata");
    }
    Ok(bytes)
}

pub(crate) fn mirror_git(state: &AppState) -> Command {
    let mut cmd = state.storage.git(&state.config);
    cmd.env("GIT_NO_REPLACE_OBJECTS", "1");
    let memory = state.config.git_memory_bytes;
    let file = state.config.max_repo_bytes;
    let cpu = state.config.git_timeout.as_secs().max(1);
    unsafe {
        cmd.pre_exec(move || {
            for (resource, limit) in [
                (libc::RLIMIT_AS, memory),
                (libc::RLIMIT_CPU, cpu),
                (libc::RLIMIT_FSIZE, file),
                (libc::RLIMIT_NOFILE, 256),
            ] {
                let value = libc::rlimit {
                    rlim_cur: limit,
                    rlim_max: limit,
                };
                if libc::setrlimit(resource, &value) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    cmd
}

pub(crate) fn ci_route(path: &str) -> Result<(&str, &str), Error> {
    let tail = path.strip_prefix("/ci/").ok_or_else(Error::not_found)?;
    let (oid, rest) = tail.split_once('/').ok_or_else(Error::not_found)?;
    if !matches!(oid.len(), 40 | 64)
        || !oid
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::bad_request());
    }
    // Return the raw /git/... suffix so the normal strict path parser still applies.
    Ok((oid, &path[path.len() - rest.len() - 1..]))
}
