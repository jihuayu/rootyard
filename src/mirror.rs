//! Explicit, full-snapshot read mirrors. No write authority, automatic failover,
//! replication scheduler, or garbage collection is implied by this first slice.
use crate::{AppState, Error, auth, config::Config, db, git_http, storage::Storage};
use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use deadpool_postgres::Pool;
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path as FsPath, PathBuf},
    sync::Arc,
};
use tokio::process::Command;
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    repository_id: Uuid,
    storage_generation: i64,
    snapshot: Uuid,
}

/// Only a configured trusted primary receives the caller's existing token.
/// Redirects, credential helpers and arbitrary Git transports are disabled.
fn primary_origin(value: &str) -> Result<String> {
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

pub async fn open(config: Config, pool: Pool) -> Result<Arc<AppState>> {
    let primary = primary_origin(
        &std::env::var("ROOTYARD_PRIMARY_URL")
            .context("ROOTYARD_PRIMARY_URL is required for a read mirror")?,
    )?;
    let storage = Storage::open_mirror(&config)?;
    // Read replicas never migrate, repair, provision, reconcile, or run workers.
    pool.get()
        .await?
        .simple_query("SELECT id, storage_generation FROM repositories LIMIT 0")
        .await?;
    let state = Arc::new(AppState {
        git_slots: Arc::new(tokio::sync::Semaphore::new(config.max_concurrent_git)),
        mirror_primary: Some(primary),
        config,
        pool,
        storage,
        hooks: None,
        transfer_metrics: Arc::new(crate::metrics::TransferCounters::default()),
        dispatch: crate::dispatch::Signals::default(),
    });
    let mut command = mirror_git(&state);
    command.arg("--version");
    let version = git_http::collect_git_output(command, 256, state.config.git_timeout).await?;
    let text = String::from_utf8(version)?;
    let version: Vec<_> = text
        .split_whitespace()
        .nth(2)
        .unwrap_or("")
        .split('.')
        .take(2)
        .map(|n| n.parse::<u32>().unwrap_or(0))
        .collect();
    if version.len() != 2 || (version[0], version[1]) < (2, 43) {
        bail!("Git 2.43 or newer is required");
    }
    Ok(state)
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health/live", get(|| async { "ok" }))
        .route("/health/ready", get(ready))
        .route("/api/repos/{owner}/{name}/mirror-sync", post(sync))
        .route("/api/repos/{owner}/{name}/mirror-prepare", post(prepare))
        .fallback(|State(state): State<Arc<AppState>>, request| async move {
            git_http::handle(state, request).await
        })
        .layer(DefaultBodyLimit::max(16 * 1024))
        .with_state(state)
}

async fn ready(State(state): State<Arc<AppState>>) -> Result<&'static str, Error> {
    state
        .pool
        .get()
        .await
        .map_err(Error::internal)?
        .simple_query("SELECT id, storage_generation FROM repositories LIMIT 0")
        .await
        .map_err(Error::internal)?;
    if !state.storage.root.join("repos").is_dir() {
        return Err(Error::internal("mirror volume unavailable"));
    }
    Ok("ready")
}

async fn repository(
    state: &AppState,
    headers: &HeaderMap,
    owner: &str,
    name: &str,
) -> Result<db::Repository, Error> {
    let identity = auth::authenticate(&state.pool, headers).await?;
    if identity.username != owner || !db::valid_name(owner) || !db::valid_name(name) {
        return Err(Error::not_found());
    }
    let row = state
        .pool
        .get()
        .await
        .map_err(Error::internal)?
        .query_opt(
            &format!("{} WHERE r.owner_id=$1 AND r.name=$2", db::REPO_SELECT),
            &[&identity.id, &name],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let repo = db::Repository::from_row(&row);
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
struct PrepareRequest {
    target_oid: String,
    storage_generation: i64,
}
async fn prepare(
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
        let pin = pinned_path(&state, &repo, &input.target_oid).await?;
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
        validate_pin(
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

async fn sync(
    State(state): State<Arc<AppState>>,
    Path((owner, name)): Path<(String, String)>,
    headers: HeaderMap,
) -> Result<Response, Error> {
    // Keep cleanup and locks alive even if the HTTP caller disconnects.
    tokio::spawn(async move { sync_snapshot(state, owner, name, headers).await })
        .await
        .map_err(Error::internal)?
}
async fn sync_snapshot(
    state: Arc<AppState>,
    owner: String,
    name: String,
    headers: HeaderMap,
) -> Result<Response, Error> {
    let repo = repository(&state, &headers, &owner, &name).await?;
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
        std::fs::rename(&stage, &final_path)?;
        File::open(&root)?.sync_all()?;
        atomic_file(&root, "current.json", &serde_json::to_vec(&snapshot)?)?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    if result.is_err() {
        // Only this invocation's unpublished tree. Published snapshots are never pruned here.
        let _ = std::fs::remove_dir_all(&stage);
    }
    result.map_err(Error::internal)?;
    Ok(([(header::CACHE_CONTROL, "no-store")], Json(snapshot)).into_response())
}

fn bare_config() -> &'static str {
    "[core]\n\tbare = true\n\thooksPath = /dev/null\n[http]\n\treceivepack = false\n\tgetanyfile = false\n[uploadpack]\n\tallowFilter = false\n\tallowAnySHA1InWant = false\n\tallowTipSHA1InWant = false\n\tallowReachableSHA1InWant = false\n[gc]\n\tauto = 0\n[maintenance]\n\tauto = false\n[pack]\n\tthreads = 1\n\twindowMemory = 32m\n\tdeltaCacheSize = 32m\n"
}
fn private_directory(path: &FsPath) -> Result<()> {
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
fn atomic_file(root: &FsPath, name: &str, bytes: &[u8]) -> Result<()> {
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
    if oid.len() != 40
        || !oid
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::bad_request());
    }
    // Return the raw /git/... suffix so the normal strict path parser still applies.
    Ok((oid, &path[path.len() - rest.len() - 1..]))
}

/// Pin by immutable snapshot and exact commit. Old snapshots and pins are kept;
/// no GC may remove objects referenced by these views or by active Git children.
pub(crate) async fn pinned_path(
    state: &AppState,
    repo: &db::Repository,
    oid: &str,
) -> Result<PathBuf, Error> {
    let root = state.storage.root.join("repos").join(repo.id.to_string());
    let unavailable = || {
        Error(
            StatusCode::CONFLICT,
            "mirror has no complete snapshot for this generation; sync and retry",
        )
    };
    let pin_name = format!("pin-{}-{oid}.json", repo.storage_generation);
    let load = || -> Result<(Snapshot, bool), Error> {
        let (path, pinned) = match root.join(&pin_name).try_exists() {
            Ok(true) => (root.join(&pin_name), true),
            Ok(false) => (root.join("current.json"), false),
            Err(error) => return Err(Error::internal(error)),
        };
        verify_directory(&root).map_err(|_| unavailable())?;
        let bytes = read_regular(&path, 4096).map_err(|_| unavailable())?;
        let snapshot: Snapshot = serde_json::from_slice(&bytes).map_err(Error::internal)?;
        if snapshot.repository_id != repo.id
            || snapshot.storage_generation != repo.storage_generation
        {
            return Err(unavailable());
        }
        Ok((snapshot, pinned))
    };
    let (snapshot, pinned) = load()?;
    let path_for = |snapshot: &Snapshot| {
        root.join(snapshot.snapshot.to_string())
            .join("pins")
            .join(format!("{oid}.git"))
    };
    if pinned {
        let pin = path_for(&snapshot);
        validate_pin(&pin, oid, &root.join(snapshot.snapshot.to_string()))
            .map_err(Error::internal)?;
        return Ok(pin);
    }
    let _lock = tokio::time::timeout(state.config.git_timeout, state.storage.write_lock(repo.id))
        .await
        .map_err(|_| Error::timeout())?;
    // A concurrent request may have established this pin while we waited. Pins
    // survive later snapshots that drop the original ref, but never generations.
    let (snapshot, pinned) = load()?;
    if !pinned {
        let mut count = 0;
        let mut entries = 0;
        for entry in std::fs::read_dir(&root).map_err(Error::internal)? {
            entries += 1;
            if entries > 100_000 {
                return Err(Error::internal("mirror directory exceeds bound"));
            }
            let entry = entry.map_err(Error::internal)?;
            if entry.file_name().to_string_lossy().starts_with("pin-") {
                count += 1;
            }
        }
        if count >= crate::ci_pins::MAX_PINS {
            return Err(Error(
                StatusCode::TOO_MANY_REQUESTS,
                "mirror pin admission limit reached",
            ));
        }
    }
    let snapshot_root = root.join(snapshot.snapshot.to_string());
    let bare = snapshot_root.join("repository.git");
    for path in [
        &snapshot_root,
        &bare,
        &bare.join("objects"),
        &snapshot_root.join("pins"),
    ] {
        verify_directory(path).map_err(Error::internal)?;
    }
    let pin = path_for(&snapshot);
    if pin.try_exists().map_err(Error::internal)? {
        validate_pin(&pin, oid, &snapshot_root).map_err(Error::internal)?;
        if !pinned {
            atomic_file(
                &root,
                &pin_name,
                &serde_json::to_vec(&snapshot).map_err(Error::internal)?,
            )
            .map_err(Error::internal)?;
        }
        return Ok(pin);
    }
    let mut command = mirror_git(state);
    command
        .arg("--git-dir")
        .arg(&bare)
        .args(["cat-file", "-t", oid]);
    let result = git_http::collect_git_output(command, 128, state.config.git_timeout).await;
    if !matches!(result,Ok(ref bytes) if bytes==b"commit\n") {
        return Err(Error(
            StatusCode::CONFLICT,
            "exact commit unavailable on mirror; sync and retry or use primary explicitly",
        ));
    }
    let temporary = snapshot_root
        .join("pins")
        .join(format!(".{}.staging", Uuid::new_v4()));
    let result = (|| -> Result<()> {
        private_directory(&temporary)?;
        for name in ["objects", "objects/info", "refs", "refs/heads"] {
            private_directory(&temporary.join(name))?;
        }
        std::fs::write(temporary.join("HEAD"), b"ref: refs/heads/main\n")?;
        std::fs::write(temporary.join("refs/heads/main"), format!("{oid}\n"))?;
        std::fs::write(temporary.join("config"), bare_config())?;
        let objects = bare.join("objects").canonicalize()?;
        let text = objects
            .to_str()
            .context("mirror data directory must be UTF-8")?;
        if text.contains(['\n', '\r']) {
            bail!("invalid mirror data path");
        }
        std::fs::write(
            temporary.join("objects/info/alternates"),
            format!("{text}\n"),
        )?;
        crate::storage::sync_tree(&temporary)?;
        std::fs::rename(&temporary, &pin)?;
        File::open(snapshot_root.join("pins"))?.sync_all()?;
        atomic_file(&root, &pin_name, &serde_json::to_vec(&snapshot)?)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_dir_all(&temporary);
    }
    result.map_err(Error::internal)?;
    Ok(pin)
}

fn verify_directory(path: &FsPath) -> Result<()> {
    if !std::fs::symlink_metadata(path)?.is_dir() || path.canonicalize()? != path {
        bail!("mirror directory must be real and contained");
    }
    Ok(())
}
fn read_regular(path: &FsPath, maximum: u64) -> Result<Vec<u8>> {
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
fn validate_pin(pin: &FsPath, oid: &str, snapshot: &FsPath) -> Result<()> {
    for path in [
        snapshot.to_path_buf(),
        snapshot.join("repository.git"),
        snapshot.join("repository.git/objects"),
        snapshot.join("pins"),
        pin.to_path_buf(),
        pin.join("objects"),
        pin.join("objects/info"),
        pin.join("refs"),
        pin.join("refs/heads"),
    ] {
        verify_directory(&path)?;
    }
    if read_regular(&pin.join("HEAD"), 64)? != b"ref: refs/heads/main\n"
        || read_regular(&pin.join("refs/heads/main"), 64)? != format!("{oid}\n").as_bytes()
        || read_regular(&pin.join("config"), 4096)? != bare_config().as_bytes()
        || read_regular(&pin.join("objects/info/alternates"), 4096)?
            != format!("{}\n", snapshot.join("repository.git/objects").display()).as_bytes()
    {
        bail!("immutable mirror pin changed");
    }
    Ok(())
}

/// A runner authorization must never use the legacy alternates-backed pin.
/// This independently materializes only the target's full reachable ancestry.
pub(crate) async fn job_path(
    state: &AppState,
    repo: &db::Repository,
    oid: &str,
) -> Result<PathBuf, Error> {
    let root = state.storage.root.join("repos").join(repo.id.to_string());
    let views = root.join("job-views");
    let destination = views.join(format!("{}-{oid}.git", repo.storage_generation));
    if destination.try_exists().map_err(Error::internal)? {
        validate_job_view(state, &destination, oid)
            .await
            .map_err(Error::internal)?;
        return Ok(destination);
    }
    // Establish the existing immutable snapshot selection before taking the
    // shared repository preparation lock (pinned_path takes that same lock).
    let source = pinned_path(state, repo, oid).await?;
    let _lock = tokio::time::timeout(state.config.git_timeout, state.storage.write_lock(repo.id))
        .await
        .map_err(|_| Error::timeout())?;
    if destination.try_exists().map_err(Error::internal)? {
        validate_job_view(state, &destination, oid)
            .await
            .map_err(Error::internal)?;
        return Ok(destination);
    }
    let snapshot = source
        .parent()
        .and_then(FsPath::parent)
        .ok_or_else(Error::bad_request)?;
    let bare = snapshot.join("repository.git");
    let stage = views.join(format!(".{}.staging", Uuid::new_v4()));
    let result = async {
        verify_directory(&root)?;
        private_directory(&views)?;
        // Never allow a source graft/shallow/promisor/alternate to silently
        // shorten history or fetch an undeclared external dependency.
        for forbidden in [
            "shallow",
            "info/grafts",
            "objects/info/alternates",
            "objects/info/http-alternates",
        ] {
            anyhow::ensure!(
                !crate::journal::exists(&bare.join(forbidden))?,
                "unsupported source topology"
            );
        }
        anyhow::ensure!(
            read_regular(&bare.join("config"), 4096)? == bare_config().as_bytes(),
            "snapshot configuration changed"
        );
        for entry in std::fs::read_dir(bare.join("objects/pack"))? {
            anyhow::ensure!(
                !entry?.file_name().to_string_lossy().ends_with(".promisor"),
                "promisor source unsupported"
            );
        }
        let expected = closure_objects(state, &source, oid).await?;
        private_directory(&stage)?;
        let view = stage.join("view.git");
        private_directory(&view)?;
        for dir in [
            "objects",
            "objects/pack",
            "objects/info",
            "refs",
            "refs/heads",
        ] {
            private_directory(&view.join(dir))?;
        }
        std::fs::write(view.join("HEAD"), b"ref: refs/heads/main\n")?;
        std::fs::write(view.join("refs/heads/main"), format!("{oid}\n"))?;
        std::fs::write(view.join("config"), bare_config())?;
        let input = stage.join("revisions");
        std::fs::write(&input, format!("{oid}\n"))?;
        let mut cmd = mirror_git(state);
        cmd.arg("--git-dir")
            .arg(&source)
            .args(["-c", "pack.writeReverseIndex=false"])
            .args([
                "pack-objects",
                "--revs",
                "--no-reuse-delta",
                "--no-reuse-object",
            ])
            .arg(view.join("objects/pack/pack"));
        git_http::collect_git_output_input(
            cmd,
            128,
            state.config.git_timeout,
            File::open(input)?.into(),
        )
        .await?;
        validate_job_view(state, &view, oid).await?;
        anyhow::ensure!(
            all_objects(state, &view).await? == expected,
            "materialized target object set differs"
        );
        anyhow::ensure!(
            crate::storage::disk_bytes(&stage, state.config.max_repo_bytes)?
                < state.config.max_repo_bytes,
            "job view exceeds quota"
        );
        let to_sync = view.clone();
        tokio::task::spawn_blocking(move || crate::storage::sync_tree(&to_sync)).await??;
        std::fs::rename(&view, &destination)?;
        File::open(&views)?.sync_all()?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    // Only this unpublished staging directory, never retained objects.
    if stage.exists() {
        let _ = std::fs::remove_dir_all(stage);
    }
    result.map_err(Error::internal)?;
    Ok(destination)
}
async fn object_command(state: &AppState, path: &FsPath, args: &[&str]) -> Result<Vec<u8>> {
    let mut cmd = mirror_git(state);
    cmd.arg("--git-dir").arg(path).args(args);
    git_http::collect_git_output(cmd, 64 * 1024 * 1024, state.config.git_timeout).await
}
fn object_set(bytes: Vec<u8>) -> Result<std::collections::BTreeSet<String>> {
    let mut result = std::collections::BTreeSet::new();
    for oid in std::str::from_utf8(&bytes)?.lines() {
        anyhow::ensure!(crate::ci_pins::valid_oid(oid), "invalid object enumeration");
        result.insert(oid.to_owned());
    }
    anyhow::ensure!(!result.is_empty(), "empty object closure");
    Ok(result)
}
async fn closure_objects(
    state: &AppState,
    path: &FsPath,
    oid: &str,
) -> Result<std::collections::BTreeSet<String>> {
    object_set(
        object_command(
            state,
            path,
            &["rev-list", "--objects", "--no-object-names", oid, "--"],
        )
        .await?,
    )
}
async fn all_objects(
    state: &AppState,
    path: &FsPath,
) -> Result<std::collections::BTreeSet<String>> {
    object_set(
        object_command(
            state,
            path,
            &[
                "cat-file",
                "--batch-all-objects",
                "--batch-check=%(objectname)",
            ],
        )
        .await?,
    )
}
async fn validate_job_view(state: &AppState, path: &FsPath, oid: &str) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    // Closed filesystem grammar: no symlinks, extra refs, loose objects, grafts,
    // shallow/promisor metadata, alternates, hooks, URL routes or config extras.
    verify_directory(path)?;
    let directories = [
        "objects",
        "objects/pack",
        "objects/info",
        "refs",
        "refs/heads",
    ];
    let files = ["HEAD", "config", "refs/heads/main"];
    let mut stack = vec![path.to_path_buf()];
    let mut packs = std::collections::BTreeSet::new();
    let mut indexes = std::collections::BTreeSet::new();
    let mut count = 0;
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(dir)? {
            count += 1;
            anyhow::ensure!(count <= 32, "unexpected job view entries");
            let entry = entry?;
            let p = entry.path();
            let meta = std::fs::symlink_metadata(&p)?;
            let relative = p
                .strip_prefix(path)?
                .to_str()
                .context("invalid job view path")?;
            if meta.is_dir() {
                anyhow::ensure!(
                    directories.contains(&relative),
                    "unexpected job view directory"
                );
                verify_directory(&p)?;
                stack.push(p);
            } else {
                anyhow::ensure!(
                    meta.is_file() && meta.nlink() == 1,
                    "non-private job view file"
                );
                if files.contains(&relative) {
                    continue;
                }
                let suffix = relative
                    .strip_prefix("objects/pack/pack-")
                    .context("unexpected job view file")?;
                let (hash, extension) = suffix.split_once('.').context("invalid job view pack")?;
                anyhow::ensure!(crate::ci_pins::valid_oid(hash), "invalid job pack identity");
                match extension {
                    "pack" => {
                        packs.insert(hash.to_owned());
                    }
                    "idx" => {
                        indexes.insert(hash.to_owned());
                    }
                    _ => anyhow::bail!("unexpected job pack metadata"),
                }
            }
        }
    }
    anyhow::ensure!(
        packs.len() == 1 && packs == indexes,
        "job pack pair differs"
    );
    for dir in directories {
        verify_directory(&path.join(dir))?;
    }
    anyhow::ensure!(
        read_regular(&path.join("config"), 4096)? == bare_config().as_bytes()
            && read_regular(&path.join("HEAD"), 64)? == b"ref: refs/heads/main\n"
            && read_regular(&path.join("refs/heads/main"), 64)? == format!("{oid}\n").as_bytes(),
        "job identity changed"
    );
    anyhow::ensure!(
        object_command(state, path, &["rev-parse", "--show-object-format"]).await? == b"sha1\n",
        "job object format changed"
    );
    anyhow::ensure!(
        object_command(state, path, &["cat-file", "-t", oid]).await? == b"commit\n",
        "job target must be a commit"
    );
    object_command(state, path, &["fsck", "--full", "--strict", "--no-reflogs"]).await?;
    anyhow::ensure!(
        closure_objects(state, path, oid).await? == all_objects(state, path).await?,
        "job view contains unrelated objects"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn primary_is_only_a_trusted_origin() {
        for good in [
            "https://git.example.test",
            "https://git.example.test:8443/",
            "http://127.0.0.1:8080",
            "http://[::1]:8080",
        ] {
            assert!(primary_origin(good).is_ok(), "{good}");
        }
        for bad in [
            "http://example.test",
            "file:///tmp/repo",
            "https://user:pass@example.test",
            "https://example.test/git",
            "https://example.test/?token=x",
            "https://example.test/#x",
            "ssh://example.test",
        ] {
            assert!(primary_origin(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn exact_oid_path_required() {
        let oid = "0123456789abcdef0123456789abcdef01234567";
        assert_eq!(
            ci_route(&format!("/ci/{oid}/git/a/b.git/info/refs")).unwrap(),
            (oid, "/git/a/b.git/info/refs")
        );
        for path in [
            "/git/a/b.git/info/refs",
            "/ci/main/git/a/b.git/info/refs",
            "/ci/../git/a/b.git/info/refs",
        ] {
            assert!(ci_route(path).is_err());
        }
    }
    #[test]
    fn metadata_and_pin_corruption_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        atomic_file(&root, "pointer", b"complete").unwrap();
        assert_eq!(
            read_regular(&root.join("pointer"), 32).unwrap(),
            b"complete"
        );
        assert!(read_regular(&root.join("pointer"), 2).is_err());
        std::os::unix::fs::symlink(root.join("pointer"), root.join("link")).unwrap();
        assert!(read_regular(&root.join("link"), 32).is_err());
        std::os::unix::fs::symlink(&root, root.join("escaped")).unwrap();
        assert!(verify_directory(&root.join("escaped")).is_err());
    }

    // Native Git coverage without a database server: exercise the exact views,
    // retained pins and replacement ref semantics, not HTTP/authentication.
    #[tokio::test]
    async fn native_git_views_keep_exact_pins_and_ignore_replacements() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let git = std::env::split_paths(&std::env::var_os("PATH").unwrap())
            .map(|p| p.join("git"))
            .find(|p| p.is_file())
            .unwrap()
            .canonicalize()
            .unwrap();
        let run = |dir: &FsPath, args: &[&str]| -> String {
            let output = std::process::Command::new(&git)
                .current_dir(dir)
                .env_clear()
                .env("PATH", "/usr/local/bin:/usr/bin:/bin")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .args(args)
                .output()
                .unwrap();
            assert!(output.status.success(), "Git fixture failed");
            String::from_utf8(output.stdout).unwrap().trim().to_owned()
        };
        let source = root.join("source");
        std::fs::create_dir(&source).unwrap();
        run(&source, &["init", "--initial-branch=main", "--template="]);
        std::fs::write(source.join("hello"), b"first\n").unwrap();
        run(&source, &["add", "hello"]);
        run(
            &source,
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-m",
                "first",
            ],
        );
        let oid = run(&source, &["rev-parse", "HEAD"]);
        let blob = run(&source, &["rev-parse", "HEAD:hello"]);
        // This is legal outside refs/heads and can arrive via a normal push.
        run(
            &source,
            &["update-ref", &format!("refs/replace/{blob}"), &oid],
        );
        let config = Config {
            database_url: "postgres://unused@127.0.0.1/unused".into(),
            data_dir: root.join("mirror"),
            bind: "127.0.0.1:0".parse().unwrap(),
            git,
            max_request_bytes: 1024 * 1024,
            max_output_bytes: 1024 * 1024,
            max_concurrent_git: 2,
            git_timeout: std::time::Duration::from_secs(20),
            git_memory_bytes: 1024 * 1024 * 1024,
            max_repo_bytes: 1024 * 1024 * 1024,
            max_pending_deliveries: 100,
            outbox_worker: false,
            metrics_bind: None,
        };
        let state = AppState {
            pool: db::pool(&config.database_url).unwrap(),
            storage: Storage::open_mirror(&config).unwrap(),
            config,
            mirror_primary: Some("http://127.0.0.1".into()),
            hooks: None,
            git_slots: Arc::new(tokio::sync::Semaphore::new(2)),
            transfer_metrics: Arc::new(crate::metrics::TransferCounters::default()),
            dispatch: crate::dispatch::Signals::default(),
        };
        let repo = db::Repository {
            id: Uuid::new_v4(),
            name: "demo".into(),
            owner: "alice".into(),
            state: "ready".into(),
            clone_path: String::new(),
            storage_backend: "gitfs".into(),
            storage_generation: 1,
        };
        let repo_root = state.storage.root.join("repos").join(repo.id.to_string());
        private_directory(&repo_root).unwrap();
        let snapshot = Snapshot {
            repository_id: repo.id,
            storage_generation: 1,
            snapshot: Uuid::new_v4(),
        };
        let snapshot_root = repo_root.join(snapshot.snapshot.to_string());
        private_directory(&snapshot_root).unwrap();
        private_directory(&snapshot_root.join("pins")).unwrap();
        let mut clone = mirror_git(&state);
        clone
            .args(["clone", "--mirror", "--no-hardlinks"])
            .arg(&source)
            .arg(snapshot_root.join("repository.git"));
        git_http::collect_git_output(clone, 4096, state.config.git_timeout)
            .await
            .unwrap();
        atomic_file(
            &repo_root,
            "current.json",
            &serde_json::to_vec(&snapshot).unwrap(),
        )
        .unwrap();
        assert_eq!(
            pinned_path(&state, &repo, &blob).await.unwrap_err().0,
            StatusCode::CONFLICT
        );
        let pin = pinned_path(&state, &repo, &oid).await.unwrap();
        validate_pin(&pin, &oid, &snapshot_root).unwrap();
        let mut clone = mirror_git(&state);
        clone
            .arg("clone")
            .arg("--no-local")
            .arg(&pin)
            .arg(root.join("checkout"));
        git_http::collect_git_output(clone, 4096, state.config.git_timeout)
            .await
            .unwrap();
        let mut head = mirror_git(&state);
        head.arg("-C")
            .arg(root.join("checkout"))
            .args(["rev-parse", "HEAD"]);
        assert_eq!(
            String::from_utf8(
                git_http::collect_git_output(head, 128, state.config.git_timeout)
                    .await
                    .unwrap()
            )
            .unwrap()
            .trim(),
            oid
        );
        // A later current snapshot cannot erase a previously established pin.
        let next = Snapshot {
            snapshot: Uuid::new_v4(),
            ..snapshot
        };
        atomic_file(
            &repo_root,
            "current.json",
            &serde_json::to_vec(&next).unwrap(),
        )
        .unwrap();
        assert_eq!(pinned_path(&state, &repo, &oid).await.unwrap(), pin);
        std::fs::write(pin.join("refs/heads/main"), format!("{blob}\n")).unwrap();
        assert_eq!(
            pinned_path(&state, &repo, &oid).await.unwrap_err().0,
            StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
