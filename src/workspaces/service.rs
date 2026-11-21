#[path = "lease_takeover.rs"]
mod takeover;

use self::takeover::{TakeoverGuards, commit_lease_tx, prepare_takeover, verify_takeover_checkpoint};
use super::models::{CreateWorkspace, LeaseRequest, WS_COLUMNS, Workspace};
use crate::{AppState, Error, auth, members::models::Role, storage::read_leases};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path as FsPath, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use uuid::Uuid;

pub fn workspace_root(state: &AppState) -> PathBuf {
    state.storage.root.join("workspace-service")
}
pub fn workspace_repo(state: &AppState, id: Uuid) -> PathBuf {
    if super::mounts::enabled() { super::mounts::mount_path(state, id) } else { super::mounts::lower_path(state, id) }
}
pub fn checkpoint_repo(state: &AppState, id: Uuid) -> PathBuf {
    workspace_root(state).join("checkpoints").join(id.to_string())
}
pub fn conflict() -> Error {
    Error(StatusCode::CONFLICT, "workspace version or lease conflict")
}

pub(crate) async fn creation_lock(
    tx: &deadpool_postgres::Transaction<'_>,
    actor: Uuid,
    key: &str,
) -> Result<(), Error> {
    tx.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended($1::uuid::text || ':' || $2::text, 709))",
        &[&actor, &key],
    )
    .await
    .map_err(Error::internal)?;
    Ok(())
}

pub(super) async fn lookup_existing_creation(
    tx: &deadpool_postgres::Transaction<'_>,
    actor_id: Uuid,
    key: &str,
    digest: &str,
    for_update: bool,
) -> Result<Option<Workspace>, Error> {
    let lock = if for_update { " FOR UPDATE" } else { "" };
    let sql = format!(
        "SELECT request_sha256,workspace_id FROM workspace_creations WHERE actor_id=$1 AND idempotency_key=$2{lock}"
    );
    let Some(row) = tx.query_opt(&sql, &[&actor_id, &key]).await.map_err(Error::internal)? else {
        return Ok(None);
    };
    if row.get::<_, String>(0) != digest {
        return Err(conflict());
    }
    let existing_id: Uuid = row.get(1);
    let row = tx
        .query_one(&format!("SELECT {WS_COLUMNS} FROM workspaces WHERE id=$1"), &[&existing_id])
        .await
        .map_err(Error::internal)?;
    Ok(Some(Workspace::from_row(&row)))
}

pub async fn git(state: &AppState, repo: &FsPath, args: &[&str], limit: usize) -> Result<Vec<u8>, Error> {
    super::git::run(state, repo, args, limit).await
}

pub async fn authorized(
    state: &AppState,
    headers: &HeaderMap,
    id: Uuid,
    role: Role,
    action: crate::token_scopes::RepoAction,
) -> Result<Workspace, Error> {
    let actor = auth::authenticate(&state.pool, headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let sql = format!("SELECT {WS_COLUMNS} FROM workspaces WHERE id=$1");
    let row = tx.query_opt(&sql, &[&id]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let ws = Workspace::from_row(&row);
    let access = auth::authorize_repo_with_role(&tx, &actor, &ws.owner, &ws.repository, role, action).await?;
    if access.repo_id != ws.repository_id || ws.creator_id != actor.id || ws.state != "ready" {
        return Err(Error::not_found());
    }
    tx.commit().await.map_err(Error::internal)?;
    drop(client);
    if !super::mounts::mounted(id) {
        return Err(Error::internal("workspace FUSE mount missing"));
    }
    Ok(ws)
}

pub async fn locked(
    tx: &deadpool_postgres::Transaction<'_>,
    actor: &crate::db::Identity,
    id: Uuid,
    role: Role,
    action: crate::token_scopes::RepoAction,
) -> Result<Workspace, Error> {
    locked_inner(tx, actor, id, role, action, true).await
}

async fn locked_inner(
    tx: &deadpool_postgres::Transaction<'_>,
    actor: &crate::db::Identity,
    id: Uuid,
    role: Role,
    action: crate::token_scopes::RepoAction,
    require_mount: bool,
) -> Result<Workspace, Error> {
    let sql = format!("SELECT {WS_COLUMNS} FROM workspaces WHERE id=$1");
    let row = tx.query_opt(&sql, &[&id]).await.map_err(Error::internal)?.ok_or_else(Error::not_found)?;
    let initial = Workspace::from_row(&row);
    let access = auth::authorize_repo_with_role(tx, actor, &initial.owner, &initial.repository, role, action).await?;
    if access.repo_id != initial.repository_id {
        return Err(Error::not_found());
    }
    let row = tx
        .query_one(&format!("SELECT {WS_COLUMNS} FROM workspaces WHERE id=$1 FOR UPDATE"), &[&id])
        .await
        .map_err(Error::internal)?;
    let ws = Workspace::from_row(&row);
    if ws.repository_id != initial.repository_id
        || ws.creator_id != initial.creator_id
        || ws.owner != initial.owner
        || ws.repository != initial.repository
        || ws.creator_id != actor.id
        || ws.state != "ready"
    {
        return Err(Error::not_found());
    }
    if require_mount && !super::mounts::mounted(id) {
        return Err(Error::internal("workspace FUSE mount missing"));
    }
    Ok(ws)
}

pub async fn get(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
) -> Result<Json<Workspace>, Error> {
    Ok(Json(authorized(&state, &headers, id, Role::Read, crate::token_scopes::RepoAction::WorkspacesRead).await?))
}

pub async fn lease(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<LeaseRequest>,
) -> Result<Json<Workspace>, Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;

    // Phase 1: short read pre-check without holding a row lock across S3 or disk work.
    let takeover = {
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let row = tx
            .query_opt(
                &format!(
                    "SELECT {WS_COLUMNS},lease_until<=clock_timestamp() AS lease_expired FROM workspaces WHERE id=$1"
                ),
                &[&id],
            )
            .await
            .map_err(Error::internal)?
            .ok_or_else(Error::not_found)?;
        let ws = Workspace::from_row(&row);
        let access = auth::authorize_repo_with_role(
            &tx,
            &actor,
            &ws.owner,
            &ws.repository,
            Role::Write,
            crate::token_scopes::RepoAction::WorkspacesWrite,
        )
        .await?;
        if access.repo_id != ws.repository_id || ws.creator_id != actor.id || ws.state != "ready" {
            return Err(Error::not_found());
        }
        if ws.lease_epoch != input.expected_lease_epoch {
            return Err(conflict());
        }
        let plan = if ws.host_id != state.storage.volume_id {
            if !row.get::<_, bool>("lease_expired") {
                return Err(conflict());
            }
            let cp = verify_takeover_checkpoint(&tx, &ws).await?;
            Some((cp, ws.repository_id, access.owner_id))
        } else {
            None
        };
        tx.commit().await.map_err(Error::internal)?;
        plan
    };
    let mutation = super::blocking::lock_mutation(id, super::blocking::io_timeout()).await?;

    // Phase 2: materialize cross-host takeover or check local repo off-thread with no DB TX held.
    let mut takeover_guards = if let Some((cp, repository_id, tenant)) = takeover {
        prepare_takeover(&state, id, cp, repository_id, tenant, &mutation).await?
    } else {
        let lower = super::mounts::lower_path(&state, id);
        if !super::blocking::run_mutating(&mutation, move |abandoned, _fence| {
            if abandoned.is_abandoned() {
                return Err(Error::timeout());
            }
            Ok(lower.join(".git").is_dir())
        })
        .await?
        {
            return Err(conflict());
        }
        TakeoverGuards::default()
    };

    // Phase 3: freeze local FUSE before checking out DB client on same-host renewals; clean up on pre-COMMIT failure.
    let commit_started = Arc::new(AtomicBool::new(false));
    let planned_cp = takeover.map(|(cp, _, _)| cp);
    let commit_phase = commit_lease_tx(
        &state,
        &actor,
        id,
        input.expected_lease_epoch,
        planned_cp,
        &mut takeover_guards,
        &commit_started,
    );
    let phase3: Result<(Workspace, i64), Error> = if takeover.is_none() {
        super::mounts::with_frozen_fenced(id, commit_started.clone(), mutation.freeze_guard(), commit_phase).await
    } else {
        commit_phase.await
    };

    let (saved, deadline) = match phase3 {
        Ok(pair) => pair,
        Err(error) => {
            if !commit_started.load(Ordering::Acquire) {
                takeover_guards.cleanup().await;
            }
            return Err(error);
        }
    };
    super::mounts::ensure_async(&state, id, saved.lease_epoch, deadline).await?;
    Ok(Json(saved))
}

pub async fn fence_restored(pool: &deadpool_postgres::Pool) -> Result<(), Error> {
    let mut client = pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    tx.execute(
        "UPDATE workspaces SET lease_epoch=lease_epoch+1,lease_until=clock_timestamp()-interval '1 second' WHERE state='ready'",
        &[],
    )
    .await
    .map_err(Error::internal)?;
    tx.execute(
        "UPDATE sandbox_jobs SET state='cancelled',pid=NULL,finished_at=clock_timestamp() WHERE state IN ('queued','preparing','running')",
        &[],
    )
    .await
    .map_err(Error::internal)?;
    tx.commit().await.map_err(Error::internal)
}

fn conflict_head() -> Error {
    Error(StatusCode::CONFLICT, super::compat::CONFLICT_HEAD)
}

fn probe_unavailable() -> Error {
    Error(StatusCode::SERVICE_UNAVAILABLE, "workspace Git probe unavailable")
}

/// Exact HEAD identity admitted from the service-owned source. The unborn target
/// is carried through the clone instead of being re-derived from clone defaults.
enum SourceHead {
    Committed { oid: String },
    Unborn { target: String },
}

enum GitProbe {
    Output(Vec<u8>),
    /// Only a documented `rev-parse --verify --quiet`/`config --get` exit 1 is
    /// treated as absence. Timeout, signal and every other failure stay errors.
    Absent,
}

enum SourceHeadFile {
    Symbolic(String),
    Detached,
}

fn classify_git_probe(error: anyhow::Error, expected_absent_exit: Option<i32>) -> Result<GitProbe, Error> {
    if let Some(failed) = error.downcast_ref::<crate::git_http::GitCommandFailed>() {
        if expected_absent_exit.is_some() && failed.exit == expected_absent_exit {
            return Ok(GitProbe::Absent);
        }
        return Err(probe_unavailable());
    }
    if error.to_string().contains("timed out") {
        return Err(Error::timeout());
    }
    Err(probe_unavailable())
}

/// Probe the exact verified source git directory, never a discovered parent.
async fn source_git_probe(
    state: &AppState,
    source: &FsPath,
    args: &[&str],
    limit: usize,
    expected_absent_exit: Option<i32>,
) -> Result<GitProbe, Error> {
    let mut command = state.storage.git(&state.config);
    command.args(["--no-optional-locks", "--no-replace-objects", "--git-dir"]).arg(source).args(args);
    match crate::git_http::collect_git_output(command, limit, state.config.git_timeout).await {
        Ok(output) => Ok(GitProbe::Output(output)),
        Err(error) => classify_git_probe(error, expected_absent_exit),
    }
}

async fn source_git_required(state: &AppState, source: &FsPath, args: &[&str], limit: usize) -> Result<Vec<u8>, Error> {
    match source_git_probe(state, source, args, limit, None).await? {
        GitProbe::Output(output) => Ok(output),
        GitProbe::Absent => Err(probe_unavailable()),
    }
}

/// Destination probes keep the workspace Git admission slot and the same clean
/// environment as ordinary workspace Git, while preserving the exit status.
async fn dest_git_probe(
    state: &AppState,
    repo: &FsPath,
    args: &[&str],
    limit: usize,
    expected_absent_exit: Option<i32>,
) -> Result<GitProbe, Error> {
    let _slot = super::git::try_slot(state)?;
    let mut command = state.storage.git(&state.config);
    command.args(["--no-optional-locks", "--no-replace-objects", "-C"]).arg(repo).args(args);
    match crate::git_http::collect_git_output(command, limit, state.config.git_timeout).await {
        Ok(output) => Ok(GitProbe::Output(output)),
        Err(error) => classify_git_probe(error, expected_absent_exit),
    }
}

async fn dest_git_required(state: &AppState, repo: &FsPath, args: &[&str], limit: usize) -> Result<Vec<u8>, Error> {
    match dest_git_probe(state, repo, args, limit, None).await? {
        GitProbe::Output(output) => Ok(output),
        GitProbe::Absent => Err(probe_unavailable()),
    }
}

fn parse_source_head(bytes: &[u8]) -> Result<SourceHeadFile, Error> {
    if bytes.contains(&0) {
        return Err(conflict_head());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| conflict_head())?;
    let trimmed = text.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() || trimmed.contains(['\r', '\n']) {
        return Err(conflict_head());
    }
    if let Some(target) = trimmed.strip_prefix("ref: ") {
        if !super::compat::is_safe_head_ref(target) {
            return Err(conflict_head());
        }
        return Ok(SourceHeadFile::Symbolic(target.to_owned()));
    }
    if super::compat::is_valid_sha1_oid(trimmed) {
        return Ok(SourceHeadFile::Detached);
    }
    Err(conflict_head())
}

fn source_dir_is_empty(path: &FsPath, budget: &mut usize) -> Result<bool, Error> {
    for entry in fs::read_dir(path).map_err(Error::internal)? {
        *budget += 1;
        if *budget > 4096 {
            return Err(conflict_head());
        }
        let entry = entry.map_err(Error::internal)?;
        let meta = fs::symlink_metadata(entry.path()).map_err(Error::internal)?;
        if meta.file_type().is_symlink() {
            return Err(conflict_head());
        }
        if meta.is_dir() {
            if !source_dir_is_empty(&entry.path(), budget)? {
                return Ok(false);
            }
        } else {
            return Ok(false);
        }
    }
    Ok(true)
}

fn require_empty_source_dir(path: &FsPath, required: bool, budget: &mut usize) -> Result<(), Error> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => {
            if source_dir_is_empty(path, budget)? {
                Ok(())
            } else {
                Err(conflict_head())
            }
        }
        Ok(_) => Err(conflict_head()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !required => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(conflict_head()),
        Err(error) => Err(Error::internal(error)),
    }
}

/// A declared unborn source must be a real, independent, genuinely empty bare
/// repository. The strict no-objects rule applies only here; an already-created
/// local workspace may legitimately hold staged blobs before its first commit.
fn validate_unborn_source_layout(source: &FsPath) -> Result<(), Error> {
    for rel in ["commondir", "gitdir", "shallow", "reftable", "worktrees", "modules"] {
        match fs::symlink_metadata(source.join(rel)) {
            Ok(_) => return Err(conflict_head()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(Error::internal(error)),
        }
    }
    let mut budget = 0usize;
    require_empty_source_dir(&source.join("objects"), true, &mut budget)?;
    require_empty_source_dir(&source.join("refs"), true, &mut budget)?;
    require_empty_source_dir(&source.join("info"), false, &mut budget)?;
    require_empty_source_dir(&source.join("logs"), false, &mut budget)?;
    let packed = source.join("packed-refs");
    match fs::symlink_metadata(&packed) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_file() {
                return Err(conflict_head());
            }
            let bytes = crate::workspace_lab::core::read_regular(&packed, crate::workspace_lab::core::MAX_MANIFEST)
                .map_err(Error::internal)?;
            if super::compat::packed_refs_has_any_ref(&bytes) {
                return Err(conflict_head());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(Error::internal(error)),
    }
    Ok(())
}

/// Admit the source snapshot as either a committed SHA-1 repository or a
/// genuinely declared unborn branch. The source is checked before cloning so a
/// malformed HEAD cannot be normalized by `git clone` into an empty checkout.
async fn validate_source_head(state: &AppState, source: &FsPath, repo_id: Uuid) -> Result<SourceHead, Error> {
    let head_source = source.to_path_buf();
    let head_file = super::blocking::run(move || {
        let head_bytes = crate::workspace_lab::core::read_regular(
            &head_source.join("HEAD"),
            crate::workspace_lab::core::MAX_MANIFEST,
        )
        .map_err(|_| conflict_head())?;
        parse_source_head(&head_bytes)
    })
    .await?;

    let format = source_git_required(state, source, &["rev-parse", "--show-object-format"], 4096).await?;
    if String::from_utf8_lossy(&format).trim() != "sha1" {
        return Err(conflict_head());
    }
    let bare = source_git_required(state, source, &["rev-parse", "--is-bare-repository"], 4096).await?;
    if String::from_utf8_lossy(&bare).trim() != "true" {
        return Err(conflict_head());
    }
    let identity = match source_git_probe(
        state,
        source,
        &["config", "--local", "--no-includes", "--get", "rootyard.repositoryId"],
        4096,
        Some(1),
    )
    .await?
    {
        GitProbe::Output(output) => String::from_utf8(output).map_err(|_| conflict_head())?.trim().to_owned(),
        GitProbe::Absent => return Err(conflict_head()),
    };
    if identity != repo_id.to_string() {
        return Err(conflict_head());
    }

    match source_git_probe(state, source, &["rev-parse", "--verify", "--quiet", "HEAD^{commit}"], 4096, Some(1)).await?
    {
        GitProbe::Output(commit) => {
            let oid = String::from_utf8(commit).map_err(|_| conflict_head())?.trim().to_owned();
            if !super::compat::is_valid_sha1_oid(&oid) {
                return Err(conflict_head());
            }
            Ok(SourceHead::Committed { oid })
        }
        GitProbe::Absent => {
            let target = match head_file {
                SourceHeadFile::Symbolic(target) if super::compat::is_safe_unborn_head_ref(&target) => target,
                _ => return Err(conflict_head()),
            };
            let unborn_source = source.to_path_buf();
            super::blocking::run(move || validate_unborn_source_layout(&unborn_source)).await?;
            // Structural emptiness above rejects loose refs, broken refs and
            // object files. `for-each-ref` additionally covers alternate ref
            // backends without relying on `fsck`, which can report dangling
            // objects and still exit 0.
            let refs = source_git_required(state, source, &["for-each-ref", "--format=%(refname)"], 64 * 1024).await?;
            if !refs.is_empty() {
                return Err(conflict_head());
            }
            match source_git_probe(state, source, &["rev-parse", "--verify", "--quiet", &target], 4096, Some(1)).await?
            {
                GitProbe::Absent => {}
                GitProbe::Output(_) => return Err(conflict_head()),
            }
            Ok(SourceHead::Unborn { target })
        }
    }
}

/// The cloned workspace must carry the exact symbolic branch name validated on
/// the source and must still have no refs. A fallback-master or detached clone is
/// therefore rejected instead of being mislabeled as a declared unborn branch.
async fn validate_cloned_unborn(state: &AppState, repo: &FsPath, expected: &str) -> Result<(), Error> {
    let symbolic = match dest_git_probe(state, repo, &["symbolic-ref", "-q", "HEAD"], 4096, Some(1)).await? {
        GitProbe::Output(output) => String::from_utf8(output).map_err(|_| conflict_head())?.trim().to_owned(),
        GitProbe::Absent => return Err(conflict_head()),
    };
    if symbolic != expected || !super::compat::is_safe_unborn_head_ref(&symbolic) {
        return Err(conflict_head());
    }
    let refs = dest_git_required(state, repo, &["for-each-ref", "--format=%(refname)"], 64 * 1024).await?;
    if !refs.is_empty() {
        return Err(conflict_head());
    }
    Ok(())
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(input): Json<CreateWorkspace>,
) -> Result<(StatusCode, Json<Workspace>), Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let key = auth::idempotency_key(&headers)?.ok_or_else(Error::bad_request)?.to_owned();
    if input.agent_id.is_empty()
        || input.agent_id.len() > 128
        || !input.agent_id.bytes().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
    {
        return Err(Error::bad_request());
    }
    if let Some(base) = &input.base_oid
        && !crate::browse::models::valid_non_zero_oid(base)
    {
        return Err(Error::bad_request());
    }
    let digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&(&input.owner, &input.repository, &input.agent_id, &input.base_oid))
            .map_err(Error::internal)?,
    ));

    // Phase 1: short read pre-check and idempotency fast path.
    let repo = {
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let repo = auth::authorize_repo_with_role(
            &tx,
            &actor,
            &input.owner,
            &input.repository,
            Role::Write,
            crate::token_scopes::RepoAction::WorkspacesWrite,
        )
        .await?;
        if let Some(saved) = lookup_existing_creation(&tx, actor.id, &key, &digest, false).await? {
            tx.commit().await.map_err(Error::internal)?;
            drop(client);
            super::mounts::ensure_from_database(&state, saved.id).await?;
            return Ok((StatusCode::OK, Json(saved)));
        }
        tx.commit().await.map_err(Error::internal)?;
        repo
    };

    // Phase 2: clone under bounded Git slot + source read lease, then compute
    // initial fingerprint on the bounded blocking pool with zero DB locks held.
    let id = Uuid::new_v4();
    let mutation = super::blocking::lock_mutation(id, state.config.git_timeout).await?;
    let dest = super::mounts::lower_path(&state, id);
    let dest_parent = dest.clone();
    super::blocking::run_mutating(&mutation, move |abandoned, _fence| {
        if abandoned.is_abandoned() {
            return Err(Error::timeout());
        }
        if let Some(parent) = dest_parent.parent() {
            fs::create_dir_all(parent).map_err(Error::internal)?;
        }
        Ok(())
    })
    .await?;
    let mut cleanup = Some(super::blocking::DirCleanupGuard::with_fence(dest.clone(), Some(mutation.freeze_guard())));
    let phase2_and_3: Result<(StatusCode, Workspace), Error> = async {
        let source_head = {
            let _clone_slot = super::git::try_slot(&state)?;
            let source_lease =
                read_leases::shared(&state.pool, repo.repo_id, tokio::time::Instant::now() + state.config.git_timeout)
                    .await?;
            let _local = tokio::time::timeout(state.config.git_timeout, state.storage.read_snapshot_lock(repo.repo_id))
                .await
                .map_err(|_| Error::timeout())?;
            source_lease.ensure_active()?;
            {
                let mut client = state.pool.get().await.map_err(Error::internal)?;
                let tx = client.transaction().await.map_err(Error::internal)?;
                let refreshed = auth::authorize_repo_with_role(
                    &tx,
                    &actor,
                    &input.owner,
                    &input.repository,
                    Role::Write,
                    crate::token_scopes::RepoAction::WorkspacesWrite,
                )
                .await?;
                if refreshed.repo_id != repo.repo_id {
                    return Err(Error::not_found());
                }
                tx.commit().await.map_err(Error::internal)?;
            }
            let repo_id = repo.repo_id;
            let state_verify = state.clone();
            let source =
                super::blocking::run(move || state_verify.storage.verify_path(repo_id).map_err(Error::internal))
                    .await?;
            let source_head = source_lease
                .guard(async {
                    let source_head = validate_source_head(&state, &source, repo_id).await?;
                    let mut clone = state.storage.git(&state.config);
                    clone
                        .args(["-c", "core.hooksPath=/dev/null", "clone", "--no-local", "--no-hardlinks", "--"])
                        .arg(&source)
                        .arg(&dest);
                    crate::git_http::collect_git_output(clone, 4096, state.config.git_timeout)
                        .await
                        .map_err(Error::internal)?;
                    Ok::<SourceHead, Error>(source_head)
                })
                .await??;
            source_lease.ensure_active()?;
            source_head
        };

        let head = match dest_git_probe(
            &state,
            &dest,
            &["rev-parse", "--verify", "--quiet", "HEAD^{commit}"],
            4096,
            Some(1),
        )
        .await?
        {
            GitProbe::Absent => None,
            GitProbe::Output(bytes) => {
                let value = String::from_utf8(bytes).map_err(|_| conflict_head())?.trim().to_owned();
                if !super::compat::is_valid_sha1_oid(&value) {
                    return Err(conflict_head());
                }
                Some(value)
            }
        };
        if let Some(base) = &input.base_oid
            && head.as_deref() != Some(base.as_str())
        {
            return Err(conflict());
        }
        let base_oid = match source_head {
            SourceHead::Committed { oid } => {
                let Some(head) = head else { return Err(conflict_head()) };
                if head != oid {
                    return Err(conflict_head());
                }
                let tree_listing = dest_git_required(
                    &state,
                    &dest,
                    &["ls-tree", "-r", "-z", "--full-tree", "HEAD"],
                    8 * 1024 * 1024,
                )
                .await?;
                super::compat::validate_tree_listing_no_gitlinks(&tree_listing)?;
                input.base_oid.clone().or(Some(head))
            }
            SourceHead::Unborn { target } => {
                if head.is_some() {
                    return Err(conflict_head());
                }
                validate_cloned_unborn(&state, &dest, &target).await?;
                None
            }
        };
        let dest_fp = dest.clone();
        let initial_fingerprint = super::blocking::run_mutating(&mutation, move |abandoned, _fence| {
            if abandoned.is_abandoned() {
                return Err(Error::timeout());
            }
            super::compat::validate_repo(&dest_fp)?;
            super::capture::fingerprint(&dest_fp)
        })
        .await?;

        // Phase 3: short commit transaction with zero filesystem or Git work.
        let mut client = state.pool.get().await.map_err(Error::internal)?;
        let tx = client.transaction().await.map_err(Error::internal)?;
        let refreshed = auth::authorize_repo_with_role(
            &tx,
            &actor,
            &input.owner,
            &input.repository,
            Role::Write,
            crate::token_scopes::RepoAction::WorkspacesWrite,
        )
        .await?;
        if refreshed.repo_id != repo.repo_id {
            return Err(Error::not_found());
        }
        creation_lock(&tx, actor.id, &key).await?;
        if let Some(saved) = lookup_existing_creation(&tx, actor.id, &key, &digest, true).await? {
            tx.commit().await.map_err(Error::internal)?;
            return Ok((StatusCode::OK, saved));
        }
        let host_id = state.storage.volume_id;
        tx.execute(
            "INSERT INTO workspaces(id,repository_id,owner_slug,repository_name,agent_id,creator_id,state,host_id,lease_until,base_oid) \
             VALUES($1,$2,$3,$4,$5,$6,'ready',$7,clock_timestamp()+interval '5 minutes',$8)",
            &[&id, &repo.repo_id, &input.owner, &input.repository, &input.agent_id, &actor.id, &host_id, &base_oid],
        )
        .await
        .map_err(Error::internal)?;
        tx.execute(
            "INSERT INTO workspace_creations(actor_id,idempotency_key,request_sha256,workspace_id) VALUES($1,$2,$3,$4)",
            &[&actor.id, &key, &digest, &id],
        )
        .await
        .map_err(Error::internal)?;
        super::capture::record_fingerprint(&tx, id, &initial_fingerprint).await?;
        let row = tx
            .query_one(&format!("SELECT {WS_COLUMNS} FROM workspaces WHERE id=$1"), &[&id])
            .await
            .map_err(Error::internal)?;
        if let Some(guard) = cleanup.take() {
            guard.keep();
        }
        tx.commit().await.map_err(Error::internal)?;
        Ok((StatusCode::CREATED, Workspace::from_row(&row)))
    }
    .await;

    if let Some(guard) = cleanup.take() {
        guard.cleanup().await;
    }
    let (status, saved) = phase2_and_3?;
    super::mounts::ensure_from_database(&state, saved.id).await?;
    Ok((status, Json(saved)))
}
