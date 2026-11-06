//! Import a projected Git bundle and map its tree back into a pinned source subdir.
use super::{changesets, views};
#[path = "reverse_git.rs"]
mod reverse_git;
use crate::{AppState, Error, auth, browse::transactions, members::models::Role, storage::read_leases};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use reverse_git::{git, git_input, git_oid, verify_candidate_budget};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    os::fd::AsRawFd,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path as FsPath, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};
use uuid::Uuid;

pub const BODY_LIMIT: usize = 24 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReverseInput {
    pub bundle_base64: String,
    pub bundle_ref: String,
    pub source_ref: String,
    pub message: String,
}

struct Stage(PathBuf);
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn replace_tree(repo: &FsPath, tree: &str, parts: &[&str], projected: &str) -> Result<String, Error> {
    let raw = git(repo, &["ls-tree", "-z", tree])?;
    let mut entries = BTreeMap::<Vec<u8>, Vec<u8>>::new();
    for record in raw.split(|b| *b == 0).filter(|r| !r.is_empty()) {
        let Some(tab) = record.iter().position(|b| *b == b'\t') else {
            return Err(Error::internal("invalid Git tree record"));
        };
        entries.insert(record[tab + 1..].to_vec(), record.to_vec());
    }
    let part = parts.first().ok_or_else(Error::bad_request)?;
    let key = part.as_bytes().to_vec();
    let next = if parts.len() == 1 {
        projected.to_owned()
    } else {
        let child = if let Some(old) = entries.get(&key) {
            let head = old.split(|b| *b == b'\t').next().unwrap_or_default();
            let text = std::str::from_utf8(head).map_err(Error::internal)?;
            let fields: Vec<&str> = text.split(' ').collect();
            if fields.len() != 3 || fields[1] != "tree" {
                return Err(Error(StatusCode::CONFLICT, "source path is not a tree"));
            }
            fields[2].to_owned()
        } else {
            git_input(repo, &["mktree", "-z"], b"", None)?
        };
        replace_tree(repo, &child, &parts[1..], projected)?
    };
    entries.insert(key, format!("040000 tree {next}\t{part}").into_bytes());
    let mut out = Vec::new();
    for record in entries.values() {
        out.extend_from_slice(record);
        out.push(0);
    }
    git_input(repo, &["mktree", "-z"], &out, None)
}

fn build_source_commit(
    source: &FsPath,
    projected_repo: &FsPath,
    root: &FsPath,
    bundle: &[u8],
    bundle_ref: &str,
    view: &views::View,
    source_ref: &str,
    actor: &str,
    message: &str,
    max_repo_bytes: u64,
) -> Result<String, Error> {
    fs::create_dir_all(root).map_err(Error::internal)?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).map_err(Error::internal)?;
    let _cleanup = Stage(root.to_path_buf());
    let file = root.join("proposal.bundle");
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&file)
        .map_err(Error::internal)?;
    output.write_all(bundle).map_err(Error::internal)?;
    output.sync_all().map_err(Error::internal)?;
    drop(output);
    let checkout = root.join("projected");
    let source_view_bytes =
        crate::storage::disk_bytes(&projected_repo.join(".git"), 256 * 1024 * 1024).map_err(Error::internal)?;
    if source_view_bytes > 256 * 1024 * 1024 {
        return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "View Git store exceeds import budget"));
    }
    git(
        root,
        &[
            "clone",
            "--no-local",
            "--no-hardlinks",
            projected_repo.to_str().ok_or_else(Error::bad_request)?,
            checkout.to_str().ok_or_else(Error::bad_request)?,
        ],
    )?;
    git(&checkout, &["bundle", "verify", file.to_str().ok_or_else(Error::bad_request)?])?;
    git(&checkout, &["fetch", "--no-tags", file.to_str().ok_or_else(Error::bad_request)?, bundle_ref])?;
    let candidate = git_oid(&checkout, &["rev-parse", "FETCH_HEAD^{commit}"])?;
    git(&checkout, &["merge-base", "--is-ancestor", &view.projected_oid, &candidate])?;
    let candidate_bytes = verify_candidate_budget(&checkout, &candidate, &view.projected_oid)?;
    let staged_bytes =
        crate::storage::disk_bytes(&checkout.join(".git"), 512 * 1024 * 1024).map_err(Error::internal)?;
    if staged_bytes > 512 * 1024 * 1024 {
        return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "proposal staging exceeds 512 MiB"));
    }
    git(&checkout, &["fsck", "--strict", "--no-reflogs", &candidate])?;
    let projected_tree = git_oid(&checkout, &["rev-parse", &format!("{candidate}^{{tree}}")])?;
    let old_projected_tree = git_oid(&checkout, &["rev-parse", &format!("{}^{{tree}}", view.projected_oid)])?;
    if projected_tree == old_projected_tree {
        return Err(Error(StatusCode::CONFLICT, "projected tree is unchanged"));
    }
    let current = git_oid(source, &["rev-parse", "--verify", source_ref])?;
    if current != view.source_oid {
        return Err(Error(StatusCode::CONFLICT, "source ref advanced"));
    }
    let source_bytes = crate::storage::disk_bytes(source, max_repo_bytes).map_err(Error::internal)?;
    if source_bytes.saturating_add(candidate_bytes) > max_repo_bytes {
        return Err(Error(StatusCode::INSUFFICIENT_STORAGE, "repository quota reached"));
    }
    git(&checkout, &["update-ref", "refs/heads/reverse-import", &candidate])?;
    git(
        source,
        &[
            "fetch",
            "--no-tags",
            "--no-write-fetch-head",
            checkout.to_str().ok_or_else(Error::bad_request)?,
            "refs/heads/reverse-import",
        ],
    )?;
    if crate::storage::disk_bytes(source, max_repo_bytes).map_err(Error::internal)? > max_repo_bytes {
        return Err(Error(StatusCode::INSUFFICIENT_STORAGE, "repository quota reached"));
    }
    let old_tree = git_oid(source, &["rev-parse", &format!("{}^{{tree}}", view.source_oid)])?;
    let new_tree = if view.subdir.is_empty() {
        projected_tree
    } else {
        let parts: Vec<&str> = view.subdir.split('/').collect();
        replace_tree(source, &old_tree, &parts, &projected_tree)?
    };
    let body = format!("Rootyard View {} proposal\n\n{}\n", view.id, message);
    git_input(source, &["commit-tree", &new_tree, "-p", &view.source_oid], body.as_bytes(), Some(actor))
}

pub async fn create(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(input): Json<ReverseInput>,
) -> Result<(StatusCode, Json<changesets::ChangeSet>), Error> {
    let view = views::load(&state, &headers, id).await?;
    if !crate::browse::models::valid_public_ref(&input.bundle_ref)
        || !input.bundle_ref.starts_with("refs/heads/")
        || !crate::browse::models::valid_public_ref(&input.source_ref)
        || !input.source_ref.starts_with("refs/heads/")
        || input.message.is_empty()
        || input.message.len() > 2048
        || input.bundle_base64.len() > BODY_LIMIT
    {
        return Err(Error::bad_request());
    }
    let bundle = STANDARD.decode(&input.bundle_base64).map_err(|_| Error::bad_request())?;
    if bundle.is_empty() || bundle.len() > 16 * 1024 * 1024 {
        return Err(Error::bad_request());
    }
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let mut client = state.pool.get().await.map_err(Error::internal)?;
    let tx = client.transaction().await.map_err(Error::internal)?;
    let ns = super::handlers::load(&state, &headers, view.namespace_id).await?;
    let mount = ns.mounts.iter().find(|m| m.path == view.mount_path).ok_or_else(Error::not_found)?;
    if mount.base_oid != view.source_oid {
        return Err(Error::not_found());
    }
    let access = auth::authorize_repo_with_role(&tx, &actor, &mount.owner, &mount.repository, Role::Write).await?;
    if access.repo_id != view.repository_id {
        return Err(Error::not_found());
    }
    let generation: i64 = tx
        .query_one("SELECT storage_generation FROM repositories WHERE id=$1 AND state='ready'", &[&access.repo_id])
        .await
        .map_err(Error::internal)?
        .get(0);
    tx.commit().await.map_err(Error::internal)?;
    drop(client);
    let source_lease =
        read_leases::shared(&state.pool, access.repo_id, tokio::time::Instant::now() + state.config.git_timeout)
            .await?;
    let _local = tokio::time::timeout(state.config.git_timeout, state.storage.read_snapshot_lock(access.repo_id))
        .await
        .map_err(|_| Error::timeout())?;
    source_lease.ensure_active()?;
    auth::verify_active(&state.pool, &actor, access.repo_id, true).await?;
    let _slot = state
        .git_slots
        .clone()
        .try_acquire_owned()
        .map_err(|_| Error(StatusCode::SERVICE_UNAVAILABLE, "Git capacity exhausted"))?;
    let _write = state.storage.write_lock(access.repo_id).await;
    let source = state.storage.verify_path(access.repo_id).map_err(Error::internal)?;
    let projected = state.storage.root.join("workspace-service/views").join(id.to_string());
    let stage = state.storage.root.join("workspace-service/reverse").join(Uuid::new_v4().to_string());
    let actor_name = actor.username.clone();
    let view_copy = view;
    let source_ref = input.source_ref.clone();
    let bundle_ref = input.bundle_ref.clone();
    let message = input.message.clone();
    let quota = state.config.max_repo_bytes;
    let volume_lock_fd = state.storage.lock_file.as_raw_fd();
    // The local gate survives HTTP cancellation. A separate watcher also
    // fences a lost cross-process PG lease while synchronous Git is active:
    // reverse_git kills and reaps its whole process group before this returns.
    let canceled = Arc::new(AtomicBool::new(false));
    let finished = Arc::new(AtomicBool::new(false));
    let new_oid = std::thread::scope(|scope| {
        let watcher_cancel = canceled.clone();
        let watcher_finished = finished.clone();
        let lease = &source_lease;
        scope.spawn(move || {
            while !watcher_finished.load(Ordering::Acquire) {
                if lease.ensure_active().is_err() {
                    watcher_cancel.store(true, Ordering::Release);
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        });
        let result = tokio::task::block_in_place(move || {
            reverse_git::with_read_cancel(canceled, volume_lock_fd, || {
                build_source_commit(
                    &source,
                    &projected,
                    &stage,
                    &bundle,
                    &bundle_ref,
                    &view_copy,
                    &source_ref,
                    &actor_name,
                    &message,
                    quota,
                )
            })
        });
        finished.store(true, Ordering::Release);
        result
    })?;
    source_lease.ensure_active()?;
    drop(_local);
    drop(_write);
    drop(_slot);
    let mut pin_headers = headers.clone();
    let proposal_id = Uuid::new_v4();
    pin_headers
        .insert("idempotency-key", HeaderValue::from_str(&format!("pin-{}", Uuid::new_v4())).map_err(Error::internal)?);
    let pinned = transactions::create_proposal_pin(
        state.clone(),
        mount.owner.clone(),
        mount.repository.clone(),
        pin_headers,
        proposal_id,
        new_oid.clone(),
        generation,
    )
    .await?;
    if !pinned.status().is_success() {
        return Err(Error(StatusCode::CONFLICT, "proposal pin was rejected"));
    }
    source_lease.ensure_active()?;
    changesets::create(
        State(state),
        headers,
        Path(ns.id),
        Json(changesets::Propose {
            steps: vec![changesets::StepInput {
                mount_path: mount.path.clone(),
                ref_name: input.source_ref,
                old_oid: mount.base_oid.clone(),
                new_oid,
                storage_generation: generation,
            }],
        }),
    )
    .await
}
