//! Authenticated, tenant-scoped remote checkpoint closure and recovery.
use super::{remote_publish_guard, service};
use crate::{
    AppState, Error, auth,
    members::models::Role,
    storage::{
        remote_errors::RemoteStoreError,
        remote_objects::{ObjectKey, RemoteObjectStore},
    },
    workspace_lab::core,
};
use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::{
        ffi::OsStringExt,
        fs::{OpenOptionsExt, PermissionsExt, symlink},
    },
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::time::Instant;
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteEntry {
    pub path_base64: String,
    pub kind: String,
    pub mode: u32,
    pub size: u64,
    pub sha256: String,
    pub target_base64: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RemoteManifest {
    pub schema: u32,
    pub checkpoint_id: Uuid,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub captured_revision: i64,
    pub entries: Vec<RemoteEntry>,
}

pub(super) fn remote_store(state: &AppState) -> Result<RemoteObjectStore, Error> {
    store_at(&state.storage.root)
}

/// Object store built from the process environment and a storage root only.
pub(super) fn store_at(root: &std::path::Path) -> Result<RemoteObjectStore, Error> {
    let store =
        RemoteObjectStore::from_env(root.join("workspace-service/local-object-cache")).map_err(Error::internal)?;
    if matches!(store, RemoteObjectStore::Local(_)) {
        return Err(Error(StatusCode::SERVICE_UNAVAILABLE, "remote object store is not configured"));
    }
    Ok(store)
}

pub(super) fn key(tenant: Uuid, digest: &str) -> Result<ObjectKey, Error> {
    ObjectKey::new(tenant, "workspace", digest).map_err(|_| Error::bad_request())
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(120)
}

fn bounded_manifest(raw: &[u8]) -> Result<RemoteManifest, Error> {
    if raw.len() > 16 * 1024 * 1024 {
        return Err(Error::bad_request());
    }
    serde_json::from_slice(raw).map_err(|_| Error::bad_request())
}

/// A typed object-store `NotFound` means the committed manifest or a member
/// blob named by it is missing. Local I/O, permission, transient and transport
/// failures stay on the existing internal/503 path.
pub(super) fn remote_read_error(error: anyhow::Error) -> Error {
    let missing = error.downcast_ref::<RemoteStoreError>().is_some_and(RemoteStoreError::is_not_found);
    if missing { Error(StatusCode::CONFLICT, "remote checkpoint incomplete") } else { Error::internal(error) }
}

fn manifest_binding_matches(
    manifest: &RemoteManifest,
    checkpoint_id: Uuid,
    repository_id: Uuid,
    tenant_id: Uuid,
    captured_revision: i64,
) -> bool {
    manifest.schema == 1
        && manifest.checkpoint_id == checkpoint_id
        && manifest.repository_id == repository_id
        && manifest.tenant_id == tenant_id
        && manifest.captured_revision == captured_revision
}

fn target_matches(size: u64, sha256: &str, target: &[u8]) -> bool {
    target.len() as u64 == size && hex::encode(Sha256::digest(target)) == sha256
}

fn report(cp: Uuid, manifest: &str, size: i64, revision: i64) -> Value {
    json!({
        "checkpoint_id": cp,
        "state": "COMMITTED",
        "durability": "remote_verified",
        "manifest_sha256": manifest,
        "manifest_size": size,
        "captured_revision": revision
    })
}

pub(super) async fn load_manifest(
    state: &AppState,
    cp: Uuid,
    repo: Uuid,
    tenant: Uuid,
) -> Result<RemoteManifest, Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let row = client
        .query_opt(
            "SELECT state,manifest_digest,manifest_size,captured_revision FROM workspace_checkpoints WHERE id=$1 AND repository_id=$2",
            &[&cp, &repo],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    drop(client);
    if row.get::<_, String>(0) != "committed" {
        return Err(service::conflict());
    }
    let digest: String = row.get::<_, Option<String>>(1).ok_or_else(|| Error::internal("missing remote metadata"))?;
    let size: i64 = row.get::<_, Option<i64>>(2).ok_or_else(|| Error::internal("missing remote metadata"))?;
    let captured_revision: i64 = row.get(3);
    if !(1..=16 * 1024 * 1024).contains(&size) {
        return Err(Error::internal("invalid remote manifest size"));
    }
    let store = remote_store(state)?;
    let stage = state.storage.root.join("workspace-service/staging");
    let stage_dir = stage.clone();
    super::blocking::run(move || {
        fs::create_dir_all(&stage_dir).map_err(Error::internal)?;
        Ok(())
    })
    .await?;
    let path = stage.join(format!("lazy-manifest-{cp}-{}", Uuid::new_v4()));
    let temp_guard = super::cleanup::FileCleanupGuard::new(path.clone());
    if let Err(error) = store.get_to_file(&key(tenant, &digest)?, &path, size as u64, deadline()).await {
        temp_guard.cleanup().await;
        return Err(remote_read_error(error));
    }
    let manifest = match super::blocking::run(move || {
        let raw = fs::read(&path).map_err(Error::internal);
        let _ = fs::remove_file(&path);
        bounded_manifest(&raw?)
    })
    .await
    {
        Ok(m) => {
            temp_guard.keep();
            m
        }
        Err(err) => {
            temp_guard.cleanup().await;
            return Err(err);
        }
    };
    if !manifest_binding_matches(&manifest, cp, repo, tenant, captured_revision) {
        return Err(Error::bad_request());
    }
    Ok(manifest)
}

pub async fn publish(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(cp): Path<Uuid>,
) -> Result<(StatusCode, Json<Value>), Error> {
    let actor = auth::authenticate(&state.pool, &headers).await?;
    let row = {
        let client = state.pool.get().await.map_err(Error::internal)?;
        client
            .query_opt(
                "SELECT c.workspace_id,c.repository_id,c.state,c.lease_epoch,c.captured_revision,c.manifest_digest,c.manifest_size,r.owner_id,r.storage_generation \
                 FROM workspace_checkpoints c JOIN repositories r ON r.id=c.repository_id WHERE c.id=$1",
                &[&cp],
            )
            .await
            .map_err(Error::internal)?
            .ok_or_else(Error::not_found)?
    };
    let ws_id: Uuid = row.get(0);
    let repo_id: Uuid = row.get(1);
    let status: String = row.get(2);
    let epoch: i64 = row.get(3);
    let captured: i64 = row.get(4);
    let digest: Option<String> = row.get(5);
    let size: Option<i64> = row.get(6);
    let tenant: Uuid = row.get(7);
    let storage_generation: i64 = row.get(8);
    let ws =
        service::authorized(&state, &headers, ws_id, Role::Write, crate::token_scopes::RepoAction::WorkspacesWrite)
            .await?;
    if ws.repository_id != repo_id {
        return Err(Error::not_found());
    }
    if status == "committed" {
        return Ok((
            StatusCode::OK,
            Json(report(
                cp,
                &digest.ok_or_else(|| Error::internal("missing remote metadata"))?,
                size.ok_or_else(|| Error::internal("missing remote metadata"))?,
                captured,
            )),
        ));
    }
    if status != "local_complete" || ws.host_id != state.storage.volume_id || ws.lease_epoch != epoch {
        return Err(service::conflict());
    }
    let valid_lease: bool = {
        let client = state.pool.get().await.map_err(Error::internal)?;
        client
            .query_one("SELECT lease_until>clock_timestamp() FROM workspaces WHERE id=$1", &[&ws_id])
            .await
            .map_err(Error::internal)?
            .get(0)
    };
    if !valid_lease {
        return Err(service::conflict());
    }

    // Local-only unborn checkpoints are classified from the frozen checkpoint
    // tree itself, before admission or any object upload. A preexisting
    // committed row returns above and is never reclassified from base_oid.
    let root = service::checkpoint_repo(&state, cp);
    let root_check = root.clone();
    let head_kind = super::blocking::run(move || super::compat::validate_repo(&root_check)).await?;
    if head_kind == super::compat::HeadKind::Unborn {
        return Err(Error(StatusCode::CONFLICT, super::compat::CONFLICT_HEAD));
    }

    let admission =
        crate::storage::admission::acquire(&state.pool, repo_id, storage_generation, "workspace_publish", deadline())
            .await?;
    let store = remote_store(&state)?;
    let root_inv = root.clone();
    let scanned_items = super::blocking::run(move || {
        let entries = core::inventory(&root_inv).map_err(Error::internal)?;
        let mut prepared = Vec::with_capacity(entries.len());
        for entry in entries {
            let rel = core::decode_path(&entry.path_base64).map_err(Error::internal)?;
            let file = root_inv.join(rel);
            let target = if entry.kind == "symlink" {
                let target = fs::read_link(&file).map_err(Error::internal)?.into_os_string().into_vec();
                if !target_matches(entry.size, &entry.sha256, &target) {
                    return Err(Error::internal("workspace symlink target changed during checkpoint capture"));
                }
                Some(STANDARD.encode(target))
            } else {
                None
            };
            prepared.push((entry, file, target));
        }
        Ok(prepared)
    })
    .await?;

    let mut remote_entries = Vec::with_capacity(scanned_items.len());
    let mut uploaded = 0usize;
    for (entry, file, target) in scanned_items {
        if entry.kind != "symlink" {
            remote_publish_guard::stage_key_guarded(
                &state,
                &store,
                remote_publish_guard::StageKeyTarget {
                    checkpoint_id: cp,
                    repository_id: repo_id,
                    tenant_id: tenant,
                    digest: &entry.sha256,
                    size: entry.size,
                    kind: "file",
                },
                &admission,
                deadline(),
            )
            .await?;
            admission.ensure_active()?;
            store
                .put_file(&key(tenant, &entry.sha256)?, &file, entry.size, deadline())
                .await
                .map_err(Error::internal)?;
            uploaded += 1;
            if std::env::var("ROOTYARD_WORKSPACE_REMOTE_KILL_AFTER_OBJECTS").ok().and_then(|v| v.parse::<usize>().ok())
                == Some(uploaded)
            {
                std::process::exit(77);
            }
        }
        remote_entries.push(RemoteEntry {
            path_base64: entry.path_base64,
            kind: entry.kind,
            mode: entry.mode,
            size: entry.size,
            sha256: entry.sha256,
            target_base64: target,
        });
    }
    let manifest = RemoteManifest {
        schema: 1,
        checkpoint_id: cp,
        repository_id: repo_id,
        tenant_id: tenant,
        captured_revision: captured,
        entries: remote_entries,
    };
    let raw = serde_json::to_vec(&manifest).map_err(Error::internal)?;
    bounded_manifest(&raw)?;
    let raw_len = raw.len();
    let digest = hex::encode(Sha256::digest(&raw));
    remote_publish_guard::stage_key_guarded(
        &state,
        &store,
        remote_publish_guard::StageKeyTarget {
            checkpoint_id: cp,
            repository_id: repo_id,
            tenant_id: tenant,
            digest: &digest,
            size: raw_len as u64,
            kind: "manifest",
        },
        &admission,
        deadline(),
    )
    .await?;
    let stage = state.storage.root.join("workspace-service/staging");
    let file = super::blocking::run(move || {
        fs::create_dir_all(&stage).map_err(Error::internal)?;
        let file = stage.join(format!("manifest-{cp}-{}", Uuid::new_v4()));
        let mut output =
            OpenOptions::new().write(true).create_new(true).mode(0o600).open(&file).map_err(Error::internal)?;
        output.write_all(&raw).map_err(Error::internal)?;
        output.sync_all().map_err(Error::internal)?;
        Ok(file)
    })
    .await?;
    let temp_guard = super::cleanup::FileCleanupGuard::new(file.clone());
    admission.ensure_active()?;
    let upload = store.put_file(&key(tenant, &digest)?, &file, raw_len as u64, deadline()).await;
    temp_guard.cleanup().await;
    upload.map_err(Error::internal)?;

    remote_publish_guard::commit_checkpoint_guarded(
        &state,
        cp,
        repo_id,
        tenant,
        &actor,
        &digest,
        raw_len as i64,
        &admission,
    )
    .await?;
    admission.finish().await;
    if std::env::var("ROOTYARD_WORKSPACE_REMOTE_KILL_AFTER_COMMIT").as_deref() == Ok("1") {
        std::process::exit(78);
    }
    Ok((StatusCode::OK, Json(report(cp, &digest, raw_len as i64, captured))))
}

pub async fn ensure_local(state: &AppState, cp: Uuid, repo: Uuid, tenant: Uuid) -> Result<(), Error> {
    let final_path = service::checkpoint_repo(state, cp);
    let check_path = final_path.clone();
    if super::blocking::run(move || Ok(check_path.is_dir())).await? {
        return Ok(());
    }
    let manifest = load_manifest(state, cp, repo, tenant).await?;
    let store = remote_store(state)?;
    let mut paths = BTreeSet::new();
    let mut symlinks = BTreeSet::new();
    let mut total = 0u64;
    let mut downloads = Vec::new();
    for entry in &manifest.entries {
        let path = core::decode_path(&entry.path_base64).map_err(|_| Error::bad_request())?;
        if !paths.insert(path.clone()) || entry.mode > 0o777 || entry.size > core::MAX_BYTES {
            return Err(Error::bad_request());
        }
        total = total.checked_add(entry.size).ok_or_else(Error::bad_request)?;
        if total > core::MAX_BYTES {
            return Err(Error::bad_request());
        }
        let obj_key = key(tenant, &entry.sha256)?;
        if entry.kind == "symlink" {
            symlinks.insert(path);
        } else if entry.kind != "file" || entry.target_base64.is_some() {
            return Err(Error::bad_request());
        } else {
            downloads.push((path, obj_key, entry.size));
        }
    }
    for path in &paths {
        if symlinks.iter().any(|link| path != link && path.starts_with(link)) {
            return Err(Error::bad_request());
        }
    }

    let stage = state.storage.root.join("workspace-service/staging").join(format!("restore-{cp}-{}", Uuid::new_v4()));
    let stage_guard = super::blocking::DirCleanupGuard::new(stage.clone());
    let root = stage.join("repo");
    let root_init = root.clone();
    let stage_init = stage.clone();
    let rels: Vec<PathBuf> = downloads.iter().map(|(rel, _, _)| rel.clone()).collect();
    if let Err(err) = super::blocking::run(move || {
        fs::create_dir_all(&stage_init).map_err(Error::internal)?;
        fs::create_dir(&root_init).map_err(Error::internal)?;
        for rel in rels {
            let parent = root_init.join(&rel).parent().ok_or_else(Error::bad_request)?.to_path_buf();
            fs::create_dir_all(parent).map_err(Error::internal)?;
        }
        Ok(())
    })
    .await
    {
        stage_guard.cleanup().await;
        return Err(err);
    }

    let download_outcome: Result<(), Error> = async {
        for (rel, obj_key, size) in &downloads {
            let to = root.join(rel);
            store.get_to_file(obj_key, &to, *size, deadline()).await.map_err(remote_read_error)?;
        }
        Ok(())
    }
    .await;
    if let Err(err) = download_outcome {
        stage_guard.cleanup().await;
        return Err(err);
    }

    let entries = manifest.entries;
    let finalize = super::blocking::run(move || {
        let outcome = (|| -> Result<(), Error> {
            let mut expected = Vec::with_capacity(entries.len());
            for entry in entries {
                let rel = core::decode_path(&entry.path_base64).map_err(|_| Error::bad_request())?;
                let to = root.join(&rel);
                let parent = to.parent().ok_or_else(Error::bad_request)?;
                fs::create_dir_all(parent).map_err(Error::internal)?;
                if entry.kind == "file" {
                    fs::set_permissions(&to, fs::Permissions::from_mode(entry.mode)).map_err(Error::internal)?;
                } else {
                    let target = STANDARD
                        .decode(entry.target_base64.as_deref().ok_or_else(Error::bad_request)?)
                        .map_err(|_| Error::bad_request())?;
                    if !target_matches(entry.size, &entry.sha256, &target) {
                        return Err(Error::bad_request());
                    }
                    symlink(OsString::from_vec(target), &to).map_err(Error::internal)?;
                }
                expected.push(core::Entry {
                    path_base64: entry.path_base64,
                    kind: entry.kind,
                    mode: entry.mode,
                    size: entry.size,
                    sha256: entry.sha256,
                });
            }
            let actual = core::inventory(&root).map_err(Error::internal)?;
            if actual != expected {
                return Err(Error::internal("remote checkpoint inventory mismatch"));
            }
            if super::compat::validate_repo(&root)? == super::compat::HeadKind::Unborn {
                // Remote/cross-host materialization remains committed-only in
                // this local checkpoint slice. A declared unborn local
                // workspace is intentionally not replayed from remote storage.
                return Err(Error(StatusCode::CONFLICT, super::compat::CONFLICT_HEAD));
            }
            core::sync_tree(&root).map_err(Error::internal)?;
            if let Some(parent) = final_path.parent() {
                fs::create_dir_all(parent).map_err(Error::internal)?;
            }
            if fs::rename(&root, &final_path).is_err() && !final_path.is_dir() {
                return Err(Error::internal("checkpoint restore publication failed"));
            }
            Ok(())
        })();
        let _ = fs::remove_dir_all(&stage);
        outcome
    })
    .await;
    match finalize {
        Ok(()) => {
            stage_guard.keep();
            Ok(())
        }
        Err(err) => {
            stage_guard.cleanup().await;
            Err(err)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(captured_revision: i64) -> RemoteManifest {
        RemoteManifest {
            schema: 1,
            checkpoint_id: Uuid::nil(),
            repository_id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            captured_revision,
            entries: Vec::new(),
        }
    }

    #[test]
    fn typed_remote_not_found_maps_to_the_incomplete_checkpoint_conflict() {
        let missing = anyhow::Error::new(RemoteStoreError::http_typed(
            crate::storage::remote_errors::RemoteOp::Get,
            404,
            crate::storage::remote_errors::RemoteSdkKind::NotFound,
            false,
        ));
        let mapped = remote_read_error(missing);
        assert_eq!(mapped.0, StatusCode::CONFLICT);
        assert_eq!(mapped.1, "remote checkpoint incomplete");
    }

    #[test]
    fn unrelated_or_local_failure_keeps_the_internal_status() {
        let unavailable = anyhow::Error::new(RemoteStoreError::http_typed(
            crate::storage::remote_errors::RemoteOp::Get,
            503,
            crate::storage::remote_errors::RemoteSdkKind::Other,
            true,
        ));
        let mapped = remote_read_error(unavailable);
        assert_eq!(mapped.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(mapped.1, "service temporarily unavailable");

        let local_missing = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::NotFound));
        let mapped = remote_read_error(local_missing);
        assert_eq!(mapped.0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(mapped.1, "service temporarily unavailable");
    }

    #[test]
    fn manifest_binding_requires_the_committed_capture_revision() {
        let manifest = manifest(7);
        assert!(manifest_binding_matches(&manifest, Uuid::nil(), Uuid::nil(), Uuid::nil(), 7));
        assert!(!manifest_binding_matches(&manifest, Uuid::nil(), Uuid::nil(), Uuid::nil(), 8));
    }

    #[test]
    fn target_binding_rejects_a_reread_symlink_that_differs_from_inventory() {
        let target = b"target-\xff";
        let digest = hex::encode(Sha256::digest(target));
        assert!(target_matches(target.len() as u64, &digest, target));
        assert!(!target_matches(target.len() as u64, &digest, b"target-\xfe"));
        assert!(!target_matches(target.len() as u64 + 1, &digest, target));
    }
}
