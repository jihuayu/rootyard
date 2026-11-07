//! Durable CI pin/checkout sidecar handoff for online repository migration.
//!
//! The source's `ci-pins/<repo>` directory carries the exact pin intents and
//! pinned receipts that authorize CI checkout issuance. Those files are not
//! part of the Git repository, so a bare ref transfer would leave a migrated
//! primary unable to verify a previously issued pin. This module captures the
//! directory together with the measured final ref manifest, transfers it inside
//! the authenticated snapshot/delta frame, validates it against the target
//! tenant, repository, job, object id, object format, generation, operation and
//! journal sequence, and only publishes it after the cutover has committed.
//!
//! Released pins and cancelled jobs are tombstones: an intent whose retained CI
//! root is no longer in the measured manifest is dropped, never recreated. A
//! receipt without its retained root, an unmanaged CI root, a symlink, a
//! non-canonical path or a mismatched descriptor fails closed. Publication is
//! serialized with ordinary pin issuance by the repository exclusive guard and
//! merges every legitimately accepted new-generation live intent instead of
//! replacing the live directory with the old source image.
use crate::{
    AppState, Error, journal,
    sharding::{
        faults, locks,
        models::conflict,
        replication::{self},
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    path::{Path as FsPath, PathBuf},
};
use uuid::Uuid;
#[path = "sidecar_capture.rs"]
mod sidecar_capture;
#[path = "sidecar_publish.rs"]
mod sidecar_publish;

use sidecar_capture::bundle_intents;
pub(crate) use sidecar_capture::{capture, precheck};
use sidecar_publish::{
    desired_files, progress_path, publish_directory, receipt_path, scan_live_new_generation, staged_path,
};
pub(crate) use sidecar_publish::{stage_incoming, write_progress};

pub(crate) const SIDECAR_VERSION: u32 = 1;
const CI_PREFIX: &str = "refs/rootyard-ci/jobs/";
const RETAINED_PREFIX: &str = "refs/rootyard-";
const MAX_SIDECAR_FILES: usize = crate::ci_pins::MAX_PINS * 2 + 16;
const MAX_SIDECAR_BYTES: usize = 2 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SidecarFile {
    pub(crate) name: String,
    pub(crate) sha256: String,
    pub(crate) content: String,
}

/// A complete, deterministic image of the repository CI pin sidecars at the
/// measured final manifest. `files` is sorted by canonical name.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SidecarBundle {
    pub(crate) version: u32,
    pub(crate) repository_id: Uuid,
    pub(crate) operation_id: Uuid,
    pub(crate) source_generation: i64,
    pub(crate) target_generation: i64,
    pub(crate) refs_sha256: String,
    pub(crate) journal_sequence: i64,
    pub(crate) files: Vec<SidecarFile>,
    /// Every `refs/rootyard-*` root outside the CI job namespace that the
    /// measured manifest retained (backup, snapshot and hidden retention roots).
    pub(crate) retained_refs: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PublishedFile {
    name: String,
    sha256: String,
}

/// Durable proof that a committed operation's sidecar image was published.
/// Retries after a lost HTTP response and startup recovery consult this receipt
/// instead of treating an intentionally removed staging directory as failure.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PublicationReceipt {
    version: u32,
    repository_id: Uuid,
    operation_id: Uuid,
    target_generation: i64,
    refs_sha256: String,
    journal_sequence: i64,
    route_epoch: i64,
    fencing_token: i64,
    files: Vec<PublishedFile>,
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_directory(path: &FsPath) -> Result<bool, Error> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() && !meta.file_type().is_symlink() => Ok(true),
        Ok(_) => Err(conflict("unsafe CI sidecar directory")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(Error::internal(error)),
    }
}

fn sync_directory(path: &FsPath) -> Result<(), Error> {
    File::open(path).and_then(|file| file.sync_all()).map_err(Error::internal)
}

fn sidecar_directory(root: &FsPath, repo_id: Uuid) -> PathBuf {
    root.join("ci-pins").join(repo_id.to_string())
}

fn canonical_job(name: &str, suffix: &str) -> Result<Uuid, Error> {
    let Some(raw) = name.strip_suffix(suffix) else {
        return Err(conflict("non-canonical CI sidecar filename"));
    };
    if raw.is_empty() || raw.contains('/') || raw.contains('\0') {
        return Err(conflict("unsafe CI sidecar filename"));
    }
    let job: Uuid = raw.parse().map_err(|_| conflict("non-canonical CI sidecar identity"))?;
    if name != format!("{job}{suffix}") {
        return Err(conflict("non-canonical CI sidecar identity"));
    }
    Ok(job)
}

async fn operation_context(
    state: &AppState,
    repo_id: Uuid,
    operation_id: Uuid,
    generation: i64,
    expected_route: Option<(i64, i64)>,
) -> Result<(Uuid, i64, String, i64, i64, i64, String), Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let row = client
        .query_opt(
            "SELECT o.state,o.source_generation,o.refs_sha256,o.journal_sequence,o.target_node_id, \
                    p.owner_id,p.object_format,p.storage_generation, \
                    r.primary_node_id,r.route_epoch,r.fencing_token,r.draining,r.read_only_degraded \
             FROM shard_replication_operations o \
             JOIN repositories p ON p.id=o.repository_id \
             LEFT JOIN repository_shard_routes r ON r.repository_id=o.repository_id \
             WHERE o.id=$1 AND o.repository_id=$2",
            &[&operation_id, &repo_id],
        )
        .await
        .map_err(Error::internal)?
        .ok_or_else(Error::not_found)?;
    let op_state: String = row.get(0);
    let source_generation: i64 = row.get(1);
    let refs_sha256: Option<String> = row.get(2);
    let journal_sequence: Option<i64> = row.get(3);
    let target: String = row.get(4);
    let owner_id: Uuid = row.get(5);
    let object_format: String = row.get(6);
    let repo_generation: i64 = row.get(7);
    let primary: Option<String> = row.get(8);
    let route_epoch: Option<i64> = row.get(9);
    let fencing_token: Option<i64> = row.get(10);
    let draining: Option<bool> = row.get(11);
    let degraded: Option<bool> = row.get(12);
    let node = crate::sharding::transport::node_id()?.unwrap_or_default();
    let (Some(primary), Some(route_epoch), Some(fencing_token)) = (primary, route_epoch, fencing_token) else {
        return Err(conflict("committed cutover has no shard route"));
    };
    if op_state != "completed"
        || target != node
        || primary != node
        || draining != Some(false)
        || degraded != Some(false)
        || source_generation + 1 != generation
        || repo_generation != generation
    {
        return Err(conflict("CI sidecar finalization differs from the committed route"));
    }
    if let Some((expected_epoch, expected_token)) = expected_route
        && (route_epoch != expected_epoch || fencing_token != expected_token)
    {
        return Err(conflict("CI sidecar finalization envelope raced the shard route"));
    }
    let refs_sha256 = refs_sha256.ok_or_else(|| conflict("committed operation has no ref digest"))?;
    Ok((
        owner_id,
        source_generation,
        object_format,
        route_epoch,
        fencing_token,
        journal_sequence.unwrap_or(-1),
        refs_sha256,
    ))
}

async fn verify_published_receipt(
    state: &AppState,
    repo_id: Uuid,
    operation_id: Uuid,
    generation: i64,
    expected_route: Option<(i64, i64)>,
    require_staged: bool,
) -> Result<bool, Error> {
    let path = receipt_path(state, operation_id)?;
    if !journal::exists(&path).map_err(Error::internal)? {
        return if require_staged { Err(conflict("target CI sidecar staging is missing")) } else { Ok(false) };
    }
    let receipt: PublicationReceipt = serde_json::from_slice(&journal::read(&path).map_err(Error::internal)?)
        .map_err(|_| conflict("corrupt CI sidecar publication receipt"))?;
    let (owner_id, source_generation, object_format, route_epoch, fencing_token, sequence, refs_sha256) =
        operation_context(state, repo_id, operation_id, generation, expected_route).await?;
    if receipt.version != SIDECAR_VERSION
        || receipt.repository_id != repo_id
        || receipt.operation_id != operation_id
        || receipt.target_generation != generation
        || receipt.journal_sequence != sequence
        || receipt.refs_sha256 != refs_sha256
        || receipt.route_epoch != route_epoch
        || receipt.fencing_token != fencing_token
    {
        return Err(conflict("CI sidecar publication receipt differs from the committed operation"));
    }
    let guard = locks::exclusive(state, repo_id).await?;
    guard.ensure_active()?;
    let repo_path = state.storage.verify_path(repo_id).map_err(Error::internal)?;
    let manifest = replication::read_manifest_plain(state, &repo_path).await?;
    let _ = (source_generation, object_format, owner_id);
    let directory = sidecar_directory(&state.storage.root, repo_id);
    if !safe_directory(&directory)? {
        // Every receipt file may have been legitimately released already.
        let all_released = receipt.files.iter().all(|file| {
            let job = file
                .name
                .strip_suffix(".pinned.json")
                .or_else(|| file.name.strip_suffix(".json"))
                .and_then(|raw| raw.parse::<Uuid>().ok());
            job.is_some_and(|job| !manifest.refs.contains_key(&format!("{CI_PREFIX}{job}")))
        });
        if all_released {
            return Ok(true);
        }
        return Err(conflict("CI sidecar publication receipt has no live directory"));
    }
    for file in &receipt.files {
        let path = directory.join(&file.name);
        match journal::read(&path) {
            Ok(content) => {
                if digest(&content) != file.sha256 {
                    return Err(conflict("published CI sidecar file changed"));
                }
            }
            Err(_) => {
                // A legitimate post-publication release removes the intent,
                // receipt and retained root together. Never re-publish it; a
                // missing file whose retained root still exists is corruption.
                let job = file
                    .name
                    .strip_suffix(".pinned.json")
                    .or_else(|| file.name.strip_suffix(".json"))
                    .and_then(|raw| raw.parse::<Uuid>().ok())
                    .ok_or_else(|| conflict("publication receipt has a non-canonical file"))?;
                if manifest.refs.contains_key(&format!("{CI_PREFIX}{job}")) {
                    return Err(conflict("published CI sidecar file is missing"));
                }
            }
        }
    }
    guard.ensure_active()?;
    Ok(true)
}

fn write_receipt(
    state: &AppState,
    repo_id: Uuid,
    operation_id: Uuid,
    generation: i64,
    refs_sha256: &str,
    journal_sequence: i64,
    route_epoch: i64,
    fencing_token: i64,
    desired: &BTreeMap<String, Vec<u8>>,
) -> Result<(), Error> {
    let receipt = PublicationReceipt {
        version: SIDECAR_VERSION,
        repository_id: repo_id,
        operation_id,
        target_generation: generation,
        refs_sha256: refs_sha256.to_owned(),
        journal_sequence,
        route_epoch,
        fencing_token,
        files: desired
            .iter()
            .map(|(name, content)| PublishedFile { name: name.clone(), sha256: digest(content) })
            .collect(),
    };
    journal::atomic(&receipt_path(state, operation_id)?, &serde_json::to_vec(&receipt).map_err(Error::internal)?, true)
        .map_err(Error::internal)
}

/// True while a committed cutover has not yet published its non-empty source
/// sidecar image. The new primary must return a bounded 503 to fresh pin
/// issuance instead of reporting the staged old roots as unmanaged corruption.
/// A repository whose staged image is empty has no old roots to hand off, so a
/// fresh pin may be accepted and merged by the following finalize.
pub(crate) async fn handoff_pending(state: &AppState, repo_id: Uuid) -> Result<bool, Error> {
    let Some(node_id) = crate::sharding::transport::node_id()? else {
        return Ok(false);
    };
    let client = state.pool.get().await.map_err(Error::internal)?;
    let row = client
        .query_opt(
            "SELECT o.id FROM shard_replication_operations o              JOIN repositories p ON p.id=o.repository_id              JOIN repository_shard_routes r ON r.repository_id=o.repository_id              WHERE o.repository_id=$1 AND o.target_node_id=$2 AND o.state='completed'                AND r.primary_node_id=$2 AND p.storage_generation=o.source_generation+1              ORDER BY o.updated_at DESC,o.id DESC LIMIT 1",
            &[&repo_id, &node_id],
        )
        .await
        .map_err(Error::internal)?;
    let Some(row) = row else { return Ok(false) };
    let operation_id: Uuid = row.get(0);
    if journal::exists(&receipt_path(state, operation_id)?).map_err(Error::internal)? {
        return Ok(false);
    }
    let staged = staged_path(state, operation_id)?;
    if !safe_directory(&staged)? || !journal::exists(&staged.join("bundle.json")).map_err(Error::internal)? {
        // Completed cutover with no publication proof: block rather than let
        // a new pin trip over unmanaged retained roots.
        return Ok(true);
    }
    let bundle: SidecarBundle =
        serde_json::from_slice(&journal::read(&staged.join("bundle.json")).map_err(Error::internal)?)
            .map_err(|_| conflict("corrupt staged CI sidecar bundle"))?;
    Ok(!bundle.files.is_empty())
}

/// Publish a committed operation's staged bundle under the repository exclusive
/// guard, merging any legitimate new-generation live pins accepted after
/// cutover. Returns whether the operation was already published or staged.
pub(crate) async fn finalize(
    state: &AppState,
    repo_id: Uuid,
    operation_id: Uuid,
    generation: i64,
    expected_route: Option<(i64, i64)>,
    require_staged: bool,
) -> Result<bool, Error> {
    let staged = staged_path(state, operation_id)?;
    if !safe_directory(&staged)? || !journal::exists(&staged.join("bundle.json")).map_err(Error::internal)? {
        return verify_published_receipt(state, repo_id, operation_id, generation, expected_route, require_staged)
            .await;
    }
    let bundle: SidecarBundle =
        serde_json::from_slice(&journal::read(&staged.join("bundle.json")).map_err(Error::internal)?)
            .map_err(|_| conflict("corrupt staged CI sidecar bundle"))?;
    let guard = locks::exclusive(state, repo_id).await?;
    guard.ensure_active()?;
    let (owner_id, source_generation, object_format, route_epoch, fencing_token, sequence, refs_sha256) =
        operation_context(state, repo_id, operation_id, generation, expected_route).await?;
    if bundle.source_generation != source_generation
        || bundle.target_generation != generation
        || bundle.journal_sequence != sequence
        || bundle.refs_sha256 != refs_sha256
    {
        return Err(conflict("staged CI sidecar differs from the committed operation sequence"));
    }
    let repo_path = state.storage.verify_path(repo_id).map_err(Error::internal)?;
    let manifest = replication::read_manifest_plain(state, &repo_path).await?;
    bundle_intents(&bundle, repo_id, operation_id, owner_id, &object_format, source_generation)?;
    let live = scan_live_new_generation(
        &sidecar_directory(&state.storage.root, repo_id),
        repo_id,
        owner_id,
        &object_format,
        generation,
        source_generation,
        &manifest,
    )?;
    let desired = desired_files(&bundle, repo_id, owner_id, &object_format, &live, &manifest)?;
    faults::hit(
        &state.storage.root,
        "target-sidecar-before-publish",
        serde_json::json!({"repository_id": repo_id, "operation_id": operation_id, "files": desired.len()}),
    );
    guard.ensure_active()?;
    publish_directory(&state.storage.root, repo_id, &desired)?;
    guard.ensure_active()?;
    // Revalidate the exact committed operation and route after publication.
    operation_context(state, repo_id, operation_id, generation, expected_route).await?;
    write_receipt(
        state,
        repo_id,
        operation_id,
        generation,
        &bundle.refs_sha256,
        sequence,
        route_epoch,
        fencing_token,
        &desired,
    )?;
    let _ = fs::remove_dir_all(&staged);
    let _ = fs::remove_file(progress_path(state, operation_id)?);
    Ok(true)
}

struct OperationState {
    id: Uuid,
    repository_id: Uuid,
    state: String,
    source_generation: i64,
    target_node_id: String,
}

async fn reconcile_operation(state: &AppState, node_id: &str, operation: &OperationState) -> Result<(), Error> {
    let client = state.pool.get().await.map_err(Error::internal)?;
    let row = client
        .query_opt(
            "SELECT p.storage_generation,r.primary_node_id \
             FROM repositories p LEFT JOIN repository_shard_routes r ON r.repository_id=p.id \
             WHERE p.id=$1",
            &[&operation.repository_id],
        )
        .await
        .map_err(Error::internal)?;
    let Some(row) = row else { return Ok(()) };
    let generation: i64 = row.get(0);
    let primary: Option<String> = row.get(1);
    if operation.state == "completed"
        && operation.target_node_id == node_id
        && primary.as_deref() == Some(node_id)
        && generation == operation.source_generation + 1
        && let Err(error) = finalize(state, operation.repository_id, operation.id, generation, None, false).await
    {
        eprintln!("rootyard: CI sidecar finalization for {} deferred: {}", operation.id, error.1);
    }
    Ok(())
}

/// Startup recovery: republish every committed cutover whose finalization was
/// interrupted, retain staged bundles for resumable/verified operations, and
/// remove only staging proven to belong to an aborted or foreign operation.
pub async fn reconcile_startup(state: &AppState) -> Result<(), Error> {
    let Ok(Some(node_id)) = crate::sharding::transport::node_id() else {
        return Ok(());
    };
    let client = state.pool.get().await.map_err(Error::internal)?;
    let rows = client
        .query(
            "SELECT id,repository_id,target_node_id,state,source_generation \
             FROM shard_replication_operations \
             WHERE target_node_id=$1 AND state IN ('copying','verified','completed') \
             ORDER BY updated_at,id",
            &[&node_id],
        )
        .await
        .map_err(Error::internal)?;
    let known: BTreeMap<Uuid, OperationState> = rows
        .into_iter()
        .map(|row| {
            let operation = OperationState {
                id: row.get(0),
                repository_id: row.get(1),
                target_node_id: row.get(2),
                state: row.get(3),
                source_generation: row.get(4),
            };
            (row.get::<_, Uuid>(0), operation)
        })
        .collect();
    for operation in known.values() {
        reconcile_operation(state, &node_id, operation).await?;
    }
    let staging = replication::staging_root(state)?;
    for entry in fs::read_dir(&staging).map_err(Error::internal)? {
        let entry = entry.map_err(Error::internal)?;
        let name = entry.file_name().into_string().map_err(|_| conflict("non UTF-8 staging filename"))?;
        let Some(raw) = name.strip_suffix(".sidecar") else {
            continue;
        };
        let Ok(operation_id) = raw.parse::<Uuid>() else {
            continue;
        };
        if known.contains_key(&operation_id) {
            continue;
        }
        // Never delete an uninspected directory. Resolve this exact operation
        // before cleanup; only a proven aborted or foreign target stage goes.
        let exact = client
            .query_opt("SELECT target_node_id,state FROM shard_replication_operations WHERE id=$1", &[&operation_id])
            .await
            .map_err(Error::internal)?;
        let remove = match exact {
            // An uninspected orphan is retained; only exact aborted or foreign
            // operation staging is removed.
            None => false,
            Some(row) => {
                let target: String = row.get(0);
                let state_name: String = row.get(1);
                target != node_id || state_name == "aborted"
            }
        };
        if remove {
            let kind = entry.file_type().map_err(Error::internal)?;
            if kind.is_dir() && !kind.is_symlink() {
                let _ = fs::remove_dir_all(entry.path());
            } else {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
    // Reconcile interrupted atomic directory publication. A fallback swap may
    // leave a retired directory; restore it when the live name is absent.
    let base = state.storage.root.join("ci-pins");
    if safe_directory(&base)? {
        for entry in fs::read_dir(&base).map_err(Error::internal)? {
            let entry = entry.map_err(Error::internal)?;
            let name = entry.file_name().into_string().map_err(|_| conflict("non UTF-8 CI sidecar filename"))?;
            let kind = entry.file_type().map_err(Error::internal)?;
            if !kind.is_dir() || kind.is_symlink() {
                continue;
            }
            if name.contains(".stage-") {
                let _ = fs::remove_dir_all(entry.path());
                continue;
            }
            if let Some(raw) =
                name.strip_prefix('.').and_then(|value| value.split_once(".retired-").map(|(repo, _)| repo))
            {
                let Ok(repo_id) = raw.parse::<Uuid>() else { continue };
                let live = base.join(repo_id.to_string());
                if safe_directory(&live)? {
                    let _ = fs::remove_dir_all(entry.path());
                } else {
                    fs::rename(entry.path(), &live).map_err(Error::internal)?;
                    sync_directory(&base)?;
                }
            }
        }
    }
    Ok(())
}
