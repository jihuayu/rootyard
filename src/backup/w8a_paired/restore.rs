//! W8-A paired archive verification and fresh-incarnation restore.
//!
//! Verification is read-only. Restore delegates PostgreSQL + Blob rebuild to the
//! shared format30 path, proves no raft projection rows, applies the W8-A
//! fresh-incarnation fence, and runs stock Git fsck on bytes re-exported from
//! the target Blob backend.
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::Serialize;
use uuid::Uuid;

use crate::blob_store::archive::ArchiveTransfer;
use crate::blob_store::config::BlobProfile;
use crate::blob_store::opendal::BlobStore;
use crate::config::Config;
use crate::storage_lifecycle::models::Policy;

use super::create::W8aRepoFsckReceipt;
use super::manifest_key_ref::{ENV_PAIRED_RAFT_CLUSTER, W8aPairedSidecarManifest, verify_key_reference};
use super::{W8aError, W8aResult, ensure_destructive_gc_disabled};
const SIDECAR: &str = "w8a-paired.json";
const COMPLETE: &str = "W8A_COMPLETE";
const INNER: &str = "format30";
const MAX_SIDECAR_BYTES: u64 = 64 * 1024;
const EXPORT_SECONDS: u64 = 600;
#[derive(Debug, Clone, Serialize)]
pub struct W8aRestoreReceipt {
    pub w8a_backup_id: Uuid,
    pub source: String,
    pub destination: String,
    pub trusted_backup: bool,
    pub destination_trusted: bool,
    pub format: u32,
    pub schema_head: i32,
    pub new_cluster_incarnation: Uuid,
    pub new_storage_authority_id: Uuid,
    pub new_storage_restore_generation: i64,
    pub new_storage_authority_epoch: i64,
    pub remote_delete_fenced: bool,
    pub destructive_gc_enabled: bool,
    pub revoked_tokens: i64,
    pub revoked_sessions: i64,
    pub cancelled_ci_runs: i64,
    pub revoked_ci_checkouts: i64,
    pub expired_workspaces: i64,
    pub cancelled_decisions: i64,
    pub advanced_decision_scopes: i64,
    pub released_pins: i64,
    pub aborted_pull_merges: i64,
    pub reset_deliveries: i64,
    pub repositories_fscked: Vec<W8aRepoFsckReceipt>,
}

struct Checked {
    root: PathBuf,
    sidecar: W8aPairedSidecarManifest,
    manifest: super::super::Manifest,
}
pub fn check(source: &Path) -> W8aResult<W8aPairedSidecarManifest> {
    Ok(inspect(source)?.sidecar)
}
pub async fn restore(
    config: &Config,
    source: &Path,
    compute_dir: &Path,
    trust_backup: bool,
) -> W8aResult<W8aRestoreReceipt> {
    if !trust_backup {
        return Err(W8aError::RestoreFailed("paired restore requires explicit --trust-backup".into()));
    }
    if std::env::var_os(ENV_PAIRED_RAFT_CLUSTER).is_some() {
        return Err(W8aError::RaftCutForbiddenInSingleNodeW8a(format!(
            "{ENV_PAIRED_RAFT_CLUSTER} must be unset for single-node W8-A restore"
        )));
    }
    let policy = Policy::from_env().map_err(|error| W8aError::RestoreFailed(format!("policy: {error:#}")))?;
    ensure_destructive_gc_disabled(&policy)?;
    let checked = inspect(source)?;
    verify_key_reference(
        &checked.sidecar.key_reference,
        checked.sidecar.w8a_backup_id,
        &checked.sidecar.blob_backend_identity,
    )?;
    let compute = prepare_compute(compute_dir, &checked.root, &config.data_dir)?;
    super::super::restore(
        config,
        &checked.root.join(INNER),
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
    )
    .await
    .map_err(|error| classify_restore_error(&format!("{error:#}")))?;
    let mut client = super::super::pg(config).await.map_err(|error| W8aError::RestoreFailed(error.to_string()))?;
    let raft: i64 = client
        .query_one(
            "SELECT (SELECT count(*) FROM public.ref_cas_projection_cursors)
                  + (SELECT count(*) FROM public.ref_cas_projected_operations)",
            &[],
        )
        .await
        .map_err(|error| W8aError::RestoreFailed(format!("raft projection check: {error}")))?
        .get(0);
    if raft != 0 {
        return Err(W8aError::RaftCutForbiddenInSingleNodeW8a(format!(
            "restored database contains {raft} raft projection rows"
        )));
    }
    let fence = super::super::authority::fence_w8a_fresh_incarnation(
        &mut client,
        checked.sidecar.source_cluster_incarnation,
        checked.sidecar.source_storage_authority_epoch,
    )
    .await
    .map_err(|error| W8aError::RestoreFailed(format!("restored_incarnation fence: {error:#}")))?;
    let store = BlobStore::open(
        BlobProfile::from_env().map_err(|error| W8aError::RestoreFailed(format!("opening Blob backend: {error}")))?,
    )
    .map_err(|error| W8aError::RestoreFailed(format!("opening Blob backend: {error}")))?;
    if store.backend_identity().as_hex() != checked.sidecar.blob_backend_identity {
        return Err(W8aError::MissingOrCorruptBlobArtifact(
            "target Blob backend identity differs from the archive".into(),
        ));
    }
    let read = super::super::ArchiveRead::seal(checked.sidecar.inner_volume_id, checked.sidecar.inner_backup_id)
        .map_err(|error| W8aError::RestoreFailed(error.to_string()))?;
    let transfer = ArchiveTransfer::for_export(&read, store);
    let repos =
        fsck_repositories(config, &client, &checked.manifest.blob_artifacts, &transfer, &read, &compute).await?;
    drop(client);
    let _ = std::fs::remove_dir_all(&compute);
    Ok(W8aRestoreReceipt {
        w8a_backup_id: checked.sidecar.w8a_backup_id,
        source: checked.root.display().to_string(),
        destination: config.data_dir.display().to_string(),
        trusted_backup: true,
        destination_trusted: true,
        format: checked.sidecar.format,
        schema_head: checked.sidecar.schema_head,
        new_cluster_incarnation: fence.new_cluster_incarnation,
        new_storage_authority_id: fence.new_storage_authority_id,
        new_storage_restore_generation: fence.new_storage_restore_generation,
        new_storage_authority_epoch: fence.new_storage_authority_epoch,
        remote_delete_fenced: fence.remote_delete_fenced,
        destructive_gc_enabled: false,
        revoked_tokens: fence.revoked_tokens,
        revoked_sessions: fence.revoked_sessions,
        cancelled_ci_runs: fence.cancelled_ci_runs,
        revoked_ci_checkouts: fence.revoked_ci_checkouts,
        expired_workspaces: fence.expired_workspaces,
        cancelled_decisions: fence.cancelled_decisions,
        advanced_decision_scopes: fence.advanced_decision_scopes,
        released_pins: fence.released_pins,
        aborted_pull_merges: fence.aborted_pull_merges,
        reset_deliveries: fence.reset_deliveries,
        repositories_fscked: repos,
    })
}
fn inspect(source: &Path) -> W8aResult<Checked> {
    let root = super::super::absolute(source, true)
        .map_err(|error| W8aError::RestoreFailed(format!("archive path: {error:#}")))?;
    if root.join("paired-manifest.json").exists() {
        return Err(W8aError::RaftCutForbiddenInSingleNodeW8a(
            "paired-manifest.json describes a multi-node raft cut, not a single-node W8-A backup".into(),
        ));
    }
    let mut names = std::fs::read_dir(&root)
        .map_err(|error| W8aError::RestoreFailed(format!("reading archive: {error}")))?
        .map(|entry| entry.map(|value| value.file_name()))
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|error| W8aError::RestoreFailed(format!("reading archive: {error}")))?;
    names.sort();
    let allowed: Vec<OsString> = [COMPLETE, INNER, SIDECAR].into_iter().map(OsString::from).collect();
    if names != allowed {
        return Err(W8aError::MixedPointInTime(
            "paired archive must contain exactly W8A_COMPLETE, format30 and w8a-paired.json".into(),
        ));
    }
    let complete_path = root.join(COMPLETE);
    if regular_file(&complete_path, "W8A_COMPLETE", false)?.len() != 64 {
        return Err(W8aError::MixedPointInTime("W8A_COMPLETE must be exactly 64 bytes".into()));
    }
    let recorded_complete = std::fs::read_to_string(&complete_path)
        .map_err(|error| W8aError::MixedPointInTime(format!("reading W8A_COMPLETE: {error}")))?;
    if !is_lower_hex_64(&recorded_complete) {
        return Err(W8aError::MixedPointInTime("W8A_COMPLETE is not a lowercase SHA-256".into()));
    }
    let sidecar_path = root.join(SIDECAR);
    let sidecar_meta = regular_file(&sidecar_path, SIDECAR, false)?;
    if sidecar_meta.len() == 0 || sidecar_meta.len() > MAX_SIDECAR_BYTES {
        return Err(W8aError::MixedPointInTime("w8a-paired.json size is out of range".into()));
    }
    let sidecar: W8aPairedSidecarManifest = serde_json::from_slice(
        &std::fs::read(&sidecar_path)
            .map_err(|error| W8aError::MixedPointInTime(format!("reading sidecar: {error}")))?,
    )
    .map_err(|error| W8aError::MixedPointInTime(format!("parsing w8a-paired.json: {error}")))?;
    sidecar.verify_manifest_seal()?;
    if recorded_complete != super::super::hash(&sidecar_path).map_err(map_archive_error)? {
        return Err(W8aError::MixedPointInTime("W8A_COMPLETE does not cover w8a-paired.json".into()));
    }
    if sidecar.w8a_backup_id.is_nil()
        || sidecar.source_cluster_incarnation.is_nil()
        || sidecar.source_storage_authority_id.is_nil()
        || sidecar.format != super::super::FORMAT_PAIRED
        || sidecar.schema_head != crate::db::SCHEMA_VERSIONS.last().copied().unwrap_or(0)
        || sidecar.blob_backend_identity.is_empty()
        || sidecar.blob_provider.is_empty()
        || !sidecar.single_node_w8a
        || sidecar.raft_cut_supported
        || sidecar.source_storage_authority_epoch < 1
    {
        return Err(W8aError::MixedPointInTime("sidecar topology or format identity is invalid".into()));
    }
    let inner = root.join(INNER);
    let inner_meta = std::fs::symlink_metadata(&inner)
        .map_err(|error| W8aError::MixedPointInTime(format!("reading format30: {error}")))?;
    if !inner_meta.is_dir() || inner_meta.file_type().is_symlink() {
        return Err(W8aError::MixedPointInTime("format30 is not a real directory".into()));
    }
    let manifest: super::super::Manifest = serde_json::from_slice(
        &std::fs::read(inner.join("manifest.json"))
            .map_err(|error| W8aError::MixedPointInTime(format!("reading inner manifest: {error}")))?,
    )
    .map_err(|error| W8aError::MixedPointInTime(format!("parsing inner manifest: {error}")))?;
    let schema_head = manifest
        .schema_versions
        .last()
        .copied()
        .ok_or_else(|| W8aError::MixedPointInTime("inner manifest has no schema version".into()))?;
    if manifest.format != sidecar.format
        || schema_head != sidecar.schema_head
        || manifest.backup_id != sidecar.inner_backup_id
        || manifest.volume_id != sidecar.inner_volume_id
        || manifest.schema_contract_sha256 != sidecar.schema_contract_sha256
    {
        return Err(W8aError::MixedPointInTime("sidecar and inner manifest identities differ".into()));
    }
    if super::super::schema_contract_digest(sidecar.format).map_err(map_archive_error)?
        != sidecar.schema_contract_sha256
    {
        return Err(W8aError::MixedPointInTime("sidecar schema contract digest is not the frozen catalog".into()));
    }
    let closure = manifest
        .blob_closure
        .as_ref()
        .ok_or_else(|| W8aError::MissingOrCorruptBlobArtifact("inner archive has no Blob closure".into()))?;
    let recomputed = super::super::ledger::closure_of(
        &manifest.blob_artifacts,
        &sidecar.blob_backend_identity,
        &sidecar.blob_provider,
    );
    if recomputed.repositories != sidecar.blob_repository_count
        || recomputed.artifacts != sidecar.blob_artifact_count
        || recomputed.bytes != sidecar.blob_total_bytes
        || recomputed.digest != sidecar.blob_closure_digest
        || closure.backend_identity != sidecar.blob_backend_identity
        || closure.provider != sidecar.blob_provider
        || closure.artifacts != sidecar.blob_artifact_count
        || closure.bytes != sidecar.blob_total_bytes
    {
        return Err(W8aError::MissingOrCorruptBlobArtifact(
            "inner Blob closure summary differs from the sidecar".into(),
        ));
    }
    if super::super::hash(&inner.join("metadata.dump")).map_err(map_archive_error)? != sidecar.metadata_dump_sha256
        || super::super::hash(&inner.join("manifest.json")).map_err(map_archive_error)? != sidecar.inner_manifest_sha256
        || super::super::hash(&inner.join("COMPLETE")).map_err(map_archive_error)? != sidecar.inner_complete_sha256
    {
        return Err(W8aError::MixedPointInTime(
            "metadata.dump, inner manifest or inner COMPLETE was swapped after the sidecar was sealed".into(),
        ));
    }
    for artifact in &manifest.blob_artifacts {
        let path = inner.join(artifact.archive_path());
        let metadata = regular_file(&path, "archived Blob member", false)
            .map_err(|error| W8aError::MissingOrCorruptBlobArtifact(format!("Blob member: {error}")))?;
        if metadata.len() != artifact.length
            || super::super::hash(&path).map_err(|error| {
                W8aError::MissingOrCorruptBlobArtifact(format!("hashing archived Blob member: {error:#}"))
            })? != artifact.sha256
        {
            return Err(W8aError::MissingOrCorruptBlobArtifact(format!(
                "archived Blob member {} differs from its locator",
                artifact.archive_path()
            )));
        }
    }
    super::super::check(&inner).map_err(|error| classify_inner_error(&format!("{error:#}")))?;
    Ok(Checked { root, sidecar, manifest })
}
fn regular_file(path: &Path, label: &str, blob: bool) -> W8aResult<std::fs::Metadata> {
    let invalid = |message: String| {
        if blob { W8aError::MissingOrCorruptBlobArtifact(message) } else { W8aError::MixedPointInTime(message) }
    };
    let meta = std::fs::symlink_metadata(path).map_err(|error| invalid(format!("{label}: {error}")))?;
    #[cfg(unix)]
    let multi_link = {
        use std::os::unix::fs::MetadataExt;
        meta.nlink() != 1
    };
    #[cfg(not(unix))]
    let multi_link = false;
    if !meta.is_file() || meta.file_type().is_symlink() || multi_link {
        return Err(invalid(format!("{label} must be a single-link regular file")));
    }
    Ok(meta)
}
fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
fn classify_restore_error(error: &str) -> W8aError {
    let lowered = error.to_ascii_lowercase();
    if lowered.contains("refstore rows differ") {
        W8aError::MixedPointInTime(error.chars().take(512).collect())
    } else if ["blob", "rebuild", "backend identity"].iter().any(|needle| lowered.contains(needle)) {
        W8aError::MissingOrCorruptBlobArtifact(error.chars().take(512).collect())
    } else {
        W8aError::RestoreFailed(error.chars().take(512).collect())
    }
}
fn classify_inner_error(error: &str) -> W8aError {
    match classify_restore_error(error) {
        W8aError::MissingOrCorruptBlobArtifact(reason) => W8aError::MissingOrCorruptBlobArtifact(reason),
        W8aError::MixedPointInTime(reason) => W8aError::MixedPointInTime(reason),
        _ => W8aError::MixedPointInTime(error.chars().take(512).collect()),
    }
}
fn map_archive_error(error: anyhow::Error) -> W8aError {
    classify_inner_error(&format!("{error:#}"))
}
fn prepare_compute(compute_dir: &Path, source: &Path, target: &Path) -> W8aResult<PathBuf> {
    let exists = std::fs::symlink_metadata(compute_dir).is_ok();
    let compute = super::super::absolute(compute_dir, exists)
        .map_err(|error| W8aError::RestoreFailed(format!("compute directory: {error:#}")))?;
    if !exists {
        super::super::private_dir(&compute)
            .map_err(|error| W8aError::RestoreFailed(format!("creating compute directory: {error:#}")))?;
    }
    let empty = std::fs::read_dir(&compute)
        .map_err(|error| W8aError::RestoreFailed(format!("reading compute directory: {error}")))?
        .next()
        .is_none();
    if !empty {
        return Err(W8aError::RestoreFailed("compute directory must be empty".into()));
    }
    let target = super::super::absolute(target, std::fs::symlink_metadata(target).is_ok())
        .map_err(|error| W8aError::RestoreFailed(format!("restore target: {error:#}")))?;
    for (label, other) in [("archive", source), ("restore target", target.as_path())] {
        super::super::disjoint(&compute, other)
            .map_err(|error| W8aError::RestoreFailed(format!("compute directory overlaps the {label}: {error:#}")))?;
    }
    Ok(compute)
}
async fn fsck_repositories(
    config: &Config,
    client: &tokio_postgres::Client,
    artifacts: &[super::super::ledger::Artifact],
    transfer: &ArchiveTransfer,
    read: &super::super::ArchiveRead,
    compute: &Path,
) -> W8aResult<Vec<W8aRepoFsckReceipt>> {
    let repos = client
        .query(
            "SELECT r.id, r.object_format, g.head_ref FROM public.repositories r
             JOIN public.ref_store_core_gates g ON g.repository_id=r.id
             JOIN public.ref_store_serving_repositories s ON s.repository_id=r.id
             WHERE r.storage_backend='pg_refstore' AND s.state='ready' ORDER BY r.id",
            &[],
        )
        .await
        .map_err(|error| W8aError::RestoreFailed(format!("listing restored repositories: {error}")))?;
    if repos.is_empty() {
        return Err(W8aError::RestoreFailed("restored database has no serving repositories".into()));
    }
    let refs = client
        .query(
            "SELECT repository_id, ref_name, oid FROM public.ref_store_core_refs
             ORDER BY repository_id, ref_name",
            &[],
        )
        .await
        .map_err(|error| W8aError::RestoreFailed(format!("listing restored refs: {error}")))?;
    let mut refs_by_repo: BTreeMap<Uuid, Vec<(String, String)>> = BTreeMap::new();
    for row in refs {
        refs_by_repo.entry(row.get(0)).or_default().push((row.get(1), row.get(2)));
    }
    let deadline = Instant::now() + Duration::from_secs(EXPORT_SECONDS);
    let mut receipts = Vec::new();
    for row in repos {
        let repository_id: Uuid = row.get(0);
        let object_format: String = row.get(1);
        let head_ref: String = row.get(2);
        if !matches!(object_format.as_str(), "sha1" | "sha256") {
            return Err(W8aError::RestoreFailed(format!(
                "repository {repository_id} has an unsupported object format"
            )));
        }
        let members: Vec<_> = artifacts.iter().filter(|artifact| artifact.repository_id == repository_id).collect();
        if members.is_empty() {
            return Err(W8aError::MissingOrCorruptBlobArtifact(format!("repository {repository_id} has no Blob pack")));
        }
        let repo_refs = refs_by_repo
            .get(&repository_id)
            .ok_or_else(|| W8aError::RestoreFailed(format!("repository {repository_id} has no restored refs")))?;
        let head_oid =
            repo_refs.iter().find(|(name, _)| name == &head_ref).map(|(_, oid)| oid.clone()).ok_or_else(|| {
                W8aError::RestoreFailed(format!("repository {repository_id} is missing its head ref"))
            })?;
        let directory = compute.join(format!(".w8a-fsck-{}", repository_id.simple()));
        super::super::private_dir(&directory)
            .map_err(|error| W8aError::RestoreFailed(format!("creating fsck directory: {error:#}")))?;
        let result = super::create::fsck_one(
            config,
            &directory,
            repository_id,
            &object_format,
            &head_ref,
            &head_oid,
            repo_refs,
            &members,
            transfer,
            read,
            deadline,
        )
        .await;
        let _ = std::fs::remove_dir_all(&directory);
        receipts.push(result?);
    }
    Ok(receipts)
}
