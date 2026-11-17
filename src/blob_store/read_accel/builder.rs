//! Maintenance-side builder for rebuildable Blob read-acceleration sidecars.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Instant,
};

use tokio::fs;
use uuid::Uuid;

use super::{
    super::{
        BlobLocator, disposable_view::DisposableViewRoot, envelope::EnvelopeMetadata, key_provider::KeyProvider,
        opendal::BlobStore,
    },
    ReadAccelError,
    manifest::{
        PackDigestEntry, READ_ACCEL_MANIFEST_SCHEMA, ReadAccelArtifact, ReadAccelArtifactKind, ReadAccelConfig,
        ReadAccelManifest, ReadAccelManifestError, ReadAccelObjectFormat, SerializedBlobLocator, collect_pack_paths,
    },
    populate_bare_view_from_authoritative_packs, run_git, sort_pack_sources, upload_object_file,
    validate_ref_name_and_oid,
};

/// Reference to an authoritative `.pack` + `.idx` pair already published in `BlobStore`.
#[derive(Debug, Clone)]
pub struct AuthoritativePackSource {
    pub pack_stem: String,
    pub pack_locator: BlobLocator,
    pub idx_locator: BlobLocator,
    pub pack_envelope: Option<EnvelopeMetadata>,
    pub idx_envelope: Option<EnvelopeMetadata>,
}

impl AuthoritativePackSource {
    pub fn provider_managed(pack_stem: impl Into<String>, pack_locator: BlobLocator, idx_locator: BlobLocator) -> Self {
        Self { pack_stem: pack_stem.into(), pack_locator, idx_locator, pack_envelope: None, idx_envelope: None }
    }

    pub fn with_envelopes(mut self, pack_envelope: EnvelopeMetadata, idx_envelope: EnvelopeMetadata) -> Self {
        self.pack_envelope = Some(pack_envelope);
        self.idx_envelope = Some(idx_envelope);
        self
    }
}

/// Authoritative ref entry from `RefStore` passed into sidecar generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoritativeRef {
    pub name: String,
    pub oid: String,
}

impl AuthoritativeRef {
    pub fn new(name: impl Into<String>, oid: impl Into<String>) -> Self {
        Self { name: name.into(), oid: oid.into() }
    }
}

/// Request to build & upload `MIDX`, `.bitmap`, and `commit-graph` from authoritative packs.
#[derive(Clone)]
pub struct BuildReadAccelRequest {
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub history_id: Uuid,
    pub object_format: ReadAccelObjectFormat,
    pub membership_generation: u64,
    pub blob_generation: i64,
    pub config: ReadAccelConfig,
    pub packs: Vec<AuthoritativePackSource>,
    pub refs: Vec<AuthoritativeRef>,
    pub retention_registry: Option<PackRetentionRegistry>,
    pub key_provider: Option<Arc<dyn KeyProvider>>,
}

/// Measured cost/size accounting returned by maintenance sidecar build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadAccelBuildMetrics {
    pub pack_bytes_fetched: u64,
    pub midx_bytes: u64,
    pub bitmap_bytes: u64,
    pub commit_graph_bytes: u64,
    pub sidecar_uploads: usize,
    pub git_build_duration_ms: u64,
}

/// Published read-acceleration manifest and Blob receipt locator.
#[derive(Debug, Clone)]
pub struct BuiltReadAccelBundle {
    pub manifest: ReadAccelManifest,
    pub manifest_locator: BlobLocator,
    pub manifest_sha256: String,
    pub manifest_length: u64,
    pub manifest_envelope: Option<EnvelopeMetadata>,
    pub metrics: ReadAccelBuildMetrics,
}

/// Build and upload read-acceleration sidecars strictly from authoritative Blob packs.
pub async fn build_and_upload_sidecars(
    store: &BlobStore,
    view_root: &DisposableViewRoot,
    request: &BuildReadAccelRequest,
    deadline: Instant,
) -> Result<BuiltReadAccelBundle, ReadAccelError> {
    if !request.config.enabled {
        return Err(ReadAccelError::DisabledByDefault);
    }
    request.config.validate()?;
    if request.tenant_id.is_nil() || request.repo_id.is_nil() || request.history_id.is_nil() {
        return Err(ReadAccelError::InvalidInput("tenant_id, repo_id and history_id must be non-nil".into()));
    }
    if request.membership_generation == 0 || request.blob_generation <= 0 {
        return Err(ReadAccelError::InvalidInput("membership_generation and blob_generation must be positive".into()));
    }
    for reference in &request.refs {
        validate_ref_name_and_oid(&reference.name, &reference.oid, request.object_format)?;
    }

    let paired = sort_pack_sources(request.tenant_id, request.repo_id, request.object_format, &request.packs)?;
    let sorted_pack_digests: Vec<_> = paired.iter().map(|(_, entry)| entry.clone()).collect();
    let total_pack_bytes = sorted_pack_digests
        .iter()
        .fold(0u64, |acc, item| acc.saturating_add(item.pack_length).saturating_add(item.idx_length));
    let reserved_bytes = total_pack_bytes.saturating_mul(2).max(16 * 1024 * 1024);

    // Pin authoritative packs in-process before fetching so compaction cannot retire them mid-build.
    let build_retention_guard =
        request.retention_registry.as_ref().map(|reg| reg.pin_pack_entries(&sorted_pack_digests)).transpose()?;

    let lease = view_root.create_view("read-accel-bld", request.tenant_id, request.repo_id, reserved_bytes, None)?;
    let (_, pack_bytes_fetched) = populate_bare_view_from_authoritative_packs(
        store,
        &lease,
        request.object_format,
        &paired,
        &request.refs,
        request.key_provider.as_ref(),
        deadline,
    )
    .await?;
    let repo_path = lease.repo_path()?;

    for (source, _) in &paired {
        let idx_arg = format!("objects/pack/{}.idx", source.pack_stem);
        run_git(repo_path, &["verify-pack", "-v", &idx_arg], None, deadline).await?;
    }

    let git_started = Instant::now();
    if request.config.include_midx {
        let midx_args: &[&str] = if request.config.include_bitmap {
            &["multi-pack-index", "write", "--bitmap"]
        } else {
            &["multi-pack-index", "write"]
        };
        run_git(repo_path, midx_args, None, deadline).await?;
        run_git(repo_path, &["multi-pack-index", "verify"], None, deadline).await?;
    }
    if request.config.include_commit_graph {
        if request.refs.is_empty() {
            let mut stdin_list = String::new();
            for entry in &sorted_pack_digests {
                stdin_list.push_str(&entry.pack_stem);
                stdin_list.push_str(".idx\n");
            }
            run_git(
                repo_path,
                &["commit-graph", "write", "--stdin-packs", "--changed-paths"],
                Some(stdin_list.as_bytes()),
                deadline,
            )
            .await?;
        } else {
            run_git(repo_path, &["commit-graph", "write", "--reachable", "--changed-paths"], None, deadline).await?;
        }
        run_git(repo_path, &["commit-graph", "verify"], None, deadline).await?;
    }
    let git_build_duration_ms = git_started.elapsed().as_millis() as u64;

    let staging_dir = lease.dir_path()?;
    let kp = request.key_provider.as_ref();
    let mut artifacts = Vec::new();
    let mut midx_bytes = 0u64;
    let mut bitmap_bytes = 0u64;
    let mut commit_graph_bytes = 0u64;

    if request.config.include_midx {
        let midx_rel = "objects/pack/multi-pack-index".to_owned();
        let midx_path = lease.resolve_repo_relative_path(Path::new(&midx_rel))?;
        let (receipt, sha256, len, envelope) = upload_object_file(
            store,
            request.tenant_id,
            request.repo_id,
            request.blob_generation,
            &request.config.namespace,
            &midx_path,
            staging_dir,
            kp,
            deadline,
        )
        .await?;
        midx_bytes = len;
        artifacts.push(ReadAccelArtifact {
            kind: ReadAccelArtifactKind::Midx,
            relative_path: midx_rel,
            locator: SerializedBlobLocator::from_locator(receipt.locator()),
            plaintext_sha256: sha256,
            plaintext_length: len,
            envelope,
        });

        if request.config.include_bitmap {
            let bitmap_path = discover_midx_bitmap(repo_path, &midx_path, request.object_format).await?;
            let bitmap_file = bitmap_path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or(ReadAccelError::SidecarIntegrityFailed("missing generated midx bitmap filename"))?;
            let bitmap_rel = format!("objects/pack/{bitmap_file}");
            let safe_bitmap_path = lease.resolve_repo_relative_path(Path::new(&bitmap_rel))?;
            let (receipt, sha256, len, envelope) = upload_object_file(
                store,
                request.tenant_id,
                request.repo_id,
                request.blob_generation,
                &request.config.namespace,
                &safe_bitmap_path,
                staging_dir,
                kp,
                deadline,
            )
            .await?;
            bitmap_bytes = len;
            artifacts.push(ReadAccelArtifact {
                kind: ReadAccelArtifactKind::Bitmap,
                relative_path: bitmap_rel,
                locator: SerializedBlobLocator::from_locator(receipt.locator()),
                plaintext_sha256: sha256,
                plaintext_length: len,
                envelope,
            });
        }
    }

    if request.config.include_commit_graph {
        let graph_rel = "objects/info/commit-graph".to_owned();
        let graph_path = lease.resolve_repo_relative_path(Path::new(&graph_rel))?;
        let (receipt, sha256, len, envelope) = upload_object_file(
            store,
            request.tenant_id,
            request.repo_id,
            request.blob_generation,
            &request.config.namespace,
            &graph_path,
            staging_dir,
            kp,
            deadline,
        )
        .await?;
        commit_graph_bytes = len;
        artifacts.push(ReadAccelArtifact {
            kind: ReadAccelArtifactKind::CommitGraph,
            relative_path: graph_rel,
            locator: SerializedBlobLocator::from_locator(receipt.locator()),
            plaintext_sha256: sha256,
            plaintext_length: len,
            envelope,
        });
    }

    let manifest = ReadAccelManifest {
        schema_version: READ_ACCEL_MANIFEST_SCHEMA,
        tenant_id: request.tenant_id,
        repo_id: request.repo_id,
        history_id: request.history_id,
        object_format: request.object_format,
        membership_generation: request.membership_generation,
        sorted_pack_digests,
        artifacts,
    };
    let manifest_bytes = manifest.to_json_bytes()?;
    let manifest_file = staging_dir.join("read-accel-manifest.json");
    fs::write(&manifest_file, &manifest_bytes).await.map_err(|e| ReadAccelError::Io(e.to_string()))?;

    let (manifest_receipt, manifest_sha256, manifest_length, manifest_envelope) = upload_object_file(
        store,
        request.tenant_id,
        request.repo_id,
        request.blob_generation,
        &request.config.namespace,
        &manifest_file,
        staging_dir,
        kp,
        deadline,
    )
    .await?;
    let sidecar_uploads = manifest.artifacts.len().saturating_add(1);
    drop(build_retention_guard);

    Ok(BuiltReadAccelBundle {
        manifest,
        manifest_locator: manifest_receipt.locator().clone(),
        manifest_sha256,
        manifest_length,
        manifest_envelope,
        metrics: ReadAccelBuildMetrics {
            pack_bytes_fetched,
            midx_bytes,
            bitmap_bytes,
            commit_graph_bytes,
            sidecar_uploads,
            git_build_duration_ms,
        },
    })
}

async fn discover_midx_bitmap(
    repo_path: &Path,
    midx_path: &Path,
    object_format: ReadAccelObjectFormat,
) -> Result<PathBuf, ReadAccelError> {
    let midx_bytes = fs::read(midx_path).await.map_err(|e| ReadAccelError::Io(e.to_string()))?;
    let trailer_bytes = object_format.oid_hex_len() / 2;
    if midx_bytes.len() <= trailer_bytes {
        return Err(ReadAccelError::SidecarIntegrityFailed("generated multi-pack-index is truncated"));
    }
    let trailer_hex = hex::encode(&midx_bytes[midx_bytes.len() - trailer_bytes..]);
    let expected_name = format!("multi-pack-index-{trailer_hex}.bitmap");
    let expected_path = repo_path.join("objects/pack").join(&expected_name);
    let meta = fs::symlink_metadata(&expected_path)
        .await
        .map_err(|_| ReadAccelError::SidecarIntegrityFailed("expected midx bitmap file missing after build"))?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(ReadAccelError::SidecarIntegrityFailed("generated midx bitmap is not a regular file"));
    }
    Ok(expected_path)
}

/// Process-local retention pin tracker preventing compaction from retiring packs used by sidecars.
#[derive(Clone, Default)]
pub struct PackRetentionRegistry {
    pinned: Arc<Mutex<HashMap<String, usize>>>,
}

impl PackRetentionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn pin_manifest(&self, manifest: &ReadAccelManifest) -> Result<PackRetentionGuard, ReadAccelManifestError> {
        manifest.validate()?;
        self.pin_pack_entries(&manifest.sorted_pack_digests)
    }

    pub fn pin_pack_entries(&self, entries: &[PackDigestEntry]) -> Result<PackRetentionGuard, ReadAccelManifestError> {
        let paths = collect_pack_paths(entries)?;
        let mut guard = self.pinned.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        for path in &paths {
            *guard.entry(path.clone()).or_insert(0) += 1;
        }
        Ok(PackRetentionGuard { registry: Arc::clone(&self.pinned), paths })
    }

    pub fn is_pack_pinned(&self, locator: &BlobLocator) -> bool {
        let guard = self.pinned.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.get(&locator.path()).copied().unwrap_or(0) > 0
    }

    pub fn pinned_locator_count(&self) -> usize {
        self.pinned.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).len()
    }
}

/// RAII lease keeping all authoritative `.pack` / `.idx` paths in a materialized manifest pinned.
pub struct PackRetentionGuard {
    registry: Arc<Mutex<HashMap<String, usize>>>,
    paths: Vec<String>,
}

impl Drop for PackRetentionGuard {
    fn drop(&mut self) {
        let mut guard = self.registry.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        for path in &self.paths {
            if let Some(count) = guard.get_mut(path) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    guard.remove(path);
                }
            }
        }
    }
}
