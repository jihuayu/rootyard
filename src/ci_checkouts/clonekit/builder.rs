//! CloneKit immutable pack/idx builder, durable PG/Blob holds, versioned publication, and GC pins.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process::Stdio,
    sync::RwLock,
};

use deadpool_postgres::Pool;
use tokio::time::Instant as TokioInstant;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::manifest::{
    CLONEKIT_IDX_NAMESPACE, CLONEKIT_MANIFEST_SCHEMA, CLONEKIT_PACK_NAMESPACE, CloneKitArtifactDigest, CloneKitError,
    CloneKitManifest, CloneKitObjectFormat, CloneKitStatus, StoredBlobLocator, compute_file_sha256,
    default_git_timeout, ensure_not_cancelled, ensure_private_dir, git_cmd, run_git_command,
};

#[path = "publication.rs"]
mod publication;
#[path = "read_lease.rs"]
mod read_lease;

use crate::{
    blob_store::{
        BlobReceipt,
        closure::{BlobClosureEncryption, BlobClosureSpec, ClosureArtifactRole, ClosureEntrySpec},
        opendal::BlobStore,
        protected::{ProtectedUploader, UploadSource},
    },
    ref_store::{
        OperationIdentity, RequestDigest,
        artifact_hold::{AcquireArtifactHoldsRequest, AcquireOutcome, ArtifactSpec, HoldScope, PgArtifactHoldStore},
    },
};
pub use publication::{CloneKitPublicationStore, publish_clonekit_versioned};
pub use read_lease::{CloneKitReadLease, LeasedCloneKitManifest};

/// Deterministic fault injection points proving failed builds never overwrite published kits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildFailurePoint {
    AfterPackBeforeIdx,
    AfterUploadBeforePublish,
    CorruptStagedPack,
}

/// Request parameters for building a standard Git `.pack`/`.idx` CloneKit from a source repo.
#[derive(Clone, Debug)]
pub struct BuildCloneKitRequest {
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub owner_id: Uuid,
    pub history_id: Uuid,
    pub storage_generation: i64,
    pub object_format: CloneKitObjectFormat,
    pub kit_generation: u64,
    pub branch_ref: String,
    pub created_unix: i64,
    pub expires_unix: i64,
    pub git_binary: PathBuf,
    pub source_repo_dir: PathBuf,
    pub staging_root: PathBuf,
    pub retention_pin_id: Option<Uuid>,
    pub inject_failure: Option<BuildFailurePoint>,
}

/// Built local staged pack/idx artifacts and sealed manifest ready for Blob/catalog publication.
#[derive(Clone, Debug)]
pub struct BuiltCloneKitArtifacts {
    pub manifest: CloneKitManifest,
    pub staged_pack_path: Option<PathBuf>,
    pub staged_idx_path: Option<PathBuf>,
}

/// In-process retention pin & active hold ledger protecting active kit generations from GC.
#[derive(Debug, Default)]
pub struct RetentionPinLedger {
    held: RwLock<BTreeMap<(Uuid, u64), BTreeSet<Uuid>>>,
}

impl RetentionPinLedger {
    /// Create an empty retention pin ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a pin protecting `(repository_id, kit_generation)` from premature eviction.
    pub fn acquire_pin(&self, repository_id: Uuid, kit_generation: u64, pin_id: Uuid) -> Result<(), CloneKitError> {
        if repository_id.is_nil() || pin_id.is_nil() || kit_generation == 0 {
            return Err(CloneKitError::InvalidInput("retention pin requires valid repository, generation, and pin_id"));
        }
        self.held
            .write()
            .unwrap_or_else(|p| p.into_inner())
            .entry((repository_id, kit_generation))
            .or_default()
            .insert(pin_id);
        Ok(())
    }

    /// Explicitly release one pin once its transfer or backup window settles.
    pub fn release_pin(&self, repository_id: Uuid, kit_generation: u64, pin_id: Uuid) {
        let mut guard = self.held.write().unwrap_or_else(|p| p.into_inner());
        if let Some(pins) = guard.get_mut(&(repository_id, kit_generation)) {
            pins.remove(&pin_id);
            if pins.is_empty() {
                guard.remove(&(repository_id, kit_generation));
            }
        }
    }

    /// Return an active protecting pin ID if any transfer/hold still pins this kit generation.
    pub fn active_pin_for(&self, repository_id: Uuid, kit_generation: u64) -> Option<Uuid> {
        self.held
            .read()
            .unwrap_or_else(|p| p.into_inner())
            .get(&(repository_id, kit_generation))
            .and_then(|s| s.iter().next().copied())
    }

    /// Hold the process-local pin read guard from the check through the collection closure.
    pub(super) fn with_unpinned_generation<R>(
        &self,
        repository_id: Uuid,
        kit_generation: u64,
        collect: impl FnOnce() -> Result<R, CloneKitError>,
    ) -> Result<R, CloneKitError> {
        let guard = self.held.read().unwrap_or_else(|p| p.into_inner());
        if let Some(pin) = guard.get(&(repository_id, kit_generation)).and_then(|s| s.iter().next().copied()) {
            return Err(CloneKitError::PinProtectionActive(pin));
        }
        collect()
    }
}

/// RAII retention pin guard releasing its pin only after transfer teardown finishes.
pub struct RetentionPinGuard<'a> {
    ledger: &'a RetentionPinLedger,
    repository_id: Uuid,
    kit_generation: u64,
    pin_id: Uuid,
}

impl<'a> RetentionPinGuard<'a> {
    /// Acquire a scoped retention pin guard over `(repository_id, kit_generation)`.
    pub fn acquire(
        ledger: &'a RetentionPinLedger,
        repository_id: Uuid,
        kit_generation: u64,
    ) -> Result<Self, CloneKitError> {
        let pin_id = Uuid::new_v4();
        ledger.acquire_pin(repository_id, kit_generation, pin_id)?;
        Ok(Self { ledger, repository_id, kit_generation, pin_id })
    }

    /// Identifier of this active retention pin.
    pub const fn pin_id(&self) -> Uuid {
        self.pin_id
    }
}

impl Drop for RetentionPinGuard<'_> {
    fn drop(&mut self) {
        self.ledger.release_pin(self.repository_id, self.kit_generation, self.pin_id);
    }
}

fn read_regular_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, CloneKitError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|err| CloneKitError::CorruptArtifact(format!("open generation file: {err}")))?;
    let meta = file.metadata().map_err(|err| CloneKitError::CorruptArtifact(format!("stat generation file: {err}")))?;
    if !meta.is_file() || meta.len() > max_bytes {
        return Err(CloneKitError::CorruptArtifact("generation file is not a bounded regular file".into()));
    }
    let mut bytes = Vec::new();
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| CloneKitError::CorruptArtifact(format!("read generation file: {err}")))?;
    if bytes.len() as u64 > max_bytes {
        return Err(CloneKitError::CorruptArtifact("generation file exceeds the size cap".into()));
    }
    Ok(bytes)
}

fn write_private_file(dest: &Path, bytes: &[u8]) -> Result<(), CloneKitError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dest)
        .map_err(|err| CloneKitError::GitFailed(format!("create prepared clonekit file: {err}")))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|err| CloneKitError::GitFailed(format!("write prepared clonekit file: {err}")))
}

fn copy_private_file(src: &Path, dest: &Path) -> Result<(), CloneKitError> {
    let mut input = File::open(src)
        .map_err(|err| CloneKitError::CorruptArtifact(format!("open staged clonekit artifact: {err}")))?;
    if !input
        .metadata()
        .map_err(|err| CloneKitError::CorruptArtifact(format!("stat staged clonekit artifact: {err}")))?
        .is_file()
    {
        return Err(CloneKitError::CorruptArtifact("staged clonekit artifact is not a regular file".into()));
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(dest)
        .map_err(|err| CloneKitError::GitFailed(format!("create prepared clonekit artifact: {err}")))?;
    io::copy(&mut input, &mut output)
        .map_err(|err| CloneKitError::GitFailed(format!("copy prepared clonekit artifact: {err}")))?;
    output.sync_all().map_err(|err| CloneKitError::GitFailed(format!("sync prepared clonekit artifact: {err}")))
}

fn sync_dir(path: &Path) -> Result<(), CloneKitError> {
    File::open(path)
        .and_then(|dir| dir.sync_all())
        .map_err(|err| CloneKitError::GitFailed(format!("sync clonekit directory: {err}")))
}

fn verify_prepared_artifact(path: &Path, expected: &str, expected_len: u64) -> Result<(), CloneKitError> {
    let (sha256, length) = compute_file_sha256(path)?;
    if sha256 != expected || length != expected_len {
        return Err(CloneKitError::CorruptArtifact("prepared pack/idx failed digest verification".into()));
    }
    Ok(())
}

fn verify_idx_in_ephemeral_repo(
    git_binary: &Path,
    work_parent: &Path,
    object_format: CloneKitObjectFormat,
    idx_path: &Path,
    cancel: Option<&CancellationToken>,
) -> Result<(), CloneKitError> {
    let idx_str = idx_path.to_str().ok_or(CloneKitError::InvalidInput("non-utf8 idx path"))?;
    let verify_repo = work_parent.join(format!(".verify-repo-{}", Uuid::new_v4().simple()));
    let res = (|| {
        ensure_private_dir(&verify_repo)?;
        run_git_command(
            git_binary,
            Some(&verify_repo),
            &["init", "--bare", "--quiet", object_format.git_init_flag()],
            cancel,
        )?;
        run_git_command(git_binary, Some(&verify_repo), &["verify-pack", "--", idx_str], cancel)?;
        Ok(())
    })();
    let _ = fs::remove_dir_all(&verify_repo);
    res
}

fn manifest_from_request(
    req: &BuildCloneKitRequest,
    status: CloneKitStatus,
    base_commit_oid: Option<String>,
    pack: Option<CloneKitArtifactDigest>,
    idx: Option<CloneKitArtifactDigest>,
) -> Result<CloneKitManifest, CloneKitError> {
    CloneKitManifest {
        schema: CLONEKIT_MANIFEST_SCHEMA,
        tenant_id: req.tenant_id,
        repository_id: req.repository_id,
        owner_id: req.owner_id,
        history_id: req.history_id,
        storage_generation: req.storage_generation,
        object_format: req.object_format,
        kit_generation: req.kit_generation,
        status,
        base_commit_oid,
        branch_ref: req.branch_ref.clone(),
        pack,
        idx,
        backend_identity_hex: None,
        retention_pin_id: req.retention_pin_id,
        created_unix: req.created_unix,
        expires_unix: req.expires_unix,
        manifest_sha256: String::new(),
    }
    .sealed()
}

/// Build a verified standard Git `.pack`/`.idx` CloneKit (or explicit `EmptyRepository` manifest).
pub fn build_clonekit_from_git(
    req: &BuildCloneKitRequest,
    cancel: Option<&CancellationToken>,
) -> Result<BuiltCloneKitArtifacts, CloneKitError> {
    ensure_not_cancelled(cancel)?;
    let fmt_out =
        run_git_command(&req.git_binary, Some(&req.source_repo_dir), &["rev-parse", "--show-object-format"], cancel)?;
    if CloneKitObjectFormat::parse(std::str::from_utf8(&fmt_out).unwrap_or(""))? != req.object_format {
        return Err(CloneKitError::InvalidInput("source repo object format mismatches request"));
    }

    let head_check = git_cmd(&req.git_binary, Some(&req.source_repo_dir))?
        .args(["rev-parse", "--verify", "-q", &req.branch_ref])
        .output()
        .map_err(|e| CloneKitError::GitFailed(e.to_string()))?;

    if !head_check.status.success() {
        let refs_out = run_git_command(
            &req.git_binary,
            Some(&req.source_repo_dir),
            &["for-each-ref", "--count=1", "refs/"],
            cancel,
        )?;
        if refs_out.is_empty() {
            let empty_manifest = manifest_from_request(req, CloneKitStatus::EmptyRepository, None, None, None)?;
            return Ok(BuiltCloneKitArtifacts {
                manifest: empty_manifest,
                staged_pack_path: None,
                staged_idx_path: None,
            });
        }
        return Err(CloneKitError::MissingKit);
    }

    let base_oid = String::from_utf8_lossy(&head_check.stdout).trim().to_owned();
    if !req.object_format.valid_oid(&base_oid) {
        return Err(CloneKitError::CorruptArtifact("resolved branch base OID invalid".into()));
    }

    let stage_dir = req.staging_root.join(format!("build-{}", Uuid::new_v4().simple()));
    ensure_private_dir(&stage_dir)?;
    let rev_list =
        run_git_command(&req.git_binary, Some(&req.source_repo_dir), &["rev-list", "--objects", &base_oid], cancel)?;
    let mut pack_cmd = git_cmd(&req.git_binary, Some(&req.source_repo_dir))?;
    pack_cmd
        .args(["pack-objects", "--quiet"])
        .arg(stage_dir.join("clonekit"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = pack_cmd.spawn().map_err(|e| CloneKitError::GitFailed(e.to_string()))?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&rev_list).map_err(|e| CloneKitError::GitFailed(e.to_string()))?;
    }
    let pack_out = child.wait_with_output().map_err(|e| CloneKitError::GitFailed(e.to_string()))?;
    ensure_not_cancelled(cancel)?;
    if !pack_out.status.success() {
        return Err(CloneKitError::GitFailed(String::from_utf8_lossy(&pack_out.stderr).trim().to_owned()));
    }
    let pack_hash = String::from_utf8_lossy(&pack_out.stdout).trim().to_owned();
    if pack_hash.is_empty() {
        return Err(CloneKitError::GitFailed("git pack-objects emitted no pack hash".into()));
    }
    if req.inject_failure == Some(BuildFailurePoint::AfterPackBeforeIdx) {
        return Err(CloneKitError::GitFailed("injected failure after pack generation".into()));
    }

    let (pack_path, idx_path) =
        (stage_dir.join(format!("clonekit-{pack_hash}.pack")), stage_dir.join(format!("clonekit-{pack_hash}.idx")));
    let idx_arg = idx_path.to_str().ok_or(CloneKitError::InvalidInput("non-utf8 idx path"))?;
    run_git_command(&req.git_binary, Some(&req.source_repo_dir), &["verify-pack", "--", idx_arg], cancel)?;

    if req.inject_failure == Some(BuildFailurePoint::CorruptStagedPack) {
        let mut corrupted = fs::read(&pack_path).map_err(|e| CloneKitError::CorruptArtifact(e.to_string()))?;
        if let Some(first) = corrupted.first_mut() {
            *first ^= 0xff;
        }
        fs::write(&pack_path, corrupted).map_err(|e| CloneKitError::CorruptArtifact(e.to_string()))?;
    }

    let ((pack_sha256, pack_len), (idx_sha256, idx_len)) =
        (compute_file_sha256(&pack_path)?, compute_file_sha256(&idx_path)?);
    let manifest = manifest_from_request(
        req,
        CloneKitStatus::Active,
        Some(base_oid),
        Some(CloneKitArtifactDigest { sha256: pack_sha256, length: pack_len, hold_id: None, blob_locator: None }),
        Some(CloneKitArtifactDigest { sha256: idx_sha256, length: idx_len, hold_id: None, blob_locator: None }),
    )?;
    Ok(BuiltCloneKitArtifacts { manifest, staged_pack_path: Some(pack_path), staged_idx_path: Some(idx_path) })
}

/// Caller-supplied durable RefStore operation and HoldScope binding for Blob/PG publication.
#[derive(Clone, Debug)]
pub struct BlobHoldPublishContext {
    pub scope: HoldScope,
    pub operation: OperationIdentity,
    pub expected_gate_digest: RequestDigest,
    pub authority_id: Uuid,
    pub authority_generation: i64,
}

fn closure_entry(
    role: ClosureArtifactRole,
    receipt: &BlobReceipt,
    meta: &CloneKitArtifactDigest,
) -> Result<ClosureEntrySpec, CloneKitError> {
    ClosureEntrySpec::provider_managed(role, receipt.locator().clone())
        .with_expected_plaintext(&meta.sha256, meta.length)
        .map_err(|e| CloneKitError::IncompleteClosure(e.to_string()))
}

/// Upload staged `.pack` & `.idx` through `PgArtifactHoldStore` + `ProtectedUploader` and verify Blob closure.
pub async fn publish_clonekit_to_blob_store(
    pool: &Pool,
    store: &BlobStore,
    ctx: &BlobHoldPublishContext,
    built: &mut BuiltCloneKitArtifacts,
    cancel: Option<&CancellationToken>,
) -> Result<Vec<BlobReceipt>, CloneKitError> {
    ensure_not_cancelled(cancel)?;
    let (Some(pack_src), Some(idx_src)) = (&built.staged_pack_path, &built.staged_idx_path) else {
        return Err(CloneKitError::EmptyRepository);
    };
    let (Some(pack_meta), Some(idx_meta)) = (built.manifest.pack.clone(), built.manifest.idx.clone()) else {
        return Err(CloneKitError::InvalidInput("missing pack/idx metadata for blob publish"));
    };

    let pack_spec = ArtifactSpec::new(CLONEKIT_PACK_NAMESPACE, &pack_meta.sha256, pack_meta.length)
        .map_err(|e| CloneKitError::BlobFailed(e.to_string()))?;
    let idx_spec = ArtifactSpec::new(CLONEKIT_IDX_NAMESPACE, &idx_meta.sha256, idx_meta.length)
        .map_err(|e| CloneKitError::BlobFailed(e.to_string()))?;
    let req = AcquireArtifactHoldsRequest::new(
        ctx.scope,
        ctx.operation.clone(),
        Uuid::new_v4(),
        store.backend_identity().clone(),
        ctx.authority_id,
        ctx.authority_generation,
        ctx.expected_gate_digest,
        vec![pack_spec, idx_spec],
    )
    .map_err(|e| CloneKitError::DatabaseFailed(e.to_string()))?;

    let (pg_dl, blob_dl) =
        (TokioInstant::now() + default_git_timeout(), std::time::Instant::now() + default_git_timeout());
    let mut client = pool.get().await.map_err(|e| CloneKitError::DatabaseFailed(e.to_string()))?;
    let AcquireOutcome::Granted { grant, .. } = PgArtifactHoldStore
        .acquire(&mut client, store, &req, pg_dl)
        .await
        .map_err(|e| CloneKitError::DatabaseFailed(e.to_string()))?
    else {
        return Err(CloneKitError::DatabaseFailed("unexpected hold acquire replay".into()));
    };
    drop(client);
    ensure_not_cancelled(cancel)?;

    let pub_res = ProtectedUploader::new(store.clone())
        .consume_and_upload(pool, grant, &[UploadSource::new(pack_src), UploadSource::new(idx_src)], blob_dl)
        .await
        .map_err(|e| CloneKitError::BlobFailed(e.to_string()))?;
    let receipts = pub_res.receipts();
    if receipts.len() != 2 {
        return Err(CloneKitError::IncompleteClosure("expected pack and idx blob receipts".into()));
    }
    let (r_pack, r_idx) = (receipts[0].receipt().clone(), receipts[1].receipt().clone());
    let closure = BlobClosureSpec::new(
        ctx.scope.tenant_id(),
        ctx.authority_id,
        ctx.authority_generation,
        BlobClosureEncryption::ProviderManaged,
        vec![
            closure_entry(ClosureArtifactRole::Pack, &r_pack, &pack_meta)?,
            closure_entry(ClosureArtifactRole::PackIndex, &r_idx, &idx_meta)?,
        ],
    )
    .map_err(|e| CloneKitError::IncompleteClosure(e.to_string()))?;
    closure.require_git_pack_pair().map_err(|e| CloneKitError::IncompleteClosure(e.to_string()))?;
    let _proof = store
        .verify_closure(&closure, None, None, blob_dl)
        .await
        .map_err(|e| CloneKitError::IncompleteClosure(e.to_string()))?;

    if let Some(ref mut pack) = built.manifest.pack {
        pack.hold_id = Some(receipts[0].hold_id());
        pack.blob_locator = Some(StoredBlobLocator::from_blob_locator(r_pack.locator()));
    }
    if let Some(ref mut idx) = built.manifest.idx {
        idx.hold_id = Some(receipts[1].hold_id());
        idx.blob_locator = Some(StoredBlobLocator::from_blob_locator(r_idx.locator()));
    }
    built.manifest.backend_identity_hex = Some(store.backend_identity().as_hex().to_owned());
    built.manifest.retention_pin_id = Some(pub_res.acquire_request_id());
    built.manifest = built.manifest.clone().sealed()?;
    Ok(vec![r_pack, r_idx])
}
