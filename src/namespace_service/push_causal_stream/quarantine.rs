//! Isolated `0700` per-push quarantine workspace, bounded streaming ingest,
//! OpenDAL Blob upload + read-back closure proof, and fail-closed sweep (#183).

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::fs::{self, File, OpenOptions};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use crate::blob_store::capacity_contract::git_ops::{UploadScope, upload_pack_pair};
use crate::blob_store::closure::{
    BlobClosureEncryption, BlobClosureProof, BlobClosureSpec, ClosureArtifactRole, ClosureEntrySpec,
};
use crate::blob_store::opendal::BlobStore;
use crate::blob_store::{BlobError, BlobLocator, BlobReceipt};
use crate::ref_store::core::types::GitObjectFormat;

use super::types::{PushCausalError, STREAM_CHUNK_BYTES, StreamIngestLimits};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

const PACK_HEADER_LEN: usize = 12;

/// Summary recorded whenever a quarantined push workspace is swept after commit or abort.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineSweepRecord {
    pub workspace_dir: PathBuf,
    pub removed_files: usize,
    pub dir_removed: bool,
    pub retained_unpromoted_blobs: Vec<String>,
}

/// Lifecycle state of durable artifact holds guarding quarantine/staged Blobs (`#113`).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldLifecycleState {
    ActiveHeld,
    ConsumedCommitted,
    ReleasedAfterAbort,
}

/// Non-premature hold guard that refuses release during `Pending` / `CommitUnknown` outcomes.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OperationHoldGuard {
    pub operation_id: Uuid,
    pub hold_ids: Vec<Uuid>,
    pub protected_locators: Vec<BlobLocator>,
    pub state: HoldLifecycleState,
    pub unknown_outcome_pinned: bool,
}

impl OperationHoldGuard {
    pub fn acquire(operation_id: Uuid, hold_ids: Vec<Uuid>, protected_locators: Vec<BlobLocator>) -> Self {
        Self {
            operation_id,
            hold_ids,
            protected_locators,
            state: HoldLifecycleState::ActiveHeld,
            unknown_outcome_pinned: false,
        }
    }

    pub fn mark_unknown_outcome(&mut self) {
        self.unknown_outcome_pinned = true;
    }

    pub fn mark_committed(&mut self) -> Result<(), PushCausalError> {
        if self.state == HoldLifecycleState::ReleasedAfterAbort {
            return Err(PushCausalError::StateMachine("cannot commit after hold was released".into()));
        }
        self.state = HoldLifecycleState::ConsumedCommitted;
        self.unknown_outcome_pinned = false;
        Ok(())
    }

    pub fn release_on_proven_abort(&mut self) -> Result<(), PushCausalError> {
        if self.unknown_outcome_pinned {
            return Err(PushCausalError::StateMachine(
                "cannot release artifact holds while commit outcome is unknown".into(),
            ));
        }
        if self.state == HoldLifecycleState::ConsumedCommitted {
            return Err(PushCausalError::StateMachine("cannot abort-release committed artifact holds".into()));
        }
        self.state = HoldLifecycleState::ReleasedAfterAbort;
        Ok(())
    }
}

/// Private `0700` per-push quarantine directory owning incoming/staging pack artifacts.
pub struct QuarantineSlot {
    dir: PathBuf,
    tracked_files: Vec<PathBuf>,
    unpromoted_blobs: Vec<String>,
    swept: bool,
}

impl QuarantineSlot {
    pub fn create(base_root: Option<&Path>) -> Result<Self, PushCausalError> {
        let root = base_root.map(Path::to_path_buf).unwrap_or_else(std::env::temp_dir);
        let dir = root.join(format!(".rootyard-push-quarantine-{}", Uuid::new_v4()));
        create_private_dir(&dir)?;
        Ok(Self { dir, tracked_files: Vec::new(), unpromoted_blobs: Vec::new(), swept: false })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn register_file(&mut self, path: PathBuf) -> PathBuf {
        self.tracked_files.push(path.clone());
        path
    }

    pub fn record_unpromoted_blob(&mut self, locator: &BlobLocator) {
        self.unpromoted_blobs.push(locator.path().to_owned());
    }

    pub fn sweep(mut self) -> QuarantineSweepRecord {
        self.sweep_inner()
    }

    fn sweep_inner(&mut self) -> QuarantineSweepRecord {
        let mut removed_files = 0usize;
        for file in self.tracked_files.drain(..) {
            if std::fs::remove_file(&file).is_ok() {
                removed_files = removed_files.saturating_add(1);
            }
        }
        let dir_removed = std::fs::remove_dir_all(&self.dir).is_ok() || !self.dir.exists();
        self.swept = true;
        QuarantineSweepRecord {
            workspace_dir: self.dir.clone(),
            removed_files,
            dir_removed,
            retained_unpromoted_blobs: std::mem::take(&mut self.unpromoted_blobs),
        }
    }
}

impl Drop for QuarantineSlot {
    fn drop(&mut self) {
        if !self.swept {
            let _ = self.sweep_inner();
        }
    }
}

fn create_private_dir(path: &Path) -> Result<(), PushCausalError> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|e| PushCausalError::Io(e.to_string()))?;
    let meta = std::fs::symlink_metadata(path).map_err(|e| PushCausalError::Io(e.to_string()))?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(PushCausalError::Io("quarantine directory must be a non-symlink directory".into()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid returns effective UID with no memory or pointer invariants.
        let euid = unsafe { libc::geteuid() };
        if meta.uid() != euid {
            return Err(PushCausalError::AuthorizationDenied("quarantine dir uid mismatch"));
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| PushCausalError::Io(e.to_string()))?;
    }
    Ok(())
}

/// Output of bounded streaming pack reception into the private quarantine slot.
#[derive(Clone, Debug)]
pub struct PackIngestResult {
    pub has_pack: bool,
    pub incoming_pack_path: Option<PathBuf>,
    pub incoming_pack_sha256: Option<String>,
    pub incoming_pack_bytes: u64,
    pub incoming_object_count: u32,
    pub stream_wire_bytes: u64,
    pub stream_receive_ms: u64,
}

/// Stream trailing `PACK` bytes from `reader` directly into a `0600` quarantine file in 64 KiB
/// chunks without buffering the whole payload in memory.
pub async fn ingest_pack_to_quarantine<R>(
    mut reader: R,
    slot: &mut QuarantineSlot,
    object_format: GitObjectFormat,
    command_bytes_read: usize,
    limits: &StreamIngestLimits,
    deadline: Instant,
) -> Result<PackIngestResult, PushCausalError>
where
    R: AsyncRead + Unpin,
{
    let started = Instant::now();
    let max_total = limits.max_stream_bytes;
    let pack_path = slot.register_file(slot.dir().join("incoming.pack"));
    let mut file = create_private_file(&pack_path).await?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; STREAM_CHUNK_BYTES];
    let mut header_buf = [0u8; PACK_HEADER_LEN];
    let mut header_filled = 0usize;
    let mut pack_bytes = 0u64;
    let mut header_checked = false;
    let mut declared_objects = 0u32;

    loop {
        let remaining = deadline.checked_duration_since(Instant::now()).ok_or(PushCausalError::DeadlineExceeded)?;
        let n = tokio::time::timeout(remaining, reader.read(&mut buf))
            .await
            .map_err(|_| PushCausalError::DeadlineExceeded)?
            .map_err(|e| PushCausalError::Io(format!("stream read error: {e}")))?;
        if n == 0 {
            break;
        }
        pack_bytes = pack_bytes.saturating_add(n as u64);
        if (command_bytes_read as u64).saturating_add(pack_bytes) > max_total {
            return Err(PushCausalError::LimitExceeded("push stream exceeded max_stream_bytes"));
        }
        if !header_checked {
            let need = PACK_HEADER_LEN - header_filled;
            let copy_len = need.min(n);
            header_buf[header_filled..header_filled + copy_len].copy_from_slice(&buf[..copy_len]);
            header_filled += copy_len;
            if header_filled == PACK_HEADER_LEN {
                declared_objects = validate_pack_header(&header_buf, limits)?;
                header_checked = true;
            }
        }
        hasher.update(&buf[..n]);
        file.write_all(&buf[..n]).await.map_err(|e| PushCausalError::Io(e.to_string()))?;
    }

    if pack_bytes == 0 {
        drop(file);
        let _ = std::fs::remove_file(&pack_path);
        return Ok(PackIngestResult {
            has_pack: false,
            incoming_pack_path: None,
            incoming_pack_sha256: None,
            incoming_pack_bytes: 0,
            incoming_object_count: 0,
            stream_wire_bytes: command_bytes_read as u64,
            stream_receive_ms: elapsed_ms(started),
        });
    }

    let trailer_bytes = match object_format {
        GitObjectFormat::Sha1 => 20u64,
        GitObjectFormat::Sha256 => 32u64,
    };
    if !header_checked || pack_bytes < (PACK_HEADER_LEN as u64).saturating_add(trailer_bytes) {
        return Err(PushCausalError::TruncatedPack("pack stream terminated before header or trailer checksum"));
    }

    file.flush().await.map_err(|e| PushCausalError::Io(e.to_string()))?;
    file.sync_data().await.map_err(|e| PushCausalError::Io(e.to_string()))?;
    let sha = hex::encode(hasher.finalize());
    Ok(PackIngestResult {
        has_pack: true,
        incoming_pack_path: Some(pack_path),
        incoming_pack_sha256: Some(sha),
        incoming_pack_bytes: pack_bytes,
        incoming_object_count: declared_objects,
        stream_wire_bytes: (command_bytes_read as u64).saturating_add(pack_bytes),
        stream_receive_ms: elapsed_ms(started),
    })
}

async fn create_private_file(path: &Path) -> Result<File, PushCausalError> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
    }
    opts.open(path).await.map_err(|e| PushCausalError::Io(e.to_string()))
}

fn validate_pack_header(hdr: &[u8; PACK_HEADER_LEN], limits: &StreamIngestLimits) -> Result<u32, PushCausalError> {
    if &hdr[..4] != b"PACK" {
        return Err(PushCausalError::TruncatedPack("missing PACK v2 magic signature"));
    }
    let version = u32::from_be_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
    if version != 2 {
        return Err(PushCausalError::CorruptPack(format!("unsupported Git PACK version {version}")));
    }
    let count = u32::from_be_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
    if count > limits.max_pack_objects {
        return Err(PushCausalError::LimitExceeded("PACK object count exceeded max_pack_objects"));
    }
    Ok(count)
}

/// Verified pack+idx upload artifacts with cryptographic read-back proof.
#[derive(Clone, Debug)]
pub struct UploadedQuarantinePack {
    pub pack_receipt: BlobReceipt,
    pub idx_receipt: BlobReceipt,
    pub pack_sha256: String,
    pub pack_bytes: u64,
    pub idx_sha256: String,
    pub idx_bytes: u64,
    pub closure_proof: BlobClosureProof,
    pub blob_closure_digest: String,
    pub upload_ms: u64,
}

/// Artifact bundle queued for quarantined OpenDAL Blob publication.
pub struct QuarantineArtifactSet<'a> {
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub generation: i64,
    pub pack_path: &'a Path,
    pub idx_path: &'a Path,
}

/// Pluggable carrier preserving `#113` `ProtectedUploader`/`ArtifactHold` boundaries outside `blob_store`.
pub trait PushBlobCarrier: Send + Sync {
    fn upload_and_verify_closure<'a>(
        &'a self,
        store: &'a BlobStore,
        artifacts: QuarantineArtifactSet<'a>,
        deadline: Instant,
    ) -> BoxFuture<'a, Result<UploadedQuarantinePack, PushCausalError>>;
}

/// Default OpenDAL S3/provider carrier delegating PUT + full read-back closure proof to `blob_store`.
#[derive(Clone, Copy, Debug, Default)]
pub struct CapacityContractBlobCarrier;

impl PushBlobCarrier for CapacityContractBlobCarrier {
    fn upload_and_verify_closure<'a>(
        &'a self,
        store: &'a BlobStore,
        artifacts: QuarantineArtifactSet<'a>,
        deadline: Instant,
    ) -> BoxFuture<'a, Result<UploadedQuarantinePack, PushCausalError>> {
        Box::pin(async move {
            let started = Instant::now();
            let generation = artifacts.generation.max(1);
            let scope =
                UploadScope { tenant_id: artifacts.tenant_id, authority_id: artifacts.repository_id, generation };
            let pair = upload_pack_pair(store, scope, artifacts.pack_path, artifacts.idx_path, deadline)
                .await
                .map_err(|e| PushCausalError::Io(e.to_string()))?;

            let entries = vec![
                ClosureEntrySpec::provider_managed(ClosureArtifactRole::Pack, pair.pack_receipt.locator().clone())
                    .with_expected_plaintext(&pair.pack_sha256, pair.pack_length)?,
                ClosureEntrySpec::provider_managed(ClosureArtifactRole::PackIndex, pair.idx_receipt.locator().clone())
                    .with_expected_plaintext(&pair.idx_sha256, pair.idx_length)?,
            ];
            let spec = BlobClosureSpec::new(
                artifacts.tenant_id,
                artifacts.repository_id,
                generation,
                BlobClosureEncryption::ProviderManaged,
                entries,
            )?;
            let closure_proof = store.verify_closure(&spec, None, None, deadline).await?;
            if !closure_proof.has_git_pack_pair() {
                return Err(PushCausalError::Blob(BlobError::ForeignBackend));
            }
            let digest = compute_blob_closure_digest(store, &pair.pack_receipt, &pair.idx_receipt);
            Ok(UploadedQuarantinePack {
                pack_receipt: pair.pack_receipt,
                idx_receipt: pair.idx_receipt,
                pack_sha256: pair.pack_sha256,
                pack_bytes: pair.pack_length,
                idx_sha256: pair.idx_sha256,
                idx_bytes: pair.idx_length,
                closure_proof,
                blob_closure_digest: digest,
                upload_ms: elapsed_ms(started),
            })
        })
    }
}

fn compute_blob_closure_digest(store: &BlobStore, pack: &BlobReceipt, idx: &BlobReceipt) -> String {
    let mut h = Sha256::new();
    h.update(b"push-blob-closure-v1\n");
    for s in [
        store.backend_identity().as_hex().as_str(),
        pack.locator().path(),
        pack.sha256(),
        idx.locator().path(),
        idx.sha256(),
    ] {
        h.update((s.len() as u64).to_be_bytes());
        h.update(s.as_bytes());
    }
    hex::encode(h.finalize())
}

fn elapsed_ms(started: Instant) -> u64 {
    Duration::from_nanos(started.elapsed().as_nanos().min(u64::MAX as u128) as u64).as_millis() as u64
}
