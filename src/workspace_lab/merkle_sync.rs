//! Versioned hierarchical Merkle directory manifest, dirty-subtree scanner,
//! lossy-watcher quiescence convergence, and Blob-first verified incremental sync
//! for workspaces (Issue #181).
//!
//! Architectural boundaries:
//! - **Identity & hash separation**: `MerkleRootDigest`, `WorktreeTreeDigest`,
//!   `IndexMerkleRoot`, Git tree OIDs, and `checkpoint_id` (`Uuid`) are strictly
//!   separate domains. A content digest never implies authorization, git history
//!   equivalence, or checkpoint durability.
//! - **Authorization & tenant isolation**: Every read, upload, diff, restore,
//!   fork, and backup operation enforces live per-request `(tenant_id, repo_id,
//!   user_id, history_id)` authorization and rejects cross-tenant/cross-repo
//!   cache hits, hash guessing, path guessing, and fenced histories.
//! - **Single-barrier quiescence**: Lossy watcher events (`Overflow`, `Dropped`,
//!   duplicates, reordering) trigger subtree/full rescan and pre/post-capture
//!   quiescence verification; mixed-point or unsupported Git states fail closed
//!   without publishing an inconsistent checkpoint.
//! - **Blob-first durability**: Missing chunks, directory nodes, and Git state
//!   bundles are published to OpenDAL `BlobStore`, readback/hash-verified via
//!   `BlobReceipt` / `BlobClosureProof`, and only then committed atomically.

#[path = "merkle_sync/authz.rs"]
pub mod authz;
#[path = "merkle_sync/backup_restore.rs"]
pub mod backup_restore;
#[path = "merkle_sync/blob_sync.rs"]
pub mod blob_sync;
#[path = "merkle_sync/converge.rs"]
pub mod converge;
#[path = "merkle_sync/git_compare.rs"]
pub mod git_compare;
#[path = "merkle_sync/git_state.rs"]
pub mod git_state;
#[path = "merkle_sync/ledger.rs"]
pub mod ledger;
#[path = "merkle_sync/manifest.rs"]
pub mod manifest;
#[path = "merkle_sync/manifest_verify.rs"]
pub mod manifest_verify;
#[path = "merkle_sync/restore.rs"]
pub mod restore;
#[path = "merkle_sync/scan_fs.rs"]
pub mod scan_fs;
#[path = "merkle_sync/scanner.rs"]
pub mod scanner;

use std::fmt;

use crate::blob_store::{BlobError, closure::BlobClosureError, disposable_view::DisposableViewError};

pub const MERKLE_MANIFEST_SCHEMA: u32 = 1;
pub const MERKLE_CODEC_VERSION: &str = "rootyard.merkle-sync.v1";
pub const MIN_CHUNK_BYTES: usize = 4 * 1024;
pub const DEFAULT_CHUNK_BYTES: usize = 64 * 1024;
pub const MAX_CHUNK_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_TREE_ENTRIES: usize = 100_000;
pub const MAX_WORKSPACE_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_TOTAL_CHUNKS: usize = 250_000;
pub const MAX_MANIFEST_JSON_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_SYMLINK_HOPS: usize = 40;

#[derive(Debug)]
pub enum MerkleSyncError {
    InvalidInput(String),
    InvalidManifest(String),
    UnsupportedGitState(String),
    NotQuiescent(String),
    ConcurrentEdit(String),
    AccessDenied(String),
    TenantScopeMismatch(String),
    StaleHistoryFenced(String),
    ForeignBackend,
    MissingArtifact(String),
    IntegrityMismatch(String),
    GitFailed(String),
    Blob(BlobError),
    Closure(BlobClosureError),
    DisposableView(DisposableViewError),
    Io(String),
}

impl fmt::Display for MerkleSyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(msg) => write!(f, "invalid merkle-sync input: {msg}"),
            Self::InvalidManifest(msg) => write!(f, "invalid merkle manifest: {msg}"),
            Self::UnsupportedGitState(msg) => write!(f, "unsupported Git workspace state: {msg}"),
            Self::NotQuiescent(msg) => write!(f, "workspace is not quiescent: {msg}"),
            Self::ConcurrentEdit(msg) => write!(f, "concurrent workspace edit detected: {msg}"),
            Self::AccessDenied(msg) => write!(f, "workspace access denied: {msg}"),
            Self::TenantScopeMismatch(msg) => write!(f, "workspace tenant/repo scope mismatch: {msg}"),
            Self::StaleHistoryFenced(msg) => write!(f, "workspace history is fenced: {msg}"),
            Self::ForeignBackend => f.write_str("blob object belongs to a different physical backend"),
            Self::MissingArtifact(msg) => write!(f, "missing remote merkle artifact: {msg}"),
            Self::IntegrityMismatch(msg) => write!(f, "merkle integrity verification failed: {msg}"),
            Self::GitFailed(msg) => write!(f, "native Git command failed: {msg}"),
            Self::Blob(err) => write!(f, "blob store error: {err}"),
            Self::Closure(err) => write!(f, "blob closure error: {err}"),
            Self::DisposableView(err) => write!(f, "disposable view error: {err}"),
            Self::Io(msg) => write!(f, "merkle-sync I/O error: {msg}"),
        }
    }
}

impl std::error::Error for MerkleSyncError {}

impl From<BlobError> for MerkleSyncError {
    fn from(value: BlobError) -> Self {
        match value {
            BlobError::ForeignBackend => Self::ForeignBackend,
            BlobError::NotFound => Self::MissingArtifact("blob object not found".into()),
            BlobError::DigestMismatch { .. } | BlobError::LengthMismatch { .. } => {
                Self::IntegrityMismatch(value.to_string())
            }
            other => Self::Blob(other),
        }
    }
}

impl From<BlobClosureError> for MerkleSyncError {
    fn from(value: BlobClosureError) -> Self {
        match value {
            BlobClosureError::ForeignBackend => Self::ForeignBackend,
            BlobClosureError::Blob(BlobError::NotFound) => Self::MissingArtifact("closure artifact not found".into()),
            BlobClosureError::PlaintextMismatch(msg) => Self::IntegrityMismatch(msg.to_owned()),
            other => Self::Closure(other),
        }
    }
}

impl From<DisposableViewError> for MerkleSyncError {
    fn from(value: DisposableViewError) -> Self {
        Self::DisposableView(value)
    }
}

impl From<std::io::Error> for MerkleSyncError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value.to_string())
    }
}

pub use authz::{
    AccessContext, GcEligibilityClass, GcSweepPlan, HistoryFenceRegistry, HoldPurpose, LiveWorkspaceAuthRegistry,
    PinHoldRecord, PinHoldRegistry, TenantRepoScopeKey, WorkspaceAuthAction, WorkspaceAuthorizer,
};
pub use backup_restore::{
    BackupArtifactEntry, BackupRestoreReport, MerkleBackupBundle, RestoreBackupParams, export_checkpoint_backup,
    restore_checkpoint_backup,
};
pub use blob_sync::{UploadParams, sync_incremental_to_blob};
pub use converge::{
    CaptureBarrierRequest, CoalescerStats, ConvergeOutcome, NoopBarrierProbe, QuiescenceBarrierProbe, WatcherBatch,
    WatcherCoalescer, WatcherEvent, capture_with_quiescence_barrier,
};
pub use git_compare::{
    GitBundleFile, GitBundleSnapshot, HeadIndexWorktreeComparison, compare_head_index_worktree, materialize_git_bundle,
};
pub use git_state::{IgnoreSnapshot, read_git_state_and_bundle, validate_git_compat};
pub use ledger::{
    BlobUploadDriver, CheckpointCommitRecord, CheckpointCommitState, MerkleBlobCheckpointManifest,
    MerkleCheckpointLedger, PgProtectedUploadDriver, RemoteObjectLocatorEntry, SyncUploadReport, UploadFailpoint,
    UploadVerifiedArgs, UploadVerifyFuture,
};
pub use manifest::{
    ChunkRef, EmptyDirPolicy, GitIndexEntryRecord, GitStateSnapshot, HeadSnapshot, IgnorePolicySpec, MerkleChangeKind,
    MerkleChildKind, MerkleDiffEntry, MerkleDirChild, MerkleDirNode, MerkleObjectFormat, MerkleStateManifest,
    UntrackedPolicy,
};
pub use manifest_verify::{diff_manifests, validate_manifest, verify_manifest_integrity};
pub use restore::{RestoreReport, RestoreRequest, restore_or_fork_from_blob};
pub use scanner::{DirtyScope, MerkleWorkspaceScanner, ScanMetrics, ScanRequest, ScanResult};
