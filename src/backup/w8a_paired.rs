//! W8-A single-node paired PostgreSQL + Blob fresh-incarnation recovery.
//!
//! This module owns only the paired-specific envelope: a format30 archive plus
//! a non-secret key/topology sidecar and a complete marker. PostgreSQL restore,
//! Blob rebuild and the base fencing transaction remain the shared backup code;
//! W8-A adds key verification before any target touch and the fresh-incarnation
//! capability/deleter fence after restore.
use std::{error::Error, fmt};

use uuid::Uuid;

mod create;
mod deleter_fence;
mod fsck;
mod manifest_key_ref;
mod restore;
#[cfg(test)]
mod tests;

pub use super::authority::{W8aFenceReceipt, fence_w8a_fresh_incarnation};
pub use create::{W8aCreateReceipt, create};
pub use deleter_fence::{DeleterAdmissionReceipt, admit_deleter_epoch, ensure_destructive_gc_disabled};
pub use fsck::W8aRepoFsckReceipt;
pub use manifest_key_ref::{
    KEY_CANARY_DOMAIN, KEY_DIGEST_DOMAIN, MANIFEST_SEAL_DOMAIN, W8A_FORMAT_VERSION, W8aKeyReference,
    W8aPairedSidecarManifest, capture_key_reference, verify_key_reference,
};
pub use restore::{W8aRestoreReceipt, check, restore};
pub(super) use restore::{finish_guarded_restore, verify_restored_source_snapshot};

/// Fail-closed W8-A refusals. Every variant carries only non-secret, bounded
/// diagnostic text (repository ids, epochs, counts and reasons).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum W8aError {
    RaftCutForbiddenInSingleNodeW8a(String),
    DestructiveGcForbidden(String),
    UnsupportedRepositoryBackend(String),
    KeyReferenceMismatch(String),
    MixedPointInTime(String),
    MissingOrCorruptBlobArtifact(String),
    StaleDeleterFenced { candidate_epoch: i64, minimum_required_epoch: i64, remote_delete_fenced: bool },
    GitFsckFailed { repository_id: Uuid, detail: String },
    BackupFailed(String),
    RestoreFailed(String),
}

pub type W8aResult<T> = std::result::Result<T, W8aError>;

impl fmt::Display for W8aError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RaftCutForbiddenInSingleNodeW8a(reason) => {
                write!(f, "single-node W8-A backup refuses a raft cut: {reason}")
            }
            Self::DestructiveGcForbidden(reason) => write!(f, "destructive GC must be disabled: {reason}"),
            Self::UnsupportedRepositoryBackend(reason) => {
                write!(f, "paired restore requires committed PG RefStore serving: {reason}")
            }
            Self::KeyReferenceMismatch(reason) => write!(f, "paired backup key reference mismatch: {reason}"),
            Self::MixedPointInTime(reason) => write!(f, "paired archive is not one point in time: {reason}"),
            Self::MissingOrCorruptBlobArtifact(reason) => {
                write!(f, "paired archive is missing or has a corrupt Blob artifact: {reason}")
            }
            Self::StaleDeleterFenced { candidate_epoch, minimum_required_epoch, remote_delete_fenced } => write!(
                f,
                "deleter epoch {candidate_epoch} is stale (requires at least {minimum_required_epoch}, fenced={remote_delete_fenced})"
            ),
            Self::GitFsckFailed { repository_id, detail } => {
                write!(f, "restored repository {repository_id} failed git fsck --full --strict: {detail}")
            }
            Self::BackupFailed(reason) => write!(f, "paired backup failed: {reason}"),
            Self::RestoreFailed(reason) => write!(f, "paired restore failed: {reason}"),
        }
    }
}

impl Error for W8aError {}
