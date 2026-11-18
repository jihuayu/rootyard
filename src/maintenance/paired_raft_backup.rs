//! Coordinated PG cutpoint + Raft index + Blob closure paired backup and
//! clean-room new-incarnation restore engine (#153).

pub mod backup;
pub mod freeze_drain;
pub mod git_verify;
pub mod pg_cutpoint;
pub mod restore;
pub mod types;

#[cfg(test)]
mod unit_tests;

pub use backup::{PairedBackupRequest, PreparedBlobArtifact, capture_live_pg_backup, create_paired_backup};
pub use freeze_drain::{InFlightOperation, TriPartyBackupCoordinator};
pub use pg_cutpoint::{capture_pg_cutpoint_in_tx, freeze_pg_deleter, verify_pg_live_incarnation};
pub use restore::{
    IncarnationAdmissionGuard, RestoreTargetScope, restore_new_incarnation, restore_new_incarnation_with_pg,
    verify_backup_archive,
};
pub use types::{
    BackupRetentionHoldRecord, BlobArtifactEntry, BlobClosureManifest, CloseScopeBarrierReceipt,
    DecisionExecutionTicket, DeleterLeaseTicket, FreezePartyStatus, NewIncarnationAuthority, PAIRED_BACKUP_FORMAT_V1,
    PairedBackupError, PairedBackupManifest, PgCutpointProof, PgProjectionCursorCut, PgRepositoryRowProof,
    RaftCutpointProof, RestoreOutcome, WriterGrantTicket,
};
