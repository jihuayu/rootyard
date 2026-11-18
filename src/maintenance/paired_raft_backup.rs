//! Coordinated PG cutpoint + Raft index + Blob closure paired backup and
//! clean-room new-incarnation restore engine (#153).

pub mod backup;
pub mod closure_bind;
pub mod freeze_drain;
pub mod git_verify;
pub mod pg_cutpoint;
pub mod pg_restore_admission;
pub mod raft_barrier;
pub mod restore;
pub mod types;

#[cfg(test)]
mod unit_tests;

pub use backup::{PairedBackupRequest, PreparedBlobArtifact, capture_live_pg_backup, create_paired_backup};
pub use closure_bind::{
    compute_canonical_pack_set_digest, extract_raft_group_realm, verify_blob_closure_against_durable_raft,
    verify_cursor_group_epochs,
};
pub use freeze_drain::{InFlightOperation, RepoBackupRegistrationSpec, TriPartyBackupCoordinator};
pub use pg_cutpoint::{ExpectedRaftCut, capture_pg_cutpoint_in_tx, freeze_pg_deleter};
pub use pg_restore_admission::{
    install_restored_pg_incarnation, verify_pg_live_incarnation, verify_pg_restored_cursors,
};
pub use raft_barrier::{
    DurableFreezeBarrierProof, DurableRaftApplyReceipt, DurableRaftBackend, SealedArchiveReceipt, WalSyncedRaftBackend,
};
pub use restore::{
    IncarnationAdmissionGuard, RestoreTargetScope, restore_new_incarnation, restore_new_incarnation_with_pg,
    verify_backup_archive,
};
pub use types::{
    BackupRetentionHoldRecord, BlobArtifactEntry, BlobClosureManifest, CloseScopeBarrierReceipt,
    DecisionExecutionTicket, DeleterLeaseTicket, ExpectedPackPairSpec, FreezePartyStatus, NewIncarnationAuthority,
    PAIRED_BACKUP_FORMAT_V1, PairedBackupError, PairedBackupManifest, PgCutpointProof, PgProjectionCursorCut,
    PgRepositoryRowProof, RaftCutpointProof, RestoreOutcome, WriterGrantTicket,
};
