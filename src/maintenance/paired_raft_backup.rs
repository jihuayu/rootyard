//! Coordinated PG cutpoint + Raft index + Blob closure paired backup and
//! clean-room new-incarnation restore engine (#153).

pub mod admission_guard;
pub mod backup;
pub mod closure_bind;
pub mod freeze_drain;
pub mod git_verify;
pub mod peer_groups;
pub mod pg_cutpoint;
pub mod pg_restore_admission;
pub mod quorum_wal;
pub mod raft_barrier;
pub mod restore;
pub mod types;

#[cfg(test)]
mod unit_tests;
#[cfg(test)]
mod unit_tests_quorum_peers;

pub use backup::{PairedBackupRequest, PreparedBlobArtifact, capture_live_pg_backup, create_paired_backup};
pub use closure_bind::{
    compute_canonical_pack_set_digest, extract_raft_group_realm, verify_blob_closure_against_durable_raft,
};
pub use freeze_drain::{InFlightOperation, RepoBackupRegistrationSpec, TriPartyBackupCoordinator};
pub use peer_groups::{
    ExpectedGroupCursorCut, PeerGroupBackupInput, PeerRaftCutpointProof, extract_peer_expected_cuts,
    restore_peer_groups_state, verify_all_group_cursors, verify_archived_peer_groups,
};
pub use pg_cutpoint::{ExpectedRaftCut, capture_pg_cutpoint_in_tx, freeze_pg_deleter};
pub use pg_restore_admission::{
    install_restored_pg_incarnation, verify_pg_live_incarnation, verify_pg_restored_cursors,
};
pub use quorum_wal::{DurableRaftBackend, WalSyncedRaftBackend};
pub use raft_barrier::{
    DurableFreezeBarrierProof, DurableRaftApplyReceipt, LocalWalApplyReceipt, QuorumCommitReceipt,
    SealedArchiveReceipt, VoterWalAck, compute_group_membership_digest,
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
