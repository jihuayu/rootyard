//! Coordinated PG cutpoint + Raft index + Blob closure paired backup and
//! clean-room new-incarnation restore engine (#153).

pub mod admission_guard;
pub mod backup;
pub mod closure_bind;
pub mod durable_freeze_gate;
pub mod durable_guarded_ops;
pub mod format30_boot;
pub mod format30_paired;
pub mod freeze_drain;
pub mod git_verify;
pub mod mtls_raft;
pub mod mtls_wire;
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
pub use durable_freeze_gate::{
    DurableFreezeHandle, DurableFreezeRequest, PG_FREEZE_SETTING, enter_durable_pg_raft_freeze,
    execute_deleter_guarded, load_pg_repo_backup_specs, propose_raft_hold_guarded, propose_raft_ref_write_guarded,
    read_pg_database_freeze_marker, require_unfrozen_pg_and_raft, thaw_durable_pg_raft_freeze,
    upsert_repo_access_collaborator_guarded,
};
pub use format30_paired::{
    FORMAT30_SUBDIR, Format30PairedBackupRequest, Format30PairedManifest, Format30PgArchiveBinding,
    STANDARD_PAIRED_PG_FORMAT, STANDARD_SCHEMA_HEAD, create_format30_paired_raft_backup,
    restore_and_boot_format30_new_incarnation, verify_format30_paired_archive,
};
pub use freeze_drain::{InFlightOperation, RepoBackupRegistrationSpec, TriPartyBackupCoordinator};
pub use mtls_raft::{DurableRaftFreezeRecord, MtlsLiveRaftBackend, MtlsRaftClusterConfig};
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
