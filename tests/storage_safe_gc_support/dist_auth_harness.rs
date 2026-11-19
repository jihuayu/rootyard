//! Shared Ed25519, trust-provisioning and distributed-lane helpers for Safe GC integration tests (#122).

use std::path::Path;

use rootyard::storage_lifecycle::safe_gc::{
    SafeGcError,
    dist_auth::{
        BackupRootEvidence, HoldBridgeEvidence, QuorumCommitEvidence, SafeGcEd25519Signer, SafeGcRepoTrustConfig,
    },
    model::{AuthorityLane, GlobalHoldEntry, SafeGcArmReceipt, SafeGcObjectFormat},
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub use rootyard::storage_lifecycle::safe_gc::dist_auth::write_refcas_group_keyring_dir;

pub const TEST_ARM_SEED: [u8; 32] = [0x41; 32];

pub fn test_arm_signer() -> SafeGcEd25519Signer {
    SafeGcEd25519Signer::from_seed(TEST_ARM_SEED).unwrap()
}

pub fn test_dist_lane(
    ref_cas_authority_id: Uuid,
    quorum_epoch: u64,
    raft_commit_index: u64,
    holds: &[GlobalHoldEntry],
    format: SafeGcObjectFormat,
) -> AuthorityLane {
    let signer = test_arm_signer();
    let quorum = QuorumCommitEvidence::sign(
        &signer,
        ref_cas_authority_id,
        quorum_epoch,
        0,
        1,
        raft_commit_index,
        hex::encode(Sha256::digest(b"s3-it-sm-snap")),
        vec![rootyard::ref_store::core::artifact_hold::reconcile_proof::GroupVoterSignatureDto {
            voter_id: 1,
            key_id: 0,
            mac_hex: hex::encode([0x33_u8; 32]),
        }],
    )
    .unwrap();
    let bridge =
        HoldBridgeEvidence::sign(&signer, ref_cas_authority_id, quorum_epoch, raft_commit_index.max(1), holds).unwrap();
    let backup = BackupRootEvidence::sign(
        &signer,
        ref_cas_authority_id,
        quorum_epoch,
        1,
        hex::encode([0x44_u8; 32]),
        vec!["a".repeat(format.oid_hex_len())],
    )
    .unwrap();
    AuthorityLane::DistributedRefCas {
        ref_cas_authority_id,
        quorum_epoch,
        raft_commit_index,
        quorum_evidence: quorum,
        hold_bridge_evidence: bridge,
        backup_root_evidence: backup,
        async_projection_only: false,
    }
}

/// Seal an arm with the shared test signer so repository trust matches the acceptance key.
pub fn seal_test_lane_arm(
    tenant_id: Uuid,
    repo_id: Uuid,
    history_id: Uuid,
    incarnation_id: Uuid,
    incarnation_epoch: u64,
    lane: AuthorityLane,
) -> Result<SafeGcArmReceipt, SafeGcError> {
    SafeGcArmReceipt::seal(
        &test_arm_signer(),
        tenant_id,
        repo_id,
        history_id,
        incarnation_id,
        incarnation_epoch,
        true,
        lane,
    )
}

pub fn provision_single_node_trust(
    storage_root: &Path,
    tenant_id: Uuid,
    repo_id: Uuid,
    history_id: Uuid,
) -> Result<SafeGcRepoTrustConfig, SafeGcError> {
    SafeGcRepoTrustConfig::provision_single_node(storage_root, tenant_id, repo_id, history_id, &test_arm_signer())
}

pub fn provision_distributed_trust(
    storage_root: &Path,
    tenant_id: Uuid,
    repo_id: Uuid,
    history_id: Uuid,
    keyring_dir: &Path,
) -> Result<SafeGcRepoTrustConfig, SafeGcError> {
    let signer = test_arm_signer();
    SafeGcRepoTrustConfig::provision_distributed(
        storage_root,
        tenant_id,
        repo_id,
        history_id,
        (&signer, &signer, &signer),
        signer.pubkey_hex(),
        keyring_dir,
    )
}
