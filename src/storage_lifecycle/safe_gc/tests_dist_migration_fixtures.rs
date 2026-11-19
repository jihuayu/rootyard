//! Fixtures for legacy safe-gc trust and DistributedRefCas journal migration tests (#122).

use std::path::{Path, PathBuf};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ref_store::core::state_machine::{
    AppliedLogId, InitializeGateCommand, NoopCommand, RefCasCommand, RefCasSnapshot, RefCasStateMachine,
    RepositoryLane, SmPackMode, WireGateInit,
};
use crate::ref_store::core::types::GitObjectFormat;

use super::super::{
    anti_aba::{AntiAbaKeyRegistry, KeyLifecycleState},
    domain::{AuthorityRecord, BlobLocatorRecord},
    model::{
        AuthorityLane, GcMode, GlobalHoldEntry, GlobalHoldState, PairedCursorReconciliation, SafeGcArmReceipt,
        SafeGcObjectFormat, SourceFreshness,
    },
    proof::DeletionProof,
    proof_digest::compute_proof_digest,
    quiescence::ReaderQuiescenceObservation,
    store::{PendingDeleteBatch, SafeGcRepoSnapshot, ServingPackRecord},
};
use super::{
    BackupRootEvidence, HoldBridgeEvidence, QuorumCommitEvidence, QuorumCommitSeal, SafeGcEd25519Signer,
    SafeGcRepoTrustConfig, TrustedConsensusVoter, VoterCutpointClaims, ensure_private_dir,
    sign_single_voter_cutpoint_attestation, write_private_file,
};

pub(super) const BRIDGE: &str = "2222222222222222222222222222222222222222222222222222222222222222";
pub(super) const BACKUP: &str = "3333333333333333333333333333333333333333333333333333333333333333";

pub(super) fn sha(tag: &str) -> String {
    hex::encode(Sha256::digest(tag.as_bytes()))
}

pub(super) fn legacy_json(repo_id: Uuid, tenant_id: Uuid, history_id: Uuid, arm: &str) -> Vec<u8> {
    serde_json::to_vec_pretty(&json!({
        "repo_id": repo_id,
        "tenant_id": tenant_id,
        "history_id": history_id,
        "trusted_arm_pubkey_hex": arm,
        "trusted_quorum_pubkey_hex": "1".repeat(64),
        "trusted_hold_bridge_pubkey_hex": BRIDGE,
        "trusted_backup_pubkey_hex": BACKUP,
        "refcas_keyring_dir": "/var/lib/rootyard/refcas-keyring",
    }))
    .unwrap()
}

pub(super) fn write_legacy_fixture(root: &Path, repo_id: Uuid, tenant_id: Uuid, history_id: Uuid, arm: &str) {
    let dir = SafeGcRepoTrustConfig::trust_dir(root);
    ensure_private_dir(&dir).unwrap();
    write_private_file(
        &SafeGcRepoTrustConfig::config_path(root, repo_id),
        &legacy_json(repo_id, tenant_id, history_id, arm),
    )
    .unwrap();
    write_private_file(&SafeGcRepoTrustConfig::seed_path(root, repo_id, "quorum"), &[0x55; 32]).unwrap();
}

pub(super) fn voters() -> Vec<TrustedConsensusVoter> {
    [0x71_u8, 0x72]
        .into_iter()
        .enumerate()
        .map(|(index, byte)| TrustedConsensusVoter {
            voter_id: index as u64 + 1,
            key_id: 1,
            ed25519_pubkey_hex: SafeGcEd25519Signer::from_seed([byte; 32]).unwrap().pubkey_hex().to_owned(),
            endpoint_url: format!("http://127.0.0.1:{}/", 18_101 + index),
        })
        .collect()
}

pub(super) fn authority(
    tenant_id: Uuid,
    repo_id: Uuid,
    history_id: Uuid,
    arm: &SafeGcEd25519Signer,
) -> AuthorityRecord {
    AuthorityRecord {
        tenant_id,
        repo_id,
        history_id,
        trusted_arm_pubkey_hex: arm.pubkey_hex().to_owned(),
        incarnation_id: Uuid::new_v4(),
        incarnation_epoch: 1,
        membership_generation: 1,
        live_ref_seq: 2,
        lease_epoch: 1,
    }
}

pub(super) fn hold(authority: &AuthorityRecord) -> GlobalHoldEntry {
    GlobalHoldEntry {
        hold_id: Uuid::new_v4(),
        tenant_id: authority.tenant_id,
        repo_id: authority.repo_id,
        incarnation_epoch: authority.incarnation_epoch,
        registered_seq: 1,
        state: GlobalHoldState::Active,
        protected_pack_ids: Vec::new(),
        protected_oids: vec!["a".repeat(40)],
        protected_physical_keys: Vec::new(),
    }
}

fn seeded_snapshot(tenant_id: Uuid, repo_id: Uuid, history_id: Uuid) -> RefCasSnapshot {
    let mut sm = RefCasStateMachine::new();
    let gate = WireGateInit {
        repository_id: repo_id,
        tenant_id,
        object_format: GitObjectFormat::Sha1,
        history_incarnation: history_id,
        authority_epoch: 1,
        group_epoch: 1,
        head_ref: "refs/heads/main".into(),
    };
    sm.apply(
        AppliedLogId { term: 1, index: 1 },
        RefCasCommand::InitializeGate(InitializeGateCommand {
            gate,
            lane: RepositoryLane::ServingRefStore,
            pack_mode: SmPackMode::MetadataOnly,
            authz_floor: 1,
        }),
    )
    .unwrap();
    sm.apply(AppliedLogId { term: 1, index: 2 }, RefCasCommand::Noop(NoopCommand { logical_tick: None })).unwrap();
    sm.snapshot().unwrap()
}

pub(super) fn dist_lane(
    authority: &AuthorityRecord,
    holds: &[GlobalHoldEntry],
    bridge: &SafeGcEd25519Signer,
    backup: &SafeGcEd25519Signer,
) -> AuthorityLane {
    let snapshot = seeded_snapshot(authority.tenant_id, authority.repo_id, authority.history_id);
    let mut signatures = Vec::new();
    let mut snapshot_sha256 = String::new();
    for voter_id in [1_u64, 2] {
        let signer = SafeGcEd25519Signer::from_seed([0x70 + voter_id as u8; 32]).unwrap();
        let claims = VoterCutpointClaims {
            voter_id,
            key_id: 1,
            group_id: 0,
            history_incarnation: authority.history_id,
            group_epoch: 1,
            authority_epoch: 1,
            raft_term: 1,
            committed_log_index: 2,
            raft_commit_digest_hex: sha("raft-commit"),
        };
        let attestation = sign_single_voter_cutpoint_attestation(&signer, &claims, &snapshot).unwrap();
        snapshot_sha256 = hex::encode(Sha256::digest(&attestation.snapshot_bytes));
        signatures.push(attestation.signature);
    }
    let quorum = QuorumCommitEvidence::from_verified_voters(
        authority.repo_id,
        1,
        QuorumCommitSeal {
            group_id: 0,
            history_incarnation: authority.history_id,
            authority_epoch: 1,
            raft_term: 1,
            committed_log_index: 2,
            raft_commit_digest_hex: sha("raft-commit"),
            snapshot_sha256,
            snapshot_checksum: snapshot.checksum,
            quorum_threshold: 2,
            voter_signatures: signatures,
        },
    )
    .unwrap();
    AuthorityLane::DistributedRefCas {
        ref_cas_authority_id: authority.repo_id,
        quorum_epoch: 1,
        raft_commit_index: 2,
        quorum_evidence: Box::new(quorum),
        hold_bridge_evidence: Box::new(HoldBridgeEvidence::sign(bridge, authority.repo_id, 1, 1, holds).unwrap()),
        backup_root_evidence: Box::new(
            BackupRootEvidence::sign(backup, authority.repo_id, 1, 1, sha("manifest"), vec!["a".repeat(40)]).unwrap(),
        ),
        async_projection_only: false,
    }
}

pub(super) fn snapshot_with_pending(
    authority: &AuthorityRecord,
    lane: &AuthorityLane,
    holds: &[GlobalHoldEntry],
    batch_id: Uuid,
) -> SafeGcRepoSnapshot {
    let mut registry = AntiAbaKeyRegistry::new();
    let scope = (authority.tenant_id, authority.repo_id, authority.history_id, authority.incarnation_epoch);
    let pack_key =
        registry.mint_immutable_key(scope, "pack", &"b".repeat(64), KeyLifecycleState::RetiredPendingProof).unwrap();
    let idx_key =
        registry.mint_immutable_key(scope, "idx", &"c".repeat(64), KeyLifecycleState::RetiredPendingProof).unwrap();
    let locator = |sha256: String| BlobLocatorRecord {
        tenant_id: authority.tenant_id,
        authority_id: authority.repo_id,
        generation: 1,
        attempt_id: Uuid::new_v4(),
        namespace: "packs".into(),
        sha256,
        length: 1,
        remote_etag: "etag".into(),
        remote_version_id: None,
    };
    let pack = ServingPackRecord {
        pack_id: Uuid::new_v4(),
        group_id: "group-main".into(),
        pack_locator: locator("b".repeat(64)),
        idx_locator: locator("c".repeat(64)),
        pack_key,
        idx_key,
        contained_oids: Vec::new(),
    };
    let mut proof = DeletionProof {
        schema_version: super::super::model::SAFE_GC_SCHEMA_VERSION,
        tenant_id: authority.tenant_id,
        repo_id: authority.repo_id,
        history_id: authority.history_id,
        object_format: SafeGcObjectFormat::Sha1,
        incarnation_id: authority.incarnation_id,
        incarnation_epoch: authority.incarnation_epoch,
        membership_generation: authority.membership_generation,
        membership_digest: sha("membership"),
        live_ref_seq: authority.live_ref_seq,
        lane: lane.clone(),
        reader_quiescence: ReaderQuiescenceObservation {
            observed_seq: 1,
            retired_at_generation: 1,
            min_active_reader_generation: 1,
            active_blocking_readers: 0,
            drain_watermark_generation: 1,
            pg_exclusive_reader_barrier_epoch: None,
        },
        live_refs: Vec::new(),
        producers: Vec::new(),
        global_holds: holds.to_vec(),
        in_flight_decisions: Vec::new(),
        paired_cursors: PairedCursorReconciliation {
            pg_freshness: SourceFreshness::Reconciled,
            pg_applied_seq: 1,
            pg_required_seq: 1,
            refcas_freshness: SourceFreshness::Reconciled,
            refcas_applied_index: 2,
            refcas_required_index: 2,
            refcas_cut: None,
        },
        group_receipts: Vec::new(),
        candidates: Vec::new(),
        proof_digest: String::new(),
    };
    proof.proof_digest = compute_proof_digest(&proof);
    let batch = PendingDeleteBatch {
        batch_id,
        incarnation_id: authority.incarnation_id,
        incarnation_epoch: authority.incarnation_epoch,
        lease_epoch: authority.lease_epoch,
        proof,
        active_step_fence: None,
        pending_keys: vec!["pending-key".into()],
        deleted_keys: vec!["deleted-key".into()],
        already_absent_keys: Vec::new(),
        unknown_keys: Vec::new(),
        skipped_keys: Vec::new(),
        failed_keys: Vec::new(),
    };
    SafeGcRepoSnapshot {
        authority: authority.clone(),
        object_format: SafeGcObjectFormat::Sha1,
        gc_mode: GcMode::ArmedDestructive(Box::new(
            SafeGcArmReceipt::seal(
                &SafeGcEd25519Signer::from_seed([0x41; 32]).unwrap(),
                authority.tenant_id,
                authority.repo_id,
                authority.history_id,
                authority.incarnation_id,
                authority.incarnation_epoch,
                true,
                lane.clone(),
            )
            .unwrap(),
        )),
        live_refs: Vec::new(),
        active_packs: Vec::new(),
        retired_packs: vec![pack],
        group_receipts: Vec::new(),
        producers: Vec::new(),
        global_holds: holds.to_vec(),
        in_flight_decisions: Vec::new(),
        paired_cursors: PairedCursorReconciliation {
            pg_freshness: SourceFreshness::Reconciled,
            pg_applied_seq: 1,
            pg_required_seq: 1,
            refcas_freshness: SourceFreshness::Reconciled,
            refcas_applied_index: 2,
            refcas_required_index: 2,
            refcas_cut: None,
        },
        reader_leases: Default::default(),
        staged_uploads: Vec::new(),
        key_registry: registry,
        pending_delete: Some(batch),
        completed_batches: Default::default(),
        aborted_batches: Default::default(),
        reconciled_sources: Default::default(),
        audit_log: Vec::new(),
    }
}

fn legacy_quorum(quorum: &Value) -> Value {
    json!({
        "group_id": quorum["group_id"].clone(),
        "history_incarnation": quorum["history_incarnation"].clone(),
        "authority_epoch": quorum["authority_epoch"].clone(),
        "raft_term": quorum["raft_term"].clone(),
        "committed_log_index": quorum["committed_log_index"].clone(),
        "raft_commit_digest_hex": quorum["raft_commit_digest_hex"].clone(),
        "snapshot_sha256": quorum["snapshot_sha256"].clone(),
        "snapshot_checksum": quorum["snapshot_checksum"].clone(),
        "quorum_pubkey_hex": "1".repeat(64),
        "quorum_signer_pubkey_hex": "1".repeat(64),
        "quorum_signature_hex": "2".repeat(128),
        "voter_hmacs": [[1_u16, "3".repeat(64)]],
    })
}

pub(super) fn legacy_document(mut doc: Value) -> Value {
    for pointer in ["/gc_mode/ArmedDestructive/lane", "/pending_delete/proof/lane"] {
        if let Some(mut lane) = doc.pointer(pointer).cloned() {
            let quorum = lane["DistributedRefCas"]["quorum_evidence"].clone();
            lane["DistributedRefCas"]["quorum_evidence"] = legacy_quorum(&quorum);
            *doc.pointer_mut(pointer).unwrap() = lane;
        }
    }
    doc
}

pub(super) fn write_legacy_trust(
    root: &Path,
    authority: &AuthorityRecord,
    arm: &SafeGcEd25519Signer,
    bridge: &SafeGcEd25519Signer,
    backup: &SafeGcEd25519Signer,
) {
    ensure_private_dir(&SafeGcRepoTrustConfig::trust_dir(root)).unwrap();
    let bytes = serde_json::to_vec_pretty(&json!({
        "repo_id": authority.repo_id,
        "tenant_id": authority.tenant_id,
        "history_id": authority.history_id,
        "trusted_arm_pubkey_hex": arm.pubkey_hex(),
        "trusted_quorum_pubkey_hex": "1".repeat(64),
        "trusted_hold_bridge_pubkey_hex": bridge.pubkey_hex(),
        "trusted_backup_pubkey_hex": backup.pubkey_hex(),
        "refcas_keyring_dir": "/var/lib/rootyard/refcas-keyring",
    }))
    .unwrap();
    write_private_file(&SafeGcRepoTrustConfig::config_path(root, authority.repo_id), &bytes).unwrap();
    write_private_file(&SafeGcRepoTrustConfig::seed_path(root, authority.repo_id, "quorum"), &[0x55; 32]).unwrap();
}

pub(super) fn journal_path(root: &Path, repo_id: Uuid) -> PathBuf {
    root.join("safe-gc").join(format!("{repo_id}.json"))
}

pub(super) fn current_quorum(lane: &AuthorityLane) -> QuorumCommitEvidence {
    match lane {
        AuthorityLane::DistributedRefCas { quorum_evidence, .. } => quorum_evidence.as_ref().clone(),
        AuthorityLane::SingleNodePg { .. } => unreachable!(),
    }
}
