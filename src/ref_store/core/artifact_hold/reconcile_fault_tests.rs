//! Deterministic unit tests for consensus-verified shared-hold retirement proofs,
//! non-underreportable snapshot barriers, tamper rejection, and multi-group faults.

use super::bridge_contract::{
    BridgeBinding, BridgeRootRegistrationPlan, GroupHoldBinding, PgArtifactHoldReconciliationView,
    PgCrossRepoSiblingHold, PgHoldRowSummary, RetentionBridgeError, SharedHoldReference, SharedHoldRetirementStatus,
};
use super::contract::ArtifactHoldPurpose;
use super::group_keyring::{
    AttestedGroupSnapshotDto, GroupConsensusVerifier, GroupVoterSignatureDto, QuorumCommitClaims,
    quorum_commit_transcript_bytes,
};
use super::receipt::{AcquireAck, HoldAck, HoldArtifactIdentity};
use super::reconcile_proof::{GroupObservationStatus, RetirementBlockReason};
use super::retention_bridge::{
    VerifiedGlobalHoldReservation, apply_release_root_idempotent, apply_reserved_hold_to_sm,
    apply_retire_hold_batch_idempotent, publish_pin_and_root_after_hold,
};
use super::retirement_reconcile::evaluate_shared_hold_retirement;
use crate::ref_store::GitObjectFormat;
use crate::ref_store::contract::{MetadataPinPurpose, RequestDigest};
use crate::ref_store::core::state_machine::{
    AppliedLogId, ApplyResponse, InitializeGateCommand, NoopCommand, RefCasCommand, RefCasSnapshot, RefCasStateMachine,
    ReleaseRootCommand, RepositoryLane, RetireHoldBatchCommand, ScopeLifecycle, SetRepositoryLaneCommand, SmPackMode,
    StateMachineError, WireGateInit,
};
use crate::ref_store::projector::{ProjectionCursor, ProjectionRealm, TruncationCutoff};
use ring::hmac;
use sha2::{Digest, Sha256};
use uuid::Uuid;

fn dhex(label: &str) -> String {
    RequestDigest::of("retention-reconcile-fault-test", &[label.as_bytes()]).as_hex()
}

fn log(index: u64) -> AppliedLogId {
    AppliedLogId { term: 1, index }
}

fn lane_cmd(repo: Uuid, tenant: Uuid, history: Uuid, lifecycle: ScopeLifecycle) -> RefCasCommand {
    RefCasCommand::SetRepositoryLane(SetRepositoryLaneCommand {
        repository_id: repo,
        tenant_id: tenant,
        lane: RepositoryLane::ServingRefStore,
        lifecycle,
        authz_floor: 1,
        history_incarnation: history,
        authority_epoch: 1,
        group_epoch: 1,
        pack_mode: SmPackMode::MetadataOnly,
    })
}

fn make_cursor(history: Uuid, group_id: i64, group_epoch: i64, applied_log_index: u64) -> ProjectionCursor {
    ProjectionCursor::genesis(ProjectionRealm::new(history, group_id, group_epoch).unwrap())
        .map(|mut c| {
            c.applied_event_seq = applied_log_index + 3;
            c.applied_log_index = applied_log_index;
            c.applied_log_term = 1;
            c.last_event_id = Some(format!("ev-{group_id}"));
            c
        })
        .unwrap()
}

struct GroupFx {
    repo: Uuid,
    tenant: Uuid,
    owner: Uuid,
    history: Uuid,
    hold_id: Uuid,
    retire_id: Uuid,
    plan: BridgeRootRegistrationPlan,
}

fn setup_published_group(seed: u128, sha: &str, backend: &str, group_id: i64) -> (RefCasStateMachine, GroupFx) {
    let id = |n: u128| Uuid::from_u128(seed + n);
    let (repository_id, tenant_id, owner_id, history_incarnation, authority_id) = (id(1), id(2), id(3), id(4), id(5));
    let (issuer_id, operation_id, hold_id, request_id, retire_id) = (id(6), id(7), id(8), id(9), id(17));
    let mut sm = RefCasStateMachine::new();
    let gate = WireGateInit {
        repository_id,
        tenant_id,
        object_format: GitObjectFormat::Sha256,
        history_incarnation,
        authority_epoch: 1,
        group_epoch: 1,
        head_ref: "refs/heads/main".into(),
    };
    let init_cmd = InitializeGateCommand {
        gate,
        lane: RepositoryLane::ServingRefStore,
        pack_mode: SmPackMode::MetadataOnly,
        authz_floor: 1,
    };
    let ApplyResponse::GateInitialized { version, .. } =
        sm.apply(log(1), RefCasCommand::InitializeGate(init_cmd)).unwrap()
    else {
        panic!("expected GateInitialized");
    };
    let op_digest = dhex(&format!("op-{seed}"));
    let binding = BridgeBinding {
        tenant_id,
        repository_id,
        owner_id,
        authority_id,
        authority_generation: 1,
        authority_epoch: 1,
        backend_identity: backend.to_owned(),
        history_incarnation,
        group_id,
        group_epoch: 1,
        issuer_id,
        lane: "push".into(),
        sequence: 10,
        operation_id,
        operation_digest: op_digest.clone(),
    };
    let artifact = HoldArtifactIdentity {
        provider: "s3".into(),
        backend_identity: backend.to_owned(),
        tenant_id,
        authority_id,
        authority_generation: 1,
        attempt_id: id(11),
        namespace: "pack".into(),
        sha256: sha.to_owned(),
        length: 4096,
    };
    let ack = AcquireAck {
        request_id,
        request_digest: dhex(&format!("req-{seed}")),
        repository_id,
        tenant_id,
        owner_id,
        purpose: ArtifactHoldPurpose::RefPublication,
        object_format: GitObjectFormat::Sha256,
        history_incarnation,
        authority_epoch: 1,
        group_epoch: 1,
        issuer_id,
        lane: "push".into(),
        sequence: 10,
        operation_id,
        operation_digest: op_digest,
        gate_revision: 1,
        gate_digest: version.digest().as_hex(),
        shard: 0,
        backend_identity: backend.to_owned(),
        consume_request_id: id(10),
        declared_bytes: 4096,
        logical_bytes: 4608,
        artifacts: vec![HoldAck { hold_id, slot: 0, artifact, declared_bytes: 4096, logical_bytes: 4608 }],
    };
    let reservation = VerifiedGlobalHoldReservation::mint_for_unit_test(binding.clone(), ack);
    let plan = BridgeRootRegistrationPlan {
        pin_request_id: id(12),
        snapshot_id: id(13),
        pin_id: id(14),
        pin_purpose: MetadataPinPurpose::Backup,
        lease_ticks: 50,
        pin_logical_tick: 10,
        pack_digests: vec![],
        pin_request_digest: dhex(&format!("pin-{seed}")),
        root_request_id: id(15),
        root_id: id(16),
        root_purpose: "backup".into(),
        business_intent_digest: dhex(&format!("bi-{seed}")),
        selector_kind: "snapshot".into(),
        selector_digest: dhex(&format!("sel-{seed}")),
        refs_digest: dhex(&format!("refs-{seed}")),
        pack_set_digest: dhex(&format!("packs-{seed}")),
        register_digest: dhex(&format!("reg-{seed}")),
        root_request_digest: dhex(&format!("root-{seed}")),
    };
    apply_reserved_hold_to_sm(&mut sm, log(2), &reservation, &binding).unwrap();
    publish_pin_and_root_after_hold(&mut sm, log(3), log(4), &reservation, &binding, &plan).unwrap();
    let fx = GroupFx {
        repo: repository_id,
        tenant: tenant_id,
        owner: owner_id,
        history: history_incarnation,
        hold_id,
        retire_id,
        plan,
    };
    (sm, fx)
}

fn close_and_retire_at(sm: &mut RefCasStateMachine, f: &GroupFx, release_idx: u64, close_idx: u64, retire_idx: u64) {
    apply_release_root_idempotent(
        sm,
        log(release_idx),
        ReleaseRootCommand {
            request_id: Uuid::new_v4(),
            root_id: f.plan.root_id,
            repository_id: f.repo,
            tenant_id: f.tenant,
            owner_id: f.owner,
            expected_register_digest: f.plan.register_digest.clone(),
            intent_digest: dhex("done"),
        },
    )
    .unwrap();
    sm.apply(log(close_idx), lane_cmd(f.repo, f.tenant, f.history, ScopeLifecycle::Closing)).unwrap();
    apply_retire_hold_batch_idempotent(
        sm,
        log(retire_idx),
        RetireHoldBatchCommand {
            request_id: f.retire_id,
            repository_id: f.repo,
            tenant_id: f.tenant,
            hold_ids: vec![f.hold_id],
        },
    )
    .unwrap();
}

fn voter_key(group_tag: u8, voter_id: u64) -> [u8; 32] {
    let mut raw = [group_tag; 32];
    raw[0] = voter_id as u8;
    raw[31] = group_tag.wrapping_add(0x41);
    raw
}

fn voters_for(group_tag: u8) -> Vec<(u64, u8, [u8; 32])> {
    (1..=3).map(|vid| (vid, 1, voter_key(group_tag, vid))).collect()
}

fn attest_snap_bytes(
    snapshot_bytes: Vec<u8>,
    group_id: i64,
    history_incarnation: Uuid,
    voters: &[(u64, u8, [u8; 32])],
) -> AttestedGroupSnapshotDto {
    let sha_bytes: [u8; 32] = Sha256::digest(&snapshot_bytes).into();
    let snap: RefCasSnapshot = serde_json::from_slice(&snapshot_bytes).unwrap();
    let applied = snap.body.last_applied.unwrap();
    let gate = snap.body.gates.first().unwrap();
    let voter_signatures = voters
        .iter()
        .map(|&(voter_id, key_id, raw)| {
            let claims = QuorumCommitClaims {
                group_id,
                history_incarnation,
                group_epoch: gate.group_epoch,
                authority_epoch: gate.authority_epoch,
                raft_term: applied.term,
                committed_log_index: applied.index,
                voter_id,
                key_id,
                snapshot_sha256: &sha_bytes,
            };
            let key = hmac::Key::new(hmac::HMAC_SHA256, &raw);
            let tag = hmac::sign(&key, &quorum_commit_transcript_bytes(&claims));
            GroupVoterSignatureDto { voter_id, key_id, mac_hex: hex::encode(tag.as_ref()) }
        })
        .collect();
    AttestedGroupSnapshotDto {
        group_id,
        history_incarnation,
        group_epoch: gate.group_epoch,
        authority_epoch: gate.authority_epoch,
        raft_term: applied.term,
        committed_log_index: applied.index,
        snapshot_sha256: hex::encode(sha_bytes),
        snapshot_bytes,
        voter_signatures,
    }
}

fn mk_binding(group_id: i64, f: &GroupFx) -> GroupHoldBinding {
    GroupHoldBinding {
        group_id,
        history_incarnation: f.history,
        expected_group_epoch: 1,
        repository_id: f.repo,
        tenant_id: f.tenant,
        hold_ids: vec![f.hold_id],
        retire_request_id: f.retire_id,
    }
}

#[test]
fn unauthenticated_forged_quorum_and_missing_pg_evidence_fail_closed() {
    let (sha, backend) = (dhex("shared-art"), dhex("s3-shared"));
    let (mut sm1, f1) = setup_published_group(1000, &sha, &backend, 10);
    let (_sm2, f2) = setup_published_group(2000, &dhex("different-art"), &backend, 20);
    let (g1, g2) = (mk_binding(10, &f1), mk_binding(20, &f2));
    let (v1, v2) = (voters_for(0x11), voters_for(0x22));
    let verifier = GroupConsensusVerifier::from_test_quorums(vec![
        (10, f1.history, 2, v1.clone()),
        (20, f2.history, 2, v2.clone()),
    ]);

    close_and_retire_at(&mut sm1, &f1, 5, 6, 10);
    let attested = attest_snap_bytes(sm1.snapshot_bytes().unwrap(), 10, f1.history, &v1[..2]);

    // 1. Unauthenticated (empty/minority/duplicate signatures) and wrong-group key swap fail closed.
    let mut empty = attested.clone();
    empty.voter_signatures.clear();
    assert_eq!(
        verifier.verify_attested_observation(&empty, &g1, &sha, &backend, None).unwrap_err(),
        RetentionBridgeError::UntrustedObservationProof
    );
    let mut minority = attested.clone();
    minority.voter_signatures.truncate(1);
    assert_eq!(
        verifier.verify_attested_observation(&minority, &g1, &sha, &backend, None).unwrap_err(),
        RetentionBridgeError::UntrustedObservationProof
    );
    let mut dup_voter = attested.clone();
    dup_voter.voter_signatures[1] = dup_voter.voter_signatures[0].clone();
    assert_eq!(
        verifier.verify_attested_observation(&dup_voter, &g1, &sha, &backend, None).unwrap_err(),
        RetentionBridgeError::UntrustedObservationProof
    );
    let wrong_group_sig = attest_snap_bytes(sm1.snapshot_bytes().unwrap(), 10, f1.history, &v2[..2]);
    assert_eq!(
        verifier.verify_attested_observation(&wrong_group_sig, &g1, &sha, &backend, None).unwrap_err(),
        RetentionBridgeError::UntrustedObservationProof
    );

    // 2. Post-sign tampering (coordinate or snapshot bytes) AND corrupted inner snapshot body checksum fail closed.
    let mut bad_coord = attested.clone();
    bad_coord.committed_log_index = 1;
    assert_eq!(
        verifier.verify_attested_observation(&bad_coord, &g1, &sha, &backend, None).unwrap_err(),
        RetentionBridgeError::UntrustedObservationProof
    );
    let mut tampered_snap: RefCasSnapshot = serde_json::from_slice(&attested.snapshot_bytes).unwrap();
    tampered_snap.body.last_applied = Some(log(1));
    let mut tampered_wire = attested.clone();
    tampered_wire.snapshot_bytes = serde_json::to_vec(&tampered_snap).unwrap();
    assert_eq!(
        verifier.verify_attested_observation(&tampered_wire, &g1, &sha, &backend, None).unwrap_err(),
        RetentionBridgeError::UntrustedObservationProof
    );
    let corrupt_attested = attest_snap_bytes(serde_json::to_vec(&tampered_snap).unwrap(), 10, f1.history, &v1[..2]);
    let snap_err = verifier.verify_attested_observation(&corrupt_attested, &g1, &sha, &backend, None).unwrap_err();
    assert!(matches!(snap_err, RetentionBridgeError::StateMachine(StateMachineError::SnapshotCorrupted(_))));

    // 3. Low caller hint (Some(1)) still locks barrier to committed log 10; lagging cursor AND pg_holds=None fail closed!
    let verified = verifier.verify_attested_observation(&attested, &g1, &sha, &backend, Some(1)).unwrap();
    assert_eq!(verified.retired_proof().unwrap().barrier_log_index(), 10);
    let shared = SharedHoldReference {
        shared_hold_key: Uuid::from_u128(9900),
        artifact_digest: sha.clone(),
        backend_identity: backend.clone(),
        groups: vec![g1],
    };
    let out_lag =
        evaluate_shared_hold_retirement(&shared, &[verified.clone()], &[make_cursor(f1.history, 10, 1, 2)], None)
            .unwrap();
    assert_eq!(out_lag.status, SharedHoldRetirementStatus::Protected);
    assert!(out_lag.reasons.contains(&RetirementBlockReason::MissingPgEvidence));
    assert!(out_lag.reasons.iter().any(|r| matches!(
        r,
        RetirementBlockReason::CursorBehindRetirement { group_id: 10, applied_log_index: 2, retirement_log_index: 10 }
    )));
    // Even with a converged cursor, pg_holds = None NEVER returns RetiredToSafeReclaim (P2).
    let out_no_pg =
        evaluate_shared_hold_retirement(&shared, &[verified], &[make_cursor(f1.history, 10, 1, 10)], None).unwrap();
    assert_eq!(
        (out_no_pg.status, out_no_pg.reconciled_groups, out_no_pg.reasons),
        (SharedHoldRetirementStatus::Protected, 0, vec![RetirementBlockReason::MissingPgEvidence])
    );

    // 4. Cross-artifact proof substitution MUST be rejected even when quorum-signed.
    let mut sm2 = _sm2;
    close_and_retire_at(&mut sm2, &f2, 5, 6, 7);
    let att2 = attest_snap_bytes(sm2.snapshot_bytes().unwrap(), 20, f2.history, &v2[..2]);
    let wrong_art = verifier.verify_attested_observation(&att2, &g2, &dhex("different-art"), &backend, None).unwrap();
    let cross_err = evaluate_shared_hold_retirement(
        &SharedHoldReference {
            shared_hold_key: Uuid::from_u128(9901),
            artifact_digest: sha,
            backend_identity: backend,
            groups: vec![g2],
        },
        &[wrong_art],
        &[make_cursor(f2.history, 20, 1, 7)],
        None,
    )
    .unwrap();
    assert!(cross_err.reasons.iter().any(|r| matches!(r, RetirementBlockReason::InvalidReceipt { .. })));
}

#[test]
fn multi_group_faults_and_pg_convergence() {
    let (sha, backend) = (dhex("shared-physical-pack"), dhex("s3-bucket-shared"));
    let (mut sm1, f1) = setup_published_group(6000, &sha, &backend, 10);
    let (mut sm2, f2) = setup_published_group(7000, &sha, &backend, 20);
    let (g1, g2) = (mk_binding(10, &f1), mk_binding(20, &f2));
    let (v1, v2) = (voters_for(0x31), voters_for(0x41));
    let verifier = GroupConsensusVerifier::from_test_quorums(vec![
        (10, f1.history, 2, v1.clone()),
        (20, f2.history, 2, v2.clone()),
    ]);
    let shared = SharedHoldReference {
        shared_hold_key: Uuid::from_u128(8888),
        artifact_digest: sha.clone(),
        backend_identity: backend.clone(),
        groups: vec![g1.clone(), g2.clone()],
    };

    let att1_open = attest_snap_bytes(sm1.snapshot_bytes().unwrap(), 10, f1.history, &v1[..2]);
    assert_eq!(
        verifier.verify_attested_observation(&att1_open, &g1, &sha, &backend, Some(4)).unwrap().status(),
        GroupObservationStatus::Active
    );
    assert_eq!(
        verifier.verify_attested_observation(&att1_open, &g1, &sha, &backend, Some(7)).unwrap().status(),
        GroupObservationStatus::StaleSnapshot
    );

    sm1.apply(log(5), RefCasCommand::Noop(NoopCommand { logical_tick: Some(5) })).unwrap();
    close_and_retire_at(&mut sm1, &f1, 6, 7, 10);
    let obs1 = verifier
        .verify_attested_observation(
            &attest_snap_bytes(sm1.snapshot_bytes().unwrap(), 10, f1.history, &v1[1..]),
            &g1,
            &sha,
            &backend,
            Some(1),
        )
        .unwrap();
    assert_eq!(obs1.retired_proof().unwrap().barrier_log_index(), 10);

    close_and_retire_at(&mut sm2, &f2, 5, 6, 7);
    let att2 = attest_snap_bytes(sm2.snapshot_bytes().unwrap(), 20, f2.history, &v2[..2]);
    let obs2 = verifier.verify_attested_observation(&att2, &g2, &sha, &backend, None).unwrap();
    let unreach = verifier.observe_unreachable(&g2, Some("timeout".into())).unwrap();
    let (c1, c2) = (make_cursor(f1.history, 10, 1, 10), make_cursor(f2.history, 20, 1, 7));
    let r_unreach =
        evaluate_shared_hold_retirement(&shared, &[obs1.clone(), unreach], &[c1.clone(), c2.clone()], None).unwrap();
    assert!(
        r_unreach.reasons.iter().any(|r| matches!(r, RetirementBlockReason::GroupUnreachable { group_id: 20, .. }))
    );

    let mut bad_c2 = make_cursor(f2.history, 20, 2, 6);
    bad_c2.truncation_cutoff = Some(TruncationCutoff {
        log_index: 7,
        event_seq: 9,
        log_term: 1,
        closure_digest: dhex("cut"),
        archive_uri: None,
    });
    let r_lag =
        evaluate_shared_hold_retirement(&shared, &[obs1.clone(), obs2.clone()], &[c1.clone(), bad_c2], None).unwrap();
    assert!(
        r_lag.reasons.iter().any(|r| matches!(r, RetirementBlockReason::CursorBehindRetirement { group_id: 20, .. }))
    );

    let found_holds = [&f1, &f2]
        .into_iter()
        .map(|f| PgHoldRowSummary {
            hold_id: f.hold_id,
            repository_id: f.repo,
            tenant_id: f.tenant,
            sha256: sha.clone(),
            backend_identity: backend.clone(),
            state: "active".into(),
        })
        .collect();
    let mut pg_view = PgArtifactHoldReconciliationView {
        found_holds,
        unreconciled_sibling_holds: vec![PgCrossRepoSiblingHold {
            repository_id: Uuid::from_u128(9991),
            hold_id: Uuid::from_u128(9992),
        }],
    };
    let r_sib = evaluate_shared_hold_retirement(
        &shared,
        &[obs1.clone(), obs2.clone()],
        &[c1.clone(), c2.clone()],
        Some(&pg_view),
    )
    .unwrap();
    assert!(r_sib.reasons.iter().any(|r| matches!(r, RetirementBlockReason::UnreconciledCrossRepoHold { .. })));
    pg_view.unreconciled_sibling_holds.clear();
    let r_ok = evaluate_shared_hold_retirement(&shared, &[obs1, obs2], &[c1, c2], Some(&pg_view)).unwrap();
    assert_eq!(
        (r_ok.status, r_ok.reconciled_groups, r_ok.reasons.is_empty()),
        (SharedHoldRetirementStatus::RetiredToSafeReclaim, 2, true)
    );
}
