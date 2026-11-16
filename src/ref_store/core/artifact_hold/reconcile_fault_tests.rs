//! Deterministic unit tests for consensus-verified shared-hold retirement proofs,
//! non-underreportable snapshot barriers, tamper rejection, and multi-group faults.

use super::bridge_contract::{
    BridgeBinding, BridgeRootRegistrationPlan, GroupHoldBinding, PgArtifactHoldReconciliationView,
    PgCrossRepoSiblingHold, PgHoldRowSummary, RetentionBridgeError, SharedHoldReference, SharedHoldRetirementStatus,
};
use super::contract::ArtifactHoldPurpose;
use super::receipt::{AcquireAck, HoldAck, HoldArtifactIdentity};
use super::reconcile_proof::{
    GroupObservationStatus, RetirementBlockReason, VerifiedGroupObservation, observe_group_retirement_from_sm,
    observe_group_retirement_from_snapshot, observe_group_retirement_from_snapshot_bytes,
    verify_group_observation_with_snapshot,
};
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

#[test]
fn untrusted_dto_and_tampered_snapshot_proofs_fail_closed() {
    let (sha, backend) = (dhex("shared-art"), dhex("s3-shared"));
    let (mut sm_open, f_open) = setup_published_group(1000, &sha, &backend, 10);
    let g_open = GroupHoldBinding {
        group_id: 10,
        history_incarnation: f_open.history,
        expected_group_epoch: 1,
        repository_id: f_open.repo,
        tenant_id: f_open.tenant,
        hold_ids: vec![f_open.hold_id],
        retire_request_id: f_open.retire_id,
    };

    // Even if an attacker serializes/forges a Closed+Retired DTO with valid unkeyed digest, verification against live Open snapshot fails closed!
    let mut forged_obs_dto =
        observe_group_retirement_from_sm(&sm_open, &g_open, &sha, &backend, None).unwrap().to_dto();
    assert_eq!(forged_obs_dto.status, GroupObservationStatus::Active);
    forged_obs_dto.status = GroupObservationStatus::Retired;
    let err = verify_group_observation_with_snapshot(
        &forged_obs_dto,
        &sm_open.snapshot().unwrap(),
        &g_open,
        &sha,
        &backend,
        None,
    )
    .unwrap_err();
    assert_eq!(err, RetentionBridgeError::UntrustedObservationProof);

    // Tampered serialized snapshot bytes (mutating last_applied without resealing SHA-256 checksum) fail integrity check.
    close_and_retire_at(&mut sm_open, &f_open, 5, 6, 10);
    let mut tampered_snap: RefCasSnapshot = serde_json::from_slice(&sm_open.snapshot_bytes().unwrap()).unwrap();
    tampered_snap.body.last_applied = Some(log(1));
    let tampered_bytes = serde_json::to_vec(&tampered_snap).unwrap();
    let snap_err =
        observe_group_retirement_from_snapshot_bytes(&tampered_bytes, &g_open, &sha, &backend, Some(1)).unwrap_err();
    assert!(matches!(snap_err, RetentionBridgeError::StateMachine(StateMachineError::SnapshotCorrupted(_))));

    // Low caller hint (Some(1)) when actual retirement barrier committed at log_index = 10 STILL yields barrier = 10;
    // lagging PG projection cursor at index = 2 MUST fail closed (Protected / CursorBehindRetirement).
    let verified =
        observe_group_retirement_from_snapshot(&sm_open.snapshot().unwrap(), &g_open, &sha, &backend, Some(1)).unwrap();
    assert_eq!(verified.retired_proof().unwrap().barrier_log_index(), 10);
    let shared = SharedHoldReference {
        shared_hold_key: Uuid::from_u128(9900),
        artifact_digest: sha.clone(),
        backend_identity: backend.clone(),
        groups: vec![g_open],
    };
    let lagging_cursor = make_cursor(f_open.history, 10, 1, 2);
    let out = evaluate_shared_hold_retirement(&shared, &[verified], &[lagging_cursor], None).unwrap();
    assert_eq!(out.status, SharedHoldRetirementStatus::Protected);
    assert!(out.reasons.iter().any(|r| matches!(
        r,
        RetirementBlockReason::CursorBehindRetirement { group_id: 10, applied_log_index: 2, retirement_log_index: 10 }
    )));

    // Cross-artifact proof substitution MUST be rejected.
    let (_sm_other, f_other) = setup_published_group(2000, &dhex("different-art"), &backend, 10);
    let g_other = GroupHoldBinding {
        group_id: 10,
        history_incarnation: f_other.history,
        expected_group_epoch: 1,
        repository_id: f_other.repo,
        tenant_id: f_other.tenant,
        hold_ids: vec![f_other.hold_id],
        retire_request_id: f_other.retire_id,
    };
    let mut sm_other_retired = _sm_other;
    close_and_retire_at(&mut sm_other_retired, &f_other, 5, 6, 7);
    let wrong_proof =
        observe_group_retirement_from_sm(&sm_other_retired, &g_other, &dhex("different-art"), &backend, None).unwrap();
    let cross_err = evaluate_shared_hold_retirement(
        &SharedHoldReference {
            shared_hold_key: Uuid::from_u128(9901),
            artifact_digest: sha,
            backend_identity: backend,
            groups: vec![g_other],
        },
        &[wrong_proof],
        &[make_cursor(f_other.history, 10, 1, 7)],
        None,
    )
    .unwrap();
    assert_eq!(cross_err.status, SharedHoldRetirementStatus::Protected);
    assert!(cross_err.reasons.iter().any(|r| matches!(r, RetirementBlockReason::InvalidReceipt { .. })));
}

#[test]
fn multi_group_retirement_fails_closed_across_faults_and_converges_safely() {
    let (sha, backend) = (dhex("shared-physical-pack"), dhex("s3-bucket-shared"));
    let (mut sm1, f1) = setup_published_group(6000, &sha, &backend, 10);
    let (mut sm2, f2) = setup_published_group(7000, &sha, &backend, 20);
    let g1 = GroupHoldBinding {
        group_id: 10,
        history_incarnation: f1.history,
        expected_group_epoch: 1,
        repository_id: f1.repo,
        tenant_id: f1.tenant,
        hold_ids: vec![f1.hold_id],
        retire_request_id: f1.retire_id,
    };
    let g2 = GroupHoldBinding {
        group_id: 20,
        history_incarnation: f2.history,
        expected_group_epoch: 1,
        repository_id: f2.repo,
        tenant_id: f2.tenant,
        hold_ids: vec![f2.hold_id],
        retire_request_id: f2.retire_id,
    };
    let shared = SharedHoldReference {
        shared_hold_key: Uuid::from_u128(8888),
        artifact_digest: sha.clone(),
        backend_identity: backend.clone(),
        groups: vec![g1.clone(), g2.clone()],
    };

    assert_eq!(
        observe_group_retirement_from_sm(&sm1, &g1, &sha, &backend, Some(4)).unwrap().status(),
        GroupObservationStatus::Active
    );
    assert_eq!(
        observe_group_retirement_from_sm(&sm1, &g1, &sha, &backend, Some(7)).unwrap().status(),
        GroupObservationStatus::StaleSnapshot
    );

    // Advance group 1 to log 10 via no-ops + retire so barrier = 10.
    sm1.apply(log(5), RefCasCommand::Noop(NoopCommand { logical_tick: Some(5) })).unwrap();
    close_and_retire_at(&mut sm1, &f1, 6, 7, 10);
    let obs1 = observe_group_retirement_from_sm(&sm1, &g1, &sha, &backend, Some(1)).unwrap();
    assert_eq!(obs1.retired_proof().unwrap().barrier_log_index(), 10);

    // Group 2 still active -> Protected despite Group 1 retirement.
    let obs2_active = observe_group_retirement_from_sm(&sm2, &g2, &sha, &backend, None).unwrap();
    let res = evaluate_shared_hold_retirement(
        &shared,
        &[obs1.clone(), obs2_active],
        &[make_cursor(f1.history, 10, 1, 10), make_cursor(f2.history, 20, 1, 7)],
        None,
    )
    .unwrap();
    assert_eq!(res.status, SharedHoldRetirementStatus::Protected);
    assert!(res.reasons.iter().any(|r| matches!(r, RetirementBlockReason::GroupStillActive { group_id: 20, .. })));

    close_and_retire_at(&mut sm2, &f2, 5, 6, 7);
    let obs2 = observe_group_retirement_from_sm(&sm2, &g2, &sha, &backend, None).unwrap();
    assert_eq!(obs2.status(), GroupObservationStatus::Retired);
    assert_eq!(
        observe_group_retirement_from_sm(&sm2, &g2, &sha, &backend, Some(9)).unwrap().status(),
        GroupObservationStatus::StaleSnapshot
    );

    let unreach = VerifiedGroupObservation::unreachable(20, f2.repo, Some("timeout".into()));
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
        closure_digest: dhex("cutoff"),
        archive_uri: None,
    });
    let r_lag =
        evaluate_shared_hold_retirement(&shared, &[obs1.clone(), obs2.clone()], &[c1.clone(), bad_c2], None).unwrap();
    assert!(r_lag.reasons.iter().any(|r| matches!(r, RetirementBlockReason::CursorEpochMismatch { group_id: 20, .. })));
    assert!(
        r_lag.reasons.iter().any(|r| matches!(r, RetirementBlockReason::CursorBehindRetirement { group_id: 20, .. }))
    );
    assert!(
        r_lag.reasons.iter().any(|r| matches!(r, RetirementBlockReason::CursorResyncRequired { group_id: 20, .. }))
    );

    let mut pg_view = PgArtifactHoldReconciliationView {
        found_holds: vec![
            PgHoldRowSummary {
                hold_id: f1.hold_id,
                repository_id: f1.repo,
                tenant_id: f1.tenant,
                sha256: sha.clone(),
                backend_identity: backend.clone(),
                state: "active".into(),
            },
            PgHoldRowSummary {
                hold_id: f2.hold_id,
                repository_id: f2.repo,
                tenant_id: f2.tenant,
                sha256: sha,
                backend_identity: backend,
                state: "active".into(),
            },
        ],
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
