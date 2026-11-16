//! Deterministic unit tests for the PG <-> Ref-CAS retention bridge, replay,
//! cancel/release-before-register, anti-ABA fencing, closing barriers, and multi-group retirement.

use super::bridge_contract::{
    BridgeBinding, GlobalHoldReservation, GroupHoldBinding, PgArtifactHoldReconciliationView, PgCrossRepoSiblingHold,
    PgHoldRowSummary, SharedHoldReference, SharedHoldRetirementStatus,
};
use super::contract::ArtifactHoldPurpose;
use super::receipt::{AcquireAck, HoldAck, HoldArtifactIdentity};
use super::retention_bridge::{
    BridgeRootRegistrationPlan, RetentionBridgeError, apply_release_root_idempotent, apply_reserved_hold_to_sm,
    apply_retire_hold_batch_idempotent, begin_operation_for_binding, publish_pin_and_root_after_hold,
    read_sm_quota_counters, verify_state_machine_gate_for_binding,
};
use super::retirement_reconcile::{
    GroupObservationStatus, GroupRetirementObservation, RetirementBlockReason, evaluate_shared_hold_retirement,
    observe_group_retirement_from_sm,
};
use crate::ref_store::GitObjectFormat;
use crate::ref_store::contract::{MetadataPinPurpose, RequestDigest};
use crate::ref_store::core::state_machine::{
    AdvanceCancelCutoffCommand, AppliedLogId, ApplyResponse, CancelCommand, InitializeGateCommand, RefCasCommand,
    RefCasStateMachine, ReleaseRootCommand, RepositoryLane, RetireHoldBatchCommand, ScopeLifecycle,
    SetRepositoryLaneCommand, SmPackMode, StateMachineError, WireGateInit,
};
use crate::ref_store::projector::{ProjectionCursor, ProjectionRealm, TruncationCutoff};
use uuid::Uuid;

fn dhex(label: &str) -> String {
    RequestDigest::of("retention-bridge-unit-test", &[label.as_bytes()]).as_hex()
}

fn log(index: u64) -> AppliedLogId {
    AppliedLogId { term: 1, index }
}

fn lane_cmd(f: &TestGroupFixture, lifecycle: ScopeLifecycle, authority_epoch: i64) -> RefCasCommand {
    RefCasCommand::SetRepositoryLane(SetRepositoryLaneCommand {
        repository_id: f.repo,
        tenant_id: f.tenant,
        lane: RepositoryLane::ServingRefStore,
        lifecycle,
        authz_floor: 1,
        history_incarnation: f.history,
        authority_epoch,
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

fn grp(f: &TestGroupFixture, group_id: i64, retire_request_id: Uuid) -> GroupHoldBinding {
    GroupHoldBinding {
        group_id,
        history_incarnation: f.history,
        expected_group_epoch: 1,
        repository_id: f.repo,
        tenant_id: f.tenant,
        hold_ids: vec![f.hold_id],
        retire_request_id,
    }
}

fn pg_row(f: &TestGroupFixture, sha: &str, backend: &str) -> PgHoldRowSummary {
    PgHoldRowSummary {
        hold_id: f.hold_id,
        repository_id: f.repo,
        tenant_id: f.tenant,
        sha256: sha.to_owned(),
        backend_identity: backend.to_owned(),
        state: "active".into(),
    }
}

fn rel_cmd(f: &TestGroupFixture, request_id: Uuid, label: &str) -> ReleaseRootCommand {
    ReleaseRootCommand {
        request_id,
        root_id: f.plan.root_id,
        repository_id: f.repo,
        tenant_id: f.tenant,
        owner_id: f.owner,
        expected_register_digest: f.plan.register_digest.clone(),
        intent_digest: dhex(label),
    }
}

fn deny_unknown<T: serde::Serialize + serde::de::DeserializeOwned>(val: &T) {
    let mut v = serde_json::to_value(val).unwrap();
    v.as_object_mut().unwrap().insert("evil".into(), serde_json::json!(true));
    assert!(serde_json::from_value::<T>(v).is_err());
}

fn close_and_retire(sm: &mut RefCasStateMachine, f: &TestGroupFixture, release_id: Uuid, retire_id: Uuid) {
    apply_release_root_idempotent(sm, log(5), rel_cmd(f, release_id, "done")).unwrap();
    sm.apply(log(6), lane_cmd(f, ScopeLifecycle::Closing, 1)).unwrap();
    apply_retire_hold_batch_idempotent(
        sm,
        log(7),
        RetireHoldBatchCommand {
            request_id: retire_id,
            repository_id: f.repo,
            tenant_id: f.tenant,
            hold_ids: vec![f.hold_id],
        },
    )
    .unwrap();
}

struct TestGroupFixture {
    repo: Uuid,
    tenant: Uuid,
    owner: Uuid,
    history: Uuid,
    issuer_id: Uuid,
    operation_id: Uuid,
    hold_id: Uuid,
    binding: BridgeBinding,
    reservation: GlobalHoldReservation,
    plan: BridgeRootRegistrationPlan,
}

fn setup_group(seed: u128, group_id: i64, sha256: &str, backend: &str) -> (RefCasStateMachine, TestGroupFixture) {
    let id = |n: u128| Uuid::from_u128(seed + n);
    let (repository_id, tenant_id, owner_id, history_incarnation, authority_id) = (id(1), id(2), id(3), id(4), id(5));
    let (issuer_id, operation_id, hold_id, request_id) = (id(6), id(7), id(8), id(9));
    let (authority_generation, authority_epoch, group_epoch, sequence) = (1, 1, 1, 10);
    let (lane, object_format, purpose, shard) =
        ("push".to_owned(), GitObjectFormat::Sha256, ArtifactHoldPurpose::RefPublication, 0);
    let (backend_identity, operation_digest, declared_bytes, logical_bytes) =
        (backend.to_owned(), dhex(&format!("op-{seed}")), 4096, 4608);
    let mut sm = RefCasStateMachine::new();
    let gate = WireGateInit {
        repository_id,
        tenant_id,
        object_format,
        history_incarnation,
        authority_epoch,
        group_epoch,
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
    let gate_digest = version.digest().as_hex();
    let binding = BridgeBinding {
        tenant_id,
        repository_id,
        owner_id,
        authority_id,
        authority_generation,
        authority_epoch,
        backend_identity: backend_identity.clone(),
        history_incarnation,
        group_id,
        group_epoch,
        issuer_id,
        lane: lane.clone(),
        sequence,
        operation_id,
        operation_digest: operation_digest.clone(),
    };
    let artifact = HoldArtifactIdentity {
        provider: "s3".into(),
        backend_identity: backend_identity.clone(),
        tenant_id,
        authority_id,
        authority_generation,
        attempt_id: id(11),
        namespace: "pack".into(),
        sha256: sha256.to_owned(),
        length: 4096,
    };
    let ack = AcquireAck {
        request_id,
        request_digest: dhex(&format!("req-{seed}")),
        repository_id,
        tenant_id,
        owner_id,
        purpose,
        object_format,
        history_incarnation,
        authority_epoch,
        group_epoch,
        issuer_id,
        lane,
        sequence,
        operation_id,
        operation_digest,
        gate_revision: 1,
        gate_digest,
        shard,
        backend_identity,
        consume_request_id: id(10),
        declared_bytes,
        logical_bytes,
        artifacts: vec![HoldAck { hold_id, slot: 0, artifact, declared_bytes, logical_bytes }],
    };
    let reservation =
        GlobalHoldReservation { binding: binding.clone(), ack, replayed: false, recovered_from_unknown_commit: false };
    let plan = BridgeRootRegistrationPlan {
        pin_request_id: id(12),
        snapshot_id: id(13),
        pin_id: id(14),
        pin_purpose: MetadataPinPurpose::Backup,
        lease_ticks: 50,
        pin_logical_tick: 10,
        pack_digests: vec![],
        pin_request_digest: dhex(&format!("pin-req-{seed}")),
        root_request_id: id(15),
        root_id: id(16),
        root_purpose: "backup".into(),
        business_intent_digest: dhex(&format!("bi-{seed}")),
        selector_kind: "snapshot".into(),
        selector_digest: dhex(&format!("sel-{seed}")),
        refs_digest: dhex(&format!("refs-{seed}")),
        pack_set_digest: dhex(&format!("packs-{seed}")),
        register_digest: dhex(&format!("reg-{seed}")),
        root_request_digest: dhex(&format!("root-req-{seed}")),
    };
    let fx = TestGroupFixture {
        repo: repository_id,
        tenant: tenant_id,
        owner: owner_id,
        history: history_incarnation,
        issuer_id,
        operation_id,
        hold_id,
        binding,
        reservation,
        plan,
    };
    (sm, fx)
}

#[test]
fn reserve_before_publish_refuses_missing_hold_and_denies_unknown_json_fields() {
    let (sha, backend) = (dhex("shared-pack"), dhex("s3-bucket-a"));
    let (mut sm, f) = setup_group(1000, 10, &sha, &backend);

    // Must fail closed before ApplyReservedHold inserts durable hold into SM.
    let err =
        publish_pin_and_root_after_hold(&mut sm, log(2), log(3), &f.reservation, &f.binding, &f.plan).unwrap_err();
    assert!(
        matches!(err, RetentionBridgeError::MissingDurableHold { request_id } if request_id == f.reservation.ack.request_id)
    );
    let (repo_q, tenant_q) = read_sm_quota_counters(&sm, f.repo, f.tenant).unwrap();
    assert_eq!((repo_q.holds, repo_q.snapshots, repo_q.roots, tenant_q.holds), (0, 0, 0, 0));

    // Strict serde: reject unexpected fields on DTOs.
    deny_unknown(&f.binding);
    deny_unknown(&f.plan);
    deny_unknown(&f.reservation);
}

#[test]
fn lost_ack_replay_snapshot_restore_and_non_refunding_quotas_hold() {
    let (sha, backend) = (dhex("shared-pack"), dhex("s3-bucket-a"));
    let (mut sm, f) = setup_group(2000, 10, &sha, &backend);

    apply_reserved_hold_to_sm(&mut sm, log(2), &f.reservation, &f.binding).unwrap();
    begin_operation_for_binding(&mut sm, log(3), &f.binding, 5).unwrap();
    publish_pin_and_root_after_hold(&mut sm, log(4), log(5), &f.reservation, &f.binding, &f.plan).unwrap();
    let mut body_before = sm.snapshot().unwrap().body;

    let (q_before, _) = read_sm_quota_counters(&sm, f.repo, f.tenant).unwrap();
    assert_eq!((q_before.holds, q_before.hold_receipts, q_before.snapshots, q_before.roots), (1, 1, 1, 1));

    // Persist snapshot, restore into fresh SM replica, and replay hold + op + pin + root.
    let snap_bytes = sm.snapshot_bytes().unwrap();
    let mut restored = RefCasStateMachine::restore_bytes(&snap_bytes).unwrap();
    apply_reserved_hold_to_sm(&mut restored, log(6), &f.reservation, &f.binding).unwrap();
    begin_operation_for_binding(&mut restored, log(7), &f.binding, 5).unwrap();
    publish_pin_and_root_after_hold(&mut restored, log(8), log(9), &f.reservation, &f.binding, &f.plan).unwrap();

    let (q_replay, t_replay) = read_sm_quota_counters(&restored, f.repo, f.tenant).unwrap();
    assert_eq!((q_replay, t_replay), (q_before, q_before));
    let body_after = restored.snapshot().unwrap().body;
    body_before.last_applied = body_after.last_applied;
    assert_eq!(body_after, body_before);

    // Retire blocked while root is Active; after root release, release + retire replay idempotently.
    let ret_cmd = RetireHoldBatchCommand {
        request_id: Uuid::from_u128(2999),
        repository_id: f.repo,
        tenant_id: f.tenant,
        hold_ids: vec![f.hold_id],
    };
    let blocked = apply_retire_hold_batch_idempotent(&mut restored, log(10), ret_cmd.clone()).unwrap_err();
    assert!(matches!(
        blocked,
        RetentionBridgeError::StateMachine(StateMachineError::HoldProtectedByRoot { hold_id, root_id })
            if hold_id == f.hold_id && root_id == f.plan.root_id
    ));

    let rel = rel_cmd(&f, Uuid::from_u128(2998), "rel-intent");
    apply_release_root_idempotent(&mut restored, log(10), rel.clone()).unwrap();
    apply_release_root_idempotent(&mut restored, log(11), rel).unwrap();
    apply_retire_hold_batch_idempotent(&mut restored, log(12), ret_cmd.clone()).unwrap();
    apply_retire_hold_batch_idempotent(&mut restored, log(13), ret_cmd).unwrap();

    // Quotas remain strictly non-refundable after release and retirement.
    let (q_final, _) = read_sm_quota_counters(&restored, f.repo, f.tenant).unwrap();
    assert_eq!(
        (q_final.holds, q_final.hold_declared_bytes, q_final.roots, q_final.root_receipts),
        (q_before.holds, q_before.hold_declared_bytes, q_before.roots, 2)
    );
}

#[test]
fn cancel_and_release_before_register_anti_aba_and_closing_barrier_fence() {
    let (sha, backend) = (dhex("shared-pack"), dhex("s3-bucket-a"));
    let (mut sm, f) = setup_group(3000, 10, &sha, &backend);

    // 1. Cancel-before-Register fences apply_reserved_hold_to_sm & publish.
    sm.apply(
        log(2),
        RefCasCommand::Cancel(CancelCommand {
            identity: f.binding.to_wire_operation_identity(),
            reason: Some("aborted".into()),
            logical_tick: 1,
        }),
    )
    .unwrap();
    let err = apply_reserved_hold_to_sm(&mut sm, log(3), &f.reservation, &f.binding).unwrap_err();
    assert!(
        matches!(err, RetentionBridgeError::CancelledBeforeRegister { operation_id } if operation_id == f.operation_id)
    );

    // 2. Monotonic cancel_cutoff & Release-before-Register tombstones fence late publish.
    let (mut sm2, f2) = setup_group(4000, 10, &sha, &backend);
    apply_reserved_hold_to_sm(&mut sm2, log(2), &f2.reservation, &f2.binding).unwrap();
    apply_release_root_idempotent(&mut sm2, log(3), rel_cmd(&f2, Uuid::from_u128(4997), "rel-before-reg")).unwrap();
    let rel_err =
        publish_pin_and_root_after_hold(&mut sm2, log(4), log(5), &f2.reservation, &f2.binding, &f2.plan).unwrap_err();
    assert!(
        matches!(rel_err, RetentionBridgeError::StateMachine(StateMachineError::RootReleased { root_id }) if root_id == f2.plan.root_id)
    );
    sm2.apply(
        log(6),
        RefCasCommand::AdvanceCancelCutoff(AdvanceCancelCutoffCommand {
            repository_id: f2.repo,
            issuer_id: f2.issuer_id,
            lane: "push".into(),
            cutoff_sequence: 10,
            prune_tombstones_up_to_cutoff: false,
        }),
    )
    .unwrap();
    assert!(matches!(
        verify_state_machine_gate_for_binding(&sm2, &f2.binding).unwrap_err(),
        RetentionBridgeError::CancelledBeforeRegister { .. }
    ));

    // 3. Anti-ABA generation/epoch bump + Closing barrier refusal (cannot reopen).
    let (mut sm3, mut f3) = setup_group(5000, 10, &sha, &backend);
    let mut wrong_backend = f3.binding.clone();
    wrong_backend.backend_identity = dhex("other-bucket");
    assert_eq!(
        wrong_backend.matches_acquire_ack(&f3.reservation.ack).unwrap_err(),
        RetentionBridgeError::BackendMismatch
    );
    sm3.apply(log(2), lane_cmd(&f3, ScopeLifecycle::Open, 2)).unwrap();
    assert!(matches!(
        verify_state_machine_gate_for_binding(&sm3, &f3.binding).unwrap_err(),
        RetentionBridgeError::GenerationConflict { field: "authority_epoch", expected: 2, actual: 1 }
    ));

    sm3.apply(log(3), lane_cmd(&f3, ScopeLifecycle::Closing, 2)).unwrap();
    assert!(sm3.apply(log(4), lane_cmd(&f3, ScopeLifecycle::Open, 2)).is_err());
    f3.binding.authority_epoch = 2;
    assert!(matches!(
        verify_state_machine_gate_for_binding(&sm3, &f3.binding).unwrap_err(),
        RetentionBridgeError::ScopeClosingOrClosed { lifecycle: ScopeLifecycle::Closing, .. }
    ));
}

#[test]
fn multi_group_retirement_fails_closed_across_faults_and_converges_safely() {
    let (sha, backend) = (dhex("shared-physical-pack"), dhex("s3-bucket-shared"));
    let (mut sm1, f1) = setup_group(6000, 10, &sha, &backend);
    let (mut sm2, f2) = setup_group(7000, 20, &sha, &backend);
    for (sm, f) in [(&mut sm1, &f1), (&mut sm2, &f2)] {
        apply_reserved_hold_to_sm(sm, log(2), &f.reservation, &f.binding).unwrap();
        publish_pin_and_root_after_hold(sm, log(3), log(4), &f.reservation, &f.binding, &f.plan).unwrap();
    }
    let (retire1, retire2) = (Uuid::from_u128(6999), Uuid::from_u128(7999));
    let (g1, g2) = (grp(&f1, 10, retire1), grp(&f2, 20, retire2));
    let shared = SharedHoldReference {
        shared_hold_key: Uuid::from_u128(8888),
        artifact_digest: sha.clone(),
        backend_identity: backend.clone(),
        groups: vec![g1.clone(), g2.clone()],
    };
    let st_open = observe_group_retirement_from_sm(&sm1, &g1, &sha, &backend, 4).unwrap().status;
    let st_stale = observe_group_retirement_from_sm(&sm1, &g1, &sha, &backend, 7).unwrap().status;
    assert_eq!((st_open, st_stale), (GroupObservationStatus::Active, GroupObservationStatus::StaleSnapshot));

    close_and_retire(&mut sm1, &f1, Uuid::from_u128(6998), retire1);
    let obs1 = observe_group_retirement_from_sm(&sm1, &g1, &sha, &backend, 7).unwrap();
    assert_eq!(obs1.status, GroupObservationStatus::Retired);
    let (c1, c2) = (make_cursor(f1.history, 10, 1, 7), make_cursor(f2.history, 20, 1, 7));

    // Group 2 still active -> Protected despite Group 1 deletion.
    let obs2_active = observe_group_retirement_from_sm(&sm2, &g2, &sha, &backend, 4).unwrap();
    let res = evaluate_shared_hold_retirement(&shared, &[obs1.clone(), obs2_active], &[c1.clone(), c2.clone()], None)
        .unwrap();
    assert_eq!(res.status, SharedHoldRetirementStatus::Protected);
    assert!(res.reasons.iter().any(|r| matches!(r, RetirementBlockReason::GroupStillActive { group_id: 20, .. })));

    close_and_retire(&mut sm2, &f2, Uuid::from_u128(7998), retire2);
    let obs2 = observe_group_retirement_from_sm(&sm2, &g2, &sha, &backend, 7).unwrap();
    assert_eq!(obs2.status, GroupObservationStatus::Retired);
    assert_eq!(
        observe_group_retirement_from_sm(&sm2, &g2, &sha, &backend, 9).unwrap().status,
        GroupObservationStatus::StaleSnapshot
    );

    let chk = |obs: &[GroupRetirementObservation],
               cur: &[ProjectionCursor],
               pg: Option<&PgArtifactHoldReconciliationView>| {
        evaluate_shared_hold_retirement(&shared, obs, cur, pg).unwrap()
    };

    // Tampered receipt, unreachable peer, epoch mismatch, resync/lagging cursor, and cross-repo sibling hold.
    let mut bad_obs = obs2.clone();
    bad_obs.receipt.as_mut().unwrap().receipt_digest = dhex("forged");
    assert!(
        chk(&[obs1.clone(), bad_obs.clone()], &[c1.clone(), c2.clone()], None)
            .reasons
            .iter()
            .any(|r| matches!(r, RetirementBlockReason::InvalidReceipt { group_id: 20, .. }))
    );

    bad_obs.status = GroupObservationStatus::Unreachable;
    bad_obs.receipt = None;
    assert!(
        chk(&[obs1.clone(), bad_obs], &[c1.clone(), c2.clone()], None)
            .reasons
            .iter()
            .any(|r| matches!(r, RetirementBlockReason::GroupUnreachable { group_id: 20, .. }))
    );

    let mut bad_c2 = make_cursor(f2.history, 20, 2, 6);
    bad_c2.truncation_cutoff = Some(TruncationCutoff {
        log_index: 7,
        event_seq: 9,
        log_term: 1,
        closure_digest: dhex("cutoff"),
        archive_uri: None,
    });
    let r_lag = chk(&[obs1.clone(), obs2.clone()], &[c1.clone(), bad_c2], None).reasons;
    assert!(r_lag.iter().any(|r| matches!(r, RetirementBlockReason::CursorEpochMismatch { group_id: 20, .. })));
    assert!(r_lag.iter().any(|r| matches!(r, RetirementBlockReason::CursorBehindRetirement { group_id: 20, .. })));
    assert!(r_lag.iter().any(|r| matches!(r, RetirementBlockReason::CursorResyncRequired { group_id: 20, .. })));

    let mut pg_view = PgArtifactHoldReconciliationView {
        found_holds: vec![pg_row(&f1, &sha, &backend), pg_row(&f2, &sha, &backend)],
        unreconciled_sibling_holds: vec![PgCrossRepoSiblingHold {
            repository_id: Uuid::from_u128(9991),
            hold_id: Uuid::from_u128(9992),
        }],
    };
    assert!(
        chk(&[obs1.clone(), obs2.clone()], &[c1.clone(), c2.clone()], Some(&pg_view))
            .reasons
            .iter()
            .any(|r| matches!(r, RetirementBlockReason::UnreconciledCrossRepoHold { .. }))
    );

    pg_view.unreconciled_sibling_holds.clear();
    let r_ok = chk(&[obs1, obs2], &[c1, c2], Some(&pg_view));
    assert_eq!(
        (r_ok.status, r_ok.reconciled_groups, r_ok.reasons.is_empty()),
        (SharedHoldRetirementStatus::RetiredToSafeReclaim, 2, true)
    );
}
