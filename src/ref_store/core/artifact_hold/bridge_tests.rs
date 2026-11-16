//! Deterministic unit tests for the PG <-> Ref-CAS reserve-before-publish bridge,
//! opaque reservation boundaries, lost-ACK snapshot replay, cancel/release-before-register,
//! anti-ABA generation/epoch fencing, closing barriers, and non-refunding quotas.

use super::bridge_contract::{
    BridgeBinding, BridgeRootRegistrationPlan, GlobalHoldReservationDto, RetentionBridgeError,
};
use super::contract::ArtifactHoldPurpose;
use super::receipt::{AcquireAck, HoldAck, HoldArtifactIdentity};
use super::reconcile_proof::{GroupObservationStatus, GroupRetirementObservationDto};
use super::retention_bridge::{
    VerifiedGlobalHoldReservation, apply_release_root_idempotent, apply_reserved_hold_to_sm,
    apply_retire_hold_batch_idempotent, begin_operation_for_binding, publish_pin_and_root_after_hold,
    read_sm_quota_counters, verify_state_machine_gate_for_binding,
};
use crate::ref_store::GitObjectFormat;
use crate::ref_store::contract::{MetadataPinPurpose, RequestDigest};
use crate::ref_store::core::state_machine::{
    AdvanceCancelCutoffCommand, AppliedLogId, ApplyResponse, CancelCommand, InitializeGateCommand, RefCasCommand,
    RefCasStateMachine, ReleaseRootCommand, RepositoryLane, RetireHoldBatchCommand, ScopeLifecycle,
    SetRepositoryLaneCommand, SmPackMode, StateMachineError, WireGateInit,
};
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

struct TestGroupFixture {
    repo: Uuid,
    tenant: Uuid,
    owner: Uuid,
    history: Uuid,
    issuer_id: Uuid,
    operation_id: Uuid,
    hold_id: Uuid,
    binding: BridgeBinding,
    reservation: VerifiedGlobalHoldReservation,
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
    let reservation = VerifiedGlobalHoldReservation::mint_for_unit_test(binding.clone(), ack);
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
        matches!(err, RetentionBridgeError::MissingDurableHold { request_id } if request_id == f.reservation.ack().request_id)
    );
    let (repo_q, tenant_q) = read_sm_quota_counters(&sm, f.repo, f.tenant).unwrap();
    assert_eq!((repo_q.holds, repo_q.snapshots, repo_q.roots, tenant_q.holds), (0, 0, 0, 0));

    // Strict serde: reject unexpected fields on untrusted DTOs.
    deny_unknown(&f.binding);
    deny_unknown(&f.plan);
    deny_unknown(&f.reservation.to_dto());
    let sample_obs_dto = GroupRetirementObservationDto {
        group_id: 10,
        repository_id: f.repo,
        status: GroupObservationStatus::Active,
        receipt: None,
        observed_log_index: Some(1),
        detail: None,
    };
    deny_unknown(&sample_obs_dto);
    assert!(serde_json::from_str::<GlobalHoldReservationDto>("{}").is_err());
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
        wrong_backend.matches_acquire_ack(f3.reservation.ack()).unwrap_err(),
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
