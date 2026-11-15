//! Retention root pin/realm guards and idempotent `RetireHoldBatch` receipt tests.

use super::*;
use rootyard::ref_store::RefStoreError;

#[test]
fn register_root_rejects_released_pin_and_scope_or_realm_mismatches_and_retire_hold_idempotent() {
    use rootyard::ref_store::core::state_machine::{ReleasePinCommand, RetireHoldBatchCommand};

    let repo = Uuid::from_u128(3001);
    let tenant = Uuid::from_u128(3002);
    let owner = Uuid::from_u128(3003);
    let history = Uuid::from_u128(0x1111_2222_3333_4444_5555_6666_7777_8888);
    let mut sm = RefCasStateMachine::new();
    let gate_digest = match sm
        .apply(
            AppliedLogId { term: 1, index: 1 },
            RefCasCommand::InitializeGate(InitializeGateCommand {
                gate: WireGateInit::from(&make_init(repo, tenant, history)),
                pack_mode: SmPackMode::MetadataOnly,
                lane: RepositoryLane::ServingRefStore,
                authz_floor: 1,
            }),
        )
        .unwrap()
    {
        ApplyResponse::GateInitialized { version, .. } => version.digest().as_hex(),
        other => panic!("unexpected {other:?}"),
    };

    let snap1 = Uuid::from_u128(3101);
    let pin1 = Uuid::from_u128(3102);
    sm.apply(
        AppliedLogId { term: 1, index: 2 },
        RefCasCommand::CreateSnapshotPin(raft_sm_support_create_pin(
            repo,
            tenant,
            owner,
            history,
            snap1,
            pin1,
            gate_digest.clone(),
        )),
    )
    .unwrap();
    sm.apply(
        AppliedLogId { term: 1, index: 3 },
        RefCasCommand::ReleasePin(ReleasePinCommand {
            request_id: Uuid::from_u128(3103),
            repository_id: repo,
            tenant_id: tenant,
            owner_id: owner,
            pin_id: pin1,
            reason: "released".into(),
            logical_tick: 110,
            request_digest: digest("rel-pin1"),
        }),
    )
    .unwrap();

    let err = sm
        .apply(
            AppliedLogId { term: 1, index: 4 },
            RefCasCommand::RegisterRoot(RegisterRootCommand {
                request_id: Uuid::from_u128(3104),
                root_id: Uuid::from_u128(3105),
                operation_id: Uuid::from_u128(3106),
                repository_id: repo,
                tenant_id: tenant,
                owner_id: owner,
                purpose: "backup".into(),
                business_intent_digest: digest("bi1"),
                object_format: GitObjectFormat::Sha256,
                history_incarnation: history,
                authority_epoch: 1,
                group_epoch: 1,
                source_snapshot_id: snap1,
                source_pin_id: pin1,
                source_pin_generation: 1,
                selector_kind: "snapshot".into(),
                selector_digest: digest("sd1"),
                refs_digest: digest("rd1"),
                pack_set_digest: digest("psd1"),
                bound_hold_ids: vec![],
                register_digest: digest("reg1"),
                request_digest: digest("req1"),
            }),
        )
        .unwrap_err();
    assert_eq!(err, StateMachineError::PinReleased { pin_id: pin1 });

    // Active pin with mismatched realm rejects cleanly with RootConflict.
    let snap2 = Uuid::from_u128(3201);
    let pin2 = Uuid::from_u128(3202);
    let mut pin2_cmd = raft_sm_support_create_pin(repo, tenant, owner, history, snap2, pin2, gate_digest.clone());
    pin2_cmd.request_id = Uuid::from_u128(3203);
    pin2_cmd.request_digest = digest("snap2");
    sm.apply(AppliedLogId { term: 1, index: 4 }, RefCasCommand::CreateSnapshotPin(pin2_cmd)).unwrap();

    let err = sm
        .apply(
            AppliedLogId { term: 1, index: 5 },
            RefCasCommand::RegisterRoot(RegisterRootCommand {
                request_id: Uuid::from_u128(3204),
                root_id: Uuid::from_u128(3205),
                operation_id: Uuid::from_u128(3206),
                repository_id: repo,
                tenant_id: tenant,
                owner_id: owner,
                purpose: "backup".into(),
                business_intent_digest: digest("bi2"),
                object_format: GitObjectFormat::Sha256,
                history_incarnation: history,
                authority_epoch: 99,
                group_epoch: 1,
                source_snapshot_id: snap2,
                source_pin_id: pin2,
                source_pin_generation: 1,
                selector_kind: "snapshot".into(),
                selector_digest: digest("sd2"),
                refs_digest: digest("rd2"),
                pack_set_digest: digest("psd2"),
                bound_hold_ids: vec![],
                register_digest: digest("reg2"),
                request_digest: digest("req2"),
            }),
        )
        .unwrap_err();
    assert!(matches!(err, StateMachineError::RootConflict(_)));

    // Hold retirement idempotent replay across snapshot restore preserves retired_count and rejects DigestConflict.
    let hold_id = Uuid::from_u128(3301);
    sm.apply(
        AppliedLogId { term: 1, index: 5 },
        RefCasCommand::AcquireHoldBatch(AcquireHoldBatchCommand {
            request_id: Uuid::from_u128(3302),
            consume_request_id: Uuid::from_u128(3303),
            operation_id: Uuid::from_u128(3304),
            repository_id: repo,
            tenant_id: tenant,
            owner_id: owner,
            purpose: "ref_publication".into(),
            backend_identity: digest("back"),
            authority_id: Uuid::from_u128(3305),
            authority_generation: 1,
            expected_gate_digest: gate_digest,
            artifacts: vec![WireHoldArtifactSpec {
                hold_id,
                slot: 0,
                artifact_digest: digest("art"),
                declared_bytes: 512,
                logical_bytes: 256,
            }],
        }),
    )
    .unwrap();
    let retire_req = Uuid::from_u128(3306);
    let retire_cmd = RetireHoldBatchCommand {
        request_id: retire_req,
        repository_id: repo,
        tenant_id: tenant,
        hold_ids: vec![hold_id],
    };
    assert_eq!(
        sm.apply(AppliedLogId { term: 1, index: 6 }, RefCasCommand::RetireHoldBatch(retire_cmd.clone())).unwrap(),
        ApplyResponse::HoldsRetired { retired_count: 1 }
    );
    let snap_bytes = sm.snapshot_bytes().unwrap();
    let mut restored = RefCasStateMachine::restore_bytes(&snap_bytes).unwrap();
    assert_eq!(
        restored.apply(AppliedLogId { term: 1, index: 7 }, RefCasCommand::RetireHoldBatch(retire_cmd)).unwrap(),
        ApplyResponse::HoldsRetired { retired_count: 1 }
    );
    let conflict = restored
        .apply(
            AppliedLogId { term: 1, index: 8 },
            RefCasCommand::RetireHoldBatch(RetireHoldBatchCommand {
                request_id: retire_req,
                repository_id: repo,
                tenant_id: tenant,
                hold_ids: vec![Uuid::from_u128(9999)],
            }),
        )
        .unwrap_err();
    assert_eq!(conflict, StateMachineError::Store(RefStoreError::DigestConflict));
}

#[test]
fn mark_hold_consumed_requires_complete_batch_without_duplicates_and_replays_exact_order() {
    let repo = Uuid::from_u128(4001);
    let tenant = Uuid::from_u128(4002);
    let owner = Uuid::from_u128(4003);
    let history = Uuid::from_u128(0x1111_2222_3333_4444_5555_6666_7777_8888);
    let mut sm = RefCasStateMachine::new();
    let gate_digest = match sm
        .apply(
            AppliedLogId { term: 1, index: 1 },
            RefCasCommand::InitializeGate(InitializeGateCommand {
                gate: WireGateInit::from(&make_init(repo, tenant, history)),
                pack_mode: SmPackMode::MetadataOnly,
                lane: RepositoryLane::ServingRefStore,
                authz_floor: 1,
            }),
        )
        .unwrap()
    {
        ApplyResponse::GateInitialized { version, .. } => version.digest().as_hex(),
        other => panic!("unexpected {other:?}"),
    };

    let batch1_req = Uuid::from_u128(4101);
    let consume1 = Uuid::from_u128(4102);
    // Intentionally assign hold_a > hold_b numerically to prove slot canonical order is preserved.
    let hold_a = Uuid::from_u128(4202);
    let hold_b = Uuid::from_u128(4201);
    sm.apply(
        AppliedLogId { term: 1, index: 2 },
        RefCasCommand::AcquireHoldBatch(AcquireHoldBatchCommand {
            request_id: batch1_req,
            consume_request_id: consume1,
            operation_id: Uuid::from_u128(4103),
            repository_id: repo,
            tenant_id: tenant,
            owner_id: owner,
            purpose: "ref_publication".into(),
            backend_identity: digest("back-multi"),
            authority_id: Uuid::from_u128(4104),
            authority_generation: 1,
            expected_gate_digest: gate_digest.clone(),
            artifacts: vec![
                WireHoldArtifactSpec {
                    hold_id: hold_a,
                    slot: 0,
                    artifact_digest: digest("art-a"),
                    declared_bytes: 512,
                    logical_bytes: 256,
                },
                WireHoldArtifactSpec {
                    hold_id: hold_b,
                    slot: 1,
                    artifact_digest: digest("art-b"),
                    declared_bytes: 512,
                    logical_bytes: 256,
                },
            ],
        }),
    )
    .unwrap();

    let hold_other = Uuid::from_u128(4401);
    sm.apply(
        AppliedLogId { term: 1, index: 3 },
        RefCasCommand::AcquireHoldBatch(AcquireHoldBatchCommand {
            request_id: Uuid::from_u128(4301),
            consume_request_id: Uuid::from_u128(4302),
            operation_id: Uuid::from_u128(4303),
            repository_id: repo,
            tenant_id: tenant,
            owner_id: owner,
            purpose: "ref_publication".into(),
            backend_identity: digest("back-other"),
            authority_id: Uuid::from_u128(4304),
            authority_generation: 1,
            expected_gate_digest: gate_digest,
            artifacts: vec![WireHoldArtifactSpec {
                hold_id: hold_other,
                slot: 0,
                artifact_digest: digest("art-other"),
                declared_bytes: 256,
                logical_bytes: 128,
            }],
        }),
    )
    .unwrap();

    let consume_cmd = |hold_ids: Vec<Uuid>| {
        RefCasCommand::MarkHoldConsumed(MarkHoldConsumedCommand {
            consume_request_id: consume1,
            request_id: batch1_req,
            repository_id: repo,
            tenant_id: tenant,
            hold_ids,
        })
    };

    // Partial batch [hold_a] is rejected without burning consume_request_id or mutating hold_a.
    assert!(matches!(
        sm.apply(AppliedLogId { term: 1, index: 4 }, consume_cmd(vec![hold_a])).unwrap_err(),
        StateMachineError::InvalidInput(_)
    ));
    // Duplicate [hold_a, hold_a] and [hold_a, hold_b, hold_a] are rejected.
    assert!(matches!(
        sm.apply(AppliedLogId { term: 1, index: 4 }, consume_cmd(vec![hold_a, hold_a])).unwrap_err(),
        StateMachineError::InvalidInput(_)
    ));
    assert!(matches!(
        sm.apply(AppliedLogId { term: 1, index: 4 }, consume_cmd(vec![hold_a, hold_b, hold_a])).unwrap_err(),
        StateMachineError::InvalidInput(_)
    ));
    // Cross-batch [hold_a, hold_other] and unknown IDs are rejected.
    assert_eq!(
        sm.apply(AppliedLogId { term: 1, index: 4 }, consume_cmd(vec![hold_a, hold_other])).unwrap_err(),
        StateMachineError::HoldScopeMismatch { hold_id: hold_other }
    );
    let unknown = Uuid::from_u128(4999);
    assert_eq!(
        sm.apply(AppliedLogId { term: 1, index: 4 }, consume_cmd(vec![hold_a, unknown])).unwrap_err(),
        StateMachineError::HoldNotFound { hold_id: unknown }
    );
    assert_eq!(sm.read_hold(hold_a).unwrap().state, SmHoldState::Active);
    assert_eq!(sm.read_hold(hold_b).unwrap().state, SmHoldState::Active);

    // Complete batch with the same consume_request_id succeeds and marks both holds consumed.
    assert_eq!(
        sm.apply(AppliedLogId { term: 1, index: 4 }, consume_cmd(vec![hold_a, hold_b])).unwrap(),
        ApplyResponse::HoldsConsumed { consume_request_id: consume1, hold_count: 2, replayed: false }
    );
    assert_eq!(sm.read_hold(hold_a).unwrap().state, SmHoldState::Consumed);
    assert_eq!(sm.read_hold(hold_b).unwrap().state, SmHoldState::Consumed);

    let snap = sm.snapshot().unwrap();
    let rec = snap.body.hold_consumes.iter().find(|r| r.consume_request_id == consume1).unwrap();
    assert_eq!(rec.hold_ids, vec![hold_a, hold_b]);

    let mut restored = RefCasStateMachine::restore_bytes(&sm.snapshot_bytes().unwrap()).unwrap();
    assert_eq!(
        restored.apply(AppliedLogId { term: 1, index: 5 }, consume_cmd(vec![hold_a, hold_b])).unwrap(),
        ApplyResponse::HoldsConsumed { consume_request_id: consume1, hold_count: 2, replayed: true }
    );
    assert_eq!(
        restored.apply(AppliedLogId { term: 1, index: 6 }, consume_cmd(vec![hold_a])).unwrap_err(),
        StateMachineError::Store(RefStoreError::DigestConflict)
    );
    assert_eq!(
        restored.apply(AppliedLogId { term: 1, index: 6 }, consume_cmd(vec![hold_b, hold_a])).unwrap_err(),
        StateMachineError::Store(RefStoreError::DigestConflict)
    );
}
