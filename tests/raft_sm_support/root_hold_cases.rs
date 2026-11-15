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
