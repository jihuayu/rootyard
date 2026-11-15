//! Snapshot sealing, strict `#[serde(deny_unknown_fields)]`, `cancel_cutoff`,
//! pins, retention roots, and artifact holds deterministic recovery tests.

use super::*;
use rootyard::ref_store::core::state_machine::{
    AcquireHoldBatchCommand, AdvanceCancelCutoffCommand, AppliedLogId, ApplyResponse, CancelCommand, CommitRefsCommand,
    CreateSnapshotPinCommand, InitializeGateCommand, RefCasCommand, RefCasSnapshot, RefCasStateMachine,
    RegisterRootCommand, ReleasePinCommand, ReleaseRootCommand, RenewPinCommand, RepositoryLane,
    RetireHoldBatchCommand, SmHoldState, SmPackMode, SmPinState, SmRootState, StateMachineError, WireCommitRefsRequest,
    WireGateInit, WireHoldArtifactSpec, WireOperationIdentity, decode_command,
};
use rootyard::ref_store::{
    CommitMode, GitObjectFormat, HeadUpdate, MetadataPinPurpose, OperationIdentity, RequestDigest,
};
use std::collections::BTreeMap;
use uuid::Uuid;

#[test]
fn snapshot_seal_deny_unknown_fields_and_cancel_cutoff_pins_roots_holds_recovery() {
    let repo = Uuid::from_u128(11);
    let tenant = Uuid::from_u128(21);
    let issuer = Uuid::from_u128(31);
    let owner = Uuid::from_u128(41);
    let history = Uuid::from_u128(0xaaaa_bbbb_cccc_dddd_eeee_ffff_0000_1111);
    let mut sm = RefCasStateMachine::new();

    let init = make_init(repo, tenant, history);
    let version = match sm
        .apply(
            AppliedLogId { term: 1, index: 1 },
            RefCasCommand::InitializeGate(InitializeGateCommand {
                gate: WireGateInit::from(&init),
                pack_mode: SmPackMode::MetadataOnly,
                lane: RepositoryLane::PgRefstore,
                authz_floor: 2,
            }),
        )
        .unwrap()
    {
        ApplyResponse::GateInitialized { version, .. } => version,
        other => panic!("unexpected {other:?}"),
    };

    // Cancel seq 5 before register, then advance cancel_cutoff to 10 pruning tombstones.
    let op5 = Uuid::from_u128(505);
    let id5 = OperationIdentity::new(repo, issuer, lane(), 5, op5, RequestDigest::of("op5", &[b"5"])).unwrap();
    let res = sm
        .apply(
            AppliedLogId { term: 1, index: 2 },
            RefCasCommand::Cancel(CancelCommand {
                identity: WireOperationIdentity::from(&id5),
                reason: Some("early".into()),
                logical_tick: 10,
            }),
        )
        .unwrap();
    assert!(matches!(res, ApplyResponse::OperationCancelled { receipt, .. } if receipt.tombstone_created));
    assert!(sm.has_cancel_tombstone(repo, op5));

    let res = sm
        .apply(
            AppliedLogId { term: 1, index: 3 },
            RefCasCommand::AdvanceCancelCutoff(AdvanceCancelCutoffCommand {
                repository_id: repo,
                issuer_id: issuer,
                lane: lane().as_str().to_owned(),
                cutoff_sequence: 10,
                prune_tombstones_up_to_cutoff: true,
            }),
        )
        .unwrap();
    assert_eq!(res, ApplyResponse::CancelCutoffAdvanced { cutoff_sequence: 10, pruned_tombstones: 1 });
    assert!(!sm.has_cancel_tombstone(repo, op5));

    // Create + renew pin, acquire hold, register root binding that hold.
    let snap_id = Uuid::from_u128(601);
    let pin_id = Uuid::from_u128(602);
    let hold_id = Uuid::from_u128(603);
    let root_id = Uuid::from_u128(604);
    let hold_req = Uuid::from_u128(605);
    sm.apply(
        AppliedLogId { term: 1, index: 4 },
        RefCasCommand::CreateSnapshotPin(CreateSnapshotPinCommand {
            request_id: Uuid::from_u128(606),
            repository_id: repo,
            tenant_id: tenant,
            owner_id: owner,
            purpose: MetadataPinPurpose::Backup,
            snapshot_id: snap_id,
            pin_id,
            object_format: GitObjectFormat::Sha256,
            history_incarnation: history,
            authority_epoch: 1,
            group_epoch: 1,
            expected_gate_digest: version.digest().as_hex(),
            lease_ticks: 20,
            logical_tick: 20,
            pack_digests: vec![],
            request_digest: digest("create-pin"),
        }),
    )
    .unwrap();
    sm.apply(
        AppliedLogId { term: 1, index: 5 },
        RefCasCommand::RenewPin(RenewPinCommand {
            request_id: Uuid::from_u128(607),
            repository_id: repo,
            tenant_id: tenant,
            owner_id: owner,
            pin_id,
            expected_generation: 1,
            lease_ticks: 30,
            logical_tick: 25,
            request_digest: digest("renew-pin"),
        }),
    )
    .unwrap();
    sm.apply(
        AppliedLogId { term: 1, index: 6 },
        RefCasCommand::AcquireHoldBatch(AcquireHoldBatchCommand {
            request_id: hold_req,
            consume_request_id: Uuid::from_u128(608),
            operation_id: Uuid::from_u128(609),
            repository_id: repo,
            tenant_id: tenant,
            owner_id: owner,
            purpose: "ref_publication".into(),
            backend_identity: digest("back"),
            authority_id: Uuid::from_u128(610),
            authority_generation: 1,
            expected_gate_digest: version.digest().as_hex(),
            artifacts: vec![WireHoldArtifactSpec {
                hold_id,
                slot: 0,
                artifact_digest: digest("art"),
                declared_bytes: 256,
                logical_bytes: 128,
            }],
        }),
    )
    .unwrap();
    sm.apply(
        AppliedLogId { term: 1, index: 7 },
        RefCasCommand::RegisterRoot(RegisterRootCommand {
            request_id: Uuid::from_u128(611),
            root_id,
            repository_id: repo,
            tenant_id: tenant,
            owner_id: owner,
            operation_id: Uuid::from_u128(609),
            purpose: "backup".into(),
            business_intent_digest: digest("bi"),
            object_format: GitObjectFormat::Sha256,
            history_incarnation: history,
            authority_epoch: 1,
            group_epoch: 1,
            source_snapshot_id: snap_id,
            source_pin_id: pin_id,
            source_pin_generation: 2,
            selector_kind: "snapshot".into(),
            selector_digest: digest("sd"),
            refs_digest: digest("rd"),
            pack_set_digest: digest("psd"),
            bound_hold_ids: vec![hold_id],
            register_digest: digest("regd"),
            request_digest: digest("reqd"),
        }),
    )
    .unwrap();

    // Serialize snapshot, verify deny_unknown_fields & checksum tampering, then restore.
    let mut snap: RefCasSnapshot = sm.snapshot().unwrap();
    let snap_bytes = serde_json::to_vec(&snap).unwrap();
    snap.body.logical_clock_floor = 9999;
    assert!(matches!(RefCasStateMachine::restore(&snap).unwrap_err(), StateMachineError::SnapshotCorrupted(_)));

    let raw_cmd = r#"{"Noop":{"logical_tick":1,"unexpected_field":true}}"#;
    assert!(matches!(decode_command(raw_cmd.as_bytes()).unwrap_err(), StateMachineError::InvalidInput(_)));
    let mut snap_val: serde_json::Value = serde_json::from_slice(&snap_bytes).unwrap();
    snap_val.as_object_mut().unwrap().insert("unknown".into(), serde_json::json!(1));
    let malformed_snap = serde_json::to_vec(&snap_val).unwrap();
    assert!(matches!(
        RefCasStateMachine::restore_bytes(&malformed_snap).unwrap_err(),
        StateMachineError::SnapshotCorrupted(_)
    ));

    let mut restored = RefCasStateMachine::restore_bytes(&snap_bytes).unwrap();
    assert_eq!(restored.cancel_cutoff(repo, issuer, &lane()), 10);
    assert_eq!(restored.read_pin(pin_id).unwrap().generation, 2);
    assert_eq!(restored.read_pin(pin_id).unwrap().expires_at_tick, 55);
    assert_eq!(restored.read_root(root_id).unwrap().state, SmRootState::Active);

    // Cutoff persists across snapshot restore and still blocks stale seq <= 10.
    let stale_req = make_request(
        repo,
        tenant,
        issuer,
        9,
        Uuid::from_u128(612),
        1,
        HeadUpdate::Keep,
        CommitMode::Atomic,
        vec![update("refs/heads/main", None, Some(oid(GitObjectFormat::Sha256, 7)))],
    );
    let err = restored
        .apply(
            AppliedLogId { term: 1, index: 8 },
            RefCasCommand::CommitRefs(CommitRefsCommand {
                request: WireCommitRefsRequest::from(&stale_req),
                decision_id: None,
                required_holds: vec![],
                policy_rejects: BTreeMap::new(),
                logical_tick: 30,
            }),
        )
        .unwrap_err();
    assert!(matches!(err, StateMachineError::BelowCancelCutoff { sequence: 9, cutoff: 10, .. }));

    // Pin generation mismatch & expiry depend only on logical_tick, never system clock.
    let err = restored
        .apply(
            AppliedLogId { term: 1, index: 8 },
            RefCasCommand::RenewPin(RenewPinCommand {
                request_id: Uuid::from_u128(613),
                repository_id: repo,
                tenant_id: tenant,
                owner_id: owner,
                pin_id,
                expected_generation: 2,
                lease_ticks: 10,
                logical_tick: 55,
                request_digest: digest("expired-renew"),
            }),
        )
        .unwrap_err();
    assert!(matches!(err, StateMachineError::PinExpired { expires_at_tick: 55, current_tick: 55, .. }));

    // Retire hold fails while active root holds it, succeeds after release_root; released root stays released.
    let err = restored
        .apply(
            AppliedLogId { term: 1, index: 8 },
            RefCasCommand::RetireHoldBatch(RetireHoldBatchCommand {
                request_id: Uuid::from_u128(614),
                repository_id: repo,
                tenant_id: tenant,
                hold_ids: vec![hold_id],
            }),
        )
        .unwrap_err();
    assert!(matches!(err, StateMachineError::HoldProtectedByRoot { root_id: r, .. } if r == root_id));

    restored
        .apply(
            AppliedLogId { term: 1, index: 8 },
            RefCasCommand::ReleaseRoot(ReleaseRootCommand {
                request_id: Uuid::from_u128(615),
                repository_id: repo,
                tenant_id: tenant,
                owner_id: owner,
                root_id,
                expected_register_digest: digest("regd"),
                intent_digest: digest("rel-root"),
            }),
        )
        .unwrap();
    let retired = restored
        .apply(
            AppliedLogId { term: 1, index: 9 },
            RefCasCommand::RetireHoldBatch(RetireHoldBatchCommand {
                request_id: Uuid::from_u128(616),
                repository_id: repo,
                tenant_id: tenant,
                hold_ids: vec![hold_id],
            }),
        )
        .unwrap();
    assert_eq!(retired, ApplyResponse::HoldsRetired { retired_count: 1 });
    assert_eq!(restored.read_hold(hold_id).unwrap().state, SmHoldState::Retired);

    restored
        .apply(
            AppliedLogId { term: 1, index: 10 },
            RefCasCommand::ReleasePin(ReleasePinCommand {
                request_id: Uuid::from_u128(617),
                repository_id: repo,
                tenant_id: tenant,
                owner_id: owner,
                pin_id,
                reason: "done".into(),
                logical_tick: 40,
                request_digest: digest("rel-pin"),
            }),
        )
        .unwrap();
    assert_eq!(restored.read_pin(pin_id).unwrap().state, SmPinState::Released);
}
