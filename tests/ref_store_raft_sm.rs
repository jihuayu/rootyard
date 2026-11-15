//! Deterministic unit and Raft contract tests for `RefCasStateMachine` (`#116`).
//!
//! No PostgreSQL, Git processes, Blob storage, or wall-clock APIs are touched here.

use rootyard::ref_store::core::pack_commit::PackMode;
use rootyard::ref_store::core::state_machine::{
    AcquireHoldBatchCommand, AppliedLogId, ApplyResponse, CommitRefsCommand, InitializeGateCommand,
    InstallDecisionCommand, MarkHoldConsumedCommand, NoopCommand, RefCasCommand, RefCasLogEntry, RefCasStateMachine,
    RegisterRootCommand, RepositoryLane, SmDecisionState, SmHoldState, SmRootState, StateMachineError,
    WireCommitRefsRequest, WireDecisionKind, WireDecisionVerdict, WireGateInit, WireHoldArtifactSpec, encode_command,
};
use rootyard::ref_store::{
    CommitMode, CommitRefsRequest, CoreGateInit, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, MetadataPinPurpose,
    RefName, RefPrecondition, RefTarget, RefUpdate, RequestDigest,
};
use std::collections::BTreeMap;
use uuid::Uuid;

#[path = "raft_sm_support/lifecycle_cases.rs"]
mod lifecycle_cases;
#[path = "raft_sm_support/recovery_cases.rs"]
mod recovery_cases;

pub(crate) fn lane() -> IssuerLane {
    IssuerLane::new("raft-sm-test").expect("valid lane")
}

pub(crate) fn oid(format: GitObjectFormat, byte: u8) -> GitOid {
    match format {
        GitObjectFormat::Sha1 => GitOid::Sha1([byte; 20]),
        GitObjectFormat::Sha256 => GitOid::Sha256([byte; 32]),
    }
}

pub(crate) fn ref_name(value: &str) -> RefName {
    RefName::new(value).expect("valid ref name")
}

pub(crate) fn digest(label: &str) -> String {
    RequestDigest::of("raft-sm-test-digest", &[label.as_bytes()]).as_hex()
}

pub(crate) fn update(name: &str, old: Option<GitOid>, new: Option<GitOid>) -> RefUpdate {
    let pre = match old {
        Some(o) => RefPrecondition::Present(o),
        None => RefPrecondition::Absent,
    };
    let target = match new {
        Some(n) => RefTarget::Oid(n),
        None => RefTarget::Delete,
    };
    RefUpdate::new(ref_name(name), pre, target)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn make_request(
    repo: Uuid,
    tenant: Uuid,
    issuer: Uuid,
    seq: i64,
    op_id: Uuid,
    expected_rev: i64,
    head: HeadUpdate,
    mode: CommitMode,
    refs: Vec<RefUpdate>,
) -> CommitRefsRequest {
    CommitRefsRequest::new(
        repo,
        tenant,
        issuer,
        lane(),
        seq,
        op_id,
        GitObjectFormat::Sha256,
        Uuid::from_u128(0x1111_2222_3333_4444_5555_6666_7777_8888),
        1,
        1,
        expected_rev,
        head,
        mode,
        refs,
    )
    .expect("valid CommitRefsRequest")
}

pub(crate) fn make_init(repo: Uuid, tenant: Uuid, history: Uuid) -> CoreGateInit {
    CoreGateInit::new(repo, tenant, GitObjectFormat::Sha256, history, 1, 1, RefName::branch("refs/heads/main").unwrap())
        .expect("valid CoreGateInit")
}

fn encode_entries(cmds: &[(u64, u64, RefCasCommand)]) -> Vec<RefCasLogEntry> {
    cmds.iter()
        .map(|(term, index, cmd)| RefCasLogEntry {
            log_id: AppliedLogId { term: *term, index: *index },
            payload: encode_command(cmd).expect("encode command"),
        })
        .collect()
}

#[test]
fn deterministic_byte_log_replay_and_snapshot_recovery_match_state_digest() {
    let repo = Uuid::from_u128(10);
    let tenant = Uuid::from_u128(20);
    let issuer = Uuid::from_u128(30);
    let owner = Uuid::from_u128(40);
    let history = Uuid::from_u128(0x1111_2222_3333_4444_5555_6666_7777_8888);
    let op1 = Uuid::from_u128(101);
    let op2 = Uuid::from_u128(102);
    let snap_id = Uuid::from_u128(201);
    let pin_id = Uuid::from_u128(202);
    let hold_req = Uuid::from_u128(301);
    let hold_consume = Uuid::from_u128(302);
    let hold_id = Uuid::from_u128(303);
    let root_id = Uuid::from_u128(401);
    let dec_id = Uuid::from_u128(501);

    let init = make_init(repo, tenant, history);
    let req1 = make_request(
        repo,
        tenant,
        issuer,
        1,
        op1,
        1,
        HeadUpdate::Retarget(ref_name("refs/heads/main")),
        CommitMode::Atomic,
        vec![update("refs/heads/main", None, Some(oid(GitObjectFormat::Sha256, 1)))],
    );
    let req2 = make_request(
        repo,
        tenant,
        issuer,
        2,
        op2,
        2,
        HeadUpdate::Keep,
        CommitMode::AcceptedSubset,
        vec![
            update("refs/heads/feat", None, Some(oid(GitObjectFormat::Sha256, 2))),
            update("refs/heads/main", Some(oid(GitObjectFormat::Sha256, 99)), Some(oid(GitObjectFormat::Sha256, 3))),
        ],
    );

    let mut probe = RefCasStateMachine::new();
    let gate_res = probe
        .apply(
            AppliedLogId { term: 1, index: 1 },
            RefCasCommand::InitializeGate(InitializeGateCommand {
                gate: WireGateInit::from(&init),
                pack_mode: PackMode::MetadataOnly,
                lane: RepositoryLane::PgRefstore,
                authz_floor: 1,
            }),
        )
        .unwrap();
    let gate_v1 = match gate_res {
        ApplyResponse::GateInitialized { version, .. } => version,
        other => panic!("unexpected {other:?}"),
    };
    let gate_v1_digest = gate_v1.digest().as_hex();

    let cmds = vec![
        (
            1,
            1,
            RefCasCommand::InitializeGate(InitializeGateCommand {
                gate: WireGateInit::from(&init),
                pack_mode: PackMode::MetadataOnly,
                lane: RepositoryLane::PgRefstore,
                authz_floor: 1,
            }),
        ),
        (
            1,
            2,
            RefCasCommand::CommitRefs(CommitRefsCommand {
                request: WireCommitRefsRequest::from(&req1),
                decision_id: None,
                required_holds: vec![],
                policy_rejects: BTreeMap::new(),
                logical_tick: 100,
            }),
        ),
        (
            1,
            3,
            RefCasCommand::CreateSnapshotPin(super::raft_sm_support_create_pin(
                repo,
                tenant,
                owner,
                history,
                snap_id,
                pin_id,
                gate_v1_digest.clone(),
            )),
        ),
        (
            1,
            4,
            RefCasCommand::AcquireHoldBatch(AcquireHoldBatchCommand {
                request_id: hold_req,
                consume_request_id: hold_consume,
                operation_id: op2,
                repository_id: repo,
                tenant_id: tenant,
                owner_id: owner,
                purpose: "ref_publication".into(),
                backend_identity: digest("backend"),
                authority_id: Uuid::from_u128(777),
                authority_generation: 1,
                expected_gate_digest: gate_v1_digest,
                artifacts: vec![WireHoldArtifactSpec {
                    hold_id,
                    slot: 0,
                    artifact_digest: digest("pack-blob"),
                    declared_bytes: 1024,
                    logical_bytes: 512,
                }],
            }),
        ),
        (
            1,
            5,
            RefCasCommand::InstallDecision(InstallDecisionCommand {
                decision_id: dec_id,
                repository_id: repo,
                tenant_id: tenant,
                actor_id: issuer,
                operation_id: op2,
                kind: WireDecisionKind::AcceptedSubset,
                base_revision: 2,
                command_digest: req2.digest().as_hex(),
                selection_digest: digest("sel"),
                policy_digest: digest("pol"),
                facts_digest: digest("facts"),
                authz_digest: digest("authz"),
                dependencies_digest: digest("deps"),
                verdicts: vec![WireDecisionVerdict { ref_name: "refs/heads/feat".into(), allowed: true, reason: None }],
                authz_epoch: 1,
                not_after_tick: 500,
                logical_tick: 110,
            }),
        ),
        (
            2,
            6,
            RefCasCommand::CommitRefs(CommitRefsCommand {
                request: WireCommitRefsRequest::from(&req2),
                decision_id: Some(dec_id),
                required_holds: vec![hold_id],
                policy_rejects: BTreeMap::new(),
                logical_tick: 120,
            }),
        ),
        (
            2,
            7,
            RefCasCommand::MarkHoldConsumed(MarkHoldConsumedCommand {
                consume_request_id: hold_consume,
                request_id: hold_req,
                repository_id: repo,
                tenant_id: tenant,
                hold_ids: vec![hold_id],
            }),
        ),
        (
            2,
            8,
            RefCasCommand::RegisterRoot(RegisterRootCommand {
                request_id: Uuid::from_u128(902),
                root_id,
                repository_id: repo,
                tenant_id: tenant,
                owner_id: owner,
                operation_id: op2,
                purpose: "ci".into(),
                business_intent_digest: digest("intent"),
                object_format: GitObjectFormat::Sha256,
                history_incarnation: history,
                authority_epoch: 1,
                group_epoch: 1,
                source_snapshot_id: snap_id,
                source_pin_id: pin_id,
                source_pin_generation: 1,
                selector_kind: "snapshot".into(),
                selector_digest: digest("sel-root"),
                refs_digest: digest("refs-root"),
                pack_set_digest: digest("packs-root"),
                bound_hold_ids: vec![hold_id],
                register_digest: digest("reg-digest"),
                request_digest: digest("req-root"),
            }),
        ),
    ];

    let entries = encode_entries(&cmds);
    let mut replica_a = RefCasStateMachine::new();
    let mut replica_b = RefCasStateMachine::new();
    replica_a.recover_entries(entries.clone()).expect("replica_a recover");
    for entry in &entries[..4] {
        replica_b.apply_bytes(entry.log_id, &entry.payload).expect("replica_b prefix");
    }
    let mid_snap = replica_b.snapshot_bytes().expect("snapshot bytes");
    let mut restored_b = RefCasStateMachine::restore_bytes(&mid_snap).expect("restore midpoint");
    let rec = restored_b.recover_entries(entries.clone()).expect("recover full tail");
    assert!(matches!(rec[0], ApplyResponse::AlreadyApplied { .. }));
    assert!(matches!(rec[3], ApplyResponse::AlreadyApplied { .. }));

    assert_eq!(replica_a.state_digest().unwrap(), restored_b.state_digest().unwrap());
    assert_eq!(replica_a.last_applied(), restored_b.last_applied());
    assert_eq!(restored_b.read_gate_version(repo).unwrap().unwrap().revision(), 3);
    assert_eq!(restored_b.read_decision(dec_id).unwrap().state, SmDecisionState::Consumed);
    assert_eq!(restored_b.read_hold(hold_id).unwrap().state, SmHoldState::Consumed);
    assert_eq!(restored_b.read_root(root_id).unwrap().state, SmRootState::Active);

    // Non-monotonic log index must reject without changing state digest.
    let before = restored_b.state_digest().unwrap();
    let err = restored_b
        .apply(AppliedLogId { term: 2, index: 8 }, RefCasCommand::Noop(NoopCommand { logical_tick: Some(999) }))
        .unwrap_err();
    assert!(matches!(err, StateMachineError::NonMonotonicLogIndex { expected_gt: 8, got: 8 }));
    assert_eq!(restored_b.state_digest().unwrap(), before);
}

fn raft_sm_support_create_pin(
    repo: Uuid,
    tenant: Uuid,
    owner: Uuid,
    history: Uuid,
    snapshot_id: Uuid,
    pin_id: Uuid,
    expected_gate_digest: String,
) -> rootyard::ref_store::core::state_machine::CreateSnapshotPinCommand {
    rootyard::ref_store::core::state_machine::CreateSnapshotPinCommand {
        request_id: Uuid::from_u128(901),
        repository_id: repo,
        tenant_id: tenant,
        owner_id: owner,
        purpose: MetadataPinPurpose::Verification,
        snapshot_id,
        pin_id,
        object_format: GitObjectFormat::Sha256,
        history_incarnation: history,
        authority_epoch: 1,
        group_epoch: 1,
        expected_gate_digest,
        lease_ticks: 50,
        logical_tick: 105,
        pack_digests: vec![],
        request_digest: digest("snap1"),
    }
}
