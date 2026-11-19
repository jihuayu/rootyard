use super::*;
use crate::ref_store::contract::OperationState;
use crate::ref_store::core::publication_decision::contract::REPO_MAX_DECISIONS;
use crate::ref_store::core::state_machine::{
    AppliedLogId, ApplyResponse, CancelCommand, CloseAuthScopeCommand, InstallDecisionCommand,
    InstallScopedDecisionCommand, NoopCommand, RefCasCommand, RefCasStateMachine, ScopeLifecycle,
    WireDecisionGrantCommitment, WireDecisionKind, WireDecisionScopeDep, WireDecisionVerdict, WireOperationIdentity,
};
use crate::ref_store::core::types::GitObjectFormat;
use crate::ref_store::raft_backend::adapter_state::{export_adapter_state_v3, root_only_state_v3};
use crate::ref_store::raft_backend::outcome::{RootRefCasApplied, RootRefCasOutcome};
use crate::ref_store::raft_backend::proposal::{
    MAX_ADAPTER_STATE_BYTES, MAX_PROPOSAL_RECEIPT_BYTES, MAX_ROOT_STATE_BYTES, PROPOSAL_WINDOW, ProposalAttempt,
    ProposalAttemptKind, ProposalEnvelope,
};
use crate::ref_store::raft_backend::scope_close::{
    MAX_SCOPE_CLOSE_ACK_BYTES, SCOPE_CLOSE_DRAIN_FORMAT, scope_close_drain_digest,
};
use rootyard_refcas_log::state_machine::{ApplicationLogId, ApplicationStateMachine, MAX_APP_STATE_BYTES};
use std::collections::BTreeMap;
use uuid::Uuid;

const SCOPE_KIND: &str = "token";

#[allow(clippy::too_many_arguments)]
fn install_scoped_command(
    repo: Uuid,
    tenant: Uuid,
    actor: Uuid,
    decision_id: Uuid,
    operation_id: Uuid,
    scope_id: Uuid,
    gate_digest: &str,
) -> RefCasCommand {
    RefCasCommand::InstallScopedDecision(InstallScopedDecisionCommand {
        decision: InstallDecisionCommand {
            decision_id,
            repository_id: repo,
            tenant_id: tenant,
            actor_id: actor,
            operation_id,
            kind: WireDecisionKind::Atomic,
            base_revision: 1,
            command_digest: "11".repeat(32),
            selection_digest: "12".repeat(32),
            policy_digest: "13".repeat(32),
            facts_digest: "14".repeat(32),
            authz_digest: "15".repeat(32),
            dependencies_digest: "16".repeat(32),
            verdicts: vec![WireDecisionVerdict { ref_name: "refs/a".into(), accepted: true, reject_code: None }],
            authz_epoch: 2,
            not_after_tick: 1_000_000,
            logical_tick: 0,
        },
        scope_dependencies: vec![WireDecisionScopeDep {
            scope_kind: SCOPE_KIND.into(),
            scope_id,
            observed_version: 1,
            observed_digest: "17".repeat(32),
        }],
        grant_commitment: WireDecisionGrantCommitment {
            base_gate_digest: gate_digest.to_owned(),
            packs_digest: "18".repeat(32),
            hold_receipts_digest: "19".repeat(32),
            captured_oid_digest: "1a".repeat(32),
            required_holds: vec![],
        },
    })
}

#[test]
fn max_cardinality_scope_close_emits_bounded_ack_and_keeps_original_receipt() {
    let repo = Uuid::from_u128(10);
    let tenant = Uuid::from_u128(20);
    let history = Uuid::from_u128(30);
    let actor = Uuid::from_u128(40);
    let scope_id = Uuid::from_u128(50);
    let decision_base = 100_000_u128;
    let operation_base = 200_000_u128;

    let mut core = RefCasStateMachine::new();
    core.apply(AppliedLogId { term: 1, index: 1 }, init_command(repo, tenant, history, 1, 2, GitObjectFormat::Sha256))
        .expect("initialize gate");
    let gate = core.read_gate_version(repo).expect("read gate").expect("gate exists");
    let gate_digest = gate.digest().as_hex();
    let root_before = core.snapshot_bytes().expect("root before installs");
    assert!(root_only_state_v3(&root_before).is_ok());
    assert!(root_only_state_v3(&root_before).expect("root before").len() <= MAX_ROOT_STATE_BYTES);

    let count = usize::try_from(REPO_MAX_DECISIONS).expect("decision quota fits usize");
    assert_eq!(count, 2048);
    let mut decision_ids = Vec::with_capacity(count);
    let mut operation_ids = Vec::with_capacity(count);
    for index in 0..count {
        let decision_id = Uuid::from_u128(decision_base + index as u128);
        let operation_id = Uuid::from_u128(operation_base + index as u128);
        decision_ids.push(decision_id);
        operation_ids.push(operation_id);
        let command = install_scoped_command(repo, tenant, actor, decision_id, operation_id, scope_id, &gate_digest);
        match core.apply(AppliedLogId { term: 1, index: index as u64 + 2 }, command).expect("install decision") {
            ApplyResponse::DecisionInstalled { decision_id: actual, replayed: false } if actual == decision_id => {}
            other => panic!("unexpected 2048 fixture install response: {other:?}"),
        }
    }

    let drain_before_close = core.inspect_scope_drain(SCOPE_KIND, scope_id).expect("drain before close");
    assert_eq!(drain_before_close.open_decision_ids, decision_ids);
    assert_eq!(drain_before_close.pending_operation_ids, operation_ids);
    assert!(drain_before_close.settled_terminal_operations.is_empty());
    let root_after_installs = core.snapshot_bytes().expect("root after installs");
    let encoded_root_after_installs = root_only_state_v3(&root_after_installs).expect("2048 decisions fit Root budget");
    assert!(encoded_root_after_installs.len() <= MAX_ROOT_STATE_BYTES);

    let mut app =
        RootRefCasStateMachine { machine: core, attempts: BTreeMap::new(), legacy: None, forced_capacity_once: false };
    let close_log = ApplicationLogId::new(1, count as u64 + 2);
    let close_id = scoped_id(repo, tenant, history, 1, 2, GitObjectFormat::Sha256, count as u64 + 1, 100);
    let close = CloseAuthScopeCommand {
        scope_kind: SCOPE_KIND.into(),
        scope_id,
        repository_id: Some(repo),
        tenant_id: Some(tenant),
        lifecycle: ScopeLifecycle::Closing,
        authz_floor: 2,
        change_id: Uuid::from_u128(60),
        logical_tick: 1,
    };
    app.apply(close_log, &envelope(&close_id, &RefCasCommand::CloseAuthScope(close.clone())))
        .expect("close max-cardinality scope");
    let close_attempt = app.query_attempt(close_log).expect("close attempt").clone();
    assert_eq!(close_attempt.kind, ProposalAttemptKind::First);
    let close_summary = match &close_attempt.outcome {
        RootRefCasOutcome::Applied(RootRefCasApplied::AuthScopeClosedV2 { drain_summary, .. }) => drain_summary,
        other => panic!("max-cardinality close did not emit compact acknowledgment: {other:?}"),
    };
    assert_eq!(close_summary.format, SCOPE_CLOSE_DRAIN_FORMAT);
    assert_eq!(close_summary.open_decision_count, count as u64);
    assert_eq!(close_summary.pending_operation_count, count as u64);
    assert!(close_summary.validate().is_ok());
    assert_eq!(
        close_summary.ids_digest_hex,
        scope_close_drain_digest(
            SCOPE_KIND,
            scope_id,
            ScopeLifecycle::Closing,
            2,
            &drain_before_close.open_decision_ids,
            &drain_before_close.pending_operation_ids,
        )
    );
    assert!(close_attempt.serialized_len().expect("receipt len") <= MAX_SCOPE_CLOSE_ACK_BYTES);

    let drain_after_close = app.machine().inspect_scope_drain(SCOPE_KIND, scope_id).expect("drain after close");
    assert_eq!(drain_after_close.open_decision_ids, decision_ids);
    assert_eq!(drain_after_close.pending_operation_ids, operation_ids);
    assert!(drain_after_close.settled_terminal_operations.is_empty());
    let floor = drain_after_close.scope.as_ref().expect("scope floor");
    assert_eq!(floor.lifecycle, ScopeLifecycle::Closing);
    assert_eq!(floor.authz_floor, 2);
    let encoded_root_after_close =
        root_only_state_v3(&app.machine().snapshot_bytes().expect("root after close")).expect("Root fits after close");
    assert!(encoded_root_after_close.len() <= MAX_ROOT_STATE_BYTES);
    let exported = app.export_state().expect("adapter state after close");
    assert!(exported.len() <= MAX_ADAPTER_STATE_BYTES);
    assert!(exported.len() < MAX_APP_STATE_BYTES);
    let outer: serde_json::Value = serde_json::from_slice(&exported).expect("outer adapter JSON");
    assert_eq!(outer["format"].as_str(), Some(crate::ref_store::raft_backend::adapter_state::ADAPTER_STATE_FORMAT_V3));
    assert_eq!(outer["window"].as_u64(), Some(PROPOSAL_WINDOW));
    let mut reopened = RootRefCasStateMachine::new();
    reopened.restore_state(&exported).expect("restore compact close snapshot");
    assert_eq!(reopened.query_attempt(close_log), Some(&close_attempt));
    assert_eq!(
        reopened.machine().inspect_scope_drain(SCOPE_KIND, scope_id).expect("restored current drain"),
        drain_after_close
    );

    let cancel_log = ApplicationLogId::new(1, close_log.index + 1);
    let cancel_id = scoped_id(repo, tenant, history, 1, 2, GitObjectFormat::Sha256, close_log.index, 101);
    let cancel = RefCasCommand::Cancel(CancelCommand {
        identity: WireOperationIdentity {
            repository_id: repo,
            issuer_id: Uuid::from_u128(70),
            lane: "main".into(),
            sequence: 1,
            operation_id: operation_ids[0],
            digest: "00".repeat(32),
        },
        reason: Some("settle one operation for drain query".into()),
        logical_tick: 2,
    });
    app.apply(cancel_log, &envelope(&cancel_id, &cancel)).expect("cancel one scoped operation");
    assert!(app.query_attempt(cancel_log).expect("cancel attempt").outcome.is_applied());

    let drain_after_cancel = app.machine().inspect_scope_drain(SCOPE_KIND, scope_id).expect("drain after cancel");
    assert_eq!(drain_after_cancel.open_decision_ids, decision_ids[1..].to_vec());
    assert_eq!(drain_after_cancel.pending_operation_ids, operation_ids[1..].to_vec());
    assert_eq!(drain_after_cancel.settled_terminal_operations.len(), 1);
    assert_eq!(drain_after_cancel.settled_terminal_operations.get(&operation_ids[0]), Some(&OperationState::Cancelled));
    assert_eq!(app.query_attempt(close_log).expect("original close receipt"), &close_attempt);

    let fresh_close_log = ApplicationLogId::new(1, cancel_log.index + 1);
    let fresh_close_id = scoped_id(repo, tenant, history, 1, 2, GitObjectFormat::Sha256, cancel_log.index, 102);
    app.apply(fresh_close_log, &envelope(&fresh_close_id, &RefCasCommand::CloseAuthScope(close.clone())))
        .expect("fresh close captures current drain");
    let fresh_attempt = app.query_attempt(fresh_close_log).expect("fresh close attempt");
    let fresh_summary = match &fresh_attempt.outcome {
        RootRefCasOutcome::Applied(RootRefCasApplied::AuthScopeClosedV2 { replayed: true, drain_summary, .. }) => {
            drain_summary
        }
        other => panic!("fresh close did not report a replayed compact current drain: {other:?}"),
    };
    assert_eq!(fresh_summary.open_decision_count, count as u64 - 1);
    assert_eq!(fresh_summary.pending_operation_count, count as u64 - 1);
    assert_eq!(app.query_attempt(close_log).expect("original close receipt after fresh close"), &close_attempt);

    let retry_log = ApplicationLogId::new(1, fresh_close_log.index + 1);
    app.apply(retry_log, &envelope(&close_id, &RefCasCommand::CloseAuthScope(close)))
        .expect("same-ID original close retry");
    let retry_attempt = app.query_attempt(retry_log).expect("replayed close attempt");
    assert_eq!(retry_attempt.kind, ProposalAttemptKind::Replayed);
    assert_eq!(retry_attempt.original_log_id, close_log);
    assert_eq!(retry_attempt.outcome, close_attempt.outcome);
    assert_eq!(app.query_attempt(close_log).expect("original close receipt after replay"), &close_attempt);
}

// Compile-time form of the same capacity policy. These are consistency checks on production
// constants, not runtime behavior evidence; the dynamic 2048/Root/receipt checks remain below.
const _: () = assert!(PROPOSAL_WINDOW == 32);
const _: () = assert!(MAX_PROPOSAL_RECEIPT_BYTES == 80 * 1024);
const _: () =
    assert!(MAX_ROOT_STATE_BYTES + PROPOSAL_WINDOW as usize * MAX_PROPOSAL_RECEIPT_BYTES < MAX_ADAPTER_STATE_BYTES);
const _: () = assert!(MAX_ADAPTER_STATE_BYTES < MAX_APP_STATE_BYTES);

#[test]
fn legacy_full_vector_close_receipt_roundtrips_exactly_and_replays() {
    let repo = Uuid::from_u128(10);
    let tenant = Uuid::from_u128(20);
    let history = Uuid::from_u128(30);
    let scope_id = Uuid::from_u128(50);
    let change_id = Uuid::from_u128(60);
    let proposal = scoped_id(repo, tenant, history, 1, 2, GitObjectFormat::Sha256, 0, 300);
    let command = RefCasCommand::CloseAuthScope(CloseAuthScopeCommand {
        scope_kind: SCOPE_KIND.into(),
        scope_id,
        repository_id: Some(repo),
        tenant_id: Some(tenant),
        lifecycle: ScopeLifecycle::Closing,
        authz_floor: 2,
        change_id,
        logical_tick: 1,
    });
    let payload = encode_command(&command).expect("encode legacy close command");
    let command_digest = crate::ref_store::raft_backend::proposal::command_digest_hex(&payload);

    let mut core = RefCasStateMachine::new();
    core.apply(AppliedLogId { term: 1, index: 1 }, RefCasCommand::Noop(NoopCommand { logical_tick: None }))
        .expect("root coordinate");
    let root = core.snapshot_bytes().expect("legacy root snapshot");
    let old_attempt = ProposalAttempt {
        proposal_id: Some(proposal.clone()),
        command_digest_hex: command_digest,
        original_log_id: ApplicationLogId::new(1, 1),
        observed_log_id: ApplicationLogId::new(1, 1),
        kind: ProposalAttemptKind::First,
        outcome: RootRefCasOutcome::Applied(RootRefCasApplied::AuthScopeClosed {
            scope_kind: SCOPE_KIND.into(),
            scope_id,
            lifecycle: ScopeLifecycle::Closing,
            authz_floor: 2,
            replayed: false,
            open_decision_ids: vec![Uuid::from_u128(71), Uuid::from_u128(72)],
            pending_operation_ids: vec![Uuid::from_u128(73)],
        }),
    };
    let mut attempts = BTreeMap::new();
    attempts.insert(ApplicationLogId::new(1, 1), old_attempt.clone());
    let bytes = export_adapter_state_v3(root, &attempts).expect("legacy adapter fixture");

    let mut app = RootRefCasStateMachine::new();
    app.restore_state(&bytes).expect("restore legacy fixture");
    assert_eq!(app.export_state().expect("legacy export"), bytes);
    assert_eq!(app.query_attempt(ApplicationLogId::new(1, 1)), Some(&old_attempt));
    let digest = app.state_digest_hex().expect("legacy digest");
    let mut reopened = RootRefCasStateMachine::new();
    reopened.restore_state(&app.export_state().expect("legacy export")).expect("reopen legacy fixture");
    assert_eq!(reopened.state_digest_hex().expect("legacy digest"), digest);

    let envelope_bytes = ProposalEnvelope::encode(&proposal, &payload).expect("legacy replay envelope");
    let replay_log = ApplicationLogId::new(1, 2);
    app.apply(replay_log, &envelope_bytes).expect("legacy exact replay");
    let replay = app.query_attempt(replay_log).expect("legacy replay attempt");
    assert_eq!(replay.kind, ProposalAttemptKind::Replayed);
    assert_eq!(replay.original_log_id, ApplicationLogId::new(1, 1));
    assert_eq!(replay.outcome, old_attempt.outcome);
    assert_eq!(app.query_attempt(ApplicationLogId::new(1, 1)), Some(&old_attempt));
}

#[test]
fn malformed_compact_summary_fails_closed_on_restore() {
    let repo = Uuid::from_u128(10);
    let tenant = Uuid::from_u128(20);
    let history = Uuid::from_u128(30);
    let scope_id = Uuid::from_u128(50);
    let proposal = scoped_id(repo, tenant, history, 1, 2, GitObjectFormat::Sha256, 0, 400);
    let summary = crate::ref_store::raft_backend::scope_close::ScopeCloseDrainSummary::from_vectors(
        SCOPE_KIND,
        scope_id,
        ScopeLifecycle::Closing,
        2,
        &[Uuid::from_u128(71)],
        &[Uuid::from_u128(72)],
    );
    let attempt = ProposalAttempt {
        proposal_id: Some(proposal),
        command_digest_hex: "00".repeat(32),
        original_log_id: ApplicationLogId::new(1, 1),
        observed_log_id: ApplicationLogId::new(1, 1),
        kind: ProposalAttemptKind::First,
        outcome: RootRefCasOutcome::Applied(RootRefCasApplied::AuthScopeClosedV2 {
            scope_kind: SCOPE_KIND.into(),
            scope_id,
            lifecycle: ScopeLifecycle::Closing,
            authz_floor: 2,
            replayed: false,
            drain_summary: summary,
        }),
    };
    let mut core = RefCasStateMachine::new();
    core.apply(AppliedLogId { term: 1, index: 1 }, RefCasCommand::Noop(NoopCommand { logical_tick: None }))
        .expect("root coordinate");
    let mut attempts = BTreeMap::new();
    attempts.insert(ApplicationLogId::new(1, 1), attempt);
    let bytes = export_adapter_state_v3(core.snapshot_bytes().expect("root"), &attempts).expect("compact fixture");
    let mut value: serde_json::Value = serde_json::from_slice(&bytes).expect("fixture JSON");
    value["attempts"][0]["outcome"]["Applied"]["AuthScopeClosedV2"]["drain_summary"]["ids_digest_hex"] =
        serde_json::json!("zz");
    let malformed = serde_json::to_vec(&value).expect("malformed JSON");
    let mut restored = RootRefCasStateMachine::new();
    assert!(restored.restore_state(&malformed).is_err());
}
