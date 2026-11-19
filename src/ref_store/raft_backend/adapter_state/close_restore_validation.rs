//! Focused source cases for restored compact scope-close acknowledgments.
//!
//! These cases are written source only and are NOT RUN. Each fixture is a structurally valid
//! sealed `/3` adapter state: the Root snapshot checksum verifies and the attempt shape, proposal
//! identity, command digest, and compact summary shape are valid. Only the compact lifecycle/floor
//! values differ from what the core close producer can emit. The legacy full-vector variant is kept
//! on its historical decoding path.

use std::collections::BTreeMap;

use rootyard_refcas_log::state_machine::{ApplicationLogId, ApplicationStateMachine};
use uuid::Uuid;

use super::{export_adapter_state_v3, restore_adapter_state};
use crate::ref_store::core::state_machine::{
    AppliedLogId, CloseAuthScopeCommand, NoopCommand, RefCasCommand, RefCasStateMachine, ScopeLifecycle, encode_command,
};
use crate::ref_store::core::types::GitObjectFormat;
use crate::ref_store::raft_backend::RootRefCasStateMachine;
use crate::ref_store::raft_backend::outcome::{RootRefCasApplied, RootRefCasOutcome};
use crate::ref_store::raft_backend::proposal::{
    ProposalAttempt, ProposalAttemptKind, ProposalEnvelope, ProposalId, command_digest_hex,
};
use crate::ref_store::raft_backend::scope_close::ScopeCloseDrainSummary;

const SCOPE_KIND: &str = "token";
const SCOPE_ID: u128 = 50;
const CLOSE_CHANGE_ID: u128 = 60;
const ROOT_LOG: ApplicationLogId = ApplicationLogId::new(1, 1);

fn proposal_id(issued_at_index: u64, nonce: u128) -> ProposalId {
    ProposalId::new(
        Uuid::from_u128(10),
        Uuid::from_u128(20),
        Uuid::from_u128(30),
        "group-a",
        1,
        Uuid::from_u128(40),
        2,
        3,
        GitObjectFormat::Sha256,
        issued_at_index,
        Uuid::from_u128(nonce),
    )
    .expect("valid proposal fixture")
}

fn compact_summary(lifecycle: ScopeLifecycle, authz_floor: i64) -> ScopeCloseDrainSummary {
    ScopeCloseDrainSummary::from_vectors(
        SCOPE_KIND,
        Uuid::from_u128(SCOPE_ID),
        lifecycle,
        authz_floor,
        &[Uuid::from_u128(71), Uuid::from_u128(72)],
        &[Uuid::from_u128(73)],
    )
}

fn sealed_root() -> Vec<u8> {
    let mut core = RefCasStateMachine::new();
    core.apply(AppliedLogId { term: 1, index: 1 }, RefCasCommand::Noop(NoopCommand { logical_tick: None }))
        .expect("root coordinate fixture");
    let root = core.snapshot_bytes().expect("sealed root fixture");
    RefCasStateMachine::restore_bytes(&root).expect("fixture Root checksum verifies");
    root
}

fn export_fixture(attempt: ProposalAttempt) -> Vec<u8> {
    let log_id = attempt.observed_log_id;
    let mut attempts = BTreeMap::new();
    assert!(attempts.insert(log_id, attempt).is_none());
    export_adapter_state_v3(sealed_root(), &attempts).expect("structurally valid adapter fixture")
}

fn compact_attempt(lifecycle: ScopeLifecycle, authz_floor: i64, nonce: u128) -> ProposalAttempt {
    ProposalAttempt {
        proposal_id: Some(proposal_id(0, nonce)),
        command_digest_hex: command_digest_hex(b"close-auth-scope"),
        original_log_id: ROOT_LOG,
        observed_log_id: ROOT_LOG,
        kind: ProposalAttemptKind::First,
        outcome: RootRefCasOutcome::Applied(RootRefCasApplied::AuthScopeClosedV2 {
            scope_kind: SCOPE_KIND.to_owned(),
            scope_id: Uuid::from_u128(SCOPE_ID),
            lifecycle,
            authz_floor,
            replayed: false,
            drain_summary: compact_summary(lifecycle, authz_floor),
        }),
    }
}

fn assert_compact_checksum_fixture_rejected(lifecycle: ScopeLifecycle, authz_floor: i64, nonce: u128) {
    let attempt = compact_attempt(lifecycle, authz_floor, nonce);
    if let RootRefCasOutcome::Applied(RootRefCasApplied::AuthScopeClosedV2 { drain_summary, .. }) = &attempt.outcome {
        drain_summary.validate().expect("compact summary shape must remain valid");
    }
    let bytes = export_fixture(attempt);
    // Prove the rejected fixture is structurally valid and checksum-sealed before restore: only
    // the compact successful-close semantics below can make it fail.
    let outer: serde_json::Value = serde_json::from_slice(&bytes).expect("strictly decodable fixture");
    let root = outer["root_snapshot"].as_str().expect("fixture carries the Root snapshot text");
    RefCasStateMachine::restore_bytes(root.as_bytes()).expect("fixture Root checksum verifies");
    assert!(restore_adapter_state(&bytes).is_err());
}

#[test]
fn restore_rejects_compact_close_with_open_lifecycle() {
    assert_compact_checksum_fixture_rejected(ScopeLifecycle::Open, 2, 101);
}

#[test]
fn restore_rejects_compact_close_with_zero_authz_floor() {
    assert_compact_checksum_fixture_rejected(ScopeLifecycle::Closing, 0, 102);
}

#[test]
fn restore_rejects_compact_close_with_negative_authz_floor() {
    assert_compact_checksum_fixture_rejected(ScopeLifecycle::Closed, -1, 103);
}

#[test]
fn restore_accepts_compact_close_with_closing_or_closed_and_positive_floor() {
    for (lifecycle, authz_floor, nonce) in [
        (ScopeLifecycle::Closing, 1, 201),
        (ScopeLifecycle::Closing, 2, 202),
        (ScopeLifecycle::Closed, 1, 203),
        (ScopeLifecycle::Closed, 7, 204),
    ] {
        let attempt = compact_attempt(lifecycle, authz_floor, nonce);
        let bytes = export_fixture(attempt.clone());
        let restored = restore_adapter_state(&bytes).expect("producer-reachable compact close restores");
        assert!(restored.legacy.is_none());
        assert_eq!(restored.attempts.get(&ROOT_LOG), Some(&attempt));
        let root = restored.machine.snapshot_bytes().expect("restored Root snapshot");
        let reexported = export_adapter_state_v3(root, &restored.attempts).expect("reexport compact fixture");
        assert_eq!(reexported, bytes);
    }
}

#[test]
fn legacy_full_vector_close_restore_preserves_exact_bytes_digest_and_replay() {
    let proposal = proposal_id(0, 301);
    let command = RefCasCommand::CloseAuthScope(CloseAuthScopeCommand {
        scope_kind: SCOPE_KIND.to_owned(),
        scope_id: Uuid::from_u128(SCOPE_ID),
        repository_id: Some(Uuid::from_u128(10)),
        tenant_id: Some(Uuid::from_u128(20)),
        lifecycle: ScopeLifecycle::Closing,
        authz_floor: 2,
        change_id: Uuid::from_u128(CLOSE_CHANGE_ID),
        logical_tick: 1,
    });
    let payload = encode_command(&command).expect("encode legacy close command");
    let attempt = ProposalAttempt {
        proposal_id: Some(proposal.clone()),
        command_digest_hex: command_digest_hex(&payload),
        original_log_id: ROOT_LOG,
        observed_log_id: ROOT_LOG,
        kind: ProposalAttemptKind::First,
        outcome: RootRefCasOutcome::Applied(RootRefCasApplied::AuthScopeClosed {
            scope_kind: SCOPE_KIND.to_owned(),
            scope_id: Uuid::from_u128(SCOPE_ID),
            lifecycle: ScopeLifecycle::Closing,
            authz_floor: 2,
            replayed: false,
            open_decision_ids: vec![Uuid::from_u128(71), Uuid::from_u128(72)],
            pending_operation_ids: vec![Uuid::from_u128(73)],
        }),
    };
    let bytes = export_fixture(attempt.clone());

    let restored = restore_adapter_state(&bytes).expect("legacy full-vector close restores");
    assert!(restored.legacy.is_none());
    assert_eq!(restored.attempts.get(&ROOT_LOG), Some(&attempt));

    let mut app = RootRefCasStateMachine::new();
    <RootRefCasStateMachine as ApplicationStateMachine>::restore_state(&mut app, &bytes)
        .expect("actual reducer restores the legacy fixture");
    let exported = <RootRefCasStateMachine as ApplicationStateMachine>::export_state(&app)
        .expect("legacy fixture reexports exact bytes");
    assert_eq!(exported, bytes);
    let digest =
        <RootRefCasStateMachine as ApplicationStateMachine>::state_digest_hex(&app).expect("legacy fixture digest");
    let mut reopened = RootRefCasStateMachine::new();
    <RootRefCasStateMachine as ApplicationStateMachine>::restore_state(&mut reopened, &exported)
        .expect("legacy fixture reopens");
    assert_eq!(
        <RootRefCasStateMachine as ApplicationStateMachine>::state_digest_hex(&reopened)
            .expect("reopened legacy fixture digest"),
        digest
    );

    let envelope = ProposalEnvelope::encode(&proposal, &payload).expect("legacy replay envelope");
    <RootRefCasStateMachine as ApplicationStateMachine>::apply(&mut app, ApplicationLogId::new(1, 2), &envelope)
        .expect("legacy same-id exact replay");
    let replay = app.query_attempt(ApplicationLogId::new(1, 2)).expect("legacy replay attempt");
    assert_eq!(replay.kind, ProposalAttemptKind::Replayed);
    assert_eq!(replay.original_log_id, ROOT_LOG);
    assert_eq!(replay.outcome, attempt.outcome);
    assert_eq!(app.query_attempt(ROOT_LOG), Some(&attempt));
}
