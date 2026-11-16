//! Deterministic fixtures, keys, requests, and signed grant payload builders for `#152`.

use std::collections::BTreeSet;

use uuid::Uuid;
use zeroize::Zeroizing;

use rootyard::ref_store::contract::IssuerLane;
use rootyard::ref_store::core::command::CommitRefsRequest;
use rootyard::ref_store::core::contract::CommitMode;
use rootyard::ref_store::core::state_machine::{
    AcquireHoldBatchCommand, AppliedLogId, ApplyResponse, InitializeGateCommand, RefCasCommand, RefCasStateMachine,
    RepositoryLane, SmPackMode, WireDecisionKind, WireDecisionScopeDep, WireDecisionVerdict, WireGateInit,
    WireHoldArtifactSpec,
};
use rootyard::ref_store::core::types::{GitObjectFormat, GitOid, HeadUpdate, RefName, RefUpdate};
use rootyard::ref_store::projector::{
    DecisionGrantKeyring, GrantExpectedRealm, ServiceMtlsIdentity, SignedDecisionGrantPayload,
};

pub fn hex_digest(byte: u8) -> String {
    format!("{:02x}", byte).repeat(32)
}

pub fn make_test_realm(repo: Uuid, tenant: Uuid) -> GrantExpectedRealm {
    GrantExpectedRealm {
        tenant_id: tenant,
        repository_id: repo,
        group_id: 42,
        group_epoch: 3,
        history_incarnation: Uuid::from_u128(0xdead_beef_cafe_babe_0000_0000_0000_0152),
        authority_epoch: 5,
    }
}

pub fn make_service_identity(issuer_id: Uuid, san: &str) -> ServiceMtlsIdentity {
    ServiceMtlsIdentity { san_identity: san.to_owned(), issuer_id }
}

pub fn make_test_keyring(current_key_id: u8) -> DecisionGrantKeyring {
    DecisionGrantKeyring::new(
        [(1u8, Zeroizing::new([0x21u8; 32])), (2u8, Zeroizing::new([0x42u8; 32]))],
        current_key_id,
        BTreeSet::new(),
    )
    .expect("build test decision grant keyring")
}

pub fn gate_base_digest_hex(repo: Uuid, realm: &GrantExpectedRealm) -> String {
    let mut sm = RefCasStateMachine::new();
    match sm.apply(log_id(1), init_gate_cmd(repo, realm, 1)).expect("init gate for digest") {
        ApplyResponse::GateInitialized { version, .. } => version.digest().as_hex(),
        other => panic!("unexpected init gate response: {other:?}"),
    }
}

pub fn init_gate_cmd(repo: Uuid, realm: &GrantExpectedRealm, authz_floor: i64) -> RefCasCommand {
    RefCasCommand::InitializeGate(InitializeGateCommand {
        gate: WireGateInit {
            repository_id: repo,
            tenant_id: realm.tenant_id,
            object_format: GitObjectFormat::Sha256,
            history_incarnation: realm.history_incarnation,
            authority_epoch: realm.authority_epoch,
            group_epoch: realm.group_epoch,
            head_ref: "refs/heads/main".to_owned(),
        },
        lane: RepositoryLane::ServingRefStore,
        pack_mode: SmPackMode::MetadataOnly,
        authz_floor,
    })
}

pub fn acquire_holds_cmd(
    realm: &GrantExpectedRealm,
    owner_id: Uuid,
    operation_id: Uuid,
    hold_ids: &[Uuid],
) -> RefCasCommand {
    let artifacts = hold_ids
        .iter()
        .enumerate()
        .map(|(i, &hold_id)| WireHoldArtifactSpec {
            hold_id,
            slot: i as i16,
            artifact_digest: hex_digest(0xc0 + (i as u8)),
            declared_bytes: 512,
            logical_bytes: 512,
        })
        .collect();
    RefCasCommand::AcquireHoldBatch(AcquireHoldBatchCommand {
        request_id: Uuid::new_v4(),
        consume_request_id: Uuid::new_v4(),
        operation_id,
        repository_id: realm.repository_id,
        tenant_id: realm.tenant_id,
        owner_id,
        purpose: "ref_publication".to_owned(),
        backend_identity: hex_digest(0xde),
        authority_id: Uuid::new_v4(),
        authority_generation: 1,
        expected_gate_digest: gate_base_digest_hex(realm.repository_id, realm),
        artifacts,
    })
}

pub fn build_commit_request(
    realm: &GrantExpectedRealm,
    actor_id: Uuid,
    lane: &str,
    sequence: i64,
    operation_id: Uuid,
    ref_name: &str,
    new_oid_byte: u8,
) -> CommitRefsRequest {
    let old_zero = "00".repeat(32);
    let new_hex = hex_digest(new_oid_byte);
    let pre = GitOid::precondition_value(GitObjectFormat::Sha256, &old_zero).expect("absent pre");
    let target = GitOid::target_value(GitObjectFormat::Sha256, &new_hex).expect("target oid");
    let update = RefUpdate::new(RefName::new(ref_name).expect("valid ref"), pre, target);
    CommitRefsRequest::new(
        realm.repository_id,
        realm.tenant_id,
        actor_id,
        IssuerLane::new(lane).expect("valid lane"),
        sequence,
        operation_id,
        GitObjectFormat::Sha256,
        realm.history_incarnation,
        realm.authority_epoch,
        realm.group_epoch,
        1,
        HeadUpdate::Keep,
        CommitMode::Atomic,
        vec![update],
    )
    .expect("valid commit request")
}

pub fn build_grant_payload(
    realm: &GrantExpectedRealm,
    decision_id: Uuid,
    req: &CommitRefsRequest,
    scope_kind: &str,
    scope_id: Uuid,
    authz_epoch: i64,
    not_after_tick: u64,
) -> SignedDecisionGrantPayload {
    let actor_id = req.identity().issuer_id();
    let svc = make_service_identity(actor_id, "raft-bridge-svc-a");
    let verdicts = req
        .refs()
        .iter()
        .map(|u| WireDecisionVerdict { ref_name: u.name().as_str().to_owned(), accepted: true, reject_code: None })
        .collect();
    SignedDecisionGrantPayload {
        format_version: 1,
        key_id: 1,
        issuer_id: svc.issuer_id,
        service_mtls_identity: svc.san_identity,
        decision_id,
        tenant_id: realm.tenant_id,
        repository_id: realm.repository_id,
        actor_id,
        operation_id: req.identity().operation_id(),
        group_id: realm.group_id,
        group_epoch: realm.group_epoch,
        history_incarnation: realm.history_incarnation,
        authority_epoch: realm.authority_epoch,
        authz_epoch,
        base_revision: req.expected_revision(),
        kind: WireDecisionKind::Atomic,
        not_after_tick,
        command_digest: req.digest().as_hex(),
        selection_digest: hex_digest(0x11),
        policy_digest: hex_digest(0x22),
        facts_digest: hex_digest(0x33),
        authz_digest: hex_digest(0x44),
        dependencies_digest: hex_digest(0x55),
        packs_digest: hex_digest(0x66),
        hold_receipts_digest: hex_digest(0x77),
        captured_oid_digest: hex_digest(0x88),
        base_gate_digest: gate_base_digest_hex(realm.repository_id, realm),
        required_holds: vec![],
        verdicts,
        scope_dependencies: vec![WireDecisionScopeDep {
            scope_kind: scope_kind.to_owned(),
            scope_id,
            observed_version: 1,
            observed_digest: hex_digest(0xaa),
        }],
    }
}

pub fn log_id(index: u64) -> AppliedLogId {
    AppliedLogId { term: 1, index }
}
