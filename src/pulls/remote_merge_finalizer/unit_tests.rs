//! Deterministic unit tests for pre-CAS validation & remote-authz grant verification (`Refs #156`).

use std::collections::{BTreeMap, BTreeSet};

use uuid::Uuid;
use zeroize::Zeroizing;

use crate::ref_store::contract::IssuerLane;
use crate::ref_store::core::command::CommitRefsRequest;
use crate::ref_store::core::contract::CommitMode;
use crate::ref_store::core::state_machine::{
    AppliedLogId, InitializeGateCommand, RefCasCommand, RefCasStateMachine, RepositoryLane, ScopeLifecycle, SmPackMode,
    WireCommitRefsRequest, WireDecisionKind, WireDecisionScopeDep, WireDecisionVerdict, WireGateInit,
};
use crate::ref_store::core::types::{GitObjectFormat, GitOid, HeadUpdate, RefName, RefPrecondition, RefTarget, RefUpdate};
use crate::ref_store::projector::{
    DecisionGrantKeyring, GrantExpectedRealm, ServiceMtlsIdentity, SignedDecisionGrantPayload,
};

use super::coordinator::{InProcessRefCasBackend, MergeAuthorityBackend, PullRemoteMergeProducer};
use super::projector::InMemoryMergeStore;
use super::types::{
    CheckRunSnapshot, LiveAuthzScopeState, MergeAttemptSpec, MergeBindingInputs, MergeFaultInjection,
    MergePullSnapshot, MergeStrategy, ProjectedPullRecord, RemoteMergeError, compute_merge_binding_digest,
};

pub(super) fn hex_oid(fmt: GitObjectFormat, byte: u8) -> String {
    match fmt {
        GitObjectFormat::Sha1 => format!("{byte:02x}").repeat(20),
        GitObjectFormat::Sha256 => format!("{byte:02x}").repeat(32),
    }
}

pub(super) fn hex_digest(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

pub(crate) struct Fixture {
    pub(crate) tenant_id: Uuid,
    pub(crate) repo_id: Uuid,
    pub(crate) actor_id: Uuid,
    pub(crate) scope_id: Uuid,
    pub(crate) realm: GrantExpectedRealm,
    pub(crate) svc: ServiceMtlsIdentity,
    pub(crate) keyring: DecisionGrantKeyring,
    pub(crate) backend: InProcessRefCasBackend,
    pub(crate) store: InMemoryMergeStore,
    pub(crate) base_oid: String,
    pub(crate) head_oid: String,
    pub(crate) base_revision: i64,
    pub(crate) base_gate_digest: String,
}

pub(crate) fn setup_fixture(fmt: GitObjectFormat) -> Fixture {
    let (tenant_id, repo_id, actor_id, scope_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let realm = GrantExpectedRealm {
        tenant_id,
        repository_id: repo_id,
        group_id: 7,
        group_epoch: 2,
        history_incarnation: Uuid::new_v4(),
        authority_epoch: 3,
    };
    let svc = ServiceMtlsIdentity { san_identity: "raft-bridge-pulls-156".into(), issuer_id: actor_id };
    let keyring = DecisionGrantKeyring::new(
        [(1u8, Zeroizing::new([0x31u8; 32])), (2u8, Zeroizing::new([0x62u8; 32]))],
        2,
        BTreeSet::new(),
    )
    .unwrap();
    let (base_oid, head_oid) = (hex_oid(fmt, 0x11), hex_oid(fmt, 0x22));

    let mut sm = RefCasStateMachine::new();
    sm.apply(
        AppliedLogId { term: 1, index: 1 },
        RefCasCommand::InitializeGate(InitializeGateCommand {
            gate: WireGateInit {
                repository_id: repo_id,
                tenant_id,
                object_format: fmt,
                history_incarnation: realm.history_incarnation,
                authority_epoch: realm.authority_epoch,
                group_epoch: realm.group_epoch,
                head_ref: "refs/heads/main".into(),
            },
            lane: RepositoryLane::ServingRefStore,
            pack_mode: SmPackMode::MetadataOnly,
            authz_floor: 1,
        }),
    )
    .unwrap();

    let seed_req = CommitRefsRequest::new(
        repo_id,
        tenant_id,
        actor_id,
        IssuerLane::new("seed").unwrap(),
        1,
        Uuid::new_v4(),
        fmt,
        realm.history_incarnation,
        realm.authority_epoch,
        realm.group_epoch,
        1,
        HeadUpdate::Keep,
        CommitMode::Atomic,
        vec![RefUpdate::new(
            RefName::branch("refs/heads/main").unwrap(),
            RefPrecondition::Absent,
            RefTarget::Oid(GitOid::parse(fmt, &base_oid).unwrap()),
        )],
    )
    .unwrap();
    sm.apply(
        AppliedLogId { term: 1, index: 2 },
        RefCasCommand::CommitRefs(crate::ref_store::core::state_machine::CommitRefsCommand {
            request: WireCommitRefsRequest::from(&seed_req),
            decision_id: None,
            required_holds: vec![],
            policy_rejects: BTreeMap::new(),
            logical_tick: 5,
        }),
    )
    .unwrap();
    let gate_ver = sm.read_gate_version(repo_id).unwrap().unwrap();
    let store = InMemoryMergeStore::new();
    store.seed_pull(ProjectedPullRecord {
        tenant_id,
        repository_id: repo_id,
        pull_number: 1,
        state: "open".into(),
        head_oid: head_oid.clone(),
        base_oid: base_oid.clone(),
        merge_commit_oid: None,
        merged_storage_generation: None,
        version: 1,
    });

    Fixture {
        tenant_id,
        repo_id,
        actor_id,
        scope_id,
        realm,
        svc,
        keyring,
        backend: InProcessRefCasBackend::new(sm),
        store,
        base_oid,
        head_oid,
        base_revision: gate_ver.revision(),
        base_gate_digest: gate_ver.digest().as_hex(),
    }
}

pub(crate) fn build_spec_and_pull(
    f: &Fixture,
    pull_number: i64,
    seq: i64,
    authz_epoch: i64,
) -> (MergeAttemptSpec, MergePullSnapshot) {
    build_spec_with_target(f, pull_number, seq, authz_epoch, &f.head_oid)
}

pub(super) fn build_spec_with_target(
    f: &Fixture,
    pull_number: i64,
    seq: i64,
    authz_epoch: i64,
    target_oid: &str,
) -> (MergeAttemptSpec, MergePullSnapshot) {
    let (op_id, dec_id) = (Uuid::new_v4(), Uuid::new_v4());
    let required_checks = vec!["ci/verify".to_owned()];
    let pull = MergePullSnapshot {
        tenant_id: f.tenant_id,
        repository_id: f.repo_id,
        pull_number,
        state: "open".into(),
        head_ref: format!("refs/heads/pr-{pull_number}"),
        base_ref: "refs/heads/main".into(),
        head_oid: f.head_oid.clone(),
        base_oid: f.base_oid.clone(),
        merge_commit_oid: None,
        version: 1,
        storage_generation: 1,
        object_format: GitObjectFormat::Sha256,
        live_head_ref_oid: f.head_oid.clone(),
        live_base_ref_oid: f.base_oid.clone(),
        require_fast_forward: true,
        required_checks: required_checks.clone(),
        min_check_sequence: 1,
        observed_checks: vec![CheckRunSnapshot {
            context: "ci/verify".into(),
            commit_oid: f.head_oid.clone(),
            base_oid: Some(f.base_oid.clone()),
            status: "completed".into(),
            conclusion: Some("success".into()),
            sequence: 1,
            attempt: 1,
            trusted: true,
        }],
    };
    let commit_req = CommitRefsRequest::new(
        f.repo_id,
        f.tenant_id,
        f.actor_id,
        IssuerLane::new("pull-merge").unwrap(),
        seq,
        op_id,
        GitObjectFormat::Sha256,
        f.realm.history_incarnation,
        f.realm.authority_epoch,
        f.realm.group_epoch,
        f.base_revision,
        HeadUpdate::Keep,
        CommitMode::Atomic,
        vec![RefUpdate::new(
            RefName::branch("refs/heads/main").unwrap(),
            RefPrecondition::Present(GitOid::parse(GitObjectFormat::Sha256, &f.base_oid).unwrap()),
            RefTarget::Oid(GitOid::parse(GitObjectFormat::Sha256, target_oid).unwrap()),
        )],
    )
    .unwrap();
    let psha = hex_digest(0x99);
    let binding = compute_merge_binding_digest(&MergeBindingInputs {
        tenant_id: f.tenant_id,
        repository_id: f.repo_id,
        pull_number,
        actor_id: f.actor_id,
        operation_id: op_id,
        decision_id: dec_id,
        base_ref: "refs/heads/main",
        expected_head_oid: &f.head_oid,
        expected_base_oid: &f.base_oid,
        candidate_target_oid: target_oid,
        strategy: MergeStrategy::FastForward,
        expected_version: 1,
        expected_storage_generation: 1,
        required_checks: &required_checks,
        observed_checks: &pull.observed_checks,
        min_check_sequence: 1,
        authz_epoch,
        pack_sha256: &psha,
    });
    let grant = f
        .keyring
        .sign(SignedDecisionGrantPayload {
            format_version: 1,
            key_id: f.keyring.current_key_id(),
            issuer_id: f.svc.issuer_id,
            service_mtls_identity: f.svc.san_identity.clone(),
            decision_id: dec_id,
            tenant_id: f.tenant_id,
            repository_id: f.repo_id,
            actor_id: f.actor_id,
            operation_id: op_id,
            group_id: f.realm.group_id,
            group_epoch: f.realm.group_epoch,
            history_incarnation: f.realm.history_incarnation,
            authority_epoch: f.realm.authority_epoch,
            authz_epoch,
            base_revision: f.base_revision,
            kind: WireDecisionKind::Atomic,
            not_after_tick: 1000,
            command_digest: commit_req.digest().as_hex(),
            selection_digest: hex_digest(0x41),
            policy_digest: hex_digest(0x42),
            facts_digest: binding,
            authz_digest: hex_digest(0x44),
            dependencies_digest: hex_digest(0x45),
            packs_digest: hex_digest(0x46),
            hold_receipts_digest: hex_digest(0x47),
            captured_oid_digest: hex_digest(0x48),
            base_gate_digest: f.base_gate_digest.clone(),
            required_holds: vec![],
            verdicts: vec![WireDecisionVerdict { ref_name: "refs/heads/main".into(), accepted: true, reject_code: None }],
            scope_dependencies: vec![WireDecisionScopeDep {
                scope_kind: "token".into(),
                scope_id: f.scope_id,
                observed_version: 1,
                observed_digest: hex_digest(0x55),
            }],
        })
        .unwrap();
    let spec = MergeAttemptSpec {
        attempt_id: Uuid::new_v4(),
        operation_id: op_id,
        decision_id: dec_id,
        tenant_id: f.tenant_id,
        repository_id: f.repo_id,
        actor_id: f.actor_id,
        lane: "pull-merge".into(),
        sequence: seq,
        pull_number,
        base_ref: "refs/heads/main".into(),
        expected_head_oid: f.head_oid.clone(),
        expected_base_oid: f.base_oid.clone(),
        candidate_target_oid: target_oid.to_owned(),
        expected_version: 1,
        expected_storage_generation: 1,
        expected_base_revision: f.base_revision,
        strategy: MergeStrategy::FastForward,
        object_format: GitObjectFormat::Sha256,
        realm: f.realm.clone(),
        expected_service_san: f.svc.san_identity.clone(),
        grant,
        current_logical_tick: 20,
        live_scopes: vec![LiveAuthzScopeState {
            scope_kind: "token".into(),
            scope_id: f.scope_id,
            lifecycle: ScopeLifecycle::Open,
            authz_floor: 2,
        }],
        cancelled_operations: BTreeSet::new(),
        pack_sha256: hex_digest(0x99),
    };
    (spec, pull)
}

#[tokio::test]
async fn fail_closed_checks_head_base_and_revoked_grants_return_named_errors() {
    let f = setup_fixture(GitObjectFormat::Sha256);
    let prod = PullRemoteMergeProducer::new(&f.backend, &f.store, &f.keyring);
    let (spec, pull) = build_spec_and_pull(&f, 1, 1, 5);

    let mut bad_pull = pull.clone();
    bad_pull.observed_checks[0].commit_oid = hex_oid(GitObjectFormat::Sha256, 0x99);
    assert!(matches!(prod.execute_merge(&spec, &bad_pull, true, MergeFaultInjection::None).await, Err(RemoteMergeError::StaleRequiredChecks { .. })));

    let mut stale_head = pull.clone();
    stale_head.live_head_ref_oid = hex_oid(GitObjectFormat::Sha256, 0x33);
    assert!(matches!(prod.execute_merge(&spec, &stale_head, true, MergeFaultInjection::None).await, Err(RemoteMergeError::StaleHeadOid { .. })));

    let mut moved_base = pull.clone();
    moved_base.live_base_ref_oid = hex_oid(GitObjectFormat::Sha256, 0x44);
    assert!(matches!(prod.execute_merge(&spec, &moved_base, true, MergeFaultInjection::None).await, Err(RemoteMergeError::TargetRefMoved { .. })));

    let mut forged = spec.clone();
    forged.grant.payload.authz_epoch = 999;
    assert!(matches!(prod.execute_merge(&forged, &pull, true, MergeFaultInjection::None).await, Err(RemoteMergeError::RemoteAuthzDenied(_))));

    let mut closing = spec.clone();
    closing.live_scopes[0].lifecycle = ScopeLifecycle::Closing;
    assert!(matches!(prod.execute_merge(&closing, &pull, true, MergeFaultInjection::None).await, Err(RemoteMergeError::RevokedAuthorization(_))));

    let mut expired = spec.clone();
    expired.current_logical_tick = 1000;
    assert!(matches!(prod.execute_merge(&expired, &pull, true, MergeFaultInjection::None).await, Err(RemoteMergeError::RevokedAuthorization(_))));

    // Missing/omitted dependency scope in spec.live_scopes must fail closed (never fail open).
    let mut missing_scope = spec.clone();
    missing_scope.live_scopes.clear();
    assert!(matches!(prod.execute_merge(&missing_scope, &pull, true, MergeFaultInjection::None).await, Err(RemoteMergeError::RevokedAuthorization(_))));

    // Later failed/untrusted re-run must override an earlier passing check observation.
    let mut rerun_fail = pull.clone();
    rerun_fail.observed_checks.push(CheckRunSnapshot {
        context: "ci/verify".into(),
        commit_oid: spec.expected_head_oid.clone(),
        base_oid: Some(spec.expected_base_oid.clone()),
        status: "completed".into(),
        conclusion: Some("failure".into()),
        sequence: 2,
        attempt: 1,
        trusted: true,
    });
    assert!(matches!(prod.execute_merge(&spec, &rerun_fail, true, MergeFaultInjection::None).await, Err(RemoteMergeError::StaleRequiredChecks { .. })));

    // Tampered pack_sha256 mismatches signed grant facts_digest.
    let mut bad_pack = spec.clone();
    bad_pack.pack_sha256 = hex_digest(0xaa);
    assert!(matches!(prod.execute_merge(&bad_pack, &pull, true, MergeFaultInjection::None).await, Err(RemoteMergeError::RemoteAuthzDenied(_))));

    // Mutated observed_checks (even with passing/trusted check) mismatches signed grant facts_digest.
    let mut extra_obs = pull.clone();
    extra_obs.observed_checks.push(CheckRunSnapshot {
        context: "ci/extra".into(),
        commit_oid: spec.expected_head_oid.clone(),
        base_oid: Some(spec.expected_base_oid.clone()),
        status: "completed".into(),
        conclusion: Some("success".into()),
        sequence: 3,
        attempt: 1,
        trusted: true,
    });
    assert!(matches!(prod.execute_merge(&spec, &extra_obs, true, MergeFaultInjection::None).await, Err(RemoteMergeError::RemoteAuthzDenied(_))));
    assert_eq!(f.backend.read_ref_oid(f.repo_id, "refs/heads/main").await.unwrap(), Some(f.base_oid));
}
