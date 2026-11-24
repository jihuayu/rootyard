use super::*;
use std::path::PathBuf;

use uuid::Uuid;

use crate::{
    blob_git_gateway::{
        protocol::{PushCommand, PushRequest},
        publish::{Pair, slot_one::SlotOneReceive},
    },
    db::{Identity, Repository},
    ref_store::{
        CommitMode, GitObjectFormat, IssuerLane, OperationState, RequestDigest,
        core::{
            contract::CoreGate,
            pack_commit::{PackCommitBaseline, PackMode},
        },
        pg::{
            public_attempt::{PublicAttempt, PublicAttemptEvidence, PublicAttemptRequest},
            public_terminal::PublicAttemptRetirement,
            slot_zero,
        },
        serving::ServingRepository,
    },
};

const LANE: &str = "blob-git-receive";

fn serving() -> ServingRepository {
    let repository_id = Uuid::new_v4();
    let tenant_id = Uuid::new_v4();
    let gate = CoreGate::new(
        repository_id,
        tenant_id,
        GitObjectFormat::Sha1,
        Uuid::new_v4(),
        1,
        1,
        crate::ref_store::RefName::new("refs/heads/main").unwrap(),
        7,
    )
    .unwrap();
    ServingRepository {
        repository: Repository {
            id: repository_id,
            name: "receive-provenance".to_owned(),
            owner: "owner".to_owned(),
            state: "ready".to_owned(),
            clone_path: "/git/owner/receive-provenance.git".to_owned(),
            storage_backend: "pg_refstore".to_owned(),
            storage_generation: 1,
            object_format: "sha1".to_owned(),
        },
        gate,
        cluster_incarnation: Uuid::new_v4(),
    }
}

fn wire_request(atomic: bool) -> PushRequest {
    let mut capabilities = vec!["report-status".to_owned()];
    if atomic {
        capabilities.push("atomic".to_owned());
    }
    PushRequest {
        commands: vec![
            PushCommand { old: "1".repeat(40), new: "2".repeat(40), name: "refs/heads/main".to_owned() },
            PushCommand { old: "3".repeat(40), new: "4".repeat(40), name: "refs/heads/side".to_owned() },
        ],
        capabilities,
    }
}

fn mode_for(request: &PushRequest) -> CommitMode {
    if request.wants_atomic() { CommitMode::Atomic } else { CommitMode::AcceptedSubset }
}

fn staged_pair(name: &str, pack_digit: char, idx_digit: char) -> Pair {
    Pair {
        pack: PathBuf::from(format!("/staged/{name}.pack")),
        idx: PathBuf::from(format!("/staged/{name}.idx")),
        pack_id: Uuid::new_v4(),
        pack_sha: pack_digit.to_string().repeat(64),
        pack_len: 101,
        idx_sha: idx_digit.to_string().repeat(64),
        idx_len: 37,
    }
}

fn staged_pairs() -> Vec<Pair> {
    vec![staged_pair("first", 'a', 'b'), staged_pair("second", 'c', 'd')]
}

fn verified_receive<'a>(
    actor: &'a Identity,
    serving: &ServingRepository,
    operation: Uuid,
    request: PushRequest,
    mode: CommitMode,
    digest: RequestDigest,
    pairs: Vec<Pair>,
) -> VerifiedReceive<'a> {
    ReceiveInput {
        actor,
        operation,
        repository_id: serving.gate.repository_id(),
        object_format: serving.gate.object_format(),
        request,
        mode,
        digest,
    }
    .complete(pairs)
}

fn baseline(serving: &ServingRepository) -> PackCommitBaseline {
    PackCommitBaseline::new(serving.gate.version(), PackMode::MetadataOnly, Vec::new(), Vec::new()).unwrap()
}

fn public_request(
    serving: &ServingRepository,
    actor: &Identity,
    public_id: Uuid,
    digest: RequestDigest,
    mode: CommitMode,
) -> PublicAttemptRequest {
    PublicAttemptRequest {
        repository_id: serving.gate.repository_id(),
        admission_owner_id: serving.gate.tenant_id(),
        issuer_id: actor.id,
        public_id,
        wire_digest: digest,
        request_mode: mode,
        backend_identity: "a".repeat(64),
        object_format: serving.gate.object_format(),
        history_incarnation: serving.gate.history_incarnation(),
        authority_epoch: serving.gate.authority_epoch(),
        group_epoch: serving.gate.group_epoch(),
        restore_incarnation: serving.cluster_incarnation,
    }
}

fn rejected_evidence(
    public: &PublicAttemptRequest,
    private_id: Uuid,
    event_id: Uuid,
    base_revision: i64,
    event_revision: i64,
) -> PublicAttemptEvidence {
    let mut current = PublicAttempt {
        slot: 0,
        private_id,
        plan_digest: RequestDigest::of("receive-provenance-plan", &[b"plan"]),
        proof_digest: RequestDigest::of("receive-provenance-proof", &[b"placeholder"]),
        base_revision,
        lane: IssuerLane::new(LANE).unwrap(),
        sequence: 4,
        state: OperationState::Rejected,
        event_id: Some(event_id),
        event_revision: Some(event_revision),
    };
    current.proof_digest = slot_zero::recompute_slot_zero_proof(public, &current).unwrap();
    PublicAttemptEvidence { public_id: public.public_id, current, retired: Vec::new() }
}

fn retirement(event_id: Uuid, event_revision: i64) -> PublicAttemptRetirement {
    PublicAttemptRetirement { event_id, event_revision }
}

#[test]
fn completed_receive_preserves_exact_commands_capability_mode_digest_and_pair_order() {
    let serving = serving();
    let actor = Identity {
        id: Uuid::new_v4(),
        token_id: Uuid::new_v4(),
        parent_token_id: None,
        username: "actor".to_owned(),
        read_only: false,
        token_digest: vec![0; 32],
    };
    let request = wire_request(true);
    let mode = mode_for(&request);
    let digest = RequestDigest::of("receive-provenance-wire", &[b"body"]);
    let operation = Uuid::new_v4();
    let pairs = staged_pairs();
    let expected_pairs = pairs
        .iter()
        .map(|pair| {
            (
                pair.pack.clone(),
                pair.idx.clone(),
                pair.pack_sha.clone(),
                pair.pack_len,
                pair.idx_sha.clone(),
                pair.idx_len,
            )
        })
        .collect::<Vec<_>>();
    let verified = verified_receive(&actor, &serving, operation, request.clone(), mode, digest, pairs);

    assert!(std::ptr::eq(verified.actor(), &actor));
    assert_eq!(verified.operation_id(), operation);
    assert_eq!(verified.repository_id(), serving.gate.repository_id());
    assert_eq!(verified.object_format(), serving.gate.object_format());
    assert_eq!(verified.request(), &request);
    assert_eq!(verified.mode(), CommitMode::Atomic);
    assert_eq!(verified.digest(), digest);
    assert_eq!(verified.pairs().len(), expected_pairs.len());
    for (observed, (pack, idx, pack_sha, pack_len, idx_sha, idx_len)) in verified.pairs().iter().zip(&expected_pairs) {
        assert_eq!(observed.pack, *pack);
        assert_eq!(observed.idx, *idx);
        assert_eq!(observed.pack_sha, *pack_sha);
        assert_eq!(observed.pack_len, *pack_len);
        assert_eq!(observed.idx_sha, *idx_sha);
        assert_eq!(observed.idx_len, *idx_len);
    }
}

#[test]
fn handoff_uses_only_completed_receive_and_exact_retirement() {
    let serving = serving();
    let actor = Identity {
        id: Uuid::new_v4(),
        token_id: Uuid::new_v4(),
        parent_token_id: None,
        username: "actor".to_owned(),
        read_only: false,
        token_digest: vec![0; 32],
    };
    let request = wire_request(false);
    let mode = mode_for(&request);
    let digest = RequestDigest::of("receive-provenance-handoff", &[b"body"]);
    let operation = Uuid::new_v4();
    let pairs = staged_pairs();
    let verified = verified_receive(&actor, &serving, operation, request.clone(), mode, digest, pairs);
    let baseline = baseline(&serving);
    let public = public_request(&serving, &actor, operation, digest, mode);
    let private_id = Uuid::new_v4();
    let event_id = Uuid::new_v4();
    let evidence = rejected_evidence(&public, private_id, event_id, 6, 7);
    let retirement = retirement(event_id, 7);

    let handoff =
        SlotOneReceive::from_verified_rejection(&serving, &verified, &baseline, "a".repeat(64), &evidence, &retirement)
            .unwrap();

    assert_eq!(handoff.public().public_id, operation);
    assert_eq!(handoff.public().wire_digest, digest);
    assert_eq!(handoff.public().request_mode, mode);
    assert_eq!(handoff.public().admission_owner_id, serving.gate.tenant_id());
    assert!(std::ptr::eq(handoff.actor(), verified.actor()));
    assert!(std::ptr::eq(handoff.request(), verified.request()));
    assert_eq!(handoff.pairs().as_ptr(), verified.pairs().as_ptr());
    assert_eq!(handoff.request(), &request);
    assert_eq!(handoff.retirement(), &retirement);
    assert!(!format!("{handoff:?}").contains(&private_id.to_string()));
    assert!(!format!("{handoff:?}").contains(&event_id.to_string()));
    assert!(!format!("{handoff:?}").contains(&"a".repeat(64)));
}

#[test]
fn only_the_exact_current_slot_zero_retirement_is_accepted() {
    let serving = serving();
    let actor = Identity {
        id: Uuid::new_v4(),
        token_id: Uuid::new_v4(),
        parent_token_id: None,
        username: "actor".to_owned(),
        read_only: false,
        token_digest: vec![0; 32],
    };
    let request = wire_request(false);
    let mode = mode_for(&request);
    let digest = RequestDigest::of("receive-provenance-invalid", &[b"body"]);
    let operation = Uuid::new_v4();
    let pairs = staged_pairs();
    let verified = verified_receive(&actor, &serving, operation, request, mode, digest, pairs);
    let baseline = baseline(&serving);
    let public = public_request(&serving, &actor, operation, digest, mode);
    let private_id = Uuid::new_v4();
    let event_id = Uuid::new_v4();
    let valid = rejected_evidence(&public, private_id, event_id, 6, 7);
    let valid_retirement = retirement(event_id, 7);

    let cases = [
        {
            let mut evidence = valid.clone();
            evidence.current.slot = 1;
            ("slot one is current", evidence, valid_retirement.clone())
        },
        {
            let mut evidence = valid.clone();
            evidence.current.state = OperationState::Pending;
            ("not rejected", evidence, valid_retirement.clone())
        },
        {
            let mut evidence = valid.clone();
            evidence.retired.push(valid.current.clone());
            ("already retired", evidence, valid_retirement.clone())
        },
        {
            let mut evidence = valid.clone();
            evidence.current.event_id = Some(Uuid::new_v4());
            ("different event", evidence, valid_retirement.clone())
        },
        {
            let mut evidence = valid.clone();
            evidence.current.proof_digest = RequestDigest::of("receive-provenance-wrong-proof", &[b"body"]);
            ("different proof", evidence, valid_retirement.clone())
        },
        {
            let mut evidence = valid.clone();
            evidence.public_id = Uuid::new_v4();
            ("different public id", evidence, valid_retirement.clone())
        },
        ("different revision", valid.clone(), retirement(event_id, 8)),
    ];

    for (label, evidence, retirement) in cases {
        let error = SlotOneReceive::from_verified_rejection(
            &serving,
            &verified,
            &baseline,
            "a".repeat(64),
            &evidence,
            &retirement,
        )
        .unwrap_err();
        assert!(matches!(error, GatewayError::Internal(_)), "{label}: {error:?}");
        assert!(!error.message().contains(&private_id.to_string()), "{label}");
        assert!(!format!("{error:?}").contains(&private_id.to_string()), "{label}");
        assert!(!format!("{error:?}").contains(&event_id.to_string()), "{label}");
    }
}

#[test]
fn handoff_refuses_receive_provenance_from_another_repository() {
    let original = serving();
    let other = serving();
    let actor = Identity {
        id: Uuid::new_v4(),
        token_id: Uuid::new_v4(),
        parent_token_id: None,
        username: "actor".to_owned(),
        read_only: false,
        token_digest: vec![0; 32],
    };
    let request = wire_request(false);
    let mode = mode_for(&request);
    let digest = RequestDigest::of("receive-provenance-foreign", &[b"body"]);
    let operation = Uuid::new_v4();
    let verified = verified_receive(&actor, &original, operation, request, mode, digest, staged_pairs());
    let other_baseline = baseline(&other);
    let public = public_request(&other, &actor, operation, digest, mode);
    let event_id = Uuid::new_v4();
    let evidence = rejected_evidence(&public, Uuid::new_v4(), event_id, 6, 7);
    let retirement = retirement(event_id, 7);

    let error = SlotOneReceive::from_verified_rejection(
        &other,
        &verified,
        &other_baseline,
        "a".repeat(64),
        &evidence,
        &retirement,
    )
    .unwrap_err();
    assert!(matches!(error, GatewayError::Internal(_)), "{error:?}");
    assert!(!format!("{error:?}").contains(&operation.to_string()));
}

#[test]
fn receive_value_is_completed_only_by_the_producer() {
    let source = include_str!("../receive.rs");
    let (production, _) = source.split_once("#[cfg(test)]\nmod tests;").expect("production source");
    assert!(production.contains("struct ReceiveInput<'a> {"));
    assert!(!production.contains("pub(super) struct ReceiveInput<'a>"));
    assert!(production.contains("fn complete(self, pairs: Vec<Pair>) -> VerifiedReceive<'a>"));
    assert!(!production.contains("pub(super) fn complete("));
    assert_eq!(production.matches("ReceiveInput {").count(), 1);
    assert_eq!(production.matches(".complete(pairs)").count(), 1);
    let fields = production
        .split("pub(super) struct VerifiedReceive<'a> {")
        .nth(1)
        .expect("verified receive")
        .split('}')
        .next()
        .expect("verified receive fields");
    for field in ["actor:", "operation:", "repository_id:", "object_format:", "request:", "mode:", "digest:", "pairs:"]
    {
        assert!(fields.contains(field));
        assert!(!fields.contains(&format!("pub {field}")));
    }
}
