//! Owner and tenant scope regressions: one mutation per field.
//!
//! Every case keeps the digest in sync with its rows, so the canonical rebuild
//! can never stand in for the owner chain, and keeps the legal producer
//! distinct from the repository tenant. A root requester is a separate identity
//! and is covered by the `ledger_sets_tests` fixture.
use super::declared_owner_scope::{declared_binding, declared_violations};
use super::*;
use crate::backup::ledger::{ack_owner_differs, ack_repository_differs, ack_scope_differs, ack_tenant_differs};
use crate::backup::ledger_canonical::canonical;
use crate::ref_store::artifact_hold::{ConsumeAck, HoldArtifactIdentity};
use crate::ref_store::core::artifact_hold::ArtifactHoldPurpose;
use crate::ref_store::core::pack_commit::{
    ArtifactLocator, ArtifactSetDigest, ContentDigest, PackArtifactRole, RegisteredArtifact,
};
use crate::ref_store::core::types::GitObjectFormat;

const REPO: Uuid = Uuid::from_u128(0x0100);
const TENANT: Uuid = Uuid::from_u128(0x0200);
const PRODUCER: Uuid = Uuid::from_u128(0x0300);
const PACK: Uuid = Uuid::from_u128(0x0400);
const REGISTRATION: Uuid = Uuid::from_u128(0x0500);
const INCARNATION: Uuid = Uuid::from_u128(0x0600);
const ACQUIRE: Uuid = Uuid::from_u128(0x0700);
const CONSUME: Uuid = Uuid::from_u128(0x0800);
const PACK_HOLD: Uuid = Uuid::from_u128(0x0900);
const IDX_HOLD: Uuid = Uuid::from_u128(0x0a00);
const AUTH: Uuid = Uuid::from_u128(0x0b00);
const PACK_ATTEMPT: Uuid = Uuid::from_u128(0x0c00);
const IDX_ATTEMPT: Uuid = Uuid::from_u128(0x0d00);
const GATE_REVISION: i64 = 7;
const JOINED: i64 = GATE_REVISION + 1;

/// A second, distinct tenant: the repository/gate tenant drifts away from the
/// publication tenant.
const OTHER_TENANT: Uuid = Uuid::from_u128(0x1900);
/// An A3 owner that is neither the producer nor the tenant.
const OTHER_OWNER: Uuid = Uuid::from_u128(0x1b00);

fn sha(byte: u8) -> String {
    hex::encode([byte; 32])
}

/// One declared registration whose rows all carry the legal scope: tenant
/// `TENANT`, producer `PRODUCER` (a distinct identity).
fn declared() -> DeclaredPair {
    let mut pair = DeclaredPair {
        repository_id: REPO,
        pack_id: PACK,
        registration_id: REGISTRATION,
        declared_by: vec!["membership".into()],
        declared_sets: Vec::new(),
        actual: ActualRepository { owner_id: Some(TENANT), gate_tenant_id: Some(TENANT) },
        publication: None,
        artifacts: Vec::new(),
        scope: Vec::new(),
    };
    let artifacts = pair_artifacts();
    let digest = ArtifactSetDigest::of(
        &artifacts.iter().map(|artifact| registered(artifact).expect("canonical row")).collect::<Vec<_>>(),
    )
    .as_hex();
    pair.declared_sets = vec![("membership".into(), digest.clone(), JOINED)];
    pair.publication = Some(PublishedPack {
        repository_id: REPO,
        pack_id: PACK,
        tenant_id: TENANT,
        owner_id: PRODUCER,
        history_incarnation: INCARNATION,
        authority_epoch: 1,
        group_epoch: 1,
        object_format: "sha1".into(),
        gate_revision: GATE_REVISION,
        acquire_request_id: ACQUIRE,
        consume_request_id: CONSUME,
        digest,
    });
    pair.artifacts = artifacts;
    pair.scope = declared_violations(&pair);
    assert!(pair.scope.is_empty(), "the legal fixture must have no scope lines: {:?}", pair.scope);
    pair
}

fn pair_artifacts() -> Vec<PairArtifact> {
    [("pack", 0, PACK_HOLD, PACK_ATTEMPT, 0x21, 1024), ("idx", 1, IDX_HOLD, IDX_ATTEMPT, 0x22, 256)]
        .into_iter()
        .map(|(role, slot, hold, attempt, digest, length)| PairArtifact {
            role: role.into(),
            slot,
            hold_id: hold,
            acquire_request_id: ACQUIRE,
            consume_request_id: CONSUME,
            provider: "s3".into(),
            backend_identity: sha(0x11),
            sha256: sha(digest),
            length,
            tenant_id: TENANT,
            authority_id: AUTH,
            generation: 3,
            attempt_id: attempt,
            namespace: "core-pack".into(),
            repository_id: REPO,
            pack_id: PACK,
            request: Some(RequestRow { repository_id: REPO, tenant_id: TENANT, owner_id: PRODUCER }),
            hold: Some(HoldRow {
                request_id: ACQUIRE,
                slot,
                repository_id: REPO,
                tenant_id: TENANT,
                owner_id: PRODUCER,
                provider: "s3".into(),
                backend_identity: sha(0x11),
                storage_tenant_id: TENANT,
                authority_id: AUTH,
                generation: 3,
                attempt_id: attempt,
                namespace: "core-pack".into(),
                sha256: sha(digest),
                length,
            }),
            receipt: true,
            receipt_scope: Some(ReceiptRow { repository_id: REPO, tenant_id: TENANT, owner_id: PRODUCER }),
            issuer_operation: true,
            hold_slot: Some(slot),
        })
        .collect()
}

fn registered(artifact: &PairArtifact) -> Result<RegisteredArtifact, ()> {
    let sha = ContentDigest::parse(artifact.sha256.clone()).map_err(|_| ())?;
    RegisteredArtifact::new(
        PackArtifactRole::parse(&artifact.role).unwrap(),
        artifact.slot,
        artifact.hold_id,
        ArtifactLocator::new(
            artifact.tenant_id,
            artifact.authority_id,
            artifact.generation,
            artifact.attempt_id,
            artifact.namespace.clone(),
            sha.clone(),
            artifact.length,
        )
        .unwrap(),
        artifact.provider.clone(),
        artifact.backend_identity.clone(),
        sha,
        artifact.length,
    )
    .map_err(|_| ())
}

/// Re-seal the stored digest of the mutated artifact rows, so the canonical
/// rebuild cannot stand in for an owner check.
fn resealed(pair: &mut DeclaredPair) {
    let digest =
        ArtifactSetDigest::of(&pair.artifacts.iter().filter_map(|a| registered(a).ok()).collect::<Vec<_>>()).as_hex();
    pair.publication.as_mut().unwrap().digest = digest.clone();
    for set in &mut pair.declared_sets {
        set.1 = digest.clone();
    }
    // The decoder stores the same lines on the pair.
    pair.scope = declared_violations(pair);
}

fn at(index: usize) -> String {
    let role = if index == 0 { "pack" } else { "idx" };
    format!("{REPO}:{PACK}:{REGISTRATION}:{role}:{index}")
}

/// The publication owner is the A3 producer: each one of the acquire request,
/// both durable holds, both consume receipts and the typed ACK body must carry
/// it. A producer distinct from the tenant is legal; a drift is not.
#[test]
fn the_publication_producer_is_each_artifact_owner() {
    let mutations: &[(&str, fn(&mut DeclaredPair))] = &[
        ("publication_owner", |pair| pair.publication.as_mut().unwrap().owner_id = OTHER_OWNER),
        ("request_owner_pack", |pair| pair.artifacts[0].request.as_mut().unwrap().owner_id = OTHER_OWNER),
        ("request_owner_idx", |pair| pair.artifacts[1].request.as_mut().unwrap().owner_id = OTHER_OWNER),
        ("hold_owner_pack", |pair| pair.artifacts[0].hold.as_mut().unwrap().owner_id = OTHER_OWNER),
        ("hold_owner_idx", |pair| pair.artifacts[1].hold.as_mut().unwrap().owner_id = OTHER_OWNER),
        ("receipt_owner_pack", |pair| pair.artifacts[0].receipt_scope.as_mut().unwrap().owner_id = OTHER_OWNER),
        ("receipt_owner_idx", |pair| pair.artifacts[1].receipt_scope.as_mut().unwrap().owner_id = OTHER_OWNER),
    ];
    // A producer distinct from the tenant is legal.
    assert_ne!(PRODUCER, TENANT);
    assert_eq!(check_declared(&[declared()]), Vec::<String>::new());
    for (field, mutate) in mutations {
        let mut declared = declared();
        mutate(&mut declared);
        let expected: Vec<_> = if *field == "publication_owner" {
            vec![0, 1]
        } else if field.ends_with("pack") {
            vec![0]
        } else {
            vec![1]
        };
        let lines = check_declared(std::slice::from_ref(&declared));
        let expected =
            expected.into_iter().map(|index| format!("owner_scope_mismatch:{}", at(index))).collect::<Vec<_>>();
        assert_eq!(declared.scope, expected, "{field}: {lines:?}");
        assert!(!lines.iter().any(|line| line.contains("digest")), "{field}: {lines:?}");
        assert!(canonical(&declared).is_ok() || *field == "publication_owner", "{field}: {lines:?}");
    }
}

/// The typed consume ACK body is judged by its own fields through the pure
/// helper the inventory decode path uses: a foreign producer, repository or
/// tenant is refused, while a producer distinct from the repository tenant is
/// accepted. The body itself is built by the real `ConsumeAck` in the core;
/// this fixture only varies the three scope fields.
#[test]
fn the_typed_consume_ack_body_carries_the_publication_producer() {
    let publication = declared().publication.clone().unwrap();
    let ack = |owner_id: Uuid, repository_id: Uuid, tenant_id: Uuid| ConsumeAck {
        consume_request_id: CONSUME,
        request_id: ACQUIRE,
        consume_digest: sha(0x41),
        hold_id: PACK_HOLD,
        slot: 0,
        repository_id,
        tenant_id,
        owner_id,
        purpose: ArtifactHoldPurpose::RefPublication,
        object_format: GitObjectFormat::Sha1,
        history_incarnation: INCARNATION,
        authority_epoch: 1,
        group_epoch: 1,
        issuer_id: Uuid::from_u128(0x1e00),
        lane: "core".into(),
        sequence: 1,
        operation_id: Uuid::from_u128(0x1f00),
        operation_digest: sha(0x42),
        gate_revision: GATE_REVISION,
        gate_digest: sha(0x43),
        consumed_at_unix_micros: 1_700_000_000_000_000,
        artifact: HoldArtifactIdentity {
            provider: "s3".into(),
            backend_identity: sha(0x11),
            tenant_id: TENANT,
            authority_id: AUTH,
            authority_generation: 3,
            attempt_id: PACK_ATTEMPT,
            namespace: "core-pack".into(),
            sha256: sha(0x21),
            length: 1024,
        },
    };
    let agrees = |body: &ConsumeAck| ack_scope_differs(body, publication.owner_id, REPO, TENANT);
    // A producer distinct from the tenant is legal.
    assert_ne!(publication.owner_id, TENANT);
    let legal = ack(PRODUCER, REPO, TENANT);
    assert!(!agrees(&legal));
    assert!(!ack_owner_differs(&legal, publication.owner_id));
    assert!(!ack_repository_differs(&legal, REPO));
    assert!(!ack_tenant_differs(&legal, TENANT));
    // Each field alone is refused by the pure helper.
    let moved: [(&str, fn(&ConsumeAck, Uuid) -> bool, ConsumeAck, Uuid); 4] = [
        ("owner", ack_owner_differs, ack(OTHER_OWNER, REPO, TENANT), publication.owner_id),
        ("repository", ack_repository_differs, ack(PRODUCER, Uuid::from_u128(0x1c00), TENANT), REPO),
        ("tenant", ack_tenant_differs, ack(PRODUCER, REPO, OTHER_TENANT), TENANT),
        ("tenant_is_not_producer", ack_tenant_differs, ack(PRODUCER, REPO, PRODUCER), TENANT),
    ];
    for (field, differs, body, expected) in moved {
        assert!(differs(&body, expected), "{field}");
        assert!(agrees(&body), "{field}");
    }
}

/// The publication tenant is the actual repository tenant and the core gate
/// tenant. Its rows keep the legal producer, so when the publication tenant is
/// the one that moves only the binding is refused.
#[test]
fn the_publication_tenant_is_the_actual_repository_and_gate_tenant() {
    let mut fixed = declared();
    fixed.publication.as_mut().unwrap().tenant_id = OTHER_TENANT;
    assert!(!declared_binding(&fixed));
    for mutate in [
        (|pair: &mut DeclaredPair| pair.actual.owner_id = Some(OTHER_TENANT)) as fn(&mut DeclaredPair),
        |pair: &mut DeclaredPair| pair.actual.gate_tenant_id = Some(OTHER_TENANT),
        |pair: &mut DeclaredPair| pair.actual.owner_id = None,
        |pair: &mut DeclaredPair| pair.actual.gate_tenant_id = None,
    ] {
        let mut pair = declared();
        mutate(&mut pair);
        assert!(!declared_binding(&pair));
        assert!(canonical(&pair).is_ok(), "the artifact rows stay canonical");
        let lines = check_declared(std::slice::from_ref(&pair));
        assert!(lines.contains(&format!("publication_binding_mismatch:{REPO}:{PACK}:{REGISTRATION}")), "{lines:?}");
        assert!(!lines.iter().any(|line| line.starts_with("owner_scope_mismatch")), "{lines:?}");
    }
    // The publication tenant moves and every A3 row follows it: the artifact
    // rows stay canonical and the actual repository still refuses.
    let mut moved = declared();
    moved.publication.as_mut().unwrap().tenant_id = OTHER_TENANT;
    for artifact in &mut moved.artifacts {
        artifact.tenant_id = OTHER_TENANT;
        artifact.request.as_mut().unwrap().tenant_id = OTHER_TENANT;
        artifact.hold.as_mut().unwrap().tenant_id = OTHER_TENANT;
        artifact.hold.as_mut().unwrap().storage_tenant_id = OTHER_TENANT;
        artifact.receipt_scope.as_mut().unwrap().tenant_id = OTHER_TENANT;
    }
    resealed(&mut moved);
    let lines = check_declared(std::slice::from_ref(&moved));
    assert!(lines.contains(&format!("publication_binding_mismatch:{REPO}:{PACK}:{REGISTRATION}")), "{lines:?}");
    assert!(lines.iter().all(|line| line.starts_with("publication_binding_mismatch")), "{lines:?}");
}

/// Every artifact row's tenant is the publication (actual repository) tenant.
#[test]
fn every_artifact_tenant_is_the_publication_tenant() {
    let mutations: &[(&str, fn(&mut PairArtifact))] = &[
        ("artifact_tenant", |a| a.tenant_id = OTHER_TENANT),
        ("request_tenant", |a| a.request.as_mut().unwrap().tenant_id = OTHER_TENANT),
        ("hold_tenant", |a| a.hold.as_mut().unwrap().tenant_id = OTHER_TENANT),
        ("storage_tenant", |a| a.hold.as_mut().unwrap().storage_tenant_id = OTHER_TENANT),
        ("receipt_tenant", |a| a.receipt_scope.as_mut().unwrap().tenant_id = OTHER_TENANT),
    ];
    for (field, mutate) in mutations {
        for index in 0..2 {
            let mut pair = declared();
            mutate(&mut pair.artifacts[index]);
            resealed(&mut pair);
            let lines = check_declared(std::slice::from_ref(&pair));
            let expected = format!("owner_scope_mismatch:{}", at(index));
            assert!(lines.contains(&expected), "{field}/{expected}: {lines:?}");
            assert!(!lines.iter().any(|line| line.contains("canonical_pair_mismatch")), "{field}: {lines:?}");
        }
    }
}

/// An artifact row's own repository and pack are not in the locator digest;
/// each is judged against the declared key on its own.
#[test]
fn the_artifact_repository_and_pack_are_the_declared_key() {
    let mutations: &[(&str, fn(&mut PairArtifact))] = &[
        ("artifact_repository", |a| a.repository_id = Uuid::from_u128(0x1c00)),
        ("artifact_pack", |a| a.pack_id = Uuid::from_u128(0x1d00)),
        ("request_repository", |a| a.request.as_mut().unwrap().repository_id = Uuid::from_u128(0x1c00)),
        ("receipt_repository", |a| a.receipt_scope.as_mut().unwrap().repository_id = Uuid::from_u128(0x1c00)),
    ];
    for (field, mutate) in mutations {
        for index in 0..2 {
            let mut pair = declared();
            mutate(&mut pair.artifacts[index]);
            resealed(&mut pair);
            let lines = check_declared(std::slice::from_ref(&pair));
            let expected = format!("owner_scope_mismatch:{}", at(index));
            assert!(lines.contains(&expected), "{field}/{expected}: {lines:?}");
            assert!(
                !lines.iter().any(|line| line.contains("canonical")) && !lines.iter().any(|l| l.contains("digest"))
            );
        }
    }
    // A missing acquire request, hold or receipt is its own refusal, never a
    // silent acceptance or a hidden row.
    for (field, mutate) in [
        ("request", (|a: &mut PairArtifact| a.request = None) as fn(&mut PairArtifact)),
        ("hold", |a| a.hold = None),
        ("receipt", |a| a.receipt = false),
        ("hold_slot", |a| a.hold_slot = None),
    ] {
        let mut pair = declared();
        mutate(&mut pair.artifacts[0]);
        let lines = check_declared(std::slice::from_ref(&pair));
        assert!(lines.contains(&format!("owner_scope_mismatch:{}", at(0))), "{field}: {lines:?}");
    }
}
