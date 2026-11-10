//! Database-free regressions for the source-ledger validator.
//!
//! Every case builds the exact row shapes the SQL decodes and proves that the
//! pure checkers refuse a corrupted declared set. Digest and joined-revision
//! mismatches are always re-synced first, so a targeted check is exercised on
//! its own and never refused merely because the artifact-set digest differs. A
//! producer owner distinct from the repository tenant and a released root are
//! valid.
use super::*;
use crate::backup::ledger::captured_refs;
use crate::backup::ledger_canonical::canonical;
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::pack_commit::{
    ArtifactLocator, ArtifactSetDigest, ContentDigest, PackArtifactRole, RegisteredArtifact, RegisteredPack,
};

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
const ROOT: Uuid = Uuid::from_u128(0x0e00);
const GATE_REVISION: i64 = 7;
const JOINED: i64 = GATE_REVISION + 1;
fn realm() -> Realm {
    Realm {
        tenant_id: TENANT,
        history_incarnation: INCARNATION,
        authority_epoch: 1,
        group_epoch: 1,
        object_format: "sha1".into(),
    }
}

fn sha(byte: u8) -> String {
    hex::encode([byte; 32])
}

fn pair_artifact(role: &str, slot: i32, hold: Uuid, attempt: Uuid, digest: u8, length: u64) -> PairArtifact {
    PairArtifact {
        role: role.to_owned(),
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
        hold: Some(HoldRow {
            request_id: ACQUIRE,
            slot,
            repository_id: REPO,
            tenant_id: TENANT,
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
        issuer_operation: true,
    }
}

fn base_artifacts() -> Vec<PairArtifact> {
    vec![
        pair_artifact("pack", 0, PACK_HOLD, PACK_ATTEMPT, 0x21, 1024),
        pair_artifact("idx", 1, IDX_HOLD, IDX_ATTEMPT, 0x22, 256),
    ]
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

fn digest_of(artifacts: &[PairArtifact]) -> String {
    ArtifactSetDigest::of(&artifacts.iter().filter_map(|a| registered(a).ok()).collect::<Vec<_>>()).as_hex()
}

/// The issuer domain of `ArtifactSetDigest::of` over one canonical field list.
/// A corrupted source is written straight to the database (privileged direct
/// SQL bypasses the typed constructors), so its digest is derived from the raw
/// rows instead of from a value the issuer would refuse to build.
fn raw_digest(artifacts: &[PairArtifact]) -> String {
    let mut sorted = artifacts.to_vec();
    sorted.sort_by_key(|a| (a.role.clone(), a.slot));
    let mut fields: Vec<Vec<u8>> = vec![(sorted.len() as u64).to_be_bytes().to_vec()];
    for a in &sorted {
        fields.push(a.role.as_bytes().to_vec());
        fields.push(a.slot.to_be_bytes().to_vec());
        fields.push(a.hold_id.as_bytes().to_vec());
        fields.push(a.tenant_id.as_bytes().to_vec());
        fields.push(a.authority_id.as_bytes().to_vec());
        fields.push(a.generation.to_be_bytes().to_vec());
        fields.push(a.attempt_id.as_bytes().to_vec());
        fields.push(a.namespace.as_bytes().to_vec());
        fields.push(a.sha256.as_bytes().to_vec());
        fields.push(a.length.to_be_bytes().to_vec());
        fields.push(a.provider.as_bytes().to_vec());
        fields.push(a.backend_identity.as_bytes().to_vec());
        fields.push(a.sha256.as_bytes().to_vec());
        fields.push(a.length.to_be_bytes().to_vec());
    }
    let parts = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
    RequestDigest::of("core-pack-artifact-set-v2", &parts).as_hex()
}

/// `pair` with a digest that covers the raw rows exactly as stored.
fn corrupt_pair(artifacts: Vec<PairArtifact>) -> DeclaredPair {
    let digest = raw_digest(&artifacts);
    let mut declared = pair(base_artifacts());
    declared.declared_sets =
        vec![("membership".into(), digest.clone(), JOINED), ("root_packs".into(), digest.clone(), JOINED)];
    declared.publication.as_mut().unwrap().digest = digest;
    declared.artifacts = artifacts;
    declared
}

fn pair(artifacts: Vec<PairArtifact>) -> DeclaredPair {
    let digest = digest_of(&artifacts);
    DeclaredPair {
        repository_id: REPO,
        pack_id: PACK,
        registration_id: REGISTRATION,
        declared_by: vec!["membership".into(), "root_packs".into()],
        declared_sets: vec![
            ("membership".into(), digest.clone(), JOINED),
            ("root_packs".into(), digest.clone(), JOINED),
        ],
        publication: Some(PublishedPack {
            tenant_id: TENANT,
            history_incarnation: INCARNATION,
            authority_epoch: 1,
            group_epoch: 1,
            object_format: "sha1".into(),
            gate_revision: GATE_REVISION,
            acquire_request_id: ACQUIRE,
            consume_request_id: CONSUME,
            digest,
        }),
        artifacts,
    }
}

fn retained_artifact(slot: i32, hold: Uuid, attempt: Uuid, digest: u8, length: u64) -> RetainedArtifact {
    RetainedArtifact {
        slot,
        hold_id: hold,
        tenant_id: TENANT,
        authority_id: AUTH,
        generation: 3,
        attempt_id: attempt,
        namespace: "core-pack".into(),
        sha256: sha(digest),
        length: i64::try_from(length).unwrap(),
        provider: "s3".into(),
        backend_identity: sha(0x11),
        verified_sha256: sha(digest),
        verified_length: i64::try_from(length).unwrap(),
    }
}

fn root_capture() -> RootCapture {
    let oid = "ab".repeat(20);
    RootCapture {
        repository_id: REPO,
        root_id: ROOT,
        generation: 1,
        tenant_id: TENANT,
        realm: realm(),
        ref_count: 1,
        oid_count: 1,
        pack_count: 1,
        refs_digest: String::new(),
        pack_set_digest: String::new(),
        refs: vec![("refs/heads/main".to_owned(), oid.clone())],
        oids: vec![(0, oid)],
        packs: vec![RetainedPack {
            pack_id: PACK,
            registration_id: REGISTRATION,
            artifact_set_digest: String::new(),
            joined_revision: JOINED,
            pack: retained_artifact(0, PACK_HOLD, PACK_ATTEMPT, 0x21, 1024),
            idx: retained_artifact(1, IDX_HOLD, IDX_ATTEMPT, 0x22, 256),
        }],
    }
}

fn head(state: &str, generation: i64) -> RootHead {
    RootHead {
        repository_id: REPO,
        root_id: ROOT,
        tenant_id: TENANT,
        owner_id: PRODUCER,
        purpose: "ci".into(),
        business_intent_digest: sha(0x31),
        register_digest: sha(0x32),
        state: state.into(),
        last_generation: generation,
    }
}

fn tombstone() -> RootTombstone {
    RootTombstone {
        repository_id: REPO,
        root_id: ROOT,
        generation: 2,
        tenant_id: TENANT,
        owner_id: PRODUCER,
        purpose: "ci".into(),
        business_intent_digest: sha(0x31),
        expected_register_digest: sha(0x32),
        release_digest: sha(0x33),
    }
}

/// Seal the derived digests a retained root row stores.
fn seal_root(sets: &mut SourceSets) {
    let declared = sets.declared[0].clone();
    let root = &mut sets.roots[0];
    root.refs_digest = refs_digest(&captured_refs("sha1", root.refs.clone()).expect("refs")).as_hex();
    // A selector OID outside the captured refs is still valid: it is bound
    // through the pack set and the synthetic native ref, not through refs_digest.
    root.oids.push((1, "cd".repeat(20)));
    root.oid_count = 2;
    let _ = (&root.ref_count, &root.pack_count);
    root.packs[0].artifact_set_digest = declared.publication.as_ref().unwrap().digest.clone();
    // What the root read rebuilds: `RegisteredPack::new(stored, [pack, idx], Some(joined))`.
    let pack = RegisteredPack::new(
        PACK,
        REGISTRATION,
        ArtifactSetDigest::from_digest(declared.publication.as_ref().unwrap().digest.parse::<RequestDigest>().unwrap()),
        declared.artifacts.iter().map(|a| registered(a).expect("canonical rows")).collect(),
        Some(JOINED),
    )
    .unwrap();
    root.pack_set_digest = packs_digest(&[pack]).as_hex();
}

/// A legal pair retained by a released root whose producer owner (`PRODUCER`)
/// differs from the repository tenant (`TENANT`).
fn valid_source() -> SourceSets {
    let mut sets = SourceSets {
        declared: vec![pair(base_artifacts())],
        roots: vec![root_capture()],
        heads: vec![head("released", 2)],
        tombstones: vec![tombstone()],
        ..Default::default()
    };
    seal_root(&mut sets);
    sets
}

fn assert_refused(lines: &[String], prefix: &str) {
    assert!(lines.iter().any(|line| line.starts_with(prefix)), "expected {prefix} in {lines:?}");
}

#[test]
fn a_valid_pair_and_released_root_chain_has_no_violations() {
    let sets = valid_source();
    assert_eq!(sets.violations(), Vec::<String>::new());
    assert_eq!(sets.registrations().len(), 1);
}

#[test]
fn missing_artifact_rows_are_refused() {
    for (artifacts, expected) in [
        (vec![base_artifacts()[0].clone()], "incomplete_pair"),
        (vec![base_artifacts()[1].clone()], "incomplete_pair"),
        (Vec::new(), "missing_artifacts"),
    ] {
        assert_refused(&check_declared(&[pair(artifacts)]), expected);
    }
}

#[test]
fn illegal_roles_extra_rows_and_foreign_bindings_are_refused() {
    let mut illegal = base_artifacts();
    illegal[1].slot = 0;
    let lines = check_declared(&[corrupt_pair(illegal)]);
    assert_refused(&lines, "illegal_roles");
    assert!(!lines.iter().any(|line| line.contains("digest")), "digest must agree: {lines:?}");
    let mut extra = base_artifacts();
    extra.push(pair_artifact("idx", 1, Uuid::from_u128(0x0f00), Uuid::from_u128(0x1000), 0x23, 7));
    assert_refused(&check_declared(&[pair(extra)]), "extra_artifacts");
    let mut foreign = base_artifacts();
    foreign[0].acquire_request_id = Uuid::from_u128(0x1100);
    assert_refused(&check_declared(&[pair(foreign)]), "foreign_hold_binding");
    let mut unissued = base_artifacts();
    unissued[1].issuer_operation = false;
    assert_refused(&check_declared(&[pair(unissued)]), "foreign_hold_binding");
}

/// The durable hold's own tenant column must equal the artifact locator tenant;
/// the digest is synced first, so only the tenant check can refuse.
#[test]
fn a_hold_with_another_tenant_is_refused_even_with_a_synced_digest() {
    let mut foreign = base_artifacts();
    foreign[1].hold.as_mut().unwrap().tenant_id = Uuid::from_u128(0x1200);
    let mut storage = base_artifacts();
    storage[0].hold.as_mut().unwrap().storage_tenant_id = Uuid::from_u128(0x1300);
    for artifacts in [foreign, storage] {
        let declared = pair(artifacts);
        assert!(canonical(&declared).is_ok(), "the pair must be canonically valid");
        let lines = check_declared(std::slice::from_ref(&declared));
        assert_refused(&lines, "hold_mismatch");
        assert!(!lines.iter().any(|line| line.contains("digest")), "digest must agree: {lines:?}");
    }
}

#[test]
fn a_missing_hold_or_receipt_is_refused() {
    let mut missing_hold = base_artifacts();
    missing_hold[0].hold = None;
    assert_refused(&check_declared(&[pair(missing_hold)]), "hold_mismatch");
    let mut missing_receipt = base_artifacts();
    missing_receipt[1].receipt = false;
    assert_refused(&check_declared(&[pair(missing_receipt)]), "missing_receipt");
}

#[test]
fn an_unpublished_set_wrong_digest_or_stale_joined_revision_is_refused() {
    let mut unpublished = pair(base_artifacts());
    unpublished.publication = None;
    assert_refused(&check_declared(std::slice::from_ref(&unpublished)), "unregistered_publication");
    // A snapshot or root that still names it is refused through the missing path.
    let missing = check_declared_missing(&[], &[root_capture()], &BTreeSet::new());
    assert_refused(&missing, "unregistered_publication:root_packs");
    let mut wrong = unpublished;
    wrong.publication = valid_source().declared[0].publication.clone();
    wrong.publication.as_mut().unwrap().digest = sha(0x44);
    assert_refused(&check_declared(&[wrong]), "declared_set_digest_mismatch");
    let mut stale = pair(base_artifacts());
    stale.declared_sets[1].2 = GATE_REVISION;
    assert_refused(&check_declared(&[stale]), "declared_joined_revision_mismatch");
}

#[test]
fn a_retained_root_that_is_not_the_canonical_pair_is_refused() {
    let mut altered = valid_source();
    altered.roots[0].packs[0].idx.hold_id = Uuid::from_u128(0x1400);
    assert_refused(&altered.violations(), "root_set_mismatch");
    // A retained subset (no pack row) is not a complete pair either, and the
    // rest of the root (refs) is still validated first.
    let mut subset = valid_source();
    subset.roots[0].pack_count = 0;
    subset.roots[0].packs.clear();
    assert_refused(&subset.violations(), "root_pack_set_mismatch");
    // A root captured in another realm is refused even with identical digest.
    let mut realm = valid_source();
    realm.roots[0].realm.tenant_id = Uuid::from_u128(0x1500);
    assert_refused(&realm.violations(), "root_set_mismatch");
}

#[test]
fn root_lifetime_covers_heads_captures_and_tombstones() {
    let valid = valid_source();
    assert!(valid.violations().is_empty(), "{:?}", valid.violations());
    // An active head whose capture is gone is a lost closure.
    let mut lost = valid.clone();
    lost.heads = vec![head("active", 1)];
    lost.roots.clear();
    assert!(lost.violations().contains(&format!("root_capture_missing:{REPO}:{ROOT}:active")));
    // A capture without its head is invisible and refused.
    let mut headless = valid.clone();
    headless.heads.clear();
    // Release-before-register: a released head, its tombstone and no capture.
    let mut released_first = valid.clone();
    released_first.roots.clear();
    assert!(released_first.violations().contains(&format!("root_capture_missing:{REPO}:{ROOT}:released")));
    // Classified as release-before-register, not as a lost capture.
    assert!(!released_first.violations().contains(&format!("root_capture_missing:{REPO}:{ROOT}:active")));
    // Without its tombstone that head is not a legal release-before-register.
    let mut unregistered = released_first.clone();
    unregistered.tombstones.clear();
    assert_refused(&unregistered.violations(), "root_head_mismatch");
    // A registered root must carry its release tombstone.
    let mut unserialised = valid;
    unserialised.tombstones.clear();
    assert_refused(&unserialised.violations(), "root_head_mismatch");
    // A tombstone for a different producer is a different scope than the head.
    let mut foreign = valid_source();
    foreign.tombstones[0].owner_id = Uuid::from_u128(0x1600);
    assert_refused(&foreign.violations(), "root_head_mismatch");
    // A root head with another tenant than its capture is a realm mismatch.
    let mut tenant = valid_source();
    tenant.heads[0].tenant_id = Uuid::from_u128(0x1700);
    assert_refused(&tenant.violations(), "root_head_mismatch");
    // A release-before-register head that the capture proves was registered is
    // not a release-before-register root.
    let mut contradiction = valid_source();
    contradiction.heads = vec![head("active", 1)];
    contradiction.roots.clear();
    contradiction.tombstones = vec![tombstone()];
    assert_refused(&contradiction.violations(), "root_capture_missing");
    // A stale headless tombstone is refused.
    let mut orphan_tombstone = headless.clone();
    orphan_tombstone.tombstones = vec![tombstone()];
    assert_refused(&orphan_tombstone.violations(), "root_tombstone_without_head");
}
