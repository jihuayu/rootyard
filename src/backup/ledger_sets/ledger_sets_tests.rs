//! Database-free regressions for the source-ledger validator.
//!
//! Every case builds the exact row shapes the SQL decodes and proves that the
//! pure checkers refuse a corrupted declared set. Digest and joined-revision
//! mismatches are always re-synced first, so a targeted check is exercised on
//! its own and never refused merely because the artifact-set digest differs. A
//! producer owner distinct from the repository tenant and a released root are
//! valid.
use super::declared_owner_scope::declared_violations;
use super::*;
use crate::backup::ledger::captured_refs;
use crate::backup::ledger_canonical::canonical;
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::pack_commit::{
    ArtifactLocator, ArtifactSetDigest, ContentDigest, PackArtifactRole, RegisteredArtifact, RegisteredPack,
};

pub(super) const REPO: Uuid = Uuid::from_u128(0x0100);
pub(super) const TENANT: Uuid = Uuid::from_u128(0x0200);
const PRODUCER: Uuid = Uuid::from_u128(0x0300);
const PACK: Uuid = Uuid::from_u128(0x0400);
const REGISTRATION: Uuid = Uuid::from_u128(0x0500);
pub(super) const INCARNATION: Uuid = Uuid::from_u128(0x0600);
const ACQUIRE: Uuid = Uuid::from_u128(0x0700);
const CONSUME: Uuid = Uuid::from_u128(0x0800);
const PACK_HOLD: Uuid = Uuid::from_u128(0x0900);
const IDX_HOLD: Uuid = Uuid::from_u128(0x0a00);
const AUTH: Uuid = Uuid::from_u128(0x0b00);
const PACK_ATTEMPT: Uuid = Uuid::from_u128(0x0c00);
const IDX_ATTEMPT: Uuid = Uuid::from_u128(0x0d00);
const ROOT: Uuid = Uuid::from_u128(0x0e00);
pub(super) const GATE_REVISION: i64 = 7;
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

/// The decoded row shape of `pair`/`corrupt_pair`: the scope lines the SQL
/// decoder stores on the pair are recomputed by the same pure checker.
fn scoped(mut declared: DeclaredPair) -> DeclaredPair {
    declared.scope = declared_violations(&declared);
    declared
}

/// `pair` with a digest that covers the raw rows exactly as stored.
fn corrupt_pair(artifacts: Vec<PairArtifact>) -> DeclaredPair {
    let digest = raw_digest(&artifacts);
    let mut declared = pair(base_artifacts());
    declared.declared_sets =
        vec![("membership".into(), digest.clone(), JOINED), ("root_packs".into(), digest.clone(), JOINED)];
    declared.publication.as_mut().unwrap().digest = digest;
    declared.artifacts = artifacts;
    scoped(declared)
}

fn pair(artifacts: Vec<PairArtifact>) -> DeclaredPair {
    let digest = digest_of(&artifacts);
    scoped(DeclaredPair {
        repository_id: REPO,
        pack_id: PACK,
        registration_id: REGISTRATION,
        declared_by: vec!["membership".into(), "root_packs".into()],
        declared_sets: vec![
            ("membership".into(), digest.clone(), JOINED),
            ("root_packs".into(), digest.clone(), JOINED),
        ],
        actual: ActualRepository { owner_id: Some(TENANT), gate_tenant_id: Some(TENANT) },
        publication: Some(PublishedPack {
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
        }),
        artifacts,
        scope: Vec::new(),
    })
}

/// A fixture whose artifact rows agree with the publication and its actual
/// repository: its memoized scope is empty, so only `check_declared` can refuse.
#[test]
fn a_legal_fixture_has_no_scope_lines() {
    {
        let declared = pair(base_artifacts());
        assert_eq!(declared.scope, Vec::<String>::new());
        assert!(check_declared(std::slice::from_ref(&declared)).is_empty());
    }
    let mut foreign = base_artifacts();
    foreign[0].hold.as_mut().unwrap().owner_id = Uuid::from_u128(0x1a00);
    let declared = pair(foreign);
    assert_eq!(declared.scope.len(), 1, "{:?}", declared.scope);
    assert_eq!(check_declared(std::slice::from_ref(&declared)), declared.scope);
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
        owner_id: PRODUCER,
        purpose: "ci".into(),
        business_intent_digest: sha(0x31),
        realm: realm(),
        ref_count: 1,
        oid_count: 1,
        pack_count: 1,
        refs_digest: String::new(),
        pack_set_digest: String::new(),
        register_digest: sha(0x32),
        selector_kind: "snapshot".into(),
        head_ref: "refs/heads/main".into(),
        head_oid: Some(oid.clone()),
        native_binding_digest: sha(0x37),
        refs: vec![("refs/heads/main".to_owned(), oid.clone())],
        oids: vec![(0, oid)],
        proof: None,
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
    // The core's own verdict, as `retention_root::validate_capture` returns it for
    // exactly these rows (the fixture never re-implements the binding algorithm).
    root.proof = Some(RootProof {
        tenant_id: root.tenant_id,
        owner_id: root.owner_id,
        purpose: root.purpose.clone(),
        business_intent_digest: root.business_intent_digest.clone(),
        register_digest: root.register_digest.clone(),
        head_ref: root.head_ref.clone(),
        head_oid: root.head_oid.clone(),
        selector_kind: root.selector_kind.clone(),
        oids: root.oids.iter().map(|(_, oid)| oid.clone()).collect(),
        refs_digest: root.refs_digest.clone(),
        pack_set_digest: root.pack_set_digest.clone(),
        native_binding_digest: root.native_binding_digest.clone(),
    });
}

/// A legal pair retained by a released root whose producer owner (`PRODUCER`)
/// differs from the repository tenant (`TENANT`).
pub(super) fn valid_source() -> SourceSets {
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

/// A root violation carries its root id between the prefix and the reason.
pub(super) fn assert_root_refused(lines: &[String], prefix: &str, reason: &str) {
    let expected = format!("{prefix}:{REPO}:{ROOT}:{reason}");
    assert!(lines.contains(&expected), "expected {expected} in {lines:?}");
}

/// The capture disagrees with its stored head: exactly that, never missing.
fn assert_capture_mismatched(lines: &[String], state: &str) {
    assert_root_refused(lines, "root_capture_mismatch", state);
    assert!(!lines.iter().any(|line| line.starts_with("root_capture_missing")), "{lines:?}");
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
    let missing = check_declared_missing(&[], &[root_capture()], &BTreeSet::new(), &BTreeSet::new());
    assert_refused(&missing, "unregistered_publication:root_packs");
    // A serving read header's descriptor is enumerated from its own decoded keys,
    // so it is refused too and can never shrink the expected set.
    let header = BTreeSet::from([(REPO, PACK, REGISTRATION)]);
    let missing = check_declared_missing(&[], &[], &header, &BTreeSet::new());
    assert_refused(&missing, "unregistered_publication:serving_read_packs");
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

/// The selector, scatter and binding digests are the core's verdict, not a
/// second algorithm here: a capture the core refuses, or a stored column that
/// is not exactly what the core re-derived, is refused.
#[test]
fn a_root_must_carry_exactly_the_core_verified_capture() {
    let mut unproven = valid_source();
    unproven.roots[0].proof = None;
    assert_refused(&unproven.violations(), "root_capture_invalid");
    // Only the stored side changes: a stored selector that drops one of the
    // core's re-proven oids is refused. A stored snapshot equal to refs + HEAD is
    // the core's own verdict (`Snapshot == refs + HEAD` is proven by the real
    // core validator, never by a fixture-built `proof`).
    let mut snapshot = valid_source();
    snapshot.roots[0].oids.pop();
    snapshot.roots[0].oid_count = 1;
    assert!(
        snapshot.violations().contains(&format!("root_selector_mismatch:{REPO}:{ROOT}")),
        "{:?}",
        snapshot.violations()
    );
    let mut order = valid_source();
    order.roots[0].oids[0].0 = 3;
    assert_refused(&order.violations(), "root_selector_mismatch");
    let mut kind = valid_source();
    kind.roots[0].selector_kind = "oids".into();
    assert_refused(&kind.violations(), "root_selector_mismatch");
    let mut binding = valid_source();
    binding.roots[0].native_binding_digest = sha(0x38);
    assert_refused(&binding.violations(), "root_selector_mismatch");
    let mut head = valid_source();
    head.roots[0].head_ref = "refs/heads/other".into();
    assert_refused(&head.violations(), "root_selector_mismatch");
    // Counts are the rows': a binding digest proves them, so a stored count
    // that disagrees with its digest is refused by the core's own verdict.
    let mut count = valid_source();
    count.roots[0].oid_count = 7;
    count.roots[0].proof = None;
    assert_refused(&count.violations(), "root_capture_invalid");
}

#[test]
fn root_lifetime_covers_heads_captures_and_tombstones() {
    let valid = valid_source();
    assert!(valid.violations().is_empty(), "{:?}", valid.violations());
    // `register` writes only an active head and its capture: that must be valid.
    let mut active = valid_source();
    active.heads = vec![head("active", 1)];
    active.tombstones.clear();
    assert!(active.violations().is_empty(), "{:?}", active.violations());
    // Nothing registered: refused.
    // A missing capture is exactly its own missing verdict, never a mismatch.
    let mut nothing = active.clone();
    nothing.roots.clear();
    let lines = nothing.violations();
    assert!(lines.contains(&format!("root_capture_missing:{REPO}:{ROOT}:active")), "{lines:?}");
    assert!(!lines.iter().any(|line| line.starts_with("root_capture_mismatch")), "{lines:?}");
    // A capture without its head is refused.
    let mut headless = valid.clone();
    headless.heads.clear();
    assert!(headless.violations().contains(&format!("root_head_missing:{REPO}:{ROOT}")));
    // Release-before-register: a released head, its tombstone and no capture.
    let mut released_first = valid.clone();
    released_first.roots.clear();
    assert!(released_first.violations().is_empty(), "{:?}", released_first.violations());
    // Without its tombstone that head is not a legal release-before-register.
    let mut unregistered = released_first.clone();
    unregistered.tombstones.clear();
    assert_refused(&unregistered.violations(), "root_capture_missing");
    // A released root keeps its capture but must carry the release tombstone.
    let mut registered = valid_source();
    registered.heads = vec![head("released", 2)];
    registered.tombstones.clear();
    assert_root_refused(&registered.violations(), "root_head_mismatch", "unreleased");
    // The tombstone must fence exactly the capture scope and register digest.
    // A tombstone that does not fence leaves the released capture unreleased.
    let mut foreign = registered.clone();
    foreign.tombstones = vec![RootTombstone { owner_id: Uuid::from_u128(0x1600), ..tombstone() }];
    assert_root_refused(&foreign.violations(), "root_head_mismatch", "unreleased");
    let mut stale = registered.clone();
    stale.tombstones = vec![RootTombstone { expected_register_digest: sha(0x34), ..tombstone() }];
    assert_root_refused(&stale.violations(), "root_head_mismatch", "unreleased");
    // The capture exists under the head's key but under another scope.
    let mut tenant = registered.clone();
    tenant.heads[0].tenant_id = Uuid::from_u128(0x1700);
    assert_capture_mismatched(&tenant.violations(), "released");
    let mut intent = registered.clone();
    intent.heads[0].business_intent_digest = sha(0x36);
    assert_root_refused(&intent.violations(), "root_head_mismatch", "tombstone_mismatch");
    // The capture must itself carry the head's register digest, owner and tenant.
    let mut digest = registered.clone();
    digest.roots[0].register_digest = sha(0x35);
    assert_capture_mismatched(&digest.violations(), "released");
    let mut producer = active.clone();
    producer.roots[0].owner_id = Uuid::from_u128(0x1600);
    assert_root_refused(&producer.violations(), "root_capture_mismatch", "active");
    // A release-before-register head that the capture proves was registered is
    // not a release-before-register root.
    let mut contradiction = valid_source();
    contradiction.heads = vec![head("active", 1)];
    contradiction.roots.clear();
    assert_refused(&contradiction.violations(), "root_capture_missing");
    // A tombstone never follows an active capture.
    let mut early = active.clone();
    early.tombstones = vec![tombstone()];
    assert_root_refused(&early.violations(), "root_head_mismatch", "tombstone_without_release");
    // Any other lifetime shape is refused, and is a violation (never a panic)
    // whatever tombstones it carries: none, a legal-looking row or a corrupted one.
    let shapes =
        [("released", 1), ("released", 3), ("active", 2), ("active", 3), ("released", 0), ("", 1), ("Active", 1)];
    for (state, generation) in shapes {
        for tombstones in [Vec::new(), vec![tombstone()], vec![RootTombstone { generation: 3, ..tombstone() }]] {
            let mut shape = active.clone();
            shape.heads = vec![head(state, generation)];
            shape.tombstones = tombstones;
            assert_root_refused(&shape.violations(), "root_head_mismatch", "state");
        }
    }
    // A head whose owner moved away from the stored capture is a scope error, not
    // an unfenced release: the capture disagrees with its head, and the legal
    // tombstone no longer fences that head.
    let mut head_scope = registered.clone();
    head_scope.heads[0].owner_id = Uuid::from_u128(0x1800);
    assert_capture_mismatched(&head_scope.violations(), "released");
    assert_root_refused(&head_scope.violations(), "root_head_mismatch", "tombstone_mismatch");
    // A stale headless tombstone is refused.
    let mut orphan_tombstone = headless;
    orphan_tombstone.tombstones = vec![tombstone()];
    assert_refused(&orphan_tombstone.violations(), "root_tombstone_without_head");
}

/// A capture that exists under the head's key but carries another scope, owner
/// or register digest is a violation, never a release-before-register root,
/// even when a legal release tombstone fences the head.
#[test]
fn a_present_capture_that_disagrees_with_its_head_is_never_release_before_register() {
    let released = valid_source();
    assert!(released.violations().is_empty(), "{:?}", released.violations());
    let mut active = released.clone();
    active.heads = vec![head("active", 1)];
    active.tombstones.clear();
    assert!(active.violations().is_empty(), "{:?}", active.violations());
    // Each capture field alone must be a mismatch, never a missing capture.
    let fields: [(&str, fn(&mut RootCapture)); 6] = [
        ("generation", |root| root.generation = 2),
        ("tenant", |root| root.tenant_id = Uuid::from_u128(0x1700)),
        ("purpose", |root| root.purpose = "other".into()),
        ("intent", |root| root.business_intent_digest = sha(0x36)),
        ("owner", |root| root.owner_id = Uuid::from_u128(0x1600)),
        ("register_digest", |root| root.register_digest = sha(0x35)),
    ];
    // Only the head side moves away from the stored capture.
    let scopes: [(&str, fn(&mut RootHead)); 4] = [
        ("tenant", |head| head.tenant_id = Uuid::from_u128(0x1700)),
        ("purpose", |head| head.purpose = "other".into()),
        ("intent", |head| head.business_intent_digest = sha(0x36)),
        ("owner", |head| head.owner_id = Uuid::from_u128(0x1600)),
    ];
    for (field, change) in fields {
        for (state, generation, tombstones) in [("released", 2, vec![tombstone()]), ("active", 1, Vec::new())] {
            let mut sets = valid_source();
            sets.heads = vec![head(state, generation)];
            sets.tombstones = tombstones;
            change(&mut sets.roots[0]);
            let lines = sets.violations();
            let mismatch = format!("root_capture_mismatch:{REPO}:{ROOT}:{state}");
            assert!(lines.contains(&mismatch), "{field} on {state}: expected {mismatch} in {lines:?}");
            assert!(
                !lines.iter().any(|line| line.starts_with("root_capture_missing")),
                "{field} on {state}: a present capture is not missing: {lines:?}"
            );
        }
    }
    for (field, change) in scopes {
        for state in ["released", "active"] {
            // Only the head changes; the capture keeps its own rows.
            let mut sets = valid_source();
            sets.heads = vec![head(state, if state == "released" { 2 } else { 1 })];
            if state == "active" {
                sets.tombstones.clear();
            }
            change(&mut sets.heads[0]);
            let lines = sets.violations();
            assert_root_refused(&lines, "root_capture_mismatch", state);
            assert!(
                !lines.iter().any(|line| line.starts_with("root_capture_missing")),
                "{field} on {state}: a present capture is not missing: {lines:?}"
            );
            // A stored tombstone no longer fences a head whose scope changed.
            if state == "released" {
                assert_root_refused(&lines, "root_head_mismatch", "tombstone_mismatch");
            }
        }
    }
}

/// A third, distinct owner: the root head/capture/tombstone requester.
const REQUESTER: Uuid = Uuid::from_u128(0x1a00);

/// A producer owner distinct from the repository tenant is valid, and so is a
/// root requester that is a third identity: it is compared with its own head
/// and tombstone only, never with the publication owner.
#[test]
fn a_producer_and_a_root_requester_are_independent_identities() {
    let sets = valid_source();
    assert_eq!(sets.violations(), Vec::<String>::new());
    assert_eq!(sets.declared[0].publication.as_ref().unwrap().owner_id, PRODUCER);
    assert_eq!(sets.declared[0].publication.as_ref().unwrap().tenant_id, TENANT);
    assert_ne!(PRODUCER, TENANT);
    let mut requester = valid_source();
    requester.roots[0].owner_id = REQUESTER;
    requester.roots[0].proof.as_mut().unwrap().owner_id = REQUESTER;
    requester.heads[0].owner_id = REQUESTER;
    requester.tombstones[0].owner_id = REQUESTER;
    assert_ne!(REQUESTER, PRODUCER);
    assert_eq!(requester.violations(), Vec::<String>::new());
    // The requester must still be one identity across head, capture and
    // tombstone: only the head moves.
    let mut moved = requester;
    moved.heads[0].owner_id = PRODUCER;
    assert_refused(&moved.violations(), "root_capture_mismatch");
}

// Every stored tombstone row of a key is judged: see `tombstone_tests`.
// The file is a sibling of this one, hence the explicit `#[path]`.
#[cfg(test)]
#[path = "tombstone_tests.rs"]
mod tombstone_tests;

// Membership-only declared pairs still have to be the canonical A4 set: see
// `membership_tests`. A sibling file, hence the explicit `#[path]`.
#[cfg(test)]
#[path = "membership_tests.rs"]
mod membership_tests;
