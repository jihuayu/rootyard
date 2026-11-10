//! Database-free regressions for the serving read header check (#169).
//!
//! Every case goes through the one production entry, [`SourceSets::violations`],
//! on the shared valid source: a valid nonempty serving read header must be
//! accepted and every representative corrupted header must be refused. The
//! suite never mirrors the private header/cross/descriptor check layers or their
//! exact lines; it only asks whether the combined list is empty.
//!
//! The valid fixture is the exact row shape `capture_registered` writes (a
//! derived pack set from the canonical A4 rows, HEAD from the captured refs, the
//! core's own membership and capture digests and the core's logical-byte
//! accounting), built through the issuer/core helpers, and each mutation changes
//! one fact of it.
use super::ledger_sets_tests::{GATE_REVISION, INCARNATION, REPO, TENANT, valid_source};
use super::serving_reads::{
    ServingReadArtifact, ServingReadDescriptor, ServingReadHeader, ServingReadLane, ServingReadScan, ServingReads,
};
use super::*;
use crate::backup::ledger_canonical::canonical;
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::pack_commit::{
    ArtifactLocator, ArtifactSetDigest, ContentDigest, PackArtifactRole, RegisteredArtifact, RegisteredPack,
};
use crate::ref_store::core::pack_snapshot::{
    ServingCaptureDigest, ServingReadRow, captured_logical_bytes, captured_refs_digest, check_membership, scope_of,
};

const PIN: Uuid = Uuid::from_u128(0x1001);
const SNAPSHOT: Uuid = Uuid::from_u128(0x1002);
const REQUESTER: Uuid = Uuid::from_u128(0x1003);
const T_REF: &str = "refs/heads/main";
const T_OID: &str = "abababababababababababababababababababab";

/// The canonical A4 pack of the shared fixture, built by the issuer types.
fn canonical_pack() -> RegisteredPack {
    canonical(&valid_source().declared[0]).expect("the fixture is the canonical A4 set").0
}

fn refs() -> Vec<(String, String)> {
    vec![(T_REF.to_owned(), T_OID.to_owned())]
}

fn descriptor(pack: &RegisteredPack) -> ServingReadDescriptor {
    ServingReadDescriptor {
        pack_id: pack.pack_id(),
        registration_id: pack.registration_id(),
        artifact_set_digest: pack.artifact_set_digest().as_hex(),
        joined_revision: pack.joined_revision().expect("the A4 fixture joins at gate+1"),
    }
}

fn artifact(pack: &RegisteredPack, role: PackArtifactRole) -> ServingReadArtifact {
    let a = pack.artifact(role);
    ServingReadArtifact {
        pack_id: pack.pack_id(),
        role: role.as_str().to_owned(),
        slot: a.slot(),
        hold_id: a.hold_id(),
        locator_tenant_id: a.locator().tenant_id(),
        locator_authority_id: a.locator().authority_id(),
        locator_authority_generation: a.locator().authority_generation(),
        locator_attempt_id: a.locator().attempt_id(),
        locator_namespace: a.locator().namespace().to_owned(),
        locator_sha256: a.locator().sha256().as_str().to_owned(),
        locator_length: i64::try_from(a.locator().length()).unwrap(),
        provider: a.provider().to_owned(),
        backend_identity: a.backend_identity().to_owned(),
        verified_sha256: a.verified_sha256().as_str().to_owned(),
        verified_length: i64::try_from(a.verified_length()).unwrap(),
    }
}

fn lane(binding: (Uuid, String, Uuid, i64, i64, String, String)) -> ServingReadLane {
    ServingReadLane {
        storage_backend: Some("pg_refstore".into()),
        repository_owner: Some(TENANT),
        gate: Some((binding.0, binding.1.clone(), binding.2, binding.3, binding.4)),
        binding: Some(binding),
    }
}

fn ready_lane(backend: &str) -> ServingReadLane {
    lane((TENANT, "sha1".into(), INCARNATION, 1, 1, backend.to_owned(), "ready".into()))
}

/// The header exactly as `capture_registered` writes it: derived values only.
fn header(
    packs: &[ServingReadDescriptor],
    artifacts: Vec<ServingReadArtifact>,
    lane: ServingReadLane,
) -> ServingReadHeader {
    let registered = rebuild(packs, &artifacts).expect("a complete declared set");
    let membership = check_membership(&registered).unwrap();
    let captured = refs();
    let row = ServingReadRow {
        pin_id: PIN,
        snapshot_id: SNAPSHOT,
        generation: 1,
        repository_id: REPO,
        tenant_id: TENANT,
        // The serving-read requester is a distinct identity, never the tenant
        // and never the A3 producer.
        owner_id: REQUESTER,
        purpose: "verification".into(),
        object_format: "sha1".into(),
        history_incarnation: INCARNATION,
        authority_epoch: 1,
        group_epoch: 1,
        backend_identity: lane.binding.as_ref().unwrap().5.clone(),
        gate_revision: GATE_REVISION,
        gate_digest: hex::encode([0x66; 32]),
        head_ref: T_REF.into(),
        head_oid: Some(T_OID.into()),
        ref_count: 1,
        refs_digest: captured_refs_digest(&captured).as_hex(),
        pack_count: membership.pack_count,
        membership_digest: membership.membership_digest,
        snapshot_digest: String::new(),
        logical_bytes: captured_logical_bytes(T_REF, Some(T_OID), &captured, &registered),
        expires_at_unix_micros: 0,
        expired: false,
    };
    let mut header = ServingReadHeader { row, lane, refs: captured, packs: packs.to_vec(), artifacts };
    header.row.snapshot_digest = capture_digest(&header);
    header
}

/// The issuer's `RegisteredArtifact` for one stored artifact row.
fn issuer_artifact(a: &ServingReadArtifact) -> RegisteredArtifact {
    RegisteredArtifact::new(
        PackArtifactRole::parse(&a.role).unwrap(),
        a.slot,
        a.hold_id,
        ArtifactLocator::new(
            a.locator_tenant_id,
            a.locator_authority_id,
            a.locator_authority_generation,
            a.locator_attempt_id,
            a.locator_namespace.clone(),
            ContentDigest::parse(a.locator_sha256.clone()).unwrap(),
            u64::try_from(a.locator_length).unwrap(),
        )
        .unwrap(),
        a.provider.clone(),
        a.backend_identity.clone(),
        ContentDigest::parse(a.verified_sha256.clone()).unwrap(),
        u64::try_from(a.verified_length).unwrap(),
    )
    .unwrap()
}

/// The issuer's registered set, one pack per stored descriptor.
fn rebuild(packs: &[ServingReadDescriptor], artifacts: &[ServingReadArtifact]) -> Result<Vec<RegisteredPack>, String> {
    packs
        .iter()
        .map(|descriptor| {
            let parsed: RequestDigest = descriptor.artifact_set_digest.parse().map_err(|_| "digest")?;
            RegisteredPack::new(
                descriptor.pack_id,
                descriptor.registration_id,
                ArtifactSetDigest::from_digest(parsed),
                artifacts.iter().filter(|a| a.pack_id == descriptor.pack_id).map(issuer_artifact).collect(),
                Some(descriptor.joined_revision),
            )
            .map_err(|_| "pack".to_owned())
        })
        .collect()
}

/// The core's own `serving_capture_digest` over the header's stored identity.
fn capture_digest(header: &ServingReadHeader) -> String {
    ServingCaptureDigest::of(&header.row).unwrap()
}

/// One header plus the lanes and orphan rows the SQL decode would supply.
///
/// Every child row is supplied as the decode does: separately keyed by the
/// header's pin, with the lanes as their own row list. The headers then carry no
/// lane, so `from_scan` must attach the decoded lane itself.
fn scan(mut headers: Vec<ServingReadHeader>, found: Vec<(Uuid, Uuid)>, violations: Vec<String>) -> ServingReads {
    let lanes = headers.iter().map(|header| (header.row.repository_id, header.lane.clone())).collect();
    let refs = headers.iter().map(|header| (header.row.pin_id, header.refs.clone())).collect();
    let packs = headers.iter().map(|header| (header.row.pin_id, header.packs.clone())).collect();
    let artifacts = headers.iter().map(|header| (header.row.pin_id, header.artifacts.clone())).collect();
    for header in &mut headers {
        header.lane = ServingReadLane::default();
    }
    ServingReads::from_scan(ServingReadScan { headers, found, lanes, violations, refs, packs, artifacts })
}

/// The valid capture: the canonical A4 pack, its pair of artifacts and the
/// ready lane of the backend that actually stores them.
fn ready() -> ServingReadHeader {
    let pack = canonical_pack();
    let backend = pack.artifact(PackArtifactRole::Pack).backend_identity().to_owned();
    let artifacts = vec![artifact(&pack, PackArtifactRole::Pack), artifact(&pack, PackArtifactRole::Idx)];
    header(&[descriptor(&pack)], artifacts, ready_lane(&backend))
}

fn valid_reads() -> ServingReads {
    scan(vec![ready()], Vec::new(), Vec::new())
}

/// Re-seal a mutated header under the core capture digest.
fn reseal(header: &mut ServingReadHeader) {
    header.row.snapshot_digest = capture_digest(header);
}

/// The decoded header, mutated, placed into the valid source, judged by the
/// combined [`SourceSets::violations`] entry. Returns everything refused, and
/// nothing else: the clean source is proven empty first, so a line can only come
/// from the serving read header.
fn serving_read_violations(mutate: impl FnOnce(&mut ServingReadHeader)) -> (Vec<String>, ServingReads) {
    let base = valid_source();
    assert_eq!(base.violations(), Vec::<String>::new(), "the source fixture is clean");
    let mut header = ready();
    mutate(&mut header);
    let reads = scan(vec![header], Vec::new(), Vec::new());
    let mut sets = base;
    sets.serving_reads = reads.clone();
    (sets.violations(), reads)
}

/// The whole decoded `ServingReads`, judged by the combined entry.
fn source_violations(reads: ServingReads) -> Vec<String> {
    let mut sets = valid_source();
    sets.serving_reads = reads;
    sets.violations()
}

/// The valid nonempty header is accepted by the combined entry.
fn assert_accepted(reads: ServingReads, label: &str) {
    let violations = source_violations(reads);
    assert!(violations.is_empty(), "{label}: accepted header refused by {violations:?}");
}

/// A mutated header is refused by the combined entry.
fn assert_refused(mutate: impl FnOnce(&mut ServingReadHeader), label: &str) {
    let (violations, _) = serving_read_violations(mutate);
    assert!(!violations.is_empty(), "{label}: corrupted header accepted by SourceSets::violations");
}

#[test]
fn a_valid_serving_read_header_is_accepted() {
    let reads = valid_reads();
    assert_eq!(reads.headers.len(), 1);
    assert!(!reads.headers[0].packs.is_empty(), "the valid capture is nonempty");
    assert_accepted(reads, "the capture_registered row shape");
}

#[test]
fn descriptors_outside_or_foreign_to_the_declaration_are_refused() {
    // A descriptor whose registration has no A4 declaration at all.
    assert_refused(
        |h| {
            h.packs[0].registration_id = Uuid::from_u128(0x1008);
            reseal(h);
        },
        "descriptor omitted from the declaration",
    );
    // A foreign descriptor: it names its own pack, so the artifacts no longer
    // rebuild it and no declaration states it.
    assert_refused(
        |h| {
            h.packs[0].pack_id = Uuid::from_u128(0x1009);
            reseal(h);
        },
        "foreign descriptor",
    );

    // The declaration disappears: the header's descriptor is still expected.
    let mut sets = valid_source();
    sets.declared.clear();
    sets.serving_reads = valid_reads();
    let violations = sets.violations();
    assert!(!violations.is_empty(), "a descriptor without its declaration was accepted");

    // An extra artifact inside the shared pack.
    assert_refused(
        |h| {
            let mut clone = h.artifacts[0].clone();
            clone.role = "idx".into();
            clone.slot = 1;
            h.artifacts.push(clone);
        },
        "extra artifact",
    );
    // An artifact row that names a pack the header does not declare.
    assert_refused(|h| h.artifacts[0].pack_id = Uuid::from_u128(0x1007), "artifact outside the pack");
    // A missing pack: no descriptor and no artifact row at all.
    assert_refused(
        |h| {
            h.packs.clear();
            h.artifacts.clear();
            h.row.pack_count = 0;
        },
        "missing pack",
    );
}

#[test]
fn a_wrong_count_digest_or_capture_identity_is_refused() {
    let mutations: [(&str, fn(&mut ServingReadHeader)); 13] = [
        ("pack count", |h| h.row.pack_count += 1),
        ("zero pack count", |h| h.row.pack_count = 0),
        ("membership digest", |h| h.row.membership_digest = hex::encode([0x70; 32])),
        ("snapshot digest", |h| h.row.snapshot_digest = hex::encode([0x71; 32])),
        ("ref count", |h| h.row.ref_count += 1),
        ("logical bytes", |h| h.row.logical_bytes += 1),
        ("HEAD", |h| h.row.head_oid = None),
        ("refs digest", |h| h.row.refs_digest = hex::encode([0x72; 32])),
        ("no refs stored", |h| h.refs.clear()),
        ("refs emptied but re-sealed", |h| {
            h.refs.clear();
            reseal(h);
        }),
        ("tampered ref oid", |h| h.refs[0].1 = "cd".repeat(20)),
        ("extra ref", |h| h.refs.push(("refs/tags/v1".into(), "ef".repeat(20)))),
        ("renamed HEAD ref", |h| {
            h.refs[0].0 = "refs/heads/other".into();
            h.row.head_ref = "refs/heads/other".into();
            h.row.head_oid = None;
            h.row.refs_digest = captured_refs_digest(&h.refs).as_hex();
        }),
    ];
    for (label, mutate) in mutations {
        assert_refused(mutate, label);
    }
}

#[test]
fn a_foreign_backend_invalid_lane_or_realm_is_refused() {
    let foreign = hex::encode([0x73; 32]);
    // A header backend that differs from the serving binding.
    assert_refused(|h| h.lane = ready_lane(&foreign), "header backend");
    // A captured artifact from another physical backend.
    assert_refused(|h| h.artifacts[0].backend_identity = foreign.clone(), "artifact backend");
    // A lane of a repository that is not served by the pg ref-store at all,
    // even though it carries no header: the lane itself is judged.
    let mut reads = valid_reads();
    let mut bad = ready_lane(&foreign);
    bad.storage_backend = Some("gitfs".into());
    reads.lanes.insert(Uuid::from_u128(0x1096), bad);
    assert!(
        !source_violations(reads).is_empty(),
        "a repository without a header but with a foreign serving realm was accepted"
    );
    let lanes: [(&str, fn(&mut ServingReadLane)); 4] = [
        ("binding not ready", |l| l.binding.as_mut().unwrap().6 = "pending".into()),
        ("binding disagrees with the gate", |l| l.gate.as_mut().unwrap().3 = 9),
        ("foreign lane owner", |l| l.repository_owner = Some(Uuid::from_u128(0x1097))),
        ("missing binding", |l| l.binding = None),
    ];
    for (label, mutate) in lanes {
        assert_refused(|h| mutate(&mut h.lane), label);
    }
    let realms: [(&str, fn(&mut ServingReadHeader)); 6] = [
        ("tenant", |h| h.row.tenant_id = Uuid::from_u128(0x1099)),
        ("incarnation", |h| h.row.history_incarnation = Uuid::from_u128(0x1098)),
        ("authority epoch", |h| h.row.authority_epoch = 2),
        ("group epoch", |h| h.row.group_epoch = 2),
        ("object format", |h| h.row.object_format = "sha256".into()),
        // A stored header whose realm moved away from the declared publication,
        // re-sealed so only the cross-row realm disagreement remains.
        ("undeclared publication realm", |h| {
            h.row.group_epoch = 3;
            reseal(h);
        }),
    ];
    for (label, mutate) in realms {
        assert_refused(mutate, label);
    }
}

#[test]
fn an_orphan_pin_or_orphan_header_is_refused() {
    // A header whose pack rows exist but whose header row is missing: the SQL
    // decode names the bare pin, and the header's own pin is never an orphan.
    let orphan = Uuid::from_u128(0x1004);
    let reads = scan(vec![ready()], vec![(REPO, PIN), (REPO, orphan)], Vec::new());
    let violations = source_violations(reads);
    assert!(!violations.is_empty(), "an orphaned serving read pin was accepted; expected a violation naming {orphan}");
    // The decode already named the orphan row, and no header row was found.
    let reads = scan(Vec::new(), vec![(REPO, orphan)], vec![format!("serving_read_orphan:{orphan}")]);
    let violations = source_violations(reads);
    assert!(!violations.is_empty(), "a decode-named orphan was accepted; expected a violation naming {orphan}");
}

#[test]
fn the_requester_is_not_the_tenant_or_the_producer() {
    // The scope is decoded from the stored row as a pure identity shape: the
    // header requester is the owner, never the tenant, and the valid header is
    // accepted with that distinct identity.
    let row = &valid_reads().headers[0].row;
    let scope = scope_of(row).expect("the stored header decodes into a snapshot scope");
    assert_eq!(scope.repository_id(), REPO);
    assert_eq!(scope.owner_id(), REQUESTER);
    assert_eq!(scope.tenant_id(), TENANT);
    assert_ne!(scope.owner_id(), scope.tenant_id());
    let publication = valid_source().declared[0].publication.clone().expect("the fixture publishes its pack");
    assert_ne!(scope.owner_id(), publication.owner_id);
    assert_accepted(valid_reads(), "a distinct requester");
    // The requester and purpose are still bound by the capture digest.
    assert_refused(|h| h.row.purpose = "export".into(), "a re-bound purpose");
}
