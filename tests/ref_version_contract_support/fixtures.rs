//! Shared deterministic fixtures for `tests/ref_version_contract.rs` (§2 & §8).

use rootyard::ref_store::core::pack_commit::{
    ArtifactLocator, ArtifactSetDigest, ContentDigest, PackArtifactRole, PlannedArtifact, PlannedPack,
    RegisteredArtifact, RegisteredPack,
};
use rootyard::ref_store::ref_version::{
    AuthorityKind, BaseRequestSelector, CausalVersionNode, CommitSetHead, CommitSetInput, CommitSetVersionEntry,
    OperationDigestInput, PackSetEntry, RefVersionIntent, RefVersionKind, RefVersionRealm, VerifiedClosurePack,
    VersionId, VersionRecord, VersionRecordInput, compute_commit_set_id, compute_pack_set_digest,
    derive_candidate_version_id, operation_digest,
};
use rootyard::ref_store::{
    CommitMode, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, RefName, RefPrecondition, RefTarget, RequestDigest,
};
use uuid::Uuid;

pub fn uid(seed: u128) -> Uuid {
    Uuid::from_u128(0x0011_2233_4455_6677_8899_0000_0000_0000_u128 + seed)
}

pub fn oid(byte: u8) -> GitOid {
    GitOid::Sha1([byte; 20])
}

pub fn oid256(byte: u8) -> GitOid {
    GitOid::Sha256([byte; 32])
}

pub fn default_realm() -> RefVersionRealm {
    RefVersionRealm::new(uid(1), uid(2), uid(3), AuthorityKind::Pg, 1, 0, 1, GitObjectFormat::Sha1)
}

pub fn planned_pack(seed: u64, length: u64) -> PlannedPack {
    let pack_digest = ContentDigest::parse(format!("{:064x}", seed * 2 + 1)).unwrap();
    let idx_digest = ContentDigest::parse(format!("{:064x}", seed * 2 + 2)).unwrap();
    let pack = PlannedArtifact::new(PackArtifactRole::Pack, pack_digest, length).unwrap();
    let idx = PlannedArtifact::new(PackArtifactRole::Idx, idx_digest, 128).unwrap();
    PlannedPack::new(uid(0x1000 + u128::from(seed)), uid(0x2000 + u128::from(seed)), pack, idx).unwrap()
}

pub fn registered_pack(
    tenant_id: Uuid,
    authority_id: Uuid,
    seed: u64,
    provider: &str,
    backend_identity: &str,
    length: u64,
    joined_revision: Option<i64>,
) -> RegisteredPack {
    let sha_pack = ContentDigest::parse(format!("{:064x}", seed * 2 + 1)).unwrap();
    let sha_idx = ContentDigest::parse(format!("{:064x}", seed * 2 + 2)).unwrap();
    let loc_pack = ArtifactLocator::new(
        tenant_id,
        authority_id,
        1,
        uid(0x3000 + u128::from(seed)),
        "core-pack",
        sha_pack.clone(),
        length,
    )
    .unwrap();
    let loc_idx = ArtifactLocator::new(
        tenant_id,
        authority_id,
        1,
        uid(0x3500 + u128::from(seed)),
        "core-pack",
        sha_idx.clone(),
        128,
    )
    .unwrap();
    let pack_art = RegisteredArtifact::new(
        PackArtifactRole::Pack,
        0,
        uid(0x4000 + u128::from(seed)),
        loc_pack,
        provider,
        backend_identity,
        sha_pack,
        length,
    )
    .unwrap();
    let idx_art = RegisteredArtifact::new(
        PackArtifactRole::Idx,
        1,
        uid(0x4500 + u128::from(seed)),
        loc_idx,
        provider,
        backend_identity,
        sha_idx,
        128,
    )
    .unwrap();
    let artifacts = vec![pack_art, idx_art];
    let set_digest = ArtifactSetDigest::of(&artifacts);
    RegisteredPack::new(
        uid(0x5000 + u128::from(seed)),
        uid(0x6000 + u128::from(seed)),
        set_digest,
        artifacts,
        joined_revision,
    )
    .unwrap()
}

pub fn closure_pack(
    tenant_id: Uuid,
    seed: u64,
    provider: &str,
    backend_identity: &str,
    bytes: u64,
) -> VerifiedClosurePack {
    let reg =
        registered_pack(tenant_id, uid(99), seed, provider, backend_identity, bytes.saturating_sub(128).max(1), None);
    let entry = PackSetEntry::from_registered(&reg).unwrap();
    VerifiedClosurePack::new(entry, tenant_id, uid(99), provider, backend_identity, bytes, 2).unwrap()
}

pub fn op_input(
    realm: RefVersionRealm,
    op_seed: u64,
    refs: Vec<RefVersionIntent>,
    packs: Vec<PlannedPack>,
) -> OperationDigestInput {
    OperationDigestInput::new(
        realm,
        uid(70),
        uid(71),
        IssuerLane::new("default").unwrap(),
        i64::try_from(op_seed).unwrap(),
        uid(0x7000 + u128::from(op_seed)),
        i64::try_from(op_seed).unwrap(),
        RequestDigest::from_bytes([(op_seed & 0xff) as u8; 32]),
        CommitMode::Atomic,
        HeadUpdate::Keep,
        refs,
        RequestDigest::from_bytes([((op_seed + 7) & 0xff) as u8; 32]),
        packs,
    )
}

pub struct MintSpec<'a> {
    pub realm: &'a RefVersionRealm,
    pub ref_name: &'a str,
    pub kind: RefVersionKind,
    pub precondition: RefPrecondition,
    pub base_record: Option<&'a VersionRecord>,
    pub target: RefTarget,
    pub authority_seq: i64,
    pub object_deps: Vec<VersionId>,
    pub own_packs: Vec<VerifiedClosurePack>,
    pub op_seed: u64,
}

pub fn mint_node(spec: MintSpec<'_>) -> CausalVersionNode {
    let rname = RefName::new(spec.ref_name).unwrap();
    let (base_selector, base_gen, base_vid, ref_generation) = match spec.base_record {
        None => (BaseRequestSelector::ExplicitAbsent, None, None, 1),
        Some(base) => (
            BaseRequestSelector::Present(base.version_id()),
            Some(base.ref_generation()),
            Some(base.version_id()),
            base.ref_generation() + 1,
        ),
    };
    let intent = RefVersionIntent::new(rname.clone(), spec.kind, spec.precondition, base_selector, spec.target.clone());
    let op = op_input(*spec.realm, spec.op_seed, vec![intent], vec![]);
    let od = operation_digest(&op).unwrap();
    let version_id = derive_candidate_version_id(&op, od, &rname, base_gen).unwrap();
    let entries: Vec<PackSetEntry> = spec.own_packs.iter().map(|pack| *pack.entry()).collect();
    let pack_set_digest = compute_pack_set_digest(&entries).unwrap();
    let cs_input = CommitSetInput::new(
        *spec.realm,
        spec.authority_seq,
        op.operation_id(),
        od,
        vec![CommitSetVersionEntry::new(rname.clone(), version_id, spec.kind, spec.target.clone())],
        CommitSetHead::Absent,
    );
    let commit_set_id = compute_commit_set_id(&cs_input).unwrap();
    let record = VersionRecord::seal(VersionRecordInput {
        version_id,
        realm: *spec.realm,
        ref_name: rname,
        ref_generation,
        operation_id: op.operation_id(),
        operation_digest: od,
        authority_seq: spec.authority_seq,
        kind: spec.kind,
        target: spec.target,
        base_version_id: base_vid,
        object_deps: spec.object_deps,
        pack_set_digest,
        commit_set_id,
    })
    .unwrap();
    CausalVersionNode { record, own_packs: spec.own_packs }
}

pub fn mint_publish(
    realm: &RefVersionRealm,
    ref_name: &str,
    target: GitOid,
    authority_seq: i64,
    object_deps: Vec<VersionId>,
    own_packs: Vec<VerifiedClosurePack>,
    op_seed: u64,
) -> CausalVersionNode {
    mint_node(MintSpec {
        realm,
        ref_name,
        kind: RefVersionKind::Publish,
        precondition: RefPrecondition::Absent,
        base_record: None,
        target: RefTarget::Oid(target),
        authority_seq,
        object_deps,
        own_packs,
        op_seed,
    })
}
