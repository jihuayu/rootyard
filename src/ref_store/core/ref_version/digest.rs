//! Canonical `OD` preimage from `docs/ref-version-pack-contract.md` §2.6.
//!
//! The domain and field framing are fixed literals. This is deliberately not
//! [`crate::ref_store::contract::RequestDigest::of`]: that helper prepends a
//! different domain and frames its fields differently. No generic hash API is
//! exposed.
use super::contract::{
    BaseRequestSelector, OperationDigest, OperationDigestInput, RefVersionCodecError, RefVersionIntent, RefVersionKind,
    RefVersionRealm,
};
use super::limits::{
    ARTIFACTS_PER_PACK, MAX_OPERATION_PACKS, MAX_OPERATION_REFS, count_u32, length_u64, nonnegative_u64, positive_u64,
};
use crate::ref_store::core::contract::CommitMode;
use crate::ref_store::core::pack_commit::{ContentDigest, PackArtifactRole, PlannedPack};
use crate::ref_store::core::types::{GitObjectFormat, GitOid, HeadUpdate, RefPrecondition, RefTarget};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const OPERATION_DOMAIN: &[u8] = b"ry-ref-version-operation-v1";

/// Canonical operation digest over the complete prospective mutation.
///
/// Returns a deterministic value only. It does not check live authority, object
/// existence, authorization, gate freshness or base-row coherence, and it does
/// not register or retain anything.
pub(crate) fn operation_digest(input: &OperationDigestInput) -> Result<OperationDigest, RefVersionCodecError> {
    let realm_numbers = validate_input(input)?;
    let realm = input.realm();
    let mut writer = CanonicalWriter::new();
    writer.push_len_prefixed(OPERATION_DOMAIN)?;
    writer.push_len_prefixed(realm.tenant_id().as_bytes())?;
    writer.push_len_prefixed(realm.repository_id().as_bytes())?;
    writer.push_len_prefixed(input.owner_id().as_bytes())?;
    writer.push_len_prefixed(realm.history_incarnation().as_bytes())?;
    writer.push_u8(realm.authority_kind().tag());
    writer.push_u64(realm_numbers.authority_epoch);
    writer.push_u64(realm_numbers.group_id);
    writer.push_u64(realm_numbers.group_epoch);
    writer.push_u8(format_tag(realm.object_format()));
    writer.push_len_prefixed(input.issuer_id().as_bytes())?;
    writer.push_len_prefixed(input.lane().as_str().as_bytes())?;
    writer.push_u64(positive_u64(input.issuer_sequence(), "issuer_sequence")?);
    writer.push_len_prefixed(input.operation_id().as_bytes())?;
    writer.push_u64(positive_u64(input.expected_gate_revision(), "expected_gate_revision")?);
    writer.push_len_prefixed(input.expected_gate_digest().as_bytes())?;
    writer.push_u8(commit_mode_tag(input.commit_mode()));
    match input.head() {
        HeadUpdate::Keep => writer.push_u8(0),
        HeadUpdate::Retarget(name) => {
            writer.push_u8(1);
            writer.push_len_prefixed(name.as_str().as_bytes())?;
        }
    }
    writer.push_u32(count_u32(input.refs().len(), "refs")?);
    for intent in input.refs() {
        encode_intent(&mut writer, intent)?;
    }
    writer.push_len_prefixed(input.old_membership_digest().as_bytes())?;
    writer.push_u32(count_u32(input.packs().len(), "packs")?);
    let mut packs: Vec<&PlannedPack> = input.packs().iter().collect();
    packs.sort_by_key(|pack| (pack.pack_id(), pack.registration_id()));
    for pack in packs {
        encode_pack(&mut writer, pack)?;
    }
    Ok(OperationDigest::from_canonical_hash(writer.finish()))
}

struct RealmNumbers {
    authority_epoch: u64,
    group_id: u64,
    group_epoch: u64,
}

fn validate_input(input: &OperationDigestInput) -> Result<RealmNumbers, RefVersionCodecError> {
    let realm_numbers = validate_realm(input.realm())?;
    require_non_nil(input.owner_id(), "owner_id")?;
    require_non_nil(input.issuer_id(), "issuer_id")?;
    require_non_nil(input.operation_id(), "operation_id")?;
    positive_u64(input.issuer_sequence(), "issuer_sequence")?;
    positive_u64(input.expected_gate_revision(), "expected_gate_revision")?;
    validate_intents(input.refs(), input.realm().object_format())?;
    validate_packs(input.packs())?;
    if let HeadUpdate::Retarget(name) = input.head()
        && !name.is_branch()
    {
        return Err(RefVersionCodecError::InvalidRequestShape { reason: "HEAD must name a refs/heads/ branch" });
    }
    Ok(realm_numbers)
}

fn validate_realm(realm: &RefVersionRealm) -> Result<RealmNumbers, RefVersionCodecError> {
    require_non_nil(realm.tenant_id(), "tenant_id")?;
    require_non_nil(realm.repository_id(), "repository_id")?;
    require_non_nil(realm.history_incarnation(), "history_incarnation")?;
    let authority_epoch = positive_u64(realm.authority_epoch(), "authority_epoch")?;
    let group_id = nonnegative_u64(realm.group_id(), "group_id")?;
    let group_epoch = positive_u64(realm.group_epoch(), "group_epoch")?;
    Ok(RealmNumbers { authority_epoch, group_id, group_epoch })
}

fn validate_intents(refs: &[RefVersionIntent], object_format: GitObjectFormat) -> Result<(), RefVersionCodecError> {
    if refs.is_empty() {
        return Err(RefVersionCodecError::EmptyRefList);
    }
    if refs.len() > MAX_OPERATION_REFS {
        return Err(RefVersionCodecError::Capacity { field: "refs", limit: MAX_OPERATION_REFS, actual: refs.len() });
    }
    let mut names = BTreeSet::new();
    for intent in refs {
        if !names.insert(intent.name().as_str()) {
            return Err(RefVersionCodecError::DuplicateRefName);
        }
        validate_intent(intent, object_format)?;
    }
    let has_repack = refs.iter().any(|intent| intent.kind() == RefVersionKind::Repack);
    if has_repack && refs.iter().any(|intent| intent.kind() != RefVersionKind::Repack) {
        return Err(RefVersionCodecError::InvalidRequestShape {
            reason: "repack appears only in an all-repack maintenance set",
        });
    }
    Ok(())
}

fn validate_intent(intent: &RefVersionIntent, object_format: GitObjectFormat) -> Result<(), RefVersionCodecError> {
    if let Some(oid) = intent.precondition().oid() {
        ensure_oid_format(object_format, oid, "old_oid")?;
    }
    if let Some(oid) = intent.target().oid() {
        ensure_oid_format(object_format, oid, "target_oid")?;
    }
    if matches!(intent.base(), BaseRequestSelector::ExplicitAbsent)
        && !matches!(intent.precondition(), RefPrecondition::Absent)
    {
        return Err(RefVersionCodecError::InvalidRequestShape {
            reason: "explicit absent base requires an absent old-OID precondition",
        });
    }
    match intent.kind() {
        RefVersionKind::Publish => {
            if !matches!(intent.target(), RefTarget::Oid(_)) {
                return Err(RefVersionCodecError::InvalidRequestShape {
                    reason: "publish requires a present target OID",
                });
            }
        }
        RefVersionKind::Delete => {
            if !matches!(intent.target(), RefTarget::Delete) {
                return Err(RefVersionCodecError::InvalidRequestShape { reason: "delete requires an absent target" });
            }
            if !matches!(intent.base(), BaseRequestSelector::Present(_)) {
                return Err(RefVersionCodecError::InvalidRequestShape {
                    reason: "delete requires a present base version",
                });
            }
        }
        RefVersionKind::Repack => {
            if !matches!(intent.target(), RefTarget::Oid(_)) {
                return Err(RefVersionCodecError::InvalidRequestShape {
                    reason: "repack requires a present target OID",
                });
            }
            if !matches!(intent.base(), BaseRequestSelector::Present(_)) {
                return Err(RefVersionCodecError::InvalidRequestShape {
                    reason: "repack requires a present base version",
                });
            }
        }
    }
    Ok(())
}

fn validate_packs(packs: &[PlannedPack]) -> Result<(), RefVersionCodecError> {
    if packs.len() > MAX_OPERATION_PACKS {
        return Err(RefVersionCodecError::Capacity { field: "packs", limit: MAX_OPERATION_PACKS, actual: packs.len() });
    }
    let mut identities = BTreeSet::new();
    for pack in packs {
        require_non_nil(pack.pack_id(), "pack_id")?;
        require_non_nil(pack.registration_id(), "registration_id")?;
        if !identities.insert((pack.pack_id(), pack.registration_id())) {
            return Err(RefVersionCodecError::DuplicatePackIdentity);
        }
        content_digest_bytes(pack.artifact(PackArtifactRole::Pack).content())?;
        content_digest_bytes(pack.artifact(PackArtifactRole::Idx).content())?;
    }
    Ok(())
}

fn ensure_oid_format(
    object_format: GitObjectFormat,
    oid: GitOid,
    field: &'static str,
) -> Result<(), RefVersionCodecError> {
    if oid.format() != object_format {
        return Err(RefVersionCodecError::ObjectFormatMismatch { field });
    }
    Ok(())
}

fn require_non_nil(value: uuid::Uuid, field: &'static str) -> Result<(), RefVersionCodecError> {
    if value.is_nil() { Err(RefVersionCodecError::NilIdentifier { field }) } else { Ok(()) }
}

fn format_tag(format: GitObjectFormat) -> u8 {
    match format {
        GitObjectFormat::Sha1 => 1,
        GitObjectFormat::Sha256 => 2,
    }
}

fn commit_mode_tag(mode: CommitMode) -> u8 {
    match mode {
        CommitMode::Atomic => 1,
        CommitMode::AcceptedSubset => 2,
    }
}

fn encode_intent(writer: &mut CanonicalWriter, intent: &RefVersionIntent) -> Result<(), RefVersionCodecError> {
    writer.push_len_prefixed(intent.name().as_str().as_bytes())?;
    writer.push_u8(intent.kind().tag());
    match intent.precondition() {
        RefPrecondition::Absent => writer.push_u8(0),
        RefPrecondition::Present(oid) => {
            writer.push_u8(1);
            push_oid(writer, *oid)?;
        }
    }
    match intent.base() {
        BaseRequestSelector::LegacyNotSupplied => writer.push_u8(0),
        BaseRequestSelector::ExplicitAbsent => writer.push_u8(1),
        BaseRequestSelector::Present(version_id) => {
            writer.push_u8(2);
            writer.push_len_prefixed(version_id.as_bytes())?;
        }
    }
    match intent.target() {
        RefTarget::Delete => writer.push_u8(0),
        RefTarget::Oid(oid) => {
            writer.push_u8(1);
            push_oid(writer, *oid)?;
        }
    }
    Ok(())
}

fn encode_pack(writer: &mut CanonicalWriter, pack: &PlannedPack) -> Result<(), RefVersionCodecError> {
    writer.push_len_prefixed(pack.pack_id().as_bytes())?;
    writer.push_len_prefixed(pack.registration_id().as_bytes())?;
    writer.push_u32(ARTIFACTS_PER_PACK);
    for (role, tag) in [(PackArtifactRole::Pack, 1_u8), (PackArtifactRole::Idx, 2_u8)] {
        let artifact = pack.artifact(role);
        writer.push_u8(tag);
        writer.push_len_prefixed(&content_digest_bytes(artifact.content())?)?;
        writer.push_u64(artifact.length());
    }
    Ok(())
}

fn push_oid(writer: &mut CanonicalWriter, oid: GitOid) -> Result<(), RefVersionCodecError> {
    match oid {
        GitOid::Sha1(bytes) => writer.push_len_prefixed(&bytes),
        GitOid::Sha256(bytes) => writer.push_len_prefixed(&bytes),
    }
}

fn content_digest_bytes(content: &ContentDigest) -> Result<[u8; 32], RefVersionCodecError> {
    let decoded = hex::decode(content.as_str()).map_err(|_| RefVersionCodecError::InvalidContentDigest)?;
    decoded.try_into().map_err(|_| RefVersionCodecError::InvalidContentDigest)
}

struct CanonicalWriter {
    bytes: Vec<u8>,
}

impl CanonicalWriter {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn push_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    fn push_u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn push_u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    fn push_len_prefixed(&mut self, value: &[u8]) -> Result<(), RefVersionCodecError> {
        self.push_u64(length_u64(value.len(), "field_length")?);
        self.bytes.try_reserve(value.len()).map_err(|_| RefVersionCodecError::LengthOverflow { field: "preimage" })?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }

    fn finish(self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(&self.bytes);
        hash.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::super::contract::{AuthorityKind, VersionId};
    use super::*;
    use crate::ref_store::contract::{IssuerLane, RequestDigest};
    use crate::ref_store::core::pack_commit::{ContentDigest, PlannedArtifact, PlannedPack};
    use crate::ref_store::core::types::RefName;
    use uuid::Uuid;

    const A_DIGEST: &str = "0851116cdafd58f653a85e086b65628ea1b65cebcfb4605f518c993d4198ba25";
    const B_DIGEST: &str = "612e1751cbcfd54eac3ef660fb92e10a06aca197a4d950ff995d309c67fb8124";
    const C_DIGEST: &str = "de3497686e155bdee2a6abe6e385e2a2ba6554fa3a8c6f2221d874f289d05781";
    const D_DIGEST: &str = "a1f3bd39d3ccb7c08e8b41a1bb71944077586bc76fa9aa840b4bcefbbe4e00d8";
    const LEGACY_DIGEST: &str = "b78c88d6ca3c3084f423286eaf80d227059b4de405c3f747bf7e535c94145e50";
    const MAIN_THEN_TOPIC: &str = "743230794bca95d7af12496e4bc5478979ea351e71c048d4641760cb91a95006";
    const TOPIC_THEN_MAIN: &str = "a62fe0df7576ecfe9bc0ded542945ebebffe67d16f9189f8e03a2ba277e948c1";
    const PACK_ORDER: &str = "2cdb97121c1d8a5452d2af6cfbe6455a09b5485bba1e40d11d5b1ce2a4fbf779";

    fn uuid(value: u128) -> Uuid {
        Uuid::from_u128(value)
    }

    fn raw_uuid(byte: u8) -> Uuid {
        Uuid::from_bytes([byte; 16])
    }

    fn version(byte: u8) -> VersionId {
        VersionId::from_test_bytes([byte; 32])
    }

    fn main_name() -> RefName {
        RefName::new("refs/heads/main").unwrap()
    }

    fn topic_name() -> RefName {
        RefName::new("refs/heads/topic").unwrap()
    }

    fn oid(byte: u8) -> GitOid {
        GitOid::Sha1([byte; 20])
    }

    fn content(byte: u8) -> ContentDigest {
        ContentDigest::parse(hex::encode([byte; 32])).unwrap()
    }

    fn pack(
        pack_id: u8,
        registration_id: u8,
        pack_digest: u8,
        pack_length: u64,
        idx_digest: u8,
        idx_length: u64,
    ) -> PlannedPack {
        PlannedPack::new(
            raw_uuid(pack_id),
            raw_uuid(registration_id),
            PlannedArtifact::new(PackArtifactRole::Pack, content(pack_digest), pack_length).unwrap(),
            PlannedArtifact::new(PackArtifactRole::Idx, content(idx_digest), idx_length).unwrap(),
        )
        .unwrap()
    }

    fn pack_one() -> PlannedPack {
        pack(0x99, 0xaa, 0xbb, 123, 0xcc, 45)
    }

    fn pack_two() -> PlannedPack {
        pack(0x88, 0xdd, 0xee, 7, 0xff, 11)
    }

    fn realm_with(
        tenant_id: Uuid,
        repository_id: Uuid,
        history_incarnation: Uuid,
        authority_epoch: i64,
        group_id: i64,
        group_epoch: i64,
        object_format: GitObjectFormat,
    ) -> RefVersionRealm {
        RefVersionRealm::new(
            tenant_id,
            repository_id,
            history_incarnation,
            AuthorityKind::Pg,
            authority_epoch,
            group_id,
            group_epoch,
            object_format,
        )
    }

    fn realm() -> RefVersionRealm {
        realm_with(uuid(1), uuid(2), uuid(3), 7, 0, 9, GitObjectFormat::Sha1)
    }

    fn intent(
        name: RefName,
        kind: RefVersionKind,
        precondition: RefPrecondition,
        base: BaseRequestSelector,
        target: RefTarget,
    ) -> RefVersionIntent {
        RefVersionIntent::new(name, kind, precondition, base, target)
    }

    fn main_intent(
        kind: RefVersionKind,
        precondition: RefPrecondition,
        base: BaseRequestSelector,
        target: RefTarget,
    ) -> RefVersionIntent {
        intent(main_name(), kind, precondition, base, target)
    }

    fn a_intent() -> RefVersionIntent {
        main_intent(
            RefVersionKind::Publish,
            RefPrecondition::Present(oid(0x44)),
            BaseRequestSelector::Present(version(0x22)),
            RefTarget::Oid(oid(0x33)),
        )
    }

    fn b_intent() -> RefVersionIntent {
        main_intent(
            RefVersionKind::Publish,
            RefPrecondition::Present(oid(0x44)),
            BaseRequestSelector::Present(version(0x77)),
            RefTarget::Oid(oid(0x33)),
        )
    }

    fn c_intent() -> RefVersionIntent {
        main_intent(
            RefVersionKind::Publish,
            RefPrecondition::Absent,
            BaseRequestSelector::ExplicitAbsent,
            RefTarget::Oid(oid(0x33)),
        )
    }

    fn d_intent() -> RefVersionIntent {
        main_intent(
            RefVersionKind::Delete,
            RefPrecondition::Present(oid(0x44)),
            BaseRequestSelector::Present(version(0x22)),
            RefTarget::Delete,
        )
    }

    fn legacy_intent() -> RefVersionIntent {
        main_intent(
            RefVersionKind::Publish,
            RefPrecondition::Present(oid(0x44)),
            BaseRequestSelector::LegacyNotSupplied,
            RefTarget::Oid(oid(0x33)),
        )
    }

    fn topic_intent() -> RefVersionIntent {
        intent(
            topic_name(),
            RefVersionKind::Publish,
            RefPrecondition::Absent,
            BaseRequestSelector::ExplicitAbsent,
            RefTarget::Oid(oid(0x88)),
        )
    }

    fn build_input_with_realm(
        realm: RefVersionRealm,
        owner_id: Uuid,
        issuer_id: Uuid,
        operation_id: Uuid,
        issuer_sequence: i64,
        expected_gate_revision: i64,
        refs: Vec<RefVersionIntent>,
        packs: Vec<PlannedPack>,
    ) -> OperationDigestInput {
        OperationDigestInput::new(
            realm,
            owner_id,
            issuer_id,
            IssuerLane::new("main").unwrap(),
            issuer_sequence,
            operation_id,
            expected_gate_revision,
            RequestDigest::from_bytes([0x55; 32]),
            CommitMode::Atomic,
            HeadUpdate::Retarget(main_name()),
            refs,
            RequestDigest::from_bytes([0x66; 32]),
            packs,
        )
    }

    fn input(operation_id: Uuid, refs: Vec<RefVersionIntent>, packs: Vec<PlannedPack>) -> OperationDigestInput {
        build_input_with_realm(realm(), uuid(5), uuid(6), operation_id, 3, 41, refs, packs)
    }

    fn digest(input: &OperationDigestInput) -> Result<String, RefVersionCodecError> {
        operation_digest(input).map(|value| value.as_hex())
    }

    #[test]
    fn operation_digest_matches_contract_a_b_c_d_vectors() {
        assert_eq!(digest(&input(uuid(4), vec![a_intent()], vec![pack_one()])).unwrap(), A_DIGEST);
        assert_eq!(digest(&input(uuid(4), vec![b_intent()], vec![pack_one()])).unwrap(), B_DIGEST);
        assert_eq!(digest(&input(uuid(7), vec![c_intent()], vec![pack_one()])).unwrap(), C_DIGEST);
        assert_eq!(digest(&input(uuid(8), vec![d_intent()], vec![pack_one()])).unwrap(), D_DIGEST);

        // An exact retry of A reproduces A; B is a different ABA precondition.
        assert_eq!(digest(&input(uuid(4), vec![a_intent()], vec![pack_one()])).unwrap(), A_DIGEST);
        assert_ne!(digest(&input(uuid(4), vec![a_intent()], vec![pack_one()])).unwrap(), B_DIGEST);
    }

    #[test]
    fn legacy_base_is_digested_but_distinct() {
        assert_eq!(digest(&input(uuid(4), vec![legacy_intent()], vec![pack_one()])).unwrap(), LEGACY_DIGEST);
        assert_ne!(LEGACY_DIGEST, A_DIGEST);
    }

    #[test]
    fn request_order_is_preserved_and_changes_the_digest() {
        let main_then_topic = input(uuid(4), vec![a_intent(), topic_intent()], vec![pack_one()]);
        let topic_then_main = input(uuid(4), vec![topic_intent(), a_intent()], vec![pack_one()]);
        assert_eq!(digest(&main_then_topic).unwrap(), MAIN_THEN_TOPIC);
        assert_eq!(digest(&topic_then_main).unwrap(), TOPIC_THEN_MAIN);
        assert_ne!(MAIN_THEN_TOPIC, TOPIC_THEN_MAIN);
    }

    #[test]
    fn packs_are_sorted_canonically_and_duplicate_pairs_are_refused() {
        let first = input(uuid(4), vec![a_intent()], vec![pack_one(), pack_two()]);
        let second = input(uuid(4), vec![a_intent()], vec![pack_two(), pack_one()]);
        assert_eq!(digest(&first).unwrap(), PACK_ORDER);
        assert_eq!(digest(&second).unwrap(), PACK_ORDER);

        let duplicate = input(uuid(4), vec![a_intent()], vec![pack_one(), pack_one()]);
        assert_eq!(digest(&duplicate), Err(RefVersionCodecError::DuplicatePackIdentity));
    }

    #[test]
    fn ref_and_pack_bounds_are_checked_before_encoding() {
        let empty = input(uuid(4), Vec::new(), vec![pack_one()]);
        assert_eq!(digest(&empty), Err(RefVersionCodecError::EmptyRefList));

        let too_many_refs: Vec<RefVersionIntent> = (0..=MAX_OPERATION_REFS)
            .map(|index| {
                let name = RefName::new(format!("refs/heads/r{index}")).unwrap();
                intent(
                    name,
                    RefVersionKind::Publish,
                    RefPrecondition::Absent,
                    BaseRequestSelector::ExplicitAbsent,
                    RefTarget::Oid(oid(0x33)),
                )
            })
            .collect();
        assert_eq!(
            digest(&input(uuid(4), too_many_refs, vec![pack_one()])),
            Err(RefVersionCodecError::Capacity {
                field: "refs",
                limit: MAX_OPERATION_REFS,
                actual: MAX_OPERATION_REFS + 1,
            })
        );

        let too_many_packs: Vec<PlannedPack> = (0..=MAX_OPERATION_PACKS)
            .map(|index| {
                let pack_id = u8::try_from(index + 1).unwrap();
                let registration_id = u8::try_from(index + 21).unwrap();
                pack(pack_id, registration_id, 0xbb, 1, 0xcc, 1)
            })
            .collect();
        assert_eq!(
            digest(&input(uuid(4), vec![a_intent()], too_many_packs)),
            Err(RefVersionCodecError::Capacity {
                field: "packs",
                limit: MAX_OPERATION_PACKS,
                actual: MAX_OPERATION_PACKS + 1,
            })
        );

        let duplicate_refs = input(uuid(4), vec![a_intent(), a_intent()], vec![pack_one()]);
        assert_eq!(digest(&duplicate_refs), Err(RefVersionCodecError::DuplicateRefName));
    }

    #[test]
    fn request_shape_and_selected_format_are_checked() {
        let wrong_target_format = input(
            uuid(4),
            vec![main_intent(
                RefVersionKind::Publish,
                RefPrecondition::Present(oid(0x44)),
                BaseRequestSelector::Present(version(0x22)),
                RefTarget::Oid(GitOid::Sha256([0x33; 32])),
            )],
            vec![pack_one()],
        );
        assert_eq!(
            digest(&wrong_target_format),
            Err(RefVersionCodecError::ObjectFormatMismatch { field: "target_oid" })
        );

        let explicit_absent_with_old_oid = input(
            uuid(4),
            vec![main_intent(
                RefVersionKind::Publish,
                RefPrecondition::Present(oid(0x44)),
                BaseRequestSelector::ExplicitAbsent,
                RefTarget::Oid(oid(0x33)),
            )],
            vec![pack_one()],
        );
        assert!(matches!(digest(&explicit_absent_with_old_oid), Err(RefVersionCodecError::InvalidRequestShape { .. })));

        let delete_without_base = input(
            uuid(4),
            vec![main_intent(
                RefVersionKind::Delete,
                RefPrecondition::Absent,
                BaseRequestSelector::ExplicitAbsent,
                RefTarget::Delete,
            )],
            vec![pack_one()],
        );
        assert!(matches!(digest(&delete_without_base), Err(RefVersionCodecError::InvalidRequestShape { .. })));

        let delete_with_target = input(
            uuid(4),
            vec![main_intent(
                RefVersionKind::Delete,
                RefPrecondition::Present(oid(0x44)),
                BaseRequestSelector::Present(version(0x22)),
                RefTarget::Oid(oid(0x33)),
            )],
            vec![pack_one()],
        );
        assert!(matches!(digest(&delete_with_target), Err(RefVersionCodecError::InvalidRequestShape { .. })));

        let mixed_repack = input(
            uuid(4),
            vec![
                main_intent(
                    RefVersionKind::Repack,
                    RefPrecondition::Present(oid(0x44)),
                    BaseRequestSelector::Present(version(0x22)),
                    RefTarget::Oid(oid(0x33)),
                ),
                topic_intent(),
            ],
            vec![pack_one()],
        );
        assert!(matches!(digest(&mixed_repack), Err(RefVersionCodecError::InvalidRequestShape { .. })));

        let bad_head = OperationDigestInput::new(
            realm(),
            uuid(5),
            uuid(6),
            IssuerLane::new("main").unwrap(),
            3,
            uuid(4),
            41,
            RequestDigest::from_bytes([0x55; 32]),
            CommitMode::Atomic,
            HeadUpdate::Retarget(RefName::new("refs/tags/v1").unwrap()),
            vec![a_intent()],
            RequestDigest::from_bytes([0x66; 32]),
            vec![pack_one()],
        );
        assert!(matches!(digest(&bad_head), Err(RefVersionCodecError::InvalidRequestShape { .. })));
    }

    #[test]
    fn identifiers_and_persisted_counters_are_checked() {
        let nil_tenant = build_input_with_realm(
            realm_with(Uuid::nil(), uuid(2), uuid(3), 7, 0, 9, GitObjectFormat::Sha1),
            uuid(5),
            uuid(6),
            uuid(4),
            3,
            41,
            vec![a_intent()],
            vec![pack_one()],
        );
        assert_eq!(digest(&nil_tenant), Err(RefVersionCodecError::NilIdentifier { field: "tenant_id" }));

        let nil_owner =
            build_input_with_realm(realm(), Uuid::nil(), uuid(6), uuid(4), 3, 41, vec![a_intent()], vec![pack_one()]);
        assert_eq!(digest(&nil_owner), Err(RefVersionCodecError::NilIdentifier { field: "owner_id" }));

        let nil_issuer =
            build_input_with_realm(realm(), uuid(5), Uuid::nil(), uuid(4), 3, 41, vec![a_intent()], vec![pack_one()]);
        assert_eq!(digest(&nil_issuer), Err(RefVersionCodecError::NilIdentifier { field: "issuer_id" }));

        let nil_operation =
            build_input_with_realm(realm(), uuid(5), uuid(6), Uuid::nil(), 3, 41, vec![a_intent()], vec![pack_one()]);
        assert_eq!(digest(&nil_operation), Err(RefVersionCodecError::NilIdentifier { field: "operation_id" }));

        let negative_epoch = build_input_with_realm(
            realm_with(uuid(1), uuid(2), uuid(3), -1, 0, 9, GitObjectFormat::Sha1),
            uuid(5),
            uuid(6),
            uuid(4),
            3,
            41,
            vec![a_intent()],
            vec![pack_one()],
        );
        assert_eq!(digest(&negative_epoch), Err(RefVersionCodecError::NegativeCounter { field: "authority_epoch" }));

        let negative_group = build_input_with_realm(
            realm_with(uuid(1), uuid(2), uuid(3), 7, -1, 9, GitObjectFormat::Sha1),
            uuid(5),
            uuid(6),
            uuid(4),
            3,
            41,
            vec![a_intent()],
            vec![pack_one()],
        );
        assert_eq!(digest(&negative_group), Err(RefVersionCodecError::NegativeCounter { field: "group_id" }));

        let zero_group_epoch = build_input_with_realm(
            realm_with(uuid(1), uuid(2), uuid(3), 7, 0, 0, GitObjectFormat::Sha1),
            uuid(5),
            uuid(6),
            uuid(4),
            3,
            41,
            vec![a_intent()],
            vec![pack_one()],
        );
        assert_eq!(digest(&zero_group_epoch), Err(RefVersionCodecError::ZeroCounter { field: "group_epoch" }));

        let negative_sequence =
            build_input_with_realm(realm(), uuid(5), uuid(6), uuid(4), -1, 41, vec![a_intent()], vec![pack_one()]);
        assert_eq!(digest(&negative_sequence), Err(RefVersionCodecError::NegativeCounter { field: "issuer_sequence" }));

        let zero_revision =
            build_input_with_realm(realm(), uuid(5), uuid(6), uuid(4), 3, 0, vec![a_intent()], vec![pack_one()]);
        assert_eq!(digest(&zero_revision), Err(RefVersionCodecError::ZeroCounter { field: "expected_gate_revision" }));
    }
}
