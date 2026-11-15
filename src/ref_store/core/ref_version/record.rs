//! Immutable `VersionRecord` (§2.1), `RefHead` (§2.2), tombstone/ABA lineage and CAS base coherence.
use super::commit_set::CommitSetId;
use super::contract::{
    BaseRequestSelector, OperationDigest, RefVersionCodecError, RefVersionIntent, RefVersionKind, RefVersionRealm,
    VersionId,
};
use super::digest::{CanonicalWriter, ensure_present_oid, hash_sha256, push_oid, require_non_nil, validate_realm};
use super::limits::{MAX_OBJECT_DEPS_PER_VERSION, count_u32, positive_u64};
use super::pack_set::PackSetDigest;
use super::reasons::CausalRejectCode;
use crate::ref_store::core::types::{GitOid, RefName, RefPrecondition, RefTarget};
use std::collections::BTreeSet;
use std::fmt;
use uuid::Uuid;

const RECORD_DOMAIN: &[u8] = b"ry-ref-version-record-v1";

/// Canonical SHA-256 digest over an immutable [`VersionRecord`] (§2.1).
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RecordDigest([u8; 32]);

impl RecordDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for RecordDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "RecordDigest({})", hex::encode(self.0))
    }
}

/// Input parameters used by an authority to mint and seal a [`VersionRecord`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionRecordInput {
    pub version_id: VersionId,
    pub realm: RefVersionRealm,
    pub ref_name: RefName,
    pub ref_generation: u64,
    pub operation_id: Uuid,
    pub operation_digest: OperationDigest,
    pub authority_seq: i64,
    pub kind: RefVersionKind,
    pub target: RefTarget,
    pub base_version_id: Option<VersionId>,
    pub object_deps: Vec<VersionId>,
    pub pack_set_digest: PackSetDigest,
    pub commit_set_id: CommitSetId,
}

/// Authoritative immutable ref-version record binding identity, lineage, pack set,
/// verified object dependencies and commit set (§2.1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionRecord {
    version_id: VersionId,
    realm: RefVersionRealm,
    ref_name: RefName,
    ref_generation: u64,
    operation_id: Uuid,
    operation_digest: OperationDigest,
    authority_seq: i64,
    kind: RefVersionKind,
    target: RefTarget,
    base_version_id: Option<VersionId>,
    object_deps: Vec<VersionId>,
    pack_set_digest: PackSetDigest,
    commit_set_id: CommitSetId,
    record_digest: RecordDigest,
}

impl VersionRecord {
    /// Validate invariants, sort/check object dependencies, and seal `record_digest`.
    pub fn seal(input: VersionRecordInput) -> Result<Self, RefVersionCodecError> {
        validate_record_fields(&input)?;
        let mut sorted_deps = input.object_deps;
        sorted_deps.sort();
        let record_digest = compute_record_digest(
            input.version_id,
            positive_u64(input.authority_seq, "authority_seq")?,
            input.kind,
            &input.target,
            input.base_version_id,
            &sorted_deps,
            input.pack_set_digest,
            input.commit_set_id,
        )?;
        Ok(Self {
            version_id: input.version_id,
            realm: input.realm,
            ref_name: input.ref_name,
            ref_generation: input.ref_generation,
            operation_id: input.operation_id,
            operation_digest: input.operation_digest,
            authority_seq: input.authority_seq,
            kind: input.kind,
            target: input.target,
            base_version_id: input.base_version_id,
            object_deps: sorted_deps,
            pack_set_digest: input.pack_set_digest,
            commit_set_id: input.commit_set_id,
            record_digest,
        })
    }

    /// Recompute `record_digest` from fields and verify immutability.
    pub fn verify_digest(&self) -> Result<(), RefVersionCodecError> {
        let recomputed = compute_record_digest(
            self.version_id,
            positive_u64(self.authority_seq, "authority_seq")?,
            self.kind,
            &self.target,
            self.base_version_id,
            &self.object_deps,
            self.pack_set_digest,
            self.commit_set_id,
        )?;
        if recomputed != self.record_digest {
            return Err(RefVersionCodecError::RecordDigestMismatch);
        }
        Ok(())
    }

    pub const fn version_id(&self) -> VersionId {
        self.version_id
    }

    pub const fn realm(&self) -> &RefVersionRealm {
        &self.realm
    }

    pub fn ref_name(&self) -> &RefName {
        &self.ref_name
    }

    pub const fn ref_generation(&self) -> u64 {
        self.ref_generation
    }

    pub const fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    pub const fn operation_digest(&self) -> OperationDigest {
        self.operation_digest
    }

    pub const fn authority_seq(&self) -> i64 {
        self.authority_seq
    }

    pub const fn kind(&self) -> RefVersionKind {
        self.kind
    }

    pub const fn target(&self) -> &RefTarget {
        &self.target
    }

    pub const fn base_version_id(&self) -> Option<VersionId> {
        self.base_version_id
    }

    pub fn object_deps(&self) -> &[VersionId] {
        &self.object_deps
    }

    pub const fn pack_set_digest(&self) -> PackSetDigest {
        self.pack_set_digest
    }

    pub const fn commit_set_id(&self) -> CommitSetId {
        self.commit_set_id
    }

    pub const fn record_digest(&self) -> RecordDigest {
        self.record_digest
    }

    pub const fn is_tombstone(&self) -> bool {
        matches!(self.kind, RefVersionKind::Delete) || matches!(self.target, RefTarget::Delete)
    }
}

/// Enforce insert-only record immutability for an existing `VersionId` (§2.1).
pub fn ensure_immutable_record(existing: &VersionRecord, candidate: &VersionRecord) -> Result<(), CausalRejectCode> {
    if existing.version_id() != candidate.version_id() {
        return Err(CausalRejectCode::VersionIdRecordConflict);
    }
    if existing.record_digest() != candidate.record_digest() || existing != candidate {
        return Err(CausalRejectCode::VersionIdRecordConflict);
    }
    Ok(())
}

/// Authoritative per-ref head pointer and monotonic generation high-water mark (§2.2).
///
/// Deletion moves the head to `target = None` while advancing `ref_generation`
/// and updating `version_id` so recreated refs can never collide with prior generations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RefHead {
    realm: RefVersionRealm,
    ref_name: RefName,
    version_id: VersionId,
    ref_generation: u64,
    target: Option<GitOid>,
}

impl RefHead {
    pub fn from_committed(record: &VersionRecord) -> Result<Self, RefVersionCodecError> {
        record.verify_digest()?;
        let target = match record.target() {
            RefTarget::Delete => None,
            RefTarget::Oid(oid) => Some(*oid),
        };
        Ok(Self {
            realm: *record.realm(),
            ref_name: record.ref_name().clone(),
            version_id: record.version_id(),
            ref_generation: record.ref_generation(),
            target,
        })
    }

    pub const fn realm(&self) -> &RefVersionRealm {
        &self.realm
    }

    pub fn ref_name(&self) -> &RefName {
        &self.ref_name
    }

    pub const fn version_id(&self) -> VersionId {
        self.version_id
    }

    pub const fn ref_generation(&self) -> u64 {
        self.ref_generation
    }

    pub const fn target(&self) -> Option<GitOid> {
        self.target
    }

    pub const fn is_tombstone(&self) -> bool {
        self.target.is_none()
    }
}

/// Result of verifying a prospective ref update against the authoritative [`RefHead`] (§2.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BaseCoherenceError {
    /// Request shape cannot mint a causal version (e.g. legacy absent base selector).
    LegacyUnsupported,
    /// Authoritative rejection mapped into the closed §2.5.2 code table.
    Rejected(CausalRejectCode),
}

/// Validate `intent`'s base selector and old-OID precondition against `current_head`
/// using the §2.2 / §2.5.2 precedence rules (`base_version_mismatch` beats `old_oid_mismatch`).
pub fn verify_base_coherence(
    realm: &RefVersionRealm,
    intent: &RefVersionIntent,
    current_head: Option<&RefHead>,
) -> Result<u64, BaseCoherenceError> {
    match intent.base() {
        BaseRequestSelector::LegacyNotSupplied => Err(BaseCoherenceError::LegacyUnsupported),
        BaseRequestSelector::ExplicitAbsent => {
            if current_head.is_some() {
                return Err(BaseCoherenceError::Rejected(CausalRejectCode::BaseVersionMismatch));
            }
            if !matches!(intent.precondition(), RefPrecondition::Absent) {
                return Err(BaseCoherenceError::Rejected(CausalRejectCode::BaseVersionMismatch));
            }
            if intent.kind() != RefVersionKind::Publish {
                return Err(BaseCoherenceError::Rejected(CausalRejectCode::BaseVersionMismatch));
            }
            Ok(1)
        }
        BaseRequestSelector::Present(expected_base) => {
            let Some(head) = current_head else {
                return Err(BaseCoherenceError::Rejected(CausalRejectCode::BaseVersionMismatch));
            };
            if head.realm() != realm || head.ref_name() != intent.name() || head.version_id() != *expected_base {
                return Err(BaseCoherenceError::Rejected(CausalRejectCode::BaseVersionMismatch));
            }
            let next_generation = head
                .ref_generation()
                .checked_add(1)
                .ok_or(BaseCoherenceError::Rejected(CausalRejectCode::RefGenerationExhausted))?;
            match (head.target(), intent.precondition()) {
                (Some(live_oid), RefPrecondition::Present(req_oid)) if live_oid == *req_oid => {}
                (None, RefPrecondition::Absent) => {}
                _ => return Err(BaseCoherenceError::Rejected(CausalRejectCode::OldOidMismatch)),
            }
            if intent.kind() == RefVersionKind::Repack && head.target() != intent.target().oid() {
                return Err(BaseCoherenceError::Rejected(CausalRejectCode::OldOidMismatch));
            }
            Ok(next_generation)
        }
    }
}

fn validate_record_fields(input: &VersionRecordInput) -> Result<(), RefVersionCodecError> {
    validate_realm(&input.realm)?;
    require_non_nil(input.operation_id, "operation_id")?;
    positive_u64(input.authority_seq, "authority_seq")?;
    match (input.ref_generation, input.base_version_id) {
        (0, _) => return Err(RefVersionCodecError::ZeroCounter { field: "ref_generation" }),
        (1, None) => {}
        (1, Some(_)) => return Err(RefVersionCodecError::UnexpectedAuthorityBaseGeneration),
        (_, None) => return Err(RefVersionCodecError::MissingAuthorityBaseGeneration),
        (_, Some(base_id)) => {
            if base_id == input.version_id {
                return Err(RefVersionCodecError::SelfDependency);
            }
        }
    }
    match (input.kind, &input.target) {
        (RefVersionKind::Delete, RefTarget::Delete) => {
            if !input.object_deps.is_empty() {
                return Err(RefVersionCodecError::InvalidRequestShape {
                    reason: "delete tombstone must not declare object dependencies",
                });
            }
        }
        (RefVersionKind::Delete, RefTarget::Oid(_)) => {
            return Err(RefVersionCodecError::InvalidRequestShape { reason: "delete record must omit target OID" });
        }
        (RefVersionKind::Publish | RefVersionKind::Repack, RefTarget::Oid(oid)) => {
            ensure_present_oid(input.realm.object_format(), *oid, "target_oid")?;
        }
        (RefVersionKind::Publish | RefVersionKind::Repack, RefTarget::Delete) => {
            return Err(RefVersionCodecError::InvalidRequestShape {
                reason: "publish or repack record requires a present target OID",
            });
        }
    }
    if input.object_deps.len() > MAX_OBJECT_DEPS_PER_VERSION {
        return Err(RefVersionCodecError::Capacity {
            field: "object_deps",
            limit: MAX_OBJECT_DEPS_PER_VERSION,
            actual: input.object_deps.len(),
        });
    }
    let mut seen = BTreeSet::new();
    for dep in &input.object_deps {
        if *dep == input.version_id {
            return Err(RefVersionCodecError::SelfDependency);
        }
        if !seen.insert(*dep) {
            return Err(RefVersionCodecError::DuplicateDependency);
        }
    }
    Ok(())
}

fn compute_record_digest(
    version_id: VersionId,
    authority_seq: u64,
    kind: RefVersionKind,
    target: &RefTarget,
    base_version_id: Option<VersionId>,
    sorted_deps: &[VersionId],
    pack_set_digest: PackSetDigest,
    commit_set_id: CommitSetId,
) -> Result<RecordDigest, RefVersionCodecError> {
    let mut writer = CanonicalWriter::new();
    writer.push_len_prefixed(RECORD_DOMAIN)?;
    writer.push_len_prefixed(version_id.as_bytes())?;
    writer.push_u64(authority_seq);
    writer.push_u8(kind.tag());
    match target {
        RefTarget::Delete => writer.push_u8(0),
        RefTarget::Oid(oid) => {
            writer.push_u8(1);
            push_oid(&mut writer, *oid)?;
        }
    }
    match base_version_id {
        None => writer.push_u8(0),
        Some(base_id) => {
            writer.push_u8(1);
            writer.push_len_prefixed(base_id.as_bytes())?;
        }
    }
    writer.push_u32(count_u32(sorted_deps.len(), "object_deps")?);
    for dep in sorted_deps {
        writer.push_len_prefixed(dep.as_bytes())?;
    }
    writer.push_len_prefixed(pack_set_digest.as_bytes())?;
    writer.push_len_prefixed(commit_set_id.as_bytes())?;
    Ok(RecordDigest(hash_sha256(&writer.into_bytes())))
}
