//! Immutable compaction cover hierarchy records and concurrency fencing (Issue #184).
//!
//! Each [`CoverHierarchyRecord`] binds a physical pack/idx pair ([`VerifiedClosurePack`],
//! [`CoverArtifactPair`]) to an exact realm, tier, covered ref-version set, commit DAG
//! links, compaction input lineage, membership digest, compaction epoch, and canonical
//! SHA-256 record digest (`ry-pack-cover-record-v1`).
use super::super::contract::{RefVersionCodecError, RefVersionRealm, VersionId};
use super::super::digest::{CanonicalWriter, format_tag, validate_realm};
use super::super::limits::count_u32;
use super::super::pack_set::{PackSetEntry, VerifiedClosurePack};
pub use super::model_codec::CoverHierarchyIndex;
use super::model_codec::{compute_record_digest, normalize_and_validate};
use crate::blob_store::BlobLocator;
use crate::ref_store::core::types::GitOid;
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

const COVER_MEMBERSHIP_DOMAIN: &[u8] = b"ry-pack-cover-membership-v1";

/// Compaction hierarchy tier (`L0` leaf delta -> `L3` deep baseline cover).
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverTier {
    Delta,
    Segment,
    Compacted,
    Base,
}

impl CoverTier {
    pub const fn tag(self) -> u8 {
        match self {
            Self::Delta => 0,
            Self::Segment => 1,
            Self::Compacted => 2,
            Self::Base => 3,
        }
    }

    pub const fn rank(self) -> u8 {
        self.tag()
    }
}

/// Canonical SHA-256 digest of a [`CoverHierarchyRecord`].
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CoverRecordDigest([u8; 32]);

impl CoverRecordDigest {
    pub(super) const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for CoverRecordDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CoverRecordDigest({})", hex::encode(self.0))
    }
}

/// Canonical SHA-256 digest of an active repository pack membership snapshot.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CoverMembershipDigest([u8; 32]);

impl CoverMembershipDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for CoverMembershipDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CoverMembershipDigest({})", hex::encode(self.0))
    }
}

/// Physical Blob locators and thin-pack delta-base dependency edges for one cover pack.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverArtifactPair {
    pub pack_stem: String,
    pub pack_locator: BlobLocator,
    pub idx_locator: BlobLocator,
    pub is_thin_pack: bool,
    pub delta_base_cover_ids: Vec<Uuid>,
}

/// Commit DAG node covered by a pack cover, carrying exact parent links and causal version.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverCommitLink {
    pub commit_oid: GitOid,
    pub parent_oids: Vec<GitOid>,
    pub version_id: VersionId,
    pub authority_seq: i64,
}

/// Unsealed input parameters to mint and digest-bind a [`CoverHierarchyRecord`].
#[derive(Clone, Debug)]
pub struct CoverHierarchyRecordInput {
    pub cover_id: Uuid,
    pub realm: RefVersionRealm,
    pub tier: CoverTier,
    pub pack: VerifiedClosurePack,
    pub artifacts: CoverArtifactPair,
    pub covered_versions: Vec<VersionId>,
    pub min_authority_seq: i64,
    pub max_authority_seq: i64,
    pub covered_commits: Vec<CoverCommitLink>,
    pub input_cover_ids: Vec<Uuid>,
    pub membership_generation: u64,
    pub membership_digest: CoverMembershipDigest,
    pub compaction_epoch: u64,
    pub worker_id: Uuid,
    pub operation_id: Uuid,
}

/// Immutable, digest-sealed compaction cover record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverHierarchyRecord {
    cover_id: Uuid,
    realm: RefVersionRealm,
    tier: CoverTier,
    pack: VerifiedClosurePack,
    artifacts: CoverArtifactPair,
    covered_versions: Vec<VersionId>,
    min_authority_seq: i64,
    max_authority_seq: i64,
    covered_commits: Vec<CoverCommitLink>,
    input_cover_ids: Vec<Uuid>,
    membership_generation: u64,
    membership_digest: CoverMembershipDigest,
    compaction_epoch: u64,
    worker_id: Uuid,
    operation_id: Uuid,
    record_digest: CoverRecordDigest,
}

/// Typed errors raised by cover hierarchy sealing or compaction publication fencing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoverModelError {
    Codec(RefVersionCodecError),
    InvalidShape(&'static str),
    RecordDigestMismatch,
    CoverRecordConflict,
    RealmMismatch,
    StaleCompactionEpoch,
    MembershipConflict,
    MissingInputCover,
    InputCoverageDrop,
    MissingDeltaBaseCover,
    ActiveHoldPreventsRetirement,
}

impl fmt::Display for CoverModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Codec(err) => write!(f, "cover codec error: {err}"),
            Self::InvalidShape(msg) => write!(f, "invalid cover shape: {msg}"),
            Self::RecordDigestMismatch => f.write_str("cover record digest mismatch"),
            Self::CoverRecordConflict => f.write_str("conflicting record for existing cover id"),
            Self::RealmMismatch => f.write_str("cover realm does not match index realm"),
            Self::StaleCompactionEpoch => f.write_str("compaction worker epoch is stale"),
            Self::MembershipConflict => f.write_str("active pack membership changed concurrently"),
            Self::MissingInputCover => f.write_str("compaction input cover not found"),
            Self::InputCoverageDrop => f.write_str("compacted cover dropped input versions or commits"),
            Self::MissingDeltaBaseCover => f.write_str("thin-pack external delta base cover missing"),
            Self::ActiveHoldPreventsRetirement => f.write_str("active holds prevent cover retirement"),
        }
    }
}

impl std::error::Error for CoverModelError {}

impl From<RefVersionCodecError> for CoverModelError {
    fn from(value: RefVersionCodecError) -> Self {
        Self::Codec(value)
    }
}

/// Result of publishing a compacted cover under monotonic epoch + membership CAS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompactionPublishOutcome {
    Committed,
    IdempotentReplay,
}

/// Compute canonical membership digest over sorted active [`PackSetEntry`] items.
pub fn compute_cover_membership_digest(
    realm: &RefVersionRealm,
    membership_generation: u64,
    entries: &[PackSetEntry],
) -> Result<CoverMembershipDigest, CoverModelError> {
    let nums = validate_realm(realm)?;
    if membership_generation == 0 {
        return Err(CoverModelError::InvalidShape("membership_generation must be positive"));
    }
    let mut sorted = entries.to_vec();
    sorted.sort_by_key(|entry| (entry.pack_id(), entry.registration_id()));
    for pair in sorted.windows(2) {
        if pair[0].pack_id() == pair[1].pack_id() || pair[0].registration_id() == pair[1].registration_id() {
            return Err(CoverModelError::InvalidShape("duplicate pack or registration in membership"));
        }
    }
    let mut writer = CanonicalWriter::new();
    writer.push_len_prefixed(COVER_MEMBERSHIP_DOMAIN)?;
    writer.push_len_prefixed(realm.tenant_id().as_bytes())?;
    writer.push_len_prefixed(realm.repository_id().as_bytes())?;
    writer.push_len_prefixed(realm.history_incarnation().as_bytes())?;
    writer.push_u8(realm.authority_kind().tag());
    writer.push_u64(nums.authority_epoch);
    writer.push_u64(nums.group_id);
    writer.push_u64(nums.group_epoch);
    writer.push_u8(format_tag(realm.object_format()));
    writer.push_u64(membership_generation);
    writer.push_u32(count_u32(sorted.len(), "membership_entries")?);
    for entry in &sorted {
        writer.push_len_prefixed(entry.pack_id().as_bytes())?;
        writer.push_len_prefixed(entry.registration_id().as_bytes())?;
        writer.push_len_prefixed(entry.artifact_set_digest())?;
    }
    Ok(CoverMembershipDigest(writer.finish()))
}

impl CoverHierarchyRecord {
    /// Validate invariants, normalize deterministic orderings, and seal `record_digest`.
    pub fn seal(mut input: CoverHierarchyRecordInput) -> Result<Self, CoverModelError> {
        normalize_and_validate(&mut input)?;
        let digest = compute_record_digest(&input)?;
        Ok(Self {
            cover_id: input.cover_id,
            realm: input.realm,
            tier: input.tier,
            pack: input.pack,
            artifacts: input.artifacts,
            covered_versions: input.covered_versions,
            min_authority_seq: input.min_authority_seq,
            max_authority_seq: input.max_authority_seq,
            covered_commits: input.covered_commits,
            input_cover_ids: input.input_cover_ids,
            membership_generation: input.membership_generation,
            membership_digest: input.membership_digest,
            compaction_epoch: input.compaction_epoch,
            worker_id: input.worker_id,
            operation_id: input.operation_id,
            record_digest: digest,
        })
    }

    /// Recompute `record_digest` and fail closed on any field or locator tamper.
    pub fn verify_digest(&self) -> Result<(), CoverModelError> {
        let mut copy = CoverHierarchyRecordInput {
            cover_id: self.cover_id,
            realm: self.realm,
            tier: self.tier,
            pack: self.pack.clone(),
            artifacts: self.artifacts.clone(),
            covered_versions: self.covered_versions.clone(),
            min_authority_seq: self.min_authority_seq,
            max_authority_seq: self.max_authority_seq,
            covered_commits: self.covered_commits.clone(),
            input_cover_ids: self.input_cover_ids.clone(),
            membership_generation: self.membership_generation,
            membership_digest: self.membership_digest,
            compaction_epoch: self.compaction_epoch,
            worker_id: self.worker_id,
            operation_id: self.operation_id,
        };
        normalize_and_validate(&mut copy)?;
        let expected = compute_record_digest(&copy)?;
        if expected != self.record_digest
            || copy.covered_versions != self.covered_versions
            || copy.covered_commits != self.covered_commits
            || copy.input_cover_ids != self.input_cover_ids
            || copy.artifacts.delta_base_cover_ids != self.artifacts.delta_base_cover_ids
        {
            return Err(CoverModelError::RecordDigestMismatch);
        }
        Ok(())
    }

    pub const fn cover_id(&self) -> Uuid {
        self.cover_id
    }
    pub const fn realm(&self) -> &RefVersionRealm {
        &self.realm
    }
    pub const fn tier(&self) -> CoverTier {
        self.tier
    }
    pub const fn pack(&self) -> &VerifiedClosurePack {
        &self.pack
    }
    pub const fn artifacts(&self) -> &CoverArtifactPair {
        &self.artifacts
    }
    pub fn covered_versions(&self) -> &[VersionId] {
        &self.covered_versions
    }
    pub const fn min_authority_seq(&self) -> i64 {
        self.min_authority_seq
    }
    pub const fn max_authority_seq(&self) -> i64 {
        self.max_authority_seq
    }
    pub fn covered_commits(&self) -> &[CoverCommitLink] {
        &self.covered_commits
    }
    pub fn input_cover_ids(&self) -> &[Uuid] {
        &self.input_cover_ids
    }
    pub const fn membership_generation(&self) -> u64 {
        self.membership_generation
    }
    pub const fn membership_digest(&self) -> CoverMembershipDigest {
        self.membership_digest
    }
    pub const fn compaction_epoch(&self) -> u64 {
        self.compaction_epoch
    }
    pub const fn worker_id(&self) -> Uuid {
        self.worker_id
    }
    pub const fn operation_id(&self) -> Uuid {
        self.operation_id
    }
    pub const fn record_digest(&self) -> CoverRecordDigest {
        self.record_digest
    }

    #[cfg(test)]
    pub(super) fn tamper_record_digest_for_test(&mut self) {
        self.record_digest.0[0] ^= 0xff;
    }
}

pub(super) fn oid_bytes(oid: GitOid) -> Vec<u8> {
    match oid {
        GitOid::Sha1(b) => b.to_vec(),
        GitOid::Sha256(b) => b.to_vec(),
    }
}
