//! Canonical `CommitSetId` (§2.5) for atomic committed ref-version batches.
use super::contract::{OperationDigest, RefVersionCodecError, RefVersionKind, RefVersionRealm, VersionId};
use super::digest::{CanonicalWriter, ensure_present_oid, format_tag, push_oid, require_non_nil, validate_realm};
use super::limits::{MAX_COMMIT_SET_REFS, count_u32, positive_u64};
use crate::ref_store::core::types::{GitOid, RefName, RefTarget};
use std::collections::BTreeSet;
use std::fmt;
use uuid::Uuid;

const COMMIT_SET_DOMAIN: &[u8] = b"ry-version-commit-set-id-v1";

/// One committed version entry inside a [`CommitSetInput`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitSetVersionEntry {
    ref_name: RefName,
    version_id: VersionId,
    kind: RefVersionKind,
    target: RefTarget,
}

impl CommitSetVersionEntry {
    pub fn new(ref_name: RefName, version_id: VersionId, kind: RefVersionKind, target: RefTarget) -> Self {
        Self { ref_name, version_id, kind, target }
    }

    pub fn ref_name(&self) -> &RefName {
        &self.ref_name
    }

    pub const fn version_id(&self) -> VersionId {
        self.version_id
    }

    pub const fn kind(&self) -> RefVersionKind {
        self.kind
    }

    pub const fn target(&self) -> &RefTarget {
        &self.target
    }
}

/// Optional resulting HEAD state bound by `CommitSetId` (§2.5).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommitSetHead {
    /// `head_tag = 0`: no HEAD branch recorded.
    Absent,
    /// `head_tag = 1`: HEAD names `ref_name`, with `target_tag = 0 | 1`.
    Present { ref_name: RefName, target_oid: Option<GitOid> },
}

/// Preimage input for `CommitSetId = SHA-256(CS)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitSetInput {
    realm: RefVersionRealm,
    authority_seq: i64,
    operation_id: Uuid,
    operation_digest: OperationDigest,
    versions: Vec<CommitSetVersionEntry>,
    head: CommitSetHead,
}

impl CommitSetInput {
    pub fn new(
        realm: RefVersionRealm,
        authority_seq: i64,
        operation_id: Uuid,
        operation_digest: OperationDigest,
        versions: Vec<CommitSetVersionEntry>,
        head: CommitSetHead,
    ) -> Self {
        Self { realm, authority_seq, operation_id, operation_digest, versions, head }
    }

    pub const fn realm(&self) -> &RefVersionRealm {
        &self.realm
    }

    pub const fn authority_seq(&self) -> i64 {
        self.authority_seq
    }

    pub const fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    pub const fn operation_digest(&self) -> OperationDigest {
        self.operation_digest
    }

    pub fn versions(&self) -> &[CommitSetVersionEntry] {
        &self.versions
    }

    pub const fn head(&self) -> &CommitSetHead {
        &self.head
    }
}

/// Canonical SHA-256 identifier for one committed ref-version batch (§2.5).
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CommitSetId([u8; 32]);

impl CommitSetId {
    pub(super) const fn from_canonical_hash(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for CommitSetId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "CommitSetId({})", hex::encode(self.0))
    }
}

/// Compute `CommitSetId` and the encoded preimage length (§2.5).
pub fn compute_commit_set_id(input: &CommitSetInput) -> Result<CommitSetId, RefVersionCodecError> {
    let (bytes, id) = encode_commit_set(input)?;
    let _ = bytes.len();
    Ok(id)
}

pub(crate) fn encode_commit_set(input: &CommitSetInput) -> Result<(Vec<u8>, CommitSetId), RefVersionCodecError> {
    let realm = input.realm();
    let realm_numbers = validate_realm(realm)?;
    let authority_seq = positive_u64(input.authority_seq(), "authority_seq")?;
    require_non_nil(input.operation_id(), "operation_id")?;
    if input.versions().is_empty() {
        return Err(RefVersionCodecError::InvalidRequestShape {
            reason: "a committed version set must contain at least one ref",
        });
    }
    if input.versions().len() > MAX_COMMIT_SET_REFS {
        return Err(RefVersionCodecError::Capacity {
            field: "commit_set_versions",
            limit: MAX_COMMIT_SET_REFS,
            actual: input.versions().len(),
        });
    }
    let mut names = BTreeSet::new();
    let has_repack = input.versions().iter().any(|entry| entry.kind() == RefVersionKind::Repack);
    for entry in input.versions() {
        if !names.insert(entry.ref_name().as_str()) {
            return Err(RefVersionCodecError::DuplicateRefName);
        }
        if has_repack && entry.kind() != RefVersionKind::Repack {
            return Err(RefVersionCodecError::InvalidRequestShape {
                reason: "repack appears only in an all-repack maintenance commit set",
            });
        }
        match (entry.kind(), entry.target()) {
            (RefVersionKind::Delete, RefTarget::Delete) => {}
            (RefVersionKind::Delete, RefTarget::Oid(_)) => {
                return Err(RefVersionCodecError::InvalidRequestShape { reason: "delete entry must omit target OID" });
            }
            (RefVersionKind::Publish | RefVersionKind::Repack, RefTarget::Oid(oid)) => {
                ensure_present_oid(realm.object_format(), *oid, "target_oid")?;
            }
            (RefVersionKind::Publish | RefVersionKind::Repack, RefTarget::Delete) => {
                return Err(RefVersionCodecError::InvalidRequestShape {
                    reason: "publish or repack entry requires a present target OID",
                });
            }
        }
    }
    if let CommitSetHead::Present { ref_name, target_oid } = input.head() {
        if !ref_name.is_branch() {
            return Err(RefVersionCodecError::InvalidRequestShape { reason: "HEAD must name a refs/heads/ branch" });
        }
        if let Some(oid) = target_oid {
            ensure_present_oid(realm.object_format(), *oid, "head_oid")?;
        }
    }
    let mut sorted: Vec<&CommitSetVersionEntry> = input.versions().iter().collect();
    sorted.sort_by(|left, right| {
        left.ref_name().as_str().cmp(right.ref_name().as_str()).then_with(|| left.version_id().cmp(&right.version_id()))
    });
    let mut writer = CanonicalWriter::new();
    writer.push_len_prefixed(COMMIT_SET_DOMAIN)?;
    writer.push_len_prefixed(realm.tenant_id().as_bytes())?;
    writer.push_len_prefixed(realm.repository_id().as_bytes())?;
    writer.push_len_prefixed(realm.history_incarnation().as_bytes())?;
    writer.push_u8(realm.authority_kind().tag());
    writer.push_u64(realm_numbers.authority_epoch);
    writer.push_u64(realm_numbers.group_id);
    writer.push_u64(realm_numbers.group_epoch);
    writer.push_u8(format_tag(realm.object_format()));
    writer.push_u64(authority_seq);
    writer.push_len_prefixed(input.operation_id().as_bytes())?;
    writer.push_len_prefixed(input.operation_digest().as_bytes())?;
    writer.push_u32(count_u32(sorted.len(), "commit_set_versions")?);
    for entry in sorted {
        writer.push_len_prefixed(entry.ref_name().as_str().as_bytes())?;
        writer.push_len_prefixed(entry.version_id().as_bytes())?;
        writer.push_u8(entry.kind().tag());
        match entry.target() {
            RefTarget::Delete => writer.push_u8(0),
            RefTarget::Oid(oid) => {
                writer.push_u8(1);
                push_oid(&mut writer, *oid)?;
            }
        }
    }
    match input.head() {
        CommitSetHead::Absent => writer.push_u8(0),
        CommitSetHead::Present { ref_name, target_oid } => {
            writer.push_u8(1);
            writer.push_len_prefixed(ref_name.as_str().as_bytes())?;
            match target_oid {
                None => writer.push_u8(0),
                Some(oid) => {
                    writer.push_u8(1);
                    push_oid(&mut writer, *oid)?;
                }
            }
        }
    }
    let bytes = writer.into_bytes();
    let id = CommitSetId::from_canonical_hash(super::digest::hash_sha256(&bytes));
    Ok((bytes, id))
}
