//! Complete, bounded capture of the old gate/refs/HEAD/membership state.
//!
//! A capture is the *whole* visible state, never a page: a repository that
//! exceeds [`MAX_CAPTURE_REFS`] refs or [`MAX_CAPTURE_ACTIVE_PACKS`] active
//! memberships is refused with a typed overflow before any plan, registration
//! or write exists. Truncating would silently shrink the set a proof covers.
//!
//! Old memberships are captured as full [`RegisteredPack`] values, so the
//! membership digest binds pack id, registration id, the complete artifact-set
//! digest (full physical identity of both artifacts) and `joined_revision`.
use super::artifact::{ArtifactSetDigest, RegisteredPack};
use super::contract::{MAX_ACTIVE_MEMBERSHIPS, MAX_CAPTURE_REFS, PackMode};
use super::error::{PackCommitError, PackCommitRejectCode, PackCommitRejection};
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::contract::CoreGateVersion;
use crate::ref_store::core::types::{GitObjectFormat, GitOid, RefName};
use std::collections::BTreeSet;
use uuid::Uuid;

/// One captured ref row. Names are stored exactly as the core stores them and
/// the capture is always sorted by name, so its digest is order-independent.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CapturedRef {
    name: String,
    oid: String,
}

impl CapturedRef {
    pub fn new(name: RefName, oid: GitOid) -> Result<Self, PackCommitError> {
        let captured = Self { name: name.as_str().to_owned(), oid: oid.as_hex() };
        captured.validate()?;
        Ok(captured)
    }

    pub(crate) fn from_stored(format: GitObjectFormat, name: String, oid: String) -> Result<Self, PackCommitError> {
        let captured = Self { name, oid };
        captured.validate_with(format)?;
        Ok(captured)
    }

    fn validate(&self) -> Result<(), PackCommitError> {
        let format = match self.oid.len() {
            40 => GitObjectFormat::Sha1,
            64 => GitObjectFormat::Sha256,
            _ => return Err(PackCommitError::Invalid("captured object id has an impossible length")),
        };
        self.validate_with(format)
    }

    fn validate_with(&self, format: GitObjectFormat) -> Result<(), PackCommitError> {
        RefName::new(self.name.clone()).map_err(|_| PackCommitError::Invalid("captured ref name is invalid"))?;
        GitOid::parse(format, &self.oid).map_err(|_| PackCommitError::Invalid("captured object id is invalid"))?;
        Ok(())
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn oid_hex(&self) -> &str {
        &self.oid
    }
}

/// One appended membership identity, bound to its complete registered pack.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct PackMembershipEntry {
    pack_id: Uuid,
    registration_id: Uuid,
    artifact_set_digest: ArtifactSetDigest,
    joined_revision: i64,
}

impl PackMembershipEntry {
    pub fn from_pack(pack: &RegisteredPack) -> Result<Self, PackCommitError> {
        let joined_revision = pack
            .joined_revision()
            .ok_or(PackCommitError::Invalid("an active membership must record its joined revision"))?;
        Ok(Self {
            pack_id: pack.pack_id(),
            registration_id: pack.registration_id(),
            artifact_set_digest: pack.artifact_set_digest(),
            joined_revision,
        })
    }

    pub fn new(
        pack_id: Uuid,
        registration_id: Uuid,
        artifact_set_digest: ArtifactSetDigest,
        joined_revision: i64,
    ) -> Result<Self, PackCommitError> {
        if pack_id.is_nil() || registration_id.is_nil() || joined_revision <= 0 {
            return Err(PackCommitError::Invalid("membership identity must be non-nil and positive"));
        }
        Ok(Self { pack_id, registration_id, artifact_set_digest, joined_revision })
    }

    pub fn pack_id(&self) -> Uuid {
        self.pack_id
    }
    pub fn registration_id(&self) -> Uuid {
        self.registration_id
    }
    pub fn artifact_set_digest(&self) -> ArtifactSetDigest {
        self.artifact_set_digest
    }
    pub fn joined_revision(&self) -> i64 {
        self.joined_revision
    }
}

/// Canonical digest of the complete sorted membership set. It binds the full
/// physical identity of every old pack, so an attach/detach or a rewritten
/// artifact set elsewhere cannot be missed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MembershipDigest(RequestDigest);

impl MembershipDigest {
    /// Sorts defensively, so a caller cannot make the digest depend on read
    /// order.
    pub fn of(entries: &[PackMembershipEntry]) -> Self {
        let mut sorted = entries.to_vec();
        sorted.sort();
        let mut fields = Vec::with_capacity(sorted.len() * 4 + 1);
        fields.push((sorted.len() as u64).to_be_bytes().to_vec());
        for entry in &sorted {
            fields.push(entry.pack_id.as_bytes().to_vec());
            fields.push(entry.registration_id.as_bytes().to_vec());
            fields.push(entry.artifact_set_digest.digest().as_bytes().to_vec());
            fields.push(entry.joined_revision.to_be_bytes().to_vec());
        }
        let parts = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
        Self(RequestDigest::of("core-pack-membership-v2", &parts))
    }

    pub fn digest(&self) -> &RequestDigest {
        &self.0
    }

    pub fn as_hex(&self) -> String {
        self.0.as_hex()
    }
}

/// Digest of one complete, sorted ref set (old capture or exact result).
pub fn refs_digest(refs: &[CapturedRef]) -> RequestDigest {
    let mut sorted = refs.to_vec();
    sorted.sort();
    let mut fields = Vec::with_capacity(sorted.len() * 2 + 1);
    fields.push((sorted.len() as u64).to_be_bytes().to_vec());
    for reference in &sorted {
        fields.push(reference.name.as_bytes().to_vec());
        fields.push(reference.oid.as_bytes().to_vec());
    }
    let parts = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
    RequestDigest::of("core-pack-ref-set-v1", &parts)
}

/// Immutable short-read capture of the complete pre-commit state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackCommitBaseline {
    gate: CoreGateVersion,
    mode: PackMode,
    refs: Vec<CapturedRef>,
    old_packs: Vec<RegisteredPack>,
    membership_digest: MembershipDigest,
}

impl PackCommitBaseline {
    /// Validates bounds, uniqueness and canonical order. Never truncates.
    pub fn new(
        gate: CoreGateVersion,
        mode: PackMode,
        refs: Vec<CapturedRef>,
        old_packs: Vec<RegisteredPack>,
    ) -> Result<Self, PackCommitError> {
        if refs.len() as i64 > MAX_CAPTURE_REFS {
            return Err(PackCommitError::Capacity {
                limit: "capture_refs",
                bound: MAX_CAPTURE_REFS,
                actual: refs.len() as i64,
            });
        }
        if old_packs.len() as i64 > MAX_ACTIVE_MEMBERSHIPS {
            return Err(PackCommitError::Capacity {
                limit: "capture_active_packs",
                bound: MAX_ACTIVE_MEMBERSHIPS,
                actual: old_packs.len() as i64,
            });
        }
        // A metadata-only gate may not silently adopt old pack memberships: the
        // global registration ledger survives business deletion, so a reused
        // repository UUID must not inherit old owner/history artifacts into a
        // metadata-only commit. Refused before any A3/Blob IO.
        if mode == PackMode::MetadataOnly && !old_packs.is_empty() {
            return Err(PackCommitError::Rejected(PackCommitRejection::new(
                PackCommitRejectCode::ModeMismatch,
                "metadata_only gate must not adopt old pack memberships",
            )));
        }
        for pack in &old_packs {
            if let Some(joined) = pack.joined_revision()
                && (joined <= 0 || joined > gate.revision())
            {
                return Err(PackCommitError::Rejected(PackCommitRejection::new(
                    PackCommitRejectCode::OldMembershipMismatch,
                    "membership joined revision is not within this gate history",
                )));
            }
        }
        let mut names = BTreeSet::new();
        for reference in &refs {
            reference.validate_with(gate.object_format())?;
            if !names.insert(reference.name.clone()) {
                return Err(PackCommitError::Invalid("captured ref set contains a duplicate name"));
            }
        }
        let mut pack_ids = BTreeSet::new();
        let mut entries = Vec::with_capacity(old_packs.len());
        for pack in &old_packs {
            if !pack_ids.insert(pack.pack_id()) {
                return Err(PackCommitError::Invalid("captured membership contains a duplicate pack"));
            }
            entries.push(PackMembershipEntry::from_pack(pack)?);
        }
        let membership_digest = MembershipDigest::of(&entries);
        let mut refs = refs;
        refs.sort();
        let mut old_packs = old_packs;
        old_packs.sort_by_key(RegisteredPack::pack_id);
        Ok(Self { gate, mode, refs, old_packs, membership_digest })
    }

    pub fn gate(&self) -> &CoreGateVersion {
        &self.gate
    }

    pub fn mode(&self) -> PackMode {
        self.mode
    }

    pub fn refs(&self) -> &[CapturedRef] {
        &self.refs
    }

    pub fn old_packs(&self) -> &[RegisteredPack] {
        &self.old_packs
    }

    pub fn membership_digest(&self) -> MembershipDigest {
        self.membership_digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn membership_digest_binds_full_pack_identity() {
        let digest = ArtifactSetDigest::of(&[]);
        let entry = |pack: u8, digest: ArtifactSetDigest| {
            PackMembershipEntry::new(Uuid::from_bytes([pack; 16]), Uuid::from_bytes([pack + 1; 16]), digest, 2).unwrap()
        };
        let forward = MembershipDigest::of(&[entry(1, digest), entry(2, digest)]);
        let reverse = MembershipDigest::of(&[entry(2, digest), entry(1, digest)]);
        assert_eq!(forward, reverse);
        assert_ne!(forward, MembershipDigest::of(&[entry(1, digest)]));
        assert!(PackMembershipEntry::new(Uuid::nil(), Uuid::from_bytes([1; 16]), digest, 1).is_err());
        assert!(PackMembershipEntry::new(Uuid::from_bytes([1; 16]), Uuid::from_bytes([2; 16]), digest, 0).is_err());
    }

    #[test]
    fn ref_capture_rejects_invalid_or_duplicate_rows() {
        let name = RefName::new("refs/heads/main").unwrap();
        let oid = GitOid::Sha1([7; 20]);
        let captured = CapturedRef::new(name, oid).unwrap();
        assert_eq!(captured.oid_hex(), oid.as_hex());
        assert!(CapturedRef::from_stored(GitObjectFormat::Sha256, "refs/heads/main".into(), oid.as_hex()).is_err());
        assert!(refs_digest(std::slice::from_ref(&captured)) != refs_digest(&[]));
    }
}
