//! Immutable pack-set digests (`PackSetDigest`, §2.3) and verified closure pack records.
use super::contract::RefVersionCodecError;
use super::digest::{CanonicalWriter, require_non_nil};
use super::limits::{ARTIFACTS_PER_PACK, MAX_CLOSURE_PACKS, MAX_OPERATION_PLANNED_BYTES, count_u32};
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::pack_commit::{PackArtifactRole, RegisteredPack};
use std::collections::BTreeSet;
use std::fmt;
use uuid::Uuid;

const PACK_SET_DOMAIN: &[u8] = b"ry-version-pack-set-v1";

/// One entry of a version's own immutable pack set (§2.3).
///
/// `joined_revision` is excluded: pack set digests bind physical registered
/// identity `(pack_id, registration_id, artifact_set_digest)` regardless of membership revision.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PackSetEntry {
    pack_id: Uuid,
    registration_id: Uuid,
    artifact_set_digest: [u8; 32],
}

impl PackSetEntry {
    /// Construct an entry from explicit identifiers and an [`ArtifactSetDigest`] raw hash.
    pub fn new(
        pack_id: Uuid,
        registration_id: Uuid,
        artifact_set_digest: RequestDigest,
    ) -> Result<Self, RefVersionCodecError> {
        require_non_nil(pack_id, "pack_id")?;
        require_non_nil(registration_id, "registration_id")?;
        Ok(Self { pack_id, registration_id, artifact_set_digest: *artifact_set_digest.as_bytes() })
    }

    /// Derive directly from an A4 [`RegisteredPack`] (ignoring `joined_revision`).
    pub fn from_registered(pack: &RegisteredPack) -> Result<Self, RefVersionCodecError> {
        Self::new(pack.pack_id(), pack.registration_id(), *pack.artifact_set_digest().digest())
    }

    pub const fn pack_id(&self) -> Uuid {
        self.pack_id
    }

    pub const fn registration_id(&self) -> Uuid {
        self.registration_id
    }

    pub const fn artifact_set_digest(&self) -> &[u8; 32] {
        &self.artifact_set_digest
    }
}

/// Canonical SHA-256 digest of a version's sorted immutable own pack set (§2.3).
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PackSetDigest([u8; 32]);

impl PackSetDigest {
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

impl fmt::Debug for PackSetDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "PackSetDigest({})", hex::encode(self.0))
    }
}

/// Verified physical pack metadata used by closure verification (§2.4).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedClosurePack {
    entry: PackSetEntry,
    storage_tenant_id: Uuid,
    authority_id: Uuid,
    provider: String,
    backend_identity: String,
    verified_bytes: u64,
    artifact_count: u32,
}

impl VerifiedClosurePack {
    /// Construct and validate a verified pack metadata descriptor.
    pub fn new(
        entry: PackSetEntry,
        storage_tenant_id: Uuid,
        authority_id: Uuid,
        provider: impl Into<String>,
        backend_identity: impl Into<String>,
        verified_bytes: u64,
        artifact_count: u32,
    ) -> Result<Self, RefVersionCodecError> {
        require_non_nil(storage_tenant_id, "storage_tenant_id")?;
        require_non_nil(authority_id, "authority_id")?;
        let provider = provider.into();
        let backend_identity = backend_identity.into();
        if provider.is_empty() || backend_identity.is_empty() {
            return Err(RefVersionCodecError::InvalidRequestShape {
                reason: "pack backend identity must be non-empty",
            });
        }
        if artifact_count != ARTIFACTS_PER_PACK {
            return Err(RefVersionCodecError::InvalidRequestShape {
                reason: "each closure pack must bind exactly one pack and one idx artifact",
            });
        }
        if verified_bytes == 0 {
            return Err(RefVersionCodecError::ZeroCounter { field: "verified_bytes" });
        }
        if verified_bytes > MAX_OPERATION_PLANNED_BYTES {
            return Err(RefVersionCodecError::PlannedBytesExceeded {
                limit: MAX_OPERATION_PLANNED_BYTES,
                actual: verified_bytes,
            });
        }
        Ok(Self { entry, storage_tenant_id, authority_id, provider, backend_identity, verified_bytes, artifact_count })
    }

    /// Convert an A4 [`RegisteredPack`], enforcing locator/backend homogeneity across `.pack` + `.idx`.
    pub fn from_registered(pack: &RegisteredPack) -> Result<Self, RefVersionCodecError> {
        let entry = PackSetEntry::from_registered(pack)?;
        let pack_art = pack.artifact(PackArtifactRole::Pack);
        let idx_art = pack.artifact(PackArtifactRole::Idx);
        if pack_art.provider() != idx_art.provider()
            || pack_art.backend_identity() != idx_art.backend_identity()
            || pack_art.locator().tenant_id() != idx_art.locator().tenant_id()
            || pack_art.locator().authority_id() != idx_art.locator().authority_id()
        {
            return Err(RefVersionCodecError::InvalidRequestShape {
                reason: "pack and idx artifacts must share provider, backend identity and storage authority",
            });
        }
        let verified_bytes = pack_art
            .verified_length()
            .checked_add(idx_art.verified_length())
            .ok_or(RefVersionCodecError::PlannedBytesOverflow)?;
        let artifact_count = u32::try_from(pack.artifacts().len())
            .map_err(|_| RefVersionCodecError::LengthOverflow { field: "artifacts" })?;
        Self::new(
            entry,
            pack_art.locator().tenant_id(),
            pack_art.locator().authority_id(),
            pack_art.provider(),
            pack_art.backend_identity(),
            verified_bytes,
            artifact_count,
        )
    }

    pub const fn entry(&self) -> &PackSetEntry {
        &self.entry
    }

    pub const fn storage_tenant_id(&self) -> Uuid {
        self.storage_tenant_id
    }

    pub const fn authority_id(&self) -> Uuid {
        self.authority_id
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }

    pub fn backend_identity(&self) -> &str {
        &self.backend_identity
    }

    pub const fn verified_bytes(&self) -> u64 {
        self.verified_bytes
    }

    pub const fn artifact_count(&self) -> u32 {
        self.artifact_count
    }
}

/// Compute `PackSetDigest = SHA-256(L("ry-version-pack-set-v1") || u32_be(count) || sorted entries)`.
pub fn compute_pack_set_digest(entries: &[PackSetEntry]) -> Result<PackSetDigest, RefVersionCodecError> {
    if entries.len() > MAX_CLOSURE_PACKS {
        return Err(RefVersionCodecError::Capacity {
            field: "pack_set_entries",
            limit: MAX_CLOSURE_PACKS,
            actual: entries.len(),
        });
    }
    let mut pairs = BTreeSet::new();
    let mut pack_ids = BTreeSet::new();
    let mut reg_ids = BTreeSet::new();
    for entry in entries {
        require_non_nil(entry.pack_id, "pack_id")?;
        require_non_nil(entry.registration_id, "registration_id")?;
        if !pairs.insert((entry.pack_id, entry.registration_id)) {
            return Err(RefVersionCodecError::DuplicatePackIdentity);
        }
        if !pack_ids.insert(entry.pack_id) {
            return Err(RefVersionCodecError::DuplicatePackId);
        }
        if !reg_ids.insert(entry.registration_id) {
            return Err(RefVersionCodecError::DuplicateRegistrationId);
        }
    }
    let mut sorted = entries.to_vec();
    sorted.sort_by_key(|entry| (entry.pack_id, entry.registration_id));
    let mut writer = CanonicalWriter::new();
    writer.push_len_prefixed(PACK_SET_DOMAIN)?;
    writer.push_u32(count_u32(sorted.len(), "pack_set_entries")?);
    for entry in &sorted {
        writer.push_len_prefixed(entry.pack_id.as_bytes())?;
        writer.push_len_prefixed(entry.registration_id.as_bytes())?;
        writer.push_len_prefixed(&entry.artifact_set_digest)?;
    }
    Ok(PackSetDigest::from_canonical_hash(writer.finish()))
}
