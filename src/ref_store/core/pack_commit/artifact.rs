//! Inert, read-only registered artifact and pack data.
//!
//! This module carries the *complete physical identity* of a durable
//! registration: role, hold id, A3 pair slot, the full Blob locator
//! (tenant/authority/generation/attempt/namespace/sha256/length), provider,
//! physical backend identity and the verified read-back digest/length. It is
//! plain metadata: nothing here is a grant, a `BlobReceipt`, an upload intent or
//! a proof. A native verifier may use it to perform a verified `BlobStore` GET of
//! the exact registered locators against the live backend identity.
use super::contract::{ARTIFACTS_PER_PACK, PackArtifactRole, is_sha256_hex};
use super::error::PackCommitError;
use super::plan::ContentDigest;
use crate::blob_store::BlobLocator;
use crate::ref_store::contract::RequestDigest;
use uuid::Uuid;

/// Exact arguments of one read-only [`BlobLocator`]: the physical address of an
/// already published object, never write authority.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ArtifactLocator {
    tenant_id: Uuid,
    authority_id: Uuid,
    authority_generation: i64,
    attempt_id: Uuid,
    namespace: String,
    sha256: ContentDigest,
    length: u64,
}

impl ArtifactLocator {
    pub fn new(
        tenant_id: Uuid,
        authority_id: Uuid,
        authority_generation: i64,
        attempt_id: Uuid,
        namespace: impl Into<String>,
        sha256: ContentDigest,
        length: u64,
    ) -> Result<Self, PackCommitError> {
        let namespace = namespace.into();
        if tenant_id.is_nil() || authority_id.is_nil() || attempt_id.is_nil() || authority_generation <= 0 {
            return Err(PackCommitError::Invalid("locator identity must be non-nil and positive"));
        }
        if namespace.is_empty() || namespace.len() > 48 {
            return Err(PackCommitError::Invalid("locator namespace must be bounded"));
        }
        if length == 0 {
            return Err(PackCommitError::Invalid("locator length must be positive"));
        }
        Ok(Self { tenant_id, authority_id, authority_generation, attempt_id, namespace, sha256, length })
    }

    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }
    pub fn authority_id(&self) -> Uuid {
        self.authority_id
    }
    pub fn authority_generation(&self) -> i64 {
        self.authority_generation
    }
    pub fn attempt_id(&self) -> Uuid {
        self.attempt_id
    }
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
    pub fn sha256(&self) -> &ContentDigest {
        &self.sha256
    }
    pub fn length(&self) -> u64 {
        self.length
    }

    /// Read-only reconstruction of the exact Blob address. Not a capability.
    pub fn blob_locator(&self) -> Result<BlobLocator, PackCommitError> {
        BlobLocator::new(
            self.tenant_id,
            self.authority_id,
            self.authority_generation,
            self.attempt_id,
            &self.namespace,
            self.sha256.as_str(),
            self.length,
        )
        .map_err(|_| PackCommitError::Invalid("stored locator cannot be reconstructed"))
    }
}

/// One registered artifact with its complete physical identity and the verified
/// read-back result recorded by A3.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct RegisteredArtifact {
    role: PackArtifactRole,
    slot: i32,
    hold_id: Uuid,
    locator: ArtifactLocator,
    provider: String,
    backend_identity: String,
    verified_sha256: ContentDigest,
    verified_length: u64,
}

impl RegisteredArtifact {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        role: PackArtifactRole,
        slot: i32,
        hold_id: Uuid,
        locator: ArtifactLocator,
        provider: impl Into<String>,
        backend_identity: impl Into<String>,
        verified_sha256: ContentDigest,
        verified_length: u64,
    ) -> Result<Self, PackCommitError> {
        let provider = provider.into();
        let backend_identity = backend_identity.into();
        if hold_id.is_nil() {
            return Err(PackCommitError::Invalid("artifact hold id must be non-nil"));
        }
        if slot != role_slot(role) {
            return Err(PackCommitError::Invalid("a pack pair uses slot 0 for pack and slot 1 for idx"));
        }
        if provider.is_empty() || !is_sha256_hex(&backend_identity) {
            return Err(PackCommitError::Invalid("artifact provider/backend identity is invalid"));
        }
        if verified_sha256 != locator.sha256 || verified_length != locator.length {
            return Err(PackCommitError::Invalid("verified read-back does not match the registered locator"));
        }
        Ok(Self { role, slot, hold_id, locator, provider, backend_identity, verified_sha256, verified_length })
    }

    pub fn role(&self) -> PackArtifactRole {
        self.role
    }
    pub fn slot(&self) -> i32 {
        self.slot
    }
    pub fn hold_id(&self) -> Uuid {
        self.hold_id
    }
    pub fn locator(&self) -> &ArtifactLocator {
        &self.locator
    }
    pub fn provider(&self) -> &str {
        &self.provider
    }
    pub fn backend_identity(&self) -> &str {
        &self.backend_identity
    }
    pub fn verified_sha256(&self) -> &ContentDigest {
        &self.verified_sha256
    }
    pub fn verified_length(&self) -> u64 {
        self.verified_length
    }
}

pub(super) const fn role_slot(role: PackArtifactRole) -> i32 {
    match role {
        PackArtifactRole::Pack => 0,
        PackArtifactRole::Idx => 1,
    }
}

/// Canonical digest over the FULL physical identity of one artifact set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactSetDigest(RequestDigest);

// Canonical byte order (not a capability): needed so membership entries and
// stored pack sets have a total order for sorting/digests.
impl PartialOrd for ArtifactSetDigest {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ArtifactSetDigest {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.as_bytes().cmp(other.0.as_bytes())
    }
}

impl ArtifactSetDigest {
    pub fn of(artifacts: &[RegisteredArtifact]) -> Self {
        let mut sorted = artifacts.to_vec();
        sorted.sort();
        let mut fields: Vec<Vec<u8>> = Vec::with_capacity(sorted.len() * 13 + 1);
        fields.push((sorted.len() as u64).to_be_bytes().to_vec());
        for artifact in &sorted {
            let locator = &artifact.locator;
            fields.push(artifact.role.as_str().as_bytes().to_vec());
            fields.push(artifact.slot.to_be_bytes().to_vec());
            fields.push(artifact.hold_id.as_bytes().to_vec());
            fields.push(locator.tenant_id.as_bytes().to_vec());
            fields.push(locator.authority_id.as_bytes().to_vec());
            fields.push(locator.authority_generation.to_be_bytes().to_vec());
            fields.push(locator.attempt_id.as_bytes().to_vec());
            fields.push(locator.namespace.as_bytes().to_vec());
            fields.push(locator.sha256.as_str().as_bytes().to_vec());
            fields.push(locator.length.to_be_bytes().to_vec());
            fields.push(artifact.provider.as_bytes().to_vec());
            fields.push(artifact.backend_identity.as_bytes().to_vec());
            fields.push(artifact.verified_sha256.as_str().as_bytes().to_vec());
            fields.push(artifact.verified_length.to_be_bytes().to_vec());
        }
        let parts = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
        Self(RequestDigest::of("core-pack-artifact-set-v2", &parts))
    }

    pub fn digest(&self) -> &RequestDigest {
        &self.0
    }

    pub fn as_hex(&self) -> String {
        self.0.as_hex()
    }

    /// Rebuild the wrapper from a stored digest. Not a capability: every
    /// consumer re-derives it from the actual artifact rows and refuses a
    /// mismatch (`RegisteredPack::new`).
    pub(crate) fn from_digest(digest: RequestDigest) -> Self {
        Self(digest)
    }
}

/// One registered pack: exactly one `.pack` and one `.idx` artifact of the SAME
/// A3 acquire/consume batch, plus its preallocated pack/registration identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredPack {
    pack_id: Uuid,
    registration_id: Uuid,
    artifact_set_digest: ArtifactSetDigest,
    joined_revision: Option<i64>,
    artifacts: Vec<RegisteredArtifact>,
}

impl RegisteredPack {
    pub fn new(
        pack_id: Uuid,
        registration_id: Uuid,
        stored_digest: ArtifactSetDigest,
        artifacts: Vec<RegisteredArtifact>,
        joined_revision: Option<i64>,
    ) -> Result<Self, PackCommitError> {
        if pack_id.is_nil() || registration_id.is_nil() {
            return Err(PackCommitError::Invalid("registered pack identity must be non-nil"));
        }
        if artifacts.len() != ARTIFACTS_PER_PACK {
            return Err(PackCommitError::Invalid("a registered pack must have exactly two artifacts"));
        }
        // Canonical stored order is exactly [pack(slot 0), idx(slot 1)], so the
        // retained vector, `artifact(role)` and the digest always agree.
        let mut artifacts = artifacts;
        artifacts.sort_by_key(|artifact| (role_slot(artifact.role()), artifact.slot()));
        let mut roles = artifacts.iter().map(RegisteredArtifact::role).collect::<Vec<_>>();
        roles.sort();
        roles.dedup();
        if roles != vec![PackArtifactRole::Pack, PackArtifactRole::Idx] {
            return Err(PackCommitError::Invalid("a registered pack is exactly one pack and one idx"));
        }
        if artifacts.iter().any(|artifact| artifact.slot() != role_slot(artifact.role())) {
            return Err(PackCommitError::Invalid("registered pair slots must be 0/1"));
        }
        let recomputed = ArtifactSetDigest::of(&artifacts);
        if recomputed != stored_digest {
            return Err(PackCommitError::Invalid("stored artifact-set digest does not match its artifacts"));
        }
        if joined_revision.is_some_and(|revision| revision <= 0) {
            return Err(PackCommitError::Invalid("joined revision must be positive"));
        }
        Ok(Self { pack_id, registration_id, artifact_set_digest: stored_digest, joined_revision, artifacts })
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
    pub fn joined_revision(&self) -> Option<i64> {
        self.joined_revision
    }
    pub fn artifacts(&self) -> &[RegisteredArtifact] {
        &self.artifacts
    }
    pub fn artifact(&self, role: PackArtifactRole) -> &RegisteredArtifact {
        self.artifacts
            .iter()
            .find(|artifact| artifact.role() == role)
            .expect("a registered pack always has one pack and one idx")
    }
}

/// Canonical digest over one complete sorted registered-pack set, including the
/// full artifact-set digest and (for old packs) the joined revision.
pub fn packs_digest(packs: &[RegisteredPack]) -> RequestDigest {
    let mut sorted = packs.to_vec();
    sorted.sort_by_key(|pack| pack.pack_id);
    let mut fields: Vec<Vec<u8>> = vec![(sorted.len() as u64).to_be_bytes().to_vec()];
    for pack in &sorted {
        fields.push(pack.pack_id.as_bytes().to_vec());
        fields.push(pack.registration_id.as_bytes().to_vec());
        fields.push(pack.artifact_set_digest.digest().as_bytes().to_vec());
        fields.push(pack.joined_revision.unwrap_or(0).to_be_bytes().to_vec());
    }
    let parts = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
    RequestDigest::of("core-pack-set-v1", &parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locator(byte: u8) -> ArtifactLocator {
        ArtifactLocator::new(
            Uuid::from_bytes([1; 16]),
            Uuid::from_bytes([2; 16]),
            1,
            Uuid::from_bytes([byte; 16]),
            format!("ns-{byte}"),
            ContentDigest::parse(hex::encode([byte; 32])).unwrap(),
            u64::from(byte),
        )
        .unwrap()
    }

    fn artifact(role: PackArtifactRole, byte: u8) -> RegisteredArtifact {
        let locator = locator(byte);
        RegisteredArtifact::new(
            role,
            role_slot(role),
            Uuid::from_bytes([byte; 16]),
            locator.clone(),
            "s3",
            hex::encode([byte; 32]),
            locator.sha256().clone(),
            locator.length(),
        )
        .unwrap()
    }

    fn pack(byte: u8) -> RegisteredPack {
        let artifacts = vec![artifact(PackArtifactRole::Pack, byte), artifact(PackArtifactRole::Idx, byte + 1)];
        let digest = ArtifactSetDigest::of(&artifacts);
        RegisteredPack::new(Uuid::from_bytes([byte; 16]), Uuid::from_bytes([byte + 1; 16]), digest, artifacts, Some(3))
            .unwrap()
    }

    #[test]
    fn artifact_set_digest_covers_full_physical_identity() {
        let left = pack(1);
        let right = pack(1);
        assert_eq!(left.artifact_set_digest(), right.artifact_set_digest());
        assert_eq!(packs_digest(std::slice::from_ref(&left)), packs_digest(&[right]));
        let mut artifacts = left.artifacts().to_vec();
        artifacts[1] = artifact(PackArtifactRole::Idx, 7);
        assert_ne!(ArtifactSetDigest::of(&artifacts), left.artifact_set_digest());
        assert!(
            RegisteredArtifact::new(
                PackArtifactRole::Idx,
                0,
                Uuid::from_bytes([9; 16]),
                locator(9),
                "s3",
                hex::encode([9u8; 32]),
                locator(9).sha256().clone(),
                locator(9).length(),
            )
            .is_err()
        );
    }
}
