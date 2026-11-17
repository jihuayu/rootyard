//! Pack-hash sharding, canonical set digests, and multi-worker routing (#162).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::blob_store::{
    BlobLocator,
    read_accel::{AuthoritativeRef, SerializedBlobLocator},
};

use super::CompactionError;

const SHARD_HASH_DOMAIN: &[u8] = b"rubicon-compaction-shard-v1\0";

/// Serializable authoritative ref record bound into compaction snapshots and proofs.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactionRef {
    pub name: String,
    pub oid: String,
}

impl CompactionRef {
    pub fn new(name: impl Into<String>, oid: impl Into<String>) -> Self {
        Self { name: name.into(), oid: oid.into() }
    }

    pub fn to_authoritative_ref(&self) -> AuthoritativeRef {
        AuthoritativeRef::new(self.name.clone(), self.oid.clone())
    }
}

impl From<AuthoritativeRef> for CompactionRef {
    fn from(value: AuthoritativeRef) -> Self {
        Self { name: value.name, oid: value.oid }
    }
}

impl From<&AuthoritativeRef> for CompactionRef {
    fn from(value: &AuthoritativeRef) -> Self {
        Self { name: value.name.clone(), oid: value.oid.clone() }
    }
}

/// Authoritative pack entry tracked in RefStore membership & segment logs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactionPackEntry {
    pub pack_id: Uuid,
    pub pack_stem: String,
    pub pack_sha256: String,
    pub pack_bytes: u64,
    pub idx_sha256: String,
    pub idx_bytes: u64,
    pub pack_locator: SerializedBlobLocator,
    pub idx_locator: SerializedBlobLocator,
    pub joined_generation: u64,
    pub shard_id: u16,
}

impl CompactionPackEntry {
    /// Construct a validated pack entry tagged with its deterministic pack-hash shard.
    pub fn from_locators(
        pack_id: Uuid,
        pack_stem: impl Into<String>,
        pack_locator: &BlobLocator,
        idx_locator: &BlobLocator,
        joined_generation: u64,
        shard_count: u16,
    ) -> Result<Self, CompactionError> {
        if pack_id.is_nil() {
            return Err(CompactionError::InvalidInput("pack_id must be non-nil".into()));
        }
        if joined_generation == 0 {
            return Err(CompactionError::InvalidInput("joined_generation must be positive".into()));
        }
        let stem = pack_stem.into();
        validate_pack_stem(&stem)?;
        let pack_sha256 = pack_locator.sha256().to_owned();
        let idx_sha256 = idx_locator.sha256().to_owned();
        let shard_id = shard_for_pack_hash(&pack_sha256, shard_count)?;
        let entry = Self {
            pack_id,
            pack_stem: stem,
            pack_sha256,
            pack_bytes: pack_locator.length(),
            idx_sha256,
            idx_bytes: idx_locator.length(),
            pack_locator: SerializedBlobLocator::from_locator(pack_locator),
            idx_locator: SerializedBlobLocator::from_locator(idx_locator),
            joined_generation,
            shard_id,
        };
        entry.validate(shard_count)?;
        Ok(entry)
    }

    pub fn validate(&self, shard_count: u16) -> Result<(), CompactionError> {
        if self.pack_id.is_nil() || self.joined_generation == 0 {
            return Err(CompactionError::InvalidInput("pack entry identity/generation is invalid".into()));
        }
        validate_pack_stem(&self.pack_stem)?;
        validate_sha256_hex(&self.pack_sha256)?;
        validate_sha256_hex(&self.idx_sha256)?;
        if self.pack_bytes == 0 || self.idx_bytes == 0 {
            return Err(CompactionError::InvalidInput("pack/idx byte sizes must be positive".into()));
        }
        let expected_shard = shard_for_pack_hash(&self.pack_sha256, shard_count)?;
        if self.shard_id != expected_shard {
            return Err(CompactionError::InvalidInput(format!(
                "pack {} shard mismatch: got {}, expected {}",
                self.pack_id, self.shard_id, expected_shard
            )));
        }
        let pack_loc = self.pack_locator.to_locator()?;
        let idx_loc = self.idx_locator.to_locator()?;
        if pack_loc.sha256() != self.pack_sha256 || pack_loc.length() != self.pack_bytes {
            return Err(CompactionError::InvalidInput("pack digest/length disagrees with locator".into()));
        }
        if idx_loc.sha256() != self.idx_sha256 || idx_loc.length() != self.idx_bytes {
            return Err(CompactionError::InvalidInput("idx digest/length disagrees with locator".into()));
        }
        Ok(())
    }

    pub fn physical_pair_bytes(&self) -> u64 {
        self.pack_bytes.saturating_add(self.idx_bytes)
    }
}

/// Deterministic modulo mapping from normalized pack SHA-256 to shard id.
pub fn shard_for_pack_hash(pack_sha256: &str, shard_count: u16) -> Result<u16, CompactionError> {
    if shard_count == 0 {
        return Err(CompactionError::InvalidInput("shard_count must be positive".into()));
    }
    validate_sha256_hex(pack_sha256)?;
    let mut hasher = Sha256::new();
    hasher.update(SHARD_HASH_DOMAIN);
    hasher.update(pack_sha256.as_bytes());
    let digest = hasher.finalize();
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    let raw = u64::from_be_bytes(prefix) % u64::from(shard_count);
    u16::try_from(raw).map_err(|_| CompactionError::InvalidInput("computed shard id out of range".into()))
}

/// Order-independent canonical digest of an authoritative pack membership set.
pub fn pack_set_digest(packs: &[CompactionPackEntry]) -> String {
    let mut sorted = packs.to_vec();
    sorted.sort_by(|a, b| a.pack_id.cmp(&b.pack_id).then_with(|| a.pack_sha256.cmp(&b.pack_sha256)));
    let mut hasher = Sha256::new();
    hasher.update((sorted.len() as u64).to_be_bytes());
    for entry in &sorted {
        hasher.update(entry.pack_id.as_bytes());
        hasher.update(entry.pack_sha256.as_bytes());
        hasher.update(entry.pack_bytes.to_be_bytes());
        hasher.update(entry.idx_sha256.as_bytes());
        hasher.update(entry.idx_bytes.to_be_bytes());
        hasher.update(entry.joined_generation.to_be_bytes());
        hasher.update(entry.shard_id.to_be_bytes());
    }
    hex::encode(hasher.finalize())
}

fn hash_ref_pairs<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    let mut sorted: Vec<(&str, &str)> = pairs.into_iter().collect();
    sorted.sort_unstable();
    let mut hasher = Sha256::new();
    hasher.update((sorted.len() as u64).to_be_bytes());
    for (name, oid) in sorted {
        hasher.update((name.len() as u64).to_be_bytes());
        hasher.update(name.as_bytes());
        hasher.update((oid.len() as u64).to_be_bytes());
        hasher.update(oid.as_bytes());
    }
    hex::encode(hasher.finalize())
}

/// Order-independent canonical digest of serializable [`CompactionRef`] entries.
pub fn refs_digest(refs: &[CompactionRef]) -> String {
    hash_ref_pairs(refs.iter().map(|r| (r.name.as_str(), r.oid.as_str())))
}

/// Order-independent canonical digest of [`AuthoritativeRef`] entries.
pub fn authoritative_refs_digest(refs: &[AuthoritativeRef]) -> String {
    hash_ref_pairs(refs.iter().map(|r| (r.name.as_str(), r.oid.as_str())))
}

/// Order-independent canonical digest of authoritative retention roots.
pub fn retention_roots_digest(roots: &[String]) -> String {
    let mut sorted = roots.to_vec();
    sorted.sort();
    sorted.dedup();
    let mut hasher = Sha256::new();
    hasher.update((sorted.len() as u64).to_be_bytes());
    for root in sorted {
        hasher.update((root.len() as u64).to_be_bytes());
        hasher.update(root.as_bytes());
    }
    hex::encode(hasher.finalize())
}

/// Routes packs to deterministic pack-hash shards and partitions shards across workers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactionShardRouter {
    pub shard_count: u16,
}

impl CompactionShardRouter {
    pub fn new(shard_count: u16) -> Result<Self, CompactionError> {
        if shard_count == 0 {
            return Err(CompactionError::InvalidInput("shard_count must be >= 1".into()));
        }
        Ok(Self { shard_count })
    }

    pub fn route_pack(&self, pack_sha256: &str) -> Result<u16, CompactionError> {
        shard_for_pack_hash(pack_sha256, self.shard_count)
    }

    pub fn partition_packs(
        &self,
        packs: &[CompactionPackEntry],
    ) -> Result<BTreeMap<u16, Vec<CompactionPackEntry>>, CompactionError> {
        let mut grouped: BTreeMap<u16, Vec<CompactionPackEntry>> = BTreeMap::new();
        for pack in packs {
            pack.validate(self.shard_count)?;
            grouped.entry(pack.shard_id).or_default().push(pack.clone());
        }
        Ok(grouped)
    }

    /// Assign disjoint shards to `worker_idx` out of `worker_total` independent workers.
    pub fn worker_shards(&self, worker_idx: usize, worker_total: usize) -> Result<Vec<u16>, CompactionError> {
        if worker_total == 0 || worker_idx >= worker_total {
            return Err(CompactionError::InvalidInput("worker index out of bounds".into()));
        }
        Ok((0..self.shard_count).filter(|shard| usize::from(*shard) % worker_total == worker_idx).collect())
    }
}

pub(super) fn validate_sha256_hex(hex_str: &str) -> Result<(), CompactionError> {
    let valid = hex_str.len() == 64 && hex_str.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !valid {
        return Err(CompactionError::InvalidInput(format!("invalid lowercase sha256 hex digest `{hex_str}`")));
    }
    Ok(())
}

pub(super) fn validate_pack_stem(stem: &str) -> Result<(), CompactionError> {
    let valid = !stem.is_empty()
        && stem.len() <= 128
        && stem.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !valid {
        return Err(CompactionError::InvalidInput(format!("invalid pack stem `{stem}`")));
    }
    Ok(())
}
