//! Verifiable dependency DAG closure verification and bounds enforcement (§2.4).
//!
//! Validates object-availability closures over authoritative committed
//! [`VersionRecord`]s and [`VerifiedClosurePack`] descriptors:
//! - client-supplied dependency lists are discarded (`select_verifier_dependencies`);
//! - BASE lineage is never traversed recursively for object availability;
//! - every transitive OBJECT edge must be same-realm, non-tombstone, strictly
//!   older in `authority_seq`, acyclic and verified against stored digests;
//! - depth (16), fanout (8), total transitive deps (64), closure packs (16),
//!   artifacts (32), verified bytes (64 MiB) and backend homogeneity fail closed.
use super::contract::{RefVersionCodecError, RefVersionRealm, VersionId};
use super::digest::{CanonicalWriter, hash_sha256};
use super::limits::{
    MAX_CLOSURE_ARTIFACTS, MAX_CLOSURE_PACKS, MAX_CLOSURE_VERIFIED_BYTES, MAX_OBJECT_DEP_DEPTH,
    MAX_OBJECT_DEPS_PER_VERSION, MAX_OBJECT_DEPS_TOTAL, count_u32,
};
use super::pack_set::{VerifiedClosurePack, compute_pack_set_digest};
use super::reasons::CausalRejectCode;
use super::record::VersionRecord;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use uuid::Uuid;

const CLOSURE_DOMAIN: &[u8] = b"ry-version-closure-v1";

/// Fail-closed refusal raised while resolving or verifying a version dependency closure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CausalClosureError {
    VersionNotFound,
    VersionRetired,
    TombstoneVersion,
    DependencyMissing,
    DependencyCorrupt,
    DependencyRealmMismatch,
    DependencyCycleIntegrity,
    ClosureTooLarge,
}

impl CausalClosureError {
    /// Map onto a §2.5.2 canonical terminal code when applicable (`VersionNotFound` /
    /// `VersionRetired` / `TombstoneVersion` map cleanly for dependency diagnostics).
    pub const fn as_causal_reject_code(self) -> CausalRejectCode {
        match self {
            Self::VersionNotFound | Self::VersionRetired | Self::DependencyMissing => {
                CausalRejectCode::DependencyMissing
            }
            Self::DependencyCorrupt => CausalRejectCode::DependencyCorrupt,
            Self::DependencyRealmMismatch => CausalRejectCode::DependencyRealmMismatch,
            Self::TombstoneVersion | Self::DependencyCycleIntegrity => CausalRejectCode::DependencyCycleIntegrity,
            Self::ClosureTooLarge => CausalRejectCode::ClosureTooLarge,
        }
    }
}

/// Canonical digest over a closed, deduplicated and ordered dependency closure.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ClosureDigest([u8; 32]);

impl ClosureDigest {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for ClosureDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "ClosureDigest({})", hex::encode(self.0))
    }
}

/// One authoritative committed version node together with its immutable own pack set.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CausalVersionNode {
    pub record: VersionRecord,
    pub own_packs: Vec<VerifiedClosurePack>,
}

/// Lookup state returned by a [`CausalVersionLookup`] implementation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VersionLookupEntry {
    Missing,
    Retired,
    Active(Box<CausalVersionNode>),
}

/// Abstract read interface for committed causal version nodes (PG, Raft or contract graph).
pub trait CausalVersionLookup {
    fn lookup_version(&self, version_id: &VersionId) -> VersionLookupEntry;
}

/// Deterministic in-memory version graph for pure contract and closure-matrix verification.
#[derive(Clone, Debug, Default)]
pub struct VersionGraph {
    nodes: BTreeMap<VersionId, VersionLookupEntry>,
}

impl VersionGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_active(&mut self, node: CausalVersionNode) {
        self.nodes.insert(node.record.version_id(), VersionLookupEntry::Active(Box::new(node)));
    }

    /// Key explicitly by an external `VersionId` (used to inject mismatched-ID corruption fixtures).
    pub fn insert_entry_at(&mut self, key: VersionId, entry: VersionLookupEntry) {
        self.nodes.insert(key, entry);
    }

    pub fn mark_retired(&mut self, version_id: VersionId) {
        self.nodes.insert(version_id, VersionLookupEntry::Retired);
    }
}

impl CausalVersionLookup for VersionGraph {
    fn lookup_version(&self, version_id: &VersionId) -> VersionLookupEntry {
        self.nodes.get(version_id).cloned().unwrap_or(VersionLookupEntry::Missing)
    }
}

/// Enforce §2.4 client-claim ignorance: discard untrusted client claims and keep
/// only server/verifier-proven OBJECT edges within fanout bounds.
pub fn select_verifier_dependencies(
    _ignored_client_claims: &[VersionId],
    verifier_selected: &[VersionId],
) -> Result<Vec<VersionId>, CausalClosureError> {
    if verifier_selected.len() > MAX_OBJECT_DEPS_PER_VERSION {
        return Err(CausalClosureError::ClosureTooLarge);
    }
    let mut unique = BTreeSet::new();
    for dep in verifier_selected {
        if !unique.insert(*dep) {
            return Err(CausalClosureError::DependencyCycleIntegrity);
        }
    }
    Ok(unique.into_iter().collect())
}

/// Verified, deduplicated, digest-stable dependency closure for one target version (§2.4).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedDependencyClosure {
    root: VersionRecord,
    dependencies: Vec<VersionRecord>,
    packs: Vec<VerifiedClosurePack>,
    max_depth: usize,
    total_verified_bytes: u64,
    total_artifacts: usize,
    closure_digest: ClosureDigest,
}

impl VerifiedDependencyClosure {
    pub const fn root(&self) -> &VersionRecord {
        &self.root
    }

    pub fn dependencies(&self) -> &[VersionRecord] {
        &self.dependencies
    }

    pub fn packs(&self) -> &[VerifiedClosurePack] {
        &self.packs
    }

    pub const fn max_depth(&self) -> usize {
        self.max_depth
    }

    pub const fn total_verified_bytes(&self) -> u64 {
        self.total_verified_bytes
    }

    pub const fn total_artifacts(&self) -> usize {
        self.total_artifacts
    }

    pub const fn closure_digest(&self) -> ClosureDigest {
        self.closure_digest
    }
}

struct ClosureAccumulator {
    visiting: BTreeSet<VersionId>,
    seen_nodes: BTreeSet<VersionId>,
    subtree_depth: BTreeMap<VersionId, usize>,
    nodes: BTreeMap<VersionId, VersionRecord>,
    packs: BTreeMap<(Uuid, Uuid), VerifiedClosurePack>,
    seen_pack_ids: BTreeMap<Uuid, Uuid>,
    seen_reg_ids: BTreeMap<Uuid, Uuid>,
    backend: Option<(String, String)>,
}

impl ClosureAccumulator {
    fn new() -> Self {
        Self {
            visiting: BTreeSet::new(),
            seen_nodes: BTreeSet::new(),
            subtree_depth: BTreeMap::new(),
            nodes: BTreeMap::new(),
            packs: BTreeMap::new(),
            seen_pack_ids: BTreeMap::new(),
            seen_reg_ids: BTreeMap::new(),
            backend: None,
        }
    }

    fn absorb_packs(
        &mut self,
        realm: &RefVersionRealm,
        own_packs: &[VerifiedClosurePack],
    ) -> Result<(), CausalClosureError> {
        for pack in own_packs {
            if pack.storage_tenant_id() != realm.tenant_id() {
                return Err(CausalClosureError::DependencyRealmMismatch);
            }
            let key = (pack.entry().pack_id(), pack.entry().registration_id());
            if let Some(existing_reg) = self.seen_pack_ids.get(&key.0)
                && *existing_reg != key.1
            {
                return Err(CausalClosureError::DependencyCorrupt);
            }
            if let Some(existing_pack) = self.seen_reg_ids.get(&key.1)
                && *existing_pack != key.0
            {
                return Err(CausalClosureError::DependencyCorrupt);
            }
            match &self.backend {
                None => self.backend = Some((pack.provider().to_owned(), pack.backend_identity().to_owned())),
                Some((provider, backend_id)) => {
                    if provider != pack.provider() || backend_id != pack.backend_identity() {
                        return Err(CausalClosureError::DependencyCorrupt);
                    }
                }
            }
            if let Some(existing) = self.packs.get(&key) {
                if existing != pack {
                    return Err(CausalClosureError::DependencyCorrupt);
                }
                continue;
            }
            if self.packs.len() >= MAX_CLOSURE_PACKS {
                return Err(CausalClosureError::ClosureTooLarge);
            }
            self.seen_pack_ids.insert(key.0, key.1);
            self.seen_reg_ids.insert(key.1, key.0);
            self.packs.insert(key, pack.clone());
        }
        Ok(())
    }
}

/// Resolve and fail-closed verify the full transitive OBJECT dependency closure
/// of `root_id` inside `expected_realm`. BASE history is never expanded here.
pub fn verify_dependency_closure(
    lookup: &dyn CausalVersionLookup,
    expected_realm: &RefVersionRealm,
    root_id: &VersionId,
) -> Result<VerifiedDependencyClosure, CausalClosureError> {
    let root_node = match lookup.lookup_version(root_id) {
        VersionLookupEntry::Missing => return Err(CausalClosureError::VersionNotFound),
        VersionLookupEntry::Retired => return Err(CausalClosureError::VersionRetired),
        VersionLookupEntry::Active(node) => *node,
    };
    validate_node(&root_node, root_id, expected_realm, true)?;
    let mut acc = ClosureAccumulator::new();
    acc.absorb_packs(expected_realm, &root_node.own_packs)?;
    let max_depth = visit_dependencies(lookup, expected_realm, &root_node, 0, &mut acc)?;
    let dependencies: Vec<VersionRecord> = acc.nodes.into_values().collect();
    if dependencies.len() > MAX_OBJECT_DEPS_TOTAL {
        return Err(CausalClosureError::ClosureTooLarge);
    }
    let packs: Vec<VerifiedClosurePack> = acc.packs.into_values().collect();
    if packs.len() > MAX_CLOSURE_PACKS {
        return Err(CausalClosureError::ClosureTooLarge);
    }
    let mut total_artifacts = 0usize;
    let mut total_verified_bytes = 0u64;
    for pack in &packs {
        let count = usize::try_from(pack.artifact_count()).map_err(|_| CausalClosureError::ClosureTooLarge)?;
        total_artifacts = total_artifacts.checked_add(count).ok_or(CausalClosureError::ClosureTooLarge)?;
        total_verified_bytes =
            total_verified_bytes.checked_add(pack.verified_bytes()).ok_or(CausalClosureError::ClosureTooLarge)?;
    }
    if total_artifacts > MAX_CLOSURE_ARTIFACTS || total_verified_bytes > MAX_CLOSURE_VERIFIED_BYTES {
        return Err(CausalClosureError::ClosureTooLarge);
    }
    let closure_digest = compute_closure_digest(&root_node.record, &dependencies, &packs)
        .map_err(|_| CausalClosureError::DependencyCorrupt)?;
    Ok(VerifiedDependencyClosure {
        root: root_node.record,
        dependencies,
        packs,
        max_depth,
        total_verified_bytes,
        total_artifacts,
        closure_digest,
    })
}

fn validate_node(
    node: &CausalVersionNode,
    expected_id: &VersionId,
    expected_realm: &RefVersionRealm,
    is_root: bool,
) -> Result<(), CausalClosureError> {
    if node.record.version_id() != *expected_id || node.record.verify_digest().is_err() {
        return Err(CausalClosureError::DependencyCorrupt);
    }
    if node.record.realm() != expected_realm {
        return Err(CausalClosureError::DependencyRealmMismatch);
    }
    if node.record.is_tombstone() {
        return Err(if is_root {
            CausalClosureError::TombstoneVersion
        } else {
            CausalClosureError::DependencyCycleIntegrity
        });
    }
    let entries: Vec<_> = node.own_packs.iter().map(|pack| *pack.entry()).collect();
    let computed_pack_set = compute_pack_set_digest(&entries).map_err(|err| match err {
        RefVersionCodecError::Capacity { .. } => CausalClosureError::ClosureTooLarge,
        _ => CausalClosureError::DependencyCorrupt,
    })?;
    if computed_pack_set != node.record.pack_set_digest() {
        return Err(CausalClosureError::DependencyCorrupt);
    }
    if node.record.object_deps().len() > MAX_OBJECT_DEPS_PER_VERSION {
        return Err(CausalClosureError::ClosureTooLarge);
    }
    Ok(())
}

fn visit_dependencies(
    lookup: &dyn CausalVersionLookup,
    expected_realm: &RefVersionRealm,
    parent: &CausalVersionNode,
    depth_from_root: usize,
    acc: &mut ClosureAccumulator,
) -> Result<usize, CausalClosureError> {
    let parent_id = parent.record.version_id();
    acc.visiting.insert(parent_id);
    let mut seen_direct = BTreeSet::new();
    let mut deepest_child = 0usize;
    for dep_id in parent.record.object_deps() {
        if *dep_id == parent_id || !seen_direct.insert(*dep_id) || acc.visiting.contains(dep_id) {
            return Err(CausalClosureError::DependencyCycleIntegrity);
        }
        let child_depth = depth_from_root.checked_add(1).ok_or(CausalClosureError::ClosureTooLarge)?;
        if child_depth > MAX_OBJECT_DEP_DEPTH {
            return Err(CausalClosureError::ClosureTooLarge);
        }
        let dep_node = match lookup.lookup_version(dep_id) {
            VersionLookupEntry::Missing | VersionLookupEntry::Retired => {
                return Err(CausalClosureError::DependencyMissing);
            }
            VersionLookupEntry::Active(node) => *node,
        };
        validate_node(&dep_node, dep_id, expected_realm, false)?;
        if dep_node.record.authority_seq() >= parent.record.authority_seq() {
            return Err(CausalClosureError::DependencyCycleIntegrity);
        }
        let height = if let Some(&cached) = acc.subtree_depth.get(dep_id) {
            if depth_from_root + 1 + cached > MAX_OBJECT_DEP_DEPTH {
                return Err(CausalClosureError::ClosureTooLarge);
            }
            cached
        } else {
            if acc.seen_nodes.len() >= MAX_OBJECT_DEPS_TOTAL {
                return Err(CausalClosureError::ClosureTooLarge);
            }
            acc.seen_nodes.insert(*dep_id);
            acc.absorb_packs(expected_realm, &dep_node.own_packs)?;
            let child_height = visit_dependencies(lookup, expected_realm, &dep_node, child_depth, acc)?;
            acc.nodes.insert(*dep_id, dep_node.record);
            acc.subtree_depth.insert(*dep_id, child_height);
            child_height
        };
        deepest_child = deepest_child.max(1 + height);
    }
    acc.visiting.remove(&parent_id);
    Ok(deepest_child)
}

fn compute_closure_digest(
    root: &VersionRecord,
    deps: &[VersionRecord],
    packs: &[VerifiedClosurePack],
) -> Result<ClosureDigest, RefVersionCodecError> {
    let mut writer = CanonicalWriter::new();
    writer.push_len_prefixed(CLOSURE_DOMAIN)?;
    writer.push_len_prefixed(root.version_id().as_bytes())?;
    writer.push_len_prefixed(root.record_digest().as_bytes())?;
    writer.push_u32(count_u32(deps.len(), "closure_deps")?);
    for dep in deps {
        writer.push_len_prefixed(dep.version_id().as_bytes())?;
        writer.push_len_prefixed(dep.record_digest().as_bytes())?;
    }
    writer.push_u32(count_u32(packs.len(), "closure_packs")?);
    for pack in packs {
        writer.push_len_prefixed(pack.entry().pack_id().as_bytes())?;
        writer.push_len_prefixed(pack.entry().registration_id().as_bytes())?;
        writer.push_len_prefixed(pack.entry().artifact_set_digest())?;
    }
    Ok(ClosureDigest(hash_sha256(&writer.into_bytes())))
}
