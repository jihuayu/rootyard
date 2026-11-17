//! Canonical validation, compaction lineage checks, and SHA-256 codecs for pack covers (Issue #184).
use super::super::contract::RefVersionRealm;
use super::super::digest::{
    CanonicalWriter, ensure_present_oid, format_tag, push_oid, require_non_nil, validate_realm,
};
use super::super::limits::{count_u32, positive_u64};
use super::model::{
    CompactionPublishOutcome, CoverHierarchyRecord, CoverHierarchyRecordInput, CoverMembershipDigest, CoverModelError,
    CoverRecordDigest, CoverTier, oid_bytes,
};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use uuid::Uuid;

const COVER_RECORD_DOMAIN: &[u8] = b"ry-pack-cover-record-v1";
const MAX_COVER_VERSIONS: usize = 4096;
const MAX_COVER_COMMITS: usize = 8192;
const MAX_COVER_INPUTS: usize = 256;
const MAX_DELTA_BASES: usize = 16;

/// Authoritative in-memory hierarchy index enforcing monotonic compaction fencing.
#[derive(Clone, Debug)]
pub struct CoverHierarchyIndex {
    realm: RefVersionRealm,
    compaction_epoch: u64,
    membership_generation: u64,
    membership_digest: CoverMembershipDigest,
    covers: BTreeMap<Uuid, CoverHierarchyRecord>,
    retired_from_active: BTreeSet<Uuid>,
}

impl CoverHierarchyIndex {
    pub fn new(
        realm: RefVersionRealm,
        initial_membership_digest: CoverMembershipDigest,
    ) -> Result<Self, CoverModelError> {
        validate_realm(&realm)?;
        Ok(Self {
            realm,
            compaction_epoch: 1,
            membership_generation: 1,
            membership_digest: initial_membership_digest,
            covers: BTreeMap::new(),
            retired_from_active: BTreeSet::new(),
        })
    }

    pub const fn realm(&self) -> &RefVersionRealm {
        &self.realm
    }
    pub const fn compaction_epoch(&self) -> u64 {
        self.compaction_epoch
    }
    pub const fn membership_generation(&self) -> u64 {
        self.membership_generation
    }
    pub const fn membership_digest(&self) -> CoverMembershipDigest {
        self.membership_digest
    }
    pub fn get(&self, cover_id: &Uuid) -> Option<&CoverHierarchyRecord> {
        self.covers.get(cover_id)
    }
    pub fn is_retired_from_active(&self, cover_id: &Uuid) -> bool {
        self.retired_from_active.contains(cover_id)
    }
    pub fn all_covers(&self) -> impl Iterator<Item = &CoverHierarchyRecord> {
        self.covers.values()
    }

    /// Register a newly committed leaf (`Delta`) cover produced by a push.
    pub fn register_leaf_cover(
        &mut self,
        record: CoverHierarchyRecord,
        new_membership_digest: CoverMembershipDigest,
    ) -> Result<(), CoverModelError> {
        record.verify_digest()?;
        if record.realm() != &self.realm {
            return Err(CoverModelError::RealmMismatch);
        }
        if record.tier() != CoverTier::Delta {
            return Err(CoverModelError::InvalidShape("leaf registration requires CoverTier::Delta"));
        }
        if let Some(existing) = self.covers.get(&record.cover_id()) {
            return if existing == &record { Ok(()) } else { Err(CoverModelError::CoverRecordConflict) };
        }
        for base_id in &record.artifacts().delta_base_cover_ids {
            let base = self.covers.get(base_id).ok_or(CoverModelError::MissingDeltaBaseCover)?;
            if base.realm() != &self.realm || base.max_authority_seq() > record.max_authority_seq() {
                return Err(CoverModelError::MissingDeltaBaseCover);
            }
        }
        self.covers.insert(record.cover_id(), record);
        self.membership_generation = self
            .membership_generation
            .checked_add(1)
            .ok_or(CoverModelError::InvalidShape("membership generation overflow"))?;
        self.membership_digest = new_membership_digest;
        Ok(())
    }

    /// Publish a compacted cover under strict epoch and expected-membership CAS fencing.
    pub fn publish_compacted_cover(
        &mut self,
        record: CoverHierarchyRecord,
        expected_compaction_epoch: u64,
        expected_membership_digest: CoverMembershipDigest,
        new_membership_digest: CoverMembershipDigest,
    ) -> Result<CompactionPublishOutcome, CoverModelError> {
        record.verify_digest()?;
        if record.realm() != &self.realm {
            return Err(CoverModelError::RealmMismatch);
        }
        if record.tier() == CoverTier::Delta {
            return Err(CoverModelError::InvalidShape("compacted publication requires tier > Delta"));
        }
        if let Some(existing) = self.covers.get(&record.cover_id()) {
            return if existing == &record {
                Ok(CompactionPublishOutcome::IdempotentReplay)
            } else {
                Err(CoverModelError::CoverRecordConflict)
            };
        }
        if expected_compaction_epoch != self.compaction_epoch {
            return Err(CoverModelError::StaleCompactionEpoch);
        }
        if expected_membership_digest != self.membership_digest {
            return Err(CoverModelError::MembershipConflict);
        }
        verify_compaction_lineage(self, &record)?;
        self.covers.insert(record.cover_id(), record);
        self.compaction_epoch =
            self.compaction_epoch.checked_add(1).ok_or(CoverModelError::InvalidShape("compaction epoch overflow"))?;
        self.membership_generation = self
            .membership_generation
            .checked_add(1)
            .ok_or(CoverModelError::InvalidShape("membership generation overflow"))?;
        self.membership_digest = new_membership_digest;
        Ok(CompactionPublishOutcome::Committed)
    }

    /// Mark an input cover retired from active planning ONLY after a newer cover subsumes it
    /// and caller explicitly proved zero active retention holds (`zero_active_holds == true`).
    pub fn mark_retired_from_active(
        &mut self,
        cover_id: Uuid,
        superseding_cover_id: Uuid,
        zero_active_holds: bool,
    ) -> Result<(), CoverModelError> {
        if !zero_active_holds {
            return Err(CoverModelError::ActiveHoldPreventsRetirement);
        }
        let target = self.covers.get(&cover_id).ok_or(CoverModelError::MissingInputCover)?;
        let sup = self.covers.get(&superseding_cover_id).ok_or(CoverModelError::MissingInputCover)?;
        if sup.cover_id() == target.cover_id() || !sup.input_cover_ids().contains(&cover_id) {
            return Err(CoverModelError::InputCoverageDrop);
        }
        let sup_versions: BTreeSet<_> = sup.covered_versions().iter().copied().collect();
        if !target.covered_versions().iter().all(|v| sup_versions.contains(v)) {
            return Err(CoverModelError::InputCoverageDrop);
        }
        self.retired_from_active.insert(cover_id);
        Ok(())
    }
}

fn verify_compaction_lineage(
    index: &CoverHierarchyIndex,
    record: &CoverHierarchyRecord,
) -> Result<(), CoverModelError> {
    let mut expected_versions = BTreeSet::new();
    let mut expected_commits = HashSet::new();
    for input_id in record.input_cover_ids() {
        let input = index.get(input_id).ok_or(CoverModelError::MissingInputCover)?;
        if input.realm() != record.realm() || input.tier().rank() >= record.tier().rank() {
            return Err(CoverModelError::InvalidShape("compaction input must share realm and have lower tier"));
        }
        if input.max_authority_seq() > record.max_authority_seq() {
            return Err(CoverModelError::InvalidShape("compaction input seq exceeds compacted cover bound"));
        }
        expected_versions.extend(input.covered_versions().iter().copied());
        expected_commits.extend(input.covered_commits().iter().map(|c| c.commit_oid));
    }
    let out_versions: BTreeSet<_> = record.covered_versions().iter().copied().collect();
    let out_commits: HashSet<_> = record.covered_commits().iter().map(|c| c.commit_oid).collect();
    if !expected_versions.is_subset(&out_versions) || !expected_commits.is_subset(&out_commits) {
        return Err(CoverModelError::InputCoverageDrop);
    }
    for base_id in &record.artifacts().delta_base_cover_ids {
        let base = index.get(base_id).ok_or(CoverModelError::MissingDeltaBaseCover)?;
        if base.realm() != record.realm() || base.max_authority_seq() > record.max_authority_seq() {
            return Err(CoverModelError::MissingDeltaBaseCover);
        }
    }
    Ok(())
}

pub(super) fn normalize_and_validate(input: &mut CoverHierarchyRecordInput) -> Result<(), CoverModelError> {
    validate_realm(&input.realm)?;
    require_non_nil(input.cover_id, "cover_id")?;
    require_non_nil(input.worker_id, "worker_id")?;
    require_non_nil(input.operation_id, "operation_id")?;
    if input.membership_generation == 0 || input.compaction_epoch == 0 {
        return Err(CoverModelError::InvalidShape("membership_generation and compaction_epoch must be positive"));
    }
    let min_seq = positive_u64(input.min_authority_seq, "min_authority_seq")?;
    let max_seq = positive_u64(input.max_authority_seq, "max_authority_seq")?;
    if min_seq > max_seq {
        return Err(CoverModelError::InvalidShape("min_authority_seq exceeds max_authority_seq"));
    }
    validate_artifacts(input)?;
    validate_versions_and_commits(input)?;
    validate_inputs(input)?;
    Ok(())
}

fn validate_artifacts(input: &mut CoverHierarchyRecordInput) -> Result<(), CoverModelError> {
    let expected_hex_len = input.realm.object_format().oid_hex_len();
    let Some(stem_hex) = input.artifacts.pack_stem.strip_prefix("pack-") else {
        return Err(CoverModelError::InvalidShape("pack_stem must start with pack-"));
    };
    if stem_hex.len() != expected_hex_len || !stem_hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(CoverModelError::InvalidShape("pack_stem hex does not match object_format"));
    }
    let p_loc = &input.artifacts.pack_locator;
    let i_loc = &input.artifacts.idx_locator;
    if p_loc.tenant_id() != input.realm.tenant_id()
        || i_loc.tenant_id() != input.realm.tenant_id()
        || p_loc.authority_id() != input.realm.repository_id()
        || i_loc.authority_id() != input.realm.repository_id()
        || input.pack.storage_tenant_id() != input.realm.tenant_id()
    {
        return Err(CoverModelError::RealmMismatch);
    }
    let total_bytes = p_loc
        .length()
        .checked_add(i_loc.length())
        .ok_or(CoverModelError::InvalidShape("artifact byte sum overflow"))?;
    if total_bytes != input.pack.verified_bytes() {
        return Err(CoverModelError::InvalidShape("locator lengths do not match pack verified_bytes"));
    }
    input.artifacts.delta_base_cover_ids.sort();
    let bases = &input.artifacts.delta_base_cover_ids;
    if bases.len() > MAX_DELTA_BASES || bases.contains(&input.cover_id) {
        return Err(CoverModelError::InvalidShape("invalid delta_base_cover_ids"));
    }
    if bases.windows(2).any(|w| w[0] == w[1]) {
        return Err(CoverModelError::InvalidShape("duplicate delta_base_cover_id"));
    }
    if input.artifacts.is_thin_pack && bases.is_empty() {
        return Err(CoverModelError::InvalidShape("thin pack must declare delta_base_cover_ids"));
    }
    if !input.artifacts.is_thin_pack && !bases.is_empty() {
        return Err(CoverModelError::InvalidShape("non-thin pack must not declare external delta bases"));
    }
    Ok(())
}

fn validate_versions_and_commits(input: &mut CoverHierarchyRecordInput) -> Result<(), CoverModelError> {
    if input.covered_versions.is_empty() || input.covered_versions.len() > MAX_COVER_VERSIONS {
        return Err(CoverModelError::InvalidShape("covered_versions empty or exceeds bound"));
    }
    input.covered_versions.sort();
    if input.covered_versions.windows(2).any(|w| w[0] == w[1]) {
        return Err(CoverModelError::InvalidShape("duplicate covered_version"));
    }
    if input.covered_commits.is_empty() || input.covered_commits.len() > MAX_COVER_COMMITS {
        return Err(CoverModelError::InvalidShape("covered_commits empty or exceeds bound"));
    }
    for link in &mut input.covered_commits {
        ensure_present_oid(input.realm.object_format(), link.commit_oid, "commit_oid")?;
        positive_u64(link.authority_seq, "commit_authority_seq")?;
        if link.authority_seq < input.min_authority_seq || link.authority_seq > input.max_authority_seq {
            return Err(CoverModelError::InvalidShape("commit authority_seq outside cover range"));
        }
        for parent in &link.parent_oids {
            ensure_present_oid(input.realm.object_format(), *parent, "parent_oid")?;
            if *parent == link.commit_oid {
                return Err(CoverModelError::InvalidShape("self-parent commit link"));
            }
        }
        link.parent_oids.sort_by_key(|oid| oid_bytes(*oid));
        if link.parent_oids.windows(2).any(|w| w[0] == w[1]) {
            return Err(CoverModelError::InvalidShape("duplicate parent oid"));
        }
    }
    input.covered_commits.sort_by_key(|link| oid_bytes(link.commit_oid));
    if input.covered_commits.windows(2).any(|w| w[0].commit_oid == w[1].commit_oid) {
        return Err(CoverModelError::InvalidShape("duplicate commit_oid in cover"));
    }
    Ok(())
}

fn validate_inputs(input: &mut CoverHierarchyRecordInput) -> Result<(), CoverModelError> {
    input.input_cover_ids.sort();
    if input.input_cover_ids.len() > MAX_COVER_INPUTS || input.input_cover_ids.contains(&input.cover_id) {
        return Err(CoverModelError::InvalidShape("invalid input_cover_ids"));
    }
    if input.input_cover_ids.windows(2).any(|w| w[0] == w[1]) {
        return Err(CoverModelError::InvalidShape("duplicate input_cover_id"));
    }
    match input.tier {
        CoverTier::Delta if !input.input_cover_ids.is_empty() => {
            return Err(CoverModelError::InvalidShape("delta leaf cover cannot declare input_cover_ids"));
        }
        CoverTier::Segment | CoverTier::Compacted | CoverTier::Base if input.input_cover_ids.is_empty() => {
            return Err(CoverModelError::InvalidShape("compacted cover must declare input_cover_ids"));
        }
        _ => {}
    }
    Ok(())
}

pub(super) fn compute_record_digest(input: &CoverHierarchyRecordInput) -> Result<CoverRecordDigest, CoverModelError> {
    let nums = validate_realm(&input.realm)?;
    let mut w = CanonicalWriter::new();
    w.push_len_prefixed(COVER_RECORD_DOMAIN)?;
    w.push_len_prefixed(input.cover_id.as_bytes())?;
    w.push_len_prefixed(input.realm.tenant_id().as_bytes())?;
    w.push_len_prefixed(input.realm.repository_id().as_bytes())?;
    w.push_len_prefixed(input.realm.history_incarnation().as_bytes())?;
    w.push_u8(input.realm.authority_kind().tag());
    w.push_u64(nums.authority_epoch);
    w.push_u64(nums.group_id);
    w.push_u64(nums.group_epoch);
    w.push_u8(format_tag(input.realm.object_format()));
    w.push_u8(input.tier.tag());
    w.push_len_prefixed(input.pack.entry().pack_id().as_bytes())?;
    w.push_len_prefixed(input.pack.entry().registration_id().as_bytes())?;
    w.push_len_prefixed(input.pack.entry().artifact_set_digest())?;
    w.push_len_prefixed(input.artifacts.pack_stem.as_bytes())?;
    w.push_len_prefixed(input.artifacts.pack_locator.path().as_bytes())?;
    w.push_len_prefixed(input.artifacts.idx_locator.path().as_bytes())?;
    w.push_u8(u8::from(input.artifacts.is_thin_pack));
    w.push_u32(count_u32(input.artifacts.delta_base_cover_ids.len(), "delta_bases")?);
    for id in &input.artifacts.delta_base_cover_ids {
        w.push_len_prefixed(id.as_bytes())?;
    }
    w.push_u64(positive_u64(input.min_authority_seq, "min_authority_seq")?);
    w.push_u64(positive_u64(input.max_authority_seq, "max_authority_seq")?);
    w.push_u32(count_u32(input.covered_versions.len(), "covered_versions")?);
    for vid in &input.covered_versions {
        w.push_len_prefixed(vid.as_bytes())?;
    }
    w.push_u32(count_u32(input.covered_commits.len(), "covered_commits")?);
    for link in &input.covered_commits {
        push_oid(&mut w, link.commit_oid)?;
        w.push_len_prefixed(link.version_id.as_bytes())?;
        w.push_u64(positive_u64(link.authority_seq, "commit_authority_seq")?);
        w.push_u32(count_u32(link.parent_oids.len(), "parent_oids")?);
        for parent in &link.parent_oids {
            push_oid(&mut w, *parent)?;
        }
    }
    w.push_u32(count_u32(input.input_cover_ids.len(), "input_cover_ids")?);
    for id in &input.input_cover_ids {
        w.push_len_prefixed(id.as_bytes())?;
    }
    w.push_u64(input.membership_generation);
    w.push_len_prefixed(input.membership_digest.as_bytes())?;
    w.push_u64(input.compaction_epoch);
    w.push_len_prefixed(input.worker_id.as_bytes())?;
    w.push_len_prefixed(input.operation_id.as_bytes())?;
    Ok(CoverRecordDigest::from_bytes(w.finish()))
}
