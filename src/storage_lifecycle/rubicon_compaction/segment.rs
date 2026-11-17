//! Open -> sealed pack segments, tiered merge planning, and no-delete byte accounting (#162).

use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{CompactionError, DELETE_OLD_PACKS_BY_DEFAULT, sharding::CompactionPackEntry};

/// Log-structured compaction tier of a pack segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SegmentTier {
    L0Ingest,
    L1Merged,
    L2Base,
}

impl SegmentTier {
    pub fn next_tier(self) -> Self {
        match self {
            Self::L0Ingest => Self::L1Merged,
            Self::L1Merged | Self::L2Base => Self::L2Base,
        }
    }
}

/// Lifecycle state of one shard pack segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SegmentState {
    Open,
    Sealed,
    Compacted { merged_into_pack_id: Uuid, compacted_at_ms: u64 },
}

/// Immutable or currently open pack segment owned by a single pack-hash shard.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackSegment {
    pub segment_id: Uuid,
    pub shard_id: u16,
    pub tier: SegmentTier,
    pub state: SegmentState,
    pub created_at_ms: u64,
    pub sealed_at_ms: Option<u64>,
    pub packs: Vec<CompactionPackEntry>,
    pub total_pair_bytes: u64,
}

/// Thresholds controlling open -> sealed segment sealing and bounded tiered merges.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SegmentTriggerPolicy {
    pub max_segment_packs: usize,
    pub max_segment_bytes: u64,
    pub max_segment_age_ms: u64,
    pub max_packs_per_batch: usize,
    pub max_rewrite_bytes_per_run: u64,
    pub min_sealed_segments_to_merge: usize,
    pub delete_old_packs: bool,
}

impl Default for SegmentTriggerPolicy {
    fn default() -> Self {
        Self {
            max_segment_packs: 4,
            max_segment_bytes: 16 * 1024 * 1024,
            max_segment_age_ms: 60_000,
            max_packs_per_batch: 8,
            max_rewrite_bytes_per_run: 64 * 1024 * 1024,
            min_sealed_segments_to_merge: 2,
            delete_old_packs: DELETE_OLD_PACKS_BY_DEFAULT,
        }
    }
}

impl SegmentTriggerPolicy {
    pub fn validate(&self) -> Result<(), CompactionError> {
        if self.max_segment_packs == 0 || self.max_packs_per_batch < 2 {
            return Err(CompactionError::InvalidInput(
                "max_segment_packs must be >= 1 and max_packs_per_batch >= 2".into(),
            ));
        }
        if self.max_segment_bytes == 0
            || self.max_segment_age_ms == 0
            || self.max_rewrite_bytes_per_run == 0
            || self.min_sealed_segments_to_merge == 0
        {
            return Err(CompactionError::InvalidInput(
                "segment byte, age, and merge thresholds must be positive".into(),
            ));
        }
        if self.delete_old_packs {
            return Err(CompactionError::DeleteForbidden);
        }
        Ok(())
    }
}

/// Planned bounded tiered merge over sealed segments of one shard.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TieredMergePlan {
    pub shard_id: u16,
    pub source_tier: SegmentTier,
    pub input_segment_ids: Vec<Uuid>,
    pub input_packs: Vec<CompactionPackEntry>,
    pub target_tier: SegmentTier,
    pub estimated_input_bytes: u64,
}

/// Separate accounting for active serving bytes vs permanently retained old pack bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactionByteAccounting {
    pub serving_pack_count: usize,
    pub retained_old_pack_count: usize,
    pub serving_pack_bytes: u64,
    pub newly_written_bytes: u64,
    pub retained_old_pack_bytes: u64,
    pub total_physical_blob_bytes: u64,
    pub delete_disabled: bool,
    pub physical_bytes_deleted: u64,
    pub claims_physical_savings: bool,
}

impl CompactionByteAccounting {
    pub fn compute(
        serving_packs: &[CompactionPackEntry],
        retained_old_packs: &[CompactionPackEntry],
        newly_written_bytes: u64,
    ) -> Self {
        let serving_pack_bytes: u64 = serving_packs.iter().map(CompactionPackEntry::physical_pair_bytes).sum();
        let retained_old_pack_bytes: u64 =
            retained_old_packs.iter().map(CompactionPackEntry::physical_pair_bytes).sum();
        Self {
            serving_pack_count: serving_packs.len(),
            retained_old_pack_count: retained_old_packs.len(),
            serving_pack_bytes,
            newly_written_bytes,
            retained_old_pack_bytes,
            total_physical_blob_bytes: serving_pack_bytes.saturating_add(retained_old_pack_bytes),
            delete_disabled: true,
            physical_bytes_deleted: 0,
            claims_physical_savings: false,
        }
    }
}

/// Result of appending one newly pushed pack into a shard segment log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IngestOutcome {
    pub target_segment_id: Uuid,
    pub sealed_segment_id: Option<Uuid>,
}

/// Per-shard log maintaining `Open -> Sealed -> Compacted` segments without blocking concurrent appends.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompactionSegmentLog {
    pub segments: BTreeMap<Uuid, PackSegment>,
    pub active_open_by_shard: BTreeMap<u16, Uuid>,
    pub segment_order: Vec<Uuid>,
}

impl CompactionSegmentLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a newly registered pack to the shard's current `Open` segment, sealing on age/count/byte triggers.
    pub fn ingest_pack(
        &mut self,
        pack: CompactionPackEntry,
        now_ms: u64,
        policy: &SegmentTriggerPolicy,
    ) -> Result<IngestOutcome, CompactionError> {
        policy.validate()?;
        if let Some(existing) =
            self.segments.values().find(|seg| seg.packs.iter().any(|existing| existing.pack_id == pack.pack_id))
        {
            return Ok(IngestOutcome { target_segment_id: existing.segment_id, sealed_segment_id: None });
        }

        let shard_id = pack.shard_id;
        let pair_bytes = pack.physical_pair_bytes();
        let mut pre_sealed = None;

        if let Some(open_id) = self.active_open_by_shard.get(&shard_id).copied()
            && let Some(open_seg) = self.segments.get_mut(&open_id)
            && open_seg.state == SegmentState::Open
            && !open_seg.packs.is_empty()
            && now_ms.saturating_sub(open_seg.created_at_ms) >= policy.max_segment_age_ms
        {
            open_seg.state = SegmentState::Sealed;
            open_seg.sealed_at_ms = Some(now_ms);
            self.active_open_by_shard.remove(&shard_id);
            pre_sealed = Some(open_id);
        }

        let seg_id = match self.active_open_by_shard.get(&shard_id).copied() {
            Some(id) if self.segments.get(&id).is_some_and(|s| s.state == SegmentState::Open) => id,
            _ => {
                let id = Uuid::new_v4();
                self.segments.insert(
                    id,
                    PackSegment {
                        segment_id: id,
                        shard_id,
                        tier: SegmentTier::L0Ingest,
                        state: SegmentState::Open,
                        created_at_ms: now_ms,
                        sealed_at_ms: None,
                        packs: Vec::new(),
                        total_pair_bytes: 0,
                    },
                );
                self.segment_order.push(id);
                self.active_open_by_shard.insert(shard_id, id);
                id
            }
        };

        let seg = self
            .segments
            .get_mut(&seg_id)
            .ok_or_else(|| CompactionError::InvalidInput("missing open segment".into()))?;
        seg.total_pair_bytes = seg.total_pair_bytes.saturating_add(pair_bytes);
        seg.packs.push(pack);

        let should_seal =
            seg.packs.len() >= policy.max_segment_packs || seg.total_pair_bytes >= policy.max_segment_bytes;
        let sealed_segment_id = if should_seal {
            seg.state = SegmentState::Sealed;
            seg.sealed_at_ms = Some(now_ms);
            self.active_open_by_shard.remove(&shard_id);
            Some(seg_id)
        } else {
            pre_sealed
        };
        Ok(IngestOutcome { target_segment_id: seg_id, sealed_segment_id })
    }

    /// Seal all non-empty `Open` segments whose age exceeded `max_segment_age_ms`.
    pub fn seal_aged_segments(
        &mut self,
        now_ms: u64,
        policy: &SegmentTriggerPolicy,
    ) -> Result<Vec<Uuid>, CompactionError> {
        policy.validate()?;
        let mut sealed = Vec::new();
        for seg_id in &self.segment_order {
            if let Some(seg) = self.segments.get_mut(seg_id)
                && seg.state == SegmentState::Open
                && !seg.packs.is_empty()
                && now_ms.saturating_sub(seg.created_at_ms) >= policy.max_segment_age_ms
            {
                seg.state = SegmentState::Sealed;
                seg.sealed_at_ms = Some(now_ms);
                self.active_open_by_shard.remove(&seg.shard_id);
                sealed.push(*seg_id);
            }
        }
        Ok(sealed)
    }

    /// Plan one bounded same-tier merge strictly over `Sealed` segments in `shard_id` (leaving `Open` and higher-tier segments untouched).
    pub fn plan_tiered_merge(
        &self,
        shard_id: u16,
        policy: &SegmentTriggerPolicy,
    ) -> Result<Option<TieredMergePlan>, CompactionError> {
        policy.validate()?;
        for tier in [SegmentTier::L0Ingest, SegmentTier::L1Merged, SegmentTier::L2Base] {
            let mut candidates: Vec<&PackSegment> = self
                .segment_order
                .iter()
                .filter_map(|id| self.segments.get(id))
                .filter(|seg| {
                    seg.shard_id == shard_id
                        && seg.tier == tier
                        && seg.state == SegmentState::Sealed
                        && !seg.packs.is_empty()
                })
                .collect();
            if candidates.is_empty() {
                continue;
            }
            candidates
                .sort_by_key(|seg| (seg.sealed_at_ms.unwrap_or(seg.created_at_ms), seg.created_at_ms, seg.segment_id));

            let mut selected_ids = Vec::new();
            let mut selected_packs = Vec::new();
            let mut est_bytes = 0u64;
            for seg in &candidates {
                let next_pack_count = selected_packs.len() + seg.packs.len();
                let next_bytes = est_bytes.saturating_add(seg.total_pair_bytes);
                if !selected_ids.is_empty()
                    && (next_pack_count > policy.max_packs_per_batch || next_bytes > policy.max_rewrite_bytes_per_run)
                {
                    break;
                }
                if seg.packs.len() > policy.max_packs_per_batch
                    || seg.total_pair_bytes > policy.max_rewrite_bytes_per_run
                {
                    return Err(CompactionError::BudgetExceeded(
                        "single sealed segment exceeds batch pack/rewrite budget".into(),
                    ));
                }
                selected_ids.push(seg.segment_id);
                selected_packs.extend(seg.packs.iter().cloned());
                est_bytes = next_bytes;
            }

            if selected_packs.len() < 2 {
                continue;
            }
            let multi_pack_l0 = tier == SegmentTier::L0Ingest && selected_ids.len() == 1;
            let single_large = est_bytes >= policy.max_segment_bytes;
            if selected_ids.len() < policy.min_sealed_segments_to_merge && !multi_pack_l0 && !single_large {
                continue;
            }

            return Ok(Some(TieredMergePlan {
                shard_id,
                source_tier: tier,
                input_segment_ids: selected_ids,
                input_packs: selected_packs,
                target_tier: tier.next_tier(),
                estimated_input_bytes: est_bytes,
            }));
        }
        Ok(None)
    }

    fn validate_merge_plan(&self, plan: &TieredMergePlan) -> Result<(), CompactionError> {
        if plan.input_segment_ids.is_empty() {
            return Err(CompactionError::InvalidInput("merge plan input_segment_ids must be non-empty".into()));
        }
        if plan.target_tier != plan.source_tier.next_tier() {
            return Err(CompactionError::OperationConflict("merge plan target_tier mismatches source_tier"));
        }
        let mut seen_segs = HashSet::with_capacity(plan.input_segment_ids.len());
        let mut expected_packs = BTreeMap::new();
        for seg_id in &plan.input_segment_ids {
            if !seen_segs.insert(*seg_id) {
                return Err(CompactionError::OperationConflict("duplicate segment_id in merge plan"));
            }
            let Some(seg) = self.segments.get(seg_id) else {
                return Err(CompactionError::MembershipDrift("planned sealed segment missing".into()));
            };
            if seg.shard_id != plan.shard_id || seg.state != SegmentState::Sealed {
                return Err(CompactionError::MembershipDrift(
                    "planned sealed segments were already compacted or moved concurrently",
                ));
            }
            if seg.tier != plan.source_tier {
                return Err(CompactionError::OperationConflict("segment tier mismatches merge plan source_tier"));
            }
            for pack in &seg.packs {
                if expected_packs.insert(pack.pack_id, pack).is_some() {
                    return Err(CompactionError::OperationConflict("duplicate pack_id inside planned segments"));
                }
            }
        }
        let mut actual_packs = BTreeMap::new();
        for pack in &plan.input_packs {
            if actual_packs.insert(pack.pack_id, pack).is_some() {
                return Err(CompactionError::OperationConflict("duplicate pack_id in merge plan input_packs"));
            }
        }
        if expected_packs.len() != actual_packs.len()
            || expected_packs.iter().any(|(id, pack)| actual_packs.get(id) != Some(pack))
        {
            return Err(CompactionError::OperationConflict("merge plan input_packs mismatch planned sealed segments"));
        }
        Ok(())
    }

    /// Atomically transition planned sealed segments to `Compacted` and append the merged segment.
    pub fn apply_compacted_merge(
        &mut self,
        plan: &TieredMergePlan,
        merged_pack: CompactionPackEntry,
        now_ms: u64,
    ) -> Result<Uuid, CompactionError> {
        self.validate_merge_plan(plan)?;
        for seg_id in &plan.input_segment_ids {
            if let Some(seg) = self.segments.get_mut(seg_id) {
                seg.state =
                    SegmentState::Compacted { merged_into_pack_id: merged_pack.pack_id, compacted_at_ms: now_ms };
            }
        }
        let merged_seg_id = Uuid::new_v4();
        let total_pair_bytes = merged_pack.physical_pair_bytes();
        let target_shard_id = merged_pack.shard_id;
        self.segments.insert(
            merged_seg_id,
            PackSegment {
                segment_id: merged_seg_id,
                shard_id: target_shard_id,
                tier: plan.target_tier,
                state: SegmentState::Sealed,
                created_at_ms: now_ms,
                sealed_at_ms: Some(now_ms),
                packs: vec![merged_pack],
                total_pair_bytes,
            },
        );
        self.segment_order.push(merged_seg_id);
        Ok(merged_seg_id)
    }

    pub fn open_pack_count(&self, shard_id: u16) -> usize {
        self.active_open_by_shard.get(&shard_id).and_then(|id| self.segments.get(id)).map_or(0, |seg| seg.packs.len())
    }

    pub fn sealed_segment_count(&self, shard_id: u16) -> usize {
        self.segments.values().filter(|seg| seg.shard_id == shard_id && seg.state == SegmentState::Sealed).count()
    }

    pub fn total_sealed_segments(&self) -> usize {
        self.segments.values().filter(|seg| seg.state == SegmentState::Sealed).count()
    }
}
