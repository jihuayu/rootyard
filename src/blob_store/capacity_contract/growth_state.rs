//! State tracking and atomic commit transitions for [`super::StreamingGrowthEngine`].

use std::collections::{BTreeMap, BTreeSet};

use uuid::Uuid;

use super::{
    git_ops::{ObjectFormat, UploadedPackPair},
    growth_types::{
        CompactionOutcome, GrowthEngineError, GrowthEngineSnapshot, PushOutcome, RefMutation, VerifiedPackRecord,
    },
    ledger_retention::RetentionLedger,
    ledger_types::LedgerEntryKind,
};

pub(super) struct EngineState {
    pub epoch: u64,
    pub active_packs: Vec<VerifiedPackRecord>,
    pub retained_old_packs: Vec<VerifiedPackRecord>,
    pub acked_refs: BTreeMap<String, String>,
    pub pinned_commits: BTreeMap<Uuid, String>,
    pub replayed_operations: BTreeMap<Uuid, (String, PushOutcome)>,
    pub cancelled_operations: BTreeSet<Uuid>,
    pub cumulative_packs_added: u64,
    pub no_new_pack_pushes: u64,
    pub compactions_completed: u64,
    pub total_blob_put_bytes: u64,
    pub total_blob_get_bytes: u64,
    pub peak_scratch_bytes: u64,
    pub ledger: RetentionLedger,
}

impl EngineState {
    pub fn snapshot(&self) -> GrowthEngineSnapshot {
        GrowthEngineSnapshot {
            epoch: self.epoch,
            active_frontier_len: self.active_packs.len(),
            cumulative_packs_added: self.cumulative_packs_added,
            no_new_pack_pushes: self.no_new_pack_pushes,
            compactions_completed: self.compactions_completed,
            active_serving_pack_bytes: self.active_packs.iter().map(VerifiedPackRecord::total_bytes).sum(),
            historical_retained_pack_bytes: self.retained_old_packs.iter().map(VerifiedPackRecord::total_bytes).sum(),
            total_blob_put_bytes: self.total_blob_put_bytes,
            total_blob_get_bytes: self.total_blob_get_bytes,
            peak_scratch_bytes: self.peak_scratch_bytes,
            acked_ref_count: self.acked_refs.len(),
            ledger: self.ledger.summary(),
        }
    }

    pub fn check_replay_or_cancel(&self, op_id: Uuid, digest: &str) -> Result<Option<PushOutcome>, GrowthEngineError> {
        if self.cancelled_operations.contains(&op_id) {
            return Err(GrowthEngineError::OperationCancelled(op_id));
        }
        if let Some((prev_digest, outcome)) = self.replayed_operations.get(&op_id) {
            if prev_digest != digest {
                return Err(GrowthEngineError::DigestConflict(op_id));
            }
            let mut replayed = outcome.clone();
            replayed.replayed = true;
            return Ok(Some(replayed));
        }
        Ok(None)
    }

    pub fn commit_compaction(
        &mut self,
        target_ids: &BTreeSet<Uuid>,
        uploaded: UploadedPackPair,
        blob_get_bytes: u64,
        peak_scratch_bytes: u64,
        oid_count: usize,
    ) -> Result<CompactionOutcome, GrowthEngineError> {
        let active_ids: BTreeSet<Uuid> = self.active_packs.iter().map(|p| p.pack_id).collect();
        if !target_ids.is_subset(&active_ids) {
            return Err(GrowthEngineError::CompactionConflict);
        }
        let compaction_epoch = self.epoch + 1;
        let compacted_rec = VerifiedPackRecord {
            pack_id: Uuid::new_v4(),
            registration_id: Uuid::new_v4(),
            pack_locator: uploaded.pack_receipt.locator().clone(),
            pack_sha256: uploaded.pack_sha256,
            pack_length: uploaded.pack_length,
            idx_locator: uploaded.idx_receipt.locator().clone(),
            idx_sha256: uploaded.idx_sha256,
            idx_length: uploaded.idx_length,
            object_count: uploaded.object_count,
            joined_epoch: compaction_epoch,
        };
        self.ledger.record_compaction_superseded(compaction_epoch, target_ids);
        self.ledger.record_entry(
            Uuid::new_v4(),
            LedgerEntryKind::Membership,
            Some(compacted_rec.pack_id),
            None,
            512,
            compaction_epoch,
        )?;
        self.ledger.record_entry(
            compacted_rec.registration_id,
            LedgerEntryKind::Registration,
            Some(compacted_rec.pack_id),
            None,
            1024,
            compaction_epoch,
        )?;

        let mut next_active = Vec::new();
        let mut newly_retained = Vec::new();
        let mut concurrent_preserved = 0usize;
        for pack in self.active_packs.drain(..) {
            if target_ids.contains(&pack.pack_id) {
                newly_retained.push(pack);
            } else {
                concurrent_preserved += 1;
                next_active.push(pack);
            }
        }
        next_active.insert(0, compacted_rec.clone());
        self.active_packs = next_active;
        self.retained_old_packs.extend(newly_retained);
        self.epoch = compaction_epoch;
        self.compactions_completed += 1;
        self.total_blob_put_bytes = self.total_blob_put_bytes.saturating_add(compacted_rec.total_bytes());
        self.total_blob_get_bytes = self.total_blob_get_bytes.saturating_add(blob_get_bytes);
        self.peak_scratch_bytes = self.peak_scratch_bytes.max(peak_scratch_bytes);
        Ok(CompactionOutcome {
            compaction_epoch,
            replaced_packs: target_ids.len(),
            compacted_pack_id: compacted_rec.pack_id,
            preserved_concurrent_packs: concurrent_preserved,
            oid_count,
        })
    }
}

pub(super) fn validate_mutations(
    format: ObjectFormat,
    max_plan_refs: usize,
    mutations: &[RefMutation],
) -> Result<(), GrowthEngineError> {
    if mutations.is_empty() || mutations.len() > max_plan_refs {
        return Err(GrowthEngineError::InvalidInput("ref_mutations must be 1..=max_plan_refs"));
    }
    let mut seen = BTreeSet::new();
    for m in mutations {
        if !m.ref_name.starts_with("refs/") || m.ref_name.contains("..") || !seen.insert(&m.ref_name) {
            return Err(GrowthEngineError::InvalidInput("invalid or duplicate ref name"));
        }
        if !(format.is_valid_oid(&m.old_oid) || format.is_zero_oid(&m.old_oid)) {
            return Err(GrowthEngineError::InvalidInput("invalid old_oid format"));
        }
        if !(format.is_valid_oid(&m.new_oid) || format.is_zero_oid(&m.new_oid)) {
            return Err(GrowthEngineError::InvalidInput("invalid new_oid format"));
        }
    }
    Ok(())
}

pub(super) fn apply_cas_mutations(
    format: ObjectFormat,
    base_refs: &BTreeMap<String, String>,
    mutations: &[RefMutation],
) -> Result<BTreeMap<String, String>, GrowthEngineError> {
    let mut next = base_refs.clone();
    for m in mutations {
        let current = next.get(&m.ref_name).map(String::as_str);
        let old_matches =
            if format.is_zero_oid(&m.old_oid) { current.is_none() } else { current == Some(m.old_oid.as_str()) };
        if !old_matches {
            return Err(GrowthEngineError::CasPreconditionFailed { ref_name: m.ref_name.clone() });
        }
        if format.is_zero_oid(&m.new_oid) {
            next.remove(&m.ref_name);
        } else {
            next.insert(m.ref_name.clone(), m.new_oid.clone());
        }
    }
    Ok(next)
}
