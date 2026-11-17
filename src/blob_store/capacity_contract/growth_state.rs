//! State tracking and atomic commit transitions for [`super::StreamingGrowthEngine`].

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use uuid::Uuid;

pub(super) use super::growth_cas::{
    apply_cas_mutations, check_commit_window_bounds, check_ref_and_hold_bytes, resident_ref_and_hold_bytes,
    stage_compaction_ledger, validate_mutations,
};
use super::{
    git_ops::{ObjectFormat, UploadedPackPair},
    growth_cas::stage_push_ledger,
    growth_types::{
        CompactionOutcome, FailedAttemptRecord, GrowthEngineError, GrowthEngineSnapshot, PushOutcome, RefMutation,
        VerifiedPackRecord,
    },
    ledger_retention::RetentionLedger,
    ledger_types::{LedgerRetentionError, ProtectionHold},
    limits::PandoCapacityContract,
};
use crate::blob_store::BlobLocator;

pub(super) struct CommitPushInput<'a> {
    pub contract: &'a PandoCapacityContract,
    pub object_format: ObjectFormat,
    pub operation_id: Uuid,
    pub request_digest: String,
    pub ref_mutations: &'a [RefMutation],
    pub base_pack_ids: &'a BTreeSet<Uuid>,
    pub uploaded_records: Vec<VerifiedPackRecord>,
    pub put_bytes: u64,
    pub blob_get_bytes: u64,
    pub peak_scratch_bytes: u64,
}

pub(super) struct CommitCompactionInput<'a> {
    pub target_ids: &'a BTreeSet<Uuid>,
    pub expected_closure_rev: u64,
    pub max_retained_pack_records: usize,
    pub max_retained_pack_bytes: u64,
    pub uploaded: UploadedPackPair,
    pub blob_get_bytes: u64,
    pub peak_scratch_bytes: u64,
    pub oid_count: usize,
}

struct FailedUpload {
    locators: Vec<BlobLocator>,
    put_bytes: u64,
    get_bytes: u64,
    scratch: u64,
}

pub(super) struct EngineState {
    pub epoch: u64,
    pub closure_revision: u64,
    pub active_packs: Vec<VerifiedPackRecord>,
    pub retained_old_packs: Vec<VerifiedPackRecord>,
    pub failed_attempt_records: Vec<FailedAttemptRecord>,
    pub acked_refs: BTreeMap<String, String>,
    pub pinned_commits: BTreeMap<Uuid, String>,
    pub replayed_operations: BTreeMap<Uuid, (String, PushOutcome)>,
    pub replay_order: VecDeque<Uuid>,
    pub acked_op_fences: BTreeSet<Uuid>,
    pub cancelled_operations: BTreeSet<Uuid>,
    pub cumulative_packs_added: u64,
    pub no_new_pack_pushes: u64,
    pub compactions_completed: u64,
    pub failed_attempt_count: u64,
    pub failed_attempt_blob_bytes: u64,
    pub total_blob_put_bytes: u64,
    pub total_blob_get_bytes: u64,
    pub peak_scratch_bytes: u64,
    pub ledger: RetentionLedger,
}

impl EngineState {
    pub fn snapshot(&self) -> GrowthEngineSnapshot {
        GrowthEngineSnapshot {
            epoch: self.epoch,
            closure_revision: self.closure_revision,
            active_frontier_len: self.active_packs.len(),
            cumulative_packs_added: self.cumulative_packs_added,
            no_new_pack_pushes: self.no_new_pack_pushes,
            compactions_completed: self.compactions_completed,
            active_serving_pack_bytes: self.active_packs.iter().map(VerifiedPackRecord::total_bytes).sum(),
            historical_retained_pack_bytes: self.retained_old_packs.iter().map(VerifiedPackRecord::total_bytes).sum(),
            failed_attempt_count: self.failed_attempt_count,
            failed_attempt_blob_bytes: self.failed_attempt_blob_bytes,
            resident_replay_ops: self.replayed_operations.len(),
            total_blob_put_bytes: self.total_blob_put_bytes,
            total_blob_get_bytes: self.total_blob_get_bytes,
            peak_scratch_bytes: self.peak_scratch_bytes,
            acked_ref_count: self.acked_refs.len(),
            ledger: self.ledger.summary(),
        }
    }

    pub fn check_replay_or_cancel(&self, op_id: Uuid, digest: &str) -> Result<Option<PushOutcome>, GrowthEngineError> {
        if let Some((prev_digest, outcome)) = self.replayed_operations.get(&op_id) {
            if prev_digest != digest {
                return Err(GrowthEngineError::DigestConflict(op_id));
            }
            let mut replayed = outcome.clone();
            replayed.replayed = true;
            return Ok(Some(replayed));
        }
        if self.acked_op_fences.contains(&op_id) {
            return Err(GrowthEngineError::InvalidInput("operation already acknowledged; replay cache evicted"));
        }
        if self.cancelled_operations.contains(&op_id) {
            return Err(GrowthEngineError::OperationCancelled(op_id));
        }
        Ok(None)
    }

    pub fn record_cancel(&mut self, op_id: Uuid, fence_cap: usize) -> Result<(), GrowthEngineError> {
        if self.replayed_operations.contains_key(&op_id) || self.acked_op_fences.contains(&op_id) {
            return Err(GrowthEngineError::InvalidInput("cannot cancel already-acked operation"));
        }
        if self.cancelled_operations.contains(&op_id) {
            return Ok(());
        }
        let total = self.acked_op_fences.len().saturating_add(self.cancelled_operations.len());
        if total >= fence_cap {
            return Err(GrowthEngineError::Ledger(LedgerRetentionError::LedgerBudgetExhausted {
                resource: "cancel_tombstones",
                current: total as u64,
                limit: fence_cap as u64,
            }));
        }
        self.cancelled_operations.insert(op_id);
        Ok(())
    }

    pub fn check_op_fence_bound(&self, op_id: Uuid, max_fences: usize) -> Result<(), GrowthEngineError> {
        let total = self.acked_op_fences.len().saturating_add(self.cancelled_operations.len());
        if !self.acked_op_fences.contains(&op_id) && total >= max_fences {
            return Err(GrowthEngineError::Ledger(LedgerRetentionError::LedgerBudgetExhausted {
                resource: "op_fences",
                current: total as u64,
                limit: max_fences as u64,
            }));
        }
        Ok(())
    }

    fn record_replay(&mut self, op_id: Uuid, digest: String, outcome: PushOutcome, cap: usize) {
        self.acked_op_fences.insert(op_id);
        if !self.replayed_operations.contains_key(&op_id) {
            self.replay_order.push_back(op_id);
        }
        self.replayed_operations.insert(op_id, (digest, outcome));
        while self.replayed_operations.len() > cap {
            if let Some(evicted) = self.replay_order.pop_front() {
                self.replayed_operations.remove(&evicted);
            }
        }
    }

    pub fn retained_pack_record_count(&self) -> usize {
        self.retained_old_packs.len().saturating_add(self.failed_attempt_records.iter().map(|r| r.pack_count).sum())
    }

    pub fn resident_retained_bytes(&self) -> u64 {
        let old_b: u64 = self.retained_old_packs.iter().map(VerifiedPackRecord::total_bytes).sum();
        let fail_b: u64 = self.failed_attempt_records.iter().map(|r| r.total_bytes).sum();
        old_b.saturating_add(fail_b)
    }

    pub fn ref_and_hold_bytes(&self) -> u64 {
        resident_ref_and_hold_bytes(&self.acked_refs, &self.pinned_commits, &self.ledger)
    }

    pub fn check_push_preconditions(
        &self,
        contract: &PandoCapacityContract,
        op_id: Uuid,
        new_packs: usize,
        new_bytes: u64,
        next_refs: &BTreeMap<String, String>,
    ) -> Result<(), GrowthEngineError> {
        self.check_op_fence_bound(op_id, contract.streaming.max_resident_op_fences)?;
        self.check_resident_pack_bound(
            contract.streaming.max_retained_pack_records,
            contract.streaming.max_retained_pack_bytes,
            new_packs,
            new_bytes,
        )?;
        let expected_frontier_holds_b = (new_packs as u64).saturating_mul(2).saturating_add(1).saturating_mul(16);
        let next_total = resident_ref_and_hold_bytes(next_refs, &self.pinned_commits, &self.ledger)
            .saturating_add(expected_frontier_holds_b);
        check_ref_and_hold_bytes(
            contract.metadata_ledger.max_resident_ref_and_hold_bytes,
            next_total,
            self.ref_and_hold_bytes(),
        )
    }

    pub fn attach_hold_checked(
        &mut self,
        hold: ProtectionHold,
        pinned_oid: Option<String>,
        max_holds: usize,
        max_ref_and_hold_bytes: u64,
    ) -> Result<usize, GrowthEngineError> {
        hold.validate()?;
        let hold_id = hold.hold_id();
        if pinned_oid.is_some() && !self.pinned_commits.contains_key(&hold_id) && self.pinned_commits.len() >= max_holds
        {
            return Err(GrowthEngineError::Ledger(LedgerRetentionError::LedgerBudgetExhausted {
                resource: "pins",
                current: self.pinned_commits.len() as u64,
                limit: max_holds as u64,
            }));
        }
        let mut next_ledger = self.ledger.clone();
        let count = next_ledger.attach_hold_to_active_frontier(hold)?;
        let extra_pin_b = match &pinned_oid {
            Some(oid) if !self.pinned_commits.contains_key(&hold_id) => 16u64.saturating_add(oid.len() as u64),
            _ => 0,
        };
        let next_total = resident_ref_and_hold_bytes(&self.acked_refs, &self.pinned_commits, &next_ledger)
            .saturating_add(extra_pin_b);
        check_ref_and_hold_bytes(max_ref_and_hold_bytes, next_total, self.ref_and_hold_bytes())?;
        self.ledger = next_ledger;
        if let Some(oid) = pinned_oid {
            self.pinned_commits.insert(hold_id, oid);
            self.closure_revision = self.closure_revision.saturating_add(1);
        }
        Ok(count)
    }

    pub fn check_resident_pack_bound(
        &self,
        max_retained: usize,
        max_retained_bytes: u64,
        extra_records: usize,
        extra_bytes: u64,
    ) -> Result<(), GrowthEngineError> {
        let resident = self.retained_pack_record_count();
        if resident.saturating_add(extra_records) > max_retained {
            return Err(GrowthEngineError::Ledger(LedgerRetentionError::LedgerBudgetExhausted {
                resource: "retained_packs",
                current: resident as u64,
                limit: max_retained as u64,
            }));
        }
        let resident_bytes = self.resident_retained_bytes();
        if resident_bytes.saturating_add(extra_bytes) > max_retained_bytes {
            return Err(GrowthEngineError::Ledger(LedgerRetentionError::LedgerBudgetExhausted {
                resource: "retained_pack_bytes",
                current: resident_bytes,
                limit: max_retained_bytes,
            }));
        }
        Ok(())
    }

    pub fn record_failed_upload(
        &mut self,
        locators: Vec<BlobLocator>,
        put_bytes: u64,
        blob_get_bytes: u64,
        peak_scratch: u64,
        pack_cap: usize,
        byte_cap: u64,
    ) {
        self.total_blob_put_bytes = self.total_blob_put_bytes.saturating_add(put_bytes);
        self.total_blob_get_bytes = self.total_blob_get_bytes.saturating_add(blob_get_bytes);
        self.peak_scratch_bytes = self.peak_scratch_bytes.max(peak_scratch);
        if put_bytes > 0 || !locators.is_empty() {
            self.failed_attempt_count = self.failed_attempt_count.saturating_add(1);
            self.failed_attempt_blob_bytes = self.failed_attempt_blob_bytes.saturating_add(put_bytes);
            let pack_count =
                locators.iter().filter(|l| l.path().contains("/packs/")).count().max(usize::from(!locators.is_empty()));
            if !locators.is_empty()
                && self.retained_pack_record_count().saturating_add(pack_count) <= pack_cap
                && self.resident_retained_bytes().saturating_add(put_bytes) <= byte_cap
            {
                self.failed_attempt_records.push(FailedAttemptRecord { locators, pack_count, total_bytes: put_bytes });
            }
        }
    }

    pub fn commit_compaction(
        &mut self,
        input: CommitCompactionInput<'_>,
    ) -> Result<CompactionOutcome, GrowthEngineError> {
        let (cap, byte_cap) = (input.max_retained_pack_records, input.max_retained_pack_bytes);
        match self.try_commit_compaction(input) {
            Ok(outcome) => Ok(outcome),
            Err((err, f)) => {
                self.record_failed_upload(f.locators, f.put_bytes, f.get_bytes, f.scratch, cap, byte_cap);
                Err(err)
            }
        }
    }

    fn try_commit_compaction(
        &mut self,
        input: CommitCompactionInput<'_>,
    ) -> Result<CompactionOutcome, (GrowthEngineError, FailedUpload)> {
        let compaction_epoch = self.epoch + 1;
        let rec = VerifiedPackRecord {
            pack_id: Uuid::new_v4(),
            registration_id: Uuid::new_v4(),
            pack_locator: input.uploaded.pack_receipt.locator().clone(),
            pack_sha256: input.uploaded.pack_sha256,
            pack_length: input.uploaded.pack_length,
            idx_locator: input.uploaded.idx_receipt.locator().clone(),
            idx_sha256: input.uploaded.idx_sha256,
            idx_length: input.uploaded.idx_length,
            object_count: input.uploaded.object_count,
            joined_epoch: compaction_epoch,
        };
        let put_bytes = rec.total_bytes();
        let mk_fail = |r: VerifiedPackRecord| FailedUpload {
            locators: vec![r.pack_locator, r.idx_locator],
            put_bytes,
            get_bytes: input.blob_get_bytes,
            scratch: input.peak_scratch_bytes,
        };
        let active_ids: BTreeSet<Uuid> = self.active_packs.iter().map(|p| p.pack_id).collect();
        if !input.target_ids.is_subset(&active_ids) || self.closure_revision != input.expected_closure_rev {
            return Err((GrowthEngineError::CompactionConflict, mk_fail(rec)));
        }
        let target_bytes: u64 = self
            .active_packs
            .iter()
            .filter(|p| input.target_ids.contains(&p.pack_id))
            .map(VerifiedPackRecord::total_bytes)
            .sum();
        if let Err(err) = self.check_resident_pack_bound(
            input.max_retained_pack_records,
            input.max_retained_pack_bytes,
            input.target_ids.len(),
            target_bytes,
        ) {
            return Err((err, mk_fail(rec)));
        }
        let next_ledger = match stage_compaction_ledger(
            &self.ledger,
            compaction_epoch,
            input.target_ids,
            rec.pack_id,
            rec.registration_id,
        ) {
            Ok(l) => l,
            Err(err) => return Err((err, mk_fail(rec))),
        };

        self.ledger = next_ledger;
        let mut next_active = Vec::new();
        let mut newly_retained = Vec::new();
        let mut concurrent_preserved = 0usize;
        for pack in self.active_packs.drain(..) {
            if input.target_ids.contains(&pack.pack_id) {
                newly_retained.push(pack);
            } else {
                concurrent_preserved += 1;
                next_active.push(pack);
            }
        }
        next_active.insert(0, rec.clone());
        self.active_packs = next_active;
        self.retained_old_packs.extend(newly_retained);
        self.epoch = compaction_epoch;
        self.compactions_completed += 1;
        self.total_blob_put_bytes = self.total_blob_put_bytes.saturating_add(put_bytes);
        self.total_blob_get_bytes = self.total_blob_get_bytes.saturating_add(input.blob_get_bytes);
        self.peak_scratch_bytes = self.peak_scratch_bytes.max(input.peak_scratch_bytes);
        Ok(CompactionOutcome {
            compaction_epoch,
            replaced_packs: input.target_ids.len(),
            compacted_pack_id: rec.pack_id,
            preserved_concurrent_packs: concurrent_preserved,
            oid_count: input.oid_count,
        })
    }

    pub fn commit_push(&mut self, input: CommitPushInput<'_>) -> Result<PushOutcome, GrowthEngineError> {
        let (pack_cap, byte_cap) =
            (input.contract.streaming.max_retained_pack_records, input.contract.streaming.max_retained_pack_bytes);
        match self.try_commit_push(input) {
            Ok((outcome, None)) => Ok(outcome),
            Ok((outcome, Some(f))) => {
                self.record_failed_upload(f.locators, f.put_bytes, f.get_bytes, f.scratch, pack_cap, byte_cap);
                Ok(outcome)
            }
            Err((err, f)) => {
                self.record_failed_upload(f.locators, f.put_bytes, f.get_bytes, f.scratch, pack_cap, byte_cap);
                Err(err)
            }
        }
    }

    fn try_commit_push(
        &mut self,
        input: CommitPushInput<'_>,
    ) -> Result<(PushOutcome, Option<FailedUpload>), (GrowthEngineError, FailedUpload)> {
        let (pb, gb, sc) = (input.put_bytes, input.blob_get_bytes, input.peak_scratch_bytes);
        let mk_fail = |recs: Vec<VerifiedPackRecord>| FailedUpload {
            locators: recs.into_iter().flat_map(|r| [r.pack_locator, r.idx_locator]).collect(),
            put_bytes: pb,
            get_bytes: gb,
            scratch: sc,
        };
        match self.check_replay_or_cancel(input.operation_id, &input.request_digest) {
            Ok(Some(replayed)) => {
                let extra = if pb > 0 || !input.uploaded_records.is_empty() {
                    Some(mk_fail(input.uploaded_records))
                } else {
                    None
                };
                return Ok((replayed, extra));
            }
            Ok(None) => {}
            Err(err) => return Err((err, mk_fail(input.uploaded_records))),
        }
        if let Err(err) = self.check_op_fence_bound(input.operation_id, input.contract.streaming.max_resident_op_fences)
        {
            return Err((err, mk_fail(input.uploaded_records)));
        }
        let current_pack_ids: BTreeSet<Uuid> = self.active_packs.iter().map(|p| p.pack_id).collect();
        if !input.base_pack_ids.is_subset(&current_pack_ids) {
            return Err((GrowthEngineError::CompactionConflict, mk_fail(input.uploaded_records)));
        }
        let next_refs = match apply_cas_mutations(input.object_format, &self.acked_refs, input.ref_mutations) {
            Ok(r) => r,
            Err(err) => return Err((err, mk_fail(input.uploaded_records))),
        };
        if let Err(err) = check_acked_refs_bound(input.contract.metadata_ledger.max_capture_refs, next_refs.len()) {
            return Err((err, mk_fail(input.uploaded_records)));
        }
        if let Err(err) = check_commit_window_bounds(input.contract, &self.active_packs, &input.uploaded_records) {
            return Err((err, mk_fail(input.uploaded_records)));
        }
        let commit_epoch = self.epoch + 1;
        let next_ledger =
            match stage_push_ledger(&self.ledger, input.operation_id, commit_epoch, &input.uploaded_records) {
                Ok(l) => l,
                Err(err) => return Err((err, mk_fail(input.uploaded_records))),
            };
        let next_ref_hold = resident_ref_and_hold_bytes(&next_refs, &self.pinned_commits, &next_ledger);
        if let Err(err) = check_ref_and_hold_bytes(
            input.contract.metadata_ledger.max_resident_ref_and_hold_bytes,
            next_ref_hold,
            self.ref_and_hold_bytes(),
        ) {
            return Err((err, mk_fail(input.uploaded_records)));
        }

        self.ledger = next_ledger;
        self.epoch = commit_epoch;
        self.closure_revision = self.closure_revision.saturating_add(1);
        self.acked_refs = next_refs;
        let added_count = input.uploaded_records.len();
        self.active_packs.extend(input.uploaded_records);
        self.cumulative_packs_added = self.cumulative_packs_added.saturating_add(added_count as u64);
        if added_count == 0 {
            self.no_new_pack_pushes = self.no_new_pack_pushes.saturating_add(1);
        }
        self.total_blob_put_bytes = self.total_blob_put_bytes.saturating_add(pb);
        self.total_blob_get_bytes = self.total_blob_get_bytes.saturating_add(gb);
        self.peak_scratch_bytes = self.peak_scratch_bytes.max(sc);
        let outcome = PushOutcome {
            epoch: commit_epoch,
            added_packs: added_count,
            no_new_pack: added_count == 0,
            active_frontier_len: self.active_packs.len(),
            cumulative_packs_added: self.cumulative_packs_added,
            replayed: false,
        };
        self.record_replay(
            input.operation_id,
            input.request_digest,
            outcome.clone(),
            input.contract.streaming.max_resident_replay_ops,
        );
        Ok((outcome, None))
    }
}

pub(super) fn check_acked_refs_bound(cap: usize, next_len: usize) -> Result<(), GrowthEngineError> {
    if next_len > cap {
        return Err(GrowthEngineError::Ledger(LedgerRetentionError::LedgerBudgetExhausted {
            resource: "acked_refs",
            current: next_len as u64,
            limit: cap as u64,
        }));
    }
    Ok(())
}
