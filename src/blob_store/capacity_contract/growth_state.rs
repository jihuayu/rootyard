//! State tracking and atomic commit transitions for [`super::StreamingGrowthEngine`].

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use uuid::Uuid;

use super::{
    admission_types::AdmissionRejection,
    git_ops::{ObjectFormat, UploadedPackPair},
    git_views::is_reserved_ref_name,
    growth_types::{
        CompactionOutcome, GrowthEngineError, GrowthEngineSnapshot, PushOutcome, RefMutation, VerifiedPackRecord,
    },
    ledger_retention::RetentionLedger,
    ledger_types::{LedgerEntryKind, LedgerRetentionError},
    limits::{PandoCapacityContract, RESERVED_GIT_OPEN_FDS},
};

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
    pub uploaded: UploadedPackPair,
    pub blob_get_bytes: u64,
    pub peak_scratch_bytes: u64,
    pub oid_count: usize,
}

struct FailedUpload {
    records: Vec<VerifiedPackRecord>,
    put_bytes: u64,
    get_bytes: u64,
    scratch: u64,
}

pub(super) struct EngineState {
    pub epoch: u64,
    pub closure_revision: u64,
    pub active_packs: Vec<VerifiedPackRecord>,
    pub retained_old_packs: Vec<VerifiedPackRecord>,
    pub failed_attempt_packs: Vec<VerifiedPackRecord>,
    pub acked_refs: BTreeMap<String, String>,
    pub pinned_commits: BTreeMap<Uuid, String>,
    pub replayed_operations: BTreeMap<Uuid, (String, PushOutcome)>,
    pub replay_order: VecDeque<Uuid>,
    pub cancelled_operations: BTreeSet<Uuid>,
    pub cancel_order: VecDeque<Uuid>,
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
        if self.cancelled_operations.contains(&op_id) {
            return Err(GrowthEngineError::OperationCancelled(op_id));
        }
        Ok(None)
    }

    pub fn record_cancel(&mut self, op_id: Uuid, cap: usize) -> Result<(), GrowthEngineError> {
        if self.replayed_operations.contains_key(&op_id) {
            return Err(GrowthEngineError::InvalidInput("cannot cancel already-acked operation"));
        }
        if self.cancelled_operations.insert(op_id) {
            self.cancel_order.push_back(op_id);
            while self.cancelled_operations.len() > cap {
                if let Some(evicted) = self.cancel_order.pop_front() {
                    self.cancelled_operations.remove(&evicted);
                }
            }
        }
        Ok(())
    }

    fn record_replay(&mut self, op_id: Uuid, digest: String, outcome: PushOutcome, cap: usize) {
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

    pub fn check_resident_pack_bound(&self, max_retained: usize, extra: usize) -> Result<(), GrowthEngineError> {
        let resident = self.retained_old_packs.len().saturating_add(self.failed_attempt_packs.len());
        if resident.saturating_add(extra) > max_retained {
            return Err(GrowthEngineError::Ledger(LedgerRetentionError::LedgerBudgetExhausted {
                resource: "retained_packs",
                current: resident as u64,
                limit: max_retained as u64,
            }));
        }
        Ok(())
    }

    pub fn record_failed_upload(
        &mut self,
        records: Vec<VerifiedPackRecord>,
        put_bytes: u64,
        blob_get_bytes: u64,
        peak_scratch: u64,
        pack_cap: usize,
    ) {
        self.total_blob_put_bytes = self.total_blob_put_bytes.saturating_add(put_bytes);
        self.total_blob_get_bytes = self.total_blob_get_bytes.saturating_add(blob_get_bytes);
        self.peak_scratch_bytes = self.peak_scratch_bytes.max(peak_scratch);
        if put_bytes > 0 || !records.is_empty() {
            self.failed_attempt_count = self.failed_attempt_count.saturating_add(1);
            self.failed_attempt_blob_bytes = self.failed_attempt_blob_bytes.saturating_add(put_bytes);
            for rec in records {
                if self.retained_old_packs.len().saturating_add(self.failed_attempt_packs.len()) >= pack_cap
                    && !self.failed_attempt_packs.is_empty()
                {
                    self.failed_attempt_packs.remove(0);
                }
                self.failed_attempt_packs.push(rec);
            }
        }
    }

    pub fn commit_compaction(
        &mut self,
        input: CommitCompactionInput<'_>,
    ) -> Result<CompactionOutcome, GrowthEngineError> {
        let cap = input.max_retained_pack_records;
        match self.try_commit_compaction(input) {
            Ok(outcome) => Ok(outcome),
            Err((err, f)) => {
                self.record_failed_upload(f.records, f.put_bytes, f.get_bytes, f.scratch, cap);
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
        let mk_fail = |r| FailedUpload {
            records: vec![r],
            put_bytes,
            get_bytes: input.blob_get_bytes,
            scratch: input.peak_scratch_bytes,
        };
        let active_ids: BTreeSet<Uuid> = self.active_packs.iter().map(|p| p.pack_id).collect();
        if !input.target_ids.is_subset(&active_ids) || self.closure_revision != input.expected_closure_rev {
            return Err((GrowthEngineError::CompactionConflict, mk_fail(rec)));
        }
        if let Err(err) = self.check_resident_pack_bound(input.max_retained_pack_records, input.target_ids.len()) {
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
        let pack_cap = input.contract.streaming.max_retained_pack_records;
        match self.try_commit_push(input) {
            Ok((outcome, None)) => Ok(outcome),
            Ok((outcome, Some(failed))) => {
                self.record_failed_upload(failed.records, failed.put_bytes, failed.get_bytes, failed.scratch, pack_cap);
                Ok(outcome)
            }
            Err((err, failed)) => {
                self.record_failed_upload(failed.records, failed.put_bytes, failed.get_bytes, failed.scratch, pack_cap);
                Err(err)
            }
        }
    }

    fn try_commit_push(
        &mut self,
        input: CommitPushInput<'_>,
    ) -> Result<(PushOutcome, Option<FailedUpload>), (GrowthEngineError, FailedUpload)> {
        let mk_fail = |records, put_bytes, get_bytes, scratch| FailedUpload { records, put_bytes, get_bytes, scratch };
        let (pb, gb, sc) = (input.put_bytes, input.blob_get_bytes, input.peak_scratch_bytes);
        match self.check_replay_or_cancel(input.operation_id, &input.request_digest) {
            Ok(Some(replayed)) => {
                let extra = if pb > 0 || !input.uploaded_records.is_empty() {
                    Some(mk_fail(input.uploaded_records, pb, gb, sc))
                } else {
                    None
                };
                return Ok((replayed, extra));
            }
            Ok(None) => {}
            Err(err) => return Err((err, mk_fail(input.uploaded_records, pb, gb, sc))),
        }
        let current_pack_ids: BTreeSet<Uuid> = self.active_packs.iter().map(|p| p.pack_id).collect();
        if !input.base_pack_ids.is_subset(&current_pack_ids) {
            return Err((GrowthEngineError::CompactionConflict, mk_fail(input.uploaded_records, pb, gb, sc)));
        }
        let next_refs = match apply_cas_mutations(input.object_format, &self.acked_refs, input.ref_mutations) {
            Ok(r) => r,
            Err(err) => return Err((err, mk_fail(input.uploaded_records, pb, gb, sc))),
        };
        if let Err(err) = check_commit_window_bounds(input.contract, &self.active_packs, &input.uploaded_records) {
            return Err((err, mk_fail(input.uploaded_records, pb, gb, sc)));
        }
        let commit_epoch = self.epoch + 1;
        let next_ledger =
            match stage_push_ledger(&self.ledger, input.operation_id, commit_epoch, &input.uploaded_records) {
                Ok(l) => l,
                Err(err) => return Err((err, mk_fail(input.uploaded_records, pb, gb, sc))),
            };

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

fn check_commit_window_bounds(
    contract: &PandoCapacityContract,
    active_packs: &[VerifiedPackRecord],
    uploaded_records: &[VerifiedPackRecord],
) -> Result<(), GrowthEngineError> {
    if uploaded_records.is_empty() {
        return Ok(());
    }
    let next_pairs = active_packs.len().saturating_add(uploaded_records.len());
    if next_pairs > contract.streaming.max_active_frontier_packs {
        return Err(GrowthEngineError::Admission(AdmissionRejection::PackCountLimitReached {
            active: active_packs.len(),
            new_packs: uploaded_records.len(),
            limit: contract.streaming.max_active_frontier_packs,
        }));
    }
    let cur_bytes: u64 = active_packs.iter().map(VerifiedPackRecord::total_bytes).sum();
    let cur_objects: u64 = active_packs.iter().map(|p| p.object_count).sum();
    let add_bytes: u64 = uploaded_records.iter().map(VerifiedPackRecord::total_bytes).sum();
    let add_objects: u64 = uploaded_records.iter().map(|p| p.object_count).sum();
    let next_bytes = cur_bytes.saturating_add(add_bytes);
    let next_objects = cur_objects.saturating_add(add_objects);
    if next_bytes > contract.verifier.max_total_bytes_per_window {
        return Err(GrowthEngineError::Admission(AdmissionRejection::PackBytesExceeded {
            requested: next_bytes,
            limit: contract.verifier.max_total_bytes_per_window,
        }));
    }
    if next_objects > contract.verifier.max_objects_per_window {
        return Err(GrowthEngineError::Admission(AdmissionRejection::TooManyObjects {
            requested: next_objects,
            limit: contract.verifier.max_objects_per_window,
        }));
    }
    let next_workspace = next_bytes.saturating_mul(2);
    if next_workspace > contract.verifier.view_max_logical_bytes {
        return Err(GrowthEngineError::Admission(AdmissionRejection::WorkspaceBudgetExceeded {
            requested: next_workspace,
            limit: contract.verifier.view_max_logical_bytes,
        }));
    }
    let next_fds = (next_pairs as u64).saturating_mul(2).saturating_add(RESERVED_GIT_OPEN_FDS);
    if next_fds > contract.verifier.git_nofile {
        return Err(GrowthEngineError::Admission(AdmissionRejection::FdBudgetExceeded {
            requested: next_fds,
            limit: contract.verifier.git_nofile,
        }));
    }
    Ok(())
}

fn record_pack_entries(
    ledger: &mut RetentionLedger,
    pack_id: Uuid,
    reg_id: Uuid,
    op_id: Option<Uuid>,
    epoch: u64,
) -> Result<(), GrowthEngineError> {
    ledger.record_entry(Uuid::new_v4(), LedgerEntryKind::Membership, Some(pack_id), op_id, 512, epoch)?;
    ledger.record_entry(reg_id, LedgerEntryKind::Registration, Some(pack_id), op_id, 1024, epoch)?;
    Ok(())
}

pub(super) fn stage_compaction_ledger(
    ledger: &RetentionLedger,
    compaction_epoch: u64,
    target_ids: &BTreeSet<Uuid>,
    pack_id: Uuid,
    registration_id: Uuid,
) -> Result<RetentionLedger, GrowthEngineError> {
    let mut next_ledger = ledger.clone();
    next_ledger.record_compaction_superseded(compaction_epoch, target_ids);
    record_pack_entries(&mut next_ledger, pack_id, registration_id, None, compaction_epoch)?;
    Ok(next_ledger)
}

fn stage_push_ledger(
    ledger: &RetentionLedger,
    operation_id: Uuid,
    commit_epoch: u64,
    uploaded_records: &[VerifiedPackRecord],
) -> Result<RetentionLedger, GrowthEngineError> {
    let mut next_ledger = ledger.clone();
    for rec in uploaded_records {
        record_pack_entries(&mut next_ledger, rec.pack_id, rec.registration_id, Some(operation_id), commit_epoch)?;
    }
    next_ledger.record_entry(
        Uuid::new_v4(),
        LedgerEntryKind::Receipt,
        uploaded_records.first().map(|r| r.pack_id),
        Some(operation_id),
        512,
        commit_epoch,
    )?;
    Ok(next_ledger)
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
        if !m.ref_name.starts_with("refs/")
            || is_reserved_ref_name(&m.ref_name)
            || m.ref_name.contains("..")
            || !seen.insert(&m.ref_name)
        {
            return Err(GrowthEngineError::InvalidInput("invalid, reserved, or duplicate ref name"));
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
