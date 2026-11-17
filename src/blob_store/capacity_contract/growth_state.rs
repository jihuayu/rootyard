//! State tracking and atomic commit transitions for [`super::StreamingGrowthEngine`].

use std::collections::{BTreeMap, BTreeSet};

use uuid::Uuid;

use super::{
    admission_types::AdmissionRejection,
    git_ops::{ObjectFormat, UploadedPackPair},
    growth_types::{
        CompactionOutcome, GrowthEngineError, GrowthEngineSnapshot, PushOutcome, RefMutation, VerifiedPackRecord,
    },
    ledger_retention::RetentionLedger,
    ledger_types::LedgerEntryKind,
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
        self.ledger = stage_compaction_ledger(
            &self.ledger,
            compaction_epoch,
            target_ids,
            compacted_rec.pack_id,
            compacted_rec.registration_id,
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

    pub fn commit_push(&mut self, input: CommitPushInput<'_>) -> Result<PushOutcome, GrowthEngineError> {
        if let Some(replayed) = self.check_replay_or_cancel(input.operation_id, &input.request_digest)? {
            return Ok(replayed);
        }
        let current_pack_ids: BTreeSet<Uuid> = self.active_packs.iter().map(|p| p.pack_id).collect();
        if !input.base_pack_ids.is_subset(&current_pack_ids) {
            return Err(GrowthEngineError::CompactionConflict);
        }
        let next_refs = apply_cas_mutations(input.object_format, &self.acked_refs, input.ref_mutations)?;
        check_commit_window_bounds(input.contract, &self.active_packs, &input.uploaded_records)?;

        let commit_epoch = self.epoch + 1;
        let next_ledger = stage_push_ledger(&self.ledger, input.operation_id, commit_epoch, &input.uploaded_records)?;

        self.ledger = next_ledger;
        self.epoch = commit_epoch;
        self.acked_refs = next_refs;
        let added_count = input.uploaded_records.len();
        self.active_packs.extend(input.uploaded_records);
        self.cumulative_packs_added = self.cumulative_packs_added.saturating_add(added_count as u64);
        if added_count == 0 {
            self.no_new_pack_pushes = self.no_new_pack_pushes.saturating_add(1);
        }
        self.total_blob_put_bytes = self.total_blob_put_bytes.saturating_add(input.put_bytes);
        self.total_blob_get_bytes = self.total_blob_get_bytes.saturating_add(input.blob_get_bytes);
        self.peak_scratch_bytes = self.peak_scratch_bytes.max(input.peak_scratch_bytes);
        let outcome = PushOutcome {
            epoch: commit_epoch,
            added_packs: added_count,
            no_new_pack: added_count == 0,
            active_frontier_len: self.active_packs.len(),
            cumulative_packs_added: self.cumulative_packs_added,
            replayed: false,
        };
        self.replayed_operations.insert(input.operation_id, (input.request_digest, outcome.clone()));
        Ok(outcome)
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

fn stage_push_ledger(
    ledger: &RetentionLedger,
    operation_id: Uuid,
    commit_epoch: u64,
    uploaded_records: &[VerifiedPackRecord],
) -> Result<RetentionLedger, GrowthEngineError> {
    let mut next_ledger = ledger.clone();
    for rec in uploaded_records {
        next_ledger.record_entry(
            Uuid::new_v4(),
            LedgerEntryKind::Membership,
            Some(rec.pack_id),
            Some(operation_id),
            512,
            commit_epoch,
        )?;
        next_ledger.record_entry(
            rec.registration_id,
            LedgerEntryKind::Registration,
            Some(rec.pack_id),
            Some(operation_id),
            1024,
            commit_epoch,
        )?;
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

fn stage_compaction_ledger(
    ledger: &RetentionLedger,
    compaction_epoch: u64,
    target_ids: &BTreeSet<Uuid>,
    pack_id: Uuid,
    registration_id: Uuid,
) -> Result<RetentionLedger, GrowthEngineError> {
    let mut next_ledger = ledger.clone();
    next_ledger.record_compaction_superseded(compaction_epoch, target_ids);
    next_ledger.record_entry(
        Uuid::new_v4(),
        LedgerEntryKind::Membership,
        Some(pack_id),
        None,
        512,
        compaction_epoch,
    )?;
    next_ledger.record_entry(
        registration_id,
        LedgerEntryKind::Registration,
        Some(pack_id),
        None,
        1024,
        compaction_epoch,
    )?;
    Ok(next_ledger)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob_store::{
        BlobLocator,
        capacity_contract::ledger_types::{LedgerBudgetPolicy, LedgerRetentionError},
    };

    fn fake_pack(pack_len: u64, objects: u64, epoch: u64) -> VerifiedPackRecord {
        let (t, r, a) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let sha = "a".repeat(64);
        VerifiedPackRecord {
            pack_id: Uuid::new_v4(),
            registration_id: Uuid::new_v4(),
            pack_locator: BlobLocator::new(t, r, epoch as i64, a, "packs", &sha, pack_len).unwrap(),
            pack_sha256: sha.clone(),
            pack_length: pack_len,
            idx_locator: BlobLocator::new(t, r, epoch as i64, a, "pack-idx", &sha, 64).unwrap(),
            idx_sha256: sha,
            idx_length: 64,
            object_count: objects,
            joined_epoch: epoch,
        }
    }

    fn empty_state(contract: &PandoCapacityContract) -> EngineState {
        EngineState {
            epoch: 0,
            active_packs: Vec::new(),
            retained_old_packs: Vec::new(),
            acked_refs: BTreeMap::new(),
            pinned_commits: BTreeMap::new(),
            replayed_operations: BTreeMap::new(),
            cancelled_operations: BTreeSet::new(),
            cumulative_packs_added: 0,
            no_new_pack_pushes: 0,
            compactions_completed: 0,
            total_blob_put_bytes: 0,
            total_blob_get_bytes: 0,
            peak_scratch_bytes: 0,
            ledger: RetentionLedger::new(LedgerBudgetPolicy::from_contract(contract)),
        }
    }

    #[test]
    fn stage_compaction_handles_16_active_and_rolls_back_budget_failures() {
        let mut contract = PandoCapacityContract::current_standalone();
        contract.metadata_ledger.repo_max_registrations = 16;
        let mut ledger = RetentionLedger::new(LedgerBudgetPolicy::from_contract(&contract));
        let mut target_ids = BTreeSet::new();
        for i in 1..=16u64 {
            let pid = Uuid::new_v4();
            target_ids.insert(pid);
            ledger.record_entry(Uuid::new_v4(), LedgerEntryKind::Membership, Some(pid), None, 512, i).unwrap();
            ledger.record_entry(Uuid::new_v4(), LedgerEntryKind::Registration, Some(pid), None, 1024, i).unwrap();
        }
        assert!(matches!(
            stage_compaction_ledger(&ledger, 17, &target_ids, Uuid::new_v4(), Uuid::new_v4()),
            Err(GrowthEngineError::Ledger(LedgerRetentionError::LedgerBudgetExhausted {
                resource: "registrations",
                ..
            }))
        ));
        assert_eq!(ledger.summary().active_memberships, 16);
        assert_eq!(ledger.summary().released_memberships, 0);

        contract.metadata_ledger.repo_max_registrations = 32;
        let mut ledger2 = RetentionLedger::new(LedgerBudgetPolicy::from_contract(&contract));
        let mut t2 = BTreeSet::new();
        for i in 1..=16u64 {
            let pid = Uuid::new_v4();
            t2.insert(pid);
            ledger2.record_entry(Uuid::new_v4(), LedgerEntryKind::Membership, Some(pid), None, 512, i).unwrap();
            ledger2.record_entry(Uuid::new_v4(), LedgerEntryKind::Registration, Some(pid), None, 1024, i).unwrap();
        }
        let compacted = stage_compaction_ledger(&ledger2, 17, &t2, Uuid::new_v4(), Uuid::new_v4()).unwrap();
        assert_eq!(compacted.summary().active_memberships, 1);
        assert_eq!(compacted.summary().released_memberships, 16);
    }

    #[test]
    fn commit_push_rejects_drift_window_bounds_and_rolls_back_ledger() {
        let mut contract = PandoCapacityContract::current_standalone();
        contract.metadata_ledger.repo_max_receipts = 1;
        contract.verifier.max_total_bytes_per_window = 2048;
        contract.verifier.max_objects_per_window = 20;
        let mut state = empty_state(&contract);
        let p0 = fake_pack(1000, 10, 1);
        let oid1 = "1".repeat(40);
        let zero = "0".repeat(40);
        let m1 = [RefMutation { ref_name: "refs/heads/main".into(), old_oid: zero.clone(), new_oid: oid1 }];
        let m2 = [RefMutation { ref_name: "refs/heads/other".into(), old_oid: zero, new_oid: "2".repeat(40) }];
        let run =
            |st: &mut EngineState, muts: &[RefMutation], base: &BTreeSet<Uuid>, packs: Vec<VerifiedPackRecord>| {
                let put_b: u64 = packs.iter().map(VerifiedPackRecord::total_bytes).sum();
                st.commit_push(CommitPushInput {
                    contract: &contract,
                    object_format: ObjectFormat::Sha1,
                    operation_id: Uuid::new_v4(),
                    request_digest: Uuid::new_v4().to_string(),
                    ref_mutations: muts,
                    base_pack_ids: base,
                    uploaded_records: packs,
                    put_bytes: put_b,
                    blob_get_bytes: 0,
                    peak_scratch_bytes: 0,
                })
            };
        run(&mut state, &m1, &BTreeSet::new(), vec![p0.clone()]).unwrap();

        let snap_before = state.snapshot();
        let live_ids = BTreeSet::from([p0.pack_id]);

        assert!(matches!(
            run(&mut state, &m2, &BTreeSet::from([Uuid::new_v4()]), vec![]),
            Err(GrowthEngineError::CompactionConflict)
        ));
        assert!(matches!(
            run(&mut state, &m2, &live_ids, vec![fake_pack(1500, 5, 2)]),
            Err(GrowthEngineError::Admission(AdmissionRejection::PackBytesExceeded { .. }))
        ));
        assert!(matches!(
            run(&mut state, &m2, &live_ids, vec![fake_pack(500, 11, 2)]),
            Err(GrowthEngineError::Admission(AdmissionRejection::TooManyObjects { .. }))
        ));
        assert!(matches!(
            run(&mut state, &m2, &live_ids, vec![fake_pack(500, 5, 2)]),
            Err(GrowthEngineError::Ledger(LedgerRetentionError::LedgerBudgetExhausted { resource: "receipts", .. }))
        ));
        assert_eq!(state.snapshot(), snap_before);
        assert_eq!(state.active_packs.len(), 1);
    }
}
