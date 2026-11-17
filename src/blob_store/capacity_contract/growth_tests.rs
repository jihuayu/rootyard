//! Unit regressions for `EngineState` atomicity, fencing, bounds, and late cancellation.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use uuid::Uuid;

use super::{
    admission_types::AdmissionRejection,
    git_ops::ObjectFormat,
    growth_state::{CommitPushInput, EngineState, stage_compaction_ledger, validate_mutations},
    growth_types::{GrowthEngineError, RefMutation, VerifiedPackRecord},
    ledger_retention::RetentionLedger,
    ledger_types::{LedgerBudgetPolicy, LedgerEntryKind, LedgerRetentionError},
    limits::PandoCapacityContract,
};
use crate::blob_store::BlobLocator;

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
        closure_revision: 0,
        active_packs: Vec::new(),
        retained_old_packs: Vec::new(),
        failed_attempt_packs: Vec::new(),
        acked_refs: BTreeMap::new(),
        pinned_commits: BTreeMap::new(),
        replayed_operations: BTreeMap::new(),
        replay_order: VecDeque::new(),
        cancelled_operations: BTreeSet::new(),
        cancel_order: VecDeque::new(),
        cumulative_packs_added: 0,
        no_new_pack_pushes: 0,
        compactions_completed: 0,
        failed_attempt_count: 0,
        failed_attempt_blob_bytes: 0,
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
        Err(GrowthEngineError::Ledger(LedgerRetentionError::LedgerBudgetExhausted { resource: "registrations", .. }))
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
fn commit_push_rejects_drift_window_bounds_accounts_failed_uploads_and_bounds_replay() {
    let mut contract = PandoCapacityContract::current_standalone();
    contract.metadata_ledger.repo_max_receipts = 2;
    contract.verifier.max_total_bytes_per_window = 2048;
    contract.verifier.max_objects_per_window = 20;
    contract.streaming.max_resident_replay_ops = 1;
    contract.streaming.max_retained_pack_records = 2;
    let mut state = empty_state(&contract);
    let p0 = fake_pack(1000, 10, 1);
    let oid1 = "1".repeat(40);
    let zero = "0".repeat(40);
    let m1 = [RefMutation { ref_name: "refs/heads/main".into(), old_oid: zero.clone(), new_oid: oid1 }];
    let m2 = [RefMutation { ref_name: "refs/heads/other".into(), old_oid: zero, new_oid: "2".repeat(40) }];
    let op1 = Uuid::new_v4();
    let run = |st: &mut EngineState,
               op: Uuid,
               muts: &[RefMutation],
               base: &BTreeSet<Uuid>,
               packs: Vec<VerifiedPackRecord>| {
        let put_b: u64 = packs.iter().map(VerifiedPackRecord::total_bytes).sum();
        st.commit_push(CommitPushInput {
            contract: &contract,
            object_format: ObjectFormat::Sha1,
            operation_id: op,
            request_digest: op.to_string(),
            ref_mutations: muts,
            base_pack_ids: base,
            uploaded_records: packs,
            put_bytes: put_b,
            blob_get_bytes: 0,
            peak_scratch_bytes: 0,
        })
    };
    run(&mut state, op1, &m1, &BTreeSet::new(), vec![p0.clone()]).unwrap();
    assert!(matches!(state.record_cancel(op1, 8), Err(GrowthEngineError::InvalidInput(_))));
    assert!(run(&mut state, op1, &m1, &BTreeSet::new(), vec![]).unwrap().replayed);

    let live_ids = BTreeSet::from([p0.pack_id]);
    assert!(matches!(
        run(&mut state, Uuid::new_v4(), &m2, &BTreeSet::from([Uuid::new_v4()]), vec![]),
        Err(GrowthEngineError::CompactionConflict)
    ));
    assert!(matches!(
        run(&mut state, Uuid::new_v4(), &m2, &live_ids, vec![fake_pack(1500, 5, 2)]),
        Err(GrowthEngineError::Admission(AdmissionRejection::PackBytesExceeded { .. }))
    ));
    assert!(matches!(
        run(&mut state, Uuid::new_v4(), &m2, &live_ids, vec![fake_pack(500, 11, 2)]),
        Err(GrowthEngineError::Admission(AdmissionRejection::TooManyObjects { .. }))
    ));
    let snap_after_failed = state.snapshot();
    assert_eq!(snap_after_failed.failed_attempt_count, 2);
    assert_eq!(snap_after_failed.failed_attempt_blob_bytes, 1564 + 564);
    assert_eq!(snap_after_failed.total_blob_put_bytes, 1064 + 1564 + 564);
    assert!(state.check_resident_pack_bound(2, 1).is_err());

    run(&mut state, Uuid::new_v4(), &m2, &live_ids, vec![]).unwrap();
    assert_eq!(state.snapshot().resident_replay_ops, 1);
    assert_eq!(state.snapshot().closure_revision, 2);
    assert!(matches!(
        validate_mutations(
            ObjectFormat::Sha1,
            16,
            &[RefMutation {
                ref_name: "refs/pando-pins/pin-0000".into(),
                old_oid: "0".repeat(40),
                new_oid: "3".repeat(40)
            }]
        ),
        Err(GrowthEngineError::InvalidInput(_))
    ));
}
