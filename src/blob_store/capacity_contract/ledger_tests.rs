//! Unit regressions for ledger retention protection holds, bounds, and byte reclamation.

use std::collections::BTreeSet;

use uuid::Uuid;

use super::{
    ledger_retention::RetentionLedger,
    ledger_types::{
        LedgerBudgetPolicy, LedgerEntryKind, LedgerRetentionError, ProtectionHold, RetentionClassification,
    },
    limits::PandoCapacityContract,
};

#[test]
fn compaction_preserves_pins_roots_backups_and_blocks_delete() {
    let contract = PandoCapacityContract::current_standalone();
    let mut ledger = RetentionLedger::new(LedgerBudgetPolicy::from_contract(&contract));
    let (p1, m1, r1) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    ledger.record_entry(m1, LedgerEntryKind::Membership, Some(p1), None, 512, 1).unwrap();
    ledger.record_entry(r1, LedgerEntryKind::Registration, Some(p1), None, 1024, 1).unwrap();

    let (pin_id, root_id) = (Uuid::new_v4(), Uuid::new_v4());
    ledger.attach_hold_to_pack(p1, ProtectionHold::Pin { pin_id, purpose: "ci".into() }).unwrap();
    ledger.attach_hold_to_pack(p1, ProtectionHold::RetentionRoot { root_id, kind: "pitr".into() }).unwrap();

    ledger.record_compaction_superseded(2, &BTreeSet::from([p1]));
    assert_eq!(ledger.get(m1).unwrap().classification(), RetentionClassification::CompactedProtected);
    assert!(matches!(ledger.attempt_delete_entry(m1), Err(LedgerRetentionError::ProtectedByHold { .. })));
    assert_eq!(ledger.archive_released_entries(), 0);

    ledger.release_hold(pin_id).unwrap();
    ledger.release_hold(root_id).unwrap();
    assert_eq!(ledger.get(m1).unwrap().classification(), RetentionClassification::ReleasedEligibleForArchive);
    assert!(matches!(
        ledger.attempt_delete_entry(m1),
        Err(LedgerRetentionError::CompactionDoesNotAuthorizeDelete { .. })
    ));
    assert_eq!(ledger.archive_released_entries(), 2);
    assert_eq!(ledger.summary().hot_logical_bytes, 0);
}

#[test]
fn enforces_hot_registration_budget_and_backup_hold_release() {
    let mut policy = LedgerBudgetPolicy::from_contract(&PandoCapacityContract::current_standalone());
    policy.repo_max_registrations = 2;
    let mut ledger = RetentionLedger::new(policy);
    let (p1, p2, m1, r1, r2, bid) =
        (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    ledger.record_entry(m1, LedgerEntryKind::Membership, Some(p1), None, 512, 1).unwrap();
    ledger.record_entry(r1, LedgerEntryKind::Registration, Some(p1), None, 1024, 1).unwrap();
    ledger.record_entry(r2, LedgerEntryKind::Registration, Some(p2), None, 1024, 2).unwrap();
    ledger.attach_hold_to_pack(p1, ProtectionHold::BackupManifest { backup_id: bid }).unwrap();
    ledger.record_compaction_superseded(3, &BTreeSet::from([p1, p2]));
    assert_eq!(ledger.get(r1).unwrap().classification(), RetentionClassification::CompactedProtected);
    assert_eq!(ledger.get(r2).unwrap().classification(), RetentionClassification::ReleasedEligibleForArchive);
    assert!(matches!(ledger.attempt_delete_entry(r1), Err(LedgerRetentionError::ProtectedByHold { .. })));
    assert!(matches!(
        ledger.attempt_delete_entry(r2),
        Err(LedgerRetentionError::CompactionDoesNotAuthorizeDelete { .. })
    ));
    assert!(matches!(
        ledger.record_entry(Uuid::new_v4(), LedgerEntryKind::Registration, Some(Uuid::new_v4()), None, 1024, 3),
        Err(LedgerRetentionError::LedgerBudgetExhausted { resource: "registrations", .. })
    ));
    assert_eq!(ledger.archive_released_entries(), 1);
    assert!(
        ledger.record_entry(Uuid::new_v4(), LedgerEntryKind::Registration, Some(Uuid::new_v4()), None, 1024, 3).is_ok()
    );
    ledger.release_hold(bid).unwrap();
    assert_eq!(ledger.get(r1).unwrap().classification(), RetentionClassification::ReleasedEligibleForArchive);
    assert_eq!(ledger.archive_released_entries(), 2);
    assert_eq!(ledger.resident_entries_len(), 1);
    assert_eq!(ledger.summary().protected_registrations, 1);
    assert_eq!(ledger.summary().archived_registrations, 2);
}

#[test]
fn resident_total_bound_fails_closed_until_released_entries_archived() {
    let mut policy = LedgerBudgetPolicy::from_contract(&PandoCapacityContract::current_standalone());
    policy.repo_max_resident_entries = 2;
    let mut ledger = RetentionLedger::new(policy);
    let p1 = Uuid::new_v4();
    ledger.record_entry(Uuid::new_v4(), LedgerEntryKind::Membership, Some(p1), None, 512, 1).unwrap();
    ledger.record_entry(Uuid::new_v4(), LedgerEntryKind::Receipt, Some(p1), None, 512, 1).unwrap();
    assert!(matches!(
        ledger.record_entry(Uuid::new_v4(), LedgerEntryKind::Receipt, None, None, 512, 2),
        Err(LedgerRetentionError::LedgerBudgetExhausted { resource: "resident_entries", .. })
    ));
    ledger.record_compaction_superseded(2, &BTreeSet::from([p1]));
    assert_eq!(ledger.archive_released_entries(), 2);
    assert_eq!(ledger.resident_entries_len(), 0);
    assert!(ledger.record_entry(Uuid::new_v4(), LedgerEntryKind::Receipt, None, None, 512, 2).is_ok());
}

#[test]
fn hold_metadata_lengths_and_hot_bytes_enforce_bounds_and_reclaim_on_release() {
    let mut policy = LedgerBudgetPolicy::from_contract(&PandoCapacityContract::current_standalone());
    let p1 = Uuid::new_v4();
    policy.max_resident_ref_and_hold_bytes = 260;
    policy.repo_max_logical_bytes = 1200;
    let mut ledger = RetentionLedger::new(policy);
    ledger.record_entry(Uuid::new_v4(), LedgerEntryKind::Membership, Some(p1), None, 512, 1).unwrap();
    ledger.record_entry(Uuid::new_v4(), LedgerEntryKind::Registration, Some(p1), None, 256, 1).unwrap();
    assert_eq!(ledger.resident_hold_bytes(), 32);

    for bad in [
        ProtectionHold::Pin { pin_id: Uuid::new_v4(), purpose: String::new() },
        ProtectionHold::Pin { pin_id: Uuid::new_v4(), purpose: "x".repeat(257) },
        ProtectionHold::RetentionRoot { root_id: Uuid::new_v4(), kind: String::new() },
        ProtectionHold::RetentionRoot { root_id: Uuid::new_v4(), kind: "k".repeat(257) },
    ] {
        assert!(matches!(ledger.attach_hold_to_pack(p1, bad), Err(LedgerRetentionError::InvalidArgument(_))));
    }

    let ok_pin = ProtectionHold::Pin { pin_id: Uuid::new_v4(), purpose: "a".repeat(64) };
    assert_eq!(ok_pin.resident_bytes(), 96);
    assert_eq!(ledger.attach_hold_to_pack(p1, ok_pin.clone()).unwrap(), 2);
    assert_eq!(ledger.resident_hold_bytes(), 32 + 192);
    assert_eq!(ledger.summary().hot_logical_bytes, 512 + 256 + 32 + 192);

    let fail_pin = ProtectionHold::Pin { pin_id: Uuid::new_v4(), purpose: "b".repeat(16) };
    assert!(matches!(
        ledger.attach_hold_to_active_frontier(fail_pin),
        Err(LedgerRetentionError::LedgerBudgetExhausted { resource: "ref_and_hold_bytes", .. })
    ));
    assert_eq!(ledger.resident_hold_bytes(), 32 + 192);

    ledger.release_hold(ok_pin.hold_id()).unwrap();
    assert_eq!(ledger.resident_hold_bytes(), 32);

    let max_ok = ProtectionHold::RetentionRoot { root_id: Uuid::new_v4(), kind: "r".repeat(256) };
    assert_eq!(max_ok.resident_bytes(), 288);
    assert!(matches!(
        ledger.attach_hold_to_pack(p1, max_ok),
        Err(LedgerRetentionError::LedgerBudgetExhausted { resource: "ref_and_hold_bytes", .. })
    ));

    let mut tight_logical = RetentionLedger::new(LedgerBudgetPolicy {
        max_resident_ref_and_hold_bytes: 1024 * 1024,
        repo_max_logical_bytes: 900,
        ..policy
    });
    tight_logical.record_entry(Uuid::new_v4(), LedgerEntryKind::Membership, Some(p1), None, 700, 1).unwrap();
    let logical_pin = ProtectionHold::Pin { pin_id: Uuid::new_v4(), purpose: "p".repeat(160) };
    assert!(matches!(
        tight_logical.attach_hold_to_pack(p1, logical_pin),
        Err(LedgerRetentionError::LedgerBudgetExhausted { resource: "logical_bytes", .. })
    ));
    tight_logical.record_compaction_superseded(2, &BTreeSet::from([p1]));
    assert_eq!(tight_logical.resident_hold_bytes(), 0);
    assert_eq!(tight_logical.archive_released_entries(), 1);
    assert_eq!(tight_logical.summary().hot_logical_bytes, 0);
}
