//! Historical membership, registration, and receipt ledger retention accounting.
//!
//! Explicitly separates released entries from entries still protected by active
//! serving frontiers, pins, retention roots, or backups. Compaction updates the
//! active serving membership frontier without deleting protected ledger history.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::ledger_types::{
    LedgerBudgetPolicy, LedgerEntry, LedgerEntryKind, LedgerRetentionError, LedgerRetentionSummary, ProtectionHold,
    RetentionClassification,
};

#[derive(Debug, Clone)]
pub struct RetentionLedger {
    policy: LedgerBudgetPolicy,
    entries: BTreeMap<Uuid, LedgerEntry>,
    archived_memberships: usize,
    archived_registrations: usize,
    archived_receipts: usize,
    archived_cold_logical_bytes: u64,
    archived_checkpoint_digest: String,
}

impl RetentionLedger {
    pub fn new(policy: LedgerBudgetPolicy) -> Self {
        Self {
            policy,
            entries: BTreeMap::new(),
            archived_memberships: 0,
            archived_registrations: 0,
            archived_receipts: 0,
            archived_cold_logical_bytes: 0,
            archived_checkpoint_digest: hex::encode(Sha256::digest(b"empty-v1")),
        }
    }

    pub fn resident_entries_len(&self) -> usize {
        self.entries.len()
    }

    pub fn total_nested_holds(&self) -> usize {
        self.entries.values().map(|e| e.holds.len()).sum()
    }

    pub fn policy(&self) -> LedgerBudgetPolicy {
        self.policy
    }

    pub fn get(&self, entry_id: Uuid) -> Option<&LedgerEntry> {
        self.entries.get(&entry_id)
    }

    fn hot_counts(&self) -> (usize, usize, usize, u64) {
        let mut active_memberships = 0usize;
        let mut hot_registrations = 0usize;
        let mut hot_receipts = 0usize;
        let mut hot_bytes = 0u64;
        for entry in self.entries.values() {
            if entry.archived {
                continue;
            }
            hot_bytes = hot_bytes.saturating_add(entry.logical_bytes);
            match (entry.kind, entry.superseded_at_epoch) {
                (LedgerEntryKind::Membership, None) => active_memberships += 1,
                (LedgerEntryKind::Registration, _) => hot_registrations += 1,
                (LedgerEntryKind::Receipt, _) => hot_receipts += 1,
                _ => {}
            }
        }
        (active_memberships, hot_registrations, hot_receipts, hot_bytes)
    }

    pub fn check_budget_for(
        &self,
        add_memberships: usize,
        add_regs: usize,
        add_receipts: usize,
        add_bytes: u64,
    ) -> Result<(), LedgerRetentionError> {
        let (act_m, hot_reg, hot_rcpt, hot_b) = self.hot_counts();
        if act_m.saturating_add(add_memberships) > self.policy.repo_max_active_memberships {
            return Err(LedgerRetentionError::LedgerBudgetExhausted {
                resource: "active_memberships",
                current: act_m as u64,
                limit: self.policy.repo_max_active_memberships as u64,
            });
        }
        if hot_reg.saturating_add(add_regs) > self.policy.repo_max_registrations {
            return Err(LedgerRetentionError::LedgerBudgetExhausted {
                resource: "registrations",
                current: hot_reg as u64,
                limit: self.policy.repo_max_registrations as u64,
            });
        }
        if hot_rcpt.saturating_add(add_receipts) > self.policy.repo_max_receipts {
            return Err(LedgerRetentionError::LedgerBudgetExhausted {
                resource: "receipts",
                current: hot_rcpt as u64,
                limit: self.policy.repo_max_receipts as u64,
            });
        }
        let next_b = hot_b.saturating_add(add_bytes);
        if next_b > self.policy.repo_max_logical_bytes {
            return Err(LedgerRetentionError::LedgerBudgetExhausted {
                resource: "logical_bytes",
                current: hot_b,
                limit: self.policy.repo_max_logical_bytes,
            });
        }
        if self.entries.len().saturating_add(1) > self.policy.repo_max_resident_entries {
            return Err(LedgerRetentionError::LedgerBudgetExhausted {
                resource: "resident_entries",
                current: self.entries.len() as u64,
                limit: self.policy.repo_max_resident_entries as u64,
            });
        }
        let nested = self.total_nested_holds();
        if nested.saturating_add(1) > self.policy.repo_max_nested_holds {
            return Err(LedgerRetentionError::LedgerBudgetExhausted {
                resource: "nested_holds",
                current: nested as u64,
                limit: self.policy.repo_max_nested_holds as u64,
            });
        }
        Ok(())
    }

    fn check_hold_addition(&self, hold: &ProtectionHold, add_nested: usize) -> Result<(), LedgerRetentionError> {
        let is_frontier = matches!(hold, ProtectionHold::ActiveServingFrontier { .. });
        if !is_frontier && hold.hold_id().is_nil() {
            return Err(LedgerRetentionError::InvalidArgument("hold_id must be non-nil"));
        }
        if !is_frontier {
            let distinct: BTreeSet<Uuid> = self
                .entries
                .values()
                .flat_map(|e| e.holds.values())
                .filter(|h| !matches!(h, ProtectionHold::ActiveServingFrontier { .. }))
                .map(ProtectionHold::hold_id)
                .collect();
            if !distinct.contains(&hold.hold_id()) && distinct.len() >= self.policy.repo_max_holds {
                return Err(LedgerRetentionError::LedgerBudgetExhausted {
                    resource: "holds",
                    current: distinct.len() as u64,
                    limit: self.policy.repo_max_holds as u64,
                });
            }
        }
        let nested = self.total_nested_holds();
        if nested.saturating_add(add_nested) > self.policy.repo_max_nested_holds {
            return Err(LedgerRetentionError::LedgerBudgetExhausted {
                resource: "nested_holds",
                current: nested as u64,
                limit: self.policy.repo_max_nested_holds as u64,
            });
        }
        Ok(())
    }

    pub fn record_entry(
        &mut self,
        entry_id: Uuid,
        kind: LedgerEntryKind,
        pack_id: Option<Uuid>,
        operation_id: Option<Uuid>,
        logical_bytes: u64,
        epoch: u64,
    ) -> Result<(), LedgerRetentionError> {
        if entry_id.is_nil() || logical_bytes == 0 || epoch == 0 {
            return Err(LedgerRetentionError::InvalidArgument("entry_id, logical_bytes, and epoch must be valid"));
        }
        if self.entries.contains_key(&entry_id) {
            return Err(LedgerRetentionError::DuplicateEntry(entry_id));
        }
        let (add_m, add_reg, add_rcpt) = match kind {
            LedgerEntryKind::Membership => (1, 0, 0),
            LedgerEntryKind::Registration => (0, 1, 0),
            LedgerEntryKind::Receipt => (0, 0, 1),
        };
        self.check_budget_for(add_m, add_reg, add_rcpt, logical_bytes)?;
        let mut holds = BTreeMap::new();
        holds.insert("frontier".to_owned(), ProtectionHold::ActiveServingFrontier { epoch });
        self.entries.insert(
            entry_id,
            LedgerEntry {
                entry_id,
                kind,
                pack_id,
                operation_id,
                logical_bytes,
                created_epoch: epoch,
                superseded_at_epoch: None,
                holds,
                archived: false,
            },
        );
        Ok(())
    }

    pub fn attach_hold_to_pack(&mut self, pack_id: Uuid, hold: ProtectionHold) -> Result<usize, LedgerRetentionError> {
        if pack_id.is_nil() {
            return Err(LedgerRetentionError::InvalidArgument("pack_id must be non-nil"));
        }
        let key = format!("{}:{}", hold.label(), hold.hold_id());
        let (mut total, mut add_nested) = (0usize, 0usize);
        for entry in self.entries.values() {
            if entry.pack_id == Some(pack_id) && !entry.archived {
                total += 1;
                if !entry.holds.contains_key(&key) {
                    add_nested += 1;
                }
            }
        }
        if total == 0 {
            return Err(LedgerRetentionError::EntryNotFound(pack_id));
        }
        self.check_hold_addition(&hold, add_nested)?;
        for entry in self.entries.values_mut() {
            if entry.pack_id == Some(pack_id) && !entry.archived {
                entry.holds.insert(key.clone(), hold.clone());
            }
        }
        Ok(total)
    }

    pub fn attach_hold_to_active_frontier(&mut self, hold: ProtectionHold) -> Result<usize, LedgerRetentionError> {
        let key = format!("{}:{}", hold.label(), hold.hold_id());
        let (mut total, mut add_nested) = (0usize, 0usize);
        for entry in self.entries.values() {
            if entry.superseded_at_epoch.is_none() && !entry.archived {
                total += 1;
                if !entry.holds.contains_key(&key) {
                    add_nested += 1;
                }
            }
        }
        self.check_hold_addition(&hold, add_nested)?;
        for entry in self.entries.values_mut() {
            if entry.superseded_at_epoch.is_none() && !entry.archived {
                entry.holds.insert(key.clone(), hold.clone());
            }
        }
        Ok(total)
    }

    /// Marks superseded pack entries at `compaction_epoch` while retaining
    /// pins, retention roots, and backups without deleting history.
    pub fn record_compaction_superseded(
        &mut self,
        compaction_epoch: u64,
        superseded_pack_ids: &BTreeSet<Uuid>,
    ) -> usize {
        let mut updated = 0usize;
        for entry in self.entries.values_mut() {
            if let Some(pid) = entry.pack_id
                && superseded_pack_ids.contains(&pid)
                && entry.superseded_at_epoch.is_none()
            {
                entry.superseded_at_epoch = Some(compaction_epoch);
                entry.holds.remove("frontier");
                updated += 1;
            }
        }
        updated
    }

    pub fn attempt_delete_entry(&self, entry_id: Uuid) -> Result<(), LedgerRetentionError> {
        let entry = self.entries.get(&entry_id).ok_or(LedgerRetentionError::EntryNotFound(entry_id))?;
        if !entry.holds.is_empty() || entry.superseded_at_epoch.is_none() {
            let holds = entry.holds.values().map(|h| format!("{}:{}", h.label(), h.hold_id())).collect();
            return Err(LedgerRetentionError::ProtectedByHold {
                entry_id,
                classification: entry.classification(),
                holds,
            });
        }
        Err(LedgerRetentionError::CompactionDoesNotAuthorizeDelete { entry_id })
    }

    pub fn release_hold(&mut self, hold_id: Uuid) -> Result<usize, LedgerRetentionError> {
        if hold_id.is_nil() {
            return Err(LedgerRetentionError::InvalidArgument("cannot release nil frontier hold directly"));
        }
        let mut removed = 0usize;
        for entry in self.entries.values_mut() {
            let before = entry.holds.len();
            entry.holds.retain(|_, h| h.hold_id() != hold_id);
            if entry.holds.len() < before {
                removed += 1;
            }
        }
        if removed == 0 {
            return Err(LedgerRetentionError::HoldNotFound(hold_id));
        }
        Ok(removed)
    }

    pub fn archive_released_entries(&mut self) -> usize {
        let mut newly_archived = Vec::new();
        for entry in self.entries.values() {
            if entry.classification() == RetentionClassification::ReleasedEligibleForArchive {
                newly_archived.push((entry.entry_id, entry.kind, entry.logical_bytes));
            }
        }
        if newly_archived.is_empty() {
            return 0;
        }
        let mut hasher = Sha256::new();
        hasher.update(self.archived_checkpoint_digest.as_bytes());
        for (id, kind, bytes) in &newly_archived {
            hasher.update(id.as_bytes());
            hasher.update(bytes.to_be_bytes());
            self.archived_cold_logical_bytes = self.archived_cold_logical_bytes.saturating_add(*bytes);
            match kind {
                LedgerEntryKind::Membership => self.archived_memberships += 1,
                LedgerEntryKind::Registration => self.archived_registrations += 1,
                LedgerEntryKind::Receipt => self.archived_receipts += 1,
            }
            self.entries.remove(id);
        }
        self.archived_checkpoint_digest = hex::encode(hasher.finalize());
        newly_archived.len()
    }

    pub fn summary(&self) -> LedgerRetentionSummary {
        let mut out = LedgerRetentionSummary {
            archived_memberships: self.archived_memberships,
            archived_registrations: self.archived_registrations,
            archived_receipts: self.archived_receipts,
            archived_cold_logical_bytes: self.archived_cold_logical_bytes,
            archived_checkpoint_digest: self.archived_checkpoint_digest.clone(),
            ..Default::default()
        };
        for entry in self.entries.values() {
            let class = entry.classification();
            match (entry.kind, class) {
                (LedgerEntryKind::Membership, RetentionClassification::ActiveProtected) => out.active_memberships += 1,
                (LedgerEntryKind::Membership, RetentionClassification::CompactedProtected) => {
                    out.compacted_protected_memberships += 1;
                }
                (LedgerEntryKind::Membership, RetentionClassification::ReleasedEligibleForArchive) => {
                    out.released_memberships += 1;
                }
                (LedgerEntryKind::Membership, RetentionClassification::ArchivedColdCheckpoint) => {
                    out.archived_memberships += 1;
                }
                (
                    LedgerEntryKind::Registration,
                    RetentionClassification::ActiveProtected | RetentionClassification::CompactedProtected,
                ) => out.protected_registrations += 1,
                (LedgerEntryKind::Registration, RetentionClassification::ReleasedEligibleForArchive) => {
                    out.released_registrations += 1;
                }
                (LedgerEntryKind::Registration, RetentionClassification::ArchivedColdCheckpoint) => {
                    out.archived_registrations += 1;
                }
                (
                    LedgerEntryKind::Receipt,
                    RetentionClassification::ActiveProtected | RetentionClassification::CompactedProtected,
                ) => out.protected_receipts += 1,
                (LedgerEntryKind::Receipt, RetentionClassification::ReleasedEligibleForArchive) => {
                    out.released_receipts += 1;
                }
                (LedgerEntryKind::Receipt, RetentionClassification::ArchivedColdCheckpoint) => {
                    out.archived_receipts += 1;
                }
            }
            match class {
                RetentionClassification::ActiveProtected => {
                    out.active_logical_bytes = out.active_logical_bytes.saturating_add(entry.logical_bytes);
                    out.hot_logical_bytes = out.hot_logical_bytes.saturating_add(entry.logical_bytes);
                }
                RetentionClassification::CompactedProtected => {
                    out.protected_historical_logical_bytes =
                        out.protected_historical_logical_bytes.saturating_add(entry.logical_bytes);
                    out.hot_logical_bytes = out.hot_logical_bytes.saturating_add(entry.logical_bytes);
                }
                RetentionClassification::ReleasedEligibleForArchive => {
                    out.released_logical_bytes = out.released_logical_bytes.saturating_add(entry.logical_bytes);
                    out.hot_logical_bytes = out.hot_logical_bytes.saturating_add(entry.logical_bytes);
                }
                RetentionClassification::ArchivedColdCheckpoint => {
                    out.archived_cold_logical_bytes =
                        out.archived_cold_logical_bytes.saturating_add(entry.logical_bytes);
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blob_store::capacity_contract::limits::PandoCapacityContract;

    #[test]
    fn compaction_preserves_pins_roots_backups_and_blocks_delete() {
        let contract = PandoCapacityContract::current_standalone();
        let mut ledger = RetentionLedger::new(LedgerBudgetPolicy::from_contract(&contract));
        let p1 = Uuid::new_v4();
        let m1 = Uuid::new_v4();
        let r1 = Uuid::new_v4();
        ledger.record_entry(m1, LedgerEntryKind::Membership, Some(p1), None, 512, 1).unwrap();
        ledger.record_entry(r1, LedgerEntryKind::Registration, Some(p1), None, 1024, 1).unwrap();

        let pin_id = Uuid::new_v4();
        let root_id = Uuid::new_v4();
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
            ledger
                .record_entry(Uuid::new_v4(), LedgerEntryKind::Registration, Some(Uuid::new_v4()), None, 1024, 3)
                .is_ok()
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
}
