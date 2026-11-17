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
    archived_checkpoint_digest: String,
}

impl RetentionLedger {
    pub fn new(policy: LedgerBudgetPolicy) -> Self {
        Self { policy, entries: BTreeMap::new(), archived_checkpoint_digest: hex::encode(Sha256::digest(b"empty-v1")) }
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
        let mut attached = 0usize;
        for entry in self.entries.values_mut() {
            if entry.pack_id == Some(pack_id) && !entry.archived {
                entry.holds.insert(key.clone(), hold.clone());
                attached += 1;
            }
        }
        if attached == 0 {
            return Err(LedgerRetentionError::EntryNotFound(pack_id));
        }
        Ok(attached)
    }

    pub fn attach_hold_to_active_frontier(&mut self, hold: ProtectionHold) -> usize {
        let key = format!("{}:{}", hold.label(), hold.hold_id());
        let mut attached = 0usize;
        for entry in self.entries.values_mut() {
            if entry.superseded_at_epoch.is_none() && !entry.archived {
                entry.holds.insert(key.clone(), hold.clone());
                attached += 1;
            }
        }
        attached
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
        for entry in self.entries.values_mut() {
            if entry.classification() == RetentionClassification::ReleasedEligibleForArchive {
                entry.archived = true;
                newly_archived.push((entry.entry_id, entry.logical_bytes));
            }
        }
        if newly_archived.is_empty() {
            return 0;
        }
        let mut hasher = Sha256::new();
        hasher.update(self.archived_checkpoint_digest.as_bytes());
        for (id, bytes) in &newly_archived {
            hasher.update(id.as_bytes());
            hasher.update(&bytes.to_be_bytes());
        }
        self.archived_checkpoint_digest = hex::encode(hasher.finalize());
        newly_archived.len()
    }

    pub fn summary(&self) -> LedgerRetentionSummary {
        let mut out = LedgerRetentionSummary {
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
}
