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
        self.entries.values().filter(|e| !e.archived).map(|e| e.holds.len()).sum()
    }

    pub fn resident_hold_bytes(&self) -> u64 {
        self.entries.values().filter(|e| !e.archived).map(entry_hold_bytes).fold(0u64, u64::saturating_add)
    }

    pub fn policy(&self) -> LedgerBudgetPolicy {
        self.policy
    }

    pub fn get(&self, entry_id: Uuid) -> Option<&LedgerEntry> {
        self.entries.get(&entry_id)
    }

    fn hot_counts(&self) -> (usize, usize, usize, u64, u64) {
        let mut active_memberships = 0usize;
        let mut hot_registrations = 0usize;
        let mut hot_receipts = 0usize;
        let mut hot_entry_bytes = 0u64;
        let mut hot_hold_bytes = 0u64;
        for entry in self.entries.values() {
            if entry.archived {
                continue;
            }
            hot_entry_bytes = hot_entry_bytes.saturating_add(entry.logical_bytes);
            hot_hold_bytes = hot_hold_bytes.saturating_add(entry_hold_bytes(entry));
            match (entry.kind, entry.superseded_at_epoch) {
                (LedgerEntryKind::Membership, None) => active_memberships += 1,
                (LedgerEntryKind::Registration, _) => hot_registrations += 1,
                (LedgerEntryKind::Receipt, _) => hot_receipts += 1,
                _ => {}
            }
        }
        (active_memberships, hot_registrations, hot_receipts, hot_entry_bytes, hot_hold_bytes)
    }

    pub fn check_budget_for(
        &self,
        add_memberships: usize,
        add_regs: usize,
        add_receipts: usize,
        add_bytes: u64,
        add_hold_bytes: u64,
    ) -> Result<(), LedgerRetentionError> {
        let (act_m, hot_reg, hot_rcpt, hot_b, hot_hold_b) = self.hot_counts();
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
        let cur_total_b = hot_b.saturating_add(hot_hold_b);
        if cur_total_b.saturating_add(add_bytes).saturating_add(add_hold_bytes) > self.policy.repo_max_logical_bytes {
            return Err(LedgerRetentionError::LedgerBudgetExhausted {
                resource: "logical_bytes",
                current: cur_total_b,
                limit: self.policy.repo_max_logical_bytes,
            });
        }
        if hot_hold_b.saturating_add(add_hold_bytes) > self.policy.max_resident_ref_and_hold_bytes {
            return Err(LedgerRetentionError::LedgerBudgetExhausted {
                resource: "ref_and_hold_bytes",
                current: hot_hold_b,
                limit: self.policy.max_resident_ref_and_hold_bytes,
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
        hold.validate()?;
        let is_frontier = matches!(hold, ProtectionHold::ActiveServingFrontier { .. });
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
        let add_hold_bytes = (add_nested as u64).saturating_mul(hold.resident_bytes());
        let (_, _, _, hot_b, hot_hold_b) = self.hot_counts();
        if hot_hold_b.saturating_add(add_hold_bytes) > self.policy.max_resident_ref_and_hold_bytes {
            return Err(LedgerRetentionError::LedgerBudgetExhausted {
                resource: "ref_and_hold_bytes",
                current: hot_hold_b,
                limit: self.policy.max_resident_ref_and_hold_bytes,
            });
        }
        let cur_total_b = hot_b.saturating_add(hot_hold_b);
        if cur_total_b.saturating_add(add_hold_bytes) > self.policy.repo_max_logical_bytes {
            return Err(LedgerRetentionError::LedgerBudgetExhausted {
                resource: "logical_bytes",
                current: cur_total_b,
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
        let frontier_hold = ProtectionHold::ActiveServingFrontier { epoch };
        self.check_budget_for(add_m, add_reg, add_rcpt, logical_bytes, frontier_hold.resident_bytes())?;
        let mut holds = BTreeMap::new();
        holds.insert("frontier".to_owned(), frontier_hold);
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
            let total_b = entry.logical_bytes.saturating_add(entry_hold_bytes(entry));
            match class {
                RetentionClassification::ActiveProtected => {
                    out.active_logical_bytes = out.active_logical_bytes.saturating_add(total_b);
                    out.hot_logical_bytes = out.hot_logical_bytes.saturating_add(total_b);
                }
                RetentionClassification::CompactedProtected => {
                    out.protected_historical_logical_bytes =
                        out.protected_historical_logical_bytes.saturating_add(total_b);
                    out.hot_logical_bytes = out.hot_logical_bytes.saturating_add(total_b);
                }
                RetentionClassification::ReleasedEligibleForArchive => {
                    out.released_logical_bytes = out.released_logical_bytes.saturating_add(total_b);
                    out.hot_logical_bytes = out.hot_logical_bytes.saturating_add(total_b);
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

fn entry_hold_bytes(entry: &LedgerEntry) -> u64 {
    entry.holds.values().map(ProtectionHold::resident_bytes).fold(0u64, u64::saturating_add)
}
