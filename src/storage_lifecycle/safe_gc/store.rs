//! Crash-recoverable atomic-JSON-journaled authority for Safe GC (#122).

use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    SafeGcError,
    anti_aba::{AntiAbaKeyRegistry, KeyLifecycleState, PhysicalBlobKey},
    domain::{
        AuthorityRecord, BlobLocatorRecord, CompactionPublishResult, DeleteExecutionReport, GcAuditEvent,
        UploadedCompactionPair,
    },
    model::{
        GcMode, GlobalHoldEntry, GroupClosureReceipt, InFlightDecisionRecord, LiveRefRoot, PairedCursorReconciliation,
        ProducerReconciliationEntry, SafeGcObjectFormat,
    },
    proof::{DeletionProof, seal_group_receipt},
    store_barrier::persist_snapshot,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServingPackRecord {
    pub pack_id: Uuid,
    pub group_id: String,
    pub pack_key: PhysicalBlobKey,
    pub idx_key: PhysicalBlobKey,
    pub pack_locator: BlobLocatorRecord,
    pub idx_locator: BlobLocatorRecord,
    pub contained_oids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingDeleteBatch {
    pub batch_id: Uuid,
    pub incarnation_id: Uuid,
    pub incarnation_epoch: u64,
    pub lease_epoch: u64,
    pub proof: DeletionProof,
    pub pending_keys: Vec<String>,
    pub deleted_keys: Vec<String>,
    pub skipped_keys: Vec<String>,
    pub failed_keys: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafeGcRepoSnapshot {
    pub authority: AuthorityRecord,
    pub object_format: SafeGcObjectFormat,
    pub gc_mode: GcMode,
    pub live_refs: Vec<LiveRefRoot>,
    pub active_packs: Vec<ServingPackRecord>,
    pub retired_packs: Vec<ServingPackRecord>,
    pub group_receipts: Vec<GroupClosureReceipt>,
    pub producers: Vec<ProducerReconciliationEntry>,
    pub global_holds: Vec<GlobalHoldEntry>,
    pub in_flight_decisions: Vec<InFlightDecisionRecord>,
    pub paired_cursors: PairedCursorReconciliation,
    pub key_registry: AntiAbaKeyRegistry,
    pub pending_delete: Option<PendingDeleteBatch>,
    pub completed_batches: BTreeMap<Uuid, DeleteExecutionReport>,
    pub audit_log: Vec<GcAuditEvent>,
}

/// Atomic-journaled safe-GC & compaction authority supporting PG and Ref-CAS lanes.
#[derive(Clone, Debug)]
pub struct DurableSafeGcAuthority {
    pub(super) inner: Arc<Mutex<SafeGcRepoSnapshot>>,
    persist_path: Option<PathBuf>,
}

impl DurableSafeGcAuthority {
    pub fn in_memory(initial: SafeGcRepoSnapshot) -> Result<Self, SafeGcError> {
        let mut snap = initial;
        snap.register_initial_keys()?;
        Ok(Self { inner: Arc::new(Mutex::new(snap)), persist_path: None })
    }

    pub fn open_with_journal(
        path: impl Into<PathBuf>,
        initial: Option<SafeGcRepoSnapshot>,
    ) -> Result<Self, SafeGcError> {
        let path = path.into();
        let mut snap = if path.exists() {
            let raw = std::fs::read(&path).map_err(|e| SafeGcError::Io(e.to_string()))?;
            serde_json::from_slice(&raw).map_err(|e| SafeGcError::Serialization(e.to_string()))?
        } else {
            let Some(seed) = initial else {
                return Err(SafeGcError::Io("journal missing and no initial snapshot provided".into()));
            };
            seed
        };
        if !path.exists() {
            snap.register_initial_keys()?;
            persist_snapshot(&path, &snap)?;
        }
        Ok(Self { inner: Arc::new(Mutex::new(snap)), persist_path: Some(path) })
    }

    pub fn snapshot(&self) -> SafeGcRepoSnapshot {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn set_gc_mode(&self, mode: GcMode) -> Result<(), SafeGcError> {
        if let GcMode::ArmedDestructive(ref receipt) = mode {
            receipt.validate()?;
        }
        self.update_persisted(|s| {
            if let GcMode::ArmedDestructive(ref receipt) = mode {
                if receipt.tenant_id != s.authority.tenant_id
                    || receipt.repo_id != s.authority.repo_id
                    || receipt.history_id != s.authority.history_id
                    || receipt.incarnation_id != s.authority.incarnation_id
                    || receipt.incarnation_epoch != s.authority.incarnation_epoch
                {
                    return Err(SafeGcError::ArmingRejected("arm receipt disagrees with live authority"));
                }
            }
            s.gc_mode = mode;
            s.push_audit("set_gc_mode", "updated");
            Ok(())
        })
    }

    pub fn rotate_incarnation(&self) -> Result<u64, SafeGcError> {
        self.update_persisted(|s| {
            let next = s
                .authority
                .incarnation_epoch
                .checked_add(1)
                .ok_or_else(|| SafeGcError::InvalidInput("incarnation epoch overflow".into()))?;
            s.key_registry.advance_incarnation_epoch(next)?;
            s.authority.incarnation_epoch = next;
            s.authority.incarnation_id = Uuid::new_v4();
            s.authority.lease_epoch += 1;
            s.gc_mode = GcMode::DisabledByDefault;
            s.push_audit("rotate_incarnation", &next.to_string());
            Ok(next)
        })
    }

    pub fn register_concurrent_ref(&self, root: LiveRefRoot) -> Result<(), SafeGcError> {
        self.update_persisted(|s| {
            s.authority.live_ref_seq += 1;
            let mut next = root;
            next.version_seq = s.authority.live_ref_seq;
            if let Some(existing) = s.live_refs.iter_mut().find(|r| r.ref_name == next.ref_name) {
                *existing = next.clone();
            } else {
                s.live_refs.push(next.clone());
            }
            s.paired_cursors.pg_applied_seq = s.paired_cursors.pg_applied_seq.max(s.authority.live_ref_seq);
            s.paired_cursors.refcas_applied_index = s.paired_cursors.refcas_applied_index.max(s.authority.live_ref_seq);
            s.push_audit("concurrent_ref", &next.ref_name);
            Ok(())
        })
    }

    pub fn upsert_global_hold(&self, hold: GlobalHoldEntry) -> Result<(), SafeGcError> {
        self.update_persisted(|s| {
            if let Some(slot) = s.global_holds.iter_mut().find(|h| h.hold_id == hold.hold_id) {
                *slot = hold.clone();
            } else {
                s.global_holds.push(hold.clone());
            }
            s.push_audit("upsert_global_hold", &hold.hold_id.to_string());
            Ok(())
        })
    }

    pub fn set_producers_and_cursors(
        &self,
        producers: Vec<ProducerReconciliationEntry>,
        cursors: PairedCursorReconciliation,
    ) -> Result<(), SafeGcError> {
        self.update_persisted(|s| {
            s.producers = producers;
            s.paired_cursors = cursors;
            s.push_audit("reconcile_sources", "updated");
            Ok(())
        })
    }

    pub fn mint_compaction_keys(
        &self,
        expected_incarnation_epoch: u64,
        pack_sha256: &str,
        idx_sha256: &str,
    ) -> Result<(PhysicalBlobKey, PhysicalBlobKey), SafeGcError> {
        self.update_persisted(|s| {
            if s.authority.incarnation_epoch != expected_incarnation_epoch {
                return Err(SafeGcError::StaleIncarnation("compaction epoch stale"));
            }
            let (t, r, h, inc) =
                (s.authority.tenant_id, s.authority.repo_id, s.authority.history_id, s.authority.incarnation_epoch);
            let pk = s.key_registry.mint_immutable_key(
                t,
                r,
                h,
                inc,
                "pack",
                pack_sha256,
                KeyLifecycleState::CompactionStaging,
            )?;
            let ik = s.key_registry.mint_immutable_key(
                t,
                r,
                h,
                inc,
                "idx",
                idx_sha256,
                KeyLifecycleState::CompactionStaging,
            )?;
            Ok((pk, ik))
        })
    }

    pub fn assert_late_put_allowed(&self, key_path: &str, writer_epoch: u64) -> Result<(), SafeGcError> {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.key_registry.assert_late_put_allowed(key_path, writer_epoch)
    }

    pub fn cas_publish_compaction(
        &self,
        op_id: Uuid,
        group_id: &str,
        expected_incarnation_id: Uuid,
        expected_incarnation_epoch: u64,
        expected_generation: u64,
        retired_pack_ids: &[Uuid],
        uploaded: UploadedCompactionPair,
        replacement_oids: Vec<String>,
        equivalence_digest: String,
    ) -> Result<CompactionPublishResult, SafeGcError> {
        self.update_persisted(|s| {
            if s.authority.incarnation_id != expected_incarnation_id
                || s.authority.incarnation_epoch != expected_incarnation_epoch
            {
                return Err(SafeGcError::StaleIncarnation("compaction publish incarnation mismatch"));
            }
            if s.authority.membership_generation != expected_generation {
                return Err(SafeGcError::MembershipOrRootDrift(
                    "membership generation advanced during compaction".into(),
                ));
            }
            let retire_set: BTreeSet<Uuid> = retired_pack_ids.iter().copied().collect();
            if retire_set.is_empty() || !retire_set.iter().all(|id| s.active_packs.iter().any(|p| &p.pack_id == id)) {
                return Err(SafeGcError::MembershipOrRootDrift(
                    "retired input pack missing from active closure".into(),
                ));
            }
            s.key_registry.transition_state(
                &uploaded.pack_key.object_path,
                KeyLifecycleState::CompactionStaging,
                KeyLifecycleState::ActiveServing,
            )?;
            s.key_registry.transition_state(
                &uploaded.idx_key.object_path,
                KeyLifecycleState::CompactionStaging,
                KeyLifecycleState::ActiveServing,
            )?;

            let mut remaining_active = Vec::with_capacity(s.active_packs.len());
            let mut moved = Vec::new();
            for item in s.active_packs.drain(..) {
                if retire_set.contains(&item.pack_id) {
                    s.key_registry.transition_state(
                        &item.pack_key.object_path,
                        KeyLifecycleState::ActiveServing,
                        KeyLifecycleState::RetiredPendingProof,
                    )?;
                    s.key_registry.transition_state(
                        &item.idx_key.object_path,
                        KeyLifecycleState::ActiveServing,
                        KeyLifecycleState::RetiredPendingProof,
                    )?;
                    moved.push(item);
                } else {
                    remaining_active.push(item);
                }
            }
            s.active_packs = remaining_active;
            s.retired_packs.extend(moved);

            let new_pack_id = Uuid::new_v4();
            let replacement_record = ServingPackRecord {
                pack_id: new_pack_id,
                group_id: group_id.to_owned(),
                pack_key: uploaded.pack_key.clone(),
                idx_key: uploaded.idx_key.clone(),
                pack_locator: uploaded.pack_locator.clone(),
                idx_locator: uploaded.idx_locator.clone(),
                contained_oids: replacement_oids,
            };
            s.active_packs.push(replacement_record);
            s.authority.membership_generation += 1;

            let receipt = seal_group_receipt(GroupClosureReceipt {
                group_id: group_id.to_owned(),
                epoch: s.authority.incarnation_epoch,
                retired_pack_ids: retired_pack_ids.to_vec(),
                replacement_pack_ids: vec![new_pack_id],
                replacement_closure_verified: true,
                quiesced: true,
                receipt_digest: String::new(),
            })?;
            s.group_receipts.push(receipt);
            s.push_audit("cas_publish_compaction", &new_pack_id.to_string());

            Ok(CompactionPublishResult {
                op_id,
                new_pack_id,
                new_membership_generation: s.authority.membership_generation,
                retired_pack_ids: retired_pack_ids.to_vec(),
                replacement_pack: uploaded.pack_locator,
                replacement_idx: uploaded.idx_locator,
                pack_key_path: uploaded.pack_key.object_path,
                equivalence_digest,
                prior_closure_retained: true,
            })
        })
    }

    pub(super) fn update_persisted<F, T>(&self, mut f: F) -> Result<T, SafeGcError>
    where
        F: FnMut(&mut SafeGcRepoSnapshot) -> Result<T, SafeGcError>,
    {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut candidate = guard.clone();
        let out = f(&mut candidate)?;
        if let Some(ref path) = self.persist_path {
            persist_snapshot(path, &candidate)?;
        }
        *guard = candidate;
        Ok(out)
    }
}
