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
        AuthorityRecord, BlobLocatorRecord, CasCompactionPublish, CompactionPublishResult, DeleteExecutionReport,
        GcAuditEvent, StagedCompactionUpload, StagedUploadState, UploadedCompactionPair,
    },
    model::{
        DecisionState, GcMode, GlobalHoldEntry, GlobalHoldState, GroupClosureReceipt, InFlightDecisionRecord,
        LiveRefRoot, PairedCursorReconciliation, ProducerReconciliationEntry, SafeGcObjectFormat,
    },
    proof::{DeletionProof, seal_group_receipt},
    proof_digest::compute_membership_digest,
    quiescence::{ActiveReaderLease, ReaderLeaseRegistry},
    store_barrier::persist_snapshot,
    store_reconcile::ReconciledSourceTracker,
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
    pub active_step_fence: Option<(Uuid, String)>,
    pub pending_keys: Vec<String>,
    pub deleted_keys: Vec<String>,
    pub already_absent_keys: Vec<String>,
    pub unknown_keys: Vec<String>,
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
    #[serde(default)]
    pub reader_leases: ReaderLeaseRegistry,
    #[serde(default)]
    pub staged_uploads: Vec<StagedCompactionUpload>,
    pub key_registry: AntiAbaKeyRegistry,
    pub pending_delete: Option<PendingDeleteBatch>,
    pub completed_batches: BTreeMap<Uuid, DeleteExecutionReport>,
    #[serde(default)]
    pub aborted_batches: BTreeMap<Uuid, DeleteExecutionReport>,
    #[serde(default)]
    pub reconciled_sources: ReconciledSourceTracker,
    pub audit_log: Vec<GcAuditEvent>,
}

impl SafeGcRepoSnapshot {
    pub fn compute_membership_digest(&self) -> String {
        compute_membership_digest(self.authority.membership_generation, &self.active_packs)
    }

    pub fn directly_pinned_pack_ids(&self) -> BTreeSet<Uuid> {
        let mut pinned = self.reader_leases.pinned_pack_ids();
        for p in &self.producers {
            pinned.extend(p.pinned_pack_ids.iter().copied());
        }
        let mut pinned_keys = BTreeSet::new();
        for h in &self.global_holds {
            if matches!(h.state, GlobalHoldState::Active | GlobalHoldState::Unknown) {
                pinned.extend(h.protected_pack_ids.iter().copied());
                pinned_keys.extend(h.protected_physical_keys.iter().map(String::as_str));
            }
        }
        for d in &self.in_flight_decisions {
            if matches!(d.state, DecisionState::Pending | DecisionState::Unknown) {
                pinned.extend(d.protected_pack_ids.iter().copied());
                if d.state == DecisionState::Pending && d.protected_pack_ids.is_empty() && d.protected_oids.is_empty() {
                    pinned.extend(self.active_packs.iter().map(|p| p.pack_id));
                    pinned.extend(self.retired_packs.iter().map(|p| p.pack_id));
                }
            }
        }
        if !pinned_keys.is_empty() {
            for rec in self.active_packs.iter().chain(self.retired_packs.iter()) {
                if pinned_keys.contains(rec.pack_key.object_path.as_str())
                    || pinned_keys.contains(rec.idx_key.object_path.as_str())
                {
                    pinned.insert(rec.pack_id);
                }
            }
        }
        pinned
    }
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
        let existed = path.exists();
        let mut snap = if existed {
            let raw = std::fs::read(&path).map_err(|e| SafeGcError::Io(e.to_string()))?;
            serde_json::from_slice(&raw).map_err(|e| SafeGcError::Serialization(e.to_string()))?
        } else {
            let Some(seed) = initial else {
                return Err(SafeGcError::Io("journal missing and no initial snapshot provided".into()));
            };
            seed
        };
        if existed {
            // A newly opened process handle does NOT hold the previous process's live
            // PostgreSQL `gc_epoch` fence, so the historical barrier epoch is cleared
            // in memory until a caller acquires a fresh live fence and rebinds.
            snap.reader_leases.set_pg_exclusive_barrier_epoch(None);
        } else {
            snap.register_initial_keys()?;
            persist_snapshot(&path, &snap)?;
        }
        Ok(Self { inner: Arc::new(Mutex::new(snap)), persist_path: Some(path) })
    }

    pub fn snapshot(&self) -> SafeGcRepoSnapshot {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    pub fn acquire_reader_lease(
        &self,
        reader_label: &str,
        pinned_pack_ids: Vec<Uuid>,
    ) -> Result<ActiveReaderLease, SafeGcError> {
        self.update_persisted(|s| {
            let cur_gen = s.authority.membership_generation;
            let lease = s.reader_leases.acquire_lease(reader_label, cur_gen, pinned_pack_ids)?;
            s.push_audit("acquire_reader_lease", &lease.lease_id.to_string());
            Ok(lease)
        })
    }

    pub fn release_reader_lease(&self, lease_id: Uuid) -> Result<bool, SafeGcError> {
        self.update_persisted(|s| {
            let cur_gen = s.authority.membership_generation;
            let removed = s.reader_leases.release_lease(lease_id, cur_gen)?;
            s.refresh_group_receipts_quiescence()?;
            s.push_audit("release_reader_lease", &lease_id.to_string());
            Ok(removed)
        })
    }

    pub fn set_pg_reader_barrier_epoch(&self, epoch: Option<u64>) -> Result<(), SafeGcError> {
        self.update_persisted(|s| {
            s.reader_leases.set_pg_exclusive_barrier_epoch(epoch);
            s.reader_leases.refresh_drain_watermark(s.authority.membership_generation);
            s.refresh_group_receipts_quiescence()?;
            Ok(())
        })
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
                if receipt.arm_pubkey_hex != s.authority.trusted_arm_pubkey_hex {
                    return Err(SafeGcError::ArmingRejected(
                        "arm receipt Ed25519 public key not trusted by repository authority",
                    ));
                }
                if let super::model::AuthorityLane::SingleNodePg { reader_barrier_epoch, .. } = &receipt.lane {
                    s.reader_leases.set_pg_exclusive_barrier_epoch(Some(*reader_barrier_epoch));
                    s.refresh_group_receipts_quiescence()?;
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

    pub fn bump_lease_epoch(&self) -> Result<u64, SafeGcError> {
        self.update_persisted(|s| {
            s.authority.lease_epoch += 1;
            s.push_audit("bump_lease_epoch", &s.authority.lease_epoch.to_string());
            Ok(s.authority.lease_epoch)
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

    pub fn set_in_flight_decisions(&self, decisions: Vec<InFlightDecisionRecord>) -> Result<(), SafeGcError> {
        self.update_persisted(|s| {
            s.in_flight_decisions = decisions;
            s.push_audit("set_in_flight_decisions", "updated");
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
            let scope =
                (s.authority.tenant_id, s.authority.repo_id, s.authority.history_id, s.authority.incarnation_epoch);
            let pk =
                s.key_registry.mint_immutable_key(scope, "pack", pack_sha256, KeyLifecycleState::CompactionStaging)?;
            let ik =
                s.key_registry.mint_immutable_key(scope, "idx", idx_sha256, KeyLifecycleState::CompactionStaging)?;
            Ok((pk, ik))
        })
    }

    pub fn record_staged_upload(&self, op_id: Uuid, uploaded: &UploadedCompactionPair) -> Result<(), SafeGcError> {
        self.update_persisted(|s| {
            s.staged_uploads.retain(|u| u.op_id != op_id);
            s.staged_uploads.push(StagedCompactionUpload {
                op_id,
                incarnation_epoch: s.authority.incarnation_epoch,
                pack_key: uploaded.pack_key.clone(),
                idx_key: uploaded.idx_key.clone(),
                pack_locator: uploaded.pack_locator.clone(),
                idx_locator: uploaded.idx_locator.clone(),
                state: StagedUploadState::Uploading,
            });
            Ok(())
        })
    }

    pub fn mark_staged_upload_abandoned(&self, op_id: Uuid) -> Result<(), SafeGcError> {
        self.update_persisted(|s| {
            if let Some(entry) = s.staged_uploads.iter_mut().find(|u| u.op_id == op_id)
                && entry.state == StagedUploadState::Uploading
            {
                entry.state = StagedUploadState::AbandonedPendingCleanup;
            }
            Ok(())
        })
    }

    pub fn assert_late_put_allowed(&self, key_path: &str, writer_epoch: u64) -> Result<(), SafeGcError> {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.key_registry.assert_late_put_allowed(key_path, writer_epoch)
    }

    pub fn cas_publish_compaction(&self, req: CasCompactionPublish) -> Result<CompactionPublishResult, SafeGcError> {
        self.update_persisted(|s| {
            if s.authority.incarnation_id != req.expected_incarnation_id
                || s.authority.incarnation_epoch != req.expected_incarnation_epoch
            {
                return Err(SafeGcError::StaleIncarnation("compaction publish incarnation mismatch"));
            }
            if s.authority.membership_generation != req.expected_generation
                || s.compute_membership_digest() != req.expected_membership_digest
            {
                return Err(SafeGcError::MembershipOrRootDrift("membership generation/digest drifted".into()));
            }
            let pinned_now = s.directly_pinned_pack_ids();
            let retire_set: BTreeSet<Uuid> = req.retired_pack_ids.iter().copied().collect();
            if retire_set.iter().any(|id| pinned_now.contains(id)) {
                return Err(SafeGcError::ProtectionOverlap("input pack newly pinned before CAS".into()));
            }
            if retire_set.is_empty() || !retire_set.iter().all(|id| s.active_packs.iter().any(|p| &p.pack_id == id)) {
                return Err(SafeGcError::MembershipOrRootDrift(
                    "retired input pack missing from active closure".into(),
                ));
            }
            for path in [&req.uploaded.pack_key.object_path, &req.uploaded.idx_key.object_path] {
                s.key_registry.transition_state(
                    path,
                    KeyLifecycleState::CompactionStaging,
                    KeyLifecycleState::ActiveServing,
                )?;
            }
            s.staged_uploads.retain(|u| u.op_id != req.op_id);

            let (mut remaining_active, mut moved) = (Vec::with_capacity(s.active_packs.len()), Vec::new());
            for item in s.active_packs.drain(..) {
                if retire_set.contains(&item.pack_id) {
                    for path in [&item.pack_key.object_path, &item.idx_key.object_path] {
                        s.key_registry.transition_state(
                            path,
                            KeyLifecycleState::ActiveServing,
                            KeyLifecycleState::RetiredPendingProof,
                        )?;
                    }
                    moved.push(item);
                } else {
                    remaining_active.push(item);
                }
            }
            s.active_packs = remaining_active;
            s.retired_packs.extend(moved);

            let new_pack_id = Uuid::new_v4();
            let rep_oids = req.replacement_oids;
            s.active_packs.push(ServingPackRecord {
                pack_id: new_pack_id,
                group_id: req.group_id.clone(),
                pack_key: req.uploaded.pack_key.clone(),
                idx_key: req.uploaded.idx_key.clone(),
                pack_locator: req.uploaded.pack_locator.clone(),
                idx_locator: req.uploaded.idx_locator.clone(),
                contained_oids: rep_oids.clone(),
            });
            s.authority.membership_generation += 1;
            let new_gen = s.authority.membership_generation;
            let rq = s.reader_leases.observe_for_retirement(&req.retired_pack_ids, new_gen, new_gen)?;
            let receipt = seal_group_receipt(GroupClosureReceipt {
                group_id: req.group_id,
                epoch: s.authority.incarnation_epoch,
                retired_at_generation: new_gen,
                retired_pack_ids: req.retired_pack_ids.clone(),
                replacement_pack_ids: vec![new_pack_id],
                replacement_oids: rep_oids,
                replacement_closure_verified: true,
                reader_quiescence: rq,
                receipt_digest: String::new(),
            })?;
            s.group_receipts.push(receipt);
            let new_digest = s.compute_membership_digest();
            s.push_audit("cas_publish_compaction", &new_pack_id.to_string());

            Ok(CompactionPublishResult {
                op_id: req.op_id,
                new_pack_id,
                new_membership_generation: new_gen,
                new_membership_digest: new_digest,
                retired_pack_ids: req.retired_pack_ids,
                replacement_pack: req.uploaded.pack_locator,
                replacement_idx: req.uploaded.idx_locator,
                pack_key_path: req.uploaded.pack_key.object_path,
                equivalence_digest: req.equivalence_digest,
                prior_closure_retained: true,
            })
        })
    }

    pub(super) fn update_persisted<F, T>(&self, f: F) -> Result<T, SafeGcError>
    where
        F: FnOnce(&mut SafeGcRepoSnapshot) -> Result<T, SafeGcError>,
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
