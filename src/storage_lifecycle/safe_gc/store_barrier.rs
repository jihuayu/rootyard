//! Delete batch state transitions, step-ticket minting & persistence (#122).

use std::{collections::BTreeSet, path::Path};

use uuid::Uuid;

use crate::ref_store::ref_version::pack_cover::PackRetentionState;

use super::{
    SafeGcError,
    anti_aba::KeyLifecycleState,
    domain::{DeleteAuthorizationTicket, DeleteExecutionReport, StagedUploadState, TicketMintSpec},
    model::{CandidatePackTarget, SafeGcArmReceipt},
    proof::{DeletionProof, DeletionProofInputs, build_and_verify_deletion_proof, verify_deletion_proof},
    store::{DurableSafeGcAuthority, PendingDeleteBatch, SafeGcRepoSnapshot, ServingPackRecord},
};

impl DurableSafeGcAuthority {
    pub fn build_authoritative_deletion_proof(
        &self,
        arm_receipt: SafeGcArmReceipt,
        target_pack_ids: &[Uuid],
    ) -> Result<DeletionProof, SafeGcError> {
        let snap = self.update_persisted(|s| {
            if let super::model::AuthorityLane::SingleNodePg { reader_barrier_epoch, .. } = arm_receipt.lane {
                s.reader_leases.set_pg_exclusive_barrier_epoch(Some(reader_barrier_epoch));
            }
            s.reader_leases.refresh_drain_watermark(s.authority.membership_generation);
            s.refresh_group_receipts_quiescence()?;
            Ok(s.clone())
        })?;
        let selected: Vec<&ServingPackRecord> = if target_pack_ids.is_empty() {
            snap.retired_packs.iter().collect()
        } else {
            snap.retired_packs.iter().filter(|r| target_pack_ids.contains(&r.pack_id)).collect()
        };
        let mut candidates = Vec::with_capacity(selected.len() * 2);
        let mut pack_ids_for_quiescence = Vec::with_capacity(selected.len());
        for rec in &selected {
            pack_ids_for_quiescence.push(rec.pack_id);
            for (role, key, loc) in
                [("pack", &rec.pack_key, &rec.pack_locator), ("idx", &rec.idx_key, &rec.idx_locator)]
            {
                if snap.key_registry.deleted_tombstones.contains(&key.object_path) {
                    continue;
                }
                candidates.push(CandidatePackTarget {
                    pack_id: rec.pack_id,
                    key_role: role.to_owned(),
                    group_id: rec.group_id.clone(),
                    physical_key: key.object_path.clone(),
                    object_sha256: key.object_sha256.clone(),
                    remote_etag: loc.remote_etag.clone(),
                    remote_version_id: loc.remote_version_id.clone(),
                    provider_generation: loc.generation,
                    key_epoch: key.incarnation_epoch,
                    retention_state: PackRetentionState::GcEligible,
                    contained_oids: rec.contained_oids.clone(),
                });
            }
        }
        let mut reg_clone = snap.reader_leases.clone();
        let reader_quiescence = reg_clone.observe_for_retirement(
            &pack_ids_for_quiescence,
            snap.authority.membership_generation,
            snap.authority.membership_generation,
        )?;
        build_and_verify_deletion_proof(DeletionProofInputs {
            tenant_id: snap.authority.tenant_id,
            repo_id: snap.authority.repo_id,
            history_id: snap.authority.history_id,
            object_format: snap.object_format,
            incarnation_id: snap.authority.incarnation_id,
            incarnation_epoch: snap.authority.incarnation_epoch,
            membership_generation: snap.authority.membership_generation,
            membership_digest: snap.compute_membership_digest(),
            live_ref_seq: snap.authority.live_ref_seq,
            arm_receipt,
            reader_quiescence,
            live_refs: snap.live_refs,
            producers: snap.producers,
            global_holds: snap.global_holds,
            in_flight_decisions: snap.in_flight_decisions,
            paired_cursors: snap.paired_cursors,
            group_receipts: snap.group_receipts,
            candidates,
        })
    }

    pub fn begin_delete_batch(
        &self,
        batch_id: Uuid,
        deleter_incarnation_id: Uuid,
        deleter_incarnation_epoch: u64,
        deleter_lease_epoch: u64,
        proof: DeletionProof,
    ) -> Result<PendingDeleteBatch, SafeGcError> {
        verify_deletion_proof(&proof)?;
        self.update_persisted(|s| {
            if s.pending_delete.is_some() {
                return Err(SafeGcError::ConcurrentRetentionRace(
                    "unfinished pending delete batch must be reconciled before starting a new batch",
                ));
            }
            s.require_live_barrier(deleter_incarnation_id, deleter_incarnation_epoch, deleter_lease_epoch, &proof)?;
            let mut keys = Vec::with_capacity(proof.candidates.len());
            for cand in &proof.candidates {
                s.key_registry.assert_delete_allowed(&cand.physical_key, deleter_incarnation_epoch)?;
                let st = s.key_registry.keys_by_path.get(&cand.physical_key).map(|k| k.state);
                if st == Some(KeyLifecycleState::RetiredPendingProof) {
                    s.key_registry.transition_state(
                        &cand.physical_key,
                        KeyLifecycleState::RetiredPendingProof,
                        KeyLifecycleState::DeletePendingBarrier,
                    )?;
                }
                keys.push(cand.physical_key.clone());
            }
            let batch = PendingDeleteBatch {
                batch_id,
                incarnation_id: deleter_incarnation_id,
                incarnation_epoch: deleter_incarnation_epoch,
                lease_epoch: deleter_lease_epoch,
                proof,
                active_step_fence: None,
                pending_keys: keys,
                deleted_keys: Vec::new(),
                already_absent_keys: Vec::new(),
                unknown_keys: Vec::new(),
                skipped_keys: Vec::new(),
                failed_keys: Vec::new(),
            };
            s.pending_delete = Some(batch.clone());
            s.push_audit("begin_delete_batch", &batch_id.to_string());
            Ok(batch)
        })
    }

    pub fn mint_fenced_step_ticket(
        &self,
        batch_id: Uuid,
        deleter_incarnation_id: Uuid,
        deleter_incarnation_epoch: u64,
        deleter_lease_epoch: u64,
        physical_key: &str,
    ) -> Result<Option<DeleteAuthorizationTicket>, SafeGcError> {
        self.update_persisted(|s| {
            let Some(batch_ref) = s.pending_delete.as_ref().filter(|b| b.batch_id == batch_id) else {
                return Err(SafeGcError::StaleDeleterFenced("pending delete batch absent or completed"));
            };
            let proof_clone = batch_ref.proof.clone();
            s.require_live_barrier(
                deleter_incarnation_id,
                deleter_incarnation_epoch,
                deleter_lease_epoch,
                &proof_clone,
            )?;
            if s.key_registry.deleted_tombstones.contains(physical_key) {
                return Ok(None);
            }
            s.key_registry.assert_delete_allowed(physical_key, deleter_incarnation_epoch)?;
            let cand = proof_clone
                .candidates
                .iter()
                .find(|c| c.physical_key == physical_key)
                .ok_or_else(|| SafeGcError::InvalidInput("physical key not part of batch proof".into()))?
                .clone();
            let locator = s
                .retired_packs
                .iter()
                .find(|p| p.pack_id == cand.pack_id)
                .and_then(|p| match cand.key_role.as_str() {
                    "pack" if p.pack_key.object_path == physical_key => Some(p.pack_locator.clone()),
                    "idx" if p.idx_key.object_path == physical_key => Some(p.idx_locator.clone()),
                    _ => None,
                })
                .ok_or_else(|| {
                    SafeGcError::InvalidInput("authoritative retired pack locator missing for step ticket".into())
                })?;
            let step_fence_id = Uuid::new_v4();
            let membership_digest = s.compute_membership_digest();
            let membership_generation = s.authority.membership_generation;
            if let Some(batch_mut) = s.pending_delete.as_mut() {
                batch_mut.active_step_fence = Some((step_fence_id, physical_key.to_owned()));
            }
            Ok(Some(DeleteAuthorizationTicket::mint(TicketMintSpec {
                batch_id,
                step_fence_id,
                incarnation_id: deleter_incarnation_id,
                incarnation_epoch: deleter_incarnation_epoch,
                lease_epoch: deleter_lease_epoch,
                membership_generation,
                membership_digest,
                proof_digest: proof_clone.proof_digest,
                pack_id: cand.pack_id,
                key_role: cand.key_role,
                physical_key: cand.physical_key,
                object_sha256: cand.object_sha256,
                locator,
                staging_cleanup_only: false,
            })))
        })
    }

    pub fn record_key_deleted(
        &self,
        batch_id: Uuid,
        physical_key: &str,
        already_absent: bool,
    ) -> Result<(), SafeGcError> {
        self.update_persisted(|s| {
            let _arm = s.gc_mode.require_armed()?;
            let Some(batch_chk) = s.pending_delete.as_ref().filter(|b| b.batch_id == batch_id) else {
                return Err(SafeGcError::StaleDeleterFenced("pending delete batch missing on post-delete commit"));
            };
            if batch_chk.incarnation_id != s.authority.incarnation_id
                || batch_chk.incarnation_epoch != s.authority.incarnation_epoch
                || batch_chk.lease_epoch != s.authority.lease_epoch
            {
                return Err(SafeGcError::StaleDeleterFenced("epoch or lease drifted before post-delete commit"));
            }
            if !s.key_registry.deleted_tombstones.contains(physical_key) {
                s.key_registry.transition_state(
                    physical_key,
                    KeyLifecycleState::DeletePendingBarrier,
                    KeyLifecycleState::PhysicallyDeletedTombstone,
                )?;
            }
            s.retired_packs.retain(|p| {
                !(s.key_registry.deleted_tombstones.contains(&p.pack_key.object_path)
                    && s.key_registry.deleted_tombstones.contains(&p.idx_key.object_path))
            });
            if let Some(batch) = s.pending_delete.as_mut().filter(|b| b.batch_id == batch_id) {
                batch.active_step_fence = None;
                batch.pending_keys.retain(|k| k != physical_key);
                batch.unknown_keys.retain(|k| k != physical_key);
                let bucket = if already_absent { &mut batch.already_absent_keys } else { &mut batch.deleted_keys };
                if !bucket.iter().any(|k| k == physical_key) {
                    bucket.push(physical_key.to_owned());
                }
            }
            s.push_audit(if already_absent { "delete_already_absent" } else { "delete_confirmed" }, physical_key);
            Ok(())
        })
    }

    pub fn record_key_outcome_unknown(
        &self,
        batch_id: Uuid,
        physical_key: &str,
        reason: &str,
    ) -> Result<(), SafeGcError> {
        self.update_persisted(|s| {
            let _arm = s.gc_mode.require_armed()?;
            if let Some(batch) = s.pending_delete.as_mut().filter(|b| b.batch_id == batch_id) {
                if batch.incarnation_id != s.authority.incarnation_id
                    || batch.incarnation_epoch != s.authority.incarnation_epoch
                    || batch.lease_epoch != s.authority.lease_epoch
                {
                    return Err(SafeGcError::StaleDeleterFenced("epoch or lease drifted on unknown outcome record"));
                }
                batch.active_step_fence = None;
                if !batch.unknown_keys.iter().any(|k| k == physical_key) {
                    batch.unknown_keys.push(physical_key.to_owned());
                }
            }
            s.push_audit("delete_outcome_unknown", &format!("{physical_key}: {reason}"));
            Ok(())
        })
    }

    pub fn abort_stale_pending_batch(
        &self,
        batch_id: Uuid,
        confirmed_absent_keys: &[String],
    ) -> Result<DeleteExecutionReport, SafeGcError> {
        self.update_persisted(|s| {
            let batch = s
                .pending_delete
                .take()
                .filter(|b| b.batch_id == batch_id)
                .ok_or_else(|| SafeGcError::InvalidInput("missing pending batch on stale abort".into()))?;
            let absent_set: BTreeSet<&str> = confirmed_absent_keys.iter().map(String::as_str).collect();
            let mut already_absent = batch.already_absent_keys.clone();
            for key in &batch.pending_keys {
                if absent_set.contains(key.as_str()) {
                    if !s.key_registry.deleted_tombstones.contains(key) {
                        s.key_registry.transition_state(
                            key,
                            KeyLifecycleState::DeletePendingBarrier,
                            KeyLifecycleState::PhysicallyDeletedTombstone,
                        )?;
                    }
                    if !already_absent.contains(key) {
                        already_absent.push(key.clone());
                    }
                } else {
                    s.key_registry.rollback_delete_barrier(key)?;
                }
            }
            s.retired_packs.retain(|p| {
                !(s.key_registry.deleted_tombstones.contains(&p.pack_key.object_path)
                    && s.key_registry.deleted_tombstones.contains(&p.idx_key.object_path))
            });
            let report = DeleteExecutionReport {
                batch_id,
                proof_digest: batch.proof.proof_digest,
                incarnation_epoch: batch.incarnation_epoch,
                deleted_keys: batch.deleted_keys,
                already_absent_keys: already_absent,
                unknown_outcome_keys: batch.unknown_keys,
                skipped_or_already_deleted: batch.skipped_keys,
                failed_keys: batch.failed_keys,
                reconciled_from_checkpoint: true,
                aborted_stale_incarnation: true,
            };
            s.aborted_batches.insert(batch_id, report.clone());
            s.push_audit("abort_stale_pending_batch", &batch_id.to_string());
            Ok(report)
        })
    }

    pub fn finalize_delete_batch(
        &self,
        batch_id: Uuid,
        skipped_keys: Vec<String>,
        unknown_keys: Vec<String>,
        failed_keys: Vec<String>,
        retry_keys: Vec<String>,
        reconciled_from_checkpoint: bool,
    ) -> Result<DeleteExecutionReport, SafeGcError> {
        self.update_persisted(|s| {
            let batch = s
                .pending_delete
                .take()
                .filter(|b| b.batch_id == batch_id)
                .ok_or_else(|| SafeGcError::InvalidInput("missing pending batch on finalize".into()))?;
            let report = DeleteExecutionReport {
                batch_id,
                proof_digest: batch.proof.proof_digest.clone(),
                incarnation_epoch: batch.incarnation_epoch,
                deleted_keys: batch.deleted_keys.clone(),
                already_absent_keys: batch.already_absent_keys.clone(),
                unknown_outcome_keys: unknown_keys.clone(),
                skipped_or_already_deleted: skipped_keys.clone(),
                failed_keys: failed_keys.clone(),
                reconciled_from_checkpoint,
                aborted_stale_incarnation: false,
            };
            if !retry_keys.is_empty() {
                s.pending_delete = Some(PendingDeleteBatch {
                    active_step_fence: None,
                    unknown_keys,
                    failed_keys,
                    skipped_keys,
                    pending_keys: retry_keys,
                    ..batch
                });
            } else {
                s.completed_batches.insert(batch_id, report.clone());
            }
            s.push_audit("finalize_delete_batch", &batch_id.to_string());
            Ok(report)
        })
    }

    pub fn quarantine_abandoned_staging(&self) -> Result<usize, SafeGcError> {
        self.update_persisted(|s| {
            let count =
                s.staged_uploads.iter().filter(|u| u.state == StagedUploadState::AbandonedPendingCleanup).count();
            if count > 0 {
                s.push_audit("quarantined_staging_delete_disabled", &count.to_string());
            }
            Ok(count)
        })
    }

    pub fn mint_staging_cleanup_tickets(&self) -> Result<Vec<DeleteAuthorizationTicket>, SafeGcError> {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let arm = guard.gc_mode.require_armed()?;
        let membership_digest = guard.compute_membership_digest();
        let mut out = Vec::new();
        for entry in guard.staged_uploads.iter().filter(|u| u.state == StagedUploadState::AbandonedPendingCleanup) {
            for (role, key, loc) in [
                ("staging_pack", &entry.pack_key, &entry.pack_locator),
                ("staging_idx", &entry.idx_key, &entry.idx_locator),
            ] {
                if guard.key_registry.deleted_tombstones.contains(&key.object_path) {
                    continue;
                }
                out.push(DeleteAuthorizationTicket::mint(TicketMintSpec {
                    batch_id: entry.op_id,
                    step_fence_id: entry.op_id,
                    incarnation_id: guard.authority.incarnation_id,
                    incarnation_epoch: guard.authority.incarnation_epoch,
                    lease_epoch: guard.authority.lease_epoch,
                    membership_generation: guard.authority.membership_generation,
                    membership_digest: membership_digest.clone(),
                    proof_digest: arm.arm_digest.clone(),
                    pack_id: entry.op_id,
                    key_role: role.to_owned(),
                    physical_key: key.object_path.clone(),
                    object_sha256: key.object_sha256.clone(),
                    locator: loc.clone(),
                    staging_cleanup_only: true,
                }));
            }
        }
        Ok(out)
    }

    pub fn record_staging_key_cleaned(&self, op_id: Uuid, physical_key: &str) -> Result<(), SafeGcError> {
        self.update_persisted(|s| {
            let _arm = s.gc_mode.require_armed()?;
            s.key_registry.tombstone_abandoned_staging(physical_key)?;
            if let Some(entry) = s.staged_uploads.iter_mut().find(|u| u.op_id == op_id)
                && s.key_registry.deleted_tombstones.contains(&entry.pack_key.object_path)
                && s.key_registry.deleted_tombstones.contains(&entry.idx_key.object_path)
            {
                entry.state = StagedUploadState::CleanedUp;
            }
            s.push_audit("staging_key_cleaned", physical_key);
            Ok(())
        })
    }
}

pub(super) fn persist_snapshot(path: &Path, snap: &SafeGcRepoSnapshot) -> Result<(), SafeGcError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| SafeGcError::Io(e.to_string()))?;
    }
    let tmp = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let bytes = serde_json::to_vec_pretty(snap).map_err(|e| SafeGcError::Serialization(e.to_string()))?;
    std::fs::write(&tmp, &bytes).map_err(|e| SafeGcError::Io(e.to_string()))?;
    std::fs::rename(&tmp, path).map_err(|e| SafeGcError::Io(e.to_string()))?;
    Ok(())
}
