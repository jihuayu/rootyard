//! Pre-delete barrier re-verification & atomic snapshot persistence (#122).

use std::{collections::BTreeSet, path::Path};

use uuid::Uuid;

use super::{
    SafeGcError,
    anti_aba::KeyLifecycleState,
    domain::{DeleteAuthorizationTicket, DeleteExecutionReport, GcAuditEvent},
    model::{AuthorityLane, DecisionState, GlobalHoldState, SourceFreshness},
    proof::{DeletionProof, verify_deletion_proof},
    store::{DurableSafeGcAuthority, PendingDeleteBatch, SafeGcRepoSnapshot},
};

impl DurableSafeGcAuthority {
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
                pending_keys: keys,
                deleted_keys: Vec::new(),
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
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let Some(batch) = guard.pending_delete.as_ref().filter(|b| b.batch_id == batch_id) else {
            return Err(SafeGcError::StaleDeleterFenced("pending delete batch absent or completed"));
        };
        guard.require_live_barrier(
            deleter_incarnation_id,
            deleter_incarnation_epoch,
            deleter_lease_epoch,
            &batch.proof,
        )?;
        if guard.key_registry.deleted_tombstones.contains(physical_key) {
            return Ok(None);
        }
        guard.key_registry.assert_delete_allowed(physical_key, deleter_incarnation_epoch)?;
        let cand = batch
            .proof
            .candidates
            .iter()
            .find(|c| c.physical_key == physical_key)
            .ok_or_else(|| SafeGcError::InvalidInput("physical key not part of batch proof".into()))?;
        let locator = guard.retired_packs.iter().find_map(|p| {
            if p.pack_key.object_path == physical_key {
                Some(p.pack_locator.clone())
            } else if p.idx_key.object_path == physical_key {
                Some(p.idx_locator.clone())
            } else {
                None
            }
        });
        Ok(Some(DeleteAuthorizationTicket::mint(
            (batch_id, deleter_incarnation_id, deleter_incarnation_epoch, deleter_lease_epoch),
            batch.proof.proof_digest.clone(),
            cand.pack_id,
            (cand.physical_key.clone(), cand.object_sha256.clone(), locator),
        )))
    }

    pub fn record_key_deleted(&self, batch_id: Uuid, physical_key: &str) -> Result<(), SafeGcError> {
        self.update_persisted(|s| {
            if !s.key_registry.deleted_tombstones.contains(physical_key) {
                s.key_registry.transition_state(
                    physical_key,
                    KeyLifecycleState::DeletePendingBarrier,
                    KeyLifecycleState::PhysicallyDeletedTombstone,
                )?;
            }
            s.retired_packs.retain(|p| p.pack_key.object_path != physical_key);
            if let Some(batch) = s.pending_delete.as_mut().filter(|b| b.batch_id == batch_id) {
                batch.pending_keys.retain(|k| k != physical_key);
                if !batch.deleted_keys.iter().any(|k| k == physical_key) {
                    batch.deleted_keys.push(physical_key.to_owned());
                }
            }
            s.push_audit("delete_committed", physical_key);
            Ok(())
        })
    }

    pub fn finalize_delete_batch(
        &self,
        batch_id: Uuid,
        skipped_keys: Vec<String>,
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
                skipped_or_already_deleted: skipped_keys.clone(),
                failed_keys: failed_keys.clone(),
                reconciled_from_checkpoint,
            };
            if !retry_keys.is_empty() {
                s.pending_delete =
                    Some(PendingDeleteBatch { failed_keys, skipped_keys, pending_keys: retry_keys, ..batch });
            } else {
                s.completed_batches.insert(batch_id, report.clone());
            }
            s.push_audit("finalize_delete_batch", &batch_id.to_string());
            Ok(report)
        })
    }
}

impl SafeGcRepoSnapshot {
    pub(super) fn register_initial_keys(&mut self) -> Result<(), SafeGcError> {
        for p in self.active_packs.iter().chain(self.retired_packs.iter()) {
            if !self.key_registry.keys_by_path.contains_key(&p.pack_key.object_path) {
                self.key_registry.register_verified_key(p.pack_key.clone())?;
            }
            if !self.key_registry.keys_by_path.contains_key(&p.idx_key.object_path) {
                self.key_registry.register_verified_key(p.idx_key.clone())?;
            }
        }
        Ok(())
    }

    pub(super) fn push_audit(&mut self, action: &str, target: &str) {
        let seq = self.audit_log.last().map_or(1, |e| e.seq + 1);
        self.audit_log.push(GcAuditEvent {
            seq,
            incarnation_epoch: self.authority.incarnation_epoch,
            action: action.to_owned(),
            target: target.to_owned(),
        });
    }

    pub(super) fn require_live_barrier(
        &self,
        deleter_incarnation_id: Uuid,
        deleter_incarnation_epoch: u64,
        deleter_lease_epoch: u64,
        proof: &DeletionProof,
    ) -> Result<(), SafeGcError> {
        let arm = self.gc_mode.require_armed()?;
        if deleter_incarnation_epoch != self.authority.incarnation_epoch
            || deleter_incarnation_id != self.authority.incarnation_id
            || arm.incarnation_epoch != self.authority.incarnation_epoch
        {
            return Err(SafeGcError::StaleIncarnation("authority incarnation rotated"));
        }
        if deleter_lease_epoch < self.authority.lease_epoch {
            return Err(SafeGcError::StaleDeleterFenced("stale deleter lease epoch"));
        }
        if matches!(arm.lane, AuthorityLane::DistributedRefCas { .. })
            && !matches!(proof.lane, AuthorityLane::DistributedRefCas { .. })
        {
            return Err(SafeGcError::DistributedPrereqsMissing("proof lane mismatch"));
        }
        if self.authority.live_ref_seq != proof.live_ref_seq {
            return Err(SafeGcError::ConcurrentRetentionRace("live refs mutated after proof"));
        }
        self.check_live_holds_and_decisions(proof)
    }

    fn check_live_holds_and_decisions(&self, proof: &DeletionProof) -> Result<(), SafeGcError> {
        let cand_ids: BTreeSet<Uuid> = proof.candidates.iter().map(|c| c.pack_id).collect();
        let cand_keys: BTreeSet<&str> = proof.candidates.iter().map(|c| c.physical_key.as_str()).collect();
        let cand_oids: BTreeSet<&str> =
            proof.candidates.iter().flat_map(|c| c.contained_oids.iter().map(String::as_str)).collect();

        if self.active_packs.iter().any(|p| cand_ids.contains(&p.pack_id)) {
            return Err(SafeGcError::ProtectionOverlap("candidate is still in active serving set".into()));
        }
        for r in &self.live_refs {
            if cand_oids.contains(r.target_oid.as_str()) {
                return Err(SafeGcError::ConcurrentRetentionRace("live ref now references candidate"));
            }
        }
        for p in &self.producers {
            if p.freshness != SourceFreshness::Reconciled
                || p.observed_cursor_seq < p.required_cursor_seq
                || p.authority_epoch < self.authority.incarnation_epoch
            {
                return Err(SafeGcError::ConcurrentRetentionRace("live producer lagged or drifted"));
            }
            if p.pinned_pack_ids.iter().any(|id| cand_ids.contains(id))
                || p.root_oids.iter().any(|o| cand_oids.contains(o.as_str()))
            {
                return Err(SafeGcError::ConcurrentRetentionRace("producer concurrently pinned candidate"));
            }
        }
        for h in &self.global_holds {
            match h.state {
                GlobalHoldState::Unknown => {
                    return Err(SafeGcError::ConcurrentRetentionRace("live global hold unknown"));
                }
                GlobalHoldState::Active => {
                    if h.protected_pack_ids.iter().any(|id| cand_ids.contains(id))
                        || h.protected_physical_keys.iter().any(|k| cand_keys.contains(k.as_str()))
                        || h.protected_oids.iter().any(|o| cand_oids.contains(o.as_str()))
                    {
                        return Err(SafeGcError::ConcurrentRetentionRace("active global hold covers candidate"));
                    }
                }
                GlobalHoldState::Released { released_at_seq } => {
                    if released_at_seq > self.paired_cursors.pg_applied_seq
                        || released_at_seq > self.paired_cursors.refcas_applied_index
                    {
                        return Err(SafeGcError::ConcurrentRetentionRace("release-before-register cursor gap"));
                    }
                }
            }
        }
        for d in &self.in_flight_decisions {
            if d.state == DecisionState::Unknown
                || (d.state == DecisionState::Pending
                    && (d.protected_pack_ids.iter().any(|id| cand_ids.contains(id))
                        || d.protected_oids.iter().any(|o| cand_oids.contains(o.as_str()))))
            {
                return Err(SafeGcError::ConcurrentRetentionRace("in-flight decision protects candidate"));
            }
        }
        if self.paired_cursors.pg_freshness != SourceFreshness::Reconciled
            || self.paired_cursors.pg_applied_seq < self.paired_cursors.pg_required_seq
            || self.paired_cursors.refcas_freshness != SourceFreshness::Reconciled
            || self.paired_cursors.refcas_applied_index < self.paired_cursors.refcas_required_index
        {
            return Err(SafeGcError::ConcurrentRetentionRace("paired cursors drifted/lagging"));
        }
        Ok(())
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
