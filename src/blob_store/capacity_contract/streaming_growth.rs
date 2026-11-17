//! Bounded streaming growth engine supporting > 16 incremental packs.
//!
//! Coordinates fail-closed admission, streamed BlobStore pack upload/readback,
//! DisposableViewRoot verification, no-new-pack ref updates, idempotent retries,
//! cancellation tombstones, pins/roots/backups, and no-delete compaction.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Mutex,
    time::Instant,
};

use uuid::Uuid;

use super::{
    admission::AdmissionController,
    admission_types::{AdmissionClass, AdmissionLimits, AdmissionRejection, AdmissionRequest},
    git_ops::{ObjectFormat, PackDownloadRef, UploadScope, hash_file_bounded, inspect_pack_file, upload_pack_pair},
    git_views::{CompactViewInput, VerifyViewInput, compact_packs_in_view, verify_frontier_in_view},
    growth_state::{CommitPushInput, EngineState, apply_cas_mutations, validate_mutations},
    growth_types::{
        CompactionOutcome, EngineScope, GrowthEngineError, GrowthEngineSnapshot, IncrementalPushRequest, PushOutcome,
        VerifiedPackRecord,
    },
    ledger_retention::RetentionLedger,
    ledger_types::{LedgerBudgetPolicy, ProtectionHold},
    limits::{PandoCapacityContract, RESERVED_GIT_OPEN_FDS},
};
use crate::blob_store::{BlobLocator, disposable_view::DisposableViewRoot, opendal::BlobStore};

pub struct StreamingGrowthEngine {
    contract: PandoCapacityContract,
    admission: AdmissionController,
    store: BlobStore,
    view_root: DisposableViewRoot,
    tenant_id: Uuid,
    repo_id: Uuid,
    authority_id: Uuid,
    object_format: ObjectFormat,
    auto_compact: bool,
    state: Mutex<EngineState>,
}

impl StreamingGrowthEngine {
    pub fn new(
        contract: PandoCapacityContract,
        store: BlobStore,
        view_root: DisposableViewRoot,
        scope: EngineScope,
    ) -> Result<Self, GrowthEngineError> {
        contract.validate()?;
        if scope.tenant_id.is_nil() || scope.repo_id.is_nil() || scope.authority_id.is_nil() {
            return Err(GrowthEngineError::InvalidInput("tenant_id, repo_id, and authority_id must be non-nil"));
        }
        let limits = AdmissionLimits::from_contract(&contract)?;
        let admission = AdmissionController::new(limits)?;
        let ledger = RetentionLedger::new(LedgerBudgetPolicy::from_contract(&contract));
        Ok(Self {
            contract,
            admission,
            store,
            view_root,
            tenant_id: scope.tenant_id,
            repo_id: scope.repo_id,
            authority_id: scope.authority_id,
            object_format: scope.object_format,
            auto_compact: scope.auto_compact,
            state: Mutex::new(EngineState {
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
                ledger,
            }),
        })
    }

    pub fn admission(&self) -> &AdmissionController {
        &self.admission
    }

    pub fn snapshot(&self) -> GrowthEngineSnapshot {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).snapshot()
    }

    pub fn acked_refs(&self) -> BTreeMap<String, String> {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).acked_refs.clone()
    }

    pub fn active_pack_locators(&self) -> Vec<BlobLocator> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .active_packs
            .iter()
            .map(|p| p.pack_locator.clone())
            .collect()
    }

    pub fn retained_pack_locators(&self) -> Vec<BlobLocator> {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retained_old_packs
            .iter()
            .map(|p| p.pack_locator.clone())
            .collect()
    }

    pub fn cancel_operation(&self, operation_id: Uuid) -> Result<(), GrowthEngineError> {
        if operation_id.is_nil() {
            return Err(GrowthEngineError::InvalidInput("operation_id must be non-nil"));
        }
        self.state.lock().unwrap_or_else(|p| p.into_inner()).cancelled_operations.insert(operation_id);
        Ok(())
    }

    pub fn attach_hold(&self, hold: ProtectionHold, pinned_oid: Option<String>) -> Result<usize, GrowthEngineError> {
        if let Some(oid) = &pinned_oid
            && !self.object_format.is_valid_oid(oid)
        {
            return Err(GrowthEngineError::InvalidInput("pinned oid does not match repository format"));
        }
        let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let hold_id = hold.hold_id();
        let count = guard.ledger.attach_hold_to_active_frontier(hold);
        if let Some(oid) = pinned_oid {
            guard.pinned_commits.insert(hold_id, oid);
        }
        Ok(count)
    }

    pub fn release_hold(&self, hold_id: Uuid) -> Result<usize, GrowthEngineError> {
        let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
        guard.pinned_commits.remove(&hold_id);
        Ok(guard.ledger.release_hold(hold_id)?)
    }

    pub fn archive_released_ledger(&self) -> usize {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).ledger.archive_released_entries()
    }

    pub fn attempt_delete_ledger_entry(&self, entry_id: Uuid) -> Result<(), GrowthEngineError> {
        self.state.lock().unwrap_or_else(|p| p.into_inner()).ledger.attempt_delete_entry(entry_id).map_err(Into::into)
    }

    pub async fn apply_push(
        &self,
        req: IncrementalPushRequest,
        deadline: Instant,
    ) -> Result<PushOutcome, GrowthEngineError> {
        if !req.caller_authorized {
            return Err(GrowthEngineError::Admission(AdmissionRejection::Unauthorized));
        }
        if req.operation_id.is_nil() || req.request_digest.is_empty() {
            return Err(GrowthEngineError::InvalidInput("operation_id and request_digest required"));
        }
        validate_mutations(self.object_format, self.contract.metadata_ledger.max_plan_refs, &req.ref_mutations)?;
        if let Some(replayed) = {
            let guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
            guard.check_replay_or_cancel(req.operation_id, &req.request_digest)?
        } {
            return Ok(replayed);
        }

        if self.auto_compact && !req.new_pack_paths.is_empty() {
            let need_compact = {
                let guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
                guard.active_packs.len().saturating_add(req.new_pack_paths.len())
                    > self.contract.streaming.compact_trigger_packs
                    && !guard.active_packs.is_empty()
            };
            if need_compact {
                match self.compact_serving_frontier(deadline).await {
                    Ok(_) | Err(GrowthEngineError::CompactionConflict) => {}
                    Err(err) => return Err(err),
                }
            }
        }

        let (base_epoch, base_packs, base_refs) = {
            let guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
            (guard.epoch, guard.active_packs.clone(), guard.acked_refs.clone())
        };
        let base_pack_ids: BTreeSet<Uuid> = base_packs.iter().map(|p| p.pack_id).collect();
        let resulting_refs = apply_cas_mutations(self.object_format, &base_refs, &req.ref_mutations)?;

        let (mut new_pack_bytes, mut new_pack_objects) = (0u64, 0u64);
        for (pack_path, idx_path) in &req.new_pack_paths {
            let (_, plen, objs) = inspect_pack_file(pack_path)?;
            let (_, ilen) = hash_file_bounded(idx_path)?;
            new_pack_bytes = new_pack_bytes.saturating_add(plen).saturating_add(ilen);
            new_pack_objects = new_pack_objects.saturating_add(objs);
        }
        let frontier_bytes: u64 = base_packs.iter().map(VerifiedPackRecord::total_bytes).sum();
        let frontier_objects: u64 = base_packs.iter().map(|p| p.object_count).sum();
        let total_pairs = base_packs.len().saturating_add(req.new_pack_paths.len());
        let total_bytes = frontier_bytes.saturating_add(new_pack_bytes);
        let adm_req = AdmissionRequest {
            tenant_id: self.tenant_id,
            repo_id: self.repo_id,
            caller_authorized: req.caller_authorized,
            class: AdmissionClass::ForegroundPush,
            new_pack_count: req.new_pack_paths.len(),
            active_frontier_packs: base_packs.len(),
            declared_pack_bytes: total_bytes,
            declared_objects: frontier_objects.saturating_add(new_pack_objects),
            max_single_object_bytes: req.max_single_object_bytes,
            estimated_memory_bytes: (self.contract.streaming.io_chunk_bytes as u64).saturating_mul(4),
            estimated_workspace_bytes: total_bytes.saturating_mul(2),
            required_fds: (total_pairs as u64).saturating_mul(2).saturating_add(RESERVED_GIT_OPEN_FDS),
            free_disk_bytes: req.free_disk_bytes,
        };
        let mut permit = self.admission.acquire(&adm_req, deadline).await?;

        let target_epoch = base_epoch + 1;
        let mut uploaded_records = Vec::with_capacity(req.new_pack_paths.len());
        let mut put_bytes = 0u64;
        for (pack_path, idx_path) in &req.new_pack_paths {
            let scope = UploadScope {
                tenant_id: self.tenant_id,
                authority_id: self.authority_id,
                generation: target_epoch as i64,
            };
            let uploaded = upload_pack_pair(&self.store, scope, pack_path, idx_path, deadline).await?;
            put_bytes = put_bytes.saturating_add(uploaded.pack_length).saturating_add(uploaded.idx_length);
            uploaded_records.push(VerifiedPackRecord {
                pack_id: Uuid::new_v4(),
                registration_id: Uuid::new_v4(),
                pack_locator: uploaded.pack_receipt.locator().clone(),
                pack_sha256: uploaded.pack_sha256,
                pack_length: uploaded.pack_length,
                idx_locator: uploaded.idx_receipt.locator().clone(),
                idx_sha256: uploaded.idx_sha256,
                idx_length: uploaded.idx_length,
                object_count: uploaded.object_count,
                joined_epoch: target_epoch,
            });
        }

        let download_refs: Vec<PackDownloadRef> =
            base_packs.iter().chain(uploaded_records.iter()).map(VerifiedPackRecord::as_download_ref).collect();
        let verified = verify_frontier_in_view(
            VerifyViewInput {
                store: &self.store,
                view_root: &self.view_root,
                tenant_id: self.tenant_id,
                authority_id: self.authority_id,
                format: self.object_format,
                packs: &download_refs,
                refs: &resulting_refs,
                max_objects: self.contract.verifier.max_objects_per_window,
                max_total_bytes: self.contract.verifier.max_total_bytes_per_window,
                full_fsck: false,
            },
            deadline,
        )
        .await?;
        permit.shrink_workspace(total_bytes);

        let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
        guard.commit_push(CommitPushInput {
            contract: &self.contract,
            object_format: self.object_format,
            operation_id: req.operation_id,
            request_digest: req.request_digest,
            ref_mutations: &req.ref_mutations,
            base_pack_ids: &base_pack_ids,
            uploaded_records,
            put_bytes,
            blob_get_bytes: verified.blob_get_bytes,
            peak_scratch_bytes: verified.peak_scratch_bytes,
        })
    }

    pub async fn compact_serving_frontier(&self, deadline: Instant) -> Result<CompactionOutcome, GrowthEngineError> {
        let (base_epoch, target_packs, refs_snap, pins_snap) = {
            let guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if guard.active_packs.is_empty() {
                return Err(GrowthEngineError::InvalidInput("cannot compact empty active frontier"));
            }
            let pins: Vec<String> = guard.pinned_commits.values().cloned().collect();
            (guard.epoch, guard.active_packs.clone(), guard.acked_refs.clone(), pins)
        };
        let target_ids: BTreeSet<Uuid> = target_packs.iter().map(|p| p.pack_id).collect();
        let total_bytes: u64 = target_packs.iter().map(VerifiedPackRecord::total_bytes).sum();
        let total_objects: u64 = target_packs.iter().map(|p| p.object_count).sum();
        let adm_req = AdmissionRequest {
            tenant_id: self.tenant_id,
            repo_id: self.repo_id,
            caller_authorized: true,
            class: AdmissionClass::CompactionMaintenance,
            new_pack_count: 1,
            active_frontier_packs: 0,
            declared_pack_bytes: total_bytes,
            declared_objects: total_objects,
            max_single_object_bytes: total_bytes.max(1),
            estimated_memory_bytes: (self.contract.streaming.io_chunk_bytes as u64).saturating_mul(4),
            estimated_workspace_bytes: total_bytes.saturating_mul(2),
            required_fds: (target_packs.len() as u64).saturating_mul(2).saturating_add(RESERVED_GIT_OPEN_FDS),
            free_disk_bytes: total_bytes.saturating_mul(2).saturating_add(self.contract.verifier.disk_headroom_bytes),
        };
        let _permit = self.admission.acquire(&adm_req, deadline).await?;
        let dl_refs: Vec<PackDownloadRef> = target_packs.iter().map(VerifiedPackRecord::as_download_ref).collect();
        let summary = compact_packs_in_view(
            CompactViewInput {
                store: &self.store,
                view_root: &self.view_root,
                tenant_id: self.tenant_id,
                authority_id: self.authority_id,
                generation: (base_epoch + 1) as i64,
                format: self.object_format,
                packs: &dl_refs,
                refs: &refs_snap,
                pinned_oids: &pins_snap,
                max_objects: self.contract.verifier.max_objects_per_window,
                max_total_bytes: self.contract.verifier.max_total_bytes_per_window,
            },
            deadline,
        )
        .await?;

        self.state.lock().unwrap_or_else(|p| p.into_inner()).commit_compaction(
            &target_ids,
            summary.uploaded,
            summary.blob_get_bytes,
            summary.peak_scratch_bytes,
            summary.oid_count,
        )
    }

    pub async fn verify_full_serving_closure(&self, deadline: Instant) -> Result<usize, GrowthEngineError> {
        let (packs, refs_snap) = {
            let guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
            let mut refs = guard.acked_refs.clone();
            for (idx, oid) in guard.pinned_commits.values().enumerate() {
                refs.insert(format!("refs/pando-pins/pin-{idx:04}"), oid.clone());
            }
            (guard.active_packs.clone(), refs)
        };
        let dl_refs: Vec<PackDownloadRef> = packs.iter().map(VerifiedPackRecord::as_download_ref).collect();
        let summary = verify_frontier_in_view(
            VerifyViewInput {
                store: &self.store,
                view_root: &self.view_root,
                tenant_id: self.tenant_id,
                authority_id: self.authority_id,
                format: self.object_format,
                packs: &dl_refs,
                refs: &refs_snap,
                max_objects: self.contract.verifier.max_objects_per_window,
                max_total_bytes: self.contract.verifier.max_total_bytes_per_window,
                full_fsck: true,
            },
            deadline,
        )
        .await?;
        let mut guard = self.state.lock().unwrap_or_else(|p| p.into_inner());
        guard.total_blob_get_bytes = guard.total_blob_get_bytes.saturating_add(summary.blob_get_bytes);
        guard.peak_scratch_bytes = guard.peak_scratch_bytes.max(summary.peak_scratch_bytes);
        Ok(refs_snap.len())
    }
}
