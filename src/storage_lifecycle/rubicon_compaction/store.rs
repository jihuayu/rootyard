//! Crash-recoverable atomic-JSON-journaled RefStore & lease authority store (#162).

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use uuid::Uuid;

use crate::blob_store::read_accel::AuthoritativeRef;

use super::{
    CompactionError,
    lease::{
        BoxFuture, CompactionAuthoritativeSnapshot, CompactionAuthorityStore, CompactionFaultHook, CompactionLeaseKey,
        CompactionLeaseToken, CompactionPublishReceipt, CompactionPublishRequest, PendingOperationRecord,
    },
    segment::{CompactionSegmentLog, SegmentTriggerPolicy},
    sharding::{
        CompactionPackEntry, CompactionRef, CompactionShardRouter, pack_set_digest, refs_digest, retention_roots_digest,
    },
    store_cas::{
        DurableStoreState, LeaseSlotState, acquire_lease_locked, apply_cas_commit_locked, lease_slot_key,
        repo_slot_key, validate_lease_in_state,
    },
};

/// Crash-recoverable in-memory / atomic-JSON-checkpointed authority & lease store.
#[derive(Clone, Debug)]
pub struct DurableCompactionStore {
    inner: Arc<Mutex<DurableStoreState>>,
    persist_path: Option<PathBuf>,
}

impl DurableCompactionStore {
    pub fn in_memory() -> Self {
        Self { inner: Arc::new(Mutex::new(DurableStoreState::default())), persist_path: None }
    }

    pub fn open_with_journal(path: impl Into<PathBuf>) -> Result<Self, CompactionError> {
        let path = path.into();
        let state = if path.exists() {
            let bytes = std::fs::read(&path).map_err(|e| CompactionError::Io(e.to_string()))?;
            serde_json::from_slice(&bytes).map_err(|e| CompactionError::Serialization(e.to_string()))?
        } else {
            DurableStoreState::default()
        };
        Ok(Self { inner: Arc::new(Mutex::new(state)), persist_path: Some(path) })
    }

    pub fn reload_after_crash(&self) -> Result<Self, CompactionError> {
        match &self.persist_path {
            Some(path) => Self::open_with_journal(path.clone()),
            None => Err(CompactionError::InvalidInput("cannot reload store without persist_path".into())),
        }
    }

    fn flush_state(&self, state: &DurableStoreState) -> Result<(), CompactionError> {
        let Some(path) = &self.persist_path else { return Ok(()) };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| CompactionError::Io(e.to_string()))?;
        }
        let encoded = serde_json::to_vec(state).map_err(|e| CompactionError::Serialization(e.to_string()))?;
        let tmp = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
        std::fs::write(&tmp, &encoded).map_err(|e| CompactionError::Io(e.to_string()))?;
        std::fs::File::open(&tmp).and_then(|f| f.sync_all()).map_err(|e| CompactionError::Io(e.to_string()))?;
        std::fs::rename(&tmp, path).map_err(|e| CompactionError::Io(e.to_string()))?;
        Ok(())
    }

    pub fn seed_repository(
        &self,
        tenant_id: Uuid,
        repo_id: Uuid,
        history_id: Uuid,
        authority_epoch: u64,
        object_format: &str,
        shard_count: u16,
        packs: Vec<CompactionPackEntry>,
        refs: Vec<AuthoritativeRef>,
        retention_roots: Vec<String>,
        now_ms: u64,
        policy: &SegmentTriggerPolicy,
    ) -> Result<CompactionAuthoritativeSnapshot, CompactionError> {
        let _ = CompactionShardRouter::new(shard_count)?.partition_packs(&packs)?;
        let mut segments = CompactionSegmentLog::new();
        for pack in &packs {
            segments.ingest_pack(pack.clone(), now_ms, policy)?;
        }
        let stored_refs: Vec<CompactionRef> = refs.into_iter().map(CompactionRef::from).collect();
        let snap = CompactionAuthoritativeSnapshot {
            tenant_id,
            repo_id,
            history_id,
            authority_epoch,
            object_format: object_format.to_owned(),
            shard_count,
            membership_generation: 1,
            pack_set_digest: pack_set_digest(&packs),
            refs_digest: refs_digest(&stored_refs),
            retention_roots_digest: retention_roots_digest(&retention_roots),
            serving_packs: packs,
            retained_old_packs: Vec::new(),
            refs: stored_refs,
            retention_roots,
            segments,
            cumulative_newly_written_bytes: 0,
        };
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut next = guard.clone();
        next.repos.insert(repo_slot_key(tenant_id, repo_id, history_id), snap.clone());
        self.flush_state(&next)?;
        *guard = next;
        Ok(snap)
    }

    pub fn append_concurrent_pack(
        &self,
        tenant_id: Uuid,
        repo_id: Uuid,
        history_id: Uuid,
        pack: CompactionPackEntry,
        updated_refs: Vec<AuthoritativeRef>,
        now_ms: u64,
        policy: &SegmentTriggerPolicy,
    ) -> Result<CompactionAuthoritativeSnapshot, CompactionError> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut next = guard.clone();
        let repo = next
            .repos
            .get_mut(&repo_slot_key(tenant_id, repo_id, history_id))
            .ok_or_else(|| CompactionError::InvalidInput("unknown repo".into()))?;
        pack.validate(repo.shard_count)?;
        if repo.serving_packs.iter().any(|p| p.pack_id == pack.pack_id) {
            return Err(CompactionError::OperationConflict("duplicate concurrent pack_id"));
        }
        repo.segments.ingest_pack(pack.clone(), now_ms, policy)?;
        repo.serving_packs.push(pack);
        repo.refs = updated_refs.into_iter().map(CompactionRef::from).collect();
        repo.membership_generation = repo.membership_generation.saturating_add(1);
        repo.pack_set_digest = pack_set_digest(&repo.serving_packs);
        repo.refs_digest = refs_digest(&repo.refs);
        let cloned = repo.clone();
        self.flush_state(&next)?;
        *guard = next;
        Ok(cloned)
    }

    pub fn register_retention_root(
        &self,
        tenant_id: Uuid,
        repo_id: Uuid,
        history_id: Uuid,
        root_oid: String,
    ) -> Result<CompactionAuthoritativeSnapshot, CompactionError> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut next = guard.clone();
        let repo = next
            .repos
            .get_mut(&repo_slot_key(tenant_id, repo_id, history_id))
            .ok_or_else(|| CompactionError::InvalidInput("unknown repo".into()))?;
        if !repo.retention_roots.contains(&root_oid) {
            repo.retention_roots.push(root_oid);
            repo.retention_roots_digest = retention_roots_digest(&repo.retention_roots);
            repo.membership_generation = repo.membership_generation.saturating_add(1);
        }
        let cloned = repo.clone();
        self.flush_state(&next)?;
        *guard = next;
        Ok(cloned)
    }

    pub fn seal_aged_segments(
        &self,
        tenant_id: Uuid,
        repo_id: Uuid,
        history_id: Uuid,
        now_ms: u64,
        policy: &SegmentTriggerPolicy,
    ) -> Result<Vec<Uuid>, CompactionError> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut next = guard.clone();
        let repo = next
            .repos
            .get_mut(&repo_slot_key(tenant_id, repo_id, history_id))
            .ok_or_else(|| CompactionError::InvalidInput("unknown repo".into()))?;
        let sealed = repo.segments.seal_aged_segments(now_ms, policy)?;
        self.flush_state(&next)?;
        *guard = next;
        Ok(sealed)
    }

    pub fn force_steal_lease(
        &self,
        key: &CompactionLeaseKey,
        new_owner: &str,
        now_ms: u64,
        ttl_ms: u64,
    ) -> Result<CompactionLeaseToken, CompactionError> {
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut next = guard.clone();
        let slot =
            next.leases.entry(lease_slot_key(key)).or_insert(LeaseSlotState { next_fence_epoch: 1, active: None });
        let epoch = slot.next_fence_epoch;
        slot.next_fence_epoch = slot.next_fence_epoch.saturating_add(1);
        let token = CompactionLeaseToken {
            key: key.clone(),
            lease_id: Uuid::new_v4(),
            owner_id: new_owner.to_owned(),
            fence_epoch: epoch,
            acquired_at_ms: now_ms,
            expires_at_ms: now_ms.saturating_add(ttl_ms),
        };
        slot.active = Some(token.clone());
        self.flush_state(&next)?;
        *guard = next;
        Ok(token)
    }

    pub fn metrics_counts(&self) -> (u64, u64) {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        (guard.cas_conflict_count, guard.double_retirement_rejections)
    }

    pub fn checkpoints(&self) -> Vec<PendingOperationRecord> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).checkpoints.values().cloned().collect()
    }
}

impl CompactionAuthorityStore for DurableCompactionStore {
    fn acquire_or_renew_lease<'a>(
        &'a self,
        key: &'a CompactionLeaseKey,
        owner_id: &'a str,
        now_ms: u64,
        ttl_ms: u64,
    ) -> BoxFuture<'a, CompactionLeaseToken> {
        Box::pin(async move {
            if owner_id.trim().is_empty() || ttl_ms == 0 {
                return Err(CompactionError::InvalidInput("owner_id and ttl_ms must be valid".into()));
            }
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let mut next = guard.clone();
            let token = acquire_lease_locked(&mut next, key, owner_id, now_ms, ttl_ms)?;
            self.flush_state(&next)?;
            *guard = next;
            Ok(token)
        })
    }

    fn verify_lease_active<'a>(&'a self, token: &'a CompactionLeaseToken, now_ms: u64) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            validate_lease_in_state(&guard, &token.key, token.lease_id, token.fence_epoch, now_ms)
        })
    }

    fn release_lease<'a>(&'a self, token: &'a CompactionLeaseToken) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let mut next = guard.clone();
            if let Some(slot) = next.leases.get_mut(&lease_slot_key(&token.key))
                && slot
                    .active
                    .as_ref()
                    .is_some_and(|a| a.lease_id == token.lease_id && a.fence_epoch == token.fence_epoch)
            {
                slot.active = None;
                self.flush_state(&next)?;
                *guard = next;
            }
            Ok(())
        })
    }

    fn load_snapshot<'a>(
        &'a self,
        tenant_id: Uuid,
        repo_id: Uuid,
        history_id: Uuid,
    ) -> BoxFuture<'a, CompactionAuthoritativeSnapshot> {
        Box::pin(async move {
            self.inner
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .repos
                .get(&repo_slot_key(tenant_id, repo_id, history_id))
                .cloned()
                .ok_or_else(|| CompactionError::InvalidInput("repository snapshot not found".into()))
        })
    }

    fn lookup_operation<'a>(&'a self, op_id: Uuid) -> BoxFuture<'a, Option<CompactionPublishReceipt>> {
        Box::pin(async move {
            Ok(self.inner.lock().unwrap_or_else(|e| e.into_inner()).operations.get(&op_id).map(|e| e.receipt.clone()))
        })
    }

    fn record_checkpoint<'a>(&'a self, record: PendingOperationRecord) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let mut next = guard.clone();
            next.checkpoints.insert(record.op_id, record);
            self.flush_state(&next)?;
            *guard = next;
            Ok(())
        })
    }

    fn cas_publish_compaction<'a>(
        &'a self,
        request: &'a CompactionPublishRequest,
        now_ms: u64,
        drop_ack_fault: bool,
    ) -> BoxFuture<'a, CompactionPublishReceipt> {
        Box::pin(async move {
            let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            let mut next = guard.clone();
            let res = apply_cas_commit_locked(&mut next, request, now_ms);
            match res {
                Ok(receipt) => {
                    self.flush_state(&next)?;
                    *guard = next;
                    if drop_ack_fault {
                        return Err(CompactionError::Io(
                            "simulated dropped ACK after durable RefStore CAS publish".into(),
                        ));
                    }
                    Ok(receipt)
                }
                Err(err) => {
                    guard.cas_conflict_count = next.cas_conflict_count;
                    guard.double_retirement_rejections = next.double_retirement_rejections;
                    let _ = self.flush_state(&guard);
                    Err(err)
                }
            }
        })
    }

    fn inject_fault<'a>(
        &'a self,
        hook: &'a CompactionFaultHook,
        key: &'a CompactionLeaseKey,
        now_ms: u64,
        policy: &'a SegmentTriggerPolicy,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            match hook {
                CompactionFaultHook::LoseLeaseBeforePublish { usurper_owner } => {
                    let _ = self.force_steal_lease(key, usurper_owner, now_ms, 30_000)?;
                }
                CompactionFaultHook::ConcurrentPushBeforePublish(push) => {
                    let _ = self.append_concurrent_pack(
                        key.tenant_id,
                        key.repo_id,
                        key.history_id,
                        push.pack.clone(),
                        push.updated_refs.clone(),
                        now_ms,
                        policy,
                    )?;
                }
                _ => {}
            }
            Ok(())
        })
    }
}
