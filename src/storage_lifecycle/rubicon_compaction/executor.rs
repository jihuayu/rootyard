//! No-delete shard compaction executor: verify closures, upload/readback, prove equivalence, CAS publish (#162).

use std::{
    collections::HashSet,
    path::Path,
    time::{Duration, Instant},
};

use uuid::Uuid;

use crate::blob_store::{
    BlobLocator,
    disposable_view::DisposableViewRoot,
    opendal::BlobStore,
    read_accel::{PackDigestEntry, PackRetentionRegistry},
};

use super::{
    CompactionError,
    budget::CompactionResourceBudget,
    git_ops::{
        collect_object_ids, hash_string_lines, install_refs_verify_and_measure, locate_single_pack_pair,
        parse_object_format, populate_bare_with_entries, run_compaction_git, sha256_file_and_len,
        verify_and_readback_pair, verify_pack_self_contained,
    },
    lease::{
        BoxFuture, CompactionAuthorityStore, CompactionEquivalenceProof, CompactionFaultHook, CompactionLeaseKey,
        CompactionLeaseToken, CompactionPhase, CompactionPublishReceipt, CompactionPublishRequest,
        PendingOperationRecord,
    },
    segment::{SegmentTriggerPolicy, TieredMergePlan},
    sharding::{CompactionPackEntry, shard_for_pack_hash},
};

#[derive(Clone, Debug)]
pub struct UploadedPackPair {
    pub pack_locator: BlobLocator,
    pub idx_locator: BlobLocator,
}

/// Pluggable upload carrier preserving `ArtifactHold`/`ProtectedUploader` boundaries outside `blob_store`.
pub trait CompactionBlobUploader: Send + Sync {
    fn upload_pack_pair<'a>(
        &'a self,
        store: &'a BlobStore,
        tenant_id: Uuid,
        repo_id: Uuid,
        blob_generation: i64,
        pack_path: &'a Path,
        idx_path: &'a Path,
        deadline: Instant,
    ) -> BoxFuture<'a, UploadedPackPair>;
}

#[derive(Clone)]
pub struct CompactionRunRequest<'a> {
    pub tenant_id: Uuid,
    pub repo_id: Uuid,
    pub history_id: Uuid,
    pub blob_generation: i64,
    pub shard_id: u16,
    pub owner_id: &'a str,
    pub now_ms: u64,
    pub lease_ttl_ms: u64,
    pub policy: SegmentTriggerPolicy,
    pub max_cas_retries: usize,
    pub op_id_override: Option<Uuid>,
    pub retention_registry: Option<&'a PackRetentionRegistry>,
    pub fault_hook: CompactionFaultHook,
}

#[derive(Clone, Debug)]
pub struct PublishedCompaction {
    pub op_id: Uuid,
    pub plan: TieredMergePlan,
    pub replacement_pack: CompactionPackEntry,
    pub proof: CompactionEquivalenceProof,
    pub receipt: CompactionPublishReceipt,
    pub attempts: usize,
}

#[derive(Clone, Debug)]
pub enum CompactionRunOutcome {
    NoWorkDue,
    Published(Box<PublishedCompaction>),
}

/// Retry up to `1 + max_cas_retries` times on `MembershipDrift`, keeping concurrent pushes intact.
pub async fn execute_shard_compaction_with_retry(
    authority: &dyn CompactionAuthorityStore,
    uploader: &dyn CompactionBlobUploader,
    store: &BlobStore,
    view_root: &DisposableViewRoot,
    budget: &CompactionResourceBudget,
    request: &CompactionRunRequest<'_>,
    deadline: Instant,
) -> Result<CompactionRunOutcome, CompactionError> {
    let started_all = Instant::now();
    let mut attempt_req = request.clone();
    let max_tries = request.max_cas_retries.saturating_add(1);
    for attempt in 1..=max_tries {
        attempt_req.now_ms = current_now_ms(request.now_ms, started_all);
        match execute_shard_compaction_inner(authority, uploader, store, view_root, budget, &attempt_req, deadline)
            .await
        {
            Ok(CompactionRunOutcome::NoWorkDue) => return Ok(CompactionRunOutcome::NoWorkDue),
            Ok(CompactionRunOutcome::Published(mut published)) => {
                published.attempts = attempt;
                return Ok(CompactionRunOutcome::Published(published));
            }
            Err(CompactionError::MembershipDrift(_)) if attempt < max_tries => {
                attempt_req.fault_hook = CompactionFaultHook::None;
                attempt_req.op_id_override = None;
                continue;
            }
            Err(err) => return Err(err),
        }
    }
    unreachable!("max_tries >= 1 guarantees loop exits above")
}

pub async fn execute_shard_compaction(
    authority: &dyn CompactionAuthorityStore,
    uploader: &dyn CompactionBlobUploader,
    store: &BlobStore,
    view_root: &DisposableViewRoot,
    budget: &CompactionResourceBudget,
    request: &CompactionRunRequest<'_>,
    deadline: Instant,
) -> Result<CompactionRunOutcome, CompactionError> {
    execute_shard_compaction_inner(authority, uploader, store, view_root, budget, request, deadline).await
}

async fn execute_shard_compaction_inner(
    authority: &dyn CompactionAuthorityStore,
    uploader: &dyn CompactionBlobUploader,
    store: &BlobStore,
    view_root: &DisposableViewRoot,
    budget: &CompactionResourceBudget,
    request: &CompactionRunRequest<'_>,
    deadline: Instant,
) -> Result<CompactionRunOutcome, CompactionError> {
    request.policy.validate()?;
    if request.tenant_id.is_nil()
        || request.repo_id.is_nil()
        || request.history_id.is_nil()
        || request.blob_generation <= 0
        || request.lease_ttl_ms == 0
    {
        return Err(CompactionError::InvalidInput("invalid ids, blob_generation, or lease_ttl_ms".into()));
    }
    if let Some(op_id) = request.op_id_override
        && let Some(receipt) = authority.lookup_operation(op_id).await?
    {
        return Ok(replay_outcome(op_id, receipt));
    }

    let lease_key = CompactionLeaseKey {
        tenant_id: request.tenant_id,
        repo_id: request.repo_id,
        history_id: request.history_id,
        shard_id: request.shard_id,
    };
    let lease_token =
        authority.acquire_or_renew_lease(&lease_key, request.owner_id, request.now_ms, request.lease_ttl_ms).await?;
    let attempt = LeasedAttempt { token: &lease_token, deadline };
    match execute_leased_attempt(authority, uploader, store, view_root, budget, request, attempt).await {
        Err(LeasedAttemptError::CrashInjected(err)) => {
            // A reached crash injection leaves the lease to expire as designed.
            Err(err)
        }
        Ok(outcome) => {
            // Preserve the existing success contract: cleanup failure is surfaced.
            authority.release_lease(&lease_token).await?;
            Ok(outcome)
        }
        Err(LeasedAttemptError::Failed(err)) => {
            // Best-effort cleanup, but never mask the original compaction failure.
            let _ = authority.release_lease(&lease_token).await;
            Err(err)
        }
    }
}

enum LeasedAttemptError {
    Failed(CompactionError),
    CrashInjected(CompactionError),
}

impl From<CompactionError> for LeasedAttemptError {
    fn from(error: CompactionError) -> Self {
        Self::Failed(error)
    }
}

struct LeasedAttempt<'a> {
    token: &'a CompactionLeaseToken,
    deadline: Instant,
}

async fn execute_leased_attempt(
    authority: &dyn CompactionAuthorityStore,
    uploader: &dyn CompactionBlobUploader,
    store: &BlobStore,
    view_root: &DisposableViewRoot,
    budget: &CompactionResourceBudget,
    request: &CompactionRunRequest<'_>,
    attempt: LeasedAttempt<'_>,
) -> Result<CompactionRunOutcome, LeasedAttemptError> {
    let LeasedAttempt { token: lease_token, deadline } = attempt;
    let started_at = Instant::now();
    let snap = authority.load_snapshot(request.tenant_id, request.repo_id, request.history_id).await?;
    let fmt = parse_object_format(&snap.object_format)?;
    let Some(plan) = snap.segments.plan_tiered_merge(request.shard_id, &request.policy)? else {
        return Ok(CompactionRunOutcome::NoWorkDue);
    };

    let total_serving_bytes: u64 = snap.serving_packs.iter().map(CompactionPackEntry::physical_pair_bytes).sum();
    let scratch_need =
        total_serving_bytes.saturating_mul(2).saturating_add(plan.estimated_input_bytes.saturating_mul(2)).max(1);
    let _job_permit =
        budget.reserve_job(plan.input_packs.len(), plan.estimated_input_bytes, scratch_need, deadline).await?;
    let _retention_guard = request
        .retention_registry
        .map(|reg| {
            let entries: Vec<_> = snap
                .serving_packs
                .iter()
                .filter_map(|p| {
                    let (pl, il) = (p.pack_locator.to_locator().ok()?, p.idx_locator.to_locator().ok()?);
                    Some(PackDigestEntry::from_locators(&p.pack_stem, &pl, &il))
                })
                .collect();
            reg.pin_pack_entries(&entries)
        })
        .transpose()
        .map_err(CompactionError::from)?;
    let op_id = request.op_id_override.unwrap_or_else(Uuid::new_v4);
    authority
        .record_checkpoint(PendingOperationRecord {
            op_id,
            key: lease_token.key.clone(),
            fence_epoch: lease_token.fence_epoch,
            expected_membership_generation: snap.membership_generation,
            phase: CompactionPhase::Claimed,
        })
        .await?;

    let view_bytes = total_serving_bytes.saturating_mul(4).max(4 << 20);
    let scratch_lease = view_root
        .create_view("rubicon-compact", request.tenant_id, request.repo_id, view_bytes, None)
        .map_err(CompactionError::from)?;
    let work = scratch_lease.dir_path().map_err(CompactionError::from)?.to_path_buf();
    let (before_dir, shard_dir, cand_dir, after_dir, out_dir, rb_dir) = (
        work.join("before.git"),
        work.join("shard.git"),
        work.join("cand-check.git"),
        work.join("after.git"),
        work.join("pack-out"),
        work.join("readback"),
    );
    for d in [&before_dir, &shard_dir, &cand_dir, &after_dir, &out_dir, &rb_dir] {
        std::fs::create_dir_all(d).map_err(|e| CompactionError::Io(e.to_string()))?;
    }

    authority.verify_lease_active(lease_token, current_now_ms(request.now_ms, started_at)).await?;
    let _git_permit = budget.acquire_git_slot(deadline).await?;
    populate_bare_with_entries(store, &before_dir, fmt, &snap.serving_packs, false, deadline).await?;
    let (before_oids, before_closure) =
        install_refs_verify_and_measure(&before_dir, &snap.refs, &snap.retention_roots, deadline).await?;

    populate_bare_with_entries(store, &shard_dir, fmt, &plan.input_packs, true, deadline).await?;
    let (shard_oids, shard_obj_count) = collect_object_ids(&shard_dir, deadline).await?;
    let prefix = out_dir.join("pack");
    let prefix_str =
        prefix.to_str().ok_or_else(|| CompactionError::InvalidInput("non-utf8 pack output path".into()))?;
    // Run pack-objects on `before_dir` so cross-pack delta bases remain self-contained without merging unrelated shards.
    run_compaction_git(Some(&before_dir), &["pack-objects", "-q", prefix_str], Some(shard_oids.as_bytes()), deadline)
        .await?;
    let (cand_pack_path, cand_idx_path) = locate_single_pack_pair(&out_dir)?;
    let (compacted_obj_count, delta_obj_count) =
        verify_pack_self_contained(fmt, &cand_pack_path, &cand_idx_path, &cand_dir, deadline).await?;
    let (cand_pack_sha, cand_pack_len) = sha256_file_and_len(&cand_pack_path).await?;
    let (cand_idx_sha, cand_idx_len) = sha256_file_and_len(&cand_idx_path).await?;
    let cand_stem = cand_pack_path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| CompactionError::InvalidInput("missing stem".into()))?
        .to_owned();

    let retired_ids: HashSet<Uuid> = plan.input_packs.iter().map(|p| p.pack_id).collect();
    let remaining: Vec<_> = snap.serving_packs.iter().filter(|p| !retired_ids.contains(&p.pack_id)).cloned().collect();
    populate_bare_with_entries(store, &after_dir, fmt, &remaining, false, deadline).await?;
    let dst_pack_dir = after_dir.join("objects/pack");
    tokio::fs::copy(&cand_pack_path, dst_pack_dir.join(format!("{cand_stem}.pack")))
        .await
        .map_err(|e| CompactionError::Io(e.to_string()))?;
    tokio::fs::copy(&cand_idx_path, dst_pack_dir.join(format!("{cand_stem}.idx")))
        .await
        .map_err(|e| CompactionError::Io(e.to_string()))?;
    let (after_oids, after_closure) =
        install_refs_verify_and_measure(&after_dir, &snap.refs, &snap.retention_roots, deadline).await?;
    if after_oids != before_oids || after_closure != before_closure {
        return Err(CompactionError::EquivalenceFailed(
            "candidate pack broke repository OID set or retention closure".into(),
        )
        .into());
    }
    let clone_ok = if !snap.refs.is_empty() {
        let clone_dir = work.join("clone-check.git");
        let (src_s, dst_s) = (
            after_dir.to_str().ok_or_else(|| CompactionError::InvalidInput("non-utf8 path".into()))?,
            clone_dir.to_str().ok_or_else(|| CompactionError::InvalidInput("non-utf8 path".into()))?,
        );
        run_compaction_git(None, &["clone", "--no-local", "--bare", "--quiet", src_s, dst_s], None, deadline).await?;
        run_compaction_git(Some(&clone_dir), &["fsck", "--full", "--strict"], None, deadline).await?;
        true
    } else {
        false
    };
    let proof = CompactionEquivalenceProof {
        object_format: fmt,
        total_object_count: before_oids.len(),
        shard_input_object_count: shard_obj_count,
        compacted_output_object_count: compacted_obj_count,
        delta_objects_self_contained: delta_obj_count,
        delta_bases_verified: true,
        oid_set_digest: hash_string_lines(&before_oids),
        closure_digest: before_closure,
        retention_roots_verified: snap.retention_roots.len(),
        refs_digest: snap.refs_digest.clone(),
        fsck_verified: true,
        clone_verified: clone_ok,
    };

    authority.verify_lease_active(lease_token, current_now_ms(request.now_ms, started_at)).await?;
    if matches!(request.fault_hook, CompactionFaultHook::CrashBeforeUpload) {
        return Err(LeasedAttemptError::CrashInjected(CompactionError::Io("injected crash before Blob upload".into())));
    }
    drop(_git_permit);
    let uploaded = uploader
        .upload_pack_pair(
            store,
            request.tenant_id,
            request.repo_id,
            request.blob_generation,
            &cand_pack_path,
            &cand_idx_path,
            deadline,
        )
        .await?;
    verify_and_readback_pair(
        store,
        &uploaded.pack_locator,
        &cand_pack_sha,
        cand_pack_len,
        &uploaded.idx_locator,
        &cand_idx_sha,
        cand_idx_len,
        &rb_dir,
        deadline,
    )
    .await?;

    let replacement_pack = CompactionPackEntry::from_locators(
        Uuid::new_v4(),
        &cand_stem,
        &uploaded.pack_locator,
        &uploaded.idx_locator,
        snap.membership_generation.saturating_add(1),
        snap.shard_count,
    )?;
    if replacement_pack.shard_id != shard_for_pack_hash(&cand_pack_sha, snap.shard_count)? {
        return Err(CompactionError::EquivalenceFailed("replacement pack shard mismatch".into()).into());
    }
    authority
        .record_checkpoint(PendingOperationRecord {
            op_id,
            key: lease_token.key.clone(),
            fence_epoch: lease_token.fence_epoch,
            expected_membership_generation: snap.membership_generation,
            phase: CompactionPhase::CandidateUploaded {
                pack_id: replacement_pack.pack_id,
                pack_path: uploaded.pack_locator.path(),
                idx_path: uploaded.idx_locator.path(),
            },
        })
        .await?;

    if matches!(request.fault_hook, CompactionFaultHook::CrashAfterUploadBeforePublish) {
        return Err(LeasedAttemptError::CrashInjected(CompactionError::Io(
            "injected crash after verified upload before CAS publish".into(),
        )));
    }
    if let CompactionFaultHook::StallBeforePublish { delay_ms } = request.fault_hook {
        tokio::time::sleep(Duration::from_millis(delay_ms)).await;
    }
    let publish_now = current_now_ms(request.now_ms, started_at);
    authority.inject_fault(&request.fault_hook, &lease_token.key, publish_now, &request.policy).await?;

    let publish_req = CompactionPublishRequest {
        op_id,
        tenant_id: request.tenant_id,
        repo_id: request.repo_id,
        history_id: request.history_id,
        authority_epoch: snap.authority_epoch,
        shard_id: request.shard_id,
        lease_id: lease_token.lease_id,
        fence_epoch: lease_token.fence_epoch,
        expected_membership_generation: snap.membership_generation,
        expected_pack_set_digest: snap.pack_set_digest.clone(),
        expected_refs_digest: snap.refs_digest.clone(),
        expected_retention_roots_digest: snap.retention_roots_digest.clone(),
        retired_pack_ids: plan.input_packs.iter().map(|p| p.pack_id).collect(),
        replacement_pack: replacement_pack.clone(),
        merge_plan: plan.clone(),
        equivalence_proof_digest: proof.canonical_digest(),
        equivalence_proof: proof.clone(),
        delete_disabled: true,
    };
    let receipt =
        authority.cas_publish_compaction(&publish_req, current_now_ms(request.now_ms, started_at), false).await?;
    if matches!(request.fault_hook, CompactionFaultHook::DropPublishAck) {
        return Err(LeasedAttemptError::CrashInjected(CompactionError::Io(
            "simulated dropped ACK after durable RefStore CAS publish".into(),
        )));
    }
    Ok(CompactionRunOutcome::Published(Box::new(PublishedCompaction {
        op_id,
        plan,
        replacement_pack,
        proof,
        receipt,
        attempts: 1,
    })))
}

fn current_now_ms(base_now_ms: u64, started_at: Instant) -> u64 {
    base_now_ms.saturating_add(started_at.elapsed().as_millis() as u64)
}

fn replay_outcome(op_id: Uuid, receipt: CompactionPublishReceipt) -> CompactionRunOutcome {
    CompactionRunOutcome::Published(Box::new(PublishedCompaction {
        op_id,
        plan: receipt.merge_plan.clone(),
        replacement_pack: receipt.replacement_pack.clone(),
        proof: receipt.equivalence_proof.clone(),
        receipt,
        attempts: 1,
    }))
}
