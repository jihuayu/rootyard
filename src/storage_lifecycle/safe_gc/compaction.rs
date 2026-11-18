//! Two-phase read-back verified Blob compaction with no-delete retirement (#122).

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::blob_store::{
    disposable_view::{DisposableViewRoot, TempViewLease},
    opendal::BlobStore,
};

use super::{
    SafeGcError,
    domain::{CasCompactionPublish, CompactionPublishResult, SafeGcCompactionUploader},
    git_ops::{
        build_self_contained_pack_from_sources, download_and_verify_pair, sha256_file_and_len,
        verify_readback_pack_closure,
    },
    model::{DecisionState, GlobalHoldEntry, GlobalHoldState, LiveRefRoot, encode_len_bytes},
    store::{DurableSafeGcAuthority, SafeGcRepoSnapshot, ServingPackRecord},
};

#[derive(Clone, Debug)]
pub enum CompactionFault {
    None,
    ConcurrentRefBeforeCas(LiveRefRoot),
    AttachHoldBeforeCas(GlobalHoldEntry),
    RotateIncarnationBeforeCas,
}

#[derive(Clone)]
pub struct SafeGcCompactionRequest<'a> {
    pub op_id: Uuid,
    pub group_id: &'a str,
    pub blob_generation: i64,
    pub target_pack_ids: Vec<Uuid>,
    pub view_root: &'a DisposableViewRoot,
    pub deadline: Instant,
    pub fault: CompactionFault,
}

#[derive(Clone, Debug)]
pub struct SafeGcCompactionResult {
    pub publish: CompactionPublishResult,
    pub compacted_object_count: usize,
    pub old_pack_bytes: u64,
    pub new_pack_bytes: u64,
}

pub async fn execute_two_phase_compaction(
    authority: &DurableSafeGcAuthority,
    store: &BlobStore,
    uploader: &dyn SafeGcCompactionUploader,
    req: SafeGcCompactionRequest<'_>,
) -> Result<SafeGcCompactionResult, SafeGcError> {
    let snap = authority.snapshot();
    let expected_membership_digest = snap.compute_membership_digest();
    let (inputs, unselected) = select_input_and_kept_packs(&snap, &req.target_pack_ids)?;
    let refs: Vec<(String, String)> =
        snap.live_refs.iter().map(|r| (r.ref_name.clone(), r.target_oid.clone())).collect();
    let extra_roots = collect_retained_roots(&snap);

    let view = Arc::new(req.view_root.create_view(
        "safe-gc-compact",
        snap.authority.tenant_id,
        snap.authority.repo_id,
        64 * 1024 * 1024,
        None,
    )?);
    let root = view.dir_path()?.to_path_buf();
    let (in_dir, keep_dir) = (root.join("inputs"), root.join("kept"));
    let (work_repo, verify_repo) = (root.join("work.git"), root.join("verify.git"));
    let (stage_prefix, readback_dir) = (root.join("stage").join("compacted"), root.join("readback"));
    for d in [&in_dir, &keep_dir, &readback_dir] {
        tokio::fs::create_dir_all(d).await.map_err(|e| SafeGcError::Io(e.to_string()))?;
    }

    let (source_pairs, old_pack_bytes) =
        download_pack_list(store, &inputs, &in_dir, Arc::clone(&view), req.deadline).await?;
    let (kept_pairs, _) = download_pack_list(store, &unselected, &keep_dir, Arc::clone(&view), req.deadline).await?;
    let (new_pack_path, new_idx_path, closure_oids) = build_self_contained_pack_from_sources(
        &work_repo,
        &source_pairs,
        &kept_pairs,
        (&refs, &extra_roots),
        &stage_prefix,
        snap.object_format,
        req.deadline,
    )
    .await?;

    let (pack_sha256, new_pack_bytes) = sha256_file_and_len(&new_pack_path).await?;
    let (idx_sha256, idx_len) = sha256_file_and_len(&new_idx_path).await?;
    let (pack_key, idx_key) =
        authority.mint_compaction_keys(snap.authority.incarnation_epoch, &pack_sha256, &idx_sha256)?;

    let uploaded = uploader
        .upload_compacted_pair(
            store,
            (snap.authority.tenant_id, snap.authority.repo_id, req.blob_generation),
            (pack_key, idx_key),
            (&new_pack_path, &new_idx_path),
            req.deadline,
        )
        .await?;
    authority.record_staged_upload(req.op_id, &uploaded)?;

    let post_upload = async {
        if uploaded.pack_locator.sha256 != pack_sha256
            || uploaded.pack_locator.length != new_pack_bytes
            || uploaded.idx_locator.sha256 != idx_sha256
            || uploaded.idx_locator.length != idx_len
        {
            return Err(SafeGcError::CompactionVerificationFailed(
                "uploaded locator digest/length disagrees with staged pack".into(),
            ));
        }

        // Phase 1b: Read back uploaded blobs through BlobStore keeping Arc<TempViewLease> alive!
        let pk_loc = uploaded.pack_locator.to_locator()?;
        let ix_loc = uploaded.idx_locator.to_locator()?;
        let (rb_pack, rb_idx) =
            download_and_verify_pair(store, &pk_loc, &ix_loc, &readback_dir, Arc::clone(&view), req.deadline).await?;
        verify_readback_pack_closure(
            &verify_repo,
            (&rb_pack, &rb_idx),
            &kept_pairs,
            (&refs, &extra_roots),
            &closure_oids,
            snap.object_format,
            req.deadline,
        )
        .await?;

        match req.fault {
            CompactionFault::None => {}
            CompactionFault::ConcurrentRefBeforeCas(r) => authority.register_concurrent_ref(r)?,
            CompactionFault::AttachHoldBeforeCas(h) => authority.upsert_global_hold(h)?,
            CompactionFault::RotateIncarnationBeforeCas => {
                let _ = authority.rotate_incarnation()?;
            }
        }
        let live_after = authority.snapshot();
        if live_after.authority.live_ref_seq != snap.authority.live_ref_seq
            || collect_retained_roots(&live_after) != extra_roots
        {
            return Err(SafeGcError::MembershipOrRootDrift(
                "live refs or retention roots mutated during compaction; keeping prior closure active".into(),
            ));
        }
        let retired_ids: Vec<Uuid> = inputs.iter().map(|p| p.pack_id).collect();
        let pinned_after = live_after.directly_pinned_pack_ids();
        if retired_ids.iter().any(|id| pinned_after.contains(id)) {
            return Err(SafeGcError::ProtectionOverlap(
                "input pack pinned concurrently during compaction; keeping prior closure active".into(),
            ));
        }

        let eq_digest = compute_equivalence_digest(&closure_oids, &pack_sha256, &idx_sha256);
        let publish = authority.cas_publish_compaction(CasCompactionPublish {
            op_id: req.op_id,
            group_id: req.group_id.to_owned(),
            expected_incarnation_id: snap.authority.incarnation_id,
            expected_incarnation_epoch: snap.authority.incarnation_epoch,
            expected_generation: snap.authority.membership_generation,
            expected_membership_digest,
            retired_pack_ids: retired_ids,
            uploaded,
            replacement_oids: closure_oids.clone(),
            equivalence_digest: eq_digest,
        })?;
        Ok(SafeGcCompactionResult {
            publish,
            compacted_object_count: closure_oids.len(),
            old_pack_bytes,
            new_pack_bytes,
        })
    }
    .await;

    if post_upload.is_err() {
        let _ = authority.mark_staged_upload_abandoned(req.op_id);
    }
    post_upload
}

fn select_input_and_kept_packs(
    snap: &SafeGcRepoSnapshot,
    targets: &[Uuid],
) -> Result<(Vec<ServingPackRecord>, Vec<ServingPackRecord>), SafeGcError> {
    let pinned = snap.directly_pinned_pack_ids();
    if !targets.is_empty() && targets.iter().any(|id| pinned.contains(id)) {
        return Err(SafeGcError::ProtectionOverlap(
            "explicitly targeted pack is directly pinned by hold/producer/reader".into(),
        ));
    }
    let mut selected = Vec::new();
    let mut unselected = Vec::new();
    for p in &snap.active_packs {
        let want = if targets.is_empty() { !pinned.contains(&p.pack_id) } else { targets.contains(&p.pack_id) };
        if want {
            selected.push(p.clone());
        } else {
            unselected.push(p.clone());
        }
    }
    if selected.is_empty() {
        if !snap.active_packs.is_empty() && targets.is_empty() {
            return Err(SafeGcError::ProtectionOverlap("all active packs are directly pinned".into()));
        }
        return Err(SafeGcError::InvalidInput("no active packs selected for compaction".into()));
    }
    Ok((selected, unselected))
}

fn collect_retained_roots(snap: &SafeGcRepoSnapshot) -> Vec<String> {
    let mut roots = BTreeSet::new();
    for p in &snap.producers {
        roots.extend(p.root_oids.iter().cloned());
    }
    for h in &snap.global_holds {
        if matches!(h.state, GlobalHoldState::Active | GlobalHoldState::Unknown) {
            roots.extend(h.protected_oids.iter().cloned());
        }
    }
    for d in &snap.in_flight_decisions {
        if matches!(d.state, DecisionState::Pending | DecisionState::Unknown) {
            roots.extend(d.protected_oids.iter().cloned());
        }
    }
    roots.into_iter().collect()
}

async fn download_pack_list(
    store: &BlobStore,
    items: &[ServingPackRecord],
    base_dir: &Path,
    view_owner: Arc<TempViewLease>,
    deadline: Instant,
) -> Result<(Vec<(PathBuf, PathBuf)>, u64), SafeGcError> {
    let mut pairs = Vec::with_capacity(items.len());
    let mut bytes_sum = 0_u64;
    for (idx, item) in items.iter().enumerate() {
        let sub = base_dir.join(format!("p-{idx}"));
        tokio::fs::create_dir_all(&sub).await.map_err(|e| SafeGcError::Io(e.to_string()))?;
        let pk = item.pack_locator.to_locator()?;
        let ix = item.idx_locator.to_locator()?;
        bytes_sum = bytes_sum.saturating_add(pk.length());
        pairs.push(download_and_verify_pair(store, &pk, &ix, &sub, Arc::clone(&view_owner), deadline).await?);
    }
    Ok((pairs, bytes_sum))
}

fn compute_equivalence_digest(oids: &[String], pack_sha: &str, idx_sha: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"safe-gc-eq-v2|");
    encode_len_bytes(&mut h, pack_sha.as_bytes());
    encode_len_bytes(&mut h, idx_sha.as_bytes());
    h.update((oids.len() as u64).to_be_bytes());
    for oid in oids {
        encode_len_bytes(&mut h, oid.as_bytes());
    }
    hex::encode(h.finalize())
}
