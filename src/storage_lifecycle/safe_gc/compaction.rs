//! Two-phase read-back verified Blob compaction with no-delete retirement (#122).

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    time::Instant,
};

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::blob_store::{disposable_view::DisposableViewRoot, opendal::BlobStore};

use super::{
    SafeGcError,
    domain::{CasCompactionPublish, CompactionPublishResult, SafeGcCompactionUploader},
    git_ops::{
        build_self_contained_pack_from_sources, download_and_verify_pair, sha256_file_and_len,
        verify_readback_pack_closure,
    },
    model::{DecisionState, GlobalHoldState, LiveRefRoot, encode_len_bytes},
    store::{DurableSafeGcAuthority, SafeGcRepoSnapshot, ServingPackRecord},
};

#[derive(Clone, Debug)]
pub enum CompactionFault {
    None,
    ConcurrentRefBeforeCas(LiveRefRoot),
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
    let inputs = select_input_packs(&snap, &req.target_pack_ids)?;
    let refs: Vec<(String, String)> =
        snap.live_refs.iter().map(|r| (r.ref_name.clone(), r.target_oid.clone())).collect();
    let extra_roots = collect_retained_roots(&snap);

    let view = req.view_root.create_view(
        "safe-gc-compact",
        snap.authority.tenant_id,
        snap.authority.repo_id,
        64 * 1024 * 1024,
        None,
    )?;
    let root = view.dir_path()?.to_path_buf();
    let in_dir = root.join("inputs");
    let work_repo = root.join("work.git");
    let stage_prefix = root.join("stage").join("compacted");
    let readback_dir = root.join("readback");
    let verify_repo = root.join("verify.git");
    for d in [&in_dir, &readback_dir] {
        tokio::fs::create_dir_all(d).await.map_err(|e| SafeGcError::Io(e.to_string()))?;
    }

    let (source_pairs, old_pack_bytes) = download_input_packs(store, &inputs, &in_dir, req.deadline).await?;
    let (new_pack_path, new_idx_path, closure_oids) = build_self_contained_pack_from_sources(
        &work_repo,
        &source_pairs,
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
    if uploaded.pack_locator.sha256 != pack_sha256
        || uploaded.pack_locator.length != new_pack_bytes
        || uploaded.idx_locator.sha256 != idx_sha256
        || uploaded.idx_locator.length != idx_len
    {
        return Err(SafeGcError::CompactionVerificationFailed(
            "uploaded locator digest/length disagrees with staged pack".into(),
        ));
    }

    // Phase 1b: Read back uploaded blobs directly through BlobStore and verify full closure before CAS!
    let pk_loc = uploaded.pack_locator.to_locator()?;
    let ix_loc = uploaded.idx_locator.to_locator()?;
    let (rb_pack, rb_idx) = download_and_verify_pair(store, &pk_loc, &ix_loc, &readback_dir, req.deadline).await?;
    verify_readback_pack_closure(
        &verify_repo,
        (&rb_pack, &rb_idx),
        (&refs, &extra_roots),
        &closure_oids,
        snap.object_format,
        req.deadline,
    )
    .await?;

    match req.fault {
        CompactionFault::None => {}
        CompactionFault::ConcurrentRefBeforeCas(r) => authority.register_concurrent_ref(r)?,
        CompactionFault::RotateIncarnationBeforeCas => {
            let _ = authority.rotate_incarnation()?;
        }
    }
    let live_after = authority.snapshot();
    if live_after.authority.live_ref_seq != snap.authority.live_ref_seq {
        return Err(SafeGcError::MembershipOrRootDrift(
            "live refs mutated during compaction; keeping prior closure active".into(),
        ));
    }

    let eq_digest = compute_equivalence_digest(&closure_oids, &pack_sha256, &idx_sha256);
    let retired_ids: Vec<Uuid> = inputs.iter().map(|p| p.pack_id).collect();
    let publish = authority.cas_publish_compaction(CasCompactionPublish {
        op_id: req.op_id,
        group_id: req.group_id.to_owned(),
        expected_incarnation_id: snap.authority.incarnation_id,
        expected_incarnation_epoch: snap.authority.incarnation_epoch,
        expected_generation: snap.authority.membership_generation,
        retired_pack_ids: retired_ids,
        uploaded,
        replacement_oids: closure_oids.clone(),
        equivalence_digest: eq_digest,
    })?;

    Ok(SafeGcCompactionResult { publish, compacted_object_count: closure_oids.len(), old_pack_bytes, new_pack_bytes })
}

fn select_input_packs(snap: &SafeGcRepoSnapshot, targets: &[Uuid]) -> Result<Vec<ServingPackRecord>, SafeGcError> {
    let selected: Vec<_> = if targets.is_empty() {
        snap.active_packs.clone()
    } else {
        snap.active_packs.iter().filter(|p| targets.contains(&p.pack_id)).cloned().collect()
    };
    if selected.is_empty() {
        return Err(SafeGcError::InvalidInput("no active packs selected for compaction".into()));
    }
    Ok(selected)
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

async fn download_input_packs(
    store: &BlobStore,
    inputs: &[ServingPackRecord],
    in_dir: &Path,
    deadline: Instant,
) -> Result<(Vec<(PathBuf, PathBuf)>, u64), SafeGcError> {
    let mut pairs = Vec::with_capacity(inputs.len());
    let mut old_bytes = 0_u64;
    for (idx, item) in inputs.iter().enumerate() {
        let sub = in_dir.join(format!("p-{idx}"));
        tokio::fs::create_dir_all(&sub).await.map_err(|e| SafeGcError::Io(e.to_string()))?;
        let pk = item.pack_locator.to_locator()?;
        let ix = item.idx_locator.to_locator()?;
        old_bytes = old_bytes.saturating_add(pk.length());
        pairs.push(download_and_verify_pair(store, &pk, &ix, &sub, deadline).await?);
    }
    Ok((pairs, old_bytes))
}

fn compute_equivalence_digest(oids: &[String], pack_sha: &str, idx_sha: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"safe-gc-eq-v1|");
    encode_len_bytes(&mut h, pack_sha.as_bytes());
    encode_len_bytes(&mut h, idx_sha.as_bytes());
    h.update((oids.len() as u64).to_be_bytes());
    for oid in oids {
        encode_len_bytes(&mut h, oid.as_bytes());
    }
    hex::encode(h.finalize())
}
