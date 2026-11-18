//! Production `blob_git_gateway::receive` object-level causal dependency closure prover (#183).
//!
//! Executes real stock-Git pack/index/object closure verification on incoming HTTP `receive-pack`
//! streams BEFORE Ref-CAS admission AND deterministically over committed `BlobStore` pairs for
//! durable post-restart `CausalPushProofReceipt` replay.

use std::collections::{BTreeSet, VecDeque};
use std::fs;
use std::path::Path;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use uuid::Uuid;

use crate::blob_git_gateway::GatewayError;
use crate::blob_store::opendal::BlobStore;
use crate::ref_store::core::terminal::RefCommitResult;
use crate::ref_store::core::types::GitObjectFormat;

use super::gateway_bridge::GatewayClosureContext;
use super::gateway_prover_pack::{
    extract_and_check_wire_pack, inspect_verify_pack_bin, verify_reachability_and_ancestors,
};
use super::git_proc::{
    GitStdin, init_isolated_bare_repo_bin, list_idx_oids_bin, run_git_bin, sha256_and_len_sync, verify_file_sha256_len,
};
use super::quarantine::QuarantineSlot;
use super::receipt::CommittedPackPairProof;
use super::types::{BasePackRef, GitSubprocessLimits, PushCausalError, StreamIngestLimits};

const MAX_REJECTION_RING: usize = 64;

static CAUSAL_REJECTIONS: OnceLock<Mutex<VecDeque<(Uuid, String)>>> = OnceLock::new();

fn rejection_ring() -> &'static Mutex<VecDeque<(Uuid, String)>> {
    CAUSAL_REJECTIONS.get_or_init(|| Mutex::new(VecDeque::with_capacity(MAX_REJECTION_RING)))
}

fn record_causal_rejection(operation_id: Uuid, reason: impl Into<String>) {
    let mut guard = rejection_ring().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if guard.len() >= MAX_REJECTION_RING {
        guard.pop_front();
    }
    guard.push_back((operation_id, reason.into()));
}

/// Inspect the causal object-closure refusal recorded for a rejected HTTP `receive-pack` operation.
pub fn recent_gateway_causal_rejection(operation_id: Uuid) -> Option<String> {
    let guard = rejection_ring().lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    guard.iter().rev().find(|(op, _)| *op == operation_id).map(|(_, r)| r.clone())
}

/// Verified object-level causal closure metrics for a push operation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GatewayObjectClosureProof {
    pub object_count: u64,
    pub delta_object_count: u64,
    pub max_delta_chain_depth: u32,
    pub duplicate_object_count: u64,
    pub required_ancestor_oids: Vec<String>,
    pub resolved_thin_base_oids: Vec<String>,
}

/// Arguments for pre-CAS object-level causal closure verification on `receive-pack`.
pub struct GatewayIncomingProofArgs<'a> {
    pub operation_id: Uuid,
    pub git_binary: &'a Path,
    pub scratch_root: Option<&'a Path>,
    pub view_repo: &'a Path,
    pub request_path: &'a Path,
    pub pack_offset: usize,
    pub closure: &'a GatewayClosureContext,
    pub target_oids: &'a [String],
    pub deadline: tokio::time::Instant,
}

/// Verify that all base packs in `view_repo` match `closure` and that the incoming `PACK` stream's
/// thin-pack delta bases and commit/tree/blob ancestors resolve strictly within `(incoming ∪ closure)`
/// BEFORE native `receive-pack` or Ref-CAS admission runs.
pub async fn prove_gateway_incoming_pack_closure(
    args: GatewayIncomingProofArgs<'_>,
) -> Result<GatewayObjectClosureProof, GatewayError> {
    let std_dl = to_std_deadline(args.deadline)?;
    let proc_limits = GitSubprocessLimits::default();
    let ingest_limits = StreamIngestLimits::default();

    let proof_tmp = QuarantineSlot::create(args.scratch_root)
        .map_err(|_| GatewayError::Internal("could not create causal proof sandbox"))?;
    init_isolated_bare_repo_bin(
        args.git_binary,
        proof_tmp.dir(),
        args.closure.snapshot.object_format,
        &proc_limits,
        std_dl,
    )
    .await
    .map_err(|_| GatewayError::Internal("could not initialize causal proof bare repo"))?;

    let base_oids = stage_verified_view_bases(
        args.git_binary,
        args.view_repo,
        proof_tmp.dir(),
        &args.closure.snapshot.authorized_base_packs,
        &proc_limits,
        std_dl,
    )
    .await
    .map_err(|e| {
        record_causal_rejection(args.operation_id, format!("base_pack_verification_failed: {e}"));
        GatewayError::BadRequest("base pack set failed causal closure verification")
    })?;

    let incoming_path = proof_tmp.dir().join("incoming.pack");
    let maybe_count = extract_and_check_wire_pack(
        args.request_path,
        args.pack_offset,
        &incoming_path,
        args.closure.snapshot.object_format,
        &ingest_limits,
    )
    .map_err(|reason| {
        record_causal_rejection(args.operation_id, reason);
        GatewayError::BadRequest("push pack stream failed header or checksum verification")
    })?;

    let authorized_tips: Vec<String> = args
        .closure
        .snapshot
        .current_refs
        .values()
        .filter(|oid| !oid.bytes().all(|b| b == b'0'))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let mut proof = GatewayObjectClosureProof::default();
    if let Some(declared_count) = maybe_count
        && declared_count > 0
    {
        let resolved_idx = proof_tmp.dir().join("objects/pack/incoming.idx");
        let resolved_pack = proof_tmp.dir().join("objects/pack/incoming.pack");
        fs::rename(&incoming_path, &resolved_pack)
            .map_err(|_| GatewayError::Internal("could not move incoming pack into proof sandbox"))?;
        let idx_str = resolved_idx.to_str().ok_or(GatewayError::Internal("non-utf8 proof idx"))?;
        let pack_str = resolved_pack.to_str().ok_or(GatewayError::Internal("non-utf8 proof pack"))?;
        run_git_bin(
            args.git_binary,
            proof_tmp.dir(),
            &["index-pack", "--fix-thin", "--strict", "-o", idx_str, pack_str],
            GitStdin::Null,
            &proc_limits,
            std_dl,
        )
        .await
        .map_err(|e| {
            record_causal_rejection(args.operation_id, format!("unresolved_thin_base_or_corrupt_pack: {e}"));
            GatewayError::BadRequest("push pack failed causal thin-base closure verification")
        })?;

        let vp = inspect_verify_pack_bin(
            args.git_binary,
            proof_tmp.dir(),
            &resolved_idx,
            &ingest_limits,
            &proc_limits,
            std_dl,
        )
        .await
        .map_err(|e| {
            record_causal_rejection(args.operation_id, format!("verify_pack_failed: {e}"));
            GatewayError::BadRequest("push pack failed verify-pack inspection")
        })?;
        proof.object_count = vp.entries.len() as u64;
        proof.delta_object_count = vp.delta_count;
        proof.max_delta_chain_depth = vp.max_depth;
        let mut thin_bases = BTreeSet::new();
        for (i, entry) in vp.entries.iter().enumerate() {
            if i < declared_count as usize && base_oids.contains(&entry.oid) {
                proof.duplicate_object_count = proof.duplicate_object_count.saturating_add(1);
            }
            if i >= declared_count as usize {
                if !base_oids.contains(&entry.oid) {
                    record_causal_rejection(args.operation_id, format!("unverified_thin_base: {}", entry.oid));
                    return Err(GatewayError::BadRequest("thin pack resolved against unverified base object"));
                }
                thin_bases.insert(entry.oid.clone());
            }
            if let Some(b) = &entry.base_oid
                && base_oids.contains(b)
            {
                thin_bases.insert(b.clone());
            }
        }
        proof.resolved_thin_base_oids = thin_bases.into_iter().collect();
    }

    if !args.target_oids.is_empty() {
        proof.required_ancestor_oids = verify_reachability_and_ancestors(
            args.git_binary,
            proof_tmp.dir(),
            args.target_oids,
            &authorized_tips,
            &base_oids,
            &proc_limits,
            std_dl,
        )
        .await
        .map_err(|e| {
            record_causal_rejection(args.operation_id, format!("unresolved_causal_ancestor: {e}"));
            GatewayError::BadRequest("push commit graph has unresolved causal object dependency")
        })?;
    }
    Ok(proof)
}

/// Arguments for deterministic object-level closure proof over committed `BlobStore` pairs.
pub struct CommittedBlobProofArgs<'a> {
    pub git_binary: &'a Path,
    pub scratch_root: Option<&'a Path>,
    pub store: &'a BlobStore,
    pub format: GitObjectFormat,
    pub base_packs: &'a [BasePackRef],
    pub base_tips: &'a [String],
    pub committed_pairs: &'a [CommittedPackPairProof],
    pub terminal_refs: &'a [RefCommitResult],
    pub deadline: Instant,
}

/// Deterministic object-level causal closure prover over committed `BlobStore` `.pack`/`.idx` pairs
/// and historical `base_revision` base packs (produces identical metrics on fresh settle & restart replay).
pub async fn prove_committed_blob_pairs_closure(
    args: CommittedBlobProofArgs<'_>,
) -> Result<GatewayObjectClosureProof, PushCausalError> {
    let CommittedBlobProofArgs {
        git_binary,
        scratch_root,
        store,
        format,
        base_packs,
        base_tips,
        committed_pairs,
        terminal_refs,
        deadline,
    } = args;
    let proof_tmp = QuarantineSlot::create(scratch_root)?;
    let proc_limits = GitSubprocessLimits::default();
    let ingest_limits = StreamIngestLimits::default();
    init_isolated_bare_repo_bin(git_binary, proof_tmp.dir(), format, &proc_limits, deadline).await?;
    let pack_dir = proof_tmp.dir().join("objects/pack");

    let mut base_oids = BTreeSet::new();
    for (i, base) in base_packs.iter().enumerate() {
        let bp = pack_dir.join(format!("base-{i}.pack"));
        let bi = pack_dir.join(format!("base-{i}.idx"));
        store.get_to_file(&base.pack_locator, &bp, deadline).await?;
        store.get_to_file(&base.idx_locator, &bi, deadline).await?;
        verify_file_sha256_len(&bp, &base.pack_sha256, base.pack_length)?;
        verify_file_sha256_len(&bi, &base.idx_sha256, base.idx_length)?;
        base_oids.extend(list_idx_oids_bin(git_binary, proof_tmp.dir(), &bi, &proc_limits, deadline).await?);
    }

    let mut proof = GatewayObjectClosureProof::default();
    let mut thin_bases = BTreeSet::new();
    for (j, pair) in committed_pairs.iter().enumerate() {
        let (Some(p_loc), Some(i_loc)) = (&pair.pack_locator, &pair.idx_locator) else { continue };
        let op_p = pack_dir.join(format!("op-{j}.pack"));
        let op_i = pack_dir.join(format!("op-{j}.idx"));
        store.get_to_file(p_loc, &op_p, deadline).await?;
        store.get_to_file(i_loc, &op_i, deadline).await?;
        verify_file_sha256_len(&op_p, &pair.pack_sha256, pair.pack_bytes)?;
        verify_file_sha256_len(&op_i, &pair.idx_sha256, pair.idx_bytes)?;

        let vp =
            inspect_verify_pack_bin(git_binary, proof_tmp.dir(), &op_i, &ingest_limits, &proc_limits, deadline).await?;
        proof.object_count = proof.object_count.saturating_add(vp.entries.len() as u64);
        proof.delta_object_count = proof.delta_object_count.saturating_add(vp.delta_count);
        proof.max_delta_chain_depth = proof.max_delta_chain_depth.max(vp.max_depth);
        for entry in &vp.entries {
            if base_oids.contains(&entry.oid) {
                proof.duplicate_object_count = proof.duplicate_object_count.saturating_add(1);
            }
            if let Some(b) = &entry.base_oid
                && base_oids.contains(b)
            {
                thin_bases.insert(b.clone());
            }
        }
    }
    proof.resolved_thin_base_oids = thin_bases.into_iter().collect();

    let targets: Vec<String> = terminal_refs
        .iter()
        .filter_map(|r| match r {
            RefCommitResult::Applied { new_oid: Some(oid), .. } => Some(oid.clone()),
            _ => None,
        })
        .collect();
    if !targets.is_empty() {
        proof.required_ancestor_oids = verify_reachability_and_ancestors(
            git_binary,
            proof_tmp.dir(),
            &targets,
            base_tips,
            &base_oids,
            &proc_limits,
            deadline,
        )
        .await?;
    }
    Ok(proof)
}

async fn stage_verified_view_bases(
    git_bin: &Path,
    view_repo: &Path,
    proof_repo: &Path,
    expected: &[BasePackRef],
    proc_limits: &GitSubprocessLimits,
    deadline: Instant,
) -> Result<BTreeSet<String>, PushCausalError> {
    let src_dir = view_repo.join("objects/pack");
    let dst_dir = proof_repo.join("objects/pack");
    let mut local_pairs = Vec::new();
    if let Ok(rd) = fs::read_dir(&src_dir) {
        for ent in rd {
            let ent = ent.map_err(|e| PushCausalError::Io(e.to_string()))?;
            let path = ent.path();
            if path.extension().and_then(|s| s.to_str()) != Some("pack") {
                continue;
            }
            let idx = path.with_extension("idx");
            let (p_sha, p_len) = sha256_and_len_sync(&path)?;
            let (i_sha, i_len) = sha256_and_len_sync(&idx)?;
            let authorized = expected.iter().any(|b| {
                b.pack_sha256 == p_sha && b.pack_length == p_len && b.idx_sha256 == i_sha && b.idx_length == i_len
            });
            if !authorized {
                return Err(PushCausalError::UnauthorizedBaseDependency("unverified local base pack in view".into()));
            }
            local_pairs.push((path, idx));
        }
    }
    if local_pairs.len() != expected.len() {
        return Err(PushCausalError::UnauthorizedBaseDependency("view base pack count disagrees with snapshot".into()));
    }
    local_pairs.sort_by(|a, b| a.0.cmp(&b.0));
    let mut base_oids = BTreeSet::new();
    for (i, (p, idx)) in local_pairs.iter().enumerate() {
        let dp = dst_dir.join(format!("base-{i}.pack"));
        let di = dst_dir.join(format!("base-{i}.idx"));
        fs::copy(p, &dp).map_err(|e| PushCausalError::Io(e.to_string()))?;
        fs::copy(idx, &di).map_err(|e| PushCausalError::Io(e.to_string()))?;
        base_oids.extend(list_idx_oids_bin(git_bin, proof_repo, &di, proc_limits, deadline).await?);
    }
    Ok(base_oids)
}

fn to_std_deadline(dl: tokio::time::Instant) -> Result<Instant, GatewayError> {
    let now = tokio::time::Instant::now();
    let rem = dl.checked_duration_since(now).filter(|d| *d > Duration::ZERO).ok_or(GatewayError::Timeout)?;
    Ok(Instant::now() + rem)
}
