//! Constructs real #184 `CoverHierarchyIndex`, `RetentionClassificationIndex`,
//! `FetchPlan`, and unforgeable `VerifiedFetchPlanProof` bound to authorized
//! advertised refs and verified whole-pack object closures.

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::Path,
};

use uuid::Uuid;

use crate::{
    blob_store::BlobLocator,
    ref_store::{
        GitObjectFormat, GitOid, RefName,
        contract::RequestDigest,
        ref_version::{
            AuthorityKind, CausalVersionNode, PackSetEntry, ReadConsumer, RefHead, RefVersionRealm,
            VerifiedClosurePack, VersionGraph, VersionId, VersionRecord,
            pack_cover::{
                AuthorizationContext, CoverArtifactPair, CoverCommitLink, CoverHierarchyIndex, CoverHierarchyRecord,
                CoverHierarchyRecordInput, CoverRetentionHold, CoverTier, FetchPlan, FetchPlanOutcome,
                FetchPlanRequest, HaveSpec, PhysicalBlobStatus, ReadIsolationMode, RetentionClassificationIndex,
                StrongSnapshotCut, VerifiedFetchPlanProof, WantTarget, compute_cover_membership_digest,
                plan_fetch_covers, verify_fetch_plan_closure,
            },
        },
    },
};

pub use super::cover_git::{HelperResourceLimits, build_residual_pack_bytes, run_git_bounded};
use super::{
    cover_git::{discover_repo_packs, internal_err, seal_synth_version},
    planner::PackWireMeta,
    types::{DownloadSubjectContext, FallbackReason, PackObjectFormat, PackfileUriError},
};

/// Verified `#184` artifacts, whole-pack closure sets, and raw bytes from a materialized bare Git view.
pub struct MaterializedCoverBundle {
    pub auth: AuthorizationContext,
    pub plan: FetchPlan,
    pub proof: VerifiedFetchPlanProof,
    pub cover_index: CoverHierarchyIndex,
    pub retention_index: RetentionClassificationIndex,
    pub wire_packs: HashMap<Uuid, PackWireMeta>,
    pub raw_pack_bytes: HashMap<String, Vec<u8>>,
    pub pack_defined_oids: HashMap<String, HashSet<String>>,
    pub wanted_closure_oids: HashSet<String>,
    pub rejected_unauthorized_pack: bool,
}

/// Outcome of verifying advertised-ref `wants` and whole-pack closure over a bare Git view.
pub enum CoverBuildOutcome {
    Planned(Box<MaterializedCoverBundle>),
    Fallback(FallbackReason),
}

/// Inputs identifying the materialized bare repository, authorized advertised refs, and resource limits.
pub struct RepoCoverBuildParams<'a> {
    pub git_binary: &'a Path,
    pub repo_dir: &'a Path,
    pub advertised_refs: &'a [(String, String)],
    pub wants: &'a [String],
    pub haves: &'a [String],
    pub include_tag: bool,
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub history_incarnation: Uuid,
    pub authority_epoch: u64,
    pub group_epoch: u64,
    pub object_format: GitObjectFormat,
    pub subject: DownloadSubjectContext,
    pub provider: &'a str,
    pub backend_identity_hex: &'a str,
    pub limits: HelperResourceLimits,
}

async fn collect_bounded_object_closure(
    git_bin: &Path,
    repo_dir: &Path,
    roots: &[String],
    limits: &HelperResourceLimits,
) -> Result<HashSet<String>, PackfileUriError> {
    let mut stdin_buf = String::new();
    for r in roots {
        stdin_buf.push_str(r);
        stdin_buf.push('\n');
    }
    let raw = run_git_bounded(
        git_bin,
        repo_dir,
        &["rev-list", "--objects", "--stdin"],
        Some(stdin_buf.as_bytes()),
        limits.max_stdout_bytes,
        limits.timeout,
    )
    .await?;
    let mut set = HashSet::new();
    for line in String::from_utf8_lossy(&raw).lines() {
        let Some(oid) = line.split_whitespace().next() else { continue };
        set.insert(oid.to_owned());
        if set.len() > limits.max_closure_objects {
            return Err(PackfileUriError::CapacityExceeded("reachable object closure exceeds bound".to_owned()));
        }
    }
    Ok(set)
}

/// Builds and verifies a `#184` [`VerifiedFetchPlanProof`] bound strictly to `advertised_refs`.
pub async fn build_verified_cover_proof_from_repo(
    params: &RepoCoverBuildParams<'_>,
) -> Result<CoverBuildOutcome, PackfileUriError> {
    params.subject.validate()?;
    if params.advertised_refs.is_empty() || params.wants.is_empty() {
        return Ok(CoverBuildOutcome::Fallback(FallbackReason::IncompleteClosure));
    }
    let pack_fmt = match params.object_format {
        GitObjectFormat::Sha1 => PackObjectFormat::Sha1,
        GitObjectFormat::Sha256 => PackObjectFormat::Sha256,
    };

    let mut adv_oid_to_ref: BTreeMap<String, RefName> = BTreeMap::new();
    let mut adv_root_oids: Vec<String> = Vec::new();
    for (ref_str, oid_hex) in params.advertised_refs {
        let Ok(rname) = RefName::new(ref_str.clone()) else {
            return Ok(CoverBuildOutcome::Fallback(FallbackReason::IncompleteClosure));
        };
        if GitOid::parse(params.object_format, oid_hex).is_err() {
            return Ok(CoverBuildOutcome::Fallback(FallbackReason::IncompleteClosure));
        }
        if !adv_oid_to_ref.contains_key(oid_hex) {
            adv_oid_to_ref.insert(oid_hex.clone(), rname);
            adv_root_oids.push(oid_hex.clone());
        }
    }

    if params.include_tag
        && params
            .advertised_refs
            .iter()
            .any(|(r, oid)| r.starts_with("refs/tags/") && !params.wants.iter().any(|w| w == oid))
    {
        return Ok(CoverBuildOutcome::Fallback(FallbackReason::UnsupportedFetchArgs));
    }

    let mut want_commit_hexes = Vec::new();
    for w in params.wants {
        if !adv_oid_to_ref.contains_key(w) {
            return Ok(CoverBuildOutcome::Fallback(FallbackReason::UnadvertisedWant));
        }
        let Ok(kind_raw) =
            run_git_bounded(params.git_binary, params.repo_dir, &["cat-file", "-t", w], None, 64, params.limits.timeout)
                .await
        else {
            return Ok(CoverBuildOutcome::Fallback(FallbackReason::IncompleteClosure));
        };
        if String::from_utf8_lossy(&kind_raw).trim() != "commit" {
            return Ok(CoverBuildOutcome::Fallback(FallbackReason::IncompleteClosure));
        }
        if !want_commit_hexes.contains(w) {
            want_commit_hexes.push(w.clone());
        }
    }

    let advertised_closure_oids =
        collect_bounded_object_closure(params.git_binary, params.repo_dir, &adv_root_oids, &params.limits).await?;
    let wanted_closure_oids =
        collect_bounded_object_closure(params.git_binary, params.repo_dir, &want_commit_hexes, &params.limits).await?;
    if wanted_closure_oids.is_empty() || !wanted_closure_oids.is_subset(&advertised_closure_oids) {
        return Ok(CoverBuildOutcome::Fallback(FallbackReason::UnadvertisedWant));
    }

    let mut rev_in = String::new();
    for wc in &want_commit_hexes {
        rev_in.push_str(wc);
        rev_in.push('\n');
    }
    let rev_raw = run_git_bounded(
        params.git_binary,
        params.repo_dir,
        &["rev-list", "--topo-order", "--reverse", "--parents", "--stdin"],
        Some(rev_in.as_bytes()),
        params.limits.max_stdout_bytes,
        params.limits.timeout,
    )
    .await?;
    let mut ordered_commits = Vec::new();
    let mut commit_parents: HashMap<String, Vec<String>> = HashMap::new();
    for line in String::from_utf8_lossy(&rev_raw).lines() {
        let mut parts = line.split_whitespace();
        let Some(c) = parts.next() else { continue };
        ordered_commits.push(c.to_owned());
        if ordered_commits.len() > params.limits.max_closure_commits {
            return Err(PackfileUriError::CapacityExceeded("commit closure exceeds bound".to_owned()));
        }
        commit_parents.insert(c.to_owned(), parts.map(str::to_owned).collect());
    }

    let mut packs = discover_repo_packs(params.git_binary, params.repo_dir, pack_fmt, &params.limits).await?;
    if ordered_commits.is_empty() || packs.is_empty() {
        return Ok(CoverBuildOutcome::Fallback(FallbackReason::IncompleteClosure));
    }
    let pos_map: HashMap<&str, usize> = ordered_commits.iter().enumerate().map(|(i, c)| (c.as_str(), i)).collect();
    packs.sort_by_key(|p| p.commits.iter().filter_map(|c| pos_map.get(c.as_str()).copied()).min().unwrap_or(usize::MAX));

    let realm = RefVersionRealm::new(
        params.tenant_id,
        params.repository_id,
        params.history_incarnation,
        AuthorityKind::Pg,
        i64::try_from(params.authority_epoch.max(1)).unwrap_or(1),
        0,
        i64::try_from(params.group_epoch.max(1)).unwrap_or(1),
        params.object_format,
    );
    let mut auth = AuthorizationContext::for_realm(&realm, params.subject.actor_id, params.subject.token_id);
    auth.auth_epoch = params.subject.auth_epoch;
    auth.min_valid_auth_epoch = params.subject.auth_epoch;

    let init_mem = compute_cover_membership_digest(&realm, 1, &[]).map_err(internal_err)?;
    let mut cover_index = CoverHierarchyIndex::new(realm, init_mem).map_err(internal_err)?;
    let mut graph = VersionGraph::new();
    let mut retention = RetentionClassificationIndex::new();
    let mut entries: Vec<PackSetEntry> = Vec::new();
    let mut wire_packs: HashMap<Uuid, PackWireMeta> = HashMap::new();
    let mut raw_pack_bytes: HashMap<String, Vec<u8>> = HashMap::new();
    let mut pack_defined_oids: HashMap<String, HashSet<String>> = HashMap::new();
    let mut commit_ver_map: HashMap<String, VersionId> = HashMap::new();

    let synth_ref = RefName::new("refs/heads/__packfile_uri_closure").map_err(internal_err)?;
    let mut assigned: HashSet<String> = HashSet::new();
    let mut prev_ver: Option<VersionRecord> = None;
    let mut all_cover_ids: Vec<Uuid> = Vec::new();
    let mut rejected_unauthorized_pack = false;
    let mut seq = 0i64;

    for dp in packs {
        let mut group: Vec<String> = dp
            .commits
            .iter()
            .filter(|c| pos_map.contains_key(c.as_str()) && !assigned.contains(*c))
            .cloned()
            .collect();
        if group.is_empty() {
            continue;
        }
        group.sort_by_key(|c| pos_map[c.as_str()]);
        for c in &group {
            assigned.insert(c.clone());
        }
        seq += 1;
        let tip_oid = GitOid::parse(params.object_format, group.last().unwrap()).map_err(internal_err)?;
        let pack_loc = BlobLocator::new(
            params.tenant_id,
            params.repository_id,
            1,
            Uuid::new_v4(),
            "packs",
            &dp.pack_sha256_hex,
            dp.pack_bytes.len() as u64,
        )
        .map_err(internal_err)?;
        let idx_loc = BlobLocator::new(
            params.tenant_id,
            params.repository_id,
            1,
            Uuid::new_v4(),
            "packs",
            &dp.idx_sha256_hex,
            dp.idx_len,
        )
        .map_err(internal_err)?;
        let pse = PackSetEntry::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            RequestDigest::of("packfile-uri-art", &[dp.pack_sha256_hex.as_bytes(), dp.idx_sha256_hex.as_bytes()]),
        )
        .map_err(internal_err)?;
        let vcp = VerifiedClosurePack::new(
            pse,
            params.tenant_id,
            params.repository_id,
            params.provider,
            params.backend_identity_hex,
            pack_loc.length() + idx_loc.length(),
            dp.object_count as u64,
        )
        .map_err(internal_err)?;

        let deps: Vec<VersionId> = prev_ver.as_ref().map(VersionRecord::version_id).into_iter().collect();
        let ver = seal_synth_version(&realm, &synth_ref, seq, prev_ver.as_ref(), deps, tip_oid, &[pse])?;
        let vid = ver.version_id();
        graph.insert_active(CausalVersionNode { record: ver.clone(), own_packs: vec![vcp.clone()] });
        entries.push(pse);
        let next_gen = cover_index.membership_generation() + 1;
        let mem = compute_cover_membership_digest(&realm, next_gen, &entries).map_err(internal_err)?;
        let mut links = Vec::with_capacity(group.len());
        for ch in &group {
            commit_ver_map.insert(ch.clone(), vid);
            let coid = GitOid::parse(params.object_format, ch).map_err(internal_err)?;
            let p_oids = commit_parents
                .get(ch)
                .into_iter()
                .flatten()
                .filter(|p| pos_map.contains_key(p.as_str()))
                .map(|p| GitOid::parse(params.object_format, p).map_err(internal_err))
                .collect::<Result<Vec<_>, _>>()?;
            links.push(CoverCommitLink { commit_oid: coid, parent_oids: p_oids, version_id: vid, authority_seq: seq });
        }
        let whole_pack_in_authorized_wants = dp.object_count > 0
            && dp.defined_oids.len() == dp.object_count
            && dp
                .defined_oids
                .iter()
                .all(|oid| wanted_closure_oids.contains(oid) && advertised_closure_oids.contains(oid));
        if !whole_pack_in_authorized_wants {
            rejected_unauthorized_pack = true;
        }
        let delta_bases = if dp.is_standalone { Vec::new() } else { all_cover_ids.clone() };
        let cover_id = Uuid::new_v4();
        let cov = CoverHierarchyRecord::seal(CoverHierarchyRecordInput {
            cover_id,
            realm,
            tier: CoverTier::Delta,
            pack: vcp,
            artifacts: CoverArtifactPair {
                pack_stem: format!("pack-{}", dp.pack_hash_hex),
                pack_locator: pack_loc,
                idx_locator: idx_loc,
                is_thin_pack: !delta_bases.is_empty(),
                delta_base_cover_ids: delta_bases,
            },
            covered_versions: vec![vid],
            min_authority_seq: seq,
            max_authority_seq: seq,
            covered_commits: links,
            input_cover_ids: Vec::new(),
            membership_generation: next_gen,
            membership_digest: mem,
            compaction_epoch: cover_index.compaction_epoch(),
            worker_id: Uuid::new_v4(),
            operation_id: Uuid::new_v4(),
        })
        .map_err(internal_err)?;
        cover_index.register_leaf_cover(cov, mem).map_err(internal_err)?;
        retention.set_physical_status(pse.pack_id(), PhysicalBlobStatus::Present);
        if dp.is_standalone && whole_pack_in_authorized_wants {
            wire_packs.insert(
                pse.pack_id(),
                PackWireMeta {
                    pack_oid: dp.pack_oid.clone(),
                    pack_hash_hex: dp.pack_hash_hex,
                    sha256_hex: dp.pack_sha256_hex,
                    byte_len: dp.pack_bytes.len() as u64,
                    object_count: dp.object_count,
                    all_objects_authorized: true,
                    cache_warm: true,
                },
            );
            raw_pack_bytes.insert(dp.pack_oid.clone(), dp.pack_bytes);
            pack_defined_oids.insert(dp.pack_oid, dp.defined_oids);
        }
        all_cover_ids.push(cover_id);
        prev_ver = Some(ver);
    }

    let Some(tip_ver) = prev_ver else {
        return Ok(CoverBuildOutcome::Fallback(FallbackReason::IncompleteClosure));
    };
    if assigned.len() != ordered_commits.len() {
        return Ok(CoverBuildOutcome::Fallback(FallbackReason::IncompleteClosure));
    }
    let mut heads = BTreeMap::new();
    heads.insert(synth_ref.clone(), RefHead::from_committed(&tip_ver).map_err(internal_err)?);
    retention.add_hold(CoverRetentionHold::ActiveRefHead {
        ref_name: synth_ref.clone(),
        version_id: tip_ver.version_id(),
        cover_ids: all_cover_ids,
    });

    let mut want_targets = Vec::with_capacity(want_commit_hexes.len());
    for wc in &want_commit_hexes {
        let w_oid = GitOid::parse(params.object_format, wc).map_err(internal_err)?;
        let Some(&owner_vid) = commit_ver_map.get(wc) else {
            return Ok(CoverBuildOutcome::Fallback(FallbackReason::IncompleteClosure));
        };
        let Some(real_ref) = adv_oid_to_ref.get(wc).cloned() else {
            return Ok(CoverBuildOutcome::Fallback(FallbackReason::UnadvertisedWant));
        };
        if real_ref == synth_ref {
            return Ok(CoverBuildOutcome::Fallback(FallbackReason::UnadvertisedWant));
        }
        seq += 1;
        let w_ver = seal_synth_version(&realm, &real_ref, seq, None, vec![owner_vid], w_oid, &[])?;
        graph.insert_active(CausalVersionNode { record: w_ver.clone(), own_packs: Vec::new() });
        heads.insert(real_ref.clone(), RefHead::from_committed(&w_ver).map_err(internal_err)?);
        want_targets.push(WantTarget::Ref { ref_name: real_ref });
    }

    let cut = StrongSnapshotCut {
        authority_seq: seq,
        snapshot_digest: RequestDigest::of("packfile-uri-cut", &[&seq.to_be_bytes()]),
        membership_digest: cover_index.membership_digest(),
        heads,
    };
    let have_oids = params
        .haves
        .iter()
        .filter(|h| pos_map.contains_key(h.as_str()))
        .filter_map(|h| GitOid::parse(params.object_format, h).ok())
        .collect();
    let mut plan_req =
        FetchPlanRequest::new(ReadConsumer::SmartHttpFetch, realm, auth.clone(), ReadIsolationMode::StrongSnapshot);
    plan_req.strong_cut = Some(cut.clone());
    plan_req.wants = want_targets;
    plan_req.haves = HaveSpec { have_oids, have_version_ids: Vec::new() };

    let Ok(FetchPlanOutcome::Planned(plan_box)) = plan_fetch_covers(&plan_req, &graph, &cover_index, &retention) else {
        return Ok(CoverBuildOutcome::Fallback(FallbackReason::IncompleteClosure));
    };
    let Ok(proof) = verify_fetch_plan_closure(
        &plan_box,
        ReadConsumer::SmartHttpFetch,
        &auth,
        Some(&cut),
        &graph,
        &cover_index,
        &retention,
    ) else {
        return Ok(CoverBuildOutcome::Fallback(FallbackReason::IncompleteClosure));
    };
    Ok(CoverBuildOutcome::Planned(Box::new(MaterializedCoverBundle {
        auth,
        plan: *plan_box,
        proof,
        cover_index,
        retention_index: retention,
        wire_packs,
        raw_pack_bytes,
        pack_defined_oids,
        wanted_closure_oids,
        rejected_unauthorized_pack,
    })))
}
