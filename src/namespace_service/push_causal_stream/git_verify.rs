//! Isolated stock-Git pack staging, thin-pack base resolution, and causal closure verification (#183).

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::blob_store::opendal::BlobStore;

use super::git_proc::{
    GitStdin, batch_check_objects, check_is_ancestor, init_isolated_bare_repo, list_idx_oids, run_git,
    verify_file_sha256_len,
};
use super::lfs_verify::verify_lfs_pointers;
use super::types::{
    AuthorizedSnapshotState, BasePackRef, BranchPolicy, GitSubprocessLimits, LfsPolicy, PushAuthContext,
    PushCausalError, PushedRefCommand, StreamIngestLimits,
};

/// Result of indexing and bounding the quarantined pack against verified authorized bases.
#[derive(Clone, Debug)]
pub struct VerifiedPackStage {
    pub view_dir: PathBuf,
    pub resolved_pack_path: PathBuf,
    pub resolved_idx_path: PathBuf,
    pub resolved_object_count: u64,
    pub delta_object_count: u64,
    pub max_delta_chain_depth: u32,
    pub duplicate_object_count: u64,
    pub total_unpacked_bytes: u64,
    pub resolved_thin_base_oids: Vec<String>,
    pub authorized_base_oids: BTreeSet<String>,
    pub authorized_tips: Vec<String>,
    pub base_get_bytes: u64,
}

/// Stage ONLY authorized, read-back-verified Blob base packs into an ephemeral `0700`
/// bare repository view and run `git index-pack --stdin --fix-thin --strict` + `verify-pack -v`.
pub async fn stage_and_index_quarantine_pack(
    view_dir: &Path,
    store: &BlobStore,
    snapshot: &AuthorizedSnapshotState,
    authorized_bases: &[&BasePackRef],
    incoming_pack_path: Option<&Path>,
    incoming_object_count: u32,
    ingest_limits: &StreamIngestLimits,
    proc_limits: &GitSubprocessLimits,
    deadline: Instant,
) -> Result<VerifiedPackStage, PushCausalError> {
    init_isolated_bare_repo(view_dir, snapshot.object_format, proc_limits, deadline).await?;
    let pack_dir = view_dir.join("objects/pack");
    let mut base_get_bytes = 0u64;
    let mut base_oids = BTreeSet::new();

    for (idx, base) in authorized_bases.iter().enumerate() {
        if !base.authorized_for_principal
            || base.pack_locator.tenant_id() != snapshot.tenant_id
            || base.pack_locator.authority_id() != snapshot.repository_id
            || base.idx_locator.tenant_id() != snapshot.tenant_id
            || base.idx_locator.authority_id() != snapshot.repository_id
        {
            return Err(PushCausalError::UnauthorizedBaseDependency(format!(
                "base pack version `{}` failed principal/tenant/repository authorization",
                base.version_id
            )));
        }
        let base_pack = pack_dir.join(format!("base-{idx}.pack"));
        let base_idx = pack_dir.join(format!("base-{idx}.idx"));
        store.get_to_file(&base.pack_locator, &base_pack, deadline).await?;
        store.get_to_file(&base.idx_locator, &base_idx, deadline).await?;
        verify_file_sha256_len(&base_pack, &base.pack_sha256, base.pack_length)?;
        verify_file_sha256_len(&base_idx, &base.idx_sha256, base.idx_length)?;
        base_get_bytes = base_get_bytes.saturating_add(base.pack_length).saturating_add(base.idx_length);
        base_oids.extend(list_idx_oids(view_dir, &base_idx, proc_limits, deadline).await?);
    }

    let authorized_tips: Vec<String> = snapshot
        .current_refs
        .values()
        .filter(|oid| !oid.bytes().all(|b| b == b'0'))
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let Some(incoming) = incoming_pack_path else {
        return Ok(VerifiedPackStage {
            view_dir: view_dir.to_path_buf(),
            resolved_pack_path: PathBuf::new(),
            resolved_idx_path: PathBuf::new(),
            resolved_object_count: 0,
            delta_object_count: 0,
            max_delta_chain_depth: 0,
            duplicate_object_count: 0,
            total_unpacked_bytes: 0,
            resolved_thin_base_oids: Vec::new(),
            authorized_base_oids: base_oids,
            authorized_tips,
            base_get_bytes,
        });
    };

    let resolved_pack_path = pack_dir.join("staged-quarantine.pack");
    let resolved_idx_path = pack_dir.join("staged-quarantine.idx");
    let resolved_str = resolved_pack_path.to_str().ok_or_else(|| PushCausalError::Io("non-utf8 pack path".into()))?;
    run_git(
        view_dir,
        &["index-pack", "--stdin", "--fix-thin", "--strict", resolved_str],
        GitStdin::File(incoming),
        proc_limits,
        deadline,
    )
    .await
    .map_err(map_index_pack_error)?;

    let parsed = inspect_verify_pack(view_dir, &resolved_idx_path, ingest_limits, proc_limits, deadline).await?;
    let resolved_thin_base_oids = extract_resolved_thin_bases(&parsed, &base_oids, incoming_object_count);
    if !resolved_thin_base_oids.is_empty() && (authorized_bases.is_empty() || snapshot.root_version_id.is_none()) {
        return Err(PushCausalError::UnauthorizedBaseDependency(
            "thin pack delta bases require verified non-empty authority snapshot closure".into(),
        ));
    }
    let duplicate_object_count = parsed.entries.iter().filter(|e| base_oids.contains(&e.oid)).count() as u64;

    Ok(VerifiedPackStage {
        view_dir: view_dir.to_path_buf(),
        resolved_pack_path,
        resolved_idx_path,
        resolved_object_count: parsed.entries.len() as u64,
        delta_object_count: parsed.delta_count,
        max_delta_chain_depth: parsed.max_depth,
        duplicate_object_count,
        total_unpacked_bytes: parsed.total_unpacked_bytes,
        resolved_thin_base_oids,
        authorized_base_oids: base_oids,
        authorized_tips,
        base_get_bytes,
    })
}

/// Verify causal closure, branch target types, fast-forward/force-push rules, and LFS pointers.
pub async fn verify_causal_closure_and_lfs(
    stage: &VerifiedPackStage,
    store: &BlobStore,
    snapshot: &AuthorizedSnapshotState,
    commands: &[PushedRefCommand],
    auth: &PushAuthContext,
    branch_policy: &BranchPolicy,
    lfs_policy: &LfsPolicy,
    limits: &StreamIngestLimits,
    proc_limits: &GitSubprocessLimits,
    deadline: Instant,
) -> Result<Vec<String>, PushCausalError> {
    let mut new_targets = Vec::new();
    let mut all_check_oids = Vec::new();
    for cmd in commands {
        if !cmd.is_create() {
            all_check_oids.push(cmd.old_oid.clone());
        }
        if !cmd.is_delete() {
            new_targets.push(cmd.new_oid.clone());
            all_check_oids.push(cmd.new_oid.clone());
        }
    }
    all_check_oids.extend(stage.authorized_tips.clone());
    all_check_oids.sort();
    all_check_oids.dedup();

    let obj_meta = if all_check_oids.is_empty() {
        Default::default()
    } else {
        batch_check_objects(&stage.view_dir, &all_check_oids, proc_limits, deadline).await?
    };

    for cmd in commands {
        if cmd.is_delete() {
            if !auth.allow_branch_delete && cmd.ref_name.starts_with("refs/heads/") {
                return Err(PushCausalError::BranchPolicyDenied(format!(
                    "branch delete denied for `{}`",
                    cmd.ref_name
                )));
            }
            if auth.protected_branches.contains(&cmd.ref_name) {
                return Err(PushCausalError::BranchPolicyDenied(format!(
                    "cannot delete protected branch `{}`",
                    cmd.ref_name
                )));
            }
            continue;
        }
        let meta = obj_meta.get(&cmd.new_oid).ok_or_else(|| {
            PushCausalError::MissingCausalObject(format!("target `{}` absent from verified pack closure", cmd.new_oid))
        })?;
        if cmd.ref_name.starts_with("refs/heads/") && branch_policy.require_commit_for_branches && meta.kind != "commit"
        {
            return Err(PushCausalError::MissingCausalObject(format!(
                "branch `{}` target `{}` is `{}` instead of commit",
                cmd.ref_name, cmd.new_oid, meta.kind
            )));
        }
        if !cmd.is_create() && cmd.ref_name.starts_with("refs/heads/") {
            let is_ff = check_is_ancestor(&stage.view_dir, &cmd.old_oid, &cmd.new_oid, proc_limits, deadline).await?;
            if !is_ff {
                let ff_only = auth.protected_branches.contains(&cmd.ref_name)
                    || branch_policy.fast_forward_only_prefixes.iter().any(|p| cmd.ref_name.starts_with(p));
                if ff_only || !auth.allow_force_push {
                    return Err(PushCausalError::BranchPolicyDenied(format!(
                        "non-fast-forward update denied on `{}`",
                        cmd.ref_name
                    )));
                }
            }
        }
    }

    if !new_targets.is_empty() {
        let mut fsck_args = vec!["fsck", "--full", "--strict", "--connectivity-only"];
        for target in &new_targets {
            fsck_args.push(target.as_str());
        }
        run_git(&stage.view_dir, &fsck_args, GitStdin::Null, proc_limits, deadline)
            .await
            .map_err(|e| PushCausalError::MissingCausalObject(format!("fsck connectivity failed: {e}")))?;
    }

    let mut rev_input = String::new();
    for target in &new_targets {
        rev_input.push_str(target);
        rev_input.push('\n');
    }
    for tip in &stage.authorized_tips {
        rev_input.push('^');
        rev_input.push_str(tip);
        rev_input.push('\n');
    }

    let mut required_ancestors = BTreeSet::new();
    if !new_targets.is_empty() {
        let out = run_git(
            &stage.view_dir,
            &["rev-list", "--objects", "--stdin"],
            GitStdin::Bytes(rev_input.as_bytes()),
            proc_limits,
            deadline,
        )
        .await?;
        let text = String::from_utf8(out).map_err(|e| PushCausalError::CorruptPack(e.to_string()))?;
        let introduced_oids: Vec<String> =
            text.lines().filter_map(|l| l.split_whitespace().next().map(str::to_owned)).collect();
        verify_lfs_pointers(
            &stage.view_dir,
            &introduced_oids,
            store,
            snapshot,
            lfs_policy,
            limits,
            proc_limits,
            deadline,
        )
        .await?;

        let parents_out = run_git(
            &stage.view_dir,
            &["rev-list", "--parents", "--stdin"],
            GitStdin::Bytes(rev_input.as_bytes()),
            proc_limits,
            deadline,
        )
        .await?;
        let ptext = String::from_utf8(parents_out).map_err(|e| PushCausalError::CorruptPack(e.to_string()))?;
        let introduced_set: BTreeSet<&str> = introduced_oids.iter().map(String::as_str).collect();
        for line in ptext.lines() {
            for p in line.split_whitespace().skip(1) {
                if !introduced_set.contains(p) {
                    required_ancestors.insert(p.to_owned());
                }
            }
        }
    }
    Ok(required_ancestors.into_iter().collect())
}

struct VerifyPackEntry {
    oid: String,
    offset: u64,
    base_oid: Option<String>,
}

struct ParsedVerifyPack {
    entries: Vec<VerifyPackEntry>,
    delta_count: u64,
    max_depth: u32,
    total_unpacked_bytes: u64,
}

async fn inspect_verify_pack(
    view_dir: &Path,
    idx_path: &Path,
    ingest_limits: &StreamIngestLimits,
    proc_limits: &GitSubprocessLimits,
    deadline: Instant,
) -> Result<ParsedVerifyPack, PushCausalError> {
    let idx_str = idx_path.to_str().ok_or_else(|| PushCausalError::Io("non-utf8 idx path".into()))?;
    let raw = run_git(view_dir, &["verify-pack", "-v", idx_str], GitStdin::Null, proc_limits, deadline).await?;
    let text = String::from_utf8(raw).map_err(|e| PushCausalError::CorruptPack(e.to_string()))?;
    let (mut entries, mut delta_count, mut max_depth, mut total_unpacked_bytes) = (Vec::new(), 0u64, 0u32, 0u64);

    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5
            || !parts[0].bytes().all(|b| b.is_ascii_hexdigit())
            || !matches!(parts[1], "commit" | "tree" | "blob" | "tag")
        {
            continue;
        }
        let unpacked: u64 =
            parts[2].parse().map_err(|_| PushCausalError::CorruptPack("invalid unpacked size".into()))?;
        let offset: u64 =
            parts[4].parse().map_err(|_| PushCausalError::CorruptPack("invalid verify-pack offset".into()))?;
        if unpacked > ingest_limits.max_unpacked_object_bytes {
            return Err(PushCausalError::LimitExceeded("unpacked object size exceeded max_unpacked_object_bytes"));
        }
        total_unpacked_bytes = total_unpacked_bytes
            .checked_add(unpacked)
            .ok_or(PushCausalError::LimitExceeded("total unpacked bytes overflowed"))?;
        if total_unpacked_bytes > ingest_limits.max_inflated_pack_bytes {
            return Err(PushCausalError::LimitExceeded("inflated pack payload exceeded max_inflated_pack_bytes"));
        }
        let mut base_oid = None;
        if parts.len() >= 7 {
            let depth: u32 =
                parts[5].parse().map_err(|_| PushCausalError::CorruptPack("invalid delta chain depth".into()))?;
            if depth > ingest_limits.max_delta_depth {
                return Err(PushCausalError::LimitExceeded("delta chain depth exceeded max_delta_depth"));
            }
            delta_count = delta_count.saturating_add(1);
            max_depth = max_depth.max(depth);
            base_oid = Some(parts[6].to_owned());
        }
        entries.push(VerifyPackEntry { oid: parts[0].to_owned(), offset, base_oid });
    }
    entries.sort_by_key(|e| e.offset);
    Ok(ParsedVerifyPack { entries, delta_count, max_depth, total_unpacked_bytes })
}

fn extract_resolved_thin_bases(
    parsed: &ParsedVerifyPack,
    base_oids: &BTreeSet<String>,
    incoming_count: u32,
) -> Vec<String> {
    let mut bases = BTreeSet::new();
    for (idx, entry) in parsed.entries.iter().enumerate() {
        if idx >= incoming_count as usize && base_oids.contains(&entry.oid) {
            bases.insert(entry.oid.clone());
        }
        if let Some(base) = &entry.base_oid
            && base_oids.contains(base)
        {
            bases.insert(base.clone());
        }
    }
    bases.into_iter().collect()
}

fn map_index_pack_error(err: PushCausalError) -> PushCausalError {
    if let PushCausalError::CorruptPack(ref msg) = err {
        let low = msg.to_ascii_lowercase();
        if low.contains("unresolved delta") || low.contains("base") || low.contains("did not receive expected object") {
            return PushCausalError::MissingDeltaBase(msg.clone());
        }
    }
    err
}
