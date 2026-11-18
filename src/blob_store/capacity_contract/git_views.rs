//! Disposable-view verification and no-delete compaction workflows.

use std::{collections::BTreeMap, fs, time::Instant};

use uuid::Uuid;

use super::git_ops::{
    GitOpsError, GitProcessLimits, GitStdin, GitViewLimits, ObjectFormat, PackDownloadRef, UploadScope,
    UploadedPackPair, dir_size_bytes, populate_bare_view, run_git, upload_pack_pair,
};
use crate::blob_store::{disposable_view::DisposableViewRoot, opendal::BlobStore};

pub(super) const INTERNAL_PIN_REF_ROOT: &str = "refs/pando-pins";
pub(super) const INTERNAL_PIN_REF_PREFIX: &str = "refs/pando-pins/";

pub(super) fn is_reserved_ref_name(ref_name: &str) -> bool {
    ref_name == INTERNAL_PIN_REF_ROOT || ref_name.starts_with(INTERNAL_PIN_REF_PREFIX)
}

pub struct VerifyViewInput<'a> {
    pub store: &'a BlobStore,
    pub view_root: &'a DisposableViewRoot,
    pub tenant_id: Uuid,
    pub authority_id: Uuid,
    pub format: ObjectFormat,
    pub packs: &'a [PackDownloadRef],
    pub refs: &'a BTreeMap<String, String>,
    pub pinned_oids: &'a [String],
    pub max_objects: u64,
    pub max_total_bytes: u64,
    pub max_single_object_bytes: u64,
    pub max_view_logical_bytes: u64,
    pub process_limits: GitProcessLimits,
    pub full_fsck: bool,
}

pub struct VerifiedViewSummary {
    pub total_objects: u64,
    pub blob_get_bytes: u64,
    pub peak_scratch_bytes: u64,
}

pub struct CompactViewInput<'a> {
    pub store: &'a BlobStore,
    pub view_root: &'a DisposableViewRoot,
    pub tenant_id: Uuid,
    pub authority_id: Uuid,
    pub generation: i64,
    pub format: ObjectFormat,
    pub packs: &'a [PackDownloadRef],
    pub refs: &'a BTreeMap<String, String>,
    pub pinned_oids: &'a [String],
    pub max_objects: u64,
    pub max_total_bytes: u64,
    pub max_single_object_bytes: u64,
    pub max_view_logical_bytes: u64,
    pub process_limits: GitProcessLimits,
}

pub struct CompactedViewSummary {
    pub uploaded: UploadedPackPair,
    pub blob_get_bytes: u64,
    pub peak_scratch_bytes: u64,
    pub oid_count: usize,
}

fn view_reserved_bytes(packs: &[PackDownloadRef]) -> u64 {
    packs.iter().map(|p| p.pack_length.saturating_add(p.idx_length)).sum::<u64>().saturating_mul(2).max(4096)
}

fn validate_client_refs(format: ObjectFormat, refs: &BTreeMap<String, String>) -> Result<(), GitOpsError> {
    for (ref_name, oid) in refs {
        if is_reserved_ref_name(ref_name) {
            return Err(GitOpsError::InvalidPack("reserved internal pin ref namespace"));
        }
        if !format.is_valid_oid(oid) {
            return Err(GitOpsError::InvalidPack("ref target OID mismatches repository object format"));
        }
    }
    Ok(())
}

async fn verify_unpacked_object_bounds(
    repo_dir: &std::path::Path,
    max_single_object_bytes: u64,
    max_view_logical_bytes: u64,
    limits: GitProcessLimits,
    deadline: Instant,
) -> Result<(), GitOpsError> {
    let raw = run_git(
        repo_dir,
        &["cat-file", "--batch-all-objects", "--batch-check=%(objectsize)"],
        GitStdin::Null,
        limits,
        deadline,
    )
    .await?;
    let text = std::str::from_utf8(&raw).map_err(|_| GitOpsError::InvalidPack("non-utf8 cat-file size output"))?;
    let mut expanded_total = 0u64;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let sz: u64 = trimmed.parse().map_err(|_| GitOpsError::InvalidPack("invalid unpacked object size"))?;
        if sz > max_single_object_bytes {
            return Err(GitOpsError::LimitExceeded("unpacked object exceeds max_single_object_bytes"));
        }
        expanded_total = expanded_total.saturating_add(sz);
        if expanded_total > max_view_logical_bytes {
            return Err(GitOpsError::LimitExceeded("expanded objects exceed verifier view workspace bound"));
        }
    }
    Ok(())
}

pub async fn verify_frontier_in_view(
    input: VerifyViewInput<'_>,
    deadline: Instant,
) -> Result<VerifiedViewSummary, GitOpsError> {
    validate_client_refs(input.format, input.refs)?;
    let lease = input.view_root.create_view(
        "pando-cap-verify",
        input.tenant_id,
        input.authority_id,
        view_reserved_bytes(input.packs),
        None,
    )?;
    let limits = GitViewLimits {
        max_objects: input.max_objects,
        max_total_bytes: input.max_total_bytes,
        process: input.process_limits,
    };
    let res = async {
        let (repo_dir, total_objects, blob_get_bytes, mut peak_scratch) =
            populate_bare_view(&lease, input.store, input.format, input.packs, limits, deadline).await?;
        if total_objects > 0 {
            verify_unpacked_object_bounds(
                &repo_dir,
                input.max_single_object_bytes,
                input.max_view_logical_bytes,
                input.process_limits,
                deadline,
            )
            .await?;
        }
        if !input.refs.is_empty() || !input.pinned_oids.is_empty() {
            let mut oids_input = String::new();
            for (ref_name, oid) in input.refs {
                run_git(
                    &repo_dir,
                    &["update-ref", "--no-deref", ref_name, oid],
                    GitStdin::Null,
                    input.process_limits,
                    deadline,
                )
                .await?;
                oids_input.push_str(oid);
                oids_input.push('\n');
            }
            for (idx, oid) in input.pinned_oids.iter().enumerate() {
                if !input.format.is_valid_oid(oid) {
                    return Err(GitOpsError::InvalidPack("pinned OID mismatches repository object format"));
                }
                let pin_ref = format!("{INTERNAL_PIN_REF_PREFIX}pin-{idx:04}");
                run_git(
                    &repo_dir,
                    &["update-ref", "--no-deref", &pin_ref, oid],
                    GitStdin::Null,
                    input.process_limits,
                    deadline,
                )
                .await?;
                oids_input.push_str(oid);
                oids_input.push('\n');
            }
            let checked = run_git(
                &repo_dir,
                &["cat-file", "--batch-check=%(objectname) %(objecttype)"],
                GitStdin::Bytes(oids_input.as_bytes()),
                input.process_limits,
                deadline,
            )
            .await?;
            let text = std::str::from_utf8(&checked).map_err(|_| GitOpsError::InvalidPack("non-utf8 cat-file"))?;
            for line in text.lines() {
                if line.ends_with(" missing") {
                    return Err(GitOpsError::InvalidPack("ref target object is missing from verified pack closure"));
                }
            }
            let fsck_args = if input.full_fsck {
                &["fsck", "--full", "--strict", "--no-progress"][..]
            } else {
                &["fsck", "--connectivity-only", "--no-dangling", "--no-progress"][..]
            };
            run_git(&repo_dir, fsck_args, GitStdin::Null, input.process_limits, deadline).await?;
        }
        peak_scratch = peak_scratch.max(dir_size_bytes(lease.dir_path()?));
        Ok(VerifiedViewSummary { total_objects, blob_get_bytes, peak_scratch_bytes: peak_scratch })
    }
    .await;
    lease.reap();
    res
}

pub async fn compact_packs_in_view(
    input: CompactViewInput<'_>,
    deadline: Instant,
) -> Result<CompactedViewSummary, GitOpsError> {
    validate_client_refs(input.format, input.refs)?;
    let lease = input.view_root.create_view(
        "pando-cap-compact",
        input.tenant_id,
        input.authority_id,
        view_reserved_bytes(input.packs),
        None,
    )?;
    let limits = GitViewLimits {
        max_objects: input.max_objects,
        max_total_bytes: input.max_total_bytes,
        process: input.process_limits,
    };
    let res = async {
        let (repo_dir, total_objects, blob_get_bytes, mut peak_scratch) =
            populate_bare_view(&lease, input.store, input.format, input.packs, limits, deadline).await?;
        if total_objects > 0 {
            verify_unpacked_object_bounds(
                &repo_dir,
                input.max_single_object_bytes,
                input.max_view_logical_bytes,
                input.process_limits,
                deadline,
            )
            .await?;
        }
        for (ref_name, oid) in input.refs {
            run_git(
                &repo_dir,
                &["update-ref", "--no-deref", ref_name, oid],
                GitStdin::Null,
                input.process_limits,
                deadline,
            )
            .await?;
        }
        for (idx, oid) in input.pinned_oids.iter().enumerate() {
            if !input.format.is_valid_oid(oid) {
                return Err(GitOpsError::InvalidPack("pinned OID mismatches repository object format"));
            }
            let pin_ref = format!("{INTERNAL_PIN_REF_PREFIX}pin-{idx:04}");
            run_git(
                &repo_dir,
                &["update-ref", "--no-deref", &pin_ref, oid],
                GitStdin::Null,
                input.process_limits,
                deadline,
            )
            .await?;
        }

        let pre_raw =
            run_git(&repo_dir, &["rev-list", "--objects", "--all"], GitStdin::Null, input.process_limits, deadline)
                .await?;
        let mut pre_oids: Vec<&str> =
            std::str::from_utf8(&pre_raw).map_err(|_| GitOpsError::InvalidPack("non-utf8 rev-list"))?.lines().collect();
        pre_oids.sort_unstable();
        pre_oids.dedup();

        run_git(
            &repo_dir,
            &[
                "-c",
                "pack.threads=1",
                "-c",
                "pack.writeReverseIndex=false",
                "repack",
                "-a",
                "-d",
                "--no-write-bitmap-index",
            ],
            GitStdin::Null,
            input.process_limits,
            deadline,
        )
        .await?;
        run_git(
            &repo_dir,
            &["fsck", "--full", "--strict", "--no-progress"],
            GitStdin::Null,
            input.process_limits,
            deadline,
        )
        .await?;

        let post_raw =
            run_git(&repo_dir, &["rev-list", "--objects", "--all"], GitStdin::Null, input.process_limits, deadline)
                .await?;
        let mut post_oids: Vec<&str> = std::str::from_utf8(&post_raw)
            .map_err(|_| GitOpsError::InvalidPack("non-utf8 rev-list"))?
            .lines()
            .collect();
        post_oids.sort_unstable();
        post_oids.dedup();
        if pre_oids != post_oids {
            return Err(GitOpsError::InvalidPack("compaction changed reachable object closure"));
        }

        let pack_dir = repo_dir.join("objects").join("pack");
        let mut pack_file = None;
        let mut idx_file = None;
        for entry in fs::read_dir(&pack_dir).map_err(|e| GitOpsError::Io(e.to_string()))? {
            let path = entry.map_err(|e| GitOpsError::Io(e.to_string()))?.path();
            if path.extension().and_then(|e| e.to_str()) == Some("pack") {
                pack_file = Some(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("idx") {
                idx_file = Some(path);
            }
        }
        let (Some(pack_path), Some(idx_path)) = (pack_file, idx_file) else {
            return Err(GitOpsError::InvalidPack("compaction did not emit one canonical pack+idx pair"));
        };
        let uploaded = upload_pack_pair(
            input.store,
            UploadScope { tenant_id: input.tenant_id, authority_id: input.authority_id, generation: input.generation },
            &pack_path,
            &idx_path,
            deadline,
        )
        .await?;
        peak_scratch = peak_scratch.max(dir_size_bytes(lease.dir_path()?));
        Ok(CompactedViewSummary {
            uploaded,
            blob_get_bytes,
            peak_scratch_bytes: peak_scratch,
            oid_count: post_oids.len(),
        })
    }
    .await;
    lease.reap();
    res
}
