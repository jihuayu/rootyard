//! Git LFS pointer scanner and live remote Blob read-back byte proof (#183).

use std::path::Path;
use std::time::Instant;

use crate::blob_store::opendal::BlobStore;

use super::git_proc::{GitStdin, batch_check_objects, run_git};
use super::types::{AuthorizedSnapshotState, GitSubprocessLimits, LfsPolicy, PushCausalError, StreamIngestLimits};

pub(super) async fn verify_lfs_pointers(
    view_dir: &Path,
    introduced_oids: &[String],
    store: &BlobStore,
    snapshot: &AuthorizedSnapshotState,
    lfs_policy: &LfsPolicy,
    limits: &StreamIngestLimits,
    proc_limits: &GitSubprocessLimits,
    deadline: Instant,
) -> Result<(), PushCausalError> {
    if introduced_oids.is_empty() {
        return Ok(());
    }
    let meta = batch_check_objects(view_dir, introduced_oids, proc_limits, deadline).await?;
    let small_blobs: Vec<String> = meta
        .into_iter()
        .filter(|(_, m)| m.kind == "blob" && m.size <= limits.max_lfs_pointer_bytes)
        .map(|(oid, _)| oid)
        .collect();
    if small_blobs.is_empty() {
        return Ok(());
    }

    let mut req_input = String::new();
    for oid in &small_blobs {
        req_input.push_str(oid);
        req_input.push('\n');
    }
    let raw = run_git(view_dir, &["cat-file", "--batch"], GitStdin::Bytes(req_input.as_bytes()), proc_limits, deadline)
        .await?;
    let pointers = parse_batch_lfs_pointers(&raw)?;
    if pointers.is_empty() {
        return Ok(());
    }
    let LfsPolicy::RequireVerifiedBlobs { expected_blobs } = lfs_policy else {
        return Err(PushCausalError::LfsObjectMissingOrCorrupt(
            "push contains LFS pointers while LfsPolicy forbids unverified LFS objects".into(),
        ));
    };
    for (sha256, size) in pointers {
        let entry = expected_blobs.get(&sha256).ok_or_else(|| {
            PushCausalError::LfsObjectMissingOrCorrupt(format!("missing LFS object backing `{sha256}`"))
        })?;
        if entry.size != size
            || entry.locator.tenant_id() != snapshot.tenant_id
            || entry.locator.authority_id() != snapshot.repository_id
        {
            return Err(PushCausalError::LfsObjectMissingOrCorrupt(format!(
                "LFS object `{sha256}` size or tenant/repository scope mismatch"
            )));
        }
        store
            .verify_receipt(&entry.locator, &sha256, size, deadline)
            .await
            .map_err(|e| PushCausalError::LfsObjectMissingOrCorrupt(format!("LFS verify failed: {e}")))?;
    }
    Ok(())
}

fn parse_batch_lfs_pointers(raw: &[u8]) -> Result<Vec<(String, u64)>, PushCausalError> {
    let mut rest = raw;
    let mut pointers = Vec::new();
    while !rest.is_empty() {
        let Some(nl) = rest.iter().position(|b| *b == b'\n') else {
            return Err(PushCausalError::CorruptPack("malformed cat-file batch header".into()));
        };
        let header = std::str::from_utf8(&rest[..nl]).map_err(|e| PushCausalError::CorruptPack(e.to_string()))?;
        rest = &rest[nl + 1..];
        let mut parts = header.split(' ');
        let _oid = parts.next();
        let kind = parts.next();
        let size: usize = parts
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| PushCausalError::CorruptPack("invalid cat-file object header".into()))?;
        if rest.len() < size + 1 {
            return Err(PushCausalError::CorruptPack("truncated cat-file object body".into()));
        }
        let body = &rest[..size];
        rest = &rest[size + 1..];
        if kind == Some("blob")
            && let Ok(text) = std::str::from_utf8(body)
            && text.starts_with("version https://git-lfs.github.com/spec/v1\n")
        {
            let (sha256, lfs_size) = parse_lfs_pointer_text(text)?;
            pointers.push((sha256, lfs_size));
        }
    }
    Ok(pointers)
}

fn parse_lfs_pointer_text(text: &str) -> Result<(String, u64), PushCausalError> {
    let mut sha256 = None;
    let mut size = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("oid sha256:") {
            if rest.len() != 64 || !rest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
                return Err(PushCausalError::LfsPointerInvalid("invalid sha256 oid in LFS pointer".into()));
            }
            sha256 = Some(rest.to_owned());
        } else if let Some(rest) = line.strip_prefix("size ") {
            let parsed = rest
                .parse::<u64>()
                .map_err(|_| PushCausalError::LfsPointerInvalid("invalid size in LFS pointer".into()))?;
            size = Some(parsed);
        }
    }
    match (sha256, size) {
        (Some(s), Some(sz)) => Ok((s, sz)),
        _ => Err(PushCausalError::LfsPointerInvalid("LFS pointer missing oid or size line".into())),
    }
}
