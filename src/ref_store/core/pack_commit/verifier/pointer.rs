//! Native Git LFS pointer scan for the accepted-subset facts engine.
//!
//! Only bounded native Git steps are used: one `cat-file --batch-check` to find
//! blob objects for the changed paths and one `cat-file --batch` to read the small
//! candidates. Candidate blobs are bounded to 1024 bytes (the canonical pointer
//! size bound), and the pointer count is bounded too.
//!
//! Every parsed pointer needs a durable byte fact from [`LfsByteWitness`]. The
//! native engine then opens the durable file itself and recomputes SHA-256 and
//! length on a blocking task that owns a verification-lease clone. There is no
//! caller-supplied "verified" boolean: a missing fact, a mismatched file or an
//! unreadable file yields a fixed fail-closed label and the selection rejects that
//! ref.
//!
//! Honest limitation: local durable-file verification is not a remote Blob receipt
//! or hold, so the facts API never promotes it to a publication guarantee.
use super::lease::VerificationLease;
use super::process::Stdin;
use super::view::NativeView;
use crate::ref_store::core::pack_commit::contract::VERIFIER_PIPE_BYTES;
use crate::ref_store::core::pack_commit::error::PackCommitError;
use crate::ref_store::core::pack_commit::facts::verify_local_bytes;
use crate::ref_store::core::pack_commit::facts::{LfsByteWitness, LfsPointerFact};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

/// Canonical Git LFS v1 pointer file bound.
const MAX_POINTER_BYTES: u64 = 1024;
/// Fixed pointer count bound per ref.
const MAX_POINTERS: usize = 1024;

/// One small candidate blob found for a changed path.
struct Candidate {
    /// Index into the caller's changed-path slice.
    path_index: usize,
    blob_oid: String,
}

/// Scan the changed paths of one commit target for LFS pointers and verify their
/// durable bytes. `Ok((facts, None))` means every parsed pointer was verified.
pub(super) async fn scan_pointers(
    view: &NativeView,
    target_hex: &str,
    paths: &[String],
    lfs: &dyn LfsByteWitness,
    lease: &Arc<VerificationLease>,
    deadline: Instant,
) -> Result<(Vec<LfsPointerFact>, Option<&'static str>), PackCommitError> {
    let mut input = String::new();
    for path in paths {
        let extra = target_hex.len().saturating_add(path.len()).saturating_add(2);
        if input.len().saturating_add(extra) > VERIFIER_PIPE_BYTES {
            return Ok((Vec::new(), Some("lfs-pointer-scan-input-exceeded")));
        }
        input.push_str(target_hex);
        input.push(':');
        input.push_str(path);
        input.push('\n');
    }
    let listing = view
        .step(
            "cat-file",
            &["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
            Stdin::Bytes(input.as_bytes()),
            deadline,
        )
        .await?;
    let Some(candidates) = parse_candidates(&listing, paths) else {
        return Ok((Vec::new(), Some("lfs-pointer-scan-malformed")));
    };
    if candidates.is_empty() {
        return Ok((Vec::new(), None));
    }
    let mut fetch = String::new();
    for candidate in &candidates {
        fetch.push_str(&candidate.blob_oid);
        fetch.push('\n');
    }
    let batch = view.step("cat-file", &["cat-file", "--batch"], Stdin::Bytes(fetch.as_bytes()), deadline).await?;
    let oids = candidates.iter().map(|candidate| candidate.blob_oid.clone()).collect::<Vec<_>>();
    let Some(contents) = parse_batch(&batch, &oids) else {
        return Ok((Vec::new(), Some("lfs-pointer-scan-malformed")));
    };
    let mut pointers: Vec<(usize, String, u64)> = Vec::new();
    for (content, candidate) in contents.iter().zip(candidates.iter()) {
        let Some(spec) = crate::lfs::models::parse_pointer(content) else {
            continue;
        };
        if spec.size < 0 {
            return Ok((Vec::new(), Some("lfs-pointer-scan-malformed")));
        }
        if pointers.len() >= MAX_POINTERS {
            return Ok((Vec::new(), Some("lfs-pointer-scan-exceeded")));
        }
        pointers.push((candidate.path_index, spec.oid, spec.size as u64));
    }
    if pointers.is_empty() {
        return Ok((Vec::new(), None));
    }
    let mut locations = Vec::with_capacity(pointers.len());
    for (_, oid, size) in &pointers {
        match lfs.locate(oid, *size) {
            Ok(location) => locations.push(location),
            Err(_) => return Ok((Vec::new(), Some("lfs-durable-byte-fact-unreadable"))),
        }
    }
    let mut pending: Vec<(usize, PathBuf, String, u64)> = Vec::new();
    for (index, location) in locations.iter().enumerate() {
        if let Some(location) = location {
            let (_, oid, size) = &pointers[index];
            pending.push((index, location.path().to_path_buf(), oid.clone(), *size));
        }
    }
    let mut verified = vec![false; pointers.len()];
    if !pending.is_empty() {
        let owned = pending.clone();
        let lease = Arc::clone(lease);
        let task = tokio::task::spawn_blocking(move || {
            let _lease = lease;
            owned
                .into_iter()
                .map(|(index, path, oid, size)| (index, verify_local_bytes(&path, &oid, size)))
                .collect::<Vec<(usize, bool)>>()
        });
        match tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), task).await {
            Ok(Ok(results)) => {
                for (index, ok) in results {
                    if let Some(slot) = verified.get_mut(index) {
                        *slot = ok;
                    }
                }
            }
            Ok(Err(_)) => return Ok((Vec::new(), Some("lfs-byte-verification-failed"))),
            Err(_) => return Ok((Vec::new(), Some("lfs-byte-verification-timeout"))),
        }
    }
    let mut failure = None;
    let mut facts = Vec::with_capacity(pointers.len());
    for (index, (path_index, oid, size)) in pointers.into_iter().enumerate() {
        // A LOCAL path re-hash is never remote durability: `durable` is true only
        // with a real immutable Blob receipt/hold, which this slice does not wire.
        // Pointer-bearing refs therefore fail closed unless such attestation exists.
        let durable = locations[index].as_ref().is_some_and(|location| location.remote_attested());
        let bytes_verified = verified[index];
        if !durable && failure.is_none() {
            failure = Some("lfs-durable-byte-fact-missing");
        }
        if durable && !bytes_verified && failure.is_none() {
            failure = Some("lfs-local-bytes-unverified");
        }
        let path = paths.get(path_index).cloned().unwrap_or_default();
        facts.push(LfsPointerFact::new(path, oid, size, durable, bytes_verified));
    }
    Ok((facts, failure))
}

/// Parse one `cat-file --batch-check` listing aligned with the changed paths.
///
/// `paths` lines and listing lines are one-to-one; a missing object yields
/// `<input> missing` and is skipped. Only small `blob` candidates are returned;
/// anything malformed refuses the whole scan (fail closed).
fn parse_candidates(listing: &[u8], paths: &[String]) -> Option<Vec<Candidate>> {
    let text = std::str::from_utf8(listing).ok()?;
    let lines = text.lines().collect::<Vec<_>>();
    if lines.len() != paths.len() {
        return None;
    }
    let mut candidates = Vec::new();
    for (line, path_index) in lines.iter().zip(0..paths.len()) {
        let mut parts = line.split(' ');
        let (Some(object), Some(kind)) = (parts.next(), parts.next()) else {
            return None;
        };
        if kind == "missing" {
            continue;
        }
        if kind != "blob" {
            continue;
        }
        let size = parts.next()?.parse::<u64>().ok()?;
        if size > MAX_POINTER_BYTES {
            continue;
        }
        if candidates.len() >= MAX_POINTERS {
            return None;
        }
        candidates.push(Candidate { path_index, blob_oid: object.to_owned() });
    }
    Some(candidates)
}

/// Strict parser of one `cat-file --batch` stream for the requested object ids.
///
/// The stream is `<oid> <type> <size>\n<size bytes>\n` per object in request
/// order. A missing or malformed record refuses the whole stream.
fn parse_batch(bytes: &[u8], expected: &[String]) -> Option<Vec<Vec<u8>>> {
    let mut contents = Vec::with_capacity(expected.len());
    let mut offset = 0usize;
    for oid in expected {
        let rest = bytes.get(offset..)?;
        let header_end = rest.iter().position(|byte| *byte == b'\n')?;
        let header = std::str::from_utf8(&rest[..header_end]).ok()?;
        offset = offset.checked_add(header_end).and_then(|value| value.checked_add(1))?;
        let mut parts = header.split(' ');
        let (Some(seen), Some(kind), Some(size)) = (parts.next(), parts.next(), parts.next()) else {
            return None;
        };
        if seen != oid || kind == "missing" {
            return None;
        }
        let size = size.parse::<usize>().ok()?;
        if size as u64 > MAX_POINTER_BYTES {
            return None;
        }
        let body = bytes.get(offset..offset.checked_add(size)?)?;
        contents.push(body.to_vec());
        offset = offset.checked_add(size)?.checked_add(1)?;
        if bytes.get(offset.saturating_sub(1)) != Some(&b'\n') {
            return None;
        }
    }
    Some(contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_parser_is_strict() {
        let oid = "a".repeat(40);
        let stream = format!("{oid} blob 3\nabc\n").into_bytes();
        let parsed = parse_batch(&stream, std::slice::from_ref(&oid)).unwrap();
        assert_eq!(parsed, vec![b"abc".to_vec()]);
        assert!(parse_batch(b"", std::slice::from_ref(&oid)).is_none());
        let other = "b".repeat(40);
        assert!(parse_batch(&stream, std::slice::from_ref(&other)).is_none());
        let truncated = format!("{oid} blob 4\nabc\n").into_bytes();
        assert!(parse_batch(&truncated, std::slice::from_ref(&oid)).is_none());
        let missing = format!("{oid} missing\n").into_bytes();
        assert!(parse_batch(&missing, std::slice::from_ref(&oid)).is_none());
    }

    #[test]
    fn candidate_listing_aligns_paths_and_skips_large_or_missing_blobs() {
        let paths = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let listing = format!("{} blob 3\n{} missing\n{} blob 2048\n", "a".repeat(40), "b".repeat(40), "c".repeat(40));
        let candidates = parse_candidates(listing.as_bytes(), &paths).unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].path_index, 0);
        assert!(parse_candidates(listing.as_bytes(), &paths[..2]).is_none());
    }
}
