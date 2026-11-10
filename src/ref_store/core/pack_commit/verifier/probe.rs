//! Per-ref native probing for accepted-subset publication facts.
//!
//! Only bounded, fixed-argv native Git steps are used. Object ids placed in argv
//! were already parsed into exact lowercase `GitOid` hex by the core, so no caller
//! text reaches a child. Everything here happens before PostgreSQL selection and
//! never calls a database.
//!
//! Global (whole-operation) failures: missing OLD captured object, an old branch
//! object that is not a commit, malformed native output, a native step failure or
//! the deadline. Per-ref facts (not global): missing NEW target, non-commit branch
//! target, non-fast-forward ancestry, partial changed-path scan and LFS failures.
use super::lease::VerificationLease;
use super::process::Stdin;
use super::refuse;
use super::view::NativeView;
use crate::ref_store::core::pack_commit::contract::VERIFIER_PIPE_BYTES;
use crate::ref_store::core::pack_commit::error::PackCommitError;
use crate::ref_store::core::pack_commit::facts::{GitObjectKind, LfsByteWitness, RefFacts};
use crate::ref_store::core::pack_commit::plan::PackCommitPlan;
use crate::ref_store::core::types::RefTarget;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

/// Fixed changed-path bound per ref. A larger set is reported as incomplete and
/// the selection fails that ref closed instead of truncating.
pub(super) const MAX_CHANGED_PATHS: usize = 20_000;
/// Fixed commit-history bound for a newly created branch.
pub(super) const MAX_INTRODUCED_COMMITS: u64 = 4096;

/// Everything one probe pass produced: per-ref facts plus the native object-kind
/// and ancestry observations the publication-decision facts view needs.
pub(super) struct ProbeOutput {
    pub(super) refs: Vec<RefFacts>,
}

/// Probe every planned ref in original plan order.
pub(super) async fn probe_refs(
    view: &NativeView,
    plan: &PackCommitPlan,
    old_map: &BTreeMap<String, String>,
    lfs: &dyn LfsByteWitness,
    lease: &Arc<VerificationLease>,
    deadline: Instant,
) -> Result<ProbeOutput, PackCommitError> {
    let mut oids = Vec::new();
    for update in plan.refs() {
        if let Some(actual) = old_map.get(update.name().as_str()) {
            oids.push(actual.clone());
        }
        if let RefTarget::Oid(oid) = update.target() {
            oids.push(oid.as_hex());
        }
    }
    oids.sort();
    oids.dedup();
    let kinds = probe_types(view, &oids, deadline).await?;
    let mut facts = Vec::with_capacity(plan.refs().len());
    for update in plan.refs() {
        // The actual captured old ref map, never the caller's expected OID: a
        // wrong expectation is a per-ref CAS rejection in the selection, while a
        // missing actual old object stays a whole-operation integrity failure.
        let old_hex = old_map.get(update.name().as_str()).cloned();
        let old_kind = match &old_hex {
            Some(hex) => match kinds.get(hex).copied().flatten() {
                Some(kind) => Some(kind),
                None => return Err(refuse("captured old object is not present in the verified pack set")),
            },
            None => None,
        };
        if update.name().is_branch() && old_kind.is_some_and(|kind| kind != GitObjectKind::Commit) {
            return Err(refuse("captured old branch object is not a commit"));
        }
        let target_hex = update.target().oid().map(|oid| oid.as_hex());
        let target_kind = target_hex.as_ref().and_then(|hex| kinds.get(hex).copied().flatten());
        let target_present = target_hex.as_ref().map(|_| target_kind.is_some());
        let branch_target_is_commit = if update.name().is_branch() && target_hex.is_some() {
            Some(target_kind == Some(GitObjectKind::Commit))
        } else {
            None
        };
        let both_commits = old_kind == Some(GitObjectKind::Commit) && target_kind == Some(GitObjectKind::Commit);
        let fast_forward = match (&old_hex, &target_hex) {
            (Some(old), Some(new)) if update.name().is_branch() && both_commits => {
                let verified = fast_forward(view, old, new, deadline).await?;
                Some(verified)
            }
            _ => None,
        };
        // Exact old->new paths for a commit-tipped branch; a brand-new branch
        // diffs against everything already reachable from the captured refs.
        let (changed_paths, changed_paths_complete) =
            if target_hex.is_none() || !update.name().is_branch() || target_kind != Some(GitObjectKind::Commit) {
                (Vec::new(), true)
            } else {
                let new = target_hex.as_deref().unwrap_or_default();
                match (&old_hex, old_kind) {
                    (Some(old), Some(GitObjectKind::Commit)) => diff_paths(view, old, new, deadline).await?,
                    (None, _) => introduced_paths(view, new, deadline).await?,
                    _ => (Vec::new(), true),
                }
            };
        let (lfs_facts, lfs_failure) = if let Some(new) = &target_hex {
            if target_kind == Some(GitObjectKind::Commit) {
                if !changed_paths_complete {
                    (Vec::new(), Some("lfs-path-scan-incomplete"))
                } else if changed_paths.is_empty() {
                    (Vec::new(), None)
                } else {
                    super::pointer::scan_pointers(view, new, &changed_paths, lfs, lease, deadline).await?
                }
            } else {
                (Vec::new(), None)
            }
        } else {
            (Vec::new(), None)
        };
        facts.push(RefFacts::new(
            update.name().clone(),
            old_hex,
            target_hex,
            target_present,
            target_kind,
            branch_target_is_commit,
            fast_forward,
            changed_paths,
            changed_paths_complete,
            lfs_facts,
            lfs_failure,
        ));
    }
    Ok(ProbeOutput { refs: facts })
}

/// One bounded `cat-file --batch-check` for every probed object id.
async fn probe_types(
    view: &NativeView,
    oids: &[String],
    deadline: Instant,
) -> Result<BTreeMap<String, Option<GitObjectKind>>, PackCommitError> {
    if oids.is_empty() {
        return Ok(BTreeMap::new());
    }
    let mut input = oids.join("\n");
    input.push('\n');
    if input.len() > VERIFIER_PIPE_BYTES {
        return Err(refuse("object type probe exceeds the verifier stdin bound"));
    }
    let listing = view
        .step(
            "cat-file",
            &["cat-file", "--batch-check=%(objectname) %(objecttype)"],
            Stdin::Bytes(input.as_bytes()),
            deadline,
        )
        .await?;
    let text = std::str::from_utf8(&listing).map_err(|_| refuse("native object type listing is not text"))?;
    let lines = text.lines().collect::<Vec<_>>();
    if lines.len() != oids.len() {
        return Err(refuse("native object type listing is incomplete"));
    }
    let mut map = BTreeMap::new();
    for (line, expected) in lines.iter().zip(oids.iter()) {
        let (seen, kind) = line.split_once(' ').ok_or_else(|| refuse("native object type listing is malformed"))?;
        if seen != expected {
            return Err(refuse("native object type listing is out of order"));
        }
        let kind = if kind == "missing" {
            None
        } else {
            Some(GitObjectKind::parse(kind).ok_or_else(|| refuse("native object type listing names an unknown type"))?)
        };
        map.insert(expected.clone(), kind);
    }
    Ok(map)
}

/// Verified ancestry: the captured old object is reachable from the new target.
///
/// `rev-list --count --stdin` over `old` with `^new` counts the commits reachable
/// from `old` but not from `new`. Zero means `old` is an ancestor of (or equal to)
/// `new`, i.e. a genuine fast-forward. Revisions travel on stdin, never in argv.
async fn fast_forward(
    view: &NativeView,
    old_hex: &str,
    new_hex: &str,
    deadline: Instant,
) -> Result<bool, PackCommitError> {
    let mut input = String::with_capacity(old_hex.len().saturating_add(new_hex.len()).saturating_add(3));
    input.push_str(old_hex);
    input.push('\n');
    input.push('^');
    input.push_str(new_hex);
    input.push('\n');
    let output =
        view.step("rev-list", &["rev-list", "--count", "--stdin"], Stdin::Bytes(input.as_bytes()), deadline).await?;
    let text = std::str::from_utf8(&output).map_err(|_| refuse("native ancestry count is not text"))?;
    let count = text.trim().parse::<u64>().map_err(|_| refuse("native ancestry count is malformed"))?;
    Ok(count == 0)
}

/// Exact `old..new` changed paths (stock-Git `diff --name-only`).
async fn diff_paths(
    view: &NativeView,
    old_hex: &str,
    new_hex: &str,
    deadline: Instant,
) -> Result<(Vec<String>, bool), PackCommitError> {
    if old_hex == new_hex {
        return Ok((Vec::new(), true));
    }
    let output = view
        .step(
            "diff",
            &["diff", "--no-ext-diff", "--no-renames", "--name-only", "-z", old_hex, new_hex],
            Stdin::Null,
            deadline,
        )
        .await?;
    Ok(parse_paths(&output))
}

/// Paths introduced by a newly created branch: every path of every commit not
/// already reachable from the captured old refs (stock Git LFS lock semantics).
async fn introduced_paths(
    view: &NativeView,
    new_hex: &str,
    deadline: Instant,
) -> Result<(Vec<String>, bool), PackCommitError> {
    let count_output = view
        .step(
            "rev-list",
            &["rev-list", "--count", "--max-count=4097", new_hex, "--not", "--all"],
            Stdin::Null,
            deadline,
        )
        .await?;
    let count_text =
        std::str::from_utf8(&count_output).map_err(|_| refuse("native introduced commit count is not text"))?;
    let count = count_text.trim().parse::<u64>().map_err(|_| refuse("native introduced commit count is malformed"))?;
    if count > MAX_INTRODUCED_COMMITS {
        return Ok((Vec::new(), false));
    }
    let output = view
        .step(
            "log",
            &[
                "log",
                "--root",
                "-m",
                "--format=",
                "--name-only",
                "-z",
                "--no-renames",
                "--no-ext-diff",
                new_hex,
                "--not",
                "--all",
            ],
            Stdin::Null,
            deadline,
        )
        .await?;
    Ok(parse_paths(&output))
}

/// Strict NUL-separated path parser with the fixed path bound.
fn parse_paths(bytes: &[u8]) -> (Vec<String>, bool) {
    let mut paths = Vec::new();
    for part in bytes.split(|byte| *byte == 0) {
        if part.is_empty() {
            continue;
        }
        let Ok(path) = std::str::from_utf8(part) else {
            return (paths, false);
        };
        if paths.len() >= MAX_CHANGED_PATHS {
            return (paths, false);
        }
        paths.push(path.to_owned());
    }
    (paths, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_parser_is_nul_exact_and_bounded() {
        assert_eq!(parse_paths(b"a\0b/c\0"), (vec!["a".to_string(), "b/c".to_string()], true));
        assert_eq!(parse_paths(b""), (Vec::new(), true));
        let (paths, complete) = parse_paths(&[b'a', 0, 0xff, 0]);
        assert_eq!(paths, vec!["a".to_string()]);
        assert!(!complete);
        let huge = b"x\0".repeat(MAX_CHANGED_PATHS + 1);
        let (_, complete) = parse_paths(&huge);
        assert!(!complete);
    }
}
