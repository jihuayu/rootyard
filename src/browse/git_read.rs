//! Safe, bounded native Git read helpers for Track 2A repository browsing.
use crate::{
    AppState, Error,
    browse::models::{
        self, BlobResponse, CommitDetail, CommitSummary, CommitsResponse, CompareResponse, HeadInfo,
        MAX_BROWSE_BLOB_BYTES, MAX_DIFF_BYTES, RefItem, TreeEntry, TreeResponse,
    },
};
use axum::http::StatusCode;
use base64::Engine;
use std::{
    fs::OpenOptions,
    io::{Seek, SeekFrom, Write},
    os::unix::fs::OpenOptionsExt,
    process::Stdio,
};
use uuid::Uuid;

#[path = "commit_decode.rs"]
mod commit_decode;

mod command;
mod paging;

use command::report_step_failure;
pub(crate) use command::{GitStep, git_cmd, run_git};
use commit_decode::parse_batch_commits;
pub use commit_decode::parse_commit_raw;
pub(crate) use paging::page_refs;
pub use paging::parse_for_each_ref_output;

/// Type of one object, or `None` when Git does not know the name.
///
/// Absence is decided by the precise quiet probe only. `cat-file -t` answers
/// 128 for a missing object, which is also its verdict for a damaged object
/// database or a racing repository, so a 128 there cannot prove absence. The
/// probe `rev-parse --verify --quiet <spec>^{object}` exits 1 for exactly "Git
/// does not know this name" and resolves the name to a controlled object id;
/// `^{object}` keeps the object itself, so an annotated tag still types as a
/// tag while a full object id is really existence-checked. Once the probe has
/// succeeded the object exists, so any `cat-file` failure is a broken read and
/// never an absent object.
pub(crate) async fn object_type(state: &AppState, repo_id: Uuid, spec: &str) -> Result<Option<String>, Error> {
    let query = format!("{spec}^{{object}}");
    let resolved = match run_git(
        state,
        repo_id,
        GitStep::RevParse,
        &["rev-parse", "--verify", "--quiet", &query],
        128,
    )
    .await
    {
        Ok(out) => String::from_utf8_lossy(&out).trim().to_owned(),
        Err(err) if err.0 == StatusCode::NOT_FOUND => return Ok(None),
        Err(err) => return Err(err),
    };
    if !models::valid_non_zero_oid(&resolved) {
        // A verified name always prints the object id it resolved to. Anything
        // else is a broken native read, not an absent object.
        report_step_failure(GitStep::ObjectType, None);
        return Err(Error::internal(crate::git_http::GitCommandFailed { exit: None }));
    }
    match run_git(state, repo_id, GitStep::ObjectType, &["cat-file", "-t", &resolved], 64).await {
        Ok(out) => {
            let kind = String::from_utf8_lossy(&out).trim().to_owned();
            if kind.is_empty() {
                report_step_failure(GitStep::ObjectType, None);
                return Err(Error::internal(crate::git_http::GitCommandFailed { exit: None }));
            }
            Ok(Some(kind))
        }
        // The object exists, so a non-zero exit or a signal is corruption, a
        // usage problem or a reaping failure: internal, never 404.
        Err(err) => Err(err),
    }
}


pub(crate) async fn read_head_and_refs(state: &AppState, repo_id: Uuid) -> Result<(HeadInfo, Vec<RefItem>), Error> {
    let repo_path = state.storage.verify_path(repo_id).map_err(Error::internal)?;
    let head_raw = crate::journal::read(&repo_path.join("HEAD")).map_err(Error::internal)?;
    let head_text = String::from_utf8_lossy(&head_raw).trim().to_owned();
    let raw_refs = run_git(
        state,
        repo_id,
        GitStep::HeadRefs,
        &[
            "for-each-ref",
            "--sort=refname",
            "--format=%(refname)%00%(objectname)%00%(*objectname)",
            "refs/heads",
            "refs/tags",
        ],
        4 * 1024 * 1024,
    )
    .await?;
    let refs = parse_for_each_ref_output(&raw_refs);
    let head = if let Some(target) = head_text.strip_prefix("ref: ").map(str::trim) {
        let oid = refs.iter().find(|r| r.name == target).map(|r| r.oid.clone());
        let kind = if oid.is_some() { "symbolic" } else { "unborn" };
        HeadInfo { kind: kind.to_owned(), target: Some(target.to_owned()), oid }
    } else if models::valid_non_zero_oid(&head_text) {
        HeadInfo { kind: "detached".to_owned(), target: None, oid: Some(head_text) }
    } else {
        HeadInfo { kind: "unborn".to_owned(), target: None, oid: None }
    };
    Ok((head, refs))
}

pub(crate) async fn read_head(state: &AppState, repo_id: Uuid) -> Result<HeadInfo, Error> {
    let repo_path = state.storage.verify_path(repo_id).map_err(Error::internal)?;
    let raw = crate::journal::read(&repo_path.join("HEAD")).map_err(Error::internal)?;
    let value = String::from_utf8_lossy(&raw).trim().to_owned();
    let target = value.strip_prefix("ref: ").map(str::trim);
    if let Some(target) = target {
        if !models::valid_public_ref(target) {
            return Err(Error::not_found());
        }
        let oid = match run_git(
            state,
            repo_id,
            GitStep::HeadVerify,
            &["rev-parse", "--verify", "--quiet", "HEAD"],
            128,
        )
        .await
        {
            Ok(out) => {
                let oid = String::from_utf8_lossy(&out).trim().to_owned();
                models::valid_non_zero_oid(&oid).then_some(oid)
            }
            Err(err) if err.0 == StatusCode::NOT_FOUND => None,
            Err(err) => return Err(err),
        };
        let kind = if oid.is_some() { "symbolic" } else { "unborn" };
        Ok(HeadInfo { kind: kind.to_owned(), target: Some(target.to_owned()), oid })
    } else if models::valid_non_zero_oid(&value) {
        Ok(HeadInfo { kind: "detached".to_owned(), target: None, oid: Some(value) })
    } else {
        Err(Error::not_found())
    }
}


pub(crate) async fn resolve_commit_oid(state: &AppState, repo_id: Uuid, spec: &str) -> Result<String, Error> {
    if !models::valid_revision_spec(spec) {
        return Err(Error::bad_request());
    }
    if models::valid_non_zero_oid(spec) {
        if object_type(state, repo_id, spec).await?.as_deref() != Some("commit") {
            return Err(Error::not_found());
        }
        return Ok(spec.to_owned());
    }
    if spec == "HEAD" {
        let head = read_head(state, repo_id).await?;
        return head.oid.ok_or_else(Error::not_found);
    }
    let query = format!("{spec}^{{commit}}");
    let out = run_git(state, repo_id, GitStep::RevParse, &["rev-parse", "--verify", "--quiet", &query], 128).await?;
    let oid = String::from_utf8_lossy(&out).trim().to_owned();
    if !models::valid_non_zero_oid(&oid) || object_type(state, repo_id, &oid).await?.as_deref() != Some("commit") {
        return Err(Error::not_found());
    }
    Ok(oid)
}

pub(crate) async fn read_commit_summary(state: &AppState, repo_id: Uuid, oid: &str) -> Result<CommitSummary, Error> {
    let raw = run_git(state, repo_id, GitStep::CommitRead, &["cat-file", "commit", oid], 256 * 1024).await?;
    parse_commit_raw(oid, &raw)
}

async fn read_commit_batch(state: &AppState, repo_id: Uuid, oids: &[String]) -> Result<Vec<CommitSummary>, Error> {
    if oids.is_empty() {
        return Ok(Vec::new());
    }
    let journal_root = state.storage.root.join("journal");
    crate::journal::mkdir(&journal_root).map_err(Error::internal)?;
    let path = journal_root.join(format!(".tmp-cat-file-{}", Uuid::new_v4()));
    let mut input = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(Error::internal)?;
    std::fs::remove_file(&path).map_err(Error::internal)?;
    for oid in oids {
        writeln!(input, "{oid}").map_err(Error::internal)?;
    }
    input.seek(SeekFrom::Start(0)).map_err(Error::internal)?;
    let mut cmd = git_cmd(state, repo_id)?;
    cmd.args(["cat-file", "--batch"]);
    let raw =
        crate::git_http::collect_git_output_input(cmd, 4 * 1024 * 1024, state.config.git_timeout, Stdio::from(input))
            .await
            .map_err(|err| command::map_git_failure(err, GitStep::CommitBatch))?;
    parse_batch_commits(&raw, oids)
}

pub(crate) async fn get_commit_detail(state: &AppState, repo_id: Uuid, oid: &str) -> Result<CommitDetail, Error> {
    if !models::valid_non_zero_oid(oid) {
        return Err(Error::bad_request());
    }
    if object_type(state, repo_id, oid).await?.as_deref() != Some("commit") {
        return Err(Error::not_found());
    }
    let summary = read_commit_summary(state, repo_id, oid).await?;
    let diff_raw = run_git(
        state,
        repo_id,
        GitStep::CommitDiff,
        &["diff-tree", "--no-commit-id", "--name-only", "-r", "-z", "--root", oid],
        512 * 1024,
    )
    .await?;
    let changed_paths = diff_raw
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .take(1000)
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    Ok(CommitDetail { summary, changed_paths })
}

pub(crate) async fn list_commits(
    state: &AppState,
    repo_id: Uuid,
    spec: &str,
    after: usize,
    limit: usize,
) -> Result<CommitsResponse, Error> {
    let start_oid = resolve_commit_oid(state, repo_id, spec).await?;
    let max_arg = format!("--max-count={}", limit + 1);
    let skip_arg = format!("--skip={after}");
    let out = run_git(
        state,
        repo_id,
        GitStep::CommitList,
        &["rev-list", &max_arg, &skip_arg, &start_oid, "--"],
        64 * 1024,
    )
    .await?;
    let oids: Vec<String> = String::from_utf8_lossy(&out)
        .lines()
        .map(str::trim)
        .filter(|s| models::valid_non_zero_oid(s))
        .map(str::to_owned)
        .collect();
    let more = oids.len() > limit;
    let selected: Vec<String> = oids.into_iter().take(limit).collect();
    let items = read_commit_batch(state, repo_id, &selected).await?;
    Ok(CommitsResponse { repository_id: repo_id, items, next_after: more.then_some(after + limit) })
}

pub fn parse_ls_tree_output(raw: &[u8], rel_path: &str) -> Result<Vec<TreeEntry>, Error> {
    let mut entries = Vec::new();
    for record in raw.split(|&b| b == 0).filter(|r| !r.is_empty()) {
        let line = String::from_utf8_lossy(record);
        let Some((meta, name)) = line.split_once('\t') else { continue };
        let parts: Vec<&str> = meta.split_whitespace().collect();
        if name.is_empty() || parts.len() < 4 || !models::valid_non_zero_oid(parts[2]) {
            continue;
        }
        let path = if rel_path.is_empty() { name.to_owned() } else { format!("{rel_path}/{name}") };
        entries.push(TreeEntry {
            name: name.to_owned(),
            path,
            mode: parts[0].to_owned(),
            kind: parts[1].to_owned(),
            oid: parts[2].to_owned(),
            size: parts[3].parse::<u64>().ok(),
        });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

async fn resolve_commit_or_tree_oid(state: &AppState, repo_id: Uuid, spec_opt: Option<&str>) -> Result<String, Error> {
    let spec = spec_opt.unwrap_or("HEAD");
    if !models::valid_revision_spec(spec) {
        return Err(Error::bad_request());
    }
    if models::valid_non_zero_oid(spec) {
        if !matches!(object_type(state, repo_id, spec).await?.as_deref(), Some("commit" | "tree")) {
            return Err(Error::not_found());
        }
        return Ok(spec.to_owned());
    }
    resolve_commit_oid(state, repo_id, spec).await
}

pub(crate) async fn read_tree(
    state: &AppState,
    repo_id: Uuid,
    oid_or_spec: Option<&str>,
    rel_path: &str,
    after: Option<&str>,
    limit: usize,
) -> Result<TreeResponse, Error> {
    let root_oid = resolve_commit_or_tree_oid(state, repo_id, oid_or_spec).await?;
    let tree_spec = if rel_path.is_empty() { format!("{root_oid}^{{tree}}") } else { format!("{root_oid}:{rel_path}") };
    let out = run_git(
        state,
        repo_id,
        GitStep::RevParse,
        &["rev-parse", "--verify", "--quiet", &tree_spec],
        128,
    )
    .await?;
    let tree_oid = String::from_utf8_lossy(&out).trim().to_owned();
    if !models::valid_non_zero_oid(&tree_oid)
        || object_type(state, repo_id, &tree_oid).await?.as_deref() != Some("tree")
    {
        return Err(Error::not_found());
    }
    let ls_raw = run_git(
        state,
        repo_id,
        GitStep::TreeList,
        &["ls-tree", "-z", "-l", &tree_oid],
        4 * 1024 * 1024,
    )
    .await?;
    let filtered: Vec<TreeEntry> = parse_ls_tree_output(&ls_raw, rel_path)?
        .into_iter()
        .filter(|e| after.is_none_or(|cursor| e.name.as_str() > cursor))
        .take(limit + 1)
        .collect();
    let more = filtered.len() > limit;
    let items: Vec<TreeEntry> = filtered.into_iter().take(limit).collect();
    let next_after = more.then(|| items.last().map(|e| e.name.clone())).flatten();
    Ok(TreeResponse { oid: root_oid, tree_oid, path: rel_path.to_owned(), items, next_after })
}

/// Parse the decimal byte count printed by `cat-file -s`.
///
/// The blob's existence and type are proved before this read, so output that is
/// not a plain decimal size is a broken native read: an internal failure with a
/// fixed message, never a 404.
pub(crate) fn parse_blob_size(raw: &[u8]) -> Result<u64, Error> {
    String::from_utf8_lossy(raw).trim().parse::<u64>().map_err(|_| {
        report_step_failure(GitStep::BlobSize, None);
        Error::internal(crate::git_http::GitCommandFailed { exit: None })
    })
}

pub(crate) async fn read_blob(
    state: &AppState,
    repo_id: Uuid,
    oid_or_spec: Option<&str>,
    rel_path: Option<&str>,
) -> Result<BlobResponse, Error> {
    let clean_path = models::normalize_rel_path(rel_path)?;
    let blob_oid = if !clean_path.is_empty() {
        let root_oid = resolve_commit_or_tree_oid(state, repo_id, oid_or_spec).await?;
        let spec = format!("{root_oid}:{clean_path}");
        let out = run_git(
            state,
            repo_id,
            GitStep::RevParse,
            &["rev-parse", "--verify", "--quiet", &spec],
            128,
        )
        .await?;
        String::from_utf8_lossy(&out).trim().to_owned()
    } else {
        let raw_oid = oid_or_spec.ok_or_else(Error::bad_request)?;
        if !models::valid_non_zero_oid(raw_oid) {
            return Err(Error::bad_request());
        }
        raw_oid.to_owned()
    };
    if !models::valid_non_zero_oid(&blob_oid)
        || object_type(state, repo_id, &blob_oid).await?.as_deref() != Some("blob")
    {
        return Err(Error::not_found());
    }
    let size_out = run_git(state, repo_id, GitStep::BlobSize, &["cat-file", "-s", &blob_oid], 64).await?;
    let size = parse_blob_size(&size_out)?;
    if size as usize > MAX_BROWSE_BLOB_BYTES {
        return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "blob exceeds browse size limit"));
    }
    let bytes = run_git(
        state,
        repo_id,
        GitStep::BlobContent,
        &["cat-file", "blob", &blob_oid],
        MAX_BROWSE_BLOB_BYTES,
    )
    .await?;
    let is_binary = bytes.contains(&0) || std::str::from_utf8(&bytes).is_err();
    let content = (!is_binary).then(|| std::str::from_utf8(&bytes).ok().map(str::to_owned)).flatten();
    let content_base64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    Ok(BlobResponse { oid: blob_oid, size, is_binary, content, content_base64 })
}

/// Classify a failed `merge-base` call.
///
/// `git merge-base` answers "no common ancestor" with its precise quiet exit 1,
/// which the merge-base step maps to 404; only that verdict becomes `None`.
/// Every other failure - a timeout, a damaged object database, a usage error, a
/// signal, a spawn failure - is a broken read and propagates unchanged instead
/// of being reported as an absent merge base.
fn merge_base_from_failure(err: Error) -> Result<Option<String>, Error> {
    if err.0 == StatusCode::NOT_FOUND { Ok(None) } else { Err(err) }
}

pub(crate) async fn compare_commits(
    state: &AppState,
    repo_id: Uuid,
    base_spec: &str,
    head_spec: &str,
) -> Result<CompareResponse, Error> {
    if !models::valid_revision_spec(base_spec) || !models::valid_revision_spec(head_spec) {
        return Err(Error::bad_request());
    }
    let base_oid = resolve_commit_oid(state, repo_id, base_spec).await?;
    let head_oid = resolve_commit_oid(state, repo_id, head_spec).await?;
    let merge_base_oid = match run_git(
        state,
        repo_id,
        GitStep::MergeBase,
        &["merge-base", &base_oid, &head_oid],
        128,
    )
    .await
    {
        Ok(out) => {
            let s = String::from_utf8_lossy(&out).trim().to_owned();
            if !models::valid_non_zero_oid(&s) {
                // A successful merge-base prints the common commit; anything
                // else is a broken native read, never "no common ancestor".
                report_step_failure(GitStep::MergeBase, None);
                return Err(Error::internal(crate::git_http::GitCommandFailed { exit: None }));
            }
            Some(s)
        }
        Err(err) => merge_base_from_failure(err)?,
    };
    let fast_forward = merge_base_oid.as_deref() == Some(base_oid.as_str());
    let sym_range = format!("{base_oid}...{head_oid}");
    let count_out = run_git(
        state,
        repo_id,
        GitStep::CompareCount,
        &["rev-list", "--left-right", "--count", &sym_range],
        128,
    )
    .await?;
    let count_text = String::from_utf8_lossy(&count_out);
    let mut parts = count_text.split_whitespace();
    let behind: u64 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let ahead: u64 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let log_range = format!("{base_oid}..{head_oid}");
    let rev_out = run_git(
        state,
        repo_id,
        GitStep::CompareCommits,
        &["rev-list", "--max-count=100", &log_range, "--"],
        64 * 1024,
    )
    .await?;
    let commit_oids: Vec<String> = String::from_utf8_lossy(&rev_out)
        .lines()
        .map(str::trim)
        .filter(|line| models::valid_non_zero_oid(line))
        .map(str::to_owned)
        .collect();
    let commits = read_commit_batch(state, repo_id, &commit_oids).await?;
    let diff_out = run_git(
        state,
        repo_id,
        GitStep::CompareDiff,
        &["diff", "--no-ext-diff", "--no-textconv", &base_oid, &head_oid, "--"],
        MAX_DIFF_BYTES,
    )
    .await?;
    Ok(CompareResponse {
        base_oid,
        head_oid,
        merge_base_oid,
        ahead,
        behind,
        fast_forward,
        commits,
        diff: String::from_utf8_lossy(&diff_out).into_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The service's internal failure class (503) with its fixed message; the
    /// point is that a broken read is never the 404 "not found".
    fn assert_internal(err: &Error) {
        assert!(err.0.is_server_error(), "broken read must be internal, got {}", err.0);
        assert_ne!(err.0, StatusCode::NOT_FOUND, "corruption is never an absent object");
        assert_eq!(err.1, "service temporarily unavailable", "fixed, secret-free message");
    }

    #[test]
    fn blob_size_parse_is_internal_after_the_existence_probe() {
        assert_eq!(parse_blob_size(b"12\n").ok(), Some(12));
        assert_eq!(parse_blob_size(b" 0\n").ok(), Some(0));
        for damaged in [b"".as_slice(), b"not-a-number\n".as_slice(), b"-1\n".as_slice(), b"1 2\n".as_slice()] {
            assert_internal(&parse_blob_size(damaged).expect_err("damaged blob size"));
        }
    }

    #[test]
    fn only_a_genuine_no_merge_base_verdict_is_none() {
        let none = merge_base_from_failure(Error::not_found()).expect("a real absence is not an error");
        assert!(none.is_none());
        for broken in [Error::timeout(), Error::internal("damaged read")] {
            let status = merge_base_from_failure(broken).expect_err("must propagate").0;
            assert!(
                status.is_server_error() || status == StatusCode::GATEWAY_TIMEOUT,
                "broken merge-base must stay a server failure, got {status}"
            );
        }
    }
}
