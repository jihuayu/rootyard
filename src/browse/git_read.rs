//! Safe, bounded native Git read helpers for Track 2A repository browsing.
use crate::{
    AppState, Error,
    browse::models::{
        self, BlobResponse, CommitDetail, CommitSummary, CommitsResponse, CompareResponse,
        HeadInfo, MAX_BROWSE_BLOB_BYTES, MAX_DIFF_BYTES, RefItem, TreeEntry, TreeResponse,
    },
};
use axum::http::StatusCode;
use base64::Engine;
use std::{fs::OpenOptions, io::{Seek, SeekFrom, Write}, os::unix::fs::OpenOptionsExt, process::Stdio};
use tokio::process::Command;
use uuid::Uuid;

pub(crate) fn git_cmd(state: &AppState, repo_id: Uuid) -> Result<Command, Error> {
    let repo_path = state.storage.verify_path(repo_id).map_err(Error::internal)?;
    let mut cmd = state.storage.git(&state.config);
    cmd.env("GIT_NO_REPLACE_OBJECTS", "1");
    let memory = state.config.git_memory_bytes;
    let file = state.config.max_repo_bytes;
    let cpu = state.config.git_timeout.as_secs().max(1);
    unsafe {
        cmd.pre_exec(move || {
            for (resource, limit) in [
                (libc::RLIMIT_AS, memory),
                (libc::RLIMIT_CPU, cpu),
                (libc::RLIMIT_FSIZE, file),
                (libc::RLIMIT_NOFILE, 256),
            ] {
                let value = libc::rlimit { rlim_cur: limit, rlim_max: limit };
                if libc::setrlimit(resource, &value) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    cmd.args(["-c", "core.hooksPath=/dev/null", "--no-replace-objects", "--git-dir"])
        .arg(repo_path);
    Ok(cmd)
}

pub(crate) async fn run_git(
    state: &AppState,
    repo_id: Uuid,
    args: &[&str],
    limit: usize,
) -> Result<Vec<u8>, Error> {
    let mut cmd = git_cmd(state, repo_id)?;
    cmd.args(args);
    crate::git_http::collect_git_output(cmd, limit, state.config.git_timeout)
        .await
        .map_err(|err| {
            let msg = err.to_string();
            if msg.contains("timed out") {
                Error::timeout()
            } else if msg.contains("exceeds limit") {
                Error(StatusCode::PAYLOAD_TOO_LARGE, "Git output exceeds limit")
            } else {
                Error::not_found()
            }
        })
}

pub(crate) async fn object_type(
    state: &AppState,
    repo_id: Uuid,
    spec: &str,
) -> Result<Option<String>, Error> {
    match run_git(state, repo_id, &["cat-file", "-t", spec], 64).await {
        Ok(out) => {
            let kind = String::from_utf8_lossy(&out).trim().to_owned();
            Ok((!kind.is_empty()).then_some(kind))
        }
        Err(err) if err.0 == StatusCode::NOT_FOUND => Ok(None),
        Err(err) => Err(err),
    }
}

pub fn parse_for_each_ref_output(raw: &[u8]) -> Vec<RefItem> {
    let text = String::from_utf8_lossy(raw);
    let mut items = Vec::new();
    for line in text.lines().filter(|l| !l.is_empty()) {
        let parts: Vec<&str> = line.split('\0').collect();
        if parts.len() < 2 {
            continue;
        }
        let (name, oid) = (parts[0], parts[1]);
        if crate::ci_pins::reserved(name)
            || !models::valid_public_ref(name)
            || !models::valid_non_zero_oid(oid)
        {
            continue;
        }
        let kind = if name.starts_with("refs/heads/") {
            "branch"
        } else if name.starts_with("refs/tags/") {
            "tag"
        } else {
            continue;
        };
        let peeled_oid = parts
            .get(2)
            .copied()
            .filter(|p| models::valid_non_zero_oid(p))
            .map(str::to_owned);
        items.push(RefItem {
            name: name.to_owned(),
            oid: oid.to_owned(),
            kind: kind.to_owned(),
            peeled_oid,
        });
    }
    items.sort_by(|a, b| a.name.cmp(&b.name));
    items
}

pub(crate) async fn read_head_and_refs(
    state: &AppState,
    repo_id: Uuid,
) -> Result<(HeadInfo, Vec<RefItem>), Error> {
    let repo_path = state.storage.verify_path(repo_id).map_err(Error::internal)?;
    let head_raw = crate::journal::read(&repo_path.join("HEAD")).map_err(Error::internal)?;
    let head_text = String::from_utf8_lossy(&head_raw).trim().to_owned();
    let raw_refs = run_git(
        state,
        repo_id,
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
        let oid = match run_git(state, repo_id, &["rev-parse", "--verify", "--quiet", "HEAD"], 128).await {
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

pub(crate) async fn page_refs(
    state: &AppState,
    repo_id: Uuid,
    prefix: Option<&str>,
    after: Option<&str>,
    limit: usize,
) -> Result<Vec<RefItem>, Error> {
    let mut items = Vec::with_capacity(limit + 1);
    // Git forbids --start-after with include patterns, so query each public
    // namespace separately. Cursor traversal stays bounded even when another
    // namespace (including private CI refs) contains millions of entries.
    for (namespace, excluded) in [
        ("refs/heads/", "--exclude=refs/tags/*"),
        ("refs/tags/", "--exclude=refs/heads/*"),
    ] {
        if !prefix.is_none_or(|p| namespace.starts_with(p) || p.starts_with(namespace)) {
            continue;
        }
        if after.is_some_and(|cursor| cursor >= namespace && !cursor.starts_with(namespace)) {
            continue;
        }
        let marker = after.filter(|cursor| cursor.starts_with(namespace)).unwrap_or(namespace);
        let start_after = format!("--start-after={marker}");
        let count = format!("--count={}", limit + 1);
        let args = ["for-each-ref", "--format=%(refname)%00%(objectname)%00%(*objectname)",
            count.as_str(), start_after.as_str(), excluded, "--exclude=refs/rootyard-ci/*"];
        let raw = run_git(state, repo_id, &args, 256 * 1024).await?;
        items.extend(parse_for_each_ref_output(&raw).into_iter().filter(|r| r.name.starts_with(namespace)));
        if items.len() > limit { break; }
    }
    items.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(items.into_iter()
        .filter(|r| prefix.is_none_or(|p| r.name.starts_with(p)))
        .filter(|r| after.is_none_or(|cursor| r.name.as_str() > cursor))
        .take(limit + 1)
        .collect())
}

pub(crate) async fn resolve_commit_oid(
    state: &AppState,
    repo_id: Uuid,
    spec: &str,
) -> Result<String, Error> {
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
    let out = run_git(state, repo_id, &["rev-parse", "--verify", "--quiet", &query], 128).await?;
    let oid = String::from_utf8_lossy(&out).trim().to_owned();
    if !models::valid_non_zero_oid(&oid)
        || object_type(state, repo_id, &oid).await?.as_deref() != Some("commit")
    {
        return Err(Error::not_found());
    }
    Ok(oid)
}

fn parse_signature(sig: &str) -> (String, String, i64) {
    let Some(lt) = sig.rfind('<') else {
        return (sig.trim().to_owned(), String::new(), 0);
    };
    let name = sig[..lt].trim().to_owned();
    let rest = &sig[lt + 1..];
    let Some(gt) = rest.find('>') else {
        return (name, String::new(), 0);
    };
    let email = rest[..gt].trim().to_owned();
    let ts = rest[gt + 1..]
        .split_whitespace()
        .next()
        .and_then(|t| t.parse::<i64>().ok())
        .unwrap_or(0);
    (name, email, ts)
}

pub fn parse_commit_raw(oid: &str, raw: &[u8]) -> Result<CommitSummary, Error> {
    let text = String::from_utf8_lossy(raw);
    let (header_block, body_block) = text.split_once("\n\n").unwrap_or((text.as_ref(), ""));
    let mut tree_oid = String::new();
    let mut parents = Vec::new();
    let (mut author_name, mut author_email, mut authored_at) = (String::new(), String::new(), 0);
    let (mut committer_name, mut committer_email, mut committed_at) =
        (String::new(), String::new(), 0);

    for line in header_block.lines() {
        if let Some(rest) = line.strip_prefix("tree ") {
            tree_oid = rest.trim().to_owned();
        } else if let Some(rest) = line.strip_prefix("parent ") {
            let p = rest.trim();
            if models::valid_non_zero_oid(p) {
                parents.push(p.to_owned());
            }
        } else if let Some(rest) = line.strip_prefix("author ") {
            (author_name, author_email, authored_at) = parse_signature(rest);
        } else if let Some(rest) = line.strip_prefix("committer ") {
            (committer_name, committer_email, committed_at) = parse_signature(rest);
        }
    }
    if !models::valid_non_zero_oid(&tree_oid) {
        return Err(Error::not_found());
    }
    let message = body_block.trim_end_matches(['\r', '\n']).to_owned();
    let subject = message.lines().next().unwrap_or("").to_owned();
    Ok(CommitSummary {
        oid: oid.to_owned(),
        tree_oid,
        parents,
        author_name,
        author_email,
        authored_at,
        committer_name,
        committer_email,
        committed_at,
        subject,
        message,
    })
}

pub(crate) async fn read_commit_summary(
    state: &AppState,
    repo_id: Uuid,
    oid: &str,
) -> Result<CommitSummary, Error> {
    let raw = run_git(state, repo_id, &["cat-file", "commit", oid], 256 * 1024).await?;
    parse_commit_raw(oid, &raw)
}

fn parse_batch_commits(raw: &[u8], oids: &[String]) -> Result<Vec<CommitSummary>, Error> {
    let mut offset = 0usize;
    let mut result = Vec::with_capacity(oids.len());
    for oid in oids {
        let end = raw[offset..].iter().position(|&b| b == b'\n').ok_or_else(Error::not_found)? + offset;
        let header = std::str::from_utf8(&raw[offset..end]).map_err(|_| Error::not_found())?;
        let mut parts = header.split(' ');
        if parts.next() != Some(oid.as_str()) || parts.next() != Some("commit") {
            return Err(Error::not_found());
        }
        let size: usize = parts.next().and_then(|s| s.parse().ok()).ok_or_else(Error::not_found)?;
        if parts.next().is_some() || size > 256 * 1024 || size > raw.len().saturating_sub(end + 1) {
            return Err(Error::not_found());
        }
        let start = end + 1;
        let finish = start + size;
        if raw.get(finish) != Some(&b'\n') {
            return Err(Error::not_found());
        }
        result.push(parse_commit_raw(oid, &raw[start..finish])?);
        offset = finish + 1;
    }
    if offset != raw.len() {
        return Err(Error::not_found());
    }
    Ok(result)
}

async fn read_commit_batch(state: &AppState, repo_id: Uuid, oids: &[String]) -> Result<Vec<CommitSummary>, Error> {
    if oids.is_empty() { return Ok(Vec::new()); }
    let journal_root = state.storage.root.join("journal");
    crate::journal::mkdir(&journal_root).map_err(Error::internal)?;
    let path = journal_root.join(format!(".tmp-cat-file-{}", Uuid::new_v4()));
    let mut input = OpenOptions::new().read(true).write(true).create_new(true)
        .mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&path).map_err(Error::internal)?;
    std::fs::remove_file(&path).map_err(Error::internal)?;
    for oid in oids {
        writeln!(input, "{oid}").map_err(Error::internal)?;
    }
    input.seek(SeekFrom::Start(0)).map_err(Error::internal)?;
    let mut cmd = git_cmd(state, repo_id)?;
    cmd.args(["cat-file", "--batch"]);
    let raw = crate::git_http::collect_git_output_input(cmd, 4 * 1024 * 1024, state.config.git_timeout, Stdio::from(input))
        .await.map_err(|err| {
            if err.to_string().contains("timed out") { Error::timeout() }
            else if err.to_string().contains("exceeds limit") { Error(StatusCode::PAYLOAD_TOO_LARGE, "Git output exceeds limit") }
            else { Error::not_found() }
        })?;
    parse_batch_commits(&raw, oids)
}

pub(crate) async fn get_commit_detail(
    state: &AppState,
    repo_id: Uuid,
    oid: &str,
) -> Result<CommitDetail, Error> {
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
    Ok(CommitsResponse {
        repository_id: repo_id,
        items,
        next_after: more.then_some(after + limit),
    })
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
        let path = if rel_path.is_empty() {
            name.to_owned()
        } else {
            format!("{rel_path}/{name}")
        };
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

async fn resolve_commit_or_tree_oid(
    state: &AppState,
    repo_id: Uuid,
    spec_opt: Option<&str>,
) -> Result<String, Error> {
    let spec = spec_opt.unwrap_or("HEAD");
    if !models::valid_revision_spec(spec) {
        return Err(Error::bad_request());
    }
    if models::valid_non_zero_oid(spec) {
        if !matches!(
            object_type(state, repo_id, spec).await?.as_deref(),
            Some("commit" | "tree")
        ) {
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
    let tree_spec = if rel_path.is_empty() {
        format!("{root_oid}^{{tree}}")
    } else {
        format!("{root_oid}:{rel_path}")
    };
    let out = run_git(state, repo_id, &["rev-parse", "--verify", "--quiet", &tree_spec], 128).await?;
    let tree_oid = String::from_utf8_lossy(&out).trim().to_owned();
    if !models::valid_non_zero_oid(&tree_oid)
        || object_type(state, repo_id, &tree_oid).await?.as_deref() != Some("tree")
    {
        return Err(Error::not_found());
    }
    let ls_raw = run_git(state, repo_id, &["ls-tree", "-z", "-l", &tree_oid], 4 * 1024 * 1024).await?;
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
        let out = run_git(state, repo_id, &["rev-parse", "--verify", "--quiet", &spec], 128).await?;
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
    let size_out = run_git(state, repo_id, &["cat-file", "-s", &blob_oid], 64).await?;
    let size: u64 = String::from_utf8_lossy(&size_out).trim().parse().map_err(|_| Error::not_found())?;
    if size as usize > MAX_BROWSE_BLOB_BYTES {
        return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "blob exceeds browse size limit"));
    }
    let bytes = run_git(state, repo_id, &["cat-file", "blob", &blob_oid], MAX_BROWSE_BLOB_BYTES).await?;
    let is_binary = bytes.contains(&0) || std::str::from_utf8(&bytes).is_err();
    let content = (!is_binary).then(|| std::str::from_utf8(&bytes).ok().map(str::to_owned)).flatten();
    let content_base64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
    Ok(BlobResponse { oid: blob_oid, size, is_binary, content, content_base64 })
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
    let merge_base_oid = match run_git(state, repo_id, &["merge-base", &base_oid, &head_oid], 128).await {
        Ok(out) => {
            let s = String::from_utf8_lossy(&out).trim().to_owned();
            models::valid_non_zero_oid(&s).then_some(s)
        }
        Err(err) if err.0 == StatusCode::GATEWAY_TIMEOUT => return Err(err),
        Err(_) => None,
    };
    let fast_forward = merge_base_oid.as_deref() == Some(base_oid.as_str());
    let sym_range = format!("{base_oid}...{head_oid}");
    let count_out = run_git(state, repo_id, &["rev-list", "--left-right", "--count", &sym_range], 128).await?;
    let count_text = String::from_utf8_lossy(&count_out);
    let mut parts = count_text.split_whitespace();
    let behind: u64 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let ahead: u64 = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let log_range = format!("{base_oid}..{head_oid}");
    let rev_out = run_git(state, repo_id, &["rev-list", "--max-count=100", &log_range, "--"], 64 * 1024).await?;
    let commit_oids: Vec<String> = String::from_utf8_lossy(&rev_out).lines().map(str::trim)
        .filter(|line| models::valid_non_zero_oid(line)).map(str::to_owned).collect();
    let commits = read_commit_batch(state, repo_id, &commit_oids).await?;
    let diff_out = run_git(
        state,
        repo_id,
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
