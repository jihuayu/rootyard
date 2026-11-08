//! Bounded paging for the Browse refs endpoint.
//!
//! One namespace-wide page is answered by the modern `for-each-ref
//! --start-after` seek path with the bounded streaming scan as the typed
//! fallback; a selective literal prefix always counts its page after the
//! filter. Memory, record, byte and time budgets plus child cleanup live here.
use crate::{
    AppState, Error,
    browse::models::{self, RefItem},
};
use uuid::Uuid;

use super::command::{
    GitOutcome, GitStep, git_cmd, map_git_failure, report_seek_fallback, report_step_failure, run_git_step,
};

/// Upper bounds for the bounded ref scan used by Git without `git
/// for-each-ref --start-after`. Seeking costs one sequential scan up to the
/// cursor; memory stays bounded by `limit + 1` parsed refs plus one line.
const REF_SCAN_MAX_RECORDS: usize = 1 << 20;
const REF_SCAN_MAX_BYTES: usize = 64 * 1024 * 1024;
const REF_SCAN_MAX_RECORD_BYTES: usize = 64 * 1024;

pub fn parse_for_each_ref_output(raw: &[u8]) -> Vec<RefItem> {
    let text = String::from_utf8_lossy(raw);
    let mut items = Vec::new();
    for line in text.lines().filter(|l| !l.is_empty()) {
        let parts: Vec<&str> = line.split('\0').collect();
        if parts.len() < 2 {
            continue;
        }
        let (name, oid) = (parts[0], parts[1]);
        if crate::ci_pins::reserved(name) || !models::valid_public_ref(name) || !models::valid_non_zero_oid(oid) {
            continue;
        }
        let kind = if name.starts_with("refs/heads/") {
            "branch"
        } else if name.starts_with("refs/tags/") {
            "tag"
        } else {
            continue;
        };
        let peeled_oid = parts.get(2).copied().filter(|p| models::valid_non_zero_oid(p)).map(str::to_owned);
        items.push(RefItem { name: name.to_owned(), oid: oid.to_owned(), kind: kind.to_owned(), peeled_oid });
    }
    items.sort_by(|a, b| a.name.cmp(&b.name));
    items
}

/// One namespace-wide page: the modern seek path, with the bounded scan as the
/// typed fallback.
///
/// Git 2.52 and newer seek directly with `for-each-ref --start-after`. A Git
/// that does not implement that option fails it as a *usage* error (exit 129);
/// only that typed verdict selects the bounded streaming scan, so an
/// authorization, storage or transport failure can never silently downgrade
/// into a scan. The project baseline stays Git 2.43: no minimum is raised.
///
/// `prefix` here is only ever the namespace-wide kind (`refs/`, `refs/heads/`,
/// `refs/tags/`, or a shorter cut of one of them), which every ref of the
/// namespace matches. A selective prefix never reaches this function, because
/// filtering the first `limit + 1` refs of a namespace would under-fill the page.
///
/// `--count` bounds Git records, while the parser drops non-public refs (reserved
/// proposal refs, names past the public 1024-byte limit), so a full record batch
/// that yields a short page is rerun through the bounded scan instead of being
/// reported as a complete page.
async fn namespace_page(
    state: &AppState,
    repo_id: Uuid,
    namespace: &str,
    excluded: &str,
    marker: &str,
    prefix: Option<&str>,
    limit: usize,
) -> Result<Vec<RefItem>, Error> {
    let start_after = format!("--start-after={marker}");
    let count = format!("--count={}", limit + 1);
    // Git rejects --start-after together with ref patterns, so the namespace is
    // selected by --exclude plus the Rust-side namespace filter below.
    let args = [
        "for-each-ref",
        "--format=%(refname)%00%(objectname)%00%(*objectname)",
        count.as_str(),
        start_after.as_str(),
        excluded,
        "--exclude=refs/rootyard-ci/*",
    ];
    match run_git_step(state, repo_id, GitStep::RefsPage, &args, 256 * 1024).await? {
        GitOutcome::Output(raw) => {
            // `--count` bounds the ref records Git returns, not the public refs
            // Browse may show: reserved proposal refs, names past the public
            // 1024-byte limit and other non-public refs are dropped while
            // parsing. Git only withholds later refs when it filled the batch,
            // so a short parsed page out of a full batch means public refs may
            // sit behind the rejected ones and the seek answer is truncated.
            // Rerun this one namespace through the bounded scan, which counts
            // public refs after filtering (and keeps its record, byte and time
            // limits plus child cleanup). A short batch is the real end of the
            // namespace, so fully public pages keep the seek path.
            let records = raw.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()).count();
            let items: Vec<RefItem> = parse_for_each_ref_output(&raw)
                .into_iter()
                .filter(|r| r.name.starts_with(namespace) && prefix.is_none_or(|p| r.name.starts_with(p)))
                .collect();
            if records > limit && items.len() <= limit {
                return scan_namespace_page(state, repo_id, namespace, excluded, marker, prefix, limit).await;
            }
            Ok(items)
        }
        GitOutcome::CommandFailed { exit: Some(129) } => {
            report_seek_fallback();
            scan_namespace_page(state, repo_id, namespace, excluded, marker, prefix, limit).await
        }
        GitOutcome::CommandFailed { exit } => {
            report_step_failure(GitStep::RefsPage, exit);
            Err(Error::internal(crate::git_http::GitCommandFailed { exit }))
        }
    }
}

/// True when a literal prefix selects only part of one public namespace.
///
/// A namespace-wide request (`refs/`, `refs/heads/`, `refs/tags/`, or a prefix
/// that merely cuts one of them short, like `refs/h`) is answered by the seek
/// path on a modern Git. Anything narrower (`refs/heads/z`, `refs/heads/z/topic`,
/// or a literal byte string such as `refs/heads/*`) selects a *contiguous range*
/// inside one namespace, so `limit + 1` must be counted after the filter.
fn selects_part_of_namespace(prefix: Option<&str>) -> bool {
    let Some(prefix) = prefix else {
        return false;
    };
    !["refs/", "refs/heads/", "refs/tags/"].iter().any(|whole| whole.starts_with(prefix))
}

/// Bounded replacement for the seek path on Git without `--start-after`, and the
/// only path for a selective literal prefix.
///
/// Only the public namespace is enumerated, in `refname` order, one record at a
/// time; every record at or before the cursor is discarded, `prefix` is applied
/// as a literal Rust byte filter *before* a ref counts towards the page, and the
/// scan stops as soon as `limit + 1` matching refs are known. Because refnames
/// arrive in byte order, the first valid ref greater than `prefix` that does not
/// start with it ends the prefix range, so a narrow prefix costs one linear scan
/// from the namespace start to that range and never the rest of the namespace.
/// Memory is `limit + 1` refs plus one line, the child is killed and reaped on
/// early stop, and records (1M), bytes (64 MiB), record size and time are hard
/// bounded. The Git argv carries only the compiled namespace pattern, never the
/// caller's prefix, so a prefix that contains glob bytes stays a literal byte
/// filter and can never become a Git pattern.
async fn scan_namespace_page(
    state: &AppState,
    repo_id: Uuid,
    namespace: &str,
    excluded: &str,
    marker: &str,
    prefix: Option<&str>,
    limit: usize,
) -> Result<Vec<RefItem>, Error> {
    // The caller's literal byte filter; the empty string matches every ref,
    // which is exactly the namespace-wide request.
    let prefix = prefix.unwrap_or("");
    let pattern = namespace.trim_end_matches('/');
    let args = [
        "for-each-ref",
        "--sort=refname",
        "--format=%(refname)%00%(objectname)%00%(*objectname)",
        excluded,
        "--exclude=refs/rootyard-ci/*",
        pattern,
    ];
    let mut cmd = git_cmd(state, repo_id)?;
    cmd.args(args);
    let mut items: Vec<RefItem> = Vec::with_capacity(limit + 1);
    let limits = crate::git_http::StreamLimits {
        max_records: REF_SCAN_MAX_RECORDS,
        max_bytes: REF_SCAN_MAX_BYTES,
        max_record_bytes: REF_SCAN_MAX_RECORD_BYTES,
    };
    crate::git_http::stream_git_lines(cmd, limits, state.config.git_timeout, |line| {
        for item in parse_for_each_ref_output(line) {
            if !item.name.starts_with(namespace) || item.name.as_str() <= marker {
                continue;
            }
            if !item.name.starts_with(prefix) {
                if item.name.as_str() > prefix {
                    // Ordered refnames: the literal prefix range is over, so no
                    // later ref can match and the rest of the namespace is
                    // never read.
                    return false;
                }
                continue;
            }
            items.push(item);
        }
        // Stop as soon as the page plus the look-ahead ref is known.
        items.len() <= limit
    })
    .await
    .map_err(|err| map_git_failure(err, GitStep::RefsPage))?;
    items.truncate(limit + 1);
    Ok(items)
}

pub(crate) async fn page_refs(
    state: &AppState,
    repo_id: Uuid,
    prefix: Option<&str>,
    after: Option<&str>,
    limit: usize,
) -> Result<Vec<RefItem>, Error> {
    let mut items = Vec::with_capacity(limit + 1);
    // A selective literal prefix must be filtered before a ref counts towards
    // `limit + 1`: the seek path asks Git for the first `limit + 1` refs of the
    // namespace, so filtering those afterwards would drop every match behind
    // lower unrelated refs and answer an empty page. Such a prefix therefore
    // always uses the bounded scan, on every Git version, while a namespace-wide
    // request keeps the modern `--start-after` fast path.
    let selective = selects_part_of_namespace(prefix);
    // Git forbids --start-after with include patterns, so query each public
    // namespace separately. Cursor traversal stays bounded even when another
    // namespace (including private CI refs) contains millions of entries.
    for (namespace, excluded) in [("refs/heads/", "--exclude=refs/tags/*"), ("refs/tags/", "--exclude=refs/heads/*")] {
        if !prefix.is_none_or(|p| namespace.starts_with(p) || p.starts_with(namespace)) {
            continue;
        }
        if after.is_some_and(|cursor| cursor >= namespace && !cursor.starts_with(namespace)) {
            continue;
        }
        let marker = after.filter(|cursor| cursor.starts_with(namespace)).unwrap_or(namespace);
        items.extend(if selective {
            scan_namespace_page(state, repo_id, namespace, excluded, marker, prefix, limit).await?
        } else {
            namespace_page(state, repo_id, namespace, excluded, marker, prefix, limit).await?
        });
        if items.len() > limit {
            break;
        }
    }
    items.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(items
        .into_iter()
        .filter(|r| prefix.is_none_or(|p| r.name.starts_with(p)))
        .filter(|r| after.is_none_or(|cursor| r.name.as_str() > cursor))
        .take(limit + 1)
        .collect())
}
