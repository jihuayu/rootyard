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
    sync::atomic::{AtomicU32, Ordering},
};
use tokio::process::Command;
use uuid::Uuid;

#[path = "commit_decode.rs"]
mod commit_decode;

use commit_decode::parse_batch_commits;
pub use commit_decode::parse_commit_raw;

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
    cmd.args(["-c", "core.hooksPath=/dev/null", "--no-replace-objects", "--git-dir"]).arg(repo_path);
    Ok(cmd)
}

/// Fixed label for one native read step.
///
/// A label is a compiled literal. It is never derived from argv, a ref name, an
/// object id, Git stdout or Git stderr, so a step diagnostic cannot leak a
/// credential or repository content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GitStep {
    ObjectType,
    HeadVerify,
    HeadRefs,
    RefsPage,
    RevParse,
    CommitRead,
    CommitBatch,
    CommitDiff,
    CommitList,
    TreeList,
    BlobSize,
    BlobContent,
    MergeBase,
    CompareCount,
    CompareCommits,
    CompareDiff,
    ObjectFormat,
    RefVerify,
}

impl GitStep {
    pub(crate) fn label(self) -> &'static str {
        match self {
            GitStep::ObjectType => "object-type",
            GitStep::HeadVerify => "head-verify",
            GitStep::HeadRefs => "head-refs",
            GitStep::RefsPage => "refs-page",
            GitStep::RevParse => "rev-parse",
            GitStep::CommitRead => "commit-read",
            GitStep::CommitBatch => "commit-batch",
            GitStep::CommitDiff => "commit-diff",
            GitStep::CommitList => "commit-list",
            GitStep::TreeList => "tree-list",
            GitStep::BlobSize => "blob-size",
            GitStep::BlobContent => "blob-content",
            GitStep::MergeBase => "merge-base",
            GitStep::CompareCount => "compare-count",
            GitStep::CompareCommits => "compare-commits",
            GitStep::CompareDiff => "compare-diff",
            GitStep::ObjectFormat => "object-format",
            GitStep::RefVerify => "ref-verify",
        }
    }

    /// Only these steps run Git's precise quiet probes, whose exit 1 means "no
    /// such name". Any other step runs on a repository that already passed
    /// authorization and readiness checks, so a failure is a broken native read
    /// and must never be reported as "not found". In particular `object-type`
    /// is not here: it reads a type only after a probe proved the object exists.
    pub(crate) fn absence_is_expected(self) -> bool {
        matches!(self, GitStep::HeadVerify | GitStep::RevParse | GitStep::MergeBase | GitStep::RefVerify)
    }

    /// A probe may answer 404 only when Git itself answered "no such name" with
    /// its quiet verdict, which is exactly exit 1 for `rev-parse --verify
    /// --quiet`, `merge-base` and the ref probe. Exit 128 is Git's generic fatal
    /// class (damaged object database, missing repository path, a race on an
    /// otherwise healthy repository) and cannot prove that a name is absent; a
    /// usage error (129) or a signal likewise means the native read broke. All
    /// of those stay internal failures, so corruption is never disguised as a
    /// 404 and a real absence is never disguised as a 500.
    pub(crate) fn maps_to_not_found(self, exit: Option<i32>) -> bool {
        self.absence_is_expected() && matches!(exit, Some(1))
    }

    /// Fixed exit-class label. Git reserves 129 for usage errors (for example an
    /// option the configured Git does not implement) and 128 for fatal
    /// repository errors; anything else is an unclassified non-zero exit.
    pub(crate) fn failure_class(self, exit: Option<i32>) -> &'static str {
        match exit {
            Some(129) => "usage",
            Some(128) => "fatal",
            Some(_) => "nonzero",
            None => "signal",
        }
    }
}

/// Record once per process that the configured Git lacks the paging option.
fn report_seek_fallback() {
    static REPORTED: AtomicU32 = AtomicU32::new(0);
    if REPORTED.fetch_add(1, Ordering::Relaxed) != 0 {
        return;
    }
    eprintln!(
        "rootyard: browse git read step={} class=usage fallback=bounded-scan",
        GitStep::RefsPage.label()
    );
}

/// Emit one bounded, secret-free record for a failed required native read step.
fn report_step_failure(step: GitStep, exit: Option<i32>) {
    // A broken storage volume must not be able to flood stderr per request.
    const BUDGET: u32 = 64;
    static REPORTED: AtomicU32 = AtomicU32::new(0);
    if REPORTED.fetch_add(1, Ordering::Relaxed) >= BUDGET {
        return;
    }
    let code = match exit {
        Some(code) => code.to_string(),
        None => "signal".to_owned(),
    };
    eprintln!(
        "rootyard: browse git read step={} class={} exit={}",
        step.label(),
        step.failure_class(exit),
        code
    );
}

/// Upper bounds for the bounded ref scan used by Git without `git
/// for-each-ref --start-after`. Seeking costs one sequential scan up to the
/// cursor; memory stays bounded by `limit + 1` parsed refs plus one line.
const REF_SCAN_MAX_RECORDS: usize = 1 << 20;
const REF_SCAN_MAX_BYTES: usize = 64 * 1024 * 1024;
const REF_SCAN_MAX_RECORD_BYTES: usize = 64 * 1024;

/// Raw outcome of one native read step before HTTP mapping.
///
/// The typed exit code exists so a capability fallback is selected from Git's
/// exit status, never by matching untrusted Git error text.
enum GitOutcome {
    Output(Vec<u8>),
    CommandFailed { exit: Option<i32> },
}

fn exit_of(err: &anyhow::Error) -> Option<Option<i32>> {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<crate::git_http::GitCommandFailed>())
        .map(|failure| failure.exit)
}

/// Map a failed native read to the truthful HTTP result for its step.
fn map_git_failure(err: anyhow::Error, step: GitStep) -> Error {
    let msg = err.to_string();
    if msg.contains("timed out") {
        return Error::timeout();
    }
    if msg.contains("exceeds limit") {
        return Error(StatusCode::PAYLOAD_TOO_LARGE, "Git output exceeds limit");
    }
    let failure = exit_of(&err);
    let Some(exit) = failure else {
        // Spawn, pipe or reaping failure: not a Git verdict, never a 404.
        return Error::internal(err);
    };
    if step.maps_to_not_found(exit) {
        return Error::not_found();
    }
    report_step_failure(step, exit);
    Error::internal(crate::git_http::GitCommandFailed { exit })
}

async fn run_git_step(
    state: &AppState,
    repo_id: Uuid,
    step: GitStep,
    args: &[&str],
    limit: usize,
) -> Result<GitOutcome, Error> {
    let mut cmd = git_cmd(state, repo_id)?;
    cmd.args(args);
    match crate::git_http::collect_git_output(cmd, limit, state.config.git_timeout).await {
        Ok(bytes) => Ok(GitOutcome::Output(bytes)),
        Err(err) => {
            let msg = err.to_string();
            if msg.contains("timed out") {
                return Err(Error::timeout());
            }
            if msg.contains("exceeds limit") {
                return Err(Error(StatusCode::PAYLOAD_TOO_LARGE, "Git output exceeds limit"));
            }
            let failure = exit_of(&err);
            match failure {
                Some(exit) => Ok(GitOutcome::CommandFailed { exit }),
                None => Err(Error::internal(err)),
            }
        }
    }
}

pub(crate) async fn run_git(
    state: &AppState,
    repo_id: Uuid,
    step: GitStep,
    args: &[&str],
    limit: usize,
) -> Result<Vec<u8>, Error> {
    match run_git_step(state, repo_id, step, args, limit).await? {
        GitOutcome::Output(bytes) => Ok(bytes),
        GitOutcome::CommandFailed { exit } => {
            if step.maps_to_not_found(exit) {
                // The probe asked Git whether a named ref/object exists and Git
                // answered "no"; that answer is a genuine 404.
                return Err(Error::not_found());
            }
            report_step_failure(step, exit);
            Err(Error::internal(crate::git_http::GitCommandFailed { exit }))
        }
    }
}

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
            if records >= limit + 1 && items.len() < limit + 1 {
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
            .map_err(|err| {
                if err.to_string().contains("timed out") {
                    Error::timeout()
                } else if err.to_string().contains("exceeds limit") {
                    Error(StatusCode::PAYLOAD_TOO_LARGE, "Git output exceeds limit")
                } else {
                    Error::not_found()
                }
            })?;
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
    let size: u64 = String::from_utf8_lossy(&size_out).trim().parse().map_err(|_| Error::not_found())?;
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
            models::valid_non_zero_oid(&s).then_some(s)
        }
        Err(err) if err.0 == StatusCode::GATEWAY_TIMEOUT => return Err(err),
        Err(_) => None,
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
