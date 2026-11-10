//! Read-only refs/commits/compare API over the same sealed Blob snapshot as
//! Smart HTTP and tree/blob browsing.
//!
//! Every request runs the shared read pipeline of [`super::browse`]
//! ([`browse::BrowseSession`]): authenticate the current token, take the gateway
//! slot and byte lease, resolve the repository through the shared serving
//! authority (live token, RBAC, contents read scope, ready exact binding and the
//! actually opened Blob backend), then score a presented repository session
//! lower bound against that authorized realm and gate revision, capture the
//! RefStore ref view under the same cluster authority incarnation, and build its
//! computed view. `snapshot::build_view` downloads, verifies and materializes the
//! sealed pack closure and fsck-checks it, so that private bare view holds the
//! complete current-refs reachable history. This module only runs fixed,
//! bounded, mature Git commands (`rev-list`, `cat-file`, `merge-base`, `diff`)
//! inside that verified view, revalidates the authorization before encoding, and
//! never keeps a permanent bare repository or consults legacy `AppState`.
//!
//! Routes:
//!
//! * `refs`: captured public refs in refname order with a literal `prefix`, an
//!   `after` cursor and a `limit + 1` look-ahead. Zero-oid (deletion) entries
//!   never authorize a read. Every page object is typed natively
//!   (`cat-file --batch`), so an annotated tag is recognized as a tag object
//!   even in an untyped capture; it is peeled with `rev-parse <name>^{}` and
//!   only a full, repository-format peeled commit is served. Lightweight tags
//!   (commits) have no peel.
//! * `commits`: `rev-list <rev> --` (native date order) plus one bounded
//!   `cat-file --batch` metadata read, with `after`/`limit` paging returning the
//!   next offset. A full object id is admitted when it belongs to the captured
//!   ref closure (same rule as blob-by-oid), so ancestors of the current tip
//!   are listed too.
//! * `commits/{oid}`: the legacy commit detail (`CommitDetail`) for one commit
//!   of the captured closure plus its changed paths.
//! * `compare`: `merge-base` and exact ahead/behind counts, the ahead list
//!   (legacy parity: at most 100 summaries, `truncated` when there are more) and
//!   the bounded patch with its changed paths. Any two captured revisions with a
//!   common ancestor are supported, including ancestor -> current tip.
//!
//! Every native capture, decoded copy and serialized body is bounded by the
//! request's captured-output budget (one twelfth of the reserved request
//! memory, the same split as blob browsing). An oversize patch, name list or
//! commit message, and a history past its commit ceiling, are explicit refusals
//! (`413`), never clipped answers presented as complete.
//! Responses use the legacy browse JSON models with additive `format`,
//! `hash_algorithm` and `oid_hex_len` fields so SHA-1 vs SHA-256 is explicit.
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
};
use serde::Serialize;

use super::{browse, error::GatewayError, native, state::BlobGitState};
use crate::browse::models::{self, CommitDetail, CommitSummary, CompareQuery, HeadInfo, RefItem};

/// Ancestor-walk ceiling for `commits` and `compare`; larger histories are
/// refused with `413`, never silently clipped.
const MAX_WALK_COMMITS: u64 = 20_000;
/// Maximum retained message bytes of one commit; a larger message is refused
/// with `413` on every listing, detail and compare path, never clipped.
const MAX_COMMIT_BODY: usize = 256 * 1024;
/// Shared output ceilings of one compare: the patch (legacy parity) and the
/// changed-path listing; both are further capped by the request budget.
const MAX_COMPARE_DIFF: u64 = 2 * 1024 * 1024;
/// Ahead-commit listing ceiling of one compare (legacy parity).
const MAX_COMPARE_COMMITS: usize = 100;

pub(super) async fn refs(
    State(state): State<Arc<BlobGitState>>,
    Path((owner, name)): Path<(String, String)>,
    Query(query): Query<models::RefsQuery>,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let (prefix, after, limit) = query.validate().map_err(|_| bad_input("invalid ref listing parameters"))?;
    let session = browse::BrowseSession::open(state, headers, owner, name).await?;
    let refs = captured_refs(&session.refs)?;
    let head = head_info(&session, &refs);
    let page = refs
        .iter()
        .filter(|(name, _)| prefix.is_none_or(|prefix| name.starts_with(prefix)))
        .filter(|(name, _)| after.is_none_or(|cursor| name.as_str() > cursor))
        .take(limit + 1)
        .collect::<Vec<_>>();
    let more = page.len() > limit;
    let page = &page[..page.len().min(limit)];
    let typed = page.iter().map(|(_, oid)| (*oid).clone()).collect::<BTreeSet<_>>();
    let types = batch_types(&session, &typed).await?;
    let mut items = Vec::with_capacity(page.len());
    for (ref_name, oid) in page {
        let peeled_oid = match types.get(oid) {
            Some(kind) if kind == "tag" && ref_name.starts_with("refs/tags/") => {
                Some(peel_tag(&session, ref_name).await?)
            }
            Some(_) => None,
            None => return Err(GatewayError::Internal("captured ref object could not be typed")),
        };
        items.push(RefItem {
            name: (*ref_name).clone(),
            oid: (*oid).clone(),
            kind: if ref_name.starts_with("refs/tags/") { "tag" } else { "branch" }.to_owned(),
            peeled_oid,
        });
    }
    let next_after = more.then(|| items.last().map(|item| item.name.clone())).flatten();
    let response = RefsWire {
        repository_id: session.repository_id,
        storage_generation: session.storage_generation,
        head,
        items,
        next_after,
        more,
        format: session.format_name(),
        hash_algorithm: hash_algorithm(session.format),
        oid_hex_len: session.format.oid_hex_len(),
        limit,
    };
    finish(session, &response).await
}

pub(super) async fn commits(
    State(state): State<Arc<BlobGitState>>,
    Path((owner, name)): Path<(String, String)>,
    Query(query): Query<models::CommitsQuery>,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let (spec, after, limit) = query.validate().map_err(|_| bad_input("invalid commit listing parameters"))?;
    let session = browse::BrowseSession::open(state, headers, owner, name).await?;
    let refs = captured_refs(&session.refs)?;
    let start = match spec {
        "HEAD" => match &session.head_oid {
            Some(oid) => oid.clone(),
            None => return Err(GatewayError::NotFound),
        },
        oid if models::valid_non_zero_oid(oid) => {
            if !exact_oid(oid, session.format.oid_hex_len()) {
                return Err(GatewayError::NotFound);
            }
            browse::require_reachable(&session, oid).await?;
            browse::require_kind(&session, oid, "commit").await?;
            oid.to_owned()
        }
        name => {
            let name = captured_ref_name(&refs, name)?;
            browse::peel(&session, &format!("{name}^{{commit}}")).await?
        }
    };
    let order = commit_order(&session, &start).await?;
    let end = after.saturating_add(limit + 1).min(order.len());
    let page = order.get(after..end).unwrap_or_default();
    let more = page.len() > limit;
    let items = commit_summaries(&session, &page[..page.len().min(limit)]).await?;
    let next_after = more.then(|| after + limit);
    let response = CommitsWire {
        repository_id: session.repository_id,
        start_oid: start,
        format: session.format_name(),
        hash_algorithm: hash_algorithm(session.format),
        oid_hex_len: session.format.oid_hex_len(),
        limit,
        items,
        next_after,
    };
    finish(session, &response).await
}

pub(super) async fn commit(
    State(state): State<Arc<BlobGitState>>,
    Path((owner, name, oid)): Path<(String, String, String)>,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let session = browse::BrowseSession::open(state, headers, owner, name).await?;
    if !exact_oid(&oid, session.format.oid_hex_len()) {
        return Err(GatewayError::NotFound);
    }
    browse::require_reachable(&session, &oid).await?;
    browse::require_kind(&session, &oid, "commit").await?;
    let single = [oid.clone()];
    let summary = commit_summaries(&session, &single)
        .await?
        .pop()
        .ok_or(GatewayError::Internal("captured commit metadata could not be decoded"))?;
    let changed_paths = commit_paths(&session, &oid).await?;
    let response = CommitDetailWire {
        detail: CommitDetail { summary, changed_paths },
        format: session.format_name(),
        hash_algorithm: hash_algorithm(session.format),
        oid_hex_len: session.format.oid_hex_len(),
    };
    finish(session, &response).await
}

pub(super) async fn compare(
    State(state): State<Arc<BlobGitState>>,
    Path((owner, name)): Path<(String, String)>,
    Query(query): Query<CompareQuery>,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    if !models::valid_revision_spec(&query.base) || !models::valid_revision_spec(&query.head) {
        return Err(bad_input("invalid compare revisions"));
    }
    let session = browse::BrowseSession::open(state, headers, owner, name).await?;
    let refs = captured_refs(&session.refs)?;
    let base_oid = resolve_commit(&session, &refs, &query.base).await?;
    let head_oid = resolve_commit(&session, &refs, &query.head).await?;
    // `merge-base --all` follows native Git's full merge-base set; exit 1 is
    // its precise "no common ancestor" verdict and every other failure is a
    // broken native read.
    const MAX_MERGE_BASES: u64 = 64;
    let mut command = session.view.command(session.state.git_binary());
    command.args(["merge-base", "--all", &base_oid, &head_oid]);
    let bases = native::run_capture_status(
        command,
        None,
        64 * 1024,
        (MAX_MERGE_BASES * 65).min(session.budget()),
        session.deadline,
    )
    .await?;
    let merge_base_oids = parse_oid_lines(&bases.stdout)?;
    if merge_base_oids.len() as u64 > MAX_MERGE_BASES {
        return Err(GatewayError::TooLarge);
    }
    if merge_base_oids.is_empty() {
        // Only Git's precise exit 1 without output is "no common ancestor";
        // any other failure (signal, cleanup, usage) stays internal and is
        // never reported as unrelated history.
        if bases.exit_code == Some(1) && !bases.success {
            return Err(GatewayError::Unsupported("no common ancestor between the compared revisions"));
        }
        return Err(GatewayError::Internal("native merge base read was refused"));
    }
    if !bases.success {
        return Err(GatewayError::Internal("native merge base read was refused"));
    }
    let merge_base_oid = merge_base_oids.first().cloned();
    let fast_forward = merge_base_oids.len() == 1 && merge_base_oid.as_deref() == Some(base_oid.as_str());
    let counts =
        run_text(&session, &["rev-list", "--left-right", "--count", &format!("{base_oid}...{head_oid}")], 128).await?;
    let mut parts = counts.split_whitespace();
    let behind: u64 = parts
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or(GatewayError::Internal("native comparison counts are invalid"))?;
    let ahead: u64 = parts
        .next()
        .and_then(|value| value.parse().ok())
        .ok_or(GatewayError::Internal("native comparison counts are invalid"))?;
    if parts.next().is_some() {
        return Err(GatewayError::Internal("native comparison counts are invalid"));
    }
    let truncated = ahead > MAX_COMPARE_COMMITS as u64;
    if ahead.max(behind) > MAX_WALK_COMMITS {
        return Err(GatewayError::TooLarge);
    }
    let listed = run_text(
        &session,
        &["rev-list", &format!("--max-count={MAX_COMPARE_COMMITS}"), &format!("{base_oid}..{head_oid}"), "--"],
        session.budget(),
    )
    .await?;
    let listed = parse_oid_lines(listed.as_bytes())?;
    let commits = commit_summaries(&session, &listed).await?;
    let patch = run_text(
        &session,
        &["diff", "--no-ext-diff", "--no-textconv", &base_oid, &head_oid, "--"],
        session.budget().min(MAX_COMPARE_DIFF),
    )
    .await?;
    let names = run_bytes(
        &session,
        &["diff", "--no-ext-diff", "--no-textconv", "--name-only", "-r", "-z", &base_oid, &head_oid, "--"],
        session.budget(),
    )
    .await?;
    let response = CompareWire {
        base_oid,
        head_oid,
        merge_base_oid,
        merge_base_oids,
        ahead,
        behind,
        fast_forward,
        commits,
        truncated,
        diff: patch,
        changed_paths: parse_name_list(&names)?,
        format: session.format_name(),
        hash_algorithm: hash_algorithm(session.format),
        oid_hex_len: session.format.oid_hex_len(),
        commits_limit: MAX_COMPARE_COMMITS,
    };
    finish(session, &response).await
}

fn bad_input(reason: &'static str) -> GatewayError {
    GatewayError::BadRequest(reason)
}

/// Git's protocol `hash-algo` token for the captured repository format.
fn hash_algorithm(format: crate::ref_store::GitObjectFormat) -> String {
    format!("hash-algo={}", format.as_str())
}

/// Hand the response to the shared JSON reply path: bounded encoding under this
/// request's captured-output budget, the final authorization/incarnation fence,
/// then session issuance from the sealed read. `value` is serialized exactly
/// once.
async fn finish<T: Serialize>(session: browse::BrowseSession, value: T) -> Result<Response, GatewayError> {
    browse::finalize(session, &value).await
}

// ---------------------------------------------------------------------------
// Wire models.
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct RefsWire {
    repository_id: uuid::Uuid,
    storage_generation: i64,
    head: HeadInfo,
    items: Vec<RefItem>,
    next_after: Option<String>,
    /// The page filled its limit and `next_after` continues it.
    more: bool,
    format: &'static str,
    hash_algorithm: String,
    oid_hex_len: usize,
    limit: usize,
}

#[derive(Serialize)]
struct CommitsWire {
    repository_id: uuid::Uuid,
    start_oid: String,
    format: &'static str,
    hash_algorithm: String,
    oid_hex_len: usize,
    limit: usize,
    items: Vec<CommitSummary>,
    next_after: Option<usize>,
}

#[derive(Serialize)]
struct CommitDetailWire {
    #[serde(flatten)]
    detail: CommitDetail,
    format: &'static str,
    hash_algorithm: String,
    oid_hex_len: usize,
}

#[derive(Serialize)]
struct CompareWire {
    base_oid: String,
    head_oid: String,
    /// First native merge base (`git merge-base`).
    merge_base_oid: Option<String>,
    /// Every native merge base (`git merge-base --all`); more than one means a
    /// criss-cross history and `fast_forward` is false.
    merge_base_oids: Vec<String>,
    ahead: u64,
    behind: u64,
    fast_forward: bool,
    commits: Vec<CommitSummary>,
    /// More than `commits_limit` commits are ahead; counts and diff are still
    /// complete.
    truncated: bool,
    diff: String,
    changed_paths: Vec<String>,
    format: &'static str,
    hash_algorithm: String,
    oid_hex_len: usize,
    commits_limit: usize,
}

// ---------------------------------------------------------------------------
// Captured refs
// ---------------------------------------------------------------------------

/// Captured public refs (`refs/heads/*`, `refs/tags/*`, public proposal/CI
/// refs) in refname order with zero-oid deletion entries omitted.
fn captured_refs(refs: &[(String, String)]) -> Result<Vec<(String, String)>, GatewayError> {
    let mut seen = BTreeSet::new();
    let mut public = Vec::new();
    for (name, oid) in refs {
        if name.len() > 1024 || oid.len() > 1024 {
            return Err(GatewayError::Internal("captured ref is invalid"));
        }
        if !seen.insert(name) {
            return Err(GatewayError::Internal("captured ref set contains a duplicate name"));
        }
        if models::is_zero_oid(oid) {
            continue;
        }
        if !models::valid_non_zero_oid(oid) {
            return Err(GatewayError::Internal("captured ref has an invalid object id"));
        }
        if models::valid_public_ref(name) {
            public.push((name.clone(), oid.clone()));
        }
    }
    public.sort();
    Ok(public)
}

/// A short revision denotes a captured public ref, never an abbreviation.
fn captured_ref_name(refs: &[(String, String)], spec: &str) -> Result<String, GatewayError> {
    let mut found = refs.iter().filter(|(name, _)| {
        name == spec || name.strip_prefix("refs/heads/") == Some(spec) || name.strip_prefix("refs/tags/") == Some(spec)
    });
    let Some((name, _)) = found.next() else {
        return Err(GatewayError::NotFound);
    };
    if found.next().is_some() {
        return Err(bad_input("repository revision is ambiguous; use its full ref name"));
    }
    Ok(name.clone())
}

/// A compare revision: `HEAD`, a full object id of the captured closure, or a
/// captured ref name, peeled to its commit.
async fn resolve_commit(
    session: &browse::BrowseSession,
    refs: &[(String, String)],
    spec: &str,
) -> Result<String, GatewayError> {
    if spec == "HEAD" {
        return session.head_oid.clone().ok_or(GatewayError::NotFound);
    }
    if models::valid_non_zero_oid(spec) {
        if !exact_oid(spec, session.format.oid_hex_len()) {
            return Err(GatewayError::NotFound);
        }
        browse::require_reachable(session, spec).await?;
        browse::require_kind(session, spec, "commit").await?;
        return Ok(spec.to_owned());
    }
    let name = captured_ref_name(refs, spec)?;
    browse::peel(session, &format!("{name}^{{commit}}")).await
}

/// Detached/symbolic/unborn HEAD exactly as the captured ref table shows it.
fn head_info(session: &browse::BrowseSession, refs: &[(String, String)]) -> HeadInfo {
    let head_ref = session.head_ref.as_str();
    if head_ref.starts_with("refs/") {
        let oid = session
            .head_oid
            .clone()
            .or_else(|| refs.iter().find(|(name, _)| name == head_ref).map(|(_, oid)| oid.clone()));
        let kind = if oid.is_some() { "symbolic" } else { "unborn" };
        return HeadInfo { kind: kind.to_owned(), target: Some(head_ref.to_owned()), oid };
    }
    if exact_oid(head_ref, session.format.oid_hex_len()) {
        HeadInfo { kind: "detached".to_owned(), target: None, oid: Some(head_ref.to_owned()) }
    } else {
        HeadInfo { kind: "unborn".to_owned(), target: None, oid: None }
    }
}

fn exact_oid(oid: &str, len: usize) -> bool {
    oid.len() == len
        && !models::is_zero_oid(oid)
        && oid.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

// ---------------------------------------------------------------------------
// Native Git helpers over the verified computed view
// ---------------------------------------------------------------------------

async fn run_capture(
    session: &browse::BrowseSession,
    args: &[&str],
    ceiling: u64,
) -> Result<native::Captured, GatewayError> {
    let mut command = session.view.command(session.state.git_binary());
    command.args(args);
    native::run_capture(command, None, ceiling.min(session.budget()), session.deadline).await
}

async fn run_text(session: &browse::BrowseSession, args: &[&str], ceiling: u64) -> Result<String, GatewayError> {
    let output = run_capture(session, args, ceiling).await?;
    if !output.success {
        return Err(GatewayError::Internal("native Git read was refused"));
    }
    String::from_utf8(output.stdout).map_err(|_| gateway_identifier_error())
}

async fn run_bytes(session: &browse::BrowseSession, args: &[&str], ceiling: u64) -> Result<Vec<u8>, GatewayError> {
    let output = run_capture(session, args, ceiling).await?;
    if !output.success {
        return Err(GatewayError::Internal("native Git read was refused"));
    }
    Ok(output.stdout)
}

/// `cat-file --batch` with a trusted, bounded request list on stdin.
async fn run_batch(session: &browse::BrowseSession, input: Vec<u8>, ceiling: u64) -> Result<Vec<u8>, GatewayError> {
    let mut command = session.view.command(session.state.git_binary());
    command.args(["cat-file", "--batch"]);
    let ceiling = ceiling.min(session.budget());
    let output = native::run_capture_with_input(command, input, ceiling, session.deadline).await?;
    if !output.success {
        return Err(GatewayError::Internal("native metadata read was refused"));
    }
    Ok(output.stdout)
}

/// Types of the given objects from a verified view.
async fn batch_types(
    session: &browse::BrowseSession,
    oids: &BTreeSet<String>,
) -> Result<BTreeMap<String, String>, GatewayError> {
    if oids.is_empty() {
        return Ok(BTreeMap::new());
    }
    let mut input = Vec::with_capacity(oids.len() * 65);
    for oid in oids {
        input.extend_from_slice(oid.as_bytes());
        input.push(b'\n');
    }
    let ceiling = (oids.len() as u64).saturating_mul(1024).saturating_add(1024);
    let mut command = session.view.command(session.state.git_binary());
    command.args(["cat-file", "--batch-check=%(objectname) %(objecttype)"]);
    let output =
        native::run_capture_with_input(command, input, ceiling.min(session.budget()), session.deadline).await?;
    if !output.success {
        return Err(invalid_metadata());
    }
    parse_batch_types(&output.stdout, oids)
}

/// `rev-parse <ref>^{}` and require a full, repository-format peeled object.
/// Native Git follows tag-of-tag chains itself (bounded by the process limits).
async fn peel_tag(session: &browse::BrowseSession, name: &str) -> Result<String, GatewayError> {
    let peeled = browse::peel(session, &format!("{name}^{{}}")).await?;
    if !exact_oid(&peeled, session.format.oid_hex_len()) {
        return Err(gateway_identifier_error());
    }
    Ok(peeled)
}

/// Native `rev-list <start> --` order, bounded before metadata is read.
async fn commit_order(session: &browse::BrowseSession, start: &str) -> Result<Vec<String>, GatewayError> {
    let reachable = run_text(session, &["rev-list", "--count", start, "--"], 64).await?;
    let reachable: u64 =
        reachable.trim().parse().map_err(|_| GatewayError::Internal("native revision count is invalid"))?;
    if reachable > MAX_WALK_COMMITS {
        return Err(GatewayError::TooLarge);
    }
    let raw = run_text(session, &["rev-list", start, "--"], session.budget()).await?;
    let order = parse_oid_lines(raw.as_bytes())?;
    if order.len() as u64 != reachable {
        return Err(GatewayError::Internal("native revision listing differs from its count"));
    }
    Ok(order)
}

/// Bounded metadata for commits Git already listed in the captured closure.
async fn commit_summaries(
    session: &browse::BrowseSession,
    oids: &[String],
) -> Result<Vec<CommitSummary>, GatewayError> {
    if oids.is_empty() {
        return Ok(Vec::new());
    }
    let mut input = Vec::with_capacity(oids.len() * 65);
    for oid in oids {
        input.extend_from_slice(oid.as_bytes());
        input.push(b'\n');
    }
    // One frame per commit: header slack plus at most `MAX_COMMIT_BODY`
    // retained bytes (larger messages are refused, not clipped). The whole
    // read is further bounded by this request's captured-output budget.
    let ceiling = (oids.len() as u64).saturating_mul(MAX_COMMIT_BODY as u64 + 1024).saturating_add(1024);
    parse_commit_batch(&run_batch(session, input, ceiling).await?, oids)
}

async fn commit_paths(session: &browse::BrowseSession, oid: &str) -> Result<Vec<String>, GatewayError> {
    let args = ["diff-tree", "--no-commit-id", "--name-only", "-r", "-z", "--root", oid];
    let raw = run_bytes(session, &args, session.budget()).await?;
    parse_name_list(&raw)
}

fn parse_name_list(raw: &[u8]) -> Result<Vec<String>, GatewayError> {
    let mut paths = Vec::new();
    for name in raw.split(|byte| *byte == 0).filter(|name| !name.is_empty()) {
        paths.push(std::str::from_utf8(name).map_err(|_| gateway_identifier_error())?.to_owned());
    }
    Ok(paths)
}

fn gateway_identifier_error() -> GatewayError {
    GatewayError::Unsupported("repository object or path is not UTF-8")
}

fn invalid_metadata() -> GatewayError {
    GatewayError::Internal("native commit metadata is invalid")
}

/// Full object ids, one per line.
fn parse_oid_lines(raw: &[u8]) -> Result<Vec<String>, GatewayError> {
    let text = std::str::from_utf8(raw).map_err(|_| invalid_metadata())?;
    let mut oids = Vec::new();
    for line in text.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if !models::valid_non_zero_oid(line) {
            return Err(invalid_metadata());
        }
        oids.push(line.to_owned());
    }
    Ok(oids)
}

fn parse_batch_types(raw: &[u8], oids: &BTreeSet<String>) -> Result<BTreeMap<String, String>, GatewayError> {
    let text = std::str::from_utf8(raw).map_err(|_| invalid_metadata())?;
    let mut lines = text.lines();
    let mut types = BTreeMap::new();
    for oid in oids {
        let line = lines.next().ok_or_else(invalid_metadata)?;
        let (actual, kind) = line.split_once(' ').ok_or_else(invalid_metadata)?;
        if actual != oid || !matches!(kind, "commit" | "tree" | "blob" | "tag") {
            return Err(invalid_metadata());
        }
        types.insert(oid.clone(), kind.to_owned());
    }
    if lines.next().is_some() || (!raw.is_empty() && !raw.ends_with(b"\n")) {
        return Err(invalid_metadata());
    }
    Ok(types)
}

/// Decodes `cat-file --batch` commit bodies for ids Git already listed. A
/// `missing` record or a malformed body is internal, never absent.
fn parse_commit_batch(raw: &[u8], oids: &[String]) -> Result<Vec<CommitSummary>, GatewayError> {
    let mut offset = 0usize;
    let mut result = Vec::with_capacity(oids.len());
    for oid in oids {
        let end =
            raw.get(offset..).and_then(|rest| rest.iter().position(|&b| b == b'\n')).ok_or_else(invalid_metadata)?
                + offset;
        let header = std::str::from_utf8(&raw[offset..end]).map_err(|_| invalid_metadata())?;
        let mut parts = header.split(' ');
        if parts.next() != Some(oid.as_str()) || parts.next() != Some("commit") {
            return Err(invalid_metadata());
        }
        let size: usize = parts.next().and_then(|size| size.parse().ok()).ok_or_else(invalid_metadata)?;
        if parts.next().is_some() || size > raw.len().saturating_sub(end + 1) {
            return Err(invalid_metadata());
        }
        let start = end + 1;
        let finish = start + size;
        if raw.get(finish) != Some(&b'\n') {
            return Err(invalid_metadata());
        }
        result.push(decode_commit(oid, &raw[start..finish])?);
        offset = finish + 1;
    }
    if offset != raw.len() {
        return Err(invalid_metadata());
    }
    Ok(result)
}

fn decode_commit(oid: &str, raw: &[u8]) -> Result<CommitSummary, GatewayError> {
    let text = String::from_utf8_lossy(raw);
    let (header, body) = text.split_once("\n\n").unwrap_or((text.as_ref(), ""));
    let mut tree_oid = String::new();
    let mut parents = Vec::new();
    let (mut author_name, mut author_email, mut authored_at) = (String::new(), String::new(), 0);
    let (mut committer_name, mut committer_email, mut committed_at) = (String::new(), String::new(), 0);
    for line in header.lines() {
        // Continuation lines of gpgsig/mergetag/encoding headers.
        if line.starts_with(' ') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("tree ") {
            tree_oid = rest.trim().to_owned();
        } else if let Some(rest) = line.strip_prefix("parent ") {
            let parent = rest.trim();
            if models::valid_non_zero_oid(parent) {
                parents.push(parent.to_owned());
            }
        } else if let Some(rest) = line.strip_prefix("author ") {
            (author_name, author_email, authored_at) = parse_signature(rest);
        } else if let Some(rest) = line.strip_prefix("committer ") {
            (committer_name, committer_email, committed_at) = parse_signature(rest);
        }
    }
    if !models::valid_non_zero_oid(&tree_oid) {
        return Err(invalid_metadata());
    }
    let message = body.trim_end_matches(['\r', '\n']);
    if message.len() > MAX_COMMIT_BODY {
        return Err(GatewayError::TooLarge);
    }
    let message = message.to_owned();
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

fn parse_signature(signature: &str) -> (String, String, i64) {
    let Some(lt) = signature.rfind('<') else {
        return (signature.trim().to_owned(), String::new(), 0);
    };
    let name = signature[..lt].trim().to_owned();
    let rest = &signature[lt + 1..];
    let Some(gt) = rest.find('>') else {
        return (name, String::new(), 0);
    };
    let email = rest[..gt].trim().to_owned();
    let timestamp = rest[gt + 1..].split_whitespace().next().and_then(|t| t.parse::<i64>().ok()).unwrap_or(0);
    (name, email, timestamp)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "1111111111111111111111111111111111111111";
    const B: &str = "2222222222222222222222222222222222222222";
    const C: &str = "3333333333333333333333333333333333333333";
    const T: &str = "4444444444444444444444444444444444444444";

    fn pairs(entries: &[(&str, &str)]) -> Vec<(String, String)> {
        entries.iter().map(|(name, oid)| ((*name).to_owned(), (*oid).to_owned())).collect()
    }

    #[test]
    fn captured_refs_sort_skip_zero_oids_and_refuse_duplicates() {
        let refs = captured_refs(&pairs(&[
            ("refs/tags/v1", A),
            ("refs/heads/main", B),
            ("refs/heads/a", C),
            ("HEAD", B),
            ("refs/heads/gone", models::ZERO_OID),
            ("refs/rootyard-ci/jobs/1", A),
        ]))
        .unwrap();
        assert_eq!(refs, pairs(&[("refs/heads/a", C), ("refs/heads/main", B), ("refs/tags/v1", A)]));
        assert_eq!(
            captured_refs(&pairs(&[("refs/heads/x", A), ("refs/heads/x", B)])).unwrap_err(),
            GatewayError::Internal("captured ref set contains a duplicate name")
        );
    }

    #[test]
    fn short_revision_is_a_literal_captured_name() {
        let refs = pairs(&[("refs/heads/main", A), ("refs/tags/v1", B)]);
        assert_eq!(captured_ref_name(&refs, "main").unwrap(), "refs/heads/main");
        assert_eq!(captured_ref_name(&refs, "v1").unwrap(), "refs/tags/v1");
        assert_eq!(captured_ref_name(&refs, "refs/heads/main").unwrap(), "refs/heads/main");
        assert_eq!(captured_ref_name(&refs, "refs/heads/mai").unwrap_err(), GatewayError::NotFound);
        let ambiguous = pairs(&[("refs/heads/dup", A), ("refs/tags/dup", B)]);
        assert!(matches!(captured_ref_name(&ambiguous, "dup"), Err(GatewayError::BadRequest(_))));
    }

    #[test]
    fn full_oid_check_is_format_exact_and_zero_free() {
        assert!(exact_oid(A, 40));
        assert!(!exact_oid(&A[..39], 40));
        assert!(!exact_oid(&"A".repeat(40), 40));
        assert!(!exact_oid(models::ZERO_OID, 40));
        assert!(exact_oid(&"a".repeat(64), 64));
        assert_eq!(hash_algorithm(crate::ref_store::GitObjectFormat::Sha256), "hash-algo=sha256");
    }

    #[test]
    fn batch_types_require_exact_header_only_records() {
        let typed = BTreeSet::from([A.to_owned(), B.to_owned()]);
        let raw = format!("{A} commit\n{B} tag\n");
        let types = parse_batch_types(raw.as_bytes(), &typed).unwrap();
        assert_eq!(types.get(A).map(String::as_str), Some("commit"));
        assert_eq!(types.get(B).map(String::as_str), Some("tag"));
        for bad in [
            format!("{A} missing\n"),
            format!("{A} commit\n{B} tag"),
            format!("{A} commit 5\nhello\n{B} tag\n"),
            format!("{A} commit\n{B} blob\nextra\n"),
        ] {
            assert_eq!(parse_batch_types(bad.as_bytes(), &typed).unwrap_err(), invalid_metadata());
        }
    }

    #[test]
    fn oid_lines_and_names_reject_garbage() {
        assert_eq!(parse_oid_lines(format!("{A}\n{B}\n").as_bytes()).unwrap(), [A.to_owned(), B.to_owned()]);
        assert_eq!(parse_oid_lines(b"\n").unwrap(), Vec::<String>::new());
        assert_eq!(parse_oid_lines(b"abc\n").unwrap_err(), invalid_metadata());
        assert_eq!(parse_name_list(b"a\tb\0c\nd\0\0").unwrap(), ["a\tb".to_owned(), "c\nd".to_owned()]);
        assert!(matches!(parse_name_list(b"\xff\0"), Err(GatewayError::Unsupported(_))));
    }

    #[test]
    fn commit_decode_ignores_continuation_headers_and_refuses_oversize_bodies() {
        let header = format!(
            "tree {T}\nparent {B}\nauthor A U <a@example.invalid> 1700000000 +0000\n\
             committer C U <c@example.invalid> 1700000001 +0000\n\
             mergetag object {C}\n tree {C}\n"
        );
        // Exactly at the ceiling (trailing newlines are not part of the
        // message) is accepted and decodes unchanged.
        let at_limit = format!("{header}\n{}", "\u{4e2d}".repeat(MAX_COMMIT_BODY / 3));
        let message_bytes = at_limit.len() - header.len() - 1;
        assert!(message_bytes <= MAX_COMMIT_BODY && !at_limit.ends_with('\n'));
        let raw = format!("{A} commit {}\n{at_limit}\n", at_limit.len());
        let decoded = parse_commit_batch(raw.as_bytes(), &[A.to_owned()]).unwrap();
        assert_eq!(decoded[0].tree_oid, T);
        assert_eq!(decoded[0].parents, vec![B.to_owned()]);
        assert_eq!(decoded[0].committer_email, "c@example.invalid");
        assert_eq!(decoded[0].committed_at, 1_700_000_001);
        assert_eq!(decoded[0].message.len(), message_bytes);
        // One byte past the ceiling is an explicit refusal, never a clip.
        let over = format!("{header}\n{}", "x".repeat(MAX_COMMIT_BODY + 1));
        let raw = format!("{A} commit {}\n{over}\n", over.len());
        assert_eq!(parse_commit_batch(raw.as_bytes(), &[A.to_owned()]).unwrap_err(), GatewayError::TooLarge);
        for bad in [format!("{A} missing\n"), format!("{A} blob 3\nabc\n"), format!("{A} commit 8\nno-tree\n")] {
            assert_eq!(parse_commit_batch(bad.as_bytes(), &[A.to_owned()]).unwrap_err(), invalid_metadata());
        }
    }

    #[test]
    fn commit_decode_keeps_subject_and_body() {
        let body = format!("tree {T}\n\nsubject \u{4e2d}\n\nbody line\n\n");
        let decoded = decode_commit(A, body.as_bytes()).unwrap();
        assert_eq!(decoded.subject, "subject \u{4e2d}");
        assert_eq!(decoded.message, "subject \u{4e2d}\n\nbody line");
        assert!(decoded.parents.is_empty());
    }
}
