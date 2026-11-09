//! Bounded repository browsing from the same sealed Blob snapshot as Smart HTTP.
//!
//! No local repository is authoritative. Each request captures the current refs,
//! materializes their protected pack closure and discards its computed view.
use std::sync::Arc;

use axum::{
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, header},
    response::Response,
};
use base64::Engine;
use bytes::Bytes;
use serde::Serialize;
use tokio::time::Instant;

use super::{
    error::GatewayError,
    native,
    serving::lookup,
    session::{authenticate, authority_error, read_authorization},
    snapshot::{self, ComputedView},
    state::{BlobGitState, ByteLease},
};
use crate::browse::models::{
    self, BlobByOidQuery, BlobQuery, BlobResponse, TreeByOidQuery, TreeEntry, TreeQuery, TreeResponse,
};

const MAX_CAPTURE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_MEMORY_BYTES: u64 = 32 * 1024 * 1024;

pub(super) async fn tree(
    State(state): State<Arc<BlobGitState>>,
    Path((owner, name)): Path<(String, String)>,
    Query(query): Query<TreeQuery>,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    read_tree(state, owner, name, query, headers).await
}

pub(super) async fn tree_by_oid(
    State(state): State<Arc<BlobGitState>>,
    Path((owner, name, oid)): Path<(String, String, String)>,
    Query(query): Query<TreeByOidQuery>,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    read_tree(
        state,
        owner,
        name,
        TreeQuery { oid: Some(oid), path: query.path, after: query.after, limit: query.limit },
        headers,
    )
    .await
}

pub(super) async fn blob(
    State(state): State<Arc<BlobGitState>>,
    Path((owner, name)): Path<(String, String)>,
    Query(query): Query<BlobQuery>,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    read_blob(state, owner, name, query, headers).await
}

pub(super) async fn blob_by_oid(
    State(state): State<Arc<BlobGitState>>,
    Path((owner, name, oid)): Path<(String, String, String)>,
    Query(query): Query<BlobByOidQuery>,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    read_blob(state, owner, name, BlobQuery { oid: Some(oid), path: query.path }, headers).await
}

async fn read_tree(
    state: Arc<BlobGitState>,
    owner: String,
    name: String,
    query: TreeQuery,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let path = models::normalize_rel_path(query.path.as_deref()).map_err(bad_input)?;
    let limit = models::validate_limit(query.limit).map_err(bad_input)?;
    let after = validate_tree_after(query.after.as_deref())?;
    let spec = query.oid.as_deref().unwrap_or("HEAD");
    validate_spec(spec)?;
    let actor = authenticate(&state, &headers).await?;
    let deadline = state.deadline();
    let slot = state.slot().await?;
    let memory = memory_budget(&state);
    let lease = state.reserve_bytes(memory)?;
    let serving = lookup(state.pool(), &actor, &owner, &name, false, state.store().backend_identity(), deadline)
        .await
        .map_err(authority_error)?;
    let authorization = read_authorization(state.clone(), &actor, &serving);
    let refs = snapshot::load_ref_view(&state, &serving, deadline).await?;
    let spec = captured_revision(&refs, spec)?;
    let view = snapshot::build_view(&state, &refs, deadline).await?;
    authorization.revalidate(deadline).await?;
    let root_oid = root_oid(&state, &view, &spec, memory, deadline).await?;
    let expression = if path.is_empty() { format!("{root_oid}^{{tree}}") } else { format!("{root_oid}:{path}") };
    let tree_oid = resolve(&state, &view, &expression, deadline).await?;
    require_type(&state, &view, &tree_oid, "tree", deadline).await?;
    let raw =
        run(&state, &view, &["ls-tree", "-z", "-l", &tree_oid], (memory / 8).min(MAX_CAPTURE_BYTES), deadline).await?;
    let mut entries = parse_tree(&raw, &path, after, limit)?;
    let more = entries.len() > limit;
    entries.truncate(limit);
    let next_after = if more { entries.last().map(|entry| entry.name.clone()) } else { None };
    let result = TreeResponse { oid: root_oid, tree_oid, path, items: entries, next_after };
    // This includes empty trees, just as the Blob handler includes empty files.
    authorization.revalidate(deadline).await?;
    json_response(&state, &result, slot, lease)
}

async fn read_blob(
    state: Arc<BlobGitState>,
    owner: String,
    name: String,
    query: BlobQuery,
    headers: HeaderMap,
) -> Result<Response, GatewayError> {
    let path = models::normalize_rel_path(query.path.as_deref()).map_err(bad_input)?;
    let spec = query.oid.as_deref().unwrap_or("HEAD");
    validate_spec(spec)?;
    if path.is_empty() && !models::valid_non_zero_oid(spec) {
        return Err(GatewayError::BadRequest("a file path or full blob object identifier is required"));
    }
    let actor = authenticate(&state, &headers).await?;
    let deadline = state.deadline();
    let slot = state.slot().await?;
    let memory = memory_budget(&state);
    let lease = state.reserve_bytes(memory)?;
    let serving = lookup(state.pool(), &actor, &owner, &name, false, state.store().backend_identity(), deadline)
        .await
        .map_err(authority_error)?;
    let authorization = read_authorization(state.clone(), &actor, &serving);
    let refs = snapshot::load_ref_view(&state, &serving, deadline).await?;
    let spec = captured_revision(&refs, spec)?;
    let view = snapshot::build_view(&state, &refs, deadline).await?;
    authorization.revalidate(deadline).await?;
    let oid = if path.is_empty() {
        reachable(&state, &view, &spec, memory, deadline).await?;
        resolve(&state, &view, &spec, deadline).await?
    } else {
        let root = root_oid(&state, &view, &spec, memory, deadline).await?;
        resolve(&state, &view, &format!("{root}:{path}"), deadline).await?
    };
    require_type(&state, &view, &oid, "blob", deadline).await?;
    let raw_size = run(&state, &view, &["cat-file", "-s", &oid], 64, deadline).await?;
    let size = std::str::from_utf8(&raw_size)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .ok_or(GatewayError::Internal("native blob size is invalid"))?;
    // Twelve times the payload covers base64, optional text and worst-case
    // JSON escaping together with their live input/output buffers.
    let max_blob = MAX_CAPTURE_BYTES.min(memory / 12).min(state.limits().max_response_bytes / 8);
    if size > max_blob {
        return Err(GatewayError::TooLarge);
    }
    let raw = run(&state, &view, &["cat-file", "blob", &oid], max_blob, deadline).await?;
    if raw.len() as u64 != size {
        return Err(GatewayError::Internal("native blob length differs from its object size"));
    }
    let is_binary = raw.contains(&0) || std::str::from_utf8(&raw).is_err();
    let content = if is_binary { None } else { std::str::from_utf8(&raw).ok().map(str::to_owned) };
    let content_base64 = base64::engine::general_purpose::STANDARD.encode(&raw);
    let result = BlobResponse { oid, size, is_binary, content, content_base64 };
    authorization.revalidate(deadline).await?;
    json_response(&state, &result, slot, lease)
}

fn bad_input(_: crate::Error) -> GatewayError {
    GatewayError::BadRequest("invalid repository browse parameters")
}

fn validate_spec(spec: &str) -> Result<(), GatewayError> {
    if models::valid_revision_spec(spec) {
        Ok(())
    } else {
        Err(GatewayError::BadRequest("invalid repository revision"))
    }
}

fn validate_tree_after(after: Option<&str>) -> Result<Option<&str>, GatewayError> {
    if let Some(name) = after
        && (name.is_empty() || name.len() > 4096 || name.contains(['/', '\0']) || matches!(name, "." | ".."))
    {
        return Err(GatewayError::BadRequest("invalid tree continuation name"));
    }
    // Git tree names can contain tabs and newlines. An API-generated cursor
    // must accept the same UTF-8 names on the next request (URL-encoded).
    Ok(after)
}

fn memory_budget(state: &BlobGitState) -> u64 {
    MAX_MEMORY_BYTES.min(state.limits().max_inflight_bytes)
}

fn captured_revision(refs: &snapshot::RefView, spec: &str) -> Result<String, GatewayError> {
    if models::valid_non_zero_oid(spec) || spec == "HEAD" {
        return Ok(spec.to_owned());
    }
    // A short revision denotes a captured branch/tag, never Git's object-id
    // abbreviation or another native revision fallback.
    let mut found = refs.refs.iter().filter(|(name, _)| {
        name == spec || name.strip_prefix("refs/heads/") == Some(spec) || name.strip_prefix("refs/tags/") == Some(spec)
    });
    let Some((name, _)) = found.next() else {
        return Err(GatewayError::NotFound);
    };
    if found.next().is_some() {
        return Err(GatewayError::BadRequest("repository revision is ambiguous; use its full ref name"));
    }
    Ok(name.clone())
}

async fn run(
    state: &BlobGitState,
    view: &ComputedView,
    args: &[&str],
    ceiling: u64,
    deadline: Instant,
) -> Result<Vec<u8>, GatewayError> {
    let mut command = view.command(state.git_binary());
    command.args(args);
    let output = native::run_capture(command, None, ceiling, deadline).await?;
    if !output.success {
        return Err(GatewayError::Internal("native repository browse was refused"));
    }
    Ok(output.stdout)
}

async fn resolve(
    state: &BlobGitState,
    view: &ComputedView,
    expression: &str,
    deadline: Instant,
) -> Result<String, GatewayError> {
    let mut command = view.command(state.git_binary());
    command.args(["rev-parse", "--verify", "--quiet", "--end-of-options", expression]);
    let output = native::run_capture(command, None, 128, deadline).await?;
    if !output.success {
        return Err(GatewayError::NotFound);
    }
    let oid = std::str::from_utf8(&output.stdout)
        .ok()
        .map(str::trim)
        .filter(|oid| models::valid_non_zero_oid(oid))
        .ok_or(GatewayError::Internal("native repository object identifier is invalid"))?;
    Ok(oid.to_owned())
}

async fn require_type(
    state: &BlobGitState,
    view: &ComputedView,
    oid: &str,
    expected: &str,
    deadline: Instant,
) -> Result<(), GatewayError> {
    let kind = run(state, view, &["cat-file", "-t", oid], 64, deadline).await?;
    if kind.strip_suffix(b"\n") == Some(expected.as_bytes()) { Ok(()) } else { Err(GatewayError::NotFound) }
}

async fn root_oid(
    state: &BlobGitState,
    view: &ComputedView,
    spec: &str,
    memory: u64,
    deadline: Instant,
) -> Result<String, GatewayError> {
    if models::valid_non_zero_oid(spec) {
        reachable(state, view, spec, memory, deadline).await?;
    }
    // Peel annotated tags, including tags of tags, before resolving a path.
    let oid = resolve(state, view, &format!("{spec}^{{}}"), deadline).await?;
    let kind = run(state, view, &["cat-file", "-t", &oid], 64, deadline).await?;
    if kind != b"commit\n" && kind != b"tree\n" {
        return Err(GatewayError::NotFound);
    }
    Ok(oid)
}

async fn reachable(
    state: &BlobGitState,
    view: &ComputedView,
    oid: &str,
    memory: u64,
    deadline: Instant,
) -> Result<(), GatewayError> {
    // Registered packs may also contain unreferenced objects. Knowing a full
    // object id never authorizes browsing those bytes. Only this captured ref
    // closure admits direct object-id reads, including reachable history.
    let raw = run(state, view, &["rev-list", "--objects", "--all", "--no-object-names"], memory / 2, deadline).await?;
    if raw.split(|byte| *byte == b'\n').any(|line| line == oid.as_bytes()) {
        Ok(())
    } else {
        Err(GatewayError::NotFound)
    }
}

fn parse_tree(raw: &[u8], path: &str, after: Option<&str>, limit: usize) -> Result<Vec<TreeEntry>, GatewayError> {
    // Keep at most one page plus its continuation entry. A long parent path
    // must not be copied once for every entry in a large native listing.
    let mut selected = std::collections::BTreeMap::new();
    for record in raw.split(|byte| *byte == 0).filter(|record| !record.is_empty()) {
        let tab = record
            .iter()
            .position(|byte| *byte == b'\t')
            .ok_or(GatewayError::Internal("native tree entry is invalid"))?;
        let metadata =
            std::str::from_utf8(&record[..tab]).map_err(|_| GatewayError::Internal("native tree entry is invalid"))?;
        let name = std::str::from_utf8(&record[tab + 1..])
            .map_err(|_| GatewayError::Unsupported("tree contains a filename that is not UTF-8"))?;
        let parts: Vec<_> = metadata.split_ascii_whitespace().collect();
        if parts.len() != 4 || name.is_empty() || name.contains('/') || !models::valid_non_zero_oid(parts[2]) {
            return Err(GatewayError::Internal("native tree entry is invalid"));
        }
        if name.len() > 4096 {
            return Err(GatewayError::Unsupported("tree contains a filename beyond the browse name limit"));
        }
        let size = if parts[3] == "-" {
            None
        } else {
            Some(parts[3].parse().map_err(|_| GatewayError::Internal("native tree size is invalid"))?)
        };
        if after.is_some_and(|cursor| name <= cursor)
            || (selected.len() > limit && selected.last_key_value().is_some_and(|(last, _)| *last <= name))
        {
            continue;
        }
        selected.insert(name, (parts[0], parts[1], parts[2], size));
        if selected.len() > limit + 1 {
            selected.pop_last();
        }
    }
    Ok(selected
        .into_iter()
        .map(|(name, (mode, kind, oid, size))| TreeEntry {
            name: name.to_owned(),
            path: if path.is_empty() { name.to_owned() } else { format!("{path}/{name}") },
            mode: mode.to_owned(),
            kind: kind.to_owned(),
            oid: oid.to_owned(),
            size,
        })
        .collect())
}

fn json_response<T: Serialize>(
    state: &BlobGitState,
    value: &T,
    slot: tokio::sync::OwnedSemaphorePermit,
    lease: ByteLease,
) -> Result<Response, GatewayError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| GatewayError::Internal("repository browse response could not be encoded"))?;
    if bytes.len() as u64 > state.limits().max_response_bytes {
        return Err(GatewayError::TooLarge);
    }
    // Keep the bounded response's capacity charged until its body is consumed
    // or discarded, even after the request future has returned.
    let stream =
        futures_util::stream::unfold((Some(Bytes::from(bytes)), slot, lease), |(bytes, slot, lease)| async move {
            bytes.map(|bytes| (Ok::<_, std::convert::Infallible>(bytes), (None, slot, lease)))
        });
    let mut response = Response::new(Body::from_stream(stream));
    response.headers_mut().insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/json"));
    response.headers_mut().insert(header::CACHE_CONTROL, header::HeaderValue::from_static("no-store"));
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_decoder_preserves_spaces_tabs_and_empty_blob_size() {
        let oid = "a".repeat(40);
        let raw =
            format!("100644 blob {oid}       0\tempty file\0") + &format!("100644 blob {oid}       3\twith\ttab\0");
        let entries = parse_tree(raw.as_bytes(), "nested", None, 100).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, "nested/empty file");
        assert_eq!(entries[0].size, Some(0));
        assert_eq!(entries[1].name, "with\ttab");
    }

    #[test]
    fn tree_decoder_handles_sha256_tree_and_gitlink() {
        let oid = "b".repeat(64);
        let raw =
            format!("160000 commit {oid}       -\tz-submodule\0") + &format!("040000 tree {oid}       -\ta-dir\0");
        let entries = parse_tree(raw.as_bytes(), "", None, 100).unwrap();
        assert_eq!(entries[0].name, "a-dir");
        assert_eq!(entries[0].kind, "tree");
        assert_eq!(entries[1].kind, "commit");
        assert_eq!(entries[0].size, None);
    }

    #[test]
    fn tree_page_sorts_before_truncating_and_keeps_one_continuation() {
        let oid = "a".repeat(40);
        let raw: String =
            ["z", "d", "b", "a", "c"].iter().map(|name| format!("100644 blob {oid}       1\t{name}\0")).collect();
        let entries = parse_tree(raw.as_bytes(), "nested", Some("a"), 2).unwrap();
        assert_eq!(entries.iter().map(|entry| entry.name.as_str()).collect::<Vec<_>>(), ["b", "c", "d"]);
        assert_eq!(entries[0].path, "nested/b");
    }

    #[test]
    fn tree_continuation_roundtrips_a_tabbed_filename() {
        let oid = "a".repeat(40);
        let raw: String =
            ["a\tfile", "b\nfile", "c"].iter().map(|name| format!("100644 blob {oid}       1\t{name}\0")).collect();
        let page = parse_tree(raw.as_bytes(), "", None, 1).unwrap();
        let cursor = page[0].name.as_str();
        let after = validate_tree_after(Some(cursor)).unwrap();
        let next = parse_tree(raw.as_bytes(), "", after, 1).unwrap();
        assert_eq!(next[0].name, "b\nfile");
        let after = validate_tree_after(Some(&next[0].name)).unwrap();
        assert_eq!(parse_tree(raw.as_bytes(), "", after, 1).unwrap()[0].name, "c");
    }
}
