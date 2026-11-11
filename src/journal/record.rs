//! Parsing, request/receipt evidence, and the canonical settlement shape.
use super::core::{entries, exists, read, validate};
use super::{HookEvent, MAX_BYTES, MAX_EVENT_BYTES, MAX_REFS, Operation, RefChange};
use anyhow::{Context, Result, ensure};
use std::collections::HashSet;

pub(crate) fn valid_ref(s: &str) -> bool {
    if s.len() > 1024 {
        return false;
    }
    if !s.starts_with("refs/") {
        return !s.is_empty() && s.bytes().all(|b| b.is_ascii_uppercase() || b == b'_');
    }
    !s.ends_with('/')
        && !s.ends_with('.')
        && !s.contains("..")
        && !s.contains("@{")
        && s.split('/').all(|p| !p.is_empty() && !p.starts_with('.') && !p.ends_with(".lock"))
        && !s.bytes().any(|b| b <= 32 || b == 127 || b"~^:?*[\\".contains(&b))
}
fn valid_oid(s: &str) -> bool {
    matches!(s.len(), 40 | 64) && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub(super) fn parse(input: &[u8]) -> Result<Vec<RefChange>> {
    ensure!(input.len() <= MAX_BYTES, "hook payload exceeds limit");
    let text = std::str::from_utf8(input).context("non UTF-8 ref transaction")?;
    ensure!(text.is_empty() || text.ends_with('\n'), "truncated hook payload");
    let mut result = Vec::new();
    for (index, line) in text.lines().enumerate() {
        ensure!(index < MAX_REFS, "too many reference updates");
        let fields: Vec<_> = line.split(' ').collect();
        ensure!(
            fields.len() == 3
                && valid_oid(fields[0])
                && valid_oid(fields[1])
                && fields[0].len() == fields[1].len()
                && valid_ref(fields[2]),
            "unsupported reference transaction payload"
        );
        result.push(RefChange { old_oid: fields[0].into(), new_oid: fields[1].into(), ref_name: fields[2].into() });
    }
    Ok(result)
}
fn valid_changes(changes: &[RefChange]) -> bool {
    changes.len() <= MAX_REFS
        && changes.iter().all(|c| {
            valid_ref(&c.ref_name)
                && valid_oid(&c.old_oid)
                && valid_oid(&c.new_oid)
                && c.old_oid.len() == c.new_oid.len()
        })
}

/// Raw diagnostic evidence only. Native transactions can nest and their
/// terminal callbacks are not authoritative successful-ref subsets.
pub fn events(op: &Operation) -> Result<Vec<HookEvent>> {
    Ok(events_with_size(op)?.0)
}
pub(super) fn events_with_size(op: &Operation) -> Result<(Vec<HookEvent>, usize)> {
    validate(op)?;
    ensure!(!exists(&op.path.join("corrupt"))?, "journal has incomplete hook evidence");
    let mut result = Vec::new();
    let mut total_bytes = 0usize;
    for path in entries(&op.path)? {
        let name = path.file_name().and_then(|s| s.to_str()).context("invalid event filename")?;
        if name == "operation.json"
            || name == "hook.lock"
            || name == "active.lock"
            || name == "publication.grant"
            || name == "finished"
            || name == "interrupted"
            || name == "fenced"
            || name == "post-receive.json"
            || name == "pre-receive.json"
            || name.starts_with(".tmp-")
        {
            continue;
        }
        let ordinal = name.strip_suffix(".event.json").context("unexpected journal record")?;
        let bytes = read(&path)?;
        total_bytes = total_bytes.checked_add(bytes.len()).context("event byte count overflow")?;
        ensure!(total_bytes <= MAX_EVENT_BYTES, "operation event log exceeds byte limit");
        let event: HookEvent = serde_json::from_slice(&bytes)?;
        ensure!(
            event.ordinal > 0 && ordinal == format!("{:020}", event.ordinal) && valid_changes(&event.changes),
            "invalid hook event"
        );
        result.push(event);
    }
    result.sort_by_key(|e| e.ordinal);
    ensure!(
        result.iter().enumerate().all(|(i, e)| e.ordinal == i as i64 + 1),
        "missing or duplicate hook event ordinal"
    );
    Ok((result, total_bytes))
}

/// Git post-receive's successful subset. Do not infer a successful HTTP/RPC
/// outcome from its presence: the caller must separately verify normal exit.
pub fn receipts(op: &Operation) -> Result<Option<Vec<RefChange>>> {
    validate(op)?;
    ensure!(!exists(&op.path.join("corrupt"))?, "journal has incomplete hook evidence");
    let path = op.path.join("post-receive.json");
    if !exists(&path)? {
        return Ok(None);
    }
    let changes: Vec<RefChange> = serde_json::from_slice(&read(&path)?)?;
    ensure!(valid_changes(&changes), "invalid post-receive receipt");
    Ok(Some(changes))
}

/// Whole-push admission request. This proves only validation, not publication.
pub fn requests(op: &Operation) -> Result<Option<Vec<RefChange>>> {
    validate(op)?;
    let path = op.path.join("pre-receive.json");
    if !exists(&path)? {
        return Ok(None);
    }
    let changes: Vec<RefChange> = serde_json::from_slice(&read(&path)?)?;
    validate_request(&changes)?;
    Ok(Some(changes))
}
pub(super) fn validate_request(changes: &[RefChange]) -> Result<()> {
    ensure!(valid_changes(changes), "invalid pre-receive request");
    let mut names = HashSet::new();
    ensure!(
        changes.iter().all(|c| c.ref_name.starts_with("refs/") && names.insert(&c.ref_name)),
        "duplicate or unsupported pre-receive ref target"
    );
    Ok(())
}

/// An interrupted receive is certain only when no parent publication window was
/// ever granted. Every I/O error other than a definite absence stays unknown.
pub(crate) fn no_parent_publication_possible(
    operation: &Operation,
    no_events: bool,
    no_receipt: bool,
    no_request: bool,
) -> bool {
    operation.requires_parent_publication
        && no_events
        && no_receipt
        && no_request
        && matches!(std::fs::symlink_metadata(operation.path.join("publication.grant")),
            Err(ref error) if error.kind() == std::io::ErrorKind::NotFound)
}

/// The one canonical evidence shape shared by live ref-transaction settlement
/// and startup/runtime reconciliation. A committed operation is replayed with
/// byte-identical JSON, so a crash after `tx.commit()` but before retirement
/// cannot wedge on `terminal operation evidence mismatch`.
pub fn ref_transaction_evidence(
    operation: &Operation,
    generation: i64,
    finished: bool,
    interrupted: bool,
    reference_events: &[HookEvent],
    requested: Option<&[RefChange]>,
    post_receive: Option<&[RefChange]>,
) -> serde_json::Value {
    let repeated = post_receive.is_some_and(|items| {
        let mut seen = HashSet::new();
        items.iter().any(|item| !seen.insert(&item.ref_name))
    });
    let ungranted_without_hooks = no_parent_publication_possible(
        operation,
        reference_events.is_empty(),
        post_receive.is_none(),
        requested.is_none(),
    );
    let mut evidence = serde_json::json!({
        "version": 1,
        "finished": finished,
        "interrupted": interrupted,
        "reference_events": reference_events,
        "requested": requested,
        "post_receive": post_receive,
        "storage_generation_matches": operation.storage_generation == generation,
        "repeated_receipt_refs": repeated,
        "ungranted_without_hooks": ungranted_without_hooks,
    });
    if let Some(intent) = &operation.idempotency {
        evidence["idempotency_key_sha256"] = serde_json::json!(intent.key_sha256);
        evidence["idempotency_request_sha256"] = serde_json::json!(intent.request_sha256);
    }
    evidence
}
