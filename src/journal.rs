//! Synchronous, local-volume evidence for native Git reference transactions.
//! Callers serialize operations per repository and retire only after SQL commit.
use anyhow::{Context, Result, bail, ensure};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};
use uuid::Uuid;

const MAX_BYTES: usize = 1024 * 1024;
const MAX_RECORD_BYTES: usize = 2 * MAX_BYTES;
const MAX_EVENT_BYTES: usize = 16 * MAX_BYTES;
const MAX_ENTRIES: usize = 16384;
const MAX_REFS: usize = 4096;

#[path = "journal/core.rs"]
mod core;
pub use core::{
    ActiveGuard, HookEvent, HookPhase, Operation, RefChange, begin, begin_active,
    begin_active_with, pending, sequence,
};
pub(crate) use core::{atomic, begin_ci, begin_ci_service, exists, mkdir, read, safe_path};
use core::{entries, load, op_name, sync_dir, validate};

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
        && s.split('/')
            .all(|p| !p.is_empty() && !p.starts_with('.') && !p.ends_with(".lock"))
        && !s
            .bytes()
            .any(|b| b <= 32 || b == 127 || b"~^:?*[\\".contains(&b))
}
fn valid_oid(s: &str) -> bool {
    matches!(s.len(), 40 | 64)
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn parse(input: &[u8]) -> Result<Vec<RefChange>> {
    ensure!(input.len() <= MAX_BYTES, "hook payload exceeds limit");
    let text = std::str::from_utf8(input).context("non UTF-8 ref transaction")?;
    ensure!(
        text.is_empty() || text.ends_with('\n'),
        "truncated hook payload"
    );
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
        result.push(RefChange {
            old_oid: fields[0].into(),
            new_oid: fields[1].into(),
            ref_name: fields[2].into(),
        });
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
fn events_with_size(op: &Operation) -> Result<(Vec<HookEvent>, usize)> {
    validate(op)?;
    ensure!(
        !exists(&op.path.join("corrupt"))?,
        "journal has incomplete hook evidence"
    );
    let mut result = Vec::new();
    let mut total_bytes = 0usize;
    for path in entries(&op.path)? {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .context("invalid event filename")?;
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
        let ordinal = name
            .strip_suffix(".event.json")
            .context("unexpected journal record")?;
        let bytes = read(&path)?;
        total_bytes = total_bytes
            .checked_add(bytes.len())
            .context("event byte count overflow")?;
        ensure!(
            total_bytes <= MAX_EVENT_BYTES,
            "operation event log exceeds byte limit"
        );
        let event: HookEvent = serde_json::from_slice(&bytes)?;
        ensure!(
            event.ordinal > 0
                && ordinal == format!("{:020}", event.ordinal)
                && valid_changes(&event.changes),
            "invalid hook event"
        );
        result.push(event);
    }
    result.sort_by_key(|e| e.ordinal);
    ensure!(
        result
            .iter()
            .enumerate()
            .all(|(i, e)| e.ordinal == i as i64 + 1),
        "missing or duplicate hook event ordinal"
    );
    Ok((result, total_bytes))
}

/// Git post-receive's successful subset. Do not infer a successful HTTP/RPC
/// outcome from its presence: the caller must separately verify normal exit.
pub fn receipts(op: &Operation) -> Result<Option<Vec<RefChange>>> {
    validate(op)?;
    ensure!(
        !exists(&op.path.join("corrupt"))?,
        "journal has incomplete hook evidence"
    );
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
fn validate_request(changes: &[RefChange]) -> Result<()> {
    ensure!(valid_changes(changes), "invalid pre-receive request");
    let mut names = HashSet::new();
    ensure!(
        changes
            .iter()
            .all(|c| c.ref_name.starts_with("refs/") && names.insert(&c.ref_name)),
        "duplicate or unsupported pre-receive ref target"
    );
    Ok(())
}

/// Persist that process completion was not observed before startup recovery.
pub fn mark_interrupted(op: &Operation) -> Result<()> {
    validate(op)?;
    atomic(&op.path.join("interrupted"), b"", false)
}
pub fn is_interrupted(op: &Operation) -> Result<bool> {
    validate(op)?;
    let path = op.path.join("interrupted");
    if !exists(&path)? {
        return Ok(false);
    }
    ensure!(read(&path)?.is_empty(), "invalid interrupted marker");
    Ok(true)
}
/// The writer lost its PostgreSQL admission before publishing. Local refs may
/// have advanced inside native Git; reconciliation restores their old OIDs and
/// retires the journal without creating SQL ref history.
pub fn mark_fenced_aborted(op: &Operation) -> Result<()> {
    validate(op)?;
    atomic(&op.path.join("fenced"), b"", false)
}
pub fn is_fenced_aborted(op: &Operation) -> Result<bool> {
    validate(op)?;
    let path = op.path.join("fenced");
    if !exists(&path)? {
        return Ok(false);
    }
    ensure!(read(&path)?.is_empty(), "invalid fenced marker");
    Ok(true)
}
/// Mark verified evidence loss. This is not an inference from Git's exit code.
pub fn mark_corrupt(op: &Operation) -> Result<()> {
    validate(op)?;
    atomic(&op.path.join("corrupt"), b"", false)
}

/// Canonical bounded evidence for operator inspection and immutable resolution.
pub fn evidence(op: &Operation) -> Result<serde_json::Value> {
    Ok(
        serde_json::json!({"operation":op,"reference_events":events(op)?,"requested":requests(op)?,"post_receive":receipts(op)?,"finished":is_finished(op)?,"interrupted":is_interrupted(op)?,"fenced_aborted":is_fenced_aborted(op)?}),
    )
}
pub fn evidence_digest(op: &Operation) -> Result<String> {
    use sha2::Digest;
    Ok(hex::encode(sha2::Sha256::digest(serde_json::to_vec(
        &evidence(op)?,
    )?)))
}
pub fn finish(op: &Operation) -> Result<()> {
    validate(op)?;
    atomic(&op.path.join("finished"), b"", false)
}
pub fn is_finished(op: &Operation) -> Result<bool> {
    validate(op)?;
    let p = op.path.join("finished");
    if !exists(&p)? {
        return Ok(false);
    }
    ensure!(read(&p)?.is_empty(), "invalid finished marker");
    Ok(true)
}
pub fn retire(op: &Operation) -> Result<()> {
    ensure!(is_finished(op)?, "cannot retire running operation");
    // Caller has committed SQL. Publish retirement before recursive cleanup;
    // interrupted cleanup must not turn already-projected evidence into a
    // corrupt pending operation on restart.
    let parent = op.path.parent().context("operation parent")?;
    let retired = parent.join(format!(".retired-{}", op_name(op)));
    ensure!(!exists(&retired)?, "retirement destination already exists");
    fs::rename(&op.path, &retired)?;
    sync_dir(parent)?;
    fs::remove_dir_all(&retired)?;
    sync_dir(parent)
}

fn hook_lock(op: &Operation) -> Result<File> {
    validate(op)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(op.path.join("hook.lock"))?;
    ensure!(
        file.metadata()?.is_file(),
        "hook lock is not a regular file"
    );
    file.lock_exclusive()?;
    Ok(file)
}
fn record(op: &Operation, phase: HookPhase, input: &[u8]) -> Result<()> {
    let _lock = hook_lock(op)?;
    ensure!(!is_finished(op)?, "operation already finished");
    let changes = parse(input)?;
    validate_namespace(op, &changes)?;
    let (previous, total_bytes) = events_with_size(op)?;
    ensure!(previous.len() < MAX_ENTRIES - 7, "too many hook events");
    let ordinal = previous
        .last()
        .map_or(0, |e| e.ordinal)
        .checked_add(1)
        .context("hook event ordinal exhausted")?;
    let event = HookEvent {
        ordinal,
        phase,
        changes,
    };
    let bytes = serde_json::to_vec(&event)?;
    ensure!(
        bytes.len() <= MAX_RECORD_BYTES,
        "event record exceeds byte limit"
    );
    ensure!(
        bytes.len() <= MAX_EVENT_BYTES - total_bytes,
        "operation event log exceeds byte limit"
    );
    atomic(
        &op.path.join(format!("{ordinal:020}.event.json")),
        &bytes,
        false,
    )
}
fn record_receipt(op: &Operation, input: &[u8]) -> Result<()> {
    let _lock = hook_lock(op)?;
    ensure!(!is_finished(op)?, "operation already finished");
    let changes = parse(input)?;
    ensure!(
        changes.iter().all(|c| c.ref_name.starts_with("refs/")),
        "post-receive contains pseudoref"
    );
    // Native receive-pack invokes post-receive once. Duplicate callbacks are
    // ambiguous even if identical, so never silently deduplicate them.
    ensure!(
        !exists(&op.path.join("post-receive.json"))?,
        "duplicate post-receive receipt"
    );
    let bytes = serde_json::to_vec(&changes)?;
    ensure!(
        bytes.len() <= MAX_RECORD_BYTES,
        "receipt record exceeds byte limit"
    );
    atomic(&op.path.join("post-receive.json"), &bytes, false)
}
fn record_request(op: &Operation, input: &[u8]) -> Result<()> {
    let _lock = hook_lock(op)?;
    ensure!(!is_finished(op)?, "operation already finished");
    let changes = parse(input)?;
    validate_request(&changes)?;
    ensure!(
        !exists(&op.path.join("pre-receive.json"))?,
        "duplicate pre-receive request"
    );
    let bytes = serde_json::to_vec(&changes)?;
    ensure!(
        bytes.len() <= MAX_RECORD_BYTES,
        "request record exceeds byte limit"
    );
    atomic(&op.path.join("pre-receive.json"), &bytes, false)
}

/// Durable request evidence for a server-side CAS transaction. This must be
/// written before spawning Git so a missing child acknowledgement is recoverable.
pub fn record_ref_transaction_intent(op: &Operation, changes: &[RefChange]) -> Result<()> {
    validate_request(changes)?;
    let mut input = Vec::new();
    for change in changes {
        input.extend_from_slice(
            format!(
                "{} {} {}\n",
                change.old_oid, change.new_oid, change.ref_name
            )
            .as_bytes(),
        );
    }
    record_request(op, &input)
}

/// Record a successful native acknowledgement before PostgreSQL settlement.
pub fn record_ref_transaction_receipt(op: &Operation, changes: &[RefChange]) -> Result<()> {
    validate_request(changes)?;
    let mut input = Vec::new();
    for change in changes {
        input.extend_from_slice(
            format!(
                "{} {} {}\n",
                change.old_oid, change.new_oid, change.ref_name
            )
            .as_bytes(),
        );
    }
    record(op, HookPhase::Committed, &input)?;
    record_receipt(op, &input)
}
/// A failure rejects the whole push before any ref transaction. It deliberately
/// does not mark corruption: there is no ambiguous publication at this stage.
pub fn run_pre_receive() -> Result<()> {
    let (op, input) = hook_input()?;
    // No maintenance capability can turn a receive-pack into a privileged writer.
    ensure!(
        op.ci_pin.is_none(),
        "maintenance operations cannot receive pushes"
    );
    let changes = parse(&input)?;
    validate_namespace(&op, &changes)?;
    crate::git_http::publication::await_grant(&op)?;
    crate::browse::policy::validate_hook(&op, &changes)?;
    record_request(&op, &input)
}
/// A grant authorizes exactly one absent-to-target update, not an inheritable bypass.
fn validate_namespace(op: &Operation, changes: &[RefChange]) -> Result<()> {
    if let Some(intent) = &op.ci_pin {
        ensure!(
            changes == [intent.change()],
            "maintenance transaction differs from exact grant"
        );
        let root = op
            .path
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .context("missing volume root")?;
        ensure!(
            crate::ci_pins::load_intent(root, intent.repository_id, intent.job_id)? == *intent,
            "maintenance intent changed"
        );
    } else {
        ensure!(
            changes
                .iter()
                .all(|c| !crate::ci_pins::reserved(&c.ref_name)
                    && !crate::namespace_service::proposal_ref_reserved(&c.ref_name)),
            "controller-owned retention namespace cannot be pushed"
        );
    }
    Ok(())
}

fn hook_input() -> Result<(Operation, Vec<u8>)> {
    let path = PathBuf::from(
        std::env::var_os("ROOTYARD_JOURNAL_OPERATION")
            .context("missing controlled operation directory")?,
    );
    let op = load(&path)?;
    let mut input = Vec::new();
    std::io::stdin()
        .take(MAX_BYTES as u64 + 1)
        .read_to_end(&mut input)?;
    Ok((op, input))
}
/// Invoke synchronously before constructing the Tokio runtime. Only controlled
/// Git children receive this exact absolute directory in a sanitized environment.
pub fn run_hook(state: &str) -> Result<()> {
    let phase = match state {
        "preparing" => HookPhase::Preparing,
        "prepared" => HookPhase::Prepared,
        "committed" => HookPhase::Committed,
        "aborted" => HookPhase::Aborted,
        _ => bail!("unsupported reference transaction state"),
    };
    let (op, input) = hook_input()?;
    if matches!(phase, HookPhase::Preparing | HookPhase::Prepared) {
        // `prepared` runs after Git has locked refs and immediately before it
        // writes them. Re-check the parent window and durable admission here so
        // takeover or revocation during the transfer cannot publish refs.
        crate::git_http::publication::verify_grant(&op)?;
        crate::browse::policy::validate_hook_fence(&op)?;
    }
    let result = record(&op, phase, &input);
    if result.is_err() {
        let _ = atomic(&op.path.join("corrupt"), b"", false);
    }
    result
}
pub fn run_post_receive() -> Result<()> {
    let (op, input) = hook_input()?;
    let result = record_receipt(&op, &input);
    if result.is_err() {
        let _ = atomic(&op.path.join("corrupt"), b"", false);
    }
    result
}

#[cfg(test)]
#[path = "journal/tests.rs"]
mod tests;
