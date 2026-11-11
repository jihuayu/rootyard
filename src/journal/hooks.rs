//! Native Git hook recording and the server-side ref-transaction evidence API.
use super::core::{atomic, exists, load, validate};
use super::record::{events_with_size, parse, validate_request};
use super::state::is_finished;
use super::{HookEvent, HookPhase, MAX_BYTES, MAX_ENTRIES, MAX_EVENT_BYTES, MAX_RECORD_BYTES, Operation, RefChange};
use anyhow::{Context, Result, bail, ensure};
use fs2::FileExt;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

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
    ensure!(file.metadata()?.is_file(), "hook lock is not a regular file");
    file.lock_exclusive()?;
    Ok(file)
}
pub(super) fn record(op: &Operation, phase: HookPhase, input: &[u8]) -> Result<()> {
    let _lock = hook_lock(op)?;
    ensure!(!is_finished(op)?, "operation already finished");
    let changes = parse(input)?;
    validate_namespace(op, &changes)?;
    let (previous, total_bytes) = events_with_size(op)?;
    ensure!(previous.len() < MAX_ENTRIES - 7, "too many hook events");
    let ordinal = previous.last().map_or(0, |e| e.ordinal).checked_add(1).context("hook event ordinal exhausted")?;
    let event = HookEvent { ordinal, phase, changes };
    let bytes = serde_json::to_vec(&event)?;
    ensure!(bytes.len() <= MAX_RECORD_BYTES, "event record exceeds byte limit");
    ensure!(bytes.len() <= MAX_EVENT_BYTES - total_bytes, "operation event log exceeds byte limit");
    atomic(&op.path.join(format!("{ordinal:020}.event.json")), &bytes, false)
}
pub(super) fn record_receipt(op: &Operation, input: &[u8]) -> Result<()> {
    let _lock = hook_lock(op)?;
    ensure!(!is_finished(op)?, "operation already finished");
    let changes = parse(input)?;
    ensure!(changes.iter().all(|c| c.ref_name.starts_with("refs/")), "post-receive contains pseudoref");
    // Native receive-pack invokes post-receive once. Duplicate callbacks are
    // ambiguous even if identical, so never silently deduplicate them.
    ensure!(!exists(&op.path.join("post-receive.json"))?, "duplicate post-receive receipt");
    let bytes = serde_json::to_vec(&changes)?;
    ensure!(bytes.len() <= MAX_RECORD_BYTES, "receipt record exceeds byte limit");
    atomic(&op.path.join("post-receive.json"), &bytes, false)
}
pub(super) fn record_request(op: &Operation, input: &[u8]) -> Result<()> {
    let _lock = hook_lock(op)?;
    ensure!(!is_finished(op)?, "operation already finished");
    let changes = parse(input)?;
    validate_request(&changes)?;
    ensure!(!exists(&op.path.join("pre-receive.json"))?, "duplicate pre-receive request");
    let bytes = serde_json::to_vec(&changes)?;
    ensure!(bytes.len() <= MAX_RECORD_BYTES, "request record exceeds byte limit");
    atomic(&op.path.join("pre-receive.json"), &bytes, false)
}

/// Durable request evidence for a server-side CAS transaction. This must be
/// written before spawning Git so a missing child acknowledgement is recoverable.
pub fn record_ref_transaction_intent(op: &Operation, changes: &[RefChange]) -> Result<()> {
    validate_request(changes)?;
    let mut input = Vec::new();
    for change in changes {
        input.extend_from_slice(format!("{} {} {}\n", change.old_oid, change.new_oid, change.ref_name).as_bytes());
    }
    record_request(op, &input)
}

/// Record a successful native acknowledgement before PostgreSQL settlement.
pub fn record_ref_transaction_receipt(op: &Operation, changes: &[RefChange]) -> Result<()> {
    validate_request(changes)?;
    let mut input = Vec::new();
    for change in changes {
        input.extend_from_slice(format!("{} {} {}\n", change.old_oid, change.new_oid, change.ref_name).as_bytes());
    }
    record(op, HookPhase::Committed, &input)?;
    record_receipt(op, &input)
}
/// A failure rejects the whole push before any ref transaction. It deliberately
/// does not mark corruption: there is no ambiguous publication at this stage.
pub fn run_pre_receive() -> Result<()> {
    let (op, input) = hook_input()?;
    // No maintenance capability can turn a receive-pack into a privileged writer.
    ensure!(op.ci_pin.is_none() && op.proposal_pin.is_none(), "maintenance operations cannot receive pushes");
    let changes = parse(&input)?;
    validate_namespace(&op, &changes)?;
    crate::git_http::publication::await_grant(&op)?;
    crate::browse::policy::validate_hook(&op, &changes)?;
    record_request(&op, &input)
}
/// A grant authorizes exactly one absent-to-target update, not an inheritable bypass.
fn validate_namespace(op: &Operation, changes: &[RefChange]) -> Result<()> {
    if let Some(intent) = &op.ci_pin {
        ensure!(changes == [intent.change()], "maintenance transaction differs from exact grant");
        let root = op.path.parent().and_then(Path::parent).and_then(Path::parent).context("missing volume root")?;
        ensure!(
            crate::ci_pins::load_intent(root, intent.repository_id, intent.job_id)? == *intent,
            "maintenance intent changed"
        );
    } else if let Some(intent) = &op.proposal_pin {
        intent.validate()?;
        ensure!(changes == [intent.change()], "proposal transaction differs from exact grant");
    } else {
        ensure!(
            changes.iter().all(|c| !crate::ci_pins::reserved(&c.ref_name)
                && !crate::namespace_service::proposal_ref_reserved(&c.ref_name)),
            "controller-owned retention namespace cannot be pushed"
        );
    }
    Ok(())
}

fn hook_input() -> Result<(Operation, Vec<u8>)> {
    let path = PathBuf::from(
        std::env::var_os("ROOTYARD_JOURNAL_OPERATION").context("missing controlled operation directory")?,
    );
    let op = load(&path)?;
    let mut input = Vec::new();
    std::io::stdin().take(MAX_BYTES as u64 + 1).read_to_end(&mut input)?;
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
