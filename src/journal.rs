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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub actor_id: Uuid,
    pub actor_name: String,
    pub token_id: Uuid,
    pub sequence: i64,
    pub storage_generation: i64,
    /// Exact maintenance capability, persisted before spawning Git. Never supplied by push clients.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ci_pin: Option<crate::ci_pins::Intent>,
    #[serde(skip)]
    pub path: PathBuf,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RefChange {
    pub ref_name: String,
    pub old_oid: String,
    pub new_oid: String,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum HookPhase {
    Preparing,
    Prepared,
    Committed,
    Aborted,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HookEvent {
    pub ordinal: i64,
    pub phase: HookPhase,
    pub changes: Vec<RefChange>,
}

pub(crate) fn safe_path(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "journal path must be absolute");
    let mut p = PathBuf::new();
    for c in path.components() {
        ensure!(
            matches!(c, Component::RootDir | Component::Normal(_)),
            "noncanonical journal path"
        );
        p.push(c);
        let m = fs::symlink_metadata(&p)?;
        ensure!(!m.file_type().is_symlink(), "symlink in journal path");
    }
    Ok(())
}
fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}
pub(crate) fn mkdir(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            sync_dir(path.parent().context("directory parent")?)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e.into()),
    }
    safe_path(path)?;
    ensure!(
        fs::symlink_metadata(path)?.is_dir(),
        "journal directory is not a directory"
    );
    Ok(())
}
pub(crate) fn read(path: &Path) -> Result<Vec<u8>> {
    safe_path(path)?;
    let mut f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    ensure!(
        f.metadata()?.is_file(),
        "journal record is not a regular file"
    );
    ensure!(
        f.metadata()?.len() <= MAX_RECORD_BYTES as u64,
        "journal record exceeds limit"
    );
    let mut bytes = Vec::new();
    (&mut f)
        .take(MAX_RECORD_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_RECORD_BYTES,
        "journal record exceeds limit"
    );
    Ok(bytes)
}
pub(crate) fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            safe_path(path)?;
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}
// Only the serialized sequence counter is replaceable. Immutable records must
// either be absent or contain exactly the same bytes.
pub(crate) fn atomic(path: &Path, bytes: &[u8], replace: bool) -> Result<()> {
    let parent = path.parent().context("record parent")?;
    safe_path(parent)?;
    if exists(path)? && !replace {
        ensure!(read(path)? == bytes, "conflicting journal record");
        sync_dir(parent)?;
        return Ok(());
    }
    let temp = parent.join(format!(".tmp-{}", Uuid::new_v4()));
    let result = (|| -> Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&temp, path)?;
        sync_dir(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}
fn entries(path: &Path) -> Result<Vec<PathBuf>> {
    safe_path(path)?;
    let mut result = Vec::new();
    for entry in fs::read_dir(path)? {
        ensure!(
            result.len() < MAX_ENTRIES,
            "journal directory exceeds entry limit"
        );
        result.push(entry?.path());
    }
    Ok(result)
}
fn op_name(op: &Operation) -> String {
    format!("{:020}-{}", op.sequence, op.id)
}
fn load(path: &Path) -> Result<Operation> {
    safe_path(path)?;
    let mut op: Operation = serde_json::from_slice(&read(&path.join("operation.json"))?)?;
    ensure!(
        op.sequence > 0 && op.storage_generation > 0,
        "invalid operation sequence or generation"
    );
    ensure!(
        !op.actor_name.is_empty() && op.actor_name.len() <= 4096,
        "invalid actor name"
    );
    ensure!(
        path.file_name().and_then(|s| s.to_str()) == Some(op_name(&op).as_str()),
        "operation path identity mismatch"
    );
    let repo = path.parent().context("missing repository directory")?;
    ensure!(
        repo.file_name().and_then(|s| s.to_str()) == Some(op.repository_id.to_string().as_str()),
        "repository identity mismatch"
    );
    ensure!(
        repo.parent()
            .and_then(Path::file_name)
            .and_then(|s| s.to_str())
            == Some("journal"),
        "unexpected journal layout"
    );
    op.path = path.to_path_buf();
    if let Some(intent) = &op.ci_pin {
        intent.validate()?;
        ensure!(
            intent.repository_id == op.repository_id
                && intent.owner_id == op.actor_id
                && intent.storage_generation == op.storage_generation,
            "maintenance identity mismatch"
        );
    }
    Ok(op)
}
fn validate(op: &Operation) -> Result<()> {
    ensure!(load(&op.path)? == *op, "operation metadata mismatch");
    Ok(())
}

pub fn begin(
    data_root: &Path,
    repository_id: Uuid,
    actor_id: Uuid,
    actor_name: String,
    token_id: Uuid,
    storage_generation: i64,
) -> Result<Operation> {
    begin_inner(
        data_root,
        repository_id,
        actor_id,
        actor_name,
        token_id,
        storage_generation,
        None,
    )
}

pub(crate) fn begin_ci(
    data_root: &Path,
    actor_name: String,
    token_id: Uuid,
    intent: &crate::ci_pins::Intent,
) -> Result<Operation> {
    intent.validate()?;
    begin_inner(
        data_root,
        intent.repository_id,
        intent.owner_id,
        actor_name,
        token_id,
        intent.storage_generation,
        Some(intent.clone()),
    )
}

#[allow(clippy::too_many_arguments)]
fn begin_inner(
    data_root: &Path,
    repository_id: Uuid,
    actor_id: Uuid,
    actor_name: String,
    token_id: Uuid,
    storage_generation: i64,
    ci_pin: Option<crate::ci_pins::Intent>,
) -> Result<Operation> {
    safe_path(data_root)?;
    ensure!(
        storage_generation > 0 && !actor_name.is_empty() && actor_name.len() <= 4096,
        "invalid operation metadata"
    );
    let journal = data_root.join("journal");
    mkdir(&journal)?;
    let repo = journal.join(repository_id.to_string());
    mkdir(&repo)?;
    let counter = repo.join("sequence");
    let previous: i64 = if exists(&counter)? {
        std::str::from_utf8(&read(&counter)?)?.parse()?
    } else {
        0
    };
    ensure!(previous >= 0, "invalid journal sequence");
    let sequence = previous
        .checked_add(1)
        .context("journal sequence exhausted")?;
    // Reserving before publication permits gaps, never reuse.
    atomic(&counter, sequence.to_string().as_bytes(), true)?;
    let mut op = Operation {
        id: Uuid::new_v4(),
        repository_id,
        actor_id,
        actor_name,
        token_id,
        sequence,
        storage_generation,
        ci_pin,
        path: PathBuf::new(),
    };
    op.path = repo.join(op_name(&op));
    // Publish a complete operation atomically. A crash during admission may
    // reserve a sequence or leave ignored staging, never a malformed visible
    // operation directory. No Git child receives the path until this finishes.
    let staging = repo.join(format!(".tmp-operation-{}", op.id));
    fs::create_dir(&staging)?;
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))?;
    atomic(
        &staging.join("operation.json"),
        &serde_json::to_vec(&op)?,
        false,
    )?;
    fs::rename(&staging, &op.path)?;
    sync_dir(&repo)?;
    Ok(op)
}

pub fn sequence(data_root: &Path, repository_id: Uuid) -> Result<i64> {
    safe_path(data_root)?;
    let path = data_root
        .join("journal")
        .join(repository_id.to_string())
        .join("sequence");
    if !exists(&path)? {
        return Ok(0);
    }
    let bytes = read(&path)?;
    ensure!(bytes.len() <= 32, "invalid journal counter");
    let value = std::str::from_utf8(&bytes)?.parse::<i64>()?;
    ensure!(value >= 0, "negative journal counter");
    Ok(value)
}
pub fn pending(data_root: &Path, repository_id: Uuid) -> Result<Vec<Operation>> {
    safe_path(data_root)?;
    let repo = data_root.join("journal").join(repository_id.to_string());
    if !exists(&repo)? {
        return Ok(Vec::new());
    }
    let mut result = Vec::new();
    let counter: i64 = std::str::from_utf8(&read(&repo.join("sequence"))?)?.parse()?;
    for path in entries(&repo)? {
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .context("invalid journal filename")?;
        if name == "sequence" || name.starts_with(".tmp-") || name.starts_with(".retired-") {
            continue;
        }
        let op = load(&path).context("corrupt pending operation")?;
        ensure!(
            op.repository_id == repository_id && op.sequence <= counter,
            "operation sequence exceeds durable counter"
        );
        result.push(op);
    }
    let mut identities = std::collections::HashSet::new();
    ensure!(
        result.iter().all(|o| identities.insert(o.id)),
        "duplicate journal operation identity"
    );
    result.sort_by_key(|o| o.sequence);
    ensure!(
        result.windows(2).all(|w| w[0].sequence != w[1].sequence),
        "duplicate operation sequence"
    );
    Ok(result)
}

fn valid_ref(s: &str) -> bool {
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
        && changes
            .iter()
            .all(|c| valid_ref(&c.ref_name) && valid_oid(&c.old_oid) && valid_oid(&c.new_oid) && c.old_oid.len() == c.new_oid.len())
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
            || name == "finished"
            || name == "interrupted"
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
/// Mark verified evidence loss. This is not an inference from Git's exit code.
pub fn mark_corrupt(op: &Operation) -> Result<()> {
    validate(op)?;
    atomic(&op.path.join("corrupt"), b"", false)
}

/// Canonical bounded evidence for operator inspection and immutable resolution.
pub fn evidence(op: &Operation) -> Result<serde_json::Value> {
    Ok(
        serde_json::json!({"operation":op,"reference_events":events(op)?,"requested":requests(op)?,"post_receive":receipts(op)?,"finished":is_finished(op)?,"interrupted":is_interrupted(op)?}),
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
    ensure!(
        op.ci_pin.is_none(),
        "maintenance operations cannot receive pushes"
    );
    let changes = parse(&input)?;
    validate_namespace(&op, &changes)?;
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
                .all(|c| !crate::ci_pins::reserved(&c.ref_name)),
            "CI retention namespace is controller-only"
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
    if phase == HookPhase::Preparing {
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
mod tests {
    use super::*;
    #[test]
    fn ref_transaction_intent_precedes_receipt_and_accepts_sha256() {
        let (_root, op) = setup();
        let changes = vec![RefChange {
            ref_name: "refs/heads/main".into(),
            old_oid: "0".repeat(64),
            new_oid: "a".repeat(64),
        }];
        record_ref_transaction_intent(&op, &changes).unwrap();
        assert_eq!(requests(&op).unwrap(), Some(changes.clone()));
        assert_eq!(receipts(&op).unwrap(), None);
        record_ref_transaction_receipt(&op, &changes).unwrap();
        assert_eq!(receipts(&op).unwrap(), Some(changes));
        assert_eq!(events(&op).unwrap()[0].phase, HookPhase::Committed);
    }
    fn setup() -> (tempfile::TempDir, Operation) {
        let root = tempfile::tempdir().unwrap();
        let op = begin(
            root.path(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "actor".into(),
            Uuid::new_v4(),
            1,
        )
        .unwrap();
        (root, op)
    }
    fn payload(old: char, new: char) -> Vec<u8> {
        format!(
            "{} {} refs/heads/main\n",
            old.to_string().repeat(40),
            new.to_string().repeat(40)
        )
        .into_bytes()
    }
    #[test]
    fn interrupted_admission_staging_preserves_sequence_gap() {
        let (root, op) = setup();
        let repo = op.path.parent().unwrap();
        let staging = repo.join(".tmp-operation-interrupted");
        mkdir(&staging).unwrap();
        atomic(&staging.join("operation.json"), b"incomplete", false).unwrap();
        atomic(&repo.join("sequence"), b"2", true).unwrap();
        assert_eq!(
            pending(root.path(), op.repository_id).unwrap(),
            vec![op.clone()]
        );
        let next = begin(
            root.path(),
            op.repository_id,
            op.actor_id,
            op.actor_name,
            op.token_id,
            1,
        )
        .unwrap();
        assert_eq!(next.sequence, 3);
        assert_eq!(pending(root.path(), next.repository_id).unwrap().len(), 2);
        assert!(staging.exists());
    }
    #[test]
    fn lifecycle_and_monotonic_sequence() {
        let (root, op) = setup();
        let p = payload('0', 'a');
        record(&op, HookPhase::Prepared, &p).unwrap();
        assert!(retire(&op).is_err());
        record_receipt(&op, &p).unwrap();
        finish(&op).unwrap();
        retire(&op).unwrap();
        let next = begin(
            root.path(),
            op.repository_id,
            op.actor_id,
            op.actor_name,
            op.token_id,
            1,
        )
        .unwrap();
        assert_eq!(next.sequence, 2);
        assert_eq!(pending(root.path(), op.repository_id).unwrap().len(), 1);
    }
    #[test]
    fn repeated_events_and_nested_noise_are_preserved() {
        let (_root, op) = setup();
        let p = payload('a', 'b');
        let noise = payload('0', '0');
        for (phase, input) in [
            (HookPhase::Preparing, &p),
            (HookPhase::Prepared, &p),
            (HookPhase::Prepared, &noise),
            (HookPhase::Committed, &noise),
            (HookPhase::Committed, &p),
            (HookPhase::Aborted, &noise),
            (HookPhase::Prepared, &p),
        ] {
            record(&op, phase, input).unwrap();
        }
        let e = events(&op).unwrap();
        assert_eq!(e.len(), 7);
        assert_eq!(e[1].changes, e[6].changes);
        assert_eq!(e[2].changes[0].old_oid, e[2].changes[0].new_oid);
        assert!(receipts(&op).unwrap().is_none());
    }
    #[test]
    fn receipt_is_separate_and_preserves_order() {
        let (_root, op) = setup();
        let mut p = payload('a', 'b');
        p.extend(payload('b', 'a'));
        p.extend(payload('a', 'b'));
        record_receipt(&op, &p).unwrap();
        let r = receipts(&op).unwrap().unwrap();
        assert_eq!(r.len(), 3);
        assert_eq!(r[0], r[2]);
        assert_ne!(r[0], r[1]);
        assert!(record_receipt(&op, &p).is_err());
        assert!(events(&op).unwrap().is_empty());
    }
    #[test]
    fn invalid_inputs_and_truncated_receipt() {
        let (_root, op) = setup();
        assert!(parse(b"\xff").is_err());
        assert!(parse(&vec![b'x'; MAX_BYTES + 1]).is_err());
        let mut p = payload('0', 'a');
        p.pop();
        assert!(record_receipt(&op, &p).is_err());
        assert!(receipts(&op).unwrap().is_none());
        assert!(
            parse(format!("{} ref:refs/heads/main HEAD\n", "0".repeat(40)).as_bytes()).is_err()
        );
        assert!(parse(format!("{} {} HEAD\n", "0".repeat(40), "a".repeat(40)).as_bytes()).is_ok());
        assert!(valid_ref("refs/heads/topic"));
        assert!(!valid_ref("refs/../escape"));
    }
    #[test]
    fn refuses_symlinks_and_corrupt_metadata() {
        let (_root, op) = setup();
        fs::remove_file(op.path.join("operation.json")).unwrap();
        std::os::unix::fs::symlink("/etc/passwd", op.path.join("operation.json")).unwrap();
        assert!(events(&op).is_err());
    }
    #[test]
    fn detects_missing_events_and_blocking_marker() {
        let (_root, op) = setup();
        record(&op, HookPhase::Prepared, &payload('0', 'a')).unwrap();
        record(&op, HookPhase::Committed, &payload('0', 'a')).unwrap();
        fs::remove_file(op.path.join("00000000000000000001.event.json")).unwrap();
        assert!(events(&op).is_err());
        atomic(&op.path.join("corrupt"), b"", false).unwrap();
        assert!(receipts(&op).is_err());
    }
    fn near_limit_input() -> Vec<u8> {
        let line = format!(
            "{} {} refs/heads/{}\n",
            "0".repeat(40),
            "a".repeat(40),
            "x".repeat(150)
        );
        line.repeat(MAX_REFS).into_bytes()
    }
    #[test]
    fn expanded_json_above_one_mib_round_trips() {
        let (_root, op) = setup();
        let input = near_limit_input();
        assert!(input.len() < MAX_BYTES && input.len() > MAX_BYTES * 9 / 10);
        record(&op, HookPhase::Prepared, &input).unwrap();
        let bytes = read(&op.path.join("00000000000000000001.event.json")).unwrap();
        assert!(bytes.len() > MAX_BYTES && bytes.len() < MAX_RECORD_BYTES);
        assert_eq!(events(&op).unwrap()[0].changes.len(), MAX_REFS);
        record_receipt(&op, &input).unwrap();
        assert_eq!(receipts(&op).unwrap().unwrap().len(), MAX_REFS);
    }
    #[test]
    fn aggregate_event_cap_rejects_append_and_oversized_recovery() {
        let (_root, op) = setup();
        let input = near_limit_input();
        let mut count = 0;
        while record(&op, HookPhase::Prepared, &input).is_ok() {
            count += 1;
            assert!(count < 32);
        }
        let (saved, size) = events_with_size(&op).unwrap();
        assert_eq!(saved.len(), count);
        assert!(size <= MAX_EVENT_BYTES);
        // Receipt has its own allowance and remains writable at event capacity.
        record_receipt(&op, &input).unwrap();
        assert!(receipts(&op).unwrap().is_some());
        let mut extra = saved[0].clone();
        extra.ordinal = count as i64 + 1;
        atomic(
            &op.path.join(format!("{:020}.event.json", extra.ordinal)),
            &serde_json::to_vec(&extra).unwrap(),
            false,
        )
        .unwrap();
        assert!(events(&op).is_err());
    }
    #[test]
    fn reference_name_byte_boundary() {
        let prefix = format!("refs/heads/{}", "segment/".repeat(120));
        let name = format!("{}{}", prefix, "x".repeat(1024 - prefix.len()));
        assert_eq!(name.len(), 1024);
        assert!(valid_ref(&name));
        assert!(!valid_ref(&format!("{name}x")));
        let unicode = format!("{}é", &name[..1022]);
        assert_eq!(unicode.len(), 1024);
        assert!(valid_ref(&unicode));
        assert!(!valid_ref(&format!("{unicode}x")));
        let (_root, op) = setup();
        let input = format!("{} {} {}x\n", "0".repeat(40), "a".repeat(40), name);
        assert!(record(&op, HookPhase::Prepared, input.as_bytes()).is_err());
        assert!(events(&op).unwrap().is_empty());
    }
    fn batch(count: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        for i in 0..count {
            writeln!(
                bytes,
                "{} {} refs/heads/branch-{i}",
                "0".repeat(40),
                "a".repeat(40)
            )
            .unwrap();
        }
        bytes
    }
    #[test]
    fn pre_receive_admits_4096_ordered_unique_refs() {
        let (_root, op) = setup();
        let input = batch(4096);
        record_request(&op, &input).unwrap();
        let request = requests(&op).unwrap().unwrap();
        assert_eq!(request.len(), 4096);
        assert_eq!(request[0].ref_name, "refs/heads/branch-0");
        assert_eq!(request[4095].ref_name, "refs/heads/branch-4095");
        assert!(events(&op).unwrap().is_empty());
        assert!(receipts(&op).unwrap().is_none());
    }
    #[test]
    fn pre_receive_rejects_batch_limits_without_ambiguity() {
        let mut duplicate = payload('0', 'a');
        duplicate.extend(payload('a', 'b'));
        let long = format!(
            "{} {} refs/heads/{}\n",
            "0".repeat(40),
            "a".repeat(40),
            "x".repeat(1024)
        );
        for input in [
            batch(4097),
            duplicate,
            long.into_bytes(),
            vec![b'x'; MAX_BYTES + 1],
        ] {
            let (_root, op) = setup();
            assert!(record_request(&op, &input).is_err());
            assert!(requests(&op).unwrap().is_none());
            assert!(events(&op).unwrap().is_empty());
            assert!(!exists(&op.path.join("corrupt")).unwrap());
        }
    }
    #[test]
    fn interruption_and_corruption_markers_are_durable_and_checked() {
        let (_root, op) = setup();
        assert!(!is_interrupted(&op).unwrap());
        mark_interrupted(&op).unwrap();
        mark_interrupted(&op).unwrap();
        finish(&op).unwrap();
        assert!(is_interrupted(&op).unwrap());
        assert!(is_finished(&op).unwrap());
        assert!(events(&op).unwrap().is_empty());
        fs::write(op.path.join("interrupted"), b"unexpected").unwrap();
        assert!(is_interrupted(&op).is_err());
        mark_corrupt(&op).unwrap();
        assert!(events(&op).is_err());
    }
}
