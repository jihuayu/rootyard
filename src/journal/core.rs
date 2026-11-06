//! Durable operation identity, admission, and filesystem records.
use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Operation {
    pub id: Uuid,
    pub repository_id: Uuid,
    pub actor_id: Uuid,
    pub actor_name: String,
    pub token_id: Uuid,
    /// Non-login CI scheduler principal; human IDs are nil only for this variant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_principal_id: Option<Uuid>,
    pub sequence: i64,
    pub storage_generation: i64,
    #[serde(default)]
    pub requires_parent_publication: bool,
    /// Admitted shard route epoch. Zero denotes a pre-admission legacy journal.
    #[serde(default)]
    pub shard_epoch: i64,
    /// Exact maintenance capability, persisted before spawning Git. Never supplied by push clients.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ci_pin: Option<crate::ci_pins::Intent>,
    /// Internal, absent-to-target proposal pin. Never supplied by Git clients.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) proposal_pin: Option<crate::namespace_service::ProposalIntent>,
    #[serde(skip)]
    pub path: PathBuf,
}
pub struct ActiveGuard {
    _file: File,
}
impl ActiveGuard {
    pub fn operation_is_live(op: &Operation) -> Result<bool> {
        let path = op.path.join("active.lock");
        if !exists(&path)? {
            return Ok(false);
        }
        let file = OpenOptions::new().read(true).write(true).custom_flags(libc::O_NOFOLLOW).open(&path)?;
        ensure!(file.metadata()?.is_file(), "invalid active operation lock");
        match file.try_lock_exclusive() {
            Ok(()) => Ok(false),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(true),
            Err(error) => Err(error.into()),
        }
    }
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
        ensure!(matches!(c, Component::RootDir | Component::Normal(_)), "noncanonical journal path");
        p.push(c);
        let m = fs::symlink_metadata(&p)?;
        ensure!(!m.file_type().is_symlink(), "symlink in journal path");
    }
    Ok(())
}
pub(super) fn sync_dir(path: &Path) -> Result<()> {
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
    ensure!(fs::symlink_metadata(path)?.is_dir(), "journal directory is not a directory");
    Ok(())
}
pub(crate) fn read(path: &Path) -> Result<Vec<u8>> {
    safe_path(path)?;
    let mut f = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    ensure!(f.metadata()?.is_file(), "journal record is not a regular file");
    ensure!(f.metadata()?.len() <= MAX_RECORD_BYTES as u64, "journal record exceeds limit");
    let mut bytes = Vec::new();
    (&mut f).take(MAX_RECORD_BYTES as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= MAX_RECORD_BYTES, "journal record exceeds limit");
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
        let mut f =
            OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&temp)?;
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
pub(super) fn entries(path: &Path) -> Result<Vec<PathBuf>> {
    safe_path(path)?;
    let mut result = Vec::new();
    for entry in fs::read_dir(path)? {
        ensure!(result.len() < MAX_ENTRIES, "journal directory exceeds entry limit");
        result.push(entry?.path());
    }
    Ok(result)
}
pub(super) fn op_name(op: &Operation) -> String {
    format!("{:020}-{}", op.sequence, op.id)
}
pub(super) fn load(path: &Path) -> Result<Operation> {
    safe_path(path)?;
    let mut op: Operation = serde_json::from_slice(&read(&path.join("operation.json"))?)?;
    ensure!(
        op.sequence > 0 && op.storage_generation > 0 && op.shard_epoch >= 0,
        "invalid operation sequence, generation or shard epoch"
    );
    ensure!(!op.actor_name.is_empty() && op.actor_name.len() <= 4096, "invalid actor name");
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
        repo.parent().and_then(Path::file_name).and_then(|s| s.to_str()) == Some("journal"),
        "unexpected journal layout"
    );
    op.path = path.to_path_buf();
    if let Some(intent) = &op.ci_pin {
        ensure!(op.proposal_pin.is_none(), "mixed controller capabilities");
        intent.validate()?;
        ensure!(
            intent.repository_id == op.repository_id && intent.storage_generation == op.storage_generation,
            "maintenance identity mismatch"
        );
        if op.service_principal_id.is_some() {
            ensure!(
                op.actor_id.is_nil() && op.token_id.is_nil() && op.actor_name == "ci-scheduler",
                "invalid service principal journal"
            );
        } else {
            ensure!(intent.owner_id == op.actor_id && !op.token_id.is_nil(), "maintenance human identity mismatch");
        }
    } else {
        ensure!(
            op.service_principal_id.is_none() && !op.actor_id.is_nil() && !op.token_id.is_nil(),
            "invalid human journal identity"
        );
        if let Some(intent) = &op.proposal_pin {
            intent.validate()?;
            ensure!(intent.repository_id == op.repository_id, "proposal pin repository mismatch");
        }
    }
    Ok(op)
}
pub(super) fn validate(op: &Operation) -> Result<()> {
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
    Ok(begin_inner(
        data_root,
        repository_id,
        actor_id,
        actor_name,
        token_id,
        storage_generation,
        None,
        None,
        None,
        false,
        Uuid::new_v4(),
        0,
    )?
    .0)
}

/// Admit a write whose network transfer can overlap independent refs. The
/// returned guard must outlive the Git child and be dropped only after a
/// terminal journal marker is durable. Runtime recovery skips live guards.
pub fn begin_active(
    data_root: &Path,
    repository_id: Uuid,
    actor_id: Uuid,
    actor_name: String,
    token_id: Uuid,
    storage_generation: i64,
) -> Result<(Operation, ActiveGuard)> {
    begin_active_with(data_root, repository_id, actor_id, actor_name, token_id, storage_generation, Uuid::new_v4(), 0)
}

/// Admit an active write with the exact PostgreSQL admission identity and
/// shard epoch already recorded by `storage::ref_admission::admit`.
pub fn begin_active_with(
    data_root: &Path,
    repository_id: Uuid,
    actor_id: Uuid,
    actor_name: String,
    token_id: Uuid,
    storage_generation: i64,
    writer_id: Uuid,
    shard_epoch: i64,
) -> Result<(Operation, ActiveGuard)> {
    ensure!(!writer_id.is_nil(), "invalid admission writer identity");
    let (op, guard) = begin_inner(
        data_root,
        repository_id,
        actor_id,
        actor_name,
        token_id,
        storage_generation,
        None,
        None,
        None,
        true,
        writer_id,
        shard_epoch,
    )?;
    Ok((op, guard.context("missing active admission lock")?))
}

pub(crate) fn begin_ci(
    data_root: &Path,
    actor_name: String,
    token_id: Uuid,
    intent: &crate::ci_pins::Intent,
) -> Result<Operation> {
    intent.validate()?;
    Ok(begin_inner(
        data_root,
        intent.repository_id,
        intent.owner_id,
        actor_name,
        token_id,
        intent.storage_generation,
        Some(intent.clone()),
        None,
        None,
        false,
        Uuid::new_v4(),
        0,
    )?
    .0)
}

/// Admit an exact CI retention ref operation under a non-login principal.
pub(crate) fn begin_ci_service(
    data_root: &Path,
    intent: &crate::ci_pins::Intent,
    principal_id: Uuid,
) -> Result<Operation> {
    intent.validate()?;
    ensure!(!principal_id.is_nil(), "invalid CI service principal");
    Ok(begin_inner(
        data_root,
        intent.repository_id,
        Uuid::nil(),
        "ci-scheduler".into(),
        Uuid::nil(),
        intent.storage_generation,
        Some(intent.clone()),
        Some(principal_id),
        None,
        false,
        Uuid::new_v4(),
        0,
    )?
    .0)
}

pub(crate) fn begin_proposal(
    data_root: &Path,
    repository_id: Uuid,
    actor_id: Uuid,
    actor_name: String,
    token_id: Uuid,
    storage_generation: i64,
    intent: crate::namespace_service::ProposalIntent,
) -> Result<Operation> {
    intent.validate()?;
    ensure!(intent.repository_id == repository_id, "proposal pin repository mismatch");
    begin_inner(
        data_root,
        repository_id,
        actor_id,
        actor_name,
        token_id,
        storage_generation,
        None,
        None,
        Some(intent),
        false,
        Uuid::new_v4(),
        0,
    )
    .map(|(op, _)| op)
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
    service_principal_id: Option<Uuid>,
    proposal_pin: Option<crate::namespace_service::ProposalIntent>,
    active: bool,
    writer_id: Uuid,
    shard_epoch: i64,
) -> Result<(Operation, Option<ActiveGuard>)> {
    safe_path(data_root)?;
    ensure!(storage_generation > 0 && !actor_name.is_empty() && actor_name.len() <= 4096, "invalid operation metadata");
    let journal = data_root.join("journal");
    mkdir(&journal)?;
    let repo = journal.join(repository_id.to_string());
    mkdir(&repo)?;
    // Admission is short, but multiple independent ref writers may now enter
    // it concurrently. A separate persistent inode is required because the
    // sequence counter itself is atomically replaced after each reservation.
    let sequence_lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(repo.join("sequence.lock"))?;
    ensure!(sequence_lock.metadata()?.is_file(), "invalid journal admission lock");
    sequence_lock.lock_exclusive()?;
    let counter = repo.join("sequence");
    let previous: i64 = if exists(&counter)? { std::str::from_utf8(&read(&counter)?)?.parse()? } else { 0 };
    ensure!(previous >= 0, "invalid journal sequence");
    let sequence = previous.checked_add(1).context("journal sequence exhausted")?;
    // Reserving before publication permits gaps, never reuse.
    atomic(&counter, sequence.to_string().as_bytes(), true)?;
    let mut op = Operation {
        id: writer_id,
        repository_id,
        actor_id,
        actor_name,
        token_id,
        service_principal_id,
        sequence,
        storage_generation,
        requires_parent_publication: active,
        shard_epoch,
        ci_pin,
        proposal_pin,
        path: PathBuf::new(),
    };
    op.path = repo.join(op_name(&op));
    // Publish a complete operation atomically. A crash during admission may
    // reserve a sequence or leave ignored staging, never a malformed visible
    // operation directory. No Git child receives the path until this finishes.
    let staging = repo.join(format!(".tmp-operation-{}", op.id));
    fs::create_dir(&staging)?;
    fs::set_permissions(&staging, fs::Permissions::from_mode(0o700))?;
    atomic(&staging.join("operation.json"), &serde_json::to_vec(&op)?, false)?;
    let active_guard = if active {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(staging.join("active.lock"))?;
        file.lock_exclusive()?;
        Some(ActiveGuard { _file: file })
    } else {
        None
    };
    fs::rename(&staging, &op.path)?;
    sync_dir(&repo)?;
    Ok((op, active_guard))
}

pub fn sequence(data_root: &Path, repository_id: Uuid) -> Result<i64> {
    safe_path(data_root)?;
    let path = data_root.join("journal").join(repository_id.to_string()).join("sequence");
    if !exists(&path)? {
        return Ok(0);
    }
    let bytes = read(&path)?;
    ensure!(bytes.len() <= 32, "invalid journal counter");
    let value = std::str::from_utf8(&bytes)?.parse::<i64>()?;
    ensure!(value >= 0, "negative journal counter");
    Ok(value)
}

/// Advance the durable local sequence counter to at least `floor` while holding
/// the same admission lock used by `begin_inner`. Storage transitions use this
/// to carry both backends across one shared `git_operations` uniqueness
/// namespace without ever lowering or reusing a published sequence.
pub(crate) fn ensure_sequence_at_least(data_root: &Path, repository_id: Uuid, floor: i64) -> Result<i64> {
    ensure!(floor >= 0, "invalid journal sequence floor");
    safe_path(data_root)?;
    let journal = data_root.join("journal");
    mkdir(&journal)?;
    let repo = journal.join(repository_id.to_string());
    mkdir(&repo)?;
    let sequence_lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(repo.join("sequence.lock"))?;
    ensure!(sequence_lock.metadata()?.is_file(), "invalid journal admission lock");
    sequence_lock.lock_exclusive()?;
    let counter = repo.join("sequence");
    let previous: i64 = if exists(&counter)? { std::str::from_utf8(&read(&counter)?)?.parse()? } else { 0 };
    ensure!(previous >= 0, "invalid journal sequence");
    if previous < floor {
        atomic(&counter, floor.to_string().as_bytes(), true)?;
    }
    Ok(previous.max(floor))
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
        let name = path.file_name().and_then(|s| s.to_str()).context("invalid journal filename")?;
        if name == "sequence" || name == "sequence.lock" || name.starts_with(".tmp-") || name.starts_with(".retired-") {
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
    ensure!(result.iter().all(|o| identities.insert(o.id)), "duplicate journal operation identity");
    result.sort_by_key(|o| o.sequence);
    ensure!(result.windows(2).all(|w| w[0].sequence != w[1].sequence), "duplicate operation sequence");
    Ok(result)
}
