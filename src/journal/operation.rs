//! Journal operation identity, evidence payloads and validated loading.
use super::core::{exists, read, safe_path};
use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Native operation class persisted with the intent. `None` is the receive-pack
/// default and must stay unencoded so `/operations` keeps its legacy fallback.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    RefTransaction,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<OperationKind>,
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
    /// Present for ref transactions (HTTP or proposal pin) carrying an
    /// `Idempotency-Key`. Never present on CI maintenance operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency: Option<super::IdempotencyIntent>,
    #[serde(skip)]
    pub path: PathBuf,
}
pub struct ActiveGuard {
    pub(super) _file: File,
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
    if let Some(intent) = &op.idempotency {
        let valid =
            |value: &str| value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
        ensure!(valid(&intent.key_sha256) && valid(&intent.request_sha256), "invalid idempotency intent");
        ensure!(op.ci_pin.is_none(), "idempotency intent on maintenance operation");
    }
    if op.kind == Some(OperationKind::RefTransaction) {
        ensure!(!op.requires_parent_publication && op.ci_pin.is_none(), "invalid ref_transaction operation metadata");
    }
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
