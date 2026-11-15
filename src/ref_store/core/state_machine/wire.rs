//! Strict wire DTOs for the deterministic Ref-CAS Raft state machine.
//!
//! Every `Deserialize` struct in this module sets `#[serde(deny_unknown_fields)]`
//! so Raft command payloads and serialized state-machine snapshots reject
//! unknown fields and preserve canonical conversion to `ref_store::core` types.

use crate::ref_store::contract::{
    IssuerLane, OperationIdentity, OperationRecord, OperationState, RefStoreError, RequestDigest, TerminalResult,
};
use crate::ref_store::core::command::CommitRefsRequest;
use crate::ref_store::core::contract::{CommitMode, CoreGateInit};
use crate::ref_store::core::terminal::{
    CommitRejectCode, CommitRejection, CommitTerminal, RefCommitResult, TerminalKind,
};
use crate::ref_store::core::types::{
    GitObjectFormat, GitOid, HeadUpdate, RefName, RefPrecondition, RefTarget, RefUpdate,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::str::FromStr;
use uuid::Uuid;

/// Wire representation of [`OperationIdentity`] with strict field validation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireOperationIdentity {
    pub repository_id: Uuid,
    pub issuer_id: Uuid,
    pub lane: String,
    pub sequence: i64,
    pub operation_id: Uuid,
    pub digest: String,
}

impl From<&OperationIdentity> for WireOperationIdentity {
    fn from(identity: &OperationIdentity) -> Self {
        Self {
            repository_id: identity.repository_id(),
            issuer_id: identity.issuer_id(),
            lane: identity.lane().as_str().to_owned(),
            sequence: identity.sequence(),
            operation_id: identity.operation_id(),
            digest: identity.digest().as_hex(),
        }
    }
}

impl TryFrom<&WireOperationIdentity> for OperationIdentity {
    type Error = RefStoreError;

    fn try_from(wire: &WireOperationIdentity) -> Result<Self, Self::Error> {
        let lane = IssuerLane::new(wire.lane.as_str())?;
        let digest = RequestDigest::from_str(&wire.digest)?;
        Self::new(wire.repository_id, wire.issuer_id, lane, wire.sequence, wire.operation_id, digest)
    }
}

/// Wire representation of [`CoreGateInit`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireGateInit {
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub object_format: GitObjectFormat,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
    pub group_epoch: i64,
    pub head_ref: String,
}

impl From<&CoreGateInit> for WireGateInit {
    fn from(init: &CoreGateInit) -> Self {
        Self {
            repository_id: init.repository_id(),
            tenant_id: init.tenant_id(),
            object_format: init.object_format(),
            history_incarnation: init.history_incarnation(),
            authority_epoch: init.authority_epoch(),
            group_epoch: init.group_epoch(),
            head_ref: init.head_ref().as_str().to_owned(),
        }
    }
}

impl TryFrom<&WireGateInit> for CoreGateInit {
    type Error = RefStoreError;

    fn try_from(wire: &WireGateInit) -> Result<Self, Self::Error> {
        let head = RefName::branch(wire.head_ref.as_str())?;
        Self::new(
            wire.repository_id,
            wire.tenant_id,
            wire.object_format,
            wire.history_incarnation,
            wire.authority_epoch,
            wire.group_epoch,
            head,
        )
    }
}

/// Wire representation of one [`RefUpdate`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireRefUpdate {
    pub name: String,
    pub precondition_oid: Option<String>,
    pub target_oid: Option<String>,
}

impl WireRefUpdate {
    pub fn from_ref_update(update: &RefUpdate) -> Self {
        Self {
            name: update.name().as_str().to_owned(),
            precondition_oid: update.precondition().oid().map(GitOid::as_hex),
            target_oid: update.target().oid().map(GitOid::as_hex),
        }
    }

    pub fn into_ref_update(self, format: GitObjectFormat) -> Result<RefUpdate, RefStoreError> {
        let name = RefName::new(self.name)?;
        let precondition = match self.precondition_oid {
            Some(hex) => RefPrecondition::Present(GitOid::parse(format, &hex)?),
            None => RefPrecondition::Absent,
        };
        let target = match self.target_oid {
            Some(hex) => RefTarget::Oid(GitOid::parse(format, &hex)?),
            None => RefTarget::Delete,
        };
        Ok(RefUpdate::new(name, precondition, target))
    }
}

/// Kind tag for [`WireHeadUpdate`].
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WireHeadUpdateKind {
    Keep,
    Retarget,
}

/// Wire representation of [`HeadUpdate`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireHeadUpdate {
    pub kind: WireHeadUpdateKind,
    pub target_ref: Option<String>,
}

impl From<&HeadUpdate> for WireHeadUpdate {
    fn from(head: &HeadUpdate) -> Self {
        match head {
            HeadUpdate::Keep => Self { kind: WireHeadUpdateKind::Keep, target_ref: None },
            HeadUpdate::Retarget(name) => {
                Self { kind: WireHeadUpdateKind::Retarget, target_ref: Some(name.as_str().to_owned()) }
            }
        }
    }
}

impl TryFrom<&WireHeadUpdate> for HeadUpdate {
    type Error = RefStoreError;

    fn try_from(wire: &WireHeadUpdate) -> Result<Self, Self::Error> {
        match wire.kind {
            WireHeadUpdateKind::Keep => {
                if wire.target_ref.is_some() {
                    return Err(RefStoreError::InvalidIdentity("keep head update must not carry target_ref".into()));
                }
                Ok(Self::Keep)
            }
            WireHeadUpdateKind::Retarget => {
                let target = wire
                    .target_ref
                    .as_deref()
                    .ok_or_else(|| RefStoreError::InvalidIdentity("retarget head update requires target_ref".into()))?;
                Self::retarget(target)
            }
        }
    }
}

/// Wire representation of [`CommitRefsRequest`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireCommitRefsRequest {
    pub identity: WireOperationIdentity,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub object_format: GitObjectFormat,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
    pub group_epoch: i64,
    pub expected_revision: i64,
    pub head: WireHeadUpdate,
    pub mode: CommitMode,
    pub refs: Vec<WireRefUpdate>,
}

impl From<&CommitRefsRequest> for WireCommitRefsRequest {
    fn from(req: &CommitRefsRequest) -> Self {
        Self {
            identity: WireOperationIdentity::from(req.identity()),
            repository_id: req.repository_id(),
            tenant_id: req.tenant_id(),
            object_format: req.object_format(),
            history_incarnation: req.history_incarnation(),
            authority_epoch: req.authority_epoch(),
            group_epoch: req.group_epoch(),
            expected_revision: req.expected_revision(),
            head: WireHeadUpdate::from(req.head()),
            mode: req.mode(),
            refs: req.refs().iter().map(WireRefUpdate::from_ref_update).collect(),
        }
    }
}

impl TryFrom<&WireCommitRefsRequest> for CommitRefsRequest {
    type Error = RefStoreError;

    fn try_from(wire: &WireCommitRefsRequest) -> Result<Self, Self::Error> {
        if wire.identity.repository_id != wire.repository_id {
            return Err(RefStoreError::InvalidIdentity(
                "wire commit identity repository_id differs from request repository_id".into(),
            ));
        }
        let identity = OperationIdentity::try_from(&wire.identity)?;
        let head = HeadUpdate::try_from(&wire.head)?;
        let mut refs = Vec::with_capacity(wire.refs.len());
        for item in &wire.refs {
            refs.push(item.clone().into_ref_update(wire.object_format)?);
        }
        let req = CommitRefsRequest::new(
            wire.repository_id,
            wire.tenant_id,
            identity.issuer_id(),
            identity.lane().clone(),
            identity.sequence(),
            identity.operation_id(),
            wire.object_format,
            wire.history_incarnation,
            wire.authority_epoch,
            wire.group_epoch,
            wire.expected_revision,
            head,
            wire.mode,
            refs,
        )?;
        if req.identity().digest() != identity.digest() {
            return Err(RefStoreError::InvalidIdentity(
                "wire commit digest does not match canonical request body".into(),
            ));
        }
        Ok(req)
    }
}

/// Wire representation of [`CommitRejection`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireCommitRejection {
    pub code: CommitRejectCode,
    pub ref_name: Option<String>,
    pub expected: Option<String>,
    pub actual: Option<String>,
}

impl From<&CommitRejection> for WireCommitRejection {
    fn from(rejection: &CommitRejection) -> Self {
        Self {
            code: rejection.code,
            ref_name: rejection.ref_name.clone(),
            expected: rejection.expected.clone(),
            actual: rejection.actual.clone(),
        }
    }
}

impl From<WireCommitRejection> for CommitRejection {
    fn from(wire: WireCommitRejection) -> Self {
        Self { code: wire.code, ref_name: wire.ref_name, expected: wire.expected, actual: wire.actual }
    }
}

/// Wire representation of [`RefCommitResult`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireRefCommitResult {
    pub name: String,
    pub applied: bool,
    pub old_oid: Option<String>,
    pub new_oid: Option<String>,
    pub reason: Option<CommitRejectCode>,
}

impl From<&RefCommitResult> for WireRefCommitResult {
    fn from(result: &RefCommitResult) -> Self {
        match result {
            RefCommitResult::Applied { name, old_oid, new_oid } => Self {
                name: name.clone(),
                applied: true,
                old_oid: old_oid.clone(),
                new_oid: new_oid.clone(),
                reason: None,
            },
            RefCommitResult::NotApplied { name, reason } => {
                Self { name: name.clone(), applied: false, old_oid: None, new_oid: None, reason: Some(*reason) }
            }
        }
    }
}

impl TryFrom<WireRefCommitResult> for RefCommitResult {
    type Error = RefStoreError;

    fn try_from(wire: WireRefCommitResult) -> Result<Self, Self::Error> {
        if wire.applied {
            if wire.reason.is_some() {
                return Err(RefStoreError::Database("applied ref result cannot carry rejection reason".into()));
            }
            Ok(Self::Applied { name: wire.name, old_oid: wire.old_oid, new_oid: wire.new_oid })
        } else {
            let reason = wire
                .reason
                .ok_or_else(|| RefStoreError::Database("not-applied ref result must carry rejection reason".into()))?;
            Ok(Self::NotApplied { name: wire.name, reason })
        }
    }
}

/// Wire representation of [`CommitTerminal`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireCommitTerminal {
    pub kind: TerminalKind,
    pub repository_id: Uuid,
    pub revision: i64,
    pub head_ref: Option<String>,
    pub refs: Vec<WireRefCommitResult>,
    pub rejection: Option<WireCommitRejection>,
}

impl From<&CommitTerminal> for WireCommitTerminal {
    fn from(terminal: &CommitTerminal) -> Self {
        Self {
            kind: terminal.kind,
            repository_id: terminal.repository_id,
            revision: terminal.revision,
            head_ref: terminal.head_ref.clone(),
            refs: terminal.refs.iter().map(WireRefCommitResult::from).collect(),
            rejection: terminal.rejection.as_ref().map(WireCommitRejection::from),
        }
    }
}

impl TryFrom<WireCommitTerminal> for CommitTerminal {
    type Error = RefStoreError;

    fn try_from(wire: WireCommitTerminal) -> Result<Self, Self::Error> {
        let mut refs = Vec::with_capacity(wire.refs.len());
        for entry in wire.refs {
            refs.push(RefCommitResult::try_from(entry)?);
        }
        Ok(Self {
            kind: wire.kind,
            repository_id: wire.repository_id,
            revision: wire.revision,
            head_ref: wire.head_ref,
            refs,
            rejection: wire.rejection.map(CommitRejection::from),
        })
    }
}

/// Wire representation of a persisted [`OperationRecord`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WireOperationRecord {
    pub identity: WireOperationIdentity,
    pub state: OperationState,
    pub terminal_result: Option<Value>,
}

impl WireOperationRecord {
    pub fn from_record(record: &OperationRecord) -> Self {
        Self {
            identity: WireOperationIdentity::from(record.identity()),
            state: record.state(),
            terminal_result: record.terminal_result().map(|result| result.value().clone()),
        }
    }

    pub fn into_record(self) -> Result<OperationRecord, RefStoreError> {
        let identity = OperationIdentity::try_from(&self.identity)?;
        let terminal_result = self.terminal_result.map(TerminalResult::json).transpose()?;
        OperationRecord::new(identity, self.state, terminal_result)
    }
}
