//! Immutable registration ACK, commit terminal/receipt and the pre-write size
//! budget.
//!
//! Every persisted body is canonical JSON bounded by
//! [`MAX_ACK_BODY_BYTES`]. The worst-case committed *and* rejected terminal of a
//! plan is serialized before the registry is touched, so a real commit can
//! never fail after refs/membership/revision rows were written.
use super::contract::{MAX_ACK_BODY_BYTES, MAX_BATCH_NEW_PACKS, MAX_PLAN_REFS, PackMode};
use super::error::{PackCommitError, PackCommitRejectCode, PackCommitRejection};
use super::plan::PackCommitPlan;
use crate::ref_store::contract::{OperationRecord, OperationState, RefStoreError, TerminalResult};
use crate::ref_store::core::terminal::{CommitRejectCode, RefCommitResult, TerminalKind};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const WORST_CASE_OID: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const WORST_CASE_REF_NAME_BYTES: usize = 1024;

/// One immutable registration ACK body (`<= 64 KiB`).
///
/// The body repeats the complete outer durable realm (repository/tenant/owner/
/// purpose/format/history/epochs, parent operation, gate proof, backend, planned
/// content and ids) so a bounded reader can cross-check **every** outer column
/// against the body instead of trusting syntax-only JSON.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PackRegistrationAck {
    pub registration_id: Uuid,
    pub pack_id: Uuid,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub purpose: String,
    pub object_format: String,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
    pub group_epoch: i64,
    pub plan_operation_id: Uuid,
    pub parent_digest: String,
    pub gate_revision: i64,
    pub gate_digest: String,
    pub backend_identity: String,
    pub planned_pack_sha256: String,
    pub planned_pack_length: u64,
    pub planned_idx_sha256: String,
    pub planned_idx_length: u64,
    pub artifact_set_digest: String,
    pub acquire_request_id: Uuid,
    pub consume_request_id: Uuid,
    pub hold_ids: Vec<Uuid>,
    /// Exact retained logical DB bytes of this registration. It is a fixed point
    /// of `Charge::registration(body_len, body_len)` and is the same value that is
    /// persisted in the row column and charged to the quota counters.
    pub logical_bytes: i64,
    /// Exactly one pair per registration in this slice.
    pub candidate_packs: i64,
}

impl PackRegistrationAck {
    /// One publication == one planned pair registration.
    pub const fn one_pair() -> i64 {
        1
    }

    /// Structural self-check used by the bounded reader before any cross-check.
    pub fn ensure_one_pair(&self) -> Result<(), RefStoreError> {
        if self.candidate_packs != Self::one_pair() {
            return Err(RefStoreError::Database("stored registration ACK names a non-single pair count".into()));
        }
        if self.hold_ids.len() != super::contract::ARTIFACTS_PER_PACK {
            return Err(RefStoreError::Database("stored registration ACK does not bind exactly two holds".into()));
        }
        Ok(())
    }
}

impl PackRegistrationAck {
    pub fn encode(&self) -> Result<String, PackCommitError> {
        let body = serde_json::to_string(self).map_err(|_| PackCommitError::Invalid("ACK is not serializable"))?;
        if body.len() > MAX_ACK_BODY_BYTES {
            return Err(PackCommitError::Capacity {
                limit: "registration_ack_body",
                bound: MAX_ACK_BODY_BYTES as i64,
                actual: body.len() as i64,
            });
        }
        Ok(body)
    }

    pub fn decode(body: &str) -> Result<Self, PackCommitError> {
        if body.is_empty() || body.len() > MAX_ACK_BODY_BYTES {
            return Err(PackCommitError::Invalid("stored pack registration ACK is not bounded"));
        }
        serde_json::from_str(body).map_err(|_| PackCommitError::Invalid("stored pack registration ACK is not JSON"))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackRegistrationReceipt {
    pub ack: PackRegistrationAck,
    pub replayed: bool,
}

/// Persisted rejection detail. Fixed literals only: never SQL/Git/caller text.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PackTerminalRejection {
    pub code: String,
    pub detail: String,
}

/// Registration summary carried by the commit terminal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PackTerminalRegistration {
    pub pack_id: Uuid,
    pub registration_id: Uuid,
    pub artifact_set_digest: String,
}

/// Immutable per-operation terminal of a verified pack commit.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PackCommitTerminal {
    pub kind: TerminalKind,
    pub repository_id: Uuid,
    pub revision: i64,
    pub head_ref: Option<String>,
    pub mode: String,
    pub refs: Vec<RefCommitResult>,
    pub registrations: Vec<PackTerminalRegistration>,
    pub rejection: Option<PackTerminalRejection>,
}

impl PackCommitTerminal {
    pub(crate) fn committed(
        repository_id: Uuid,
        revision: i64,
        head_ref: String,
        mode: PackMode,
        refs: Vec<RefCommitResult>,
        registrations: Vec<PackTerminalRegistration>,
    ) -> Self {
        Self {
            kind: TerminalKind::Committed,
            repository_id,
            revision,
            head_ref: Some(head_ref),
            mode: mode.as_str().to_owned(),
            refs,
            registrations,
            rejection: None,
        }
    }

    pub(crate) fn rejected(
        repository_id: Uuid,
        revision: i64,
        head_ref: Option<String>,
        mode: PackMode,
        refs: Vec<RefCommitResult>,
        rejection: PackCommitRejection,
    ) -> Self {
        Self {
            kind: TerminalKind::Rejected,
            repository_id,
            revision,
            head_ref,
            mode: mode.as_str().to_owned(),
            refs,
            registrations: Vec::new(),
            rejection: Some(PackTerminalRejection {
                code: rejection.code.as_str().to_owned(),
                detail: rejection.detail.to_owned(),
            }),
        }
    }

    pub fn is_committed(&self) -> bool {
        self.kind == TerminalKind::Committed
    }

    pub fn rejection(&self) -> Result<Option<PackCommitRejection>, RefStoreError> {
        match &self.rejection {
            None => Ok(None),
            Some(rejection) => {
                let code = PackCommitRejectCode::parse(&rejection.code)?;
                Ok(Some(PackCommitRejection::new(code, "persisted rejection")))
            }
        }
    }

    pub(crate) fn to_terminal_result(&self) -> Result<TerminalResult, RefStoreError> {
        let value = serde_json::to_value(self)
            .map_err(|_| RefStoreError::InvalidIdentity("pack commit terminal is not serializable".into()))?;
        TerminalResult::json(value)
    }

    pub(crate) fn from_terminal_result(result: &TerminalResult) -> Result<Self, RefStoreError> {
        serde_json::from_value(result.value().clone())
            .map_err(|_| RefStoreError::Database("stored core terminal is not a pack commit terminal".into()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackCommitReceipt {
    pub record: OperationRecord,
    pub replayed: bool,
    pub terminal: PackCommitTerminal,
}

impl PackCommitReceipt {
    pub fn is_committed(&self) -> bool {
        self.terminal.is_committed() && self.record.state() == OperationState::Committed
    }
}

/// Pre-write budget: the exact worst case of both outcomes for this plan.
pub fn ensure_pack_terminal_budget(plan: &PackCommitPlan) -> Result<(), RefStoreError> {
    if plan.refs().len() > MAX_PLAN_REFS || plan.packs().len() > MAX_BATCH_NEW_PACKS {
        return Err(RefStoreError::InvalidIdentity("pack commit plan exceeds a fixed bound".into()));
    }
    let names = plan.refs().iter().map(|update| update.name().as_str().to_owned()).collect::<Vec<_>>();
    let worst_names = names.iter().map(|name| worst_case_name(name)).collect::<Vec<_>>();
    let registrations = plan
        .packs()
        .iter()
        .map(|pack| PackTerminalRegistration {
            pack_id: pack.pack_id(),
            registration_id: pack.registration_id(),
            artifact_set_digest: WORST_CASE_OID.to_owned(),
        })
        .collect::<Vec<_>>();
    let committed = PackCommitTerminal::committed(
        plan.repository_id(),
        i64::MAX,
        worst_case_head(),
        plan.expected().mode(),
        worst_names
            .iter()
            .map(|name| RefCommitResult::Applied {
                name: name.clone(),
                old_oid: Some(WORST_CASE_OID.to_owned()),
                new_oid: Some(WORST_CASE_OID.to_owned()),
            })
            .collect(),
        registrations.clone(),
    );
    committed.to_terminal_result()?;
    let rejected = PackCommitTerminal::rejected(
        plan.repository_id(),
        i64::MAX,
        Some(worst_case_head()),
        plan.expected().mode(),
        worst_names
            .iter()
            .map(|name| RefCommitResult::NotApplied { name: name.clone(), reason: CommitRejectCode::OldOidMismatch })
            .collect(),
        PackCommitRejection::new(PackCommitRejectCode::ClosureMismatch, "closure"),
    );
    rejected.to_terminal_result()?;
    Ok(())
}

fn worst_case_name(name: &str) -> String {
    if name.len() >= WORST_CASE_REF_NAME_BYTES {
        return name.to_owned();
    }
    let mut padded = name.to_owned();
    padded.push_str(&"a".repeat(WORST_CASE_REF_NAME_BYTES - name.len()));
    padded
}

fn worst_case_head() -> String {
    format!("refs/heads/{}", "z".repeat(WORST_CASE_REF_NAME_BYTES - "refs/heads/".len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ack_bodies_are_bounded_and_round_trip() {
        let ack = PackRegistrationAck {
            registration_id: Uuid::from_bytes([1; 16]),
            pack_id: Uuid::from_bytes([2; 16]),
            repository_id: Uuid::from_bytes([7; 16]),
            tenant_id: Uuid::from_bytes([8; 16]),
            owner_id: Uuid::from_bytes([9; 16]),
            purpose: "ref_publication".into(),
            object_format: "sha1".into(),
            history_incarnation: Uuid::from_bytes([10; 16]),
            authority_epoch: 1,
            group_epoch: 1,
            plan_operation_id: Uuid::from_bytes([11; 16]),
            parent_digest: "a".repeat(64),
            gate_revision: 2,
            gate_digest: "c".repeat(64),
            backend_identity: "d".repeat(64),
            planned_pack_sha256: "e".repeat(64),
            planned_pack_length: 10,
            planned_idx_sha256: "f".repeat(64),
            planned_idx_length: 5,
            artifact_set_digest: "b".repeat(64),
            acquire_request_id: Uuid::from_bytes([3; 16]),
            consume_request_id: Uuid::from_bytes([4; 16]),
            hold_ids: vec![Uuid::from_bytes([5; 16]), Uuid::from_bytes([6; 16])],
            logical_bytes: 64,
            candidate_packs: PackRegistrationAck::one_pair(),
        };
        ack.ensure_one_pair().unwrap();
        let body = ack.encode().unwrap();
        assert_eq!(PackRegistrationAck::decode(&body).unwrap(), ack);
        assert!(PackRegistrationAck::decode("").is_err());
        let oversized = "x".repeat(MAX_ACK_BODY_BYTES + 1);
        assert!(PackRegistrationAck::decode(&oversized).is_err());
    }

    #[test]
    fn terminal_rejections_round_trip_through_fixed_codes() {
        let terminal = PackCommitTerminal::rejected(
            Uuid::from_bytes([1; 16]),
            3,
            Some("refs/heads/main".into()),
            PackMode::MetadataOnly,
            Vec::new(),
            PackCommitRejection::new(PackCommitRejectCode::OldMembershipMismatch, "membership"),
        );
        let stored = terminal.to_terminal_result().unwrap();
        let decoded = PackCommitTerminal::from_terminal_result(&stored).unwrap();
        assert_eq!(decoded, terminal);
        assert_eq!(decoded.rejection().unwrap().unwrap().code, PackCommitRejectCode::OldMembershipMismatch);
        assert!(PackCommitRejectCode::parse("not-a-code").is_err());
    }
}
