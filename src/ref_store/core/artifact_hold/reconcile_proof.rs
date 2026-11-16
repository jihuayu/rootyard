//! Consensus-verified per-group retirement proofs for shared physical holds (#151).
//!
//! Untrusted transport DTOs (`GroupRetirementReceiptDto`, `GroupRetirementObservationDto`,
//! `AttestedGroupSnapshotDto`) carry `#[serde(deny_unknown_fields)]` and are strictly
//! separated from opaque `VerifiedGroupRetirement` / `VerifiedGroupObservation` values.
//! `Retired` observations can ONLY be minted by [`GroupConsensusVerifier`] after verifying
//! a majority-quorum HMAC-SHA256 commit attestation from the trusted group keyring and
//! validating the integrity-sealed `RefCasSnapshot` at that exact committed coordinate.

pub use super::bridge_contract::RetentionBridgeError;
use super::contract::MAX_BATCH_ARTIFACTS;
pub use super::group_keyring::{
    AttestedGroupSnapshotDto, GROUP_KEYRING_ENV, GroupConsensusVerifier, GroupVoterSignatureDto, QuorumCommitClaims,
    quorum_commit_transcript_bytes,
};
pub use super::retirement_reconcile::{
    GroupObservationStatus, GroupRetirementObservationDto, GroupRetirementReceiptDto,
};
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::state_machine::{
    RefCasSnapshot, RefCasStateMachine, ScopeLifecycle, SmHoldState, SmRootState,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::str::FromStr;
use uuid::Uuid;

/// Binding between one Ref-CAS group + repository and its local `hold_id`s.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GroupHoldBinding {
    pub group_id: i64,
    pub history_incarnation: Uuid,
    pub expected_group_epoch: i64,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub hold_ids: Vec<Uuid>,
    pub retire_request_id: Uuid,
}

impl GroupHoldBinding {
    pub fn validate(&self) -> Result<(), RetentionBridgeError> {
        let err = |msg: &str| RetentionBridgeError::InvalidBinding(msg.into());
        if self.group_id < 0 || self.expected_group_epoch <= 0 {
            return Err(err("invalid group_id or expected_group_epoch"));
        }
        let ids = [self.history_incarnation, self.repository_id, self.tenant_id, self.retire_request_id];
        if ids.iter().any(Uuid::is_nil) {
            return Err(err("group binding UUIDs must be non-nil"));
        }
        if self.hold_ids.is_empty() || self.hold_ids.len() > MAX_BATCH_ARTIFACTS {
            return Err(err("group hold_ids batch out of bounds"));
        }
        let mut seen = BTreeSet::new();
        if self.hold_ids.iter().any(|id| id.is_nil() || !seen.insert(*id)) {
            return Err(err("group hold_ids must be non-nil and unique"));
        }
        Ok(())
    }
}

/// Complete multi-group declaration for a shared physical artifact hold.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SharedHoldReference {
    pub shared_hold_key: Uuid,
    pub artifact_digest: String,
    pub backend_identity: String,
    pub groups: Vec<GroupHoldBinding>,
}

impl SharedHoldReference {
    pub fn validate(&self) -> Result<(), RetentionBridgeError> {
        let err = |msg: &str| RetentionBridgeError::InvalidBinding(msg.into());
        if self.shared_hold_key.is_nil() || self.groups.is_empty() {
            return Err(err("shared hold requires key and >= 1 group"));
        }
        RequestDigest::from_str(&self.artifact_digest)?;
        RequestDigest::from_str(&self.backend_identity)?;
        let (mut seen_groups, mut seen_holds) = (BTreeSet::new(), BTreeSet::new());
        for g in &self.groups {
            g.validate()?;
            if !seen_groups.insert((g.group_id, g.repository_id)) {
                return Err(err("duplicate (group_id, repository_id)"));
            }
            if g.hold_ids.iter().any(|id| !seen_holds.insert(*id)) {
                return Err(err("duplicate hold_id across groups"));
            }
        }
        Ok(())
    }

    pub fn all_hold_ids(&self) -> Vec<Uuid> {
        self.groups.iter().flat_map(|g| g.hold_ids.iter().copied()).collect()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetirementBlockReason {
    GroupMissingObservation { group_id: i64, repository_id: Uuid },
    GroupDuplicateObservation { group_id: i64, repository_id: Uuid },
    GroupUnreachable { group_id: i64, repository_id: Uuid },
    GroupUnknownOutcome { group_id: i64, repository_id: Uuid },
    GroupStillActive { group_id: i64, repository_id: Uuid },
    ClosingBarrierNotReached { group_id: i64, repository_id: Uuid },
    ActiveRootStillProtecting { group_id: i64, repository_id: Uuid, active_roots: usize },
    HoldNotRetiredInGroup { group_id: i64, repository_id: Uuid },
    StaleSnapshot { group_id: i64, repository_id: Uuid, observed_log_index: u64, required_log_index: u64 },
    InvalidReceipt { group_id: i64, repository_id: Uuid },
    MissingProjectionCursor { group_id: i64, history_incarnation: Uuid },
    CursorResyncRequired { group_id: i64, history_incarnation: Uuid },
    CursorEpochMismatch { group_id: i64, expected_epoch: i64, actual_epoch: i64 },
    CursorBehindRetirement { group_id: i64, applied_log_index: u64, retirement_log_index: u64 },
    MissingPgHoldRow { repository_id: Uuid, hold_id: Uuid },
    PgHoldIdentityMismatch { repository_id: Uuid, hold_id: Uuid },
    UnreconciledCrossRepoHold { repository_id: Uuid, hold_id: Uuid },
    MissingPgEvidence,
}

/// Opaque consensus-verified retirement proof (zero `Deserialize`, private inner state).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedGroupRetirement {
    receipt: GroupRetirementReceiptDto,
    artifact_digest: String,
    backend_identity: String,
}

impl VerifiedGroupRetirement {
    pub fn receipt(&self) -> &GroupRetirementReceiptDto {
        &self.receipt
    }

    pub fn barrier_log_index(&self) -> u64 {
        self.receipt.retirement_log_index
    }

    pub(super) fn artifact_digest(&self) -> &str {
        &self.artifact_digest
    }

    pub(super) fn backend_identity(&self) -> &str {
        &self.backend_identity
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum VerifiedGroupState {
    Retired(VerifiedGroupRetirement),
    Active { detail: String },
    Unreachable,
    UnknownOutcome { detail: String },
    StaleSnapshot { observed_log_index: u64, required_log_index: u64, detail: String },
}

/// Opaque per-group observation consumed by the shared-hold retirement reconciler.
/// Cannot be deserialized from JSON; `Retired` variants require quorum attestation verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedGroupObservation {
    group_id: i64,
    repository_id: Uuid,
    state: VerifiedGroupState,
    observed_log_index: Option<u64>,
    detail: Option<String>,
}

impl VerifiedGroupObservation {
    pub fn group_id(&self) -> i64 {
        self.group_id
    }

    pub fn repository_id(&self) -> Uuid {
        self.repository_id
    }

    pub fn status(&self) -> GroupObservationStatus {
        match &self.state {
            VerifiedGroupState::Retired(_) => GroupObservationStatus::Retired,
            VerifiedGroupState::Active { .. } => GroupObservationStatus::Active,
            VerifiedGroupState::Unreachable => GroupObservationStatus::Unreachable,
            VerifiedGroupState::UnknownOutcome { .. } => GroupObservationStatus::UnknownOutcome,
            VerifiedGroupState::StaleSnapshot { .. } => GroupObservationStatus::StaleSnapshot,
        }
    }

    pub fn retired_proof(&self) -> Option<&VerifiedGroupRetirement> {
        match &self.state {
            VerifiedGroupState::Retired(proof) => Some(proof),
            _ => None,
        }
    }

    pub(super) fn state(&self) -> &VerifiedGroupState {
        &self.state
    }

    pub fn to_dto(&self) -> GroupRetirementObservationDto {
        GroupRetirementObservationDto {
            group_id: self.group_id,
            repository_id: self.repository_id,
            status: self.status(),
            receipt: self.retired_proof().map(|p| p.receipt.clone()),
            observed_log_index: self.observed_log_index,
            detail: self.detail.clone(),
        }
    }
}

impl GroupConsensusVerifier {
    /// Fail-closed observation when a consensus group cannot be reached during reconciliation.
    pub fn observe_unreachable(
        &self,
        binding: &GroupHoldBinding,
        detail: Option<String>,
    ) -> Result<VerifiedGroupObservation, RetentionBridgeError> {
        binding.validate()?;
        Ok(VerifiedGroupObservation {
            group_id: binding.group_id,
            repository_id: binding.repository_id,
            state: VerifiedGroupState::Unreachable,
            observed_log_index: None,
            detail,
        })
    }

    /// Fail-closed observation when a consensus poll ended with an inconclusive / unknown outcome.
    pub fn observe_unknown_outcome(
        &self,
        binding: &GroupHoldBinding,
        detail: Option<String>,
    ) -> Result<VerifiedGroupObservation, RetentionBridgeError> {
        binding.validate()?;
        let msg = detail.clone().unwrap_or_else(|| "unknown group outcome".into());
        Ok(VerifiedGroupObservation {
            group_id: binding.group_id,
            repository_id: binding.repository_id,
            state: VerifiedGroupState::UnknownOutcome { detail: msg },
            observed_log_index: None,
            detail,
        })
    }

    /// Authenticate a quorum-signed `RefCasSnapshot` envelope against this keyring's
    /// trusted group keys before inspecting state and minting `VerifiedGroupObservation`.
    pub fn verify_attested_observation(
        &self,
        attested: &AttestedGroupSnapshotDto,
        binding: &GroupHoldBinding,
        expected_artifact_digest: &str,
        expected_backend_identity: &str,
        min_expected_log_index: Option<u64>,
    ) -> Result<VerifiedGroupObservation, RetentionBridgeError> {
        binding.validate()?;
        RequestDigest::from_str(expected_artifact_digest)?;
        RequestDigest::from_str(expected_backend_identity)?;
        if matches!(min_expected_log_index, Some(0)) {
            return Err(RetentionBridgeError::InvalidBinding("min_expected_log_index must be >= 1".into()));
        }
        self.verify_quorum_attestation(attested)?;
        if (attested.group_id, attested.history_incarnation, attested.group_epoch)
            != (binding.group_id, binding.history_incarnation, binding.expected_group_epoch)
        {
            return Err(RetentionBridgeError::UntrustedObservationProof);
        }
        let snap: RefCasSnapshot = serde_json::from_slice(&attested.snapshot_bytes)
            .map_err(|_| RetentionBridgeError::UntrustedObservationProof)?;
        snap.verify_integrity()?;
        RefCasStateMachine::restore(&snap)?;
        let Some(applied) = snap.body.last_applied else {
            return Err(RetentionBridgeError::UntrustedObservationProof);
        };
        if applied.term != attested.raft_term || applied.index != attested.committed_log_index {
            return Err(RetentionBridgeError::UntrustedObservationProof);
        }
        evaluate_attested_snapshot(
            &snap,
            attested,
            binding,
            expected_artifact_digest,
            expected_backend_identity,
            min_expected_log_index,
        )
    }
}

fn evaluate_attested_snapshot(
    snap: &RefCasSnapshot,
    attested: &AttestedGroupSnapshotDto,
    binding: &GroupHoldBinding,
    expected_artifact_digest: &str,
    expected_backend_identity: &str,
    min_expected_log_index: Option<u64>,
) -> Result<VerifiedGroupObservation, RetentionBridgeError> {
    let (gid, rid) = (binding.group_id, binding.repository_id);
    let applied_idx = attested.committed_log_index;
    let mk_obs = |state, detail: Option<String>| {
        Ok(VerifiedGroupObservation {
            group_id: gid,
            repository_id: rid,
            state,
            observed_log_index: Some(applied_idx),
            detail,
        })
    };
    let Some(gate) = snap.body.gates.iter().find(|g| g.repository_id == rid) else {
        return mk_obs(
            VerifiedGroupState::UnknownOutcome { detail: "missing gate".into() },
            Some("missing gate".into()),
        );
    };
    if (gate.tenant_id, gate.history_incarnation, gate.group_epoch, gate.authority_epoch)
        != (binding.tenant_id, binding.history_incarnation, binding.expected_group_epoch, attested.authority_epoch)
    {
        return Err(RetentionBridgeError::UntrustedObservationProof);
    }
    if let Some(min_idx) = min_expected_log_index
        && applied_idx < min_idx
    {
        let msg = format!("applied {applied_idx} < {min_idx}");
        return mk_obs(
            VerifiedGroupState::StaleSnapshot {
                observed_log_index: applied_idx,
                required_log_index: min_idx,
                detail: msg.clone(),
            },
            Some(msg),
        );
    }
    if gate.lifecycle == ScopeLifecycle::Open {
        return mk_obs(
            VerifiedGroupState::Active { detail: "closing barrier open".into() },
            Some("closing barrier open".into()),
        );
    }
    let active_roots = snap
        .body
        .roots
        .iter()
        .filter(|r| {
            r.state == SmRootState::Active
                && (r.repository_id == rid || r.bound_hold_ids.iter().any(|id| binding.hold_ids.contains(id)))
        })
        .count();
    if active_roots > 0 {
        let msg = format!("{active_roots} active root(s) remain");
        return mk_obs(VerifiedGroupState::Active { detail: msg.clone() }, Some(msg));
    }
    let Some(retire_rec) =
        snap.body.hold_retires.iter().find(|r| {
            (r.request_id, r.repository_id, r.tenant_id) == (binding.retire_request_id, rid, binding.tenant_id)
        })
    else {
        return mk_obs(
            VerifiedGroupState::Active { detail: "no retire receipt".into() },
            Some("no retire receipt".into()),
        );
    };
    for &hold_id in &binding.hold_ids {
        if !retire_rec.hold_ids.contains(&hold_id) {
            return mk_obs(VerifiedGroupState::Active { detail: "hold omitted".into() }, Some("hold omitted".into()));
        }
        let Some(e) = snap.body.holds.iter().find(|h| h.hold_id == hold_id) else {
            return mk_obs(
                VerifiedGroupState::UnknownOutcome { detail: "missing hold".into() },
                Some("missing hold".into()),
            );
        };
        if (e.repository_id, e.tenant_id) != (rid, binding.tenant_id)
            || e.artifact_digest != expected_artifact_digest
            || e.backend_identity != expected_backend_identity
            || e.state != SmHoldState::Retired
        {
            return mk_obs(
                VerifiedGroupState::Active { detail: "hold not retired".into() },
                Some("hold not retired".into()),
            );
        }
    }
    // Conservative barrier: locked to quorum-committed `last_applied.index` so low caller hints cannot bypass fencing.
    let mut receipt = GroupRetirementReceiptDto {
        group_id: gid,
        history_incarnation: binding.history_incarnation,
        group_epoch: gate.group_epoch,
        authority_epoch: gate.authority_epoch,
        repository_id: rid,
        tenant_id: binding.tenant_id,
        scope_lifecycle: gate.lifecycle,
        retire_request_id: binding.retire_request_id,
        retired_hold_ids: binding.hold_ids.clone(),
        active_root_count: active_roots,
        retirement_log_index: applied_idx,
        applied_log_index: applied_idx,
        snapshot_digest: snap.checksum.clone(),
        receipt_digest: String::new(),
    };
    receipt.receipt_digest = receipt.compute_digest().as_hex();
    let proof = VerifiedGroupRetirement {
        receipt,
        artifact_digest: expected_artifact_digest.to_owned(),
        backend_identity: expected_backend_identity.to_owned(),
    };
    mk_obs(VerifiedGroupState::Retired(proof), None)
}
