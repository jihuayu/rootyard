//! Contracts, error types, and strict Serde DTOs for the global PG artifact-hold
//! <-> Ref-CAS retention bridge and multi-group retirement reconciler (#151).
//!
//! Every `Deserialize` struct carries `#[serde(deny_unknown_fields)]`. Zero I/O
//! or PostgreSQL queries run in this module.

use super::contract::{ArtifactHoldError, HoldScope};
use super::receipt::AcquireAck;
pub use super::reconcile_proof::{GroupHoldBinding, SharedHoldReference};
pub use super::retirement_reconcile::{
    PgArtifactHoldReconciliationView, PgCrossRepoSiblingHold, PgHoldRowSummary, SharedHoldRetirementStatus,
};
use crate::blob_store::BlobBackendIdentity;
use crate::ref_store::contract::{IssuerLane, MetadataPinPurpose, OperationIdentity, RefStoreError, RequestDigest};
use crate::ref_store::core::retention_root::{RootPurpose, RootSelectorKind};
use crate::ref_store::core::state_machine::{
    AcquireHoldBatchCommand, MarkHoldConsumedCommand, ScopeLifecycle, StateMachineError, WireHoldArtifactSpec,
    WireOperationIdentity,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use uuid::Uuid;

/// Typed errors for the PG <-> Ref-CAS retention bridge and retirement reconciler.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RetentionBridgeError {
    InvalidBinding(String),
    BackendMismatch,
    GenerationConflict { field: &'static str, expected: i64, actual: i64 },
    RealmMismatch(&'static str),
    CancelledBeforeRegister { operation_id: Uuid },
    UnknownAcquireCommit { request_id: Uuid },
    MissingDurableHold { request_id: Uuid },
    ScopeClosingOrClosed { repository_id: Uuid, lifecycle: ScopeLifecycle },
    ArtifactHold(ArtifactHoldError),
    StateMachine(StateMachineError),
    Store(RefStoreError),
    Database(String),
    RetirementRefused(String),
    UntrustedObservationProof,
}

impl fmt::Display for RetentionBridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBinding(msg) => write!(f, "invalid retention bridge binding: {msg}"),
            Self::BackendMismatch => write!(f, "retention bridge physical backend_identity mismatch"),
            Self::GenerationConflict { field, expected, actual } => {
                write!(f, "bridge anti-ABA conflict on {field}: expected {expected}, got {actual}")
            }
            Self::RealmMismatch(field) => write!(f, "retention bridge realm mismatch on {field}"),
            Self::CancelledBeforeRegister { operation_id } => {
                write!(f, "operation {operation_id} fenced by cancel-before-register or cancel_cutoff")
            }
            Self::UnknownAcquireCommit { request_id } => {
                write!(f, "global PG hold commit unknown for request {request_id}")
            }
            Self::MissingDurableHold { request_id } => {
                write!(f, "required global PG hold {request_id} missing; refusing Ref-CAS publish")
            }
            Self::ScopeClosingOrClosed { repository_id, lifecycle } => {
                write!(f, "repository {repository_id} is {lifecycle:?} and fenced against late publish")
            }
            Self::ArtifactHold(err) => write!(f, "artifact-hold error: {err}"),
            Self::StateMachine(err) => write!(f, "ref-cas state machine error: {err}"),
            Self::Store(err) => write!(f, "ref-store contract error: {err}"),
            Self::Database(msg) => write!(f, "retention bridge database error: {msg}"),
            Self::RetirementRefused(msg) => write!(f, "shared hold retirement refused: {msg}"),
            Self::UntrustedObservationProof => write!(f, "untrusted retirement DTO rejected; consensus proof required"),
        }
    }
}

impl std::error::Error for RetentionBridgeError {}

impl From<ArtifactHoldError> for RetentionBridgeError {
    fn from(err: ArtifactHoldError) -> Self {
        match err {
            ArtifactHoldError::AcquireUnknown { request_id } => Self::UnknownAcquireCommit { request_id },
            ArtifactHoldError::OperationCancelled { operation_id } => Self::CancelledBeforeRegister { operation_id },
            ArtifactHoldError::BackendMismatch => Self::BackendMismatch,
            other => Self::ArtifactHold(other),
        }
    }
}

impl From<StateMachineError> for RetentionBridgeError {
    fn from(err: StateMachineError) -> Self {
        match err {
            StateMachineError::BelowCancelCutoff { operation_id, .. }
            | StateMachineError::Store(RefStoreError::Cancelled { operation_id }) => {
                Self::CancelledBeforeRegister { operation_id }
            }
            StateMachineError::ScopeClosingOrClosed { repository_id, lifecycle } => {
                Self::ScopeClosingOrClosed { repository_id, lifecycle }
            }
            other => Self::StateMachine(other),
        }
    }
}

impl From<RefStoreError> for RetentionBridgeError {
    fn from(err: RefStoreError) -> Self {
        Self::Store(err)
    }
}

/// Shared realm/generation tuple checked against PG `AcquireAck` and hold scopes.
#[derive(Clone, Copy, Debug)]
pub(super) struct ObservedRealm<'a> {
    pub(super) tenant_id: Uuid,
    pub(super) repository_id: Uuid,
    pub(super) owner_id: Uuid,
    pub(super) history_incarnation: Uuid,
    pub(super) authority_epoch: i64,
    pub(super) group_epoch: i64,
    pub(super) backend_identity: &'a str,
}

/// Complete tenant/authority/backend/history/group/operation identity binding a
/// global PG artifact hold to its Ref-CAS pin/root authority.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeBinding {
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub owner_id: Uuid,
    pub authority_id: Uuid,
    pub authority_generation: i64,
    pub authority_epoch: i64,
    pub backend_identity: String,
    pub history_incarnation: Uuid,
    pub group_id: i64,
    pub group_epoch: i64,
    pub issuer_id: Uuid,
    pub lane: String,
    pub sequence: i64,
    pub operation_id: Uuid,
    pub operation_digest: String,
}

impl BridgeBinding {
    pub fn from_scope_and_operation(
        scope: &HoldScope,
        operation: &OperationIdentity,
        authority_id: Uuid,
        authority_generation: i64,
        group_id: i64,
        backend: &BlobBackendIdentity,
    ) -> Result<Self, RetentionBridgeError> {
        if operation.repository_id() != scope.repository_id() {
            return Err(RetentionBridgeError::RealmMismatch("operation.repository_id"));
        }
        let binding = Self {
            tenant_id: scope.tenant_id(),
            repository_id: scope.repository_id(),
            owner_id: scope.owner_id(),
            authority_id,
            authority_generation,
            authority_epoch: scope.authority_epoch(),
            backend_identity: backend.as_hex().to_owned(),
            history_incarnation: scope.history_incarnation(),
            group_id,
            group_epoch: scope.group_epoch(),
            issuer_id: operation.issuer_id(),
            lane: operation.lane().as_str().to_owned(),
            sequence: operation.sequence(),
            operation_id: operation.operation_id(),
            operation_digest: operation.digest().as_hex(),
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn validate(&self) -> Result<(), RetentionBridgeError> {
        let ids = [
            self.tenant_id,
            self.repository_id,
            self.owner_id,
            self.authority_id,
            self.history_incarnation,
            self.issuer_id,
            self.operation_id,
        ];
        if ids.iter().any(Uuid::is_nil) {
            return Err(RetentionBridgeError::InvalidBinding("all bridge UUID fields must be non-nil".into()));
        }
        if self.authority_generation <= 0
            || self.authority_epoch <= 0
            || self.group_epoch <= 0
            || self.sequence <= 0
            || self.group_id < 0
        {
            return Err(RetentionBridgeError::InvalidBinding("generation/epoch/sequence/group_id out of range".into()));
        }
        IssuerLane::new(&self.lane)?;
        RequestDigest::from_str(&self.backend_identity)?;
        RequestDigest::from_str(&self.operation_digest)?;
        Ok(())
    }

    pub fn binding_digest(&self) -> RequestDigest {
        RequestDigest::of(
            "refcas-retention-bridge-binding-v1",
            &[
                self.tenant_id.as_bytes(),
                self.repository_id.as_bytes(),
                self.owner_id.as_bytes(),
                self.authority_id.as_bytes(),
                &self.authority_generation.to_be_bytes(),
                &self.authority_epoch.to_be_bytes(),
                self.backend_identity.as_bytes(),
                self.history_incarnation.as_bytes(),
                &self.group_id.to_be_bytes(),
                &self.group_epoch.to_be_bytes(),
                self.issuer_id.as_bytes(),
                self.lane.as_bytes(),
                &self.sequence.to_be_bytes(),
                self.operation_id.as_bytes(),
                self.operation_digest.as_bytes(),
            ],
        )
    }

    pub fn to_wire_operation_identity(&self) -> WireOperationIdentity {
        WireOperationIdentity {
            repository_id: self.repository_id,
            issuer_id: self.issuer_id,
            lane: self.lane.clone(),
            sequence: self.sequence,
            operation_id: self.operation_id,
            digest: self.operation_digest.clone(),
        }
    }

    pub(super) fn check_realm(&self, observed: ObservedRealm<'_>) -> Result<(), RetentionBridgeError> {
        if observed.tenant_id != self.tenant_id
            || observed.repository_id != self.repository_id
            || observed.owner_id != self.owner_id
        {
            return Err(RetentionBridgeError::RealmMismatch("scope"));
        }
        if observed.history_incarnation != self.history_incarnation {
            return Err(RetentionBridgeError::RealmMismatch("history_incarnation"));
        }
        if observed.authority_epoch != self.authority_epoch {
            return Err(RetentionBridgeError::GenerationConflict {
                field: "authority_epoch",
                expected: self.authority_epoch,
                actual: observed.authority_epoch,
            });
        }
        if observed.group_epoch != self.group_epoch {
            return Err(RetentionBridgeError::GenerationConflict {
                field: "group_epoch",
                expected: self.group_epoch,
                actual: observed.group_epoch,
            });
        }
        if observed.backend_identity != self.backend_identity {
            return Err(RetentionBridgeError::BackendMismatch);
        }
        Ok(())
    }

    pub fn matches_acquire_ack(&self, ack: &AcquireAck) -> Result<(), RetentionBridgeError> {
        self.validate()?;
        self.check_realm(ObservedRealm {
            tenant_id: ack.tenant_id,
            repository_id: ack.repository_id,
            owner_id: ack.owner_id,
            history_incarnation: ack.history_incarnation,
            authority_epoch: ack.authority_epoch,
            group_epoch: ack.group_epoch,
            backend_identity: &ack.backend_identity,
        })?;
        if ack.issuer_id != self.issuer_id
            || ack.lane != self.lane
            || ack.sequence != self.sequence
            || ack.operation_id != self.operation_id
            || ack.operation_digest != self.operation_digest
        {
            return Err(RetentionBridgeError::RealmMismatch("operation_identity"));
        }
        for hold in &ack.artifacts {
            if hold.artifact.backend_identity != self.backend_identity {
                return Err(RetentionBridgeError::BackendMismatch);
            }
            if hold.artifact.tenant_id != self.tenant_id || hold.artifact.authority_id != self.authority_id {
                return Err(RetentionBridgeError::RealmMismatch("artifact.authority"));
            }
            if hold.artifact.authority_generation != self.authority_generation {
                return Err(RetentionBridgeError::GenerationConflict {
                    field: "authority_generation",
                    expected: self.authority_generation,
                    actual: hold.artifact.authority_generation,
                });
            }
        }
        Ok(())
    }

    pub fn to_hold_batch_command(&self, ack: &AcquireAck) -> Result<AcquireHoldBatchCommand, RetentionBridgeError> {
        self.matches_acquire_ack(ack)?;
        let mut sorted = ack.artifacts.clone();
        sorted.sort_by_key(|item| item.slot);
        let artifacts = sorted
            .iter()
            .map(|hold| {
                let slot = i16::try_from(hold.slot)
                    .map_err(|_| RetentionBridgeError::InvalidBinding("hold slot overflows i16".into()))?;
                Ok(WireHoldArtifactSpec {
                    hold_id: hold.hold_id,
                    slot,
                    artifact_digest: hold.artifact.sha256.clone(),
                    declared_bytes: hold.declared_bytes,
                    logical_bytes: hold.logical_bytes,
                })
            })
            .collect::<Result<Vec<_>, RetentionBridgeError>>()?;
        Ok(AcquireHoldBatchCommand {
            request_id: ack.request_id,
            consume_request_id: ack.consume_request_id,
            operation_id: self.operation_id,
            repository_id: self.repository_id,
            tenant_id: self.tenant_id,
            owner_id: self.owner_id,
            purpose: ack.purpose.as_str().to_owned(),
            backend_identity: self.backend_identity.clone(),
            authority_id: self.authority_id,
            authority_generation: self.authority_generation,
            expected_gate_digest: ack.gate_digest.clone(),
            artifacts,
        })
    }

    pub fn to_consume_command(&self, ack: &AcquireAck) -> MarkHoldConsumedCommand {
        let mut sorted = ack.artifacts.clone();
        sorted.sort_by_key(|item| item.slot);
        MarkHoldConsumedCommand {
            consume_request_id: ack.consume_request_id,
            request_id: ack.request_id,
            repository_id: self.repository_id,
            tenant_id: self.tenant_id,
            hold_ids: sorted.into_iter().map(|h| h.hold_id).collect(),
        }
    }
}

/// Untrusted serializable DTO mirroring a committed PG `artifact_holds` reservation.
/// Must be verified against PG into an opaque `VerifiedGlobalHoldReservation` before use.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GlobalHoldReservationDto {
    pub binding: BridgeBinding,
    pub ack: AcquireAck,
    pub replayed: bool,
    pub recovered_from_unknown_commit: bool,
}

impl GlobalHoldReservationDto {
    pub fn hold_ids(&self) -> Vec<Uuid> {
        let mut sorted = self.ack.artifacts.clone();
        sorted.sort_by_key(|item| item.slot);
        sorted.into_iter().map(|item| item.hold_id).collect()
    }

    pub fn matches_binding(&self, expected: &BridgeBinding) -> Result<(), RetentionBridgeError> {
        if &self.binding != expected {
            return Err(RetentionBridgeError::RealmMismatch("reservation_binding"));
        }
        expected.matches_acquire_ack(&self.ack)
    }
}

/// Bounded inputs for deterministic snapshot-pin + retention-root publication.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeRootRegistrationPlan {
    pub pin_request_id: Uuid,
    pub snapshot_id: Uuid,
    pub pin_id: Uuid,
    pub pin_purpose: MetadataPinPurpose,
    pub lease_ticks: u64,
    pub pin_logical_tick: u64,
    pub pack_digests: Vec<String>,
    pub pin_request_digest: String,
    pub root_request_id: Uuid,
    pub root_id: Uuid,
    pub root_purpose: String,
    pub business_intent_digest: String,
    pub selector_kind: String,
    pub selector_digest: String,
    pub refs_digest: String,
    pub pack_set_digest: String,
    pub register_digest: String,
    pub root_request_digest: String,
}

impl BridgeRootRegistrationPlan {
    pub fn validate(&self) -> Result<(), RetentionBridgeError> {
        let ids = [self.pin_request_id, self.snapshot_id, self.pin_id, self.root_request_id, self.root_id];
        if ids.iter().any(Uuid::is_nil) {
            return Err(RetentionBridgeError::InvalidBinding("pin/root ids must be non-nil".into()));
        }
        RootPurpose::parse(&self.root_purpose).map_err(|e| RetentionBridgeError::InvalidBinding(e.to_string()))?;
        RootSelectorKind::parse(&self.selector_kind)
            .map_err(|e| RetentionBridgeError::InvalidBinding(e.to_string()))?;
        for hex in [
            &self.pin_request_digest,
            &self.business_intent_digest,
            &self.selector_digest,
            &self.refs_digest,
            &self.pack_set_digest,
            &self.register_digest,
            &self.root_request_digest,
        ] {
            RequestDigest::from_str(hex)?;
        }
        Ok(())
    }
}
