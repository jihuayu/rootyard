//! Typed Ref-CAS operation identity and terminal-result contract.
//!
//! This is deliberately an *operation registry* boundary, not a second ref
//! authority. Publication of refs still happens in the existing Pando PG CAS;
//! the adapter in `pg.rs` records identity, replay/conflict state and a durable
//! cancellation tombstone in that same transaction. Read snapshots, durable
//! pins, roots, holds, decisions and GC integration are **not** implemented
//! here (see [`Capabilities`]); callers must not treat the presence of this
//! module as authority to switch ref publication or garbage collection.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, str::FromStr};
use uuid::Uuid;

const MAX_LANE_BYTES: usize = 64;
const MAX_TERMINAL_RESULT_BYTES: usize = 64 * 1024;

/// SHA-256 over a canonical, length-delimited request description.
///
/// Callers must include every input that changes the intended mutation. The
/// domain prefix prevents a digest from one operation class being interpreted
/// as another. Reusing an operation id with a different digest is a conflict,
/// never a replay.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RequestDigest([u8; 32]);

impl RequestDigest {
    pub fn of(domain: &str, fields: &[&[u8]]) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"rootyard-ref-store-request-v1\0");
        hash.update((domain.len() as u64).to_be_bytes());
        hash.update(domain.as_bytes());
        for field in fields {
            hash.update((field.len() as u64).to_be_bytes());
            hash.update(field);
        }
        Self(hash.finalize().into())
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Display for RequestDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.as_hex())
    }
}

impl FromStr for RequestDigest {
    type Err = RefStoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
            return Err(RefStoreError::InvalidIdentity("request digest must be lowercase sha256 hex".into()));
        }
        let decoded = hex::decode(value).map_err(|_| RefStoreError::InvalidIdentity("invalid request digest hex".into()))?;
        let bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|_| RefStoreError::InvalidIdentity("invalid request digest length".into()))?;
        Ok(Self(bytes))
    }
}

/// A bounded, issuer-owned sequence lane. Uniqueness is scoped by repository,
/// issuer and lane; the operation id is globally unique inside a repository.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IssuerLane(String);

impl IssuerLane {
    pub fn new(value: impl Into<String>) -> Result<Self, RefStoreError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > MAX_LANE_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
        {
            return Err(RefStoreError::InvalidIdentity(
                "issuer lane must be 1..=64 ASCII alphanumeric, '.', '_', ':' or '-'".into(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IssuerLane {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for IssuerLane {
    type Err = RefStoreError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}
/// Strongly typed identity of one mutation attempt.
///
/// `issuer_id` names the durable issuing component (for the current Pando
/// bridge, the authenticated actor), `lane`/`sequence` provide per-issuer
/// ordering, and `operation_id` is the stable replay key. A retry is a replay
/// only when all of these plus `digest` are identical.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationIdentity {
    repository_id: Uuid,
    issuer_id: Uuid,
    lane: IssuerLane,
    sequence: i64,
    operation_id: Uuid,
    digest: RequestDigest,
}

impl OperationIdentity {
    pub fn new(
        repository_id: Uuid,
        issuer_id: Uuid,
        lane: IssuerLane,
        sequence: i64,
        operation_id: Uuid,
        digest: RequestDigest,
    ) -> Result<Self, RefStoreError> {
        if repository_id.is_nil() || issuer_id.is_nil() || operation_id.is_nil() {
            return Err(RefStoreError::InvalidIdentity("repository, issuer and operation ids must be non-nil".into()));
        }
        if sequence <= 0 {
            return Err(RefStoreError::InvalidIdentity("issuer sequence must be positive".into()));
        }
        Ok(Self { repository_id, issuer_id, lane, sequence, operation_id, digest })
    }

    pub fn repository_id(&self) -> Uuid {
        self.repository_id
    }

    pub fn issuer_id(&self) -> Uuid {
        self.issuer_id
    }

    pub fn lane(&self) -> &IssuerLane {
        &self.lane
    }

    pub fn sequence(&self) -> i64 {
        self.sequence
    }

    pub fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    pub fn digest(&self) -> &RequestDigest {
        &self.digest
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    /// Registered but not yet terminal. A timeout or lost reply leaves this
    /// state; it must never be reported as aborted.
    Pending,
    Committed,
    Rejected,
    Cancelled,
}

impl OperationState {
    pub fn is_terminal(self) -> bool {
        self != Self::Pending
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Committed => "committed",
            Self::Rejected => "rejected",
            Self::Cancelled => "cancelled",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending" => Some(Self::Pending),
            "committed" => Some(Self::Committed),
            "rejected" => Some(Self::Rejected),
            "cancelled" => Some(Self::Cancelled),
            _ => None,
        }
    }
}

/// Only a completed CAS may record `Committed` or `Rejected`; cancellation is
/// recorded by the adapter cancel operation so a late commit cannot convert it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalOutcome {
    Committed,
    Rejected,
}

impl TerminalOutcome {
    pub fn state(self) -> OperationState {
        match self {
            Self::Committed => OperationState::Committed,
            Self::Rejected => OperationState::Rejected,
        }
    }
}

/// Small immutable JSON result (per-ref decisions, commit token and evidence).
/// It is persisted once and replayed byte-for-byte as JSON; a terminal record
/// can never be rewritten with a different result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalResult(serde_json::Value);

impl TerminalResult {
    pub fn json(value: serde_json::Value) -> Result<Self, RefStoreError> {
        if !value.is_object() {
            return Err(RefStoreError::InvalidIdentity("terminal result must be a JSON object".into()));
        }
        let encoded = serde_json::to_vec(&value)
            .map_err(|_| RefStoreError::InvalidIdentity("terminal result is not serializable".into()))?;
        if encoded.len() > MAX_TERMINAL_RESULT_BYTES {
            return Err(RefStoreError::InvalidIdentity("terminal result exceeds 64 KiB".into()));
        }
        Ok(Self(value))
    }

    pub fn value(&self) -> &serde_json::Value {
        &self.0
    }

    pub(crate) fn from_stored(value: serde_json::Value) -> Self {
        Self(value)
    }
}
/// Durable observation of one operation. `Pending` is an *unknown* outcome,
/// not an abort: callers must query again or cancel, never blindly replay refs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationRecord {
    identity: OperationIdentity,
    state: OperationState,
    terminal_result: Option<TerminalResult>,
}

impl OperationRecord {
    pub(crate) fn new(
        identity: OperationIdentity,
        state: OperationState,
        terminal_result: Option<TerminalResult>,
    ) -> Result<Self, RefStoreError> {
        if state.is_terminal() != terminal_result.is_some() {
            return Err(RefStoreError::InvalidIdentity("terminal state/result mismatch".into()));
        }
        Ok(Self { identity, state, terminal_result })
    }

    pub fn identity(&self) -> &OperationIdentity {
        &self.identity
    }

    pub fn state(&self) -> OperationState {
        self.state
    }

    pub fn terminal_result(&self) -> Option<&TerminalResult> {
        self.terminal_result.as_ref()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BeginReceipt {
    pub record: OperationRecord,
    /// False on an identical replay; true when this transaction inserted the
    /// pending record (or the cancel-before-register tombstone won the race).
    pub created: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CancelReceipt {
    /// `None` when no operation had been registered yet. The persistent
    /// tombstone still makes every later registration for this identity
    /// cancelled.
    pub record: Option<OperationRecord>,
    pub tombstone_created: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitReceipt {
    pub record: OperationRecord,
    /// True when an identical terminal result was already durable.
    pub replayed: bool,
}

/// `Unknown` must not be collapsed into an aborted/failed result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OperationLookup {
    Known(OperationRecord),
    Unknown,
}

/// Explicit feature gates for this transitional PostgreSQL adapter.
///
/// Capabilities marked false are not merely "not enabled by configuration":
/// they have no safe implementation here. In particular there is no atomic
/// read snapshot + durable pin and no GC consumer for such a pin, so existing
/// long PG read leases remain the read protection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capabilities {
    pub stable_operation_identity: bool,
    pub request_digest_replay: bool,
    pub digest_conflict_detection: bool,
    pub cancel_before_register: bool,
    pub immutable_terminal_result: bool,
    /// Internal, repository-scoped lookup only; there is no public HTTP route.
    pub internal_operation_lookup: bool,
    /// Existing Pando publish preallocates a server identity before mutation,
    /// but does not accept a caller-retry operation id. Therefore a retried
    /// client request is a new operation and receives no cross-request
    /// idempotency from this increment.
    pub client_idempotent_publish: bool,
    pub atomic_read_snapshot: bool,
    pub durable_snapshot_pin: bool,
    pub gc_observes_pins: bool,
    pub publication_decisions: bool,
    pub logical_roots: bool,
    pub artifact_holds: bool,
    pub authority_epoch_checks: bool,
    pub automatic_dedup_trimming: bool,
}

impl Capabilities {
    pub const fn pg_transition_increment() -> Self {
        Self {
            stable_operation_identity: true,
            request_digest_replay: true,
            digest_conflict_detection: true,
            cancel_before_register: true,
            immutable_terminal_result: true,
            internal_operation_lookup: true,
            client_idempotent_publish: false,
            atomic_read_snapshot: false,
            durable_snapshot_pin: false,
            gc_observes_pins: false,
            publication_decisions: false,
            logical_roots: false,
            artifact_holds: false,
            authority_epoch_checks: false,
            automatic_dedup_trimming: false,
        }
    }
}
/// A sequence durably reserved in an issuer lane before mutation. The caller
/// chooses the operation UUID before reservation, the reservation acquires the
/// same common operation lock as begin/cancel, and [`SequenceReservation::identity`]
/// can only use that bound UUID. Reservation alone is not an operation and
/// cannot be replayed as one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SequenceReservation {
    repository_id: Uuid,
    issuer_id: Uuid,
    lane: IssuerLane,
    sequence: i64,
    operation_id: Uuid,
}

impl SequenceReservation {
    pub(crate) fn new(
        repository_id: Uuid,
        issuer_id: Uuid,
        lane: IssuerLane,
        sequence: i64,
        operation_id: Uuid,
    ) -> Self {
        Self { repository_id, issuer_id, lane, sequence, operation_id }
    }

    pub fn sequence(&self) -> i64 {
        self.sequence
    }

    pub fn operation_id(&self) -> Uuid {
        self.operation_id
    }

    pub fn identity(&self, digest: RequestDigest) -> Result<OperationIdentity, RefStoreError> {
        OperationIdentity::new(
            self.repository_id,
            self.issuer_id,
            self.lane.clone(),
            self.sequence,
            self.operation_id,
            digest,
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RefStoreError {
    InvalidIdentity(String),
    RepositoryNotFound,
    /// Same operation/lane identity, different request digest.
    DigestConflict,
    /// Same operation id or lane sequence bound to different identity fields.
    IdentityConflict,
    /// A cancellation tombstone exists for this lane sequence with a different
    /// operation id or digest.
    CancellationConflict,
    /// A durable cancellation won; no mutation may be recorded under it.
    Cancelled { operation_id: Uuid },
    /// `record_terminal` requires a previously registered operation.
    UnknownOperation { operation_id: Uuid },
    /// A terminal operation/result is immutable and cannot be changed.
    TerminalImmutable,
    Unsupported(&'static str),
    Timeout,
    Database(String),
}

impl RefStoreError {
    pub fn is_conflict(&self) -> bool {
        matches!(
            self,
            Self::DigestConflict | Self::IdentityConflict | Self::CancellationConflict | Self::TerminalImmutable
        )
    }
}

impl fmt::Display for RefStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentity(reason) => write!(formatter, "invalid ref-store identity: {reason}"),
            Self::RepositoryNotFound => formatter.write_str("ref-store repository not found"),
            Self::DigestConflict => formatter.write_str("operation id was reused with a different request digest"),
            Self::IdentityConflict => formatter.write_str("operation identity fields conflict with a durable record"),
            Self::CancellationConflict => formatter.write_str("cancellation tombstone conflicts with operation identity"),
            Self::Cancelled { operation_id } => write!(formatter, "operation {operation_id} was cancelled"),
            Self::UnknownOperation { operation_id } => write!(formatter, "operation {operation_id} is not registered"),
            Self::TerminalImmutable => formatter.write_str("terminal operation result is immutable"),
            Self::Unsupported(capability) => write!(formatter, "ref-store capability is unsupported: {capability}"),
            Self::Timeout => formatter.write_str("ref-store transaction deadline expired"),
            Self::Database(message) => write!(formatter, "ref-store database error: {message}"),
        }
    }
}

impl std::error::Error for RefStoreError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest() -> RequestDigest {
        RequestDigest::from_bytes([7; 32])
    }

    fn lane() -> IssuerLane {
        IssuerLane::new("issuer:lane-1").unwrap()
    }

    fn identity(digest: RequestDigest) -> OperationIdentity {
        OperationIdentity::new(Uuid::new_v4(), Uuid::new_v4(), lane(), 1, Uuid::new_v4(), digest).unwrap()
    }

    #[test]
    fn identity_rejects_nil_and_nonpositive_sequences() {
        let nil = Uuid::nil();
        assert!(OperationIdentity::new(nil, Uuid::new_v4(), lane(), 1, Uuid::new_v4(), digest()).is_err());
        assert!(OperationIdentity::new(Uuid::new_v4(), nil, lane(), 1, Uuid::new_v4(), digest()).is_err());
        assert!(OperationIdentity::new(Uuid::new_v4(), Uuid::new_v4(), lane(), 1, nil, digest()).is_err());
        assert!(OperationIdentity::new(Uuid::new_v4(), Uuid::new_v4(), lane(), 0, Uuid::new_v4(), digest()).is_err());
        assert!(OperationIdentity::new(Uuid::new_v4(), Uuid::new_v4(), lane(), -1, Uuid::new_v4(), digest()).is_err());
    }

    #[test]
    fn lanes_are_bounded_and_ascii_only() {
        assert!(IssuerLane::new("").is_err());
        assert!(IssuerLane::new("x".repeat(65)).is_err());
        assert!(IssuerLane::new("bad lane").is_err());
        assert!(IssuerLane::new("bad/lane").is_err());
        assert!(IssuerLane::new("bad\nlane").is_err());
        assert!(IssuerLane::new("A-z.0_9:").is_ok());
    }

    #[test]
    fn digest_is_length_delimited_and_round_trips() {
        let one = RequestDigest::of("domain", &[b"ab", b"c"]);
        let two = RequestDigest::of("domain", &[b"a", b"bc"]);
        assert_ne!(one, two);
        assert_ne!(RequestDigest::of("a", &[b"x"]), RequestDigest::of("b", &[b"x"]));
        assert_eq!(one.as_hex().parse::<RequestDigest>().unwrap(), one);
        assert!("00".parse::<RequestDigest>().is_err());
        assert!("0".repeat(64).to_uppercase().parse::<RequestDigest>().is_err());
    }

    #[test]
    fn terminal_result_is_bounded_object_only() {
        assert!(TerminalResult::json(serde_json::json!({"ok": true})).is_ok());
        assert!(TerminalResult::json(serde_json::json!([1, 2])).is_err());
        assert!(TerminalResult::json(serde_json::json!({"body": "x".repeat(MAX_TERMINAL_RESULT_BYTES)})).is_err());
    }

    #[test]
    fn record_requires_terminal_result_exactly_for_terminal_states() {
        let identity = identity(digest());
        assert!(OperationRecord::new(identity.clone(), OperationState::Pending, None).is_ok());
        assert!(
            OperationRecord::new(
                identity.clone(),
                OperationState::Committed,
                Some(TerminalResult::json(serde_json::json!({"state": "committed"})).unwrap())
            )
            .is_ok()
        );
        assert!(OperationRecord::new(identity.clone(), OperationState::Pending, Some(
            TerminalResult::json(serde_json::json!({})).unwrap()
        ))
        .is_err());
        assert!(OperationRecord::new(identity, OperationState::Cancelled, None).is_err());
    }

    #[test]
    fn sequence_reservation_binds_the_prechosen_operation_uuid() {
        let repository = Uuid::new_v4();
        let issuer = Uuid::new_v4();
        let operation = Uuid::new_v4();
        let reservation = SequenceReservation::new(repository, issuer, lane(), 3, operation);
        assert_eq!(reservation.operation_id(), operation);
        let identity = reservation.identity(digest()).unwrap();
        assert_eq!(identity.operation_id(), operation);
        assert_eq!(identity.repository_id(), repository);
        assert_eq!(identity.issuer_id(), issuer);
        assert_eq!(identity.sequence(), 3);
    }

    #[test]
    fn new_authority_capabilities_are_explicitly_disabled() {
        let capabilities = Capabilities::pg_transition_increment();
        assert!(capabilities.stable_operation_identity);
        assert!(capabilities.cancel_before_register);
        assert!(!capabilities.client_idempotent_publish);
        assert!(!capabilities.atomic_read_snapshot);
        assert!(!capabilities.durable_snapshot_pin);
        assert!(!capabilities.gc_observes_pins);
        assert!(!capabilities.publication_decisions);
        assert!(!capabilities.logical_roots);
        assert!(!capabilities.artifact_holds);
        assert!(!capabilities.authority_epoch_checks);
        assert!(!capabilities.automatic_dedup_trimming);
    }
}
