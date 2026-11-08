//! Immutable acquire ACK and consume receipts of the global hold ledger (A3).
//!
//! Both values are plain immutable receipts. Replaying an acquire request or
//! querying a consume request returns these bytes only: there is no grant, no
//! consumed token, no reconstructed write intent and no IO. The ledger stores
//! the canonical JSON body, so a replay is byte-identical and a tampered body
//! can never be replayed as a valid old ACK.
//!
//! Every receipt persists the physical Blob backend identity hex recorded at
//! acquire time. That hex is a non-secret claim: it can be compared with an
//! actually opened store and with the hold rows, but it can never be turned
//! back into an upload capability.
//!
//! The stable consume request id is allocated by the *first* acquire, stored in
//! the immutable ACK (and its immutable request row) and reused by the consume
//! call. A caller can read it through [`AcquireAck::consume_request_id`] before
//! the grant is moved, so a `COMMIT` whose acknowledgement was lost is
//! resolvable without any new random id.
//!
//! `Debug` is written by hand for the three persisted value types: it prints
//! ids, bounded enums and counts only, never a provider path/namespace, attempt
//! id, digest or credential-derived value.
use super::contract::{ArtifactHoldError, ArtifactHoldPurpose, HoldScope, MAX_RECEIPT_BODY_BYTES, ShardId};
use super::request::canonical_push;
use crate::blob_store::{BlobLocator, UploadIntent};
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::types::GitObjectFormat;
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

/// Full physical identity of one held artifact. Every field takes part in the
/// locator path or in the physical backend binding, so a restart can
/// reconstruct a *read-only* [`BlobLocator`] for verification but can never
/// recover write authority from stored metadata.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct HoldArtifactIdentity {
    pub provider: String,
    /// Canonical hex of the physical backend identity of the store that minted
    /// the attempt (provider + endpoint + bucket/container + root + region +
    /// stable account identity). Non-secret, still not a capability.
    pub backend_identity: String,
    pub tenant_id: Uuid,
    pub authority_id: Uuid,
    pub authority_generation: i64,
    pub attempt_id: Uuid,
    pub namespace: String,
    pub sha256: String,
    pub length: u64,
}

impl HoldArtifactIdentity {
    pub(super) fn from_locator(provider: &str, backend_identity: &str, locator: &BlobLocator) -> Self {
        Self {
            provider: provider.to_owned(),
            backend_identity: backend_identity.to_owned(),
            tenant_id: locator.tenant_id(),
            authority_id: locator.authority_id(),
            authority_generation: locator.generation(),
            attempt_id: locator.attempt_id(),
            namespace: locator.namespace().to_owned(),
            sha256: locator.sha256().to_owned(),
            length: locator.length(),
        }
    }

    /// Derive the recorded physical identity from a privately owned intent. The
    /// provider name is supplied by the trusted caller because an intent
    /// exposes only its locator and backend identity, never a provider string.
    pub(super) fn from_intent(provider: &str, intent: &UploadIntent) -> Self {
        Self::from_locator(provider, intent.backend_identity().as_hex(), intent.locator())
    }

    /// Read-only reconstruction. A locator is not an upload capability.
    pub fn locator(&self) -> Result<BlobLocator, ArtifactHoldError> {
        BlobLocator::new(
            self.tenant_id,
            self.authority_id,
            self.authority_generation,
            self.attempt_id,
            &self.namespace,
            &self.sha256,
            self.length,
        )
        .map_err(|error| ArtifactHoldError::Database(format!("stored hold locator is invalid: {error}")))
    }
}

impl fmt::Debug for HoldArtifactIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Ids and the declared length are safe; the provider path (namespace),
        // attempt address, content digest and backend digest are not printed.
        formatter
            .debug_struct("HoldArtifactIdentity")
            .field("provider", &self.provider)
            .field("tenant_id", &self.tenant_id)
            .field("authority_id", &self.authority_id)
            .field("authority_generation", &self.authority_generation)
            .field("length", &self.length)
            .field("backend_identity", &"<redacted>")
            .field("attempt_id", &"<redacted>")
            .field("namespace", &"<redacted>")
            .field("sha256", &"<redacted>")
            .finish()
    }
}

/// One immutable hold ACK inside an acquire receipt.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HoldAck {
    pub hold_id: Uuid,
    pub slot: i32,
    pub artifact: HoldArtifactIdentity,
    pub declared_bytes: i64,
    pub logical_bytes: i64,
}

impl HoldAck {
    pub(super) fn new(
        hold_id: Uuid,
        slot: i32,
        artifact: HoldArtifactIdentity,
        declared_bytes: i64,
        logical_bytes: i64,
    ) -> Self {
        Self { hold_id, slot, artifact, declared_bytes, logical_bytes }
    }
}

/// Immutable ACK of one all-or-none acquire. It is the only replay answer for a
/// stable global request id.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct AcquireAck {
    pub request_id: Uuid,
    pub request_digest: String,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub purpose: ArtifactHoldPurpose,
    pub object_format: GitObjectFormat,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
    pub group_epoch: i64,
    pub issuer_id: Uuid,
    pub lane: String,
    pub sequence: i64,
    pub operation_id: Uuid,
    pub operation_digest: String,
    pub gate_revision: i64,
    pub gate_digest: String,
    pub shard: i32,
    /// Physical backend identity hex the holds were admitted against.
    pub backend_identity: String,
    /// Stable consume id allocated by this acquire and reused by consume.
    pub consume_request_id: Uuid,
    pub artifacts: Vec<HoldAck>,
    pub declared_bytes: i64,
    pub logical_bytes: i64,
}

impl AcquireAck {
    pub fn encode(&self) -> Result<String, ArtifactHoldError> {
        let body = serde_json::to_string(self)
            .map_err(|error| ArtifactHoldError::Database(format!("artifact hold ACK encoding failed: {error}")))?;
        if body.len() > MAX_RECEIPT_BODY_BYTES {
            return Err(ArtifactHoldError::ReceiptTooLarge { bytes: body.len(), max: MAX_RECEIPT_BODY_BYTES });
        }
        Ok(body)
    }

    pub fn decode(body: &str) -> Result<Self, ArtifactHoldError> {
        if body.is_empty() || body.len() > MAX_RECEIPT_BODY_BYTES {
            return Err(ArtifactHoldError::LedgerIntegrity("stored artifact hold ACK body is not bounded"));
        }
        serde_json::from_str(body)
            .map_err(|_| ArtifactHoldError::LedgerIntegrity("stored artifact hold ACK is not valid canonical JSON"))
    }

    pub fn artifact_count(&self) -> usize {
        self.artifacts.len()
    }

    pub fn holds(&self) -> &[HoldAck] {
        &self.artifacts
    }

    pub fn hold(&self, hold_id: Uuid) -> Option<&HoldAck> {
        self.artifacts.iter().find(|hold| hold.hold_id == hold_id)
    }

    /// Stable consume request id. It is allocated by the first acquire, so a
    /// caller can query an unknown consume `COMMIT` even after the grant value
    /// (and its intents) has been dropped.
    pub fn consume_request_id(&self) -> Uuid {
        self.consume_request_id
    }

    /// Physical backend identity hex recorded by this ACK.
    pub fn backend_identity_hex(&self) -> &str {
        &self.backend_identity
    }

    pub fn shard_id(&self) -> Result<ShardId, ArtifactHoldError> {
        ShardId::parse(self.shard)
    }

    pub fn request_digest_value(&self) -> Result<RequestDigest, ArtifactHoldError> {
        self.request_digest
            .parse()
            .map_err(|_| ArtifactHoldError::LedgerIntegrity("stored ACK request digest is not sha256 hex"))
    }

    /// A stored ACK must describe exactly the trusted scope of the query. This
    /// is the *immutable* scope check: it never reads the current core gate.
    pub fn ensure_scope(&self, scope: &HoldScope) -> Result<(), ArtifactHoldError> {
        if self.repository_id != scope.repository_id() || self.tenant_id != scope.tenant_id() {
            return Err(ArtifactHoldError::ScopeMismatch("request repository/tenant"));
        }
        if self.owner_id != scope.owner_id() {
            return Err(ArtifactHoldError::ScopeMismatch("request owner"));
        }
        if self.purpose != scope.purpose() {
            return Err(ArtifactHoldError::ScopeMismatch("request purpose"));
        }
        if self.object_format != scope.object_format() {
            return Err(ArtifactHoldError::ScopeMismatch("request object format"));
        }
        if self.history_incarnation != scope.history_incarnation() {
            return Err(ArtifactHoldError::ScopeMismatch("request history incarnation"));
        }
        if self.authority_epoch != scope.authority_epoch() {
            return Err(ArtifactHoldError::ScopeMismatch("request authority epoch"));
        }
        if self.group_epoch != scope.group_epoch() {
            return Err(ArtifactHoldError::ScopeMismatch("request group epoch"));
        }
        Ok(())
    }

    /// The decoded body must describe one bounded, internally consistent batch:
    /// distinct hold ids, distinct stable slots, a non-nil stable consume id and
    /// a 64-hex backend identity. Anything else is durable corruption.
    pub fn ensure_batch_shape(&self) -> Result<(), ArtifactHoldError> {
        if self.artifacts.is_empty() || self.artifacts.len() > super::contract::MAX_BATCH_ARTIFACTS {
            return Err(ArtifactHoldError::LedgerIntegrity("stored ACK batch is not bounded"));
        }
        if self.consume_request_id.is_nil() {
            return Err(ArtifactHoldError::LedgerIntegrity("stored ACK has no stable consume id"));
        }
        if self.backend_identity.len() != 64 || !is_lower_hex(&self.backend_identity) {
            return Err(ArtifactHoldError::LedgerIntegrity("stored ACK backend identity is not sha256 hex"));
        }
        for (index, hold) in self.artifacts.iter().enumerate() {
            if i32::try_from(index).ok() != Some(hold.slot) {
                return Err(ArtifactHoldError::LedgerIntegrity("stored ACK slots are not the canonical 0..n range"));
            }
            if hold.artifact.backend_identity != self.backend_identity {
                return Err(ArtifactHoldError::LedgerIntegrity("stored ACK hold backend differs from the request"));
            }
            if self.artifacts[..index].iter().any(|earlier| earlier.hold_id == hold.hold_id) {
                return Err(ArtifactHoldError::LedgerIntegrity("stored ACK repeats a hold id"));
            }
        }
        Ok(())
    }

    /// Canonical digest of one consume call over this ACK and its stable consume
    /// request id. It covers the exact granted hold/slot/locator/backend set, so
    /// a forged or reused consume id can never describe a different set.
    pub fn consume_digest(&self) -> RequestDigest {
        let mut fields = Vec::new();
        canonical_push(&mut fields, b"consume");
        canonical_push(&mut fields, self.consume_request_id.as_bytes());
        canonical_push(&mut fields, self.request_id.as_bytes());
        canonical_push(&mut fields, self.request_digest.as_bytes());
        canonical_push(&mut fields, self.repository_id.as_bytes());
        canonical_push(&mut fields, self.tenant_id.as_bytes());
        canonical_push(&mut fields, self.owner_id.as_bytes());
        canonical_push(&mut fields, self.purpose.as_str().as_bytes());
        canonical_push(&mut fields, self.object_format.as_str().as_bytes());
        canonical_push(&mut fields, self.history_incarnation.as_bytes());
        canonical_push(&mut fields, &self.authority_epoch.to_be_bytes());
        canonical_push(&mut fields, &self.group_epoch.to_be_bytes());
        canonical_push(&mut fields, self.issuer_id.as_bytes());
        canonical_push(&mut fields, self.lane.as_bytes());
        canonical_push(&mut fields, &self.sequence.to_be_bytes());
        canonical_push(&mut fields, self.operation_id.as_bytes());
        canonical_push(&mut fields, self.operation_digest.as_bytes());
        canonical_push(&mut fields, &self.gate_revision.to_be_bytes());
        canonical_push(&mut fields, self.gate_digest.as_bytes());
        canonical_push(&mut fields, &self.shard.to_be_bytes());
        canonical_push(&mut fields, self.backend_identity.as_bytes());
        canonical_push(&mut fields, &(self.artifacts.len() as u64).to_be_bytes());
        for hold in &self.artifacts {
            canonical_push(&mut fields, hold.hold_id.as_bytes());
            canonical_push(&mut fields, &hold.slot.to_be_bytes());
            canonical_push(&mut fields, hold.artifact.provider.as_bytes());
            canonical_push(&mut fields, hold.artifact.backend_identity.as_bytes());
            canonical_push(&mut fields, hold.artifact.tenant_id.as_bytes());
            canonical_push(&mut fields, hold.artifact.authority_id.as_bytes());
            canonical_push(&mut fields, &hold.artifact.authority_generation.to_be_bytes());
            canonical_push(&mut fields, hold.artifact.attempt_id.as_bytes());
            canonical_push(&mut fields, hold.artifact.namespace.as_bytes());
            canonical_push(&mut fields, hold.artifact.sha256.as_bytes());
            canonical_push(&mut fields, &hold.artifact.length.to_be_bytes());
            canonical_push(&mut fields, &hold.declared_bytes.to_be_bytes());
            canonical_push(&mut fields, &hold.logical_bytes.to_be_bytes());
        }
        RequestDigest::of("artifact-hold-consume-v1", &[&fields])
    }
}

impl fmt::Debug for AcquireAck {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Ids, bounded enums and counts only: no digest, lane path, attempt,
        // namespace or backend correlator is printed.
        formatter
            .debug_struct("AcquireAck")
            .field("request_id", &self.request_id)
            .field("consume_request_id", &self.consume_request_id)
            .field("repository_id", &self.repository_id)
            .field("tenant_id", &self.tenant_id)
            .field("owner_id", &self.owner_id)
            .field("purpose", &self.purpose)
            .field("object_format", &self.object_format)
            .field("operation_id", &self.operation_id)
            .field("gate_revision", &self.gate_revision)
            .field("shard", &self.shard)
            .field("artifacts", &self.artifacts.len())
            .field("declared_bytes", &self.declared_bytes)
            .field("logical_bytes", &self.logical_bytes)
            .finish()
    }
}

/// Immutable one-shot consume receipt for exactly one hold/slot.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct ConsumeAck {
    pub consume_request_id: Uuid,
    pub request_id: Uuid,
    pub consume_digest: String,
    pub hold_id: Uuid,
    pub slot: i32,
    pub repository_id: Uuid,
    pub tenant_id: Uuid,
    pub owner_id: Uuid,
    pub purpose: ArtifactHoldPurpose,
    pub object_format: GitObjectFormat,
    pub history_incarnation: Uuid,
    pub authority_epoch: i64,
    pub group_epoch: i64,
    pub issuer_id: Uuid,
    pub lane: String,
    pub sequence: i64,
    pub operation_id: Uuid,
    pub operation_digest: String,
    pub gate_revision: i64,
    pub gate_digest: String,
    pub consumed_at_unix_micros: i64,
    pub artifact: HoldArtifactIdentity,
}

impl ConsumeAck {
    /// Build the receipt for one hold of a consumed ACK. Scope, owner, purpose,
    /// format, history/epochs, parent operation, gate proof and backend are
    /// copied from the immutable acquire ACK so the two can never disagree.
    pub(super) fn new(ack: &AcquireAck, hold: &HoldAck, consumed_at_unix_micros: i64) -> Self {
        Self {
            consume_request_id: ack.consume_request_id,
            request_id: ack.request_id,
            consume_digest: ack.consume_digest().as_hex(),
            hold_id: hold.hold_id,
            slot: hold.slot,
            repository_id: ack.repository_id,
            tenant_id: ack.tenant_id,
            owner_id: ack.owner_id,
            purpose: ack.purpose,
            object_format: ack.object_format,
            history_incarnation: ack.history_incarnation,
            authority_epoch: ack.authority_epoch,
            group_epoch: ack.group_epoch,
            issuer_id: ack.issuer_id,
            lane: ack.lane.clone(),
            sequence: ack.sequence,
            operation_id: ack.operation_id,
            operation_digest: ack.operation_digest.clone(),
            gate_revision: ack.gate_revision,
            gate_digest: ack.gate_digest.clone(),
            consumed_at_unix_micros,
            artifact: hold.artifact.clone(),
        }
    }

    pub fn encode(&self) -> Result<String, ArtifactHoldError> {
        let body = serde_json::to_string(self).map_err(|error| {
            ArtifactHoldError::Database(format!("artifact hold consume receipt encoding failed: {error}"))
        })?;
        if body.len() > MAX_RECEIPT_BODY_BYTES {
            return Err(ArtifactHoldError::ReceiptTooLarge { bytes: body.len(), max: MAX_RECEIPT_BODY_BYTES });
        }
        Ok(body)
    }

    pub fn decode(body: &str) -> Result<Self, ArtifactHoldError> {
        if body.is_empty() || body.len() > MAX_RECEIPT_BODY_BYTES {
            return Err(ArtifactHoldError::LedgerIntegrity("stored consume receipt body is not bounded"));
        }
        serde_json::from_str(body)
            .map_err(|_| ArtifactHoldError::LedgerIntegrity("stored consume receipt is not valid canonical JSON"))
    }

    /// Immutable scope check of a historical receipt: it compares the trusted
    /// caller scope, never the current core gate.
    pub fn ensure_scope(&self, scope: &HoldScope) -> Result<(), ArtifactHoldError> {
        if self.repository_id != scope.repository_id() || self.tenant_id != scope.tenant_id() {
            return Err(ArtifactHoldError::ScopeMismatch("consume receipt repository/tenant"));
        }
        if self.owner_id != scope.owner_id() {
            return Err(ArtifactHoldError::ScopeMismatch("consume receipt owner"));
        }
        if self.purpose != scope.purpose() {
            return Err(ArtifactHoldError::ScopeMismatch("consume receipt purpose"));
        }
        if self.object_format != scope.object_format() {
            return Err(ArtifactHoldError::ScopeMismatch("consume receipt object format"));
        }
        if self.history_incarnation != scope.history_incarnation() {
            return Err(ArtifactHoldError::ScopeMismatch("consume receipt history incarnation"));
        }
        if self.authority_epoch != scope.authority_epoch() {
            return Err(ArtifactHoldError::ScopeMismatch("consume receipt authority epoch"));
        }
        if self.group_epoch != scope.group_epoch() {
            return Err(ArtifactHoldError::ScopeMismatch("consume receipt group epoch"));
        }
        Ok(())
    }

    /// A historical receipt must agree, field by field, with the immutable
    /// acquire ACK it belongs to and with the exact granted hold.
    pub fn ensure_acquire_ack(&self, ack: &AcquireAck) -> Result<(), ArtifactHoldError> {
        if self.consume_request_id != ack.consume_request_id
            || self.request_id != ack.request_id
            || self.consume_digest != ack.consume_digest().as_hex()
        {
            return Err(ArtifactHoldError::LedgerIntegrity("consume receipt identity differs from its acquire ACK"));
        }
        let scope_matches = self.repository_id == ack.repository_id
            && self.tenant_id == ack.tenant_id
            && self.owner_id == ack.owner_id
            && self.purpose == ack.purpose
            && self.object_format == ack.object_format
            && self.history_incarnation == ack.history_incarnation
            && self.authority_epoch == ack.authority_epoch
            && self.group_epoch == ack.group_epoch;
        if !scope_matches {
            return Err(ArtifactHoldError::LedgerIntegrity("consume receipt scope differs from its acquire ACK"));
        }
        if self.issuer_id != ack.issuer_id
            || self.lane != ack.lane
            || self.sequence != ack.sequence
            || self.operation_id != ack.operation_id
            || self.operation_digest != ack.operation_digest
        {
            return Err(ArtifactHoldError::LedgerIntegrity(
                "consume receipt parent operation differs from its acquire ACK",
            ));
        }
        if self.gate_revision != ack.gate_revision || self.gate_digest != ack.gate_digest {
            return Err(ArtifactHoldError::LedgerIntegrity("consume receipt gate proof differs from its acquire ACK"));
        }
        let hold = ack
            .hold(self.hold_id)
            .ok_or(ArtifactHoldError::LedgerIntegrity("consume receipt names a hold outside its acquire ACK"))?;
        if hold.slot != self.slot || hold.artifact != self.artifact {
            return Err(ArtifactHoldError::LedgerIntegrity(
                "consume receipt hold identity differs from its acquire ACK",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for ConsumeAck {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConsumeAck")
            .field("consume_request_id", &self.consume_request_id)
            .field("request_id", &self.request_id)
            .field("hold_id", &self.hold_id)
            .field("slot", &self.slot)
            .field("repository_id", &self.repository_id)
            .field("tenant_id", &self.tenant_id)
            .field("operation_id", &self.operation_id)
            .field("gate_revision", &self.gate_revision)
            .field("consumed_at_unix_micros", &self.consumed_at_unix_micros)
            .finish()
    }
}

/// Canonical lowercase sha256 hex, the only form the ledger stores.
pub(super) fn is_lower_hex(value: &str) -> bool {
    value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Receipt-only resolution of an unknown acquire COMMIT. `Unknown` is never an
/// abort and never a grant.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcquireLookup {
    Found(AcquireAck),
    Unknown,
}

/// Receipt-only resolution of an unknown consume COMMIT. It never returns a
/// consumed token or any upload capability.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ConsumeLookup {
    Found(Vec<ConsumeAck>),
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    const BACKEND: &str = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";

    fn identity() -> HoldArtifactIdentity {
        HoldArtifactIdentity {
            provider: "s3".into(),
            backend_identity: BACKEND.into(),
            tenant_id: Uuid::new_v4(),
            authority_id: Uuid::new_v4(),
            authority_generation: 2,
            attempt_id: Uuid::new_v4(),
            namespace: "packs".into(),
            sha256: "a".repeat(64),
            length: 4096,
        }
    }

    fn ack() -> AcquireAck {
        AcquireAck {
            request_id: Uuid::new_v4(),
            request_digest: "b".repeat(64),
            repository_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            owner_id: Uuid::new_v4(),
            purpose: ArtifactHoldPurpose::RefPublication,
            object_format: GitObjectFormat::Sha1,
            history_incarnation: Uuid::new_v4(),
            authority_epoch: 1,
            group_epoch: 2,
            issuer_id: Uuid::new_v4(),
            lane: "pipeline:refs".into(),
            sequence: 9,
            operation_id: Uuid::new_v4(),
            operation_digest: "c".repeat(64),
            gate_revision: 5,
            gate_digest: "d".repeat(64),
            shard: 7,
            backend_identity: BACKEND.into(),
            consume_request_id: Uuid::new_v4(),
            artifacts: vec![HoldAck::new(Uuid::new_v4(), 0, identity(), 4096, 900)],
            declared_bytes: 4096,
            logical_bytes: 900,
        }
    }

    fn scope(ack: &AcquireAck) -> HoldScope {
        HoldScope::new(
            ack.repository_id,
            ack.tenant_id,
            ack.owner_id,
            ack.purpose,
            ack.object_format,
            ack.history_incarnation,
            ack.authority_epoch,
            ack.group_epoch,
        )
        .unwrap()
    }

    #[test]
    fn ack_round_trips_and_locator_is_read_only() {
        let ack = ack();
        let body = ack.encode().unwrap();
        let decoded = AcquireAck::decode(&body).unwrap();
        assert_eq!(decoded, ack);
        assert!(decoded.ensure_batch_shape().is_ok());
        let locator = decoded.holds()[0].artifact.locator().unwrap();
        assert_eq!(locator.sha256(), "a".repeat(64));
        assert_eq!(locator.length(), 4096);
        assert!(decoded.ensure_scope(&scope(&decoded)).is_ok());
        assert!(decoded.request_digest_value().is_ok());
        assert_eq!(decoded.consume_request_id(), decoded.consume_request_id);
        assert_eq!(decoded.backend_identity_hex(), BACKEND);
    }

    #[test]
    fn consume_digest_covers_the_granted_set_and_the_stable_id() {
        let ack = ack();
        let digest = ack.consume_digest();
        let mut moved_id = ack.clone();
        moved_id.consume_request_id = Uuid::new_v4();
        assert_ne!(digest, moved_id.consume_digest());
        let mut moved_slot = ack.clone();
        moved_slot.artifacts[0].slot = 1;
        assert_ne!(digest, moved_slot.consume_digest());
        let mut moved_backend = ack;
        moved_backend.artifacts[0].artifact.backend_identity = "f".repeat(64);
        assert_ne!(digest, moved_backend.consume_digest());
    }

    #[test]
    fn batch_shape_rejects_partial_or_reordered_acks() {
        let ack = ack();
        let mut no_id = ack.clone();
        no_id.consume_request_id = Uuid::nil();
        assert!(matches!(no_id.ensure_batch_shape(), Err(ArtifactHoldError::LedgerIntegrity(_))));
        let mut gapped = ack.clone();
        gapped.artifacts[0].slot = 1;
        assert!(matches!(gapped.ensure_batch_shape(), Err(ArtifactHoldError::LedgerIntegrity(_))));
        let mut mismatched_backend = ack.clone();
        mismatched_backend.artifacts[0].artifact.backend_identity = "f".repeat(64);
        assert!(matches!(mismatched_backend.ensure_batch_shape(), Err(ArtifactHoldError::LedgerIntegrity(_))));
        let mut duplicate = ack;
        duplicate.artifacts.push(HoldAck::new(duplicate.artifacts[0].hold_id, 1, identity(), 1, 1));
        assert!(matches!(duplicate.ensure_batch_shape(), Err(ArtifactHoldError::LedgerIntegrity(_))));
    }

    #[test]
    fn consume_receipt_round_trips_and_agrees_with_its_ack() {
        let ack = ack();
        let hold = &ack.artifacts[0];
        let receipt = ConsumeAck::new(&ack, hold, 1_700_000_000_000_000);
        let body = receipt.encode().unwrap();
        assert_eq!(ConsumeAck::decode(&body).unwrap(), receipt);
        assert!(receipt.ensure_scope(&scope(&ack)).is_ok());
        assert!(receipt.ensure_acquire_ack(&ack).is_ok());
        let mut tampered = receipt.clone();
        tampered.operation_digest = "0".repeat(64);
        assert!(matches!(tampered.ensure_acquire_ack(&ack), Err(ArtifactHoldError::LedgerIntegrity(_))));
        let mut foreign_hold = receipt;
        foreign_hold.hold_id = Uuid::new_v4();
        assert!(matches!(foreign_hold.ensure_acquire_ack(&ack), Err(ArtifactHoldError::LedgerIntegrity(_))));
    }

    #[test]
    fn persisted_receipts_do_not_print_paths_attempts_or_digests() {
        let ack = ack();
        let receipt = ConsumeAck::new(&ack, &ack.artifacts[0], 7);
        let attempt = ack.artifacts[0].artifact.attempt_id.to_string();
        for rendered in [format!("{ack:?}"), format!("{:?}", ack.artifacts[0]), format!("{receipt:?}")] {
            assert!(!rendered.contains(&"a".repeat(64)), "content digest leaked: {rendered}");
            assert!(!rendered.contains(BACKEND), "backend digest leaked: {rendered}");
            assert!(!rendered.contains(&attempt), "attempt id leaked: {rendered}");
            assert!(!rendered.contains("packs"), "provider path leaked: {rendered}");
            assert!(!rendered.contains(&"b".repeat(64)), "request digest leaked: {rendered}");
            assert!(!rendered.contains(&"d".repeat(64)), "gate digest leaked: {rendered}");
        }
    }
}
