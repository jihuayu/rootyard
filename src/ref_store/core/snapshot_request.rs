//! Bounded metadata snapshot/pin requests and their canonical digests (A2).
//!
//! Each request is fixed before the first call: the caller chooses the pin,
//! snapshot and request ids and the lease, so a retry is an exact replay rather
//! than a new mutation. Canonical digests cover every semantic field and the
//! action, which is what makes one request-id space safe for
//! create/renew/release.
use super::super::contract::{MetadataPinPurpose, RefStoreError, RequestDigest};
use super::snapshot_contract::{
    MAX_SNAPSHOT_PAGE, MetadataSnapshotCursor, MetadataSnapshotScope, RefPrefix, validate_lease, validate_mutation_ids,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Create an immutable metadata snapshot header plus its durable pin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateMetadataSnapshotRequest {
    scope: MetadataSnapshotScope,
    request_id: Uuid,
    pin_id: Uuid,
    snapshot_id: Uuid,
    lease_seconds: i64,
    expected_gate_digest: RequestDigest,
}

impl CreateMetadataSnapshotRequest {
    pub fn new(
        scope: MetadataSnapshotScope,
        request_id: Uuid,
        pin_id: Uuid,
        snapshot_id: Uuid,
        lease_seconds: i64,
        expected_gate_digest: RequestDigest,
    ) -> Result<Self, RefStoreError> {
        validate_mutation_ids(request_id, pin_id, snapshot_id)?;
        if snapshot_id == pin_id {
            return Err(RefStoreError::InvalidIdentity("snapshot and pin ids must differ".into()));
        }
        validate_lease(lease_seconds)?;
        Ok(Self { scope, request_id, pin_id, snapshot_id, lease_seconds, expected_gate_digest })
    }

    pub fn validate(&self) -> Result<(), RefStoreError> {
        validate_mutation_ids(self.request_id, self.pin_id, self.snapshot_id)?;
        if self.snapshot_id == self.pin_id {
            return Err(RefStoreError::InvalidIdentity("snapshot and pin ids must differ".into()));
        }
        validate_lease(self.lease_seconds)
    }

    pub fn scope(&self) -> &MetadataSnapshotScope {
        &self.scope
    }
    pub fn purpose(&self) -> MetadataPinPurpose {
        self.scope.purpose()
    }
    pub fn request_id(&self) -> Uuid {
        self.request_id
    }
    pub fn pin_id(&self) -> Uuid {
        self.pin_id
    }
    pub fn snapshot_id(&self) -> Uuid {
        self.snapshot_id
    }
    pub fn lease_seconds(&self) -> i64 {
        self.lease_seconds
    }
    pub fn expected_gate_digest(&self) -> &RequestDigest {
        &self.expected_gate_digest
    }

    pub fn digest(&self) -> RequestDigest {
        RequestDigest::of(
            "metadata-snapshot-create-v1",
            &[
                self.scope.repository_id().as_bytes(),
                self.scope.tenant_id().as_bytes(),
                self.scope.owner_id().as_bytes(),
                self.scope.purpose().as_str().as_bytes(),
                self.scope.object_format().as_str().as_bytes(),
                self.scope.history_incarnation().as_bytes(),
                &self.scope.authority_epoch().to_be_bytes(),
                &self.scope.group_epoch().to_be_bytes(),
                self.request_id.as_bytes(),
                self.pin_id.as_bytes(),
                self.snapshot_id.as_bytes(),
                &self.lease_seconds.to_be_bytes(),
                self.expected_gate_digest.as_bytes(),
            ],
        )
    }
}

/// Read one bounded page of immutable snapshot refs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadMetadataSnapshotPageRequest {
    scope: MetadataSnapshotScope,
    snapshot_id: Uuid,
    pin_id: Uuid,
    pin_generation: i64,
    prefix: Option<RefPrefix>,
    cursor: Option<MetadataSnapshotCursor>,
    limit: u32,
}

impl ReadMetadataSnapshotPageRequest {
    pub fn new(
        scope: MetadataSnapshotScope,
        snapshot_id: Uuid,
        pin_id: Uuid,
        pin_generation: i64,
        prefix: Option<RefPrefix>,
        cursor: Option<MetadataSnapshotCursor>,
        limit: u32,
    ) -> Result<Self, RefStoreError> {
        let request = Self { scope, snapshot_id, pin_id, pin_generation, prefix, cursor, limit };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), RefStoreError> {
        if self.snapshot_id.is_nil() || self.pin_id.is_nil() {
            return Err(RefStoreError::InvalidIdentity("snapshot and pin ids must be non-nil".into()));
        }
        if self.pin_generation <= 0 {
            return Err(RefStoreError::InvalidIdentity("pin generation must be positive".into()));
        }
        if self.limit == 0 || self.limit > MAX_SNAPSHOT_PAGE {
            return Err(RefStoreError::InvalidIdentity(format!("page limit must be 1..={MAX_SNAPSHOT_PAGE}")));
        }
        if let Some(cursor) = &self.cursor
            && !cursor.binds(&self.scope, self.snapshot_id, self.pin_id, self.pin_generation, self.prefix.as_ref())
        {
            return Err(RefStoreError::MetadataCursorScopeMismatch);
        }
        Ok(())
    }

    pub fn scope(&self) -> &MetadataSnapshotScope {
        &self.scope
    }
    pub fn snapshot_id(&self) -> Uuid {
        self.snapshot_id
    }
    pub fn pin_id(&self) -> Uuid {
        self.pin_id
    }
    pub fn pin_generation(&self) -> i64 {
        self.pin_generation
    }
    pub fn prefix(&self) -> Option<&RefPrefix> {
        self.prefix.as_ref()
    }
    pub fn cursor(&self) -> Option<&MetadataSnapshotCursor> {
        self.cursor.as_ref()
    }
    pub fn limit(&self) -> u32 {
        self.limit
    }
}

/// Extend a live lease and advance the pin generation by exactly one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenewMetadataPinRequest {
    scope: MetadataSnapshotScope,
    request_id: Uuid,
    pin_id: Uuid,
    expected_generation: i64,
    lease_seconds: i64,
}

impl RenewMetadataPinRequest {
    pub fn new(
        scope: MetadataSnapshotScope,
        request_id: Uuid,
        pin_id: Uuid,
        expected_generation: i64,
        lease_seconds: i64,
    ) -> Result<Self, RefStoreError> {
        let request = Self { scope, request_id, pin_id, expected_generation, lease_seconds };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), RefStoreError> {
        if self.request_id.is_nil() || self.pin_id.is_nil() {
            return Err(RefStoreError::InvalidIdentity("metadata request and pin ids must be non-nil".into()));
        }
        if self.expected_generation <= 0 {
            return Err(RefStoreError::InvalidIdentity("expected pin generation must be positive".into()));
        }
        validate_lease(self.lease_seconds)
    }

    pub fn scope(&self) -> &MetadataSnapshotScope {
        &self.scope
    }
    pub fn request_id(&self) -> Uuid {
        self.request_id
    }
    pub fn pin_id(&self) -> Uuid {
        self.pin_id
    }
    pub fn expected_generation(&self) -> i64 {
        self.expected_generation
    }
    pub fn lease_seconds(&self) -> i64 {
        self.lease_seconds
    }

    pub fn digest(&self) -> RequestDigest {
        RequestDigest::of(
            "metadata-pin-renew-v1",
            &[
                self.scope.repository_id().as_bytes(),
                self.scope.tenant_id().as_bytes(),
                self.scope.owner_id().as_bytes(),
                self.scope.purpose().as_str().as_bytes(),
                self.scope.object_format().as_str().as_bytes(),
                self.scope.history_incarnation().as_bytes(),
                &self.scope.authority_epoch().to_be_bytes(),
                &self.scope.group_epoch().to_be_bytes(),
                self.request_id.as_bytes(),
                self.pin_id.as_bytes(),
                &self.expected_generation.to_be_bytes(),
                &self.lease_seconds.to_be_bytes(),
            ],
        )
    }
}

/// Bounded reason recorded on the single terminal release of a pin.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PinReleaseReason {
    ClientDone,
    Superseded,
    LeaseAbandoned,
    MaintenanceComplete,
    OperatorRequest,
}

impl PinReleaseReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClientDone => "client_done",
            Self::Superseded => "superseded",
            Self::LeaseAbandoned => "lease_abandoned",
            Self::MaintenanceComplete => "maintenance_complete",
            Self::OperatorRequest => "operator_request",
        }
    }

    pub fn parse(value: &str) -> Result<Self, RefStoreError> {
        match value {
            "client_done" => Ok(Self::ClientDone),
            "superseded" => Ok(Self::Superseded),
            "lease_abandoned" => Ok(Self::LeaseAbandoned),
            "maintenance_complete" => Ok(Self::MaintenanceComplete),
            "operator_request" => Ok(Self::OperatorRequest),
            _ => Err(RefStoreError::Database("stored metadata pin release reason is not a bounded enum value".into())),
        }
    }
}

/// Exactly release the pin at the expected generation, even after expiry or a
/// repository transition. It can never end a newer renewed pin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseMetadataPinRequest {
    scope: MetadataSnapshotScope,
    request_id: Uuid,
    pin_id: Uuid,
    expected_generation: i64,
    reason: PinReleaseReason,
}

impl ReleaseMetadataPinRequest {
    pub fn new(
        scope: MetadataSnapshotScope,
        request_id: Uuid,
        pin_id: Uuid,
        expected_generation: i64,
        reason: PinReleaseReason,
    ) -> Result<Self, RefStoreError> {
        let request = Self { scope, request_id, pin_id, expected_generation, reason };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), RefStoreError> {
        if self.request_id.is_nil() || self.pin_id.is_nil() {
            return Err(RefStoreError::InvalidIdentity("metadata request and pin ids must be non-nil".into()));
        }
        if self.expected_generation <= 0 {
            return Err(RefStoreError::InvalidIdentity("expected pin generation must be positive".into()));
        }
        Ok(())
    }

    pub fn scope(&self) -> &MetadataSnapshotScope {
        &self.scope
    }
    pub fn request_id(&self) -> Uuid {
        self.request_id
    }
    pub fn pin_id(&self) -> Uuid {
        self.pin_id
    }
    pub fn expected_generation(&self) -> i64 {
        self.expected_generation
    }
    pub fn reason(&self) -> PinReleaseReason {
        self.reason
    }

    pub fn digest(&self) -> RequestDigest {
        RequestDigest::of(
            "metadata-pin-release-v1",
            &[
                self.scope.repository_id().as_bytes(),
                self.scope.tenant_id().as_bytes(),
                self.scope.owner_id().as_bytes(),
                self.scope.purpose().as_str().as_bytes(),
                self.scope.object_format().as_str().as_bytes(),
                self.scope.history_incarnation().as_bytes(),
                &self.scope.authority_epoch().to_be_bytes(),
                &self.scope.group_epoch().to_be_bytes(),
                self.request_id.as_bytes(),
                self.pin_id.as_bytes(),
                &self.expected_generation.to_be_bytes(),
                self.reason.as_str().as_bytes(),
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::types::GitObjectFormat;
    use super::*;

    fn scope() -> MetadataSnapshotScope {
        MetadataSnapshotScope::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            MetadataPinPurpose::Verification,
            GitObjectFormat::Sha1,
            Uuid::new_v4(),
            1,
            1,
        )
        .unwrap()
    }

    #[test]
    fn digests_cover_action_ids_and_lease() {
        let scope = scope();
        let (request, pin, snapshot) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let gate = RequestDigest::of("gate", &[b"one"]);
        let create = CreateMetadataSnapshotRequest::new(scope, request, pin, snapshot, 60, gate).unwrap();
        assert_eq!(
            create.digest(),
            CreateMetadataSnapshotRequest::new(scope, request, pin, snapshot, 60, gate).unwrap().digest()
        );
        let renew = RenewMetadataPinRequest::new(scope, request, pin, 1, 60).unwrap();
        let release = ReleaseMetadataPinRequest::new(scope, request, pin, 1, PinReleaseReason::ClientDone).unwrap();
        assert_ne!(create.digest(), renew.digest());
        assert_ne!(renew.digest(), release.digest());
        assert_ne!(renew.digest(), RenewMetadataPinRequest::new(scope, request, pin, 1, 61).unwrap().digest());
        assert_ne!(renew.digest(), RenewMetadataPinRequest::new(scope, request, pin, 2, 60).unwrap().digest());
    }

    #[test]
    fn requests_are_bounded() {
        let scope = scope();
        let gate = RequestDigest::of("gate", &[]);
        let (request, pin, snapshot) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        assert!(CreateMetadataSnapshotRequest::new(scope, Uuid::nil(), pin, snapshot, 60, gate).is_err());
        assert!(CreateMetadataSnapshotRequest::new(scope, request, pin, pin, 60, gate).is_err());
        assert!(CreateMetadataSnapshotRequest::new(scope, request, pin, snapshot, 0, gate).is_err());
        assert!(CreateMetadataSnapshotRequest::new(scope, request, pin, snapshot, 3601, gate).is_err());
        assert!(ReadMetadataSnapshotPageRequest::new(scope, snapshot, pin, 1, None, None, 0).is_err());
        assert!(ReadMetadataSnapshotPageRequest::new(scope, snapshot, pin, 1, None, None, 257).is_err());
        assert!(ReadMetadataSnapshotPageRequest::new(scope, snapshot, pin, 1, None, None, 256).is_ok());
        assert!(RenewMetadataPinRequest::new(scope, request, pin, 0, 60).is_err());
        assert!(ReleaseMetadataPinRequest::new(scope, request, pin, 0, PinReleaseReason::ClientDone).is_err());
    }
}
