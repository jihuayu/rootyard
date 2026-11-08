//! Bounded A5a requests, read handles and their canonical digests.
//!
//! Every id is chosen by the caller before the first call, so a retry of the same
//! logical operation is an exact replay of the same request id/digest instead of
//! a second snapshot or lease. None of these values is a capability: a
//! `PackSnapshotRef` names a stored snapshot/pin, it does not prove ownership,
//! current authority or Blob/Git availability.
use super::super::contract::CoreGate;
use super::super::snapshot_contract::{MetadataSnapshotScope, validate_lease, validate_mutation_ids};
use super::contract::CREATE_REQUEST_DIGEST_DOMAIN;
use crate::ref_store::contract::{RefStoreError, RequestDigest};
use uuid::Uuid;

/// The exact gate proof a fresh pack snapshot must be captured at.
///
/// The expectation is always implicitly `pack_verified`: there is no way for a
/// caller to ask for a metadata-only snapshot through this API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackSnapshotExpectation {
    gate_revision: i64,
    gate_digest: RequestDigest,
}

impl PackSnapshotExpectation {
    pub fn new(gate_revision: i64, gate_digest: RequestDigest) -> Result<Self, RefStoreError> {
        if gate_revision <= 0 {
            return Err(RefStoreError::InvalidIdentity("expected pack snapshot gate revision must be positive".into()));
        }
        Ok(Self { gate_revision, gate_digest })
    }

    pub fn gate_revision(&self) -> i64 {
        self.gate_revision
    }
    pub fn gate_digest(&self) -> &RequestDigest {
        &self.gate_digest
    }

    /// A stale expectation is a typed mismatch under the gate lock, never a
    /// silent capture at the newer revision.
    pub(super) fn check(&self, gate: &CoreGate) -> Result<(), RefStoreError> {
        if gate.revision() != self.gate_revision || gate.digest() != &self.gate_digest {
            return Err(RefStoreError::MetadataGateVersionMismatch);
        }
        Ok(())
    }
}

/// Create one complete registered-pack-membership snapshot plus its durable pin,
/// creation receipt and permanent history row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreatePackSnapshotRequest {
    scope: MetadataSnapshotScope,
    request_id: Uuid,
    pin_id: Uuid,
    snapshot_id: Uuid,
    lease_seconds: i64,
    expected: PackSnapshotExpectation,
}

impl CreatePackSnapshotRequest {
    pub fn new(
        scope: MetadataSnapshotScope,
        request_id: Uuid,
        pin_id: Uuid,
        snapshot_id: Uuid,
        lease_seconds: i64,
        expected: PackSnapshotExpectation,
    ) -> Result<Self, RefStoreError> {
        let request = Self { scope, request_id, pin_id, snapshot_id, lease_seconds, expected };
        request.validate()?;
        Ok(request)
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
    pub fn expected(&self) -> &PackSnapshotExpectation {
        &self.expected
    }

    /// Canonical digest over every semantic field and the always-implicit
    /// `pack_verified` mode.
    pub fn digest(&self) -> RequestDigest {
        RequestDigest::of(
            CREATE_REQUEST_DIGEST_DOMAIN,
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
                &self.expected.gate_revision.to_be_bytes(),
                self.expected.gate_digest.as_bytes(),
                super::contract::PACK_MODE_VERIFIED.as_bytes(),
            ],
        )
    }
}

/// Read handle for one retained pack snapshot.
///
/// It intentionally carries **no owner/purpose/format/epochs** and no caller
/// authority: the stored snapshot header supplies the trusted historical scope,
/// and the read path compares it with the current gate realm. A caller therefore
/// cannot widen or re-own a historical snapshot by naming it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackSnapshotRef {
    repository_id: Uuid,
    tenant_id: Uuid,
    snapshot_id: Uuid,
    pin_id: Uuid,
    expected_generation: i64,
}

impl PackSnapshotRef {
    pub fn new(
        repository_id: Uuid,
        tenant_id: Uuid,
        snapshot_id: Uuid,
        pin_id: Uuid,
        expected_generation: i64,
    ) -> Result<Self, RefStoreError> {
        let reference = Self { repository_id, tenant_id, snapshot_id, pin_id, expected_generation };
        reference.validate()?;
        Ok(reference)
    }

    pub fn validate(&self) -> Result<(), RefStoreError> {
        if self.repository_id.is_nil() || self.tenant_id.is_nil() || self.snapshot_id.is_nil() {
            return Err(RefStoreError::InvalidIdentity(
                "pack snapshot reference repository, tenant and snapshot ids must be non-nil".into(),
            ));
        }
        if self.pin_id.is_nil() {
            return Err(RefStoreError::InvalidIdentity("pack snapshot reference pin id must be non-nil".into()));
        }
        if self.expected_generation <= 0 {
            return Err(RefStoreError::InvalidIdentity(
                "pack snapshot reference expects a positive pin generation".into(),
            ));
        }
        Ok(())
    }

    pub fn repository_id(&self) -> Uuid {
        self.repository_id
    }
    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }
    pub fn snapshot_id(&self) -> Uuid {
        self.snapshot_id
    }
    pub fn pin_id(&self) -> Uuid {
        self.pin_id
    }
    pub fn expected_generation(&self) -> i64 {
        self.expected_generation
    }
}

/// Full historical receipt lookup by global request id.
///
/// It names the whole trusted `MetadataSnapshotScope` the caller expects
/// (repository, tenant, snapshot producer owner, purpose, object format,
/// history incarnation and both gate epochs) plus the request id. The lookup
/// validates the *stored* scope and needs no current gate/authority, so it
/// resolves an unknown `COMMIT` and stays answerable after the repository was
/// deleted. A different repository/tenant/owner/purpose/format/epoch is a typed
/// scope/identity refusal rather than the old body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PackSnapshotReceiptQuery {
    scope: MetadataSnapshotScope,
    request_id: Uuid,
}

impl PackSnapshotReceiptQuery {
    pub fn new(scope: MetadataSnapshotScope, request_id: Uuid) -> Result<Self, RefStoreError> {
        if request_id.is_nil() {
            return Err(RefStoreError::InvalidIdentity("pack snapshot request id must be non-nil".into()));
        }
        Ok(Self { scope, request_id })
    }

    pub fn scope(&self) -> &MetadataSnapshotScope {
        &self.scope
    }
    pub fn request_id(&self) -> Uuid {
        self.request_id
    }
}
