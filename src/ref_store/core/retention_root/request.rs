//! Bounded root mutation requests and their canonical digests.
//!
//! `prepare`, `register` and `release` are three separate, explicitly bounded calls. `prepare` seals the source
//! read and the exact selectors outside every write transaction; `register` moves that sealed candidate by
//! value and never re-derives it from caller input; `release` is a standalone one-way fence.
//!
//! Every id and digest is chosen by the caller before the first call, so a retry of the same logical mutation is
//! an exact replay of the same request id/digest instead of a second capture. None of these values is a
//! capability: a `RootCandidate` is only obtainable from [`super::PgRetentionRoots::prepare`].
use super::candidate::RootCandidate;
use super::error::RootError;
use super::scope::RootsScope;
use super::selector::RootSelector;
use crate::ref_store::contract::{RefStoreError, RequestDigest};
use crate::ref_store::core::pack_snapshot::PackSnapshotRef;
use std::str::FromStr;
use uuid::Uuid;

/// Canonical domain of the whole-request digest bound by a root receipt.
pub const PREPARE_DIGEST_DOMAIN: &str = "core-root-prepare-v1";
/// Canonical domain of the release intent digest stored in the tombstone/head receipt.
pub const RELEASE_DIGEST_DOMAIN: &str = "core-root-release-v1";
/// Canonical domain of the receipted register request digest.
pub const REGISTER_REQUEST_DIGEST_DOMAIN: &str = "core-root-register-request-v1";

/// Phase 1: seal one existing durable pack snapshot as a root capture.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrepareRootRequest {
    scope: RootsScope,
    reference: PackSnapshotRef,
    root_id: Uuid,
    operation_id: Uuid,
    selector: RootSelector,
    request_id: Uuid,
}

impl PrepareRootRequest {
    pub fn new(
        scope: RootsScope,
        reference: PackSnapshotRef,
        root_id: Uuid,
        operation_id: Uuid,
        selector: RootSelector,
        request_id: Uuid,
    ) -> Result<Self, RootError> {
        let request = Self { scope, reference, root_id, operation_id, selector, request_id };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> Result<(), RootError> {
        self.reference.validate()?;
        if self.root_id.is_nil() || self.operation_id.is_nil() || self.request_id.is_nil() {
            return Err(RootError::Store(RefStoreError::InvalidIdentity(
                "root, operation and request ids must be non-nil".into(),
            )));
        }
        if self.reference.repository_id() != self.scope.repository_id()
            || self.reference.tenant_id() != self.scope.tenant_id()
        {
            return Err(RootError::RootRealmMismatch("prepare reference repository/tenant"));
        }
        if let RootSelector::ObjectIds(values) = &self.selector
            && values.is_empty()
        {
            return Err(RootError::RootSelectorInvalid("a root needs at least one object id".into()));
        }
        Ok(())
    }

    pub fn scope(&self) -> &RootsScope {
        &self.scope
    }
    pub fn reference(&self) -> &PackSnapshotRef {
        &self.reference
    }
    pub fn root_id(&self) -> Uuid {
        self.root_id
    }
    pub fn operation_id(&self) -> Uuid {
        self.operation_id
    }
    pub fn selector(&self) -> &RootSelector {
        &self.selector
    }
    pub fn request_id(&self) -> Uuid {
        self.request_id
    }

    /// Canonical digest of the prepare intent (scope, source reference, root/operation/request ids, selector).
    pub fn digest(&self) -> RequestDigest {
        let mut fields: Vec<Vec<u8>> = vec![
            self.scope.repository_id().as_bytes().to_vec(),
            self.scope.tenant_id().as_bytes().to_vec(),
            self.scope.owner_id().as_bytes().to_vec(),
            self.scope.purpose().as_str().as_bytes().to_vec(),
            self.scope.business_intent_digest().as_bytes().to_vec(),
            self.scope.object_format().as_str().as_bytes().to_vec(),
            self.scope.history_incarnation().as_bytes().to_vec(),
            self.scope.authority_epoch().to_be_bytes().to_vec(),
            self.scope.group_epoch().to_be_bytes().to_vec(),
            self.reference.snapshot_id().as_bytes().to_vec(),
            self.reference.pin_id().as_bytes().to_vec(),
            self.reference.expected_generation().to_be_bytes().to_vec(),
            self.root_id.as_bytes().to_vec(),
            self.operation_id.as_bytes().to_vec(),
            self.request_id.as_bytes().to_vec(),
            self.selector.kind().as_str().as_bytes().to_vec(),
        ];
        if let RootSelector::ObjectIds(values) = &self.selector {
            for value in values {
                fields.push(value.as_bytes().to_vec());
            }
        }
        let parts = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
        RequestDigest::of(PREPARE_DIGEST_DOMAIN, &parts)
    }
}

/// Phase 2: commit the sealed candidate as an immutable, non-expiring root.
pub struct RegisterRootRequest {
    candidate: RootCandidate,
    request_id: Uuid,
}

impl RegisterRootRequest {
    pub fn new(candidate: RootCandidate, request_id: Uuid) -> Result<Self, RootError> {
        if request_id.is_nil() {
            return Err(RootError::Store(RefStoreError::InvalidIdentity(
                "root register request id must be non-nil".into(),
            )));
        }
        Ok(Self { candidate, request_id })
    }

    pub fn candidate(&self) -> &RootCandidate {
        &self.candidate
    }
    pub fn request_id(&self) -> Uuid {
        self.request_id
    }

    pub(super) fn into_parts(self) -> (RootCandidate, Uuid) {
        (self.candidate, self.request_id)
    }

    /// Whole-request digest: the sealed candidate register digest plus the receipt request id.
    pub fn digest(&self) -> RequestDigest {
        RequestDigest::of(
            REGISTER_REQUEST_DIGEST_DOMAIN,
            &[self.candidate.register_digest().as_bytes(), self.request_id.as_bytes(), b"register"],
        )
    }
}

/// One-way release, valid before or after a capture exists.
pub struct ReleaseRootRequest {
    scope: RootsScope,
    root_id: Uuid,
    expected_generation: i64,
    request_id: Uuid,
    expected_register_digest: RequestDigest,
    release_digest: RequestDigest,
    reason: String,
}

impl ReleaseRootRequest {
    pub fn new(
        scope: RootsScope,
        root_id: Uuid,
        expected_generation: i64,
        request_id: Uuid,
        expected_register_digest: &str,
        release_digest: &str,
        reason: impl Into<String>,
    ) -> Result<Self, RootError> {
        let reason = reason.into();
        if root_id.is_nil() || request_id.is_nil() {
            return Err(RootError::Store(RefStoreError::InvalidIdentity(
                "root release root/request ids must be non-nil".into(),
            )));
        }
        if expected_generation != 1 {
            return Err(RootError::RootGenerationConflict { root_id, expected_generation, actual_generation: 1 });
        }
        if reason.is_empty() || reason.len() > 256 || reason.chars().any(char::is_control) {
            return Err(RootError::Store(RefStoreError::InvalidIdentity(
                "root release reason must be 1..=256 bytes without control characters".into(),
            )));
        }
        let expected_register_digest = RequestDigest::from_str(expected_register_digest)
            .map_err(|_| RootError::RootDigestConflict("release must bind the expected register digest"))?;
        let release_digest = RequestDigest::from_str(release_digest)
            .map_err(|_| RootError::RootDigestConflict("release digest must be lowercase sha256 hex"))?;
        Ok(Self { scope, root_id, expected_generation, request_id, expected_register_digest, release_digest, reason })
    }

    pub fn scope(&self) -> &RootsScope {
        &self.scope
    }
    pub fn root_id(&self) -> Uuid {
        self.root_id
    }
    pub fn expected_generation(&self) -> i64 {
        self.expected_generation
    }
    pub fn request_id(&self) -> Uuid {
        self.request_id
    }
    pub fn expected_register_digest(&self) -> RequestDigest {
        self.expected_register_digest
    }
    pub fn release_digest(&self) -> RequestDigest {
        self.release_digest
    }
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// Canonical release intent digest. It binds the full scope, root id, expected generation, the register
    /// digest being fenced and the caller's release digest, so the tombstone cannot be replayed for another root.
    pub fn intent_digest(&self) -> RequestDigest {
        RequestDigest::of(
            RELEASE_DIGEST_DOMAIN,
            &[
                self.scope.repository_id().as_bytes(),
                self.scope.tenant_id().as_bytes(),
                self.scope.owner_id().as_bytes(),
                self.scope.purpose().as_str().as_bytes(),
                self.scope.business_intent_digest().as_bytes(),
                self.scope.object_format().as_str().as_bytes(),
                self.scope.history_incarnation().as_bytes(),
                &self.scope.authority_epoch().to_be_bytes(),
                &self.scope.group_epoch().to_be_bytes(),
                self.root_id.as_bytes(),
                &self.expected_generation.to_be_bytes(),
                self.request_id.as_bytes(),
                self.expected_register_digest.as_bytes(),
                self.release_digest.as_bytes(),
                self.reason.as_bytes(),
            ],
        )
    }
}
