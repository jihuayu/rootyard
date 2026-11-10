//! Bounded acquire request and its stable semantic digest (A3).
//!
//! The trusted caller fixes the global request UUID, the exact parent
//! operation binding, the expected unserved core gate proof, the physical Blob
//! backend identity, the storage authority/generation and every artifact
//! specification *before* the first call. The fresh server attempt id/path is
//! minted later by the Blob byte layer and is deliberately not part of the
//! caller digest, so an exact retry is a replay while a genuinely new attempt
//! must use a new request id.
//!
//! The physical backend identity is typed ([`BlobBackendIdentity`]) rather than
//! a caller-supplied string: only an opened store can produce one, it is
//! non-secret, and it binds the request (and therefore the semantic digest, the
//! ACK and every hold) to provider + endpoint + bucket/container + root prefix
//! + region + stable account identity. The same provider with another bucket,
//!   root or account is a different identity, so it can never replay an old
//!   request id as if nothing had changed.
use super::contract::{ArtifactHoldError, ArtifactSpec, HoldScope, MAX_BATCH_ARTIFACTS};
use crate::blob_store::BlobBackendIdentity;
use crate::ref_store::contract::{OperationIdentity, RequestDigest};
use uuid::Uuid;

/// One all-or-none acquire of 1..=16 artifact holds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcquireArtifactHoldsRequest {
    scope: HoldScope,
    operation: OperationIdentity,
    request_id: Uuid,
    backend_identity: BlobBackendIdentity,
    authority_id: Uuid,
    authority_generation: i64,
    expected_gate_digest: RequestDigest,
    artifacts: Vec<ArtifactSpec>,
}

impl AcquireArtifactHoldsRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        scope: HoldScope,
        operation: OperationIdentity,
        request_id: Uuid,
        backend_identity: BlobBackendIdentity,
        authority_id: Uuid,
        authority_generation: i64,
        expected_gate_digest: RequestDigest,
        artifacts: Vec<ArtifactSpec>,
    ) -> Result<Self, ArtifactHoldError> {
        let request = Self {
            scope,
            operation,
            request_id,
            backend_identity,
            authority_id,
            authority_generation,
            expected_gate_digest,
            artifacts,
        };
        request.validate()?;
        Ok(request)
    }

    /// Bounded validation shared by construction and the adapter. The batch
    /// count cap is checked *before* any collect/digest work.
    pub fn validate(&self) -> Result<(), ArtifactHoldError> {
        if self.request_id.is_nil() {
            return Err(ArtifactHoldError::InvalidRequest("artifact hold request id must be non-nil".into()));
        }
        if self.authority_id.is_nil() {
            return Err(ArtifactHoldError::InvalidRequest("artifact hold storage authority id must be non-nil".into()));
        }
        if self.authority_generation <= 0 {
            return Err(ArtifactHoldError::InvalidRequest(
                "artifact hold storage authority generation must be positive".into(),
            ));
        }
        if self.artifacts.is_empty() {
            return Err(ArtifactHoldError::InvalidRequest(
                "artifact hold batch must contain at least one artifact".into(),
            ));
        }
        if self.artifacts.len() > MAX_BATCH_ARTIFACTS {
            return Err(ArtifactHoldError::BatchTooLarge { artifacts: self.artifacts.len(), max: MAX_BATCH_ARTIFACTS });
        }
        if self.operation.repository_id() != self.scope.repository_id() {
            return Err(ArtifactHoldError::InvalidRequest(
                "parent operation repository differs from the artifact hold scope".into(),
            ));
        }
        if self.operation.digest().as_bytes() == self.expected_gate_digest.as_bytes() {
            return Err(ArtifactHoldError::InvalidRequest(
                "parent operation digest and gate digest must be distinct proofs".into(),
            ));
        }
        if self.backend_identity.as_hex().len() != 64 {
            return Err(ArtifactHoldError::InvalidRequest(
                "artifact hold backend identity is not a canonical sha256 hex digest".into(),
            ));
        }
        // Checked declared-byte accumulation; never a wrapping/saturating sum.
        let mut declared: i64 = 0;
        for artifact in &self.artifacts {
            declared = declared.checked_add(artifact.declared_bytes()).ok_or_else(|| {
                ArtifactHoldError::InvalidRequest("artifact hold declared-byte total overflows i64".into())
            })?;
        }
        Ok(())
    }

    pub const fn scope(&self) -> &HoldScope {
        &self.scope
    }
    pub const fn operation(&self) -> &OperationIdentity {
        &self.operation
    }
    pub const fn request_id(&self) -> Uuid {
        self.request_id
    }
    /// Typed physical backend the caller believes it is uploading into. The
    /// adapter compares it with the actually opened store before any database
    /// work, and the ACK/hold rows persist its hex form.
    pub const fn backend_identity(&self) -> &BlobBackendIdentity {
        &self.backend_identity
    }
    pub const fn authority_id(&self) -> Uuid {
        self.authority_id
    }
    pub const fn authority_generation(&self) -> i64 {
        self.authority_generation
    }
    pub const fn expected_gate_digest(&self) -> &RequestDigest {
        &self.expected_gate_digest
    }
    pub fn artifacts(&self) -> &[ArtifactSpec] {
        &self.artifacts
    }
    pub fn artifact_count(&self) -> usize {
        self.artifacts.len()
    }

    /// Checked declared-byte total; callers must already have validated the
    /// batch, but this never assumes it.
    pub fn declared_bytes(&self) -> Result<i64, ArtifactHoldError> {
        let mut declared: i64 = 0;
        for artifact in &self.artifacts {
            declared = declared.checked_add(artifact.declared_bytes()).ok_or_else(|| {
                ArtifactHoldError::InvalidRequest("artifact hold declared-byte total overflows i64".into())
            })?;
        }
        Ok(declared)
    }

    /// Stable caller digest: a replay of this exact request value must produce
    /// the same bytes, while a new server attempt (random path) is not a new
    /// request. The physical backend identity is part of the digest, so the same
    /// global request id after a profile change (other endpoint, bucket, root,
    /// region or account) is a digest conflict, never an exact replay.
    pub fn digest(&self) -> RequestDigest {
        acquire_digest(
            self.request_id,
            &self.scope,
            &self.operation,
            self.backend_identity.as_hex(),
            self.authority_id,
            self.authority_generation,
            &self.expected_gate_digest,
            &self.artifacts,
        )
    }
}

/// Canonical length-delimited field encoding used by every request/receipt
/// digest. It is unambiguous even when two fields contain the same bytes.
pub(super) fn canonical_push(buffer: &mut Vec<u8>, value: &[u8]) {
    buffer.extend_from_slice(&(value.len() as u64).to_be_bytes());
    buffer.extend_from_slice(value);
}

/// Canonical semantic digest of one acquire request. It covers scope, owner,
/// purpose, parent operation binding, gate proof, physical backend identity,
/// storage authority/generation and every artifact specification, but never the
/// fresh server attempt id.
#[allow(clippy::too_many_arguments)]
pub(super) fn acquire_digest(
    request_id: Uuid,
    scope: &HoldScope,
    operation: &crate::ref_store::contract::OperationIdentity,
    backend_identity_hex: &str,
    authority_id: Uuid,
    authority_generation: i64,
    expected_gate_digest: &RequestDigest,
    artifacts: &[ArtifactSpec],
) -> RequestDigest {
    let mut fields = Vec::new();
    canonical_push(&mut fields, request_id.as_bytes());
    canonical_push(&mut fields, scope.repository_id().as_bytes());
    canonical_push(&mut fields, scope.tenant_id().as_bytes());
    canonical_push(&mut fields, scope.owner_id().as_bytes());
    canonical_push(&mut fields, scope.purpose().as_str().as_bytes());
    canonical_push(&mut fields, scope.object_format().as_str().as_bytes());
    canonical_push(&mut fields, scope.history_incarnation().as_bytes());
    canonical_push(&mut fields, &scope.authority_epoch().to_be_bytes());
    canonical_push(&mut fields, &scope.group_epoch().to_be_bytes());
    canonical_push(&mut fields, operation.repository_id().as_bytes());
    canonical_push(&mut fields, operation.issuer_id().as_bytes());
    canonical_push(&mut fields, operation.lane().as_str().as_bytes());
    canonical_push(&mut fields, &operation.sequence().to_be_bytes());
    canonical_push(&mut fields, operation.operation_id().as_bytes());
    canonical_push(&mut fields, operation.digest().as_hex().as_bytes());
    canonical_push(&mut fields, backend_identity_hex.as_bytes());
    canonical_push(&mut fields, authority_id.as_bytes());
    canonical_push(&mut fields, &authority_generation.to_be_bytes());
    canonical_push(&mut fields, expected_gate_digest.as_bytes());
    canonical_push(&mut fields, &(artifacts.len() as u64).to_be_bytes());
    for artifact in artifacts {
        canonical_push(&mut fields, artifact.namespace().as_bytes());
        canonical_push(&mut fields, artifact.sha256().as_bytes());
        canonical_push(&mut fields, &artifact.length().to_be_bytes());
    }
    RequestDigest::of("artifact-hold-acquire-v1", &[&fields])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ref_store::contract::IssuerLane;
    use crate::ref_store::core::types::GitObjectFormat;

    fn scope() -> HoldScope {
        HoldScope::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            crate::ref_store::core::artifact_hold::contract::ArtifactHoldPurpose::RefPublication,
            GitObjectFormat::Sha256,
            Uuid::new_v4(),
            2,
            3,
        )
        .unwrap()
    }

    fn operation(scope: &HoldScope) -> OperationIdentity {
        OperationIdentity::new(
            scope.repository_id(),
            scope.tenant_id(),
            IssuerLane::new("pipeline:refs").unwrap(),
            1,
            Uuid::new_v4(),
            RequestDigest::of("parent", &[b"digest"]),
        )
        .unwrap()
    }

    fn spec(namespace: &str) -> ArtifactSpec {
        ArtifactSpec::new(namespace, "a".repeat(64), 128).unwrap()
    }

    /// Standalone identity used only by these pure tests: both calls open a
    /// fresh in-process memory realm, so two calls are honestly different
    /// backends. A real request can only be built from an opened store.
    fn test_backend() -> BlobBackendIdentity {
        let limits = crate::blob_store::budget::ResourceLimits::new(1, 1, 1 << 20).expect("test limits");
        crate::blob_store::test_support::store(limits).0.backend_identity().clone()
    }

    #[test]
    fn batch_cap_is_exact_and_checked_before_digest() {
        let scope = scope();
        let operation = operation(&scope);
        let gate = RequestDigest::of("gate", &[b"g"]);
        let backend = test_backend();
        let sixteen = (0..16).map(|index| spec(&format!("ns-{index}"))).collect::<Vec<_>>();
        assert!(
            AcquireArtifactHoldsRequest::new(
                scope,
                operation.clone(),
                Uuid::new_v4(),
                backend.clone(),
                Uuid::new_v4(),
                1,
                gate,
                sixteen
            )
            .is_ok()
        );
        let seventeen = (0..17).map(|index| spec(&format!("ns-{index}"))).collect::<Vec<_>>();
        assert!(matches!(
            AcquireArtifactHoldsRequest::new(
                scope,
                operation,
                Uuid::new_v4(),
                backend,
                Uuid::new_v4(),
                1,
                gate,
                seventeen
            ),
            Err(ArtifactHoldError::BatchTooLarge { artifacts: 17, max: 16 })
        ));
    }

    #[test]
    fn digest_is_stable_across_equal_requests_and_covers_order_and_backend() {
        let scope = scope();
        let operation = operation(&scope);
        let gate = RequestDigest::of("gate", &[b"g"]);
        let request = Uuid::new_v4();
        let authority = Uuid::new_v4();
        let backend = test_backend();
        let first = AcquireArtifactHoldsRequest::new(
            scope,
            operation.clone(),
            request,
            backend.clone(),
            authority,
            4,
            gate,
            vec![spec("packs"), spec("idxs")],
        )
        .unwrap();
        let replay = AcquireArtifactHoldsRequest::new(
            scope,
            operation.clone(),
            request,
            backend,
            authority,
            4,
            gate,
            vec![spec("packs"), spec("idxs")],
        )
        .unwrap();
        assert_eq!(first.digest(), replay.digest());
        let reordered = AcquireArtifactHoldsRequest::new(
            scope,
            operation.clone(),
            request,
            replay.backend_identity().clone(),
            authority,
            4,
            gate,
            vec![spec("idxs"), spec("packs")],
        )
        .unwrap();
        assert_ne!(first.digest(), reordered.digest());
        // A different physical backend under the same global request id is a
        // digest conflict, never an exact replay.
        let other_backend = test_backend();
        let moved = AcquireArtifactHoldsRequest::new(
            scope,
            operation,
            request,
            other_backend,
            authority,
            4,
            gate,
            vec![spec("packs"), spec("idxs")],
        )
        .unwrap();
        assert_ne!(first.digest(), moved.digest());
        assert_eq!(first.declared_bytes().unwrap(), 256);
    }

    #[test]
    fn non_nil_and_positive_identity_is_required() {
        let scope = scope();
        let operation = operation(&scope);
        let gate = RequestDigest::of("gate", &[b"g"]);
        let backend = test_backend();
        assert!(
            AcquireArtifactHoldsRequest::new(
                scope,
                operation.clone(),
                Uuid::nil(),
                backend.clone(),
                Uuid::new_v4(),
                1,
                gate,
                vec![spec("a")]
            )
            .is_err()
        );
        assert!(
            AcquireArtifactHoldsRequest::new(
                scope,
                operation.clone(),
                Uuid::new_v4(),
                backend.clone(),
                Uuid::nil(),
                1,
                gate,
                vec![spec("a")]
            )
            .is_err()
        );
        assert!(
            AcquireArtifactHoldsRequest::new(
                scope,
                operation.clone(),
                Uuid::new_v4(),
                backend.clone(),
                Uuid::new_v4(),
                0,
                gate,
                vec![spec("a")]
            )
            .is_err()
        );
        assert!(
            AcquireArtifactHoldsRequest::new(
                scope,
                operation,
                Uuid::new_v4(),
                backend,
                Uuid::new_v4(),
                1,
                gate,
                Vec::new()
            )
            .is_err()
        );
    }
}
