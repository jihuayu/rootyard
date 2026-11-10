//! Internal materialization proof of one native serving read (#174).
//!
//! [`VerifiedReadViewProof`] is an **internal artifact proof** produced only by
//! the real serving materializer
//! ([`super::PgPackSnapshotMaterializer::materialize_serving_read_sealed`]).
//! It states that *this process* captured the gate state below under the strict
//! `pg_refstore` serving authority, downloaded and verified every registered
//! pack/index pair with the actual Blob backend into a private native view,
//! checked that native view's closure with `fsck`, and — after the Blob/native
//! work finished — re-proved the migration-146 transient pin, the captured
//! realm and the live backend in one fresh short transaction (T2).
//!
//! # What it is not
//!
//! It is **not** proof of a served HTTP view. No gateway route consumes it yet,
//! nothing here copies packs into a served Git view, and nothing proves the
//! bytes a client received. It is not a `metadata_only` capture, a refs/HEAD
//! listing without bytes, a write/push receipt, a durable snapshot, a pin/hold,
//! or a promise that a later push cannot supersede the gate revision.
//!
//! # Consumers must still enforce (not implemented here)
//!
//! * A gateway must copy packs/index, check the pack/index checksums and
//!   `verify_refs` before a proof may describe an encoded response, run the
//!   final authorization and the cluster incarnation fence, restore the
//!   incarnation and only then seal/issue.
//! * [`ProvenScope`] has no cluster incarnation, so it cannot by itself pin a
//!   token to one cluster authority: the issuer
//!   ([`crate::blob_git_gateway::repo_session`]) still needs a pre-capture
//!   authorization bound to the incarnation and a post-response final fence in
//!   the same incarnation (short ordered transactions, pool max 1). None of
//!   that is implemented here.
//!
//! # Construction
//!
//! The fields are private. The sealed value has no public constructor, no
//! `Clone`, no `Serialize` and no extension point. It is created only by the
//! parent materialize step from a T2-revalidated native view; test code uses a
//! separate `cfg(test)` path that can never be a production proof.

/// Read-only accessors for the out-of-crate native contract suite (`cfg(test)`
/// only, so it is never part of a production build).
#[cfg(test)]
pub(crate) mod contract;

use uuid::Uuid;

use super::PackReadSnapshot;
use crate::ref_store::contract::RequestDigest;

/// A T2-revalidated native serving read whose verified A5b binding cannot be
/// separated from the native bytes they describe.
///
/// Not `Clone`, no public constructor. The binding is the materialization
/// digest T2 recomputed and the native closure reproduced, never the narrower
/// A5a read digest.
pub(crate) struct VerifiedReadView {
    gate_revision: i64,
    scope: ProvenScope,
    binding: RequestDigest,
}

impl VerifiedReadView {
    /// Check that the materialized view's own T2-revalidated snapshot is a
    /// complete transient pack read. The parent passes the capture's A5b
    /// binding only after T2 re-proved it against this same snapshot.
    pub(super) fn of_revalidated(
        snapshot: &PackReadSnapshot,
        binding: RequestDigest,
    ) -> Result<Self, crate::ref_store::RefStoreError> {
        if !snapshot.complete_transient_pack_read() {
            return Err(crate::ref_store::RefStoreError::Database(
                "materialized serving read is not a verified transient read".into(),
            ));
        }
        Ok(Self { gate_revision: snapshot.gate_revision(), scope: ProvenScope::of(snapshot), binding })
    }

    /// Consume the view into the sealed proof. Only the materializer calls it.
    pub(super) fn seal(self) -> VerifiedReadViewProof {
        VerifiedReadViewProof { gate_revision: self.gate_revision, scope: self.scope, binding: self.binding }
    }
}

/// One sealed, fully verified native serving read (internal artifact proof).
///
/// See the module docs for what a consumer must still enforce before this can
/// stand for a served response.
#[derive(Debug)]
pub struct VerifiedReadViewProof {
    /// The RefStore core gate revision the capture locked and T2 re-proved.
    gate_revision: i64,
    scope: ProvenScope,
    /// The A5b materialization digest the native view was verified against.
    binding: RequestDigest,
}

/// The captured realm, copied out of the sealed snapshot. Deliberately has no
/// cluster incarnation (see the module docs).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ProvenScope {
    repository_id: Uuid,
    tenant_id: Uuid,
    object_format: crate::ref_store::GitObjectFormat,
    history_incarnation: Uuid,
    authority_epoch: i64,
    group_epoch: i64,
}

impl ProvenScope {
    pub(crate) fn repository_id(&self) -> Uuid {
        self.repository_id
    }

    pub(crate) fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    pub(crate) fn object_format(&self) -> crate::ref_store::GitObjectFormat {
        self.object_format
    }

    pub(crate) fn history_incarnation(&self) -> Uuid {
        self.history_incarnation
    }

    pub(crate) fn authority_epoch(&self) -> i64 {
        self.authority_epoch
    }

    pub(crate) fn group_epoch(&self) -> i64 {
        self.group_epoch
    }

    fn of(scope: &super::MetadataSnapshotScope) -> Self {
        Self {
            repository_id: scope.repository_id(),
            tenant_id: scope.tenant_id(),
            object_format: scope.object_format(),
            history_incarnation: scope.history_incarnation(),
            authority_epoch: scope.authority_epoch(),
            group_epoch: scope.group_epoch(),
        }
    }
}

#[cfg(test)]
pub(crate) use contract::{
    contract_a5a_probe, contract_binding, contract_gate_revision, contract_history_incarnation, contract_repository_id,
    contract_scope, contract_tenant_id,
};

impl VerifiedReadViewProof {
    /// The verified gate revision. Consuming the proof (not this borrow) is what
    /// a session issuer needs.
    pub fn gate_revision(&self) -> i64 {
        self.gate_revision
    }

    /// Consume the proof into its verified gate revision and realm.
    pub(crate) fn into_parts(self) -> (i64, ProvenScope) {
        (self.gate_revision, self.scope)
    }
}

impl MaterializedPackRead {
    /// Prove this view is exactly a complete, T2-revalidated transient serving
    /// read whose A5b binding is `binding`: never a retained A5a snapshot, a
    /// metadata-only shape, or a view the native closure did not cover. The
    /// binding is compared with the full A5b materialization digest, not the
    /// narrower A5a read digest.
    #[cfg(test)]
    pub(crate) fn verified_read_scope(&self, binding: &RequestDigest) -> Option<ProvenScope> {
        self.snapshot()
            .complete_transient_pack_read()
            .filter(|_| self.proven_binding() == *binding)
            .map(ProvenScope::of)
    }
}

/// Test-only: seal a proof over a synthetic scope after a test proved its own
/// realm. This never touches the production seal site and is unavailable in
/// non-test builds, so it cannot stand in for the materializer's proof.
#[cfg(test)]
pub(crate) fn seal_for_test(revision: i64, scope: ProvenScope, binding: RequestDigest) -> VerifiedReadViewProof {
    VerifiedReadViewProof { gate_revision: revision, scope, binding }
}

/// Test-only: build a synthetic scope. The produced proof is never a receipt.
#[cfg(test)]
pub(crate) fn test_scope(
    tenant_id: Uuid,
    repository_id: Uuid,
    object_format: crate::ref_store::GitObjectFormat,
    history_incarnation: Uuid,
    authority_epoch: i64,
    group_epoch: i64,
) -> ProvenScope {
    ProvenScope { repository_id, tenant_id, object_format, history_incarnation, authority_epoch, group_epoch }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ref_store::GitObjectFormat;

    fn scope(seed: u8) -> ProvenScope {
        ProvenScope {
            repository_id: Uuid::from_bytes([seed; 16]),
            tenant_id: Uuid::from_bytes([seed.wrapping_add(1); 16]),
            object_format: GitObjectFormat::Sha1,
            history_incarnation: Uuid::from_bytes([seed.wrapping_add(2); 16]),
            authority_epoch: 1,
            group_epoch: 1,
        }
    }

    #[test]
    fn a_sealed_proof_states_exactly_the_revision_it_was_sealed_with() {
        let binding = RequestDigest::of("serving-proof-unit", &[b"read"]);
        let proof = seal_for_test(17, scope(1), binding);
        // Debug output is identity-only: the revision and repository id, never
        // the A5b binding.
        let debug = format!("{proof:?}");
        assert!(debug.contains("gate_revision: 17"), "{debug}");
        assert!(!debug.contains(&binding.as_hex()), "{debug}");
        assert_eq!(proof.gate_revision(), 17);
        let (revision, proven) = proof.into_parts();
        assert_eq!(revision, 17);
        assert_eq!(proven, scope(1));
    }
}
