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
//! * The proof carries the cluster authority incarnation its capture locked
//!   `FOR SHARE` (migration 085) and its T2 re-checked exactly, but an issuer
//!   ([`crate::blob_git_gateway::repo_session`]) still needs a pre-capture
//!   authorization in that incarnation, the final authorization and the
//!   post-response cluster-incarnation fence (short ordered transactions, pool
//!   max 1) before a token may be issued. None of that is implemented here, and
//!   a proof never makes an incarnation current again after a restore.
//!
//! # Construction
//!
//! The proof has private fields and no public constructor, no `Clone`, no
//! `Serialize` and no extension point. Its only factory,
//! [`VerifiedReadView::of_materialized`], accepts nothing but the opaque
//! [`MaterializedPackRead`] the materializer builds **only after** T2 finished,
//! so a bare [`PackReadSnapshot`] plus a caller-chosen digest can never be
//! turned into a proof, not even from a sibling module of this crate. The view
//! keeps its own A5b binding and the proof is sealed on exactly that value, and
//! only when it equals the snapshot's recomputed A5b materialization digest.
//! The cluster incarnation is likewise not a caller input: the factory takes no
//! UUID at all and reads the anchor out of the view itself. Only the transient
//! serving T2 path builds a view with that anchor, after it locked
//! `cluster_authority` `FOR SHARE` and compared the live incarnation with the
//! capture; a legacy/history view is unanchored and is refused. Test code uses
//! separate `cfg(test)` helpers that supply a fixed anchor only in test builds;
//! they never feed a production seal site.

/// Crate-private read-only accessors for the `cfg(test)` contract suite that
/// lives in the sibling `materialize::serving_tests` subtree; never compiled
/// into a production build, so it widens no production visibility.
#[cfg(test)]
pub(crate) mod contract;

use uuid::Uuid;

use super::materialize::MaterializedPackRead;
use crate::ref_store::contract::{RefStoreError, RequestDigest};
use crate::ref_store::core::snapshot_contract::MetadataSnapshotScope;

/// A T2-revalidated native serving read whose verified A5b binding cannot be
/// separated from the native bytes they describe.
///
/// Not `Clone`, no constructor other than [`Self::of_materialized`]. The binding
/// is the materialization digest T2 recomputed and the native closure
/// reproduced, never the narrower A5a read digest.
pub(crate) struct VerifiedReadView {
    gate_revision: i64,
    scope: ProvenScope,
    binding: RequestDigest,
    cluster_incarnation: Uuid,
}

impl VerifiedReadView {
    /// Prove exactly this materialized view.
    ///
    /// The value is a complete transient pack read (never a retained A5a
    /// snapshot or a `metadata_only` shape), its A5b binding is the native
    /// closure's digest T2 compared with its own recomputation, and that binding
    /// must equal the A5b materialization digest recomputed from the view's
    /// snapshot. Nothing else is accepted: there is no other factory, and the
    /// view keeps its native closure, its snapshot and its provenance together,
    /// so neither its binding nor its cluster incarnation can be chosen by a
    /// caller or drift from the snapshot.
    ///
    /// The incarnation is read back from the view's private anchor, which only
    /// the serving T2 path sets (the value it locked `FOR SHARE` and compared
    /// with the capture). An unanchored view, or a nil anchor, is refused.
    pub(crate) fn of_materialized(view: &MaterializedPackRead) -> Result<Self, RefStoreError> {
        let snapshot = view.snapshot();
        if snapshot.complete_transient_pack_read().is_none() {
            return Err(RefStoreError::Unsupported(
                "serving proof requires a transient complete pack-verified read",
            ));
        }
        let binding = view.proven_binding();
        if snapshot.materialization_digest() != binding {
            return Err(RefStoreError::MetadataScopeMismatch("serving proof binding"));
        }
        let cluster_incarnation = match view.serving_incarnation() {
            Some(cluster_incarnation) if !cluster_incarnation.is_nil() => cluster_incarnation,
            Some(_) => return Err(RefStoreError::MetadataScopeMismatch("cluster authority incarnation")),
            None => return Err(RefStoreError::Unsupported("serving proof requires a T2-anchored view")),
        };
        Ok(Self {
            gate_revision: snapshot.gate_revision(),
            scope: ProvenScope::of(snapshot.scope()),
            binding,
            cluster_incarnation,
        })
    }

    /// Consume the view into the sealed proof. Only the materializer calls it.
    pub(super) fn seal(self) -> VerifiedReadViewProof {
        VerifiedReadViewProof {
            gate_revision: self.gate_revision,
            scope: self.scope,
            binding: self.binding,
            cluster_incarnation: self.cluster_incarnation,
        }
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
    /// The global cluster authority incarnation the capture locked `FOR SHARE`
    /// and T2 re-read identically; never a freshly rotated value.
    cluster_incarnation: Uuid,
}

/// The captured realm, copied out of the sealed snapshot. Deliberately has no
/// cluster incarnation: the incarnation anchor is sealed next to the scope, not
/// inside it, so it can only come from the T2-compared capture.
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

    fn of(scope: &MetadataSnapshotScope) -> Self {
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

impl VerifiedReadViewProof {
    /// The verified gate revision. Consuming the proof (not this borrow) is what
    /// a session issuer needs.
    pub fn gate_revision(&self) -> i64 {
        self.gate_revision
    }

    /// The cluster authority incarnation the capture locked and T2 re-proved.
    /// Crate-private: only gateway code in this crate may compare it, and only
    /// by equality with the live singleton.
    pub(crate) fn cluster_incarnation(&self) -> Uuid {
        self.cluster_incarnation
    }

    /// Consume the proof into its verified gate revision and realm. The cluster
    /// incarnation stays behind [`Self::cluster_incarnation`].
    pub(crate) fn into_parts(self) -> (i64, ProvenScope) {
        (self.gate_revision, self.scope)
    }
}

impl MaterializedPackRead {
    /// Prove this materialized view is exactly a complete, T2-revalidated
    /// transient serving read whose A5b binding is `binding`: never a retained
    /// A5a snapshot, a `metadata_only` shape, or a view the native closure did
    /// not cover. The binding is compared with the full A5b materialization
    /// digest, not the narrower A5a read digest. The returned probe scope never
    /// becomes a proof: the real seal site goes through
    /// [`VerifiedReadView::of_materialized`], which additionally requires the
    /// view's own T2-sealed incarnation anchor.
    #[cfg(test)]
    pub(crate) fn verified_read_scope(&self, binding: &RequestDigest) -> Option<ProvenScope> {
        self.snapshot()
            .complete_transient_pack_read()
            .filter(|_| self.proven_binding() == *binding)
            .map(|_| ProvenScope::of(self.snapshot().scope()))
    }

    /// The A5a per-read digest of the proven snapshot (`read_digest_hex`), as a
    /// probe value for tests that must show it is never mistaken for the A5b
    /// binding. Test-only so it can never become a proof input.
    #[cfg(test)]
    pub(crate) fn a5a_probe(&self) -> RequestDigest {
        self.snapshot().read_digest_hex().parse().expect("the snapshot's own A5a hex parses")
    }
}

/// Test-only: the A5a per-read digest of a transient snapshot. Never a proof.
#[cfg(test)]
#[allow(unused_imports)]
pub(crate) fn probe_a5a(snapshot: &super::read_snapshot::PackReadSnapshot) -> RequestDigest {
    snapshot.read_digest_hex().parse().expect("a snapshot's own A5a hex parses")
}
