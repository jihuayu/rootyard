//! The sealed root candidate: the only value `register` accepts.
//!
//! A candidate is produced by [`super::PgRetentionRoots::prepare`] after the T1 sealed metadata read and after the
//! private native engine proved the actual Blob + Git object closure of the exact selector against the exact
//! registered packs. It has private fields, no public constructor, no `Clone` and no
//! `Serialize`/`Deserialize`, so no caller can invent a capture, swap a selector or replay bytes it did not read.
//!
//! `register` moves the candidate **by value** and never re-derives it from caller input; it only re-reads the
//! source snapshot under PostgreSQL locks and requires byte-for-byte agreement with the sealed values here.
use super::error::RootError;
use super::scope::RootsScope;
use super::selector::{RootSelectorKind, native_refs};
use crate::ref_store::contract::{RefStoreError, RequestDigest};
use crate::ref_store::core::pack_commit::{CapturedRef, RegisteredPack, packs_digest, refs_digest};
use crate::ref_store::core::pack_snapshot::{PackReadSnapshot, PackSnapshotRef};
use crate::ref_store::core::snapshot_contract::{MAX_SNAPSHOT_PACKS, MAX_SNAPSHOT_REFS};
use uuid::Uuid;

/// Canonical domain of the complete source read digest.
pub const SOURCE_READ_DIGEST_DOMAIN: &str = "core-root-source-read-v1";
/// Canonical domain of the register intent digest bound by a tombstone.
pub const REGISTER_DIGEST_DOMAIN: &str = "core-root-register-v1";

/// One sealed root capture, ready for a short registration transaction.
#[derive(Debug)]
pub struct RootCandidate {
    pub(super) scope: RootsScope,
    pub(super) reference: PackSnapshotRef,
    pub(super) root_id: Uuid,
    pub(super) operation_id: Uuid,
    pub(super) operation_digest: RequestDigest,
    pub(super) selector_kind: RootSelectorKind,
    pub(super) oids: Vec<String>,
    pub(super) captured_refs: Vec<CapturedRef>,
    pub(super) native_refs: Vec<CapturedRef>,
    pub(super) packs: Vec<RegisteredPack>,
    pub(super) source_snapshot_digest: String,
    pub(super) source_membership_digest: String,
    pub(super) source_read_digest: RequestDigest,
    pub(super) gate_revision: i64,
    pub(super) gate_digest: String,
    pub(super) head_ref: String,
    pub(super) head_oid: Option<String>,
    pub(super) binding_digest: RequestDigest,
    pub(super) register_digest: RequestDigest,
}

/// Canonical digest over the complete sealed source read (scope, gate, snapshot/pin, refs, packs, counts).
///
/// The canonical full A5b `materialization_digest` of the same snapshot is nested as one of the fields, so a
/// root capture binds the exact shared source identity unambiguously without re-deriving a competing superset.
pub(super) fn source_read_digest(
    snapshot: &PackReadSnapshot,
    oids: &[String],
    selector_kind: RootSelectorKind,
) -> RequestDigest {
    let scope = snapshot.scope();
    let head_presence: &[u8] = if snapshot.head_oid_hex().is_some() { b"head-oid-present" } else { b"head-oid-absent" };
    let mut sorted = oids.to_vec();
    sorted.sort();
    RequestDigest::of(
        SOURCE_READ_DIGEST_DOMAIN,
        &[
            scope.repository_id().as_bytes(),
            scope.tenant_id().as_bytes(),
            scope.owner_id().as_bytes(),
            scope.object_format().as_str().as_bytes(),
            scope.history_incarnation().as_bytes(),
            &scope.authority_epoch().to_be_bytes(),
            &scope.group_epoch().to_be_bytes(),
            snapshot.snapshot_id().as_bytes(),
            snapshot.pin_id().as_bytes(),
            &snapshot.pin_generation().to_be_bytes(),
            &snapshot.gate_revision().to_be_bytes(),
            snapshot.gate_digest_hex().as_bytes(),
            snapshot.head_ref().as_bytes(),
            head_presence,
            snapshot.head_oid_hex().unwrap_or("").as_bytes(),
            refs_digest(snapshot.refs()).as_bytes(),
            packs_digest(snapshot.packs()).as_bytes(),
            snapshot.snapshot_digest_hex().as_bytes(),
            snapshot.membership_digest_hex().as_bytes(),
            &snapshot.ref_count().to_be_bytes(),
            &snapshot.pack_count().to_be_bytes(),
            &snapshot.logical_bytes().to_be_bytes(),
            &snapshot.expires_at_unix_micros().to_be_bytes(),
            selector_kind.as_str().as_bytes(),
            sorted.join(",").as_bytes(),
            snapshot.materialization_digest().as_bytes(),
        ],
    )
}

impl RootCandidate {
    /// Seal one candidate. Only the adapter may call this, and only after the native closure succeeded.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn seal(
        scope: RootsScope,
        reference: PackSnapshotRef,
        root_id: Uuid,
        operation_id: Uuid,
        operation_digest: RequestDigest,
        selector_kind: RootSelectorKind,
        oids: Vec<String>,
        snapshot: &PackReadSnapshot,
        packs: Vec<RegisteredPack>,
    ) -> Result<Self, RootError> {
        if root_id.is_nil() || operation_id.is_nil() || root_id == operation_id {
            return Err(RootError::Store(RefStoreError::InvalidIdentity(
                "root candidate ids must be non-nil and distinct".into(),
            )));
        }
        if oids.is_empty() || oids.len() > selector_kind.max_oids() {
            return Err(RootError::RootSelectorInvalid("root selector is out of bounds".into()));
        }
        if oids.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(RootError::RootSelectorInvalid("root selector oids must be sorted and unique".into()));
        }
        // The sealed source must be a complete pack-verified registered-membership snapshot.
        if snapshot.pack_count() <= 0
            || snapshot.pack_count() > MAX_SNAPSHOT_PACKS as i64
            || snapshot.ref_count() > MAX_SNAPSHOT_REFS as i64
        {
            return Err(RootError::RootSourceChanged("source snapshot membership is out of bounds"));
        }
        if snapshot.snapshot_id() != reference.snapshot_id()
            || snapshot.pin_id() != reference.pin_id()
            || snapshot.pin_generation() != reference.expected_generation()
            || snapshot.repository_id() != reference.repository_id()
            || snapshot.tenant_id() != reference.tenant_id()
        {
            return Err(RootError::RootSourceChanged("sealed source identity disagrees with the reference"));
        }
        let source_scope = snapshot.scope();
        if source_scope.repository_id() != scope.repository_id()
            || source_scope.tenant_id() != scope.tenant_id()
            || source_scope.owner_id() != scope.owner_id()
            || source_scope.object_format() != scope.object_format()
            || source_scope.history_incarnation() != scope.history_incarnation()
            || source_scope.authority_epoch() != scope.authority_epoch()
            || source_scope.group_epoch() != scope.group_epoch()
        {
            return Err(RootError::RootRealmMismatch("root scope does not match the source pin realm"));
        }
        let captured_refs = snapshot.refs().to_vec();
        if captured_refs.windows(2).any(|pair| pair[0].name() >= pair[1].name()) {
            return Err(RootError::Store(RefStoreError::Database(
                "sealed source refs are not sorted and unique".into(),
            )));
        }
        // HEAD must be exactly the captured HEAD (including unborn); a present HEAD object id must be a captured
        // ref value so the native engine can attest it.
        if let Some(head_oid) = snapshot.head_oid_hex()
            && !captured_refs
                .iter()
                .any(|reference| reference.name() == snapshot.head_ref() && reference.oid_hex() == head_oid)
        {
            return Err(RootError::RootSourceChanged("captured HEAD is not one of the captured refs"));
        }
        let mut packs = packs;
        packs.sort_by_key(RegisteredPack::pack_id);
        if packs.windows(2).any(|pair| pair[0].pack_id() == pair[1].pack_id()) {
            return Err(RootError::Store(RefStoreError::Database("sealed source repeats a registered pack id".into())));
        }
        if packs.is_empty() || packs.len() > MAX_SNAPSHOT_PACKS || packs != snapshot.packs() {
            return Err(RootError::RootSourceChanged("sealed pack identity disagrees with the source read"));
        }
        let native = native_refs(scope.object_format(), &captured_refs, &oids)?;
        let source_read_digest = source_read_digest(snapshot, &oids, selector_kind);
        let binding = super::capture::binding_digest(&super::capture::BindingParts {
            scope,
            root_id,
            generation: 1,
            operation_id,
            operation_digest: &operation_digest.as_hex(),
            selector_kind,
            oids: &oids,
            source_snapshot_id: snapshot.snapshot_id(),
            source_pin_id: snapshot.pin_id(),
            source_pin_generation: snapshot.pin_generation(),
            source_read_digest: &source_read_digest.as_hex(),
            gate_revision: snapshot.gate_revision(),
            gate_digest: snapshot.gate_digest_hex(),
            head_ref: snapshot.head_ref(),
            head_oid: snapshot.head_oid_hex(),
            captured_refs: &captured_refs,
            native_refs: &native,
            packs: &packs,
            membership_digest: snapshot.membership_digest_hex(),
        });
        let register_digest = RequestDigest::of(
            REGISTER_DIGEST_DOMAIN,
            &[binding.as_bytes(), root_id.as_bytes(), b"generation-1", scope.purpose().as_str().as_bytes()],
        );
        Ok(Self {
            scope,
            reference,
            root_id,
            operation_id,
            operation_digest,
            selector_kind,
            oids,
            captured_refs,
            native_refs: native,
            packs,
            source_snapshot_digest: snapshot.snapshot_digest_hex().to_owned(),
            source_membership_digest: snapshot.membership_digest_hex().to_owned(),
            source_read_digest,
            gate_revision: snapshot.gate_revision(),
            gate_digest: snapshot.gate_digest_hex().to_owned(),
            head_ref: snapshot.head_ref().to_owned(),
            head_oid: snapshot.head_oid_hex().map(str::to_owned),
            binding_digest: binding,
            register_digest,
        })
    }
}

impl RootCandidate {
    pub fn root_id(&self) -> Uuid {
        self.root_id
    }
    /// A root has exactly one capture; the released terminal is generation 2 and is never a capture.
    pub fn generation(&self) -> i64 {
        1
    }
    pub fn scope(&self) -> &RootsScope {
        &self.scope
    }
    pub fn reference(&self) -> &PackSnapshotRef {
        &self.reference
    }
    pub fn operation_id(&self) -> Uuid {
        self.operation_id
    }
    pub fn operation_digest(&self) -> RequestDigest {
        self.operation_digest
    }
    pub fn selector_kind(&self) -> RootSelectorKind {
        self.selector_kind
    }
    pub fn root_oids(&self) -> &[String] {
        &self.oids
    }
    pub fn captured_refs(&self) -> &[CapturedRef] {
        &self.captured_refs
    }
    pub fn native_refs(&self) -> &[CapturedRef] {
        &self.native_refs
    }
    pub fn packs(&self) -> &[RegisteredPack] {
        &self.packs
    }
    pub fn source_snapshot_id(&self) -> Uuid {
        self.reference.snapshot_id()
    }
    pub fn source_pin_id(&self) -> Uuid {
        self.reference.pin_id()
    }
    pub fn source_pin_generation(&self) -> i64 {
        self.reference.expected_generation()
    }
    pub fn source_read_digest_hex(&self) -> String {
        self.source_read_digest.as_hex()
    }
    pub fn binding_digest(&self) -> RequestDigest {
        self.binding_digest
    }
    pub fn register_digest(&self) -> RequestDigest {
        self.register_digest
    }
    pub fn pack_count(&self) -> i64 {
        i64::try_from(self.packs.len()).unwrap_or(i64::MAX)
    }
    pub fn ref_count(&self) -> i64 {
        i64::try_from(self.captured_refs.len()).unwrap_or(i64::MAX)
    }

    /// Revalidate this candidate against a fresh, locked read of its source snapshot.
    ///
    /// `register` calls this inside the short registration transaction after it re-read the snapshot/pin/realm/
    /// complete pack identity under the core gate lock. Any disagreement is a typed refusal, never a silent
    /// capture at the newer state.
    pub(super) fn verify_source(&self, fresh: &PackReadSnapshot) -> Result<(), RootError> {
        if fresh.snapshot_id() != self.source_snapshot_id()
            || fresh.pin_id() != self.source_pin_id()
            || fresh.pin_generation() != self.source_pin_generation()
            || fresh.repository_id() != self.scope.repository_id()
            || fresh.tenant_id() != self.scope.tenant_id()
        {
            return Err(RootError::RootSourceChanged("source snapshot/pin identity changed"));
        }
        let source_scope = fresh.scope();
        if source_scope.owner_id() != self.scope.owner_id()
            || source_scope.object_format() != self.scope.object_format()
            || source_scope.history_incarnation() != self.scope.history_incarnation()
            || source_scope.authority_epoch() != self.scope.authority_epoch()
            || source_scope.group_epoch() != self.scope.group_epoch()
        {
            return Err(RootError::RootRealmMismatch("source snapshot realm changed"));
        }
        if fresh.gate_revision() != self.gate_revision || fresh.gate_digest_hex() != self.gate_digest {
            return Err(RootError::RootSourceChanged("source gate revision/digest changed"));
        }
        if fresh.head_ref() != self.head_ref || fresh.head_oid_hex() != self.head_oid.as_deref() {
            return Err(RootError::RootSourceChanged("source HEAD changed"));
        }
        if fresh.snapshot_digest_hex() != self.source_snapshot_digest
            || fresh.membership_digest_hex() != self.source_membership_digest
        {
            return Err(RootError::RootSourceChanged("source snapshot/membership digest changed"));
        }
        if fresh.refs() != self.captured_refs.as_slice() {
            return Err(RootError::RootSourceChanged("source refs changed"));
        }
        if fresh.packs() != self.packs.as_slice() {
            return Err(RootError::RootSourceChanged("source registered pack identity changed"));
        }
        let recomputed = source_read_digest(fresh, &self.oids, self.selector_kind);
        if recomputed != self.source_read_digest {
            return Err(RootError::RootSourceChanged("source read digest changed"));
        }
        Ok(())
    }
}
