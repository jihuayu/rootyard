//! The sealed, self-contained capture identity used by both `prepare` and every later root read.
//!
//! [`RawCapture`] is exactly the retained row set (header + complete refs + exact selector OIDs + complete pack
//! identities). Its canonical binding digest is recomputed from the rows themselves and compared with the stored
//! `native_binding_digest`, so a partially written, reordered or tampered row set is refused rather than served.
//!
//! The binding deliberately excludes the receipt `request_id` (a replayed register is the same capture) and the
//! source pin *expiry* (a root outlives its source lease). It includes the complete source pin identity and read
//! digest, the gate revision/digest, HEAD (including unborn), the selector, every captured ref, every pack
//! identity digest and the retained-usage-relevant counts.
use super::error::RootError;
use super::rows::{CaptureRow, stored_oid};
use super::scope::RootsScope;
use super::selector::{RootSelector, RootSelectorKind};
use crate::ref_store::contract::RequestDigest;
use crate::ref_store::core::pack_commit::{CapturedRef, RegisteredPack, packs_digest, refs_digest};
use uuid::Uuid;

/// Canonical domain of the complete retained root binding.
pub const ROOT_BINDING_DIGEST_DOMAIN: &str = "core-root-binding-v1";

/// Borrowed canonical inputs of one root binding digest.
pub(super) struct BindingParts<'a> {
    pub scope: RootsScope,
    pub root_id: Uuid,
    pub generation: i64,
    pub operation_id: Uuid,
    pub operation_digest: &'a str,
    pub selector_kind: RootSelectorKind,
    pub oids: &'a [String],
    pub source_snapshot_id: Uuid,
    pub source_pin_id: Uuid,
    pub source_pin_generation: i64,
    pub source_read_digest: &'a str,
    pub gate_revision: i64,
    pub gate_digest: &'a str,
    pub head_ref: &'a str,
    pub head_oid: Option<&'a str>,
    pub captured_refs: &'a [CapturedRef],
    pub native_refs: &'a [CapturedRef],
    pub packs: &'a [RegisteredPack],
    pub membership_digest: &'a str,
}

/// Canonical digest over the complete retained root identity.
pub(super) fn binding_digest(parts: &BindingParts<'_>) -> RequestDigest {
    let head_presence: &[u8] = if parts.head_oid.is_some() { b"head-oid-present" } else { b"head-oid-absent" };
    let mut fields: Vec<Vec<u8>> = vec![
        parts.scope.repository_id().as_bytes().to_vec(),
        parts.scope.tenant_id().as_bytes().to_vec(),
        parts.scope.owner_id().as_bytes().to_vec(),
        parts.scope.purpose().as_str().as_bytes().to_vec(),
        parts.scope.business_intent_digest().as_bytes().to_vec(),
        parts.scope.object_format().as_str().as_bytes().to_vec(),
        parts.scope.history_incarnation().as_bytes().to_vec(),
        parts.scope.authority_epoch().to_be_bytes().to_vec(),
        parts.scope.group_epoch().to_be_bytes().to_vec(),
        parts.root_id.as_bytes().to_vec(),
        parts.generation.to_be_bytes().to_vec(),
        parts.operation_id.as_bytes().to_vec(),
        parts.operation_digest.as_bytes().to_vec(),
        parts.selector_kind.as_str().as_bytes().to_vec(),
        i64::try_from(parts.oids.len()).unwrap_or(i64::MAX).to_be_bytes().to_vec(),
        sorted_oids(parts.oids).into_bytes(),
        parts.source_snapshot_id.as_bytes().to_vec(),
        parts.source_pin_id.as_bytes().to_vec(),
        parts.source_pin_generation.to_be_bytes().to_vec(),
        parts.source_read_digest.as_bytes().to_vec(),
        parts.gate_revision.to_be_bytes().to_vec(),
        parts.gate_digest.as_bytes().to_vec(),
        parts.head_ref.as_bytes().to_vec(),
        head_presence.to_vec(),
        parts.head_oid.unwrap_or("").as_bytes().to_vec(),
        parts.membership_digest.as_bytes().to_vec(),
        refs_digest(parts.captured_refs).as_bytes().to_vec(),
        refs_digest(parts.native_refs).as_bytes().to_vec(),
        packs_digest(parts.packs).as_bytes().to_vec(),
        i64::try_from(parts.captured_refs.len()).unwrap_or(i64::MAX).to_be_bytes().to_vec(),
        i64::try_from(parts.packs.len()).unwrap_or(i64::MAX).to_be_bytes().to_vec(),
    ];
    fields.push(b"core-root-binding-end".to_vec());
    let parts = fields.iter().map(Vec::as_slice).collect::<Vec<_>>();
    RequestDigest::of(ROOT_BINDING_DIGEST_DOMAIN, &parts)
}

/// The register intent digest `register` stores on the head (and every tombstone binds as
/// `expected_register_digest`), derived only from the complete binding and the sealed scope.
pub(super) fn register_digest(binding: RequestDigest, root_id: Uuid, purpose: &str) -> RequestDigest {
    RequestDigest::of(
        super::candidate::REGISTER_DIGEST_DOMAIN,
        &[binding.as_bytes(), root_id.as_bytes(), b"generation-1", purpose.as_bytes()],
    )
}

fn sorted_oids(oids: &[String]) -> String {
    let mut sorted = oids.to_vec();
    sorted.sort();
    sorted.join(",")
}

/// The complete retained capture row set, revalidated.
#[derive(Clone, Debug)]
pub(super) struct RawCapture {
    pub header: CaptureRow,
    pub refs: Vec<CapturedRef>,
    pub oids: Vec<String>,
    pub packs: Vec<RegisteredPack>,
}

impl RawCapture {
    /// Complete scope of the capture, rebuilt from its retained header.
    pub(super) fn scope(&self) -> Result<RootsScope, RootError> {
        RootsScope::new(
            self.header.repository_id,
            self.header.tenant_id,
            self.header.owner_id,
            self.header.purpose,
            &self.header.business_intent_digest,
            self.header.object_format,
            self.header.history_incarnation,
            self.header.authority_epoch,
            self.header.group_epoch,
        )
    }

    /// The complete native ref set: captured refs plus synthetic non-branch refs for every selected OID that is
    /// not already a captured ref value.
    pub(super) fn native_refs(&self) -> Result<Vec<CapturedRef>, RootError> {
        super::selector::native_refs(self.header.object_format, &self.refs, &self.oids)
    }

    /// Recompute the canonical binding digest from the retained rows and require the stored values.
    pub(super) fn binding_digest(&self) -> Result<RequestDigest, RootError> {
        let native_refs = self.native_refs()?;
        // Shape checks first: counts must agree with the actual row set.
        let ref_count = i64::try_from(self.refs.len()).unwrap_or(i64::MAX);
        let oid_count = i64::try_from(self.oids.len()).unwrap_or(i64::MAX);
        let pack_count = i64::try_from(self.packs.len()).unwrap_or(i64::MAX);
        if ref_count != self.header.ref_count
            || oid_count != self.header.oid_count
            || pack_count != self.header.pack_count
        {
            return Err(RootError::Store(crate::ref_store::contract::RefStoreError::Database(
                "retained root row counts disagree with the capture header".into(),
            )));
        }
        if self.oids.is_empty() || self.oids.len() > self.header.selector_kind.max_oids() || self.packs.is_empty() {
            return Err(RootError::RootSelectorInvalid("retained root selector/pack set is out of bounds".into()));
        }
        // Order checks: refs by name, oids sorted/unique, packs by id.
        if self.refs.windows(2).any(|pair| pair[0].name() >= pair[1].name()) {
            return Err(RootError::Store(crate::ref_store::contract::RefStoreError::Database(
                "retained root refs are not sorted and unique".into(),
            )));
        }
        // The selector is exactly what `resolve_oids` derives from the stored selector kind: every captured ref
        // object id plus the captured HEAD for a whole snapshot, and the canonical sorted unique explicit set
        // otherwise (which also re-validates every stored oid against the capture object format).
        let resolved = super::selector::resolve_oids(
            &RootSelector::from_kind(self.header.selector_kind, self.oids.clone()),
            self.header.object_format,
            &self.refs,
            self.header.head_oid.as_deref(),
        )?;
        if resolved != self.oids {
            return Err(RootError::RootSelectorInvalid(
                "retained root selector oids are not the ones the selector kind resolves to".into(),
            ));
        }
        if self.oids.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(RootError::Store(crate::ref_store::contract::RefStoreError::Database(
                "retained root selector oids are not sorted and unique".into(),
            )));
        }
        if self.packs.windows(2).any(|pair| pair[0].pack_id() >= pair[1].pack_id()) {
            return Err(RootError::Store(crate::ref_store::contract::RefStoreError::Database(
                "retained root packs are not sorted and unique".into(),
            )));
        }
        // Every stored oid must be canonical for the capture format.
        for oid in &self.oids {
            stored_oid(self.header.object_format, oid)?;
        }
        let recomputed_refs = refs_digest(&self.refs).as_hex();
        if recomputed_refs != self.header.refs_digest {
            return Err(RootError::Store(crate::ref_store::contract::RefStoreError::Database(
                "retained root refs digest disagrees with the capture header".into(),
            )));
        }
        let recomputed_packs = packs_digest(&self.packs).as_hex();
        if recomputed_packs != self.header.pack_set_digest {
            return Err(RootError::Store(crate::ref_store::contract::RefStoreError::Database(
                "retained root pack set digest disagrees with the capture header".into(),
            )));
        }
        let scope = self.scope()?;
        let digest = binding_digest(&BindingParts {
            scope,
            root_id: self.header.root_id,
            generation: self.header.generation,
            operation_id: self.header.operation_id,
            operation_digest: &self.header.operation_digest,
            selector_kind: self.header.selector_kind,
            oids: &self.oids,
            source_snapshot_id: self.header.source_snapshot_id,
            source_pin_id: self.header.source_pin_id,
            source_pin_generation: self.header.source_pin_generation,
            source_read_digest: &self.header.source_read_digest,
            gate_revision: self.header.gate_revision,
            gate_digest: &self.header.gate_digest,
            head_ref: &self.header.head_ref,
            head_oid: self.header.head_oid.as_deref(),
            captured_refs: &self.refs,
            native_refs: &native_refs,
            packs: &self.packs,
            membership_digest: &self.header.membership_digest,
        });
        if digest.as_hex() != self.header.native_binding_digest {
            return Err(RootError::RootDigestConflict("retained root binding digest disagrees with its header"));
        }
        Ok(digest)
    }
}
