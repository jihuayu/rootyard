//! The data-only historical root record returned by `get`.
//!
//! A [`RootRecord`] is metadata: it never carries Blob bytes, never grants a read and never asserts that the
//! repository or the source pin still exists. It stays answerable after source-pin expiry/release and after a
//! whole business-repository delete, exactly because every field is re-derived from the root's own retained rows.
use super::capture::RawCapture;
use super::error::RootError;
use super::scope::RootPurpose;
use super::selector::RootSelectorKind;
use crate::ref_store::core::pack_commit::{CapturedRef, RegisteredPack};
use crate::ref_store::core::types::GitObjectFormat;
use uuid::Uuid;

/// One retained capture as data.
#[derive(Clone, Debug)]
pub struct RootRecord {
    state: String,
    capture: RawCapture,
}

impl RootRecord {
    pub(super) fn new(state: String, capture: RawCapture) -> Self {
        Self { state, capture }
    }

    /// `active` or `released`. A released root keeps every retained row; only the head state is one-way.
    pub fn state(&self) -> &str {
        &self.state
    }
    pub fn is_active(&self) -> bool {
        self.state == "active"
    }
    pub fn repository_id(&self) -> Uuid {
        self.capture.header.repository_id
    }
    pub fn root_id(&self) -> Uuid {
        self.capture.header.root_id
    }
    pub fn generation(&self) -> i64 {
        self.capture.header.generation
    }
    pub fn tenant_id(&self) -> Uuid {
        self.capture.header.tenant_id
    }
    pub fn owner_id(&self) -> Uuid {
        self.capture.header.owner_id
    }
    pub fn purpose(&self) -> RootPurpose {
        self.capture.header.purpose
    }
    pub fn business_intent_digest_hex(&self) -> &str {
        &self.capture.header.business_intent_digest
    }
    pub fn operation_id(&self) -> Uuid {
        self.capture.header.operation_id
    }
    pub fn operation_digest_hex(&self) -> &str {
        &self.capture.header.operation_digest
    }
    pub fn request_id(&self) -> Uuid {
        self.capture.header.request_id
    }
    pub fn selector_kind(&self) -> RootSelectorKind {
        self.capture.header.selector_kind
    }
    pub fn object_format(&self) -> GitObjectFormat {
        self.capture.header.object_format
    }
    pub fn history_incarnation(&self) -> Uuid {
        self.capture.header.history_incarnation
    }
    pub fn authority_epoch(&self) -> i64 {
        self.capture.header.authority_epoch
    }
    pub fn group_epoch(&self) -> i64 {
        self.capture.header.group_epoch
    }
    pub fn source_snapshot_id(&self) -> Uuid {
        self.capture.header.source_snapshot_id
    }
    pub fn source_pin_id(&self) -> Uuid {
        self.capture.header.source_pin_id
    }
    pub fn source_pin_generation(&self) -> i64 {
        self.capture.header.source_pin_generation
    }
    pub fn source_read_digest_hex(&self) -> &str {
        &self.capture.header.source_read_digest
    }
    pub fn gate_revision(&self) -> i64 {
        self.capture.header.gate_revision
    }
    pub fn gate_digest_hex(&self) -> &str {
        &self.capture.header.gate_digest
    }
    pub fn head_ref(&self) -> &str {
        &self.capture.header.head_ref
    }
    pub fn head_oid_hex(&self) -> Option<&str> {
        self.capture.header.head_oid.as_deref()
    }
    pub fn refs_digest_hex(&self) -> &str {
        &self.capture.header.refs_digest
    }
    pub fn ref_count(&self) -> i64 {
        self.capture.header.ref_count
    }
    pub fn membership_digest_hex(&self) -> &str {
        &self.capture.header.membership_digest
    }
    pub fn pack_set_digest_hex(&self) -> &str {
        &self.capture.header.pack_set_digest
    }
    pub fn pack_count(&self) -> i64 {
        self.capture.header.pack_count
    }
    pub fn oid_count(&self) -> i64 {
        self.capture.header.oid_count
    }
    pub fn binding_digest_hex(&self) -> &str {
        &self.capture.header.native_binding_digest
    }
    pub fn roots_revision(&self) -> i64 {
        self.capture.header.roots_revision
    }
    pub fn register_digest_hex(&self) -> &str {
        &self.capture.header.register_digest
    }
    /// The complete captured ref set (explicit `refs/*` protection for a future GC).
    pub fn refs(&self) -> &[CapturedRef] {
        &self.capture.refs
    }
    /// The exact selector object ids (may include an older, currently unreferenced commit).
    pub fn root_oids(&self) -> &[String] {
        &self.capture.oids
    }
    /// The complete protected pack identities (self-contained locators).
    pub fn packs(&self) -> &[RegisteredPack] {
        &self.capture.packs
    }

    /// Re-prove the complete retained binding (already executed on read; exposed for callers that persist the
    /// record themselves).
    pub fn verify(&self) -> Result<(), RootError> {
        self.capture.binding_digest().map(|_| ())
    }
}
