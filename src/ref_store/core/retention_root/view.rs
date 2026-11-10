//! The opaque owned root byte-read view.
//!
//! Not `Clone`, not `Serialize`/`Deserialize`, no public constructor: a value exists only after T1 proved the
//! retained rows, the private native engine proved the actual Blob/Git closure, and T2 re-proved current
//! authority plus an unchanged binding under the root head `FOR SHARE`.
//!
//! It exposes only the root's retained metadata and verified local pack/idx byte reads. The private workspace
//! path, the Blob backend and the locator values are never exposed, and the value grants no write/publish/GC
//! capability.
use super::capture::RawCapture;
use super::error::RootError;
use super::scope::RootsScope;
use super::selector::RootSelectorKind;
use crate::ref_store::contract::{RefStoreError, RequestDigest};
use crate::ref_store::core::pack_commit::{CapturedRef, NativeReadClosure, PackArtifactRole, RegisteredPack};
use crate::ref_store::core::types::GitObjectFormat;
use sha2::{Digest, Sha256};
use tokio::time::Instant;
use uuid::Uuid;

/// One materialized retained root. Owned, opaque, disposable.
pub struct RootReadView {
    capture: RawCapture,
    native: NativeReadClosure,
    binding: RequestDigest,
    scope: RootsScope,
}

impl std::fmt::Debug for RootReadView {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RootReadView")
            .field("root_id", &self.root_id())
            .field("generation", &self.generation())
            .finish_non_exhaustive()
    }
}

impl RootReadView {
    pub(super) fn seal(
        capture: RawCapture,
        native: NativeReadClosure,
        binding: RequestDigest,
    ) -> Result<Self, RootError> {
        // The scope is rebuilt once here: every accessor below reads a validated retained header.
        let scope = capture.scope()?;
        if capture.binding_digest()? != binding {
            return Err(RootError::RootDigestConflict("materialized root binding changed before sealing"));
        }
        Ok(Self { capture, native, binding, scope })
    }

    pub fn root_id(&self) -> Uuid {
        self.capture.header.root_id
    }
    pub fn generation(&self) -> i64 {
        self.capture.header.generation
    }
    pub fn scope(&self) -> &RootsScope {
        &self.scope
    }
    pub fn selector_kind(&self) -> RootSelectorKind {
        self.capture.header.selector_kind
    }
    pub fn object_format(&self) -> GitObjectFormat {
        self.capture.header.object_format
    }
    pub fn head_ref(&self) -> &str {
        &self.capture.header.head_ref
    }
    /// `None` means the captured HEAD is unborn; the native closure attested exactly that.
    pub fn head_oid_hex(&self) -> Option<&str> {
        self.capture.header.head_oid.as_deref()
    }
    pub fn refs(&self) -> &[CapturedRef] {
        &self.capture.refs
    }
    pub fn root_oids(&self) -> &[String] {
        &self.capture.oids
    }
    pub fn packs(&self) -> &[RegisteredPack] {
        &self.capture.packs
    }
    pub fn binding_digest_hex(&self) -> String {
        self.binding.as_hex()
    }
    pub fn register_digest_hex(&self) -> &str {
        &self.capture.header.register_digest
    }
    pub fn source_read_digest_hex(&self) -> &str {
        &self.capture.header.source_read_digest
    }
    pub fn verified_pairs(&self) -> usize {
        self.native.verified_pairs()
    }
    pub fn verified_bytes(&self) -> u64 {
        self.native.verified_bytes()
    }

    /// Read one exact verified local pack copy. Never re-opens the Blob backend and never exposes the workspace.
    pub async fn pack_bytes(&self, pack_id: Uuid, deadline: Instant) -> Result<Vec<u8>, RootError> {
        self.read_local(pack_id, PackArtifactRole::Pack, deadline).await
    }

    /// Read one exact verified local index copy.
    pub async fn idx_bytes(&self, pack_id: Uuid, deadline: Instant) -> Result<Vec<u8>, RootError> {
        self.read_local(pack_id, PackArtifactRole::Idx, deadline).await
    }

    async fn read_local(&self, pack_id: Uuid, role: PackArtifactRole, deadline: Instant) -> Result<Vec<u8>, RootError> {
        if deadline <= Instant::now() {
            return Err(RootError::Store(RefStoreError::Timeout));
        }
        let pack = self
            .capture
            .packs
            .iter()
            .find(|pack| pack.pack_id() == pack_id)
            .ok_or(RootError::Store(RefStoreError::Unsupported("unknown retained root pack id")))?;
        let artifact = pack.artifact(role);
        let bytes = self
            .native
            .read_artifact(pack_id, role, artifact.verified_length(), deadline.into_std())
            .await
            .map_err(RootError::from)?;
        if bytes.len() as u64 != artifact.verified_length() {
            return Err(RootError::RootClosureUnproven("verified local copy changed its length"));
        }
        if hex::encode(Sha256::digest(&bytes)) != artifact.verified_sha256().as_str() {
            return Err(RootError::RootClosureUnproven("verified local copy changed its digest"));
        }
        Ok(bytes)
    }
}
