//! Full Blob closure read-back proof primitives for receive/publication commits.
//!
//! Before a push/receive or archive publication may commit refs or ACK clients,
//! every artifact in the closure (such as `.pack` + `.idx` + optional manifest)
//! must prove full provider read-back against the target [`BlobStore`] and,
//! when configured for `local-envelope`, full local chunked AEAD decryption and
//! key-unwrap verification against the live [`KeyProvider`].

use std::{collections::BTreeSet, fmt, path::Path, sync::Arc, time::Instant};

use uuid::Uuid;

use super::{
    BlobBackendIdentity, BlobError, BlobLocator, BlobReceipt, MAX_OBJECT_BYTES,
    envelope::{EnvelopeError, EnvelopeMetadata},
    key_provider::{KeyId, KeyProvider},
    opendal::BlobStore,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClosureArtifactRole {
    Pack,
    PackIndex,
    Manifest,
    LfsObject,
    Checkpoint,
    Archive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlobClosureEncryption {
    ProviderManaged,
    LocalEnvelope,
}

#[derive(Debug)]
pub enum BlobClosureError {
    InvalidSpec(&'static str),
    IncompleteClosure(&'static str),
    EncryptionPolicyMismatch,
    MissingKeyProvider,
    MissingStagingDir,
    ForeignBackend,
    PlaintextMismatch(&'static str),
    Blob(BlobError),
    Envelope(EnvelopeError),
}

impl From<BlobError> for BlobClosureError {
    fn from(value: BlobError) -> Self {
        match value {
            BlobError::ForeignBackend => Self::ForeignBackend,
            other => Self::Blob(other),
        }
    }
}

impl From<EnvelopeError> for BlobClosureError {
    fn from(value: EnvelopeError) -> Self {
        match value {
            EnvelopeError::ForeignBackend => Self::ForeignBackend,
            EnvelopeError::EncryptionPolicyMismatch => Self::EncryptionPolicyMismatch,
            other => Self::Envelope(other),
        }
    }
}

impl fmt::Display for BlobClosureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSpec(reason) => write!(f, "invalid blob closure specification: {reason}"),
            Self::IncompleteClosure(reason) => write!(f, "incomplete blob closure: {reason}"),
            Self::EncryptionPolicyMismatch => f.write_str("blob closure encryption mode mismatches store policy"),
            Self::MissingKeyProvider => f.write_str("local-envelope closure requires a live KeyProvider"),
            Self::MissingStagingDir => f.write_str("local-envelope closure requires a staging directory"),
            Self::ForeignBackend => f.write_str("blob closure artifact belongs to a different physical backend"),
            Self::PlaintextMismatch(reason) => write!(f, "closure plaintext digest/length mismatch: {reason}"),
            Self::Blob(err) => write!(f, "{err}"),
            Self::Envelope(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for BlobClosureError {}

/// One artifact entry inside a publication closure awaiting read-back proof.
#[derive(Debug, Clone)]
pub struct ClosureEntrySpec {
    role: ClosureArtifactRole,
    locator: BlobLocator,
    envelope: Option<EnvelopeMetadata>,
    expected_plaintext_sha256: Option<String>,
    expected_plaintext_length: Option<u64>,
}

impl ClosureEntrySpec {
    pub fn provider_managed(role: ClosureArtifactRole, locator: BlobLocator) -> Self {
        Self { role, locator, envelope: None, expected_plaintext_sha256: None, expected_plaintext_length: None }
    }

    pub fn local_envelope(
        role: ClosureArtifactRole,
        locator: BlobLocator,
        envelope: EnvelopeMetadata,
    ) -> Result<Self, BlobClosureError> {
        envelope.validate()?;
        if !envelope.matches_locator(&locator) {
            return Err(BlobClosureError::InvalidSpec("envelope metadata does not match closure locator"));
        }
        Ok(Self {
            role,
            locator,
            envelope: Some(envelope),
            expected_plaintext_sha256: None,
            expected_plaintext_length: None,
        })
    }

    pub fn with_expected_plaintext(mut self, sha256: &str, length: u64) -> Result<Self, BlobClosureError> {
        if sha256.len() != 64 || !sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(BlobClosureError::InvalidSpec("invalid expected plaintext sha256"));
        }
        if length > MAX_OBJECT_BYTES {
            return Err(BlobClosureError::InvalidSpec("expected plaintext length exceeds ceiling"));
        }
        self.expected_plaintext_sha256 = Some(sha256.to_owned());
        self.expected_plaintext_length = Some(length);
        Ok(self)
    }

    pub fn role(&self) -> ClosureArtifactRole {
        self.role
    }

    pub fn locator(&self) -> &BlobLocator {
        &self.locator
    }

    pub fn envelope(&self) -> Option<&EnvelopeMetadata> {
        self.envelope.as_ref()
    }
}

/// Validated set of artifacts forming one commit closure for an owner scope.
#[derive(Debug, Clone)]
pub struct BlobClosureSpec {
    tenant_id: Uuid,
    authority_id: Uuid,
    generation: i64,
    encryption: BlobClosureEncryption,
    entries: Vec<ClosureEntrySpec>,
}

impl BlobClosureSpec {
    pub fn new(
        tenant_id: Uuid,
        authority_id: Uuid,
        generation: i64,
        encryption: BlobClosureEncryption,
        entries: Vec<ClosureEntrySpec>,
    ) -> Result<Self, BlobClosureError> {
        if tenant_id.is_nil() || authority_id.is_nil() || generation <= 0 {
            return Err(BlobClosureError::InvalidSpec(
                "closure needs non-nil tenant/authority and positive generation",
            ));
        }
        if entries.is_empty() {
            return Err(BlobClosureError::IncompleteClosure("closure must include at least one artifact"));
        }
        let mut seen = BTreeSet::new();
        for entry in &entries {
            if entry.locator.tenant_id() != tenant_id
                || entry.locator.authority_id() != authority_id
                || entry.locator.generation() != generation
            {
                return Err(BlobClosureError::InvalidSpec("entry locator scope disagrees with closure scope"));
            }
            match (encryption, &entry.envelope) {
                (BlobClosureEncryption::ProviderManaged, Some(_)) => {
                    return Err(BlobClosureError::EncryptionPolicyMismatch);
                }
                (BlobClosureEncryption::LocalEnvelope, None) => {
                    return Err(BlobClosureError::EncryptionPolicyMismatch);
                }
                (BlobClosureEncryption::LocalEnvelope, Some(env)) => {
                    env.validate()?;
                    if !env.matches_locator(&entry.locator) {
                        return Err(BlobClosureError::InvalidSpec("entry envelope does not match locator"));
                    }
                }
                (BlobClosureEncryption::ProviderManaged, None) => {}
            }
            if !seen.insert((entry.role, entry.locator.path())) {
                return Err(BlobClosureError::InvalidSpec("duplicate artifact entry in closure"));
            }
        }
        Ok(Self { tenant_id, authority_id, generation, encryption, entries })
    }

    /// Require that this closure contains a complete Git pack pair (`.pack` + `.idx`).
    pub fn require_git_pack_pair(&self) -> Result<(), BlobClosureError> {
        let has_pack = self.entries.iter().any(|entry| entry.role == ClosureArtifactRole::Pack);
        let has_idx = self.entries.iter().any(|entry| entry.role == ClosureArtifactRole::PackIndex);
        if !has_pack || !has_idx {
            return Err(BlobClosureError::IncompleteClosure("Git pack closure must include both Pack and PackIndex"));
        }
        Ok(())
    }

    pub fn entries(&self) -> &[ClosureEntrySpec] {
        &self.entries
    }
}

/// Verified per-artifact read-back record inside a [`BlobClosureProof`].
#[derive(Debug, Clone)]
pub struct VerifiedClosureArtifact {
    role: ClosureArtifactRole,
    receipt: BlobReceipt,
    plaintext_sha256: String,
    plaintext_length: u64,
    key_id: Option<KeyId>,
    envelope_id: Option<Uuid>,
}

impl VerifiedClosureArtifact {
    pub fn role(&self) -> ClosureArtifactRole {
        self.role
    }

    pub fn receipt(&self) -> &BlobReceipt {
        &self.receipt
    }

    pub fn locator(&self) -> &BlobLocator {
        self.receipt.locator()
    }

    pub fn plaintext_sha256(&self) -> &str {
        &self.plaintext_sha256
    }

    pub fn plaintext_length(&self) -> u64 {
        self.plaintext_length
    }

    pub fn key_id(&self) -> Option<&KeyId> {
        self.key_id.as_ref()
    }

    pub fn envelope_id(&self) -> Option<Uuid> {
        self.envelope_id
    }
}

/// Non-forgeable closure read-back proof produced only by [`BlobStore::verify_closure`].
#[derive(Debug, Clone)]
pub struct BlobClosureProof {
    backend_identity: BlobBackendIdentity,
    tenant_id: Uuid,
    authority_id: Uuid,
    generation: i64,
    encryption: BlobClosureEncryption,
    artifacts: Vec<VerifiedClosureArtifact>,
}

impl BlobClosureProof {
    pub fn backend_identity(&self) -> &BlobBackendIdentity {
        &self.backend_identity
    }

    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    pub fn authority_id(&self) -> Uuid {
        self.authority_id
    }

    pub fn generation(&self) -> i64 {
        self.generation
    }

    pub fn encryption(&self) -> BlobClosureEncryption {
        self.encryption
    }

    pub fn artifacts(&self) -> &[VerifiedClosureArtifact] {
        &self.artifacts
    }

    pub fn contains_role(&self, role: ClosureArtifactRole) -> bool {
        self.artifacts.iter().any(|item| item.role == role)
    }

    pub fn has_git_pack_pair(&self) -> bool {
        self.contains_role(ClosureArtifactRole::Pack) && self.contains_role(ClosureArtifactRole::PackIndex)
    }
}

impl BlobStore {
    /// Verify every artifact in `spec` via full remote Blob read-back (and full
    /// chunked AEAD decryption + key-unwrap in `local-envelope` mode) before
    /// minting a [`BlobClosureProof`].
    pub async fn verify_closure(
        &self,
        spec: &BlobClosureSpec,
        key_provider: Option<&Arc<dyn KeyProvider>>,
        staging_dir: Option<&Path>,
        deadline: Instant,
    ) -> Result<BlobClosureProof, BlobClosureError> {
        if Instant::now() >= deadline {
            return Err(BlobClosureError::Blob(BlobError::DeadlineExceeded));
        }
        let store_enc = self.profile().encryption();
        match spec.encryption {
            BlobClosureEncryption::ProviderManaged => {
                if store_enc.is_local_envelope() {
                    return Err(BlobClosureError::EncryptionPolicyMismatch);
                }
            }
            BlobClosureEncryption::LocalEnvelope => {
                if store_enc.is_explicit() && store_enc.is_provider_managed() {
                    return Err(BlobClosureError::EncryptionPolicyMismatch);
                }
                if key_provider.is_none() {
                    return Err(BlobClosureError::MissingKeyProvider);
                }
                if staging_dir.is_none() {
                    return Err(BlobClosureError::MissingStagingDir);
                }
            }
        }

        let mut artifacts = Vec::with_capacity(spec.entries.len());
        for entry in &spec.entries {
            let verified = match spec.encryption {
                BlobClosureEncryption::ProviderManaged => {
                    let receipt = self
                        .verify_receipt(&entry.locator, entry.locator.sha256(), entry.locator.length(), deadline)
                        .await?;
                    if receipt.backend_identity().as_hex() != self.backend_identity().as_hex() {
                        return Err(BlobClosureError::ForeignBackend);
                    }
                    let pt_sha = receipt.verified_sha256().to_owned();
                    let pt_len = receipt.verified_length();
                    check_expected_plaintext(entry, &pt_sha, pt_len)?;
                    VerifiedClosureArtifact {
                        role: entry.role,
                        receipt,
                        plaintext_sha256: pt_sha,
                        plaintext_length: pt_len,
                        key_id: None,
                        envelope_id: None,
                    }
                }
                BlobClosureEncryption::LocalEnvelope => {
                    let kp = key_provider.ok_or(BlobClosureError::MissingKeyProvider)?;
                    let dir = staging_dir.ok_or(BlobClosureError::MissingStagingDir)?;
                    let metadata = entry.envelope.as_ref().ok_or(BlobClosureError::EncryptionPolicyMismatch)?;
                    let enc_receipt = self.verify_encrypted_blob(&entry.locator, metadata, kp, dir, deadline).await?;
                    if enc_receipt.backend_identity().as_hex() != self.backend_identity().as_hex() {
                        return Err(BlobClosureError::ForeignBackend);
                    }
                    check_expected_plaintext(entry, enc_receipt.plaintext_sha256(), enc_receipt.plaintext_length())?;
                    VerifiedClosureArtifact {
                        role: entry.role,
                        receipt: enc_receipt.receipt().clone(),
                        plaintext_sha256: enc_receipt.plaintext_sha256().to_owned(),
                        plaintext_length: enc_receipt.plaintext_length(),
                        key_id: Some(enc_receipt.key_id().clone()),
                        envelope_id: Some(enc_receipt.envelope_id()),
                    }
                }
            };
            artifacts.push(verified);
        }

        Ok(BlobClosureProof {
            backend_identity: self.backend_identity().clone(),
            tenant_id: spec.tenant_id,
            authority_id: spec.authority_id,
            generation: spec.generation,
            encryption: spec.encryption,
            artifacts,
        })
    }
}

fn check_expected_plaintext(
    entry: &ClosureEntrySpec,
    actual_sha256: &str,
    actual_length: u64,
) -> Result<(), BlobClosureError> {
    if let Some(expected_len) = entry.expected_plaintext_length
        && expected_len != actual_length
    {
        return Err(BlobClosureError::PlaintextMismatch("verified plaintext length mismatch"));
    }
    if let Some(expected_sha) = entry.expected_plaintext_sha256.as_deref()
        && expected_sha != actual_sha256
    {
        return Err(BlobClosureError::PlaintextMismatch("verified plaintext sha256 mismatch"));
    }
    Ok(())
}
