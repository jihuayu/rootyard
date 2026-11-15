//! Client-side authenticated chunked AES-256-GCM payload envelope wired to
//! [`KeyProvider`](super::key_provider::KeyProvider).
//!
//! Each payload is sealed with a fresh 32-byte data-encryption key (`DataKey`),
//! split into bounded 64 KiB chunks authenticated independently with chunk index,
//! finality flag, envelope id, owner scope and plaintext digest in AAD. Only the
//! non-secret [`EnvelopeMetadata`] (containing a `KeyProvider`-wrapped DEK) is
//! serializable; plaintext keys are zeroized immediately after sealing or
//! decryption.

mod error;
mod io;

use std::{fmt, path::Path};

use ring::{
    aead::{self, LessSafeKey, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

pub use error::EnvelopeError;
use io::{
    ChunkAadParams, decode_nonce_prefix, decrypt_ciphertext_inner, encrypt_chunks, expected_ciphertext_length,
    hash_regular_file, validate_namespace, validate_sha256_hex,
};
pub(super) use io::{TempPathGuard, create_private_temp_file, verify_staging_dir};

use super::{
    BlobError, BlobLocator, MAX_OBJECT_BYTES,
    key_provider::{DATA_KEY_BYTES, KeyId, KeyProvider, KeyProviderError, WrapContext, WrappedKey},
};

pub const ENVELOPE_SCHEMA: u32 = 1;
pub const ENVELOPE_CIPHER: &str = "aes-256-gcm-chunked-v1";
pub const ENVELOPE_CHUNK_BYTES: usize = 64 * 1024;
pub const ENVELOPE_TAG_BYTES: usize = 16;
pub const ENVELOPE_NONCE_PREFIX_BYTES: usize = 4;
pub const MAX_ENVELOPE_METADATA_JSON_BYTES: usize = 8 * 1024;

/// Owner scope and namespace bound into a sealed envelope payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeSpec {
    pub tenant_id: Uuid,
    pub authority_id: Uuid,
    pub generation: i64,
    pub namespace: String,
}

impl EnvelopeSpec {
    pub fn validate(&self) -> Result<(), EnvelopeError> {
        if self.tenant_id.is_nil() || self.authority_id.is_nil() || self.generation <= 0 {
            return Err(EnvelopeError::Config("envelope scope needs valid tenant, authority and generation".into()));
        }
        validate_namespace(&self.namespace)
    }
}

/// Verified plaintext content identity returned on open or read-back check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaintextDigest {
    sha256: String,
    length: u64,
}

impl PlaintextDigest {
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn length(&self) -> u64 {
        self.length
    }
}

/// Serializable, non-secret envelope header persisted alongside an immutable
/// ciphertext [`BlobLocator`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeMetadata {
    schema: u32,
    cipher: String,
    envelope_id: Uuid,
    nonce_prefix: String,
    chunk_bytes: u32,
    tenant_id: Uuid,
    authority_id: Uuid,
    generation: i64,
    attempt_id: Uuid,
    namespace: String,
    plaintext_sha256: String,
    plaintext_length: u64,
    ciphertext_sha256: String,
    ciphertext_length: u64,
    wrapped_key_json: String,
}

impl EnvelopeMetadata {
    pub fn from_json(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() > MAX_ENVELOPE_METADATA_JSON_BYTES {
            return Err(EnvelopeError::MetadataCorrupt("metadata JSON exceeds maximum size"));
        }
        let parsed: Self = serde_json::from_slice(bytes)
            .map_err(|_| EnvelopeError::MetadataCorrupt("metadata JSON is invalid or has unknown fields"))?;
        parsed.validate()?;
        Ok(parsed)
    }

    pub fn to_json(&self) -> Result<String, EnvelopeError> {
        self.validate()?;
        serde_json::to_string(self).map_err(|_| EnvelopeError::MetadataCorrupt("failed to serialize metadata"))
    }

    pub fn schema(&self) -> u32 {
        self.schema
    }
    pub fn cipher(&self) -> &str {
        &self.cipher
    }
    pub fn envelope_id(&self) -> Uuid {
        self.envelope_id
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
    pub fn attempt_id(&self) -> Uuid {
        self.attempt_id
    }
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
    pub fn plaintext_sha256(&self) -> &str {
        &self.plaintext_sha256
    }
    pub fn plaintext_length(&self) -> u64 {
        self.plaintext_length
    }
    pub fn ciphertext_sha256(&self) -> &str {
        &self.ciphertext_sha256
    }
    pub fn ciphertext_length(&self) -> u64 {
        self.ciphertext_length
    }
    pub fn chunk_bytes(&self) -> u32 {
        self.chunk_bytes
    }

    pub fn key_id(&self) -> Result<KeyId, EnvelopeError> {
        Ok(self.wrapped_key()?.key_id().clone())
    }

    pub fn wrapped_key(&self) -> Result<WrappedKey, EnvelopeError> {
        Ok(WrappedKey::from_json(self.wrapped_key_json.as_bytes())?)
    }

    pub fn wrap_context(&self) -> Result<WrapContext, EnvelopeError> {
        Ok(WrapContext::new(
            self.tenant_id,
            self.authority_id,
            self.generation,
            self.attempt_id,
            &self.namespace,
            &self.plaintext_sha256,
        )?)
    }

    pub fn matches_locator(&self, locator: &BlobLocator) -> bool {
        self.tenant_id == locator.tenant_id()
            && self.authority_id == locator.authority_id()
            && self.generation == locator.generation()
            && self.attempt_id == locator.attempt_id()
            && self.namespace == locator.namespace()
            && self.ciphertext_sha256 == locator.sha256()
            && self.ciphertext_length == locator.length()
    }

    pub fn validate(&self) -> Result<(), EnvelopeError> {
        if self.schema != ENVELOPE_SCHEMA {
            return Err(EnvelopeError::UnsupportedFormat(format!("schema {}", self.schema)));
        }
        if self.cipher != ENVELOPE_CIPHER {
            return Err(EnvelopeError::UnsupportedFormat(format!("cipher {}", self.cipher)));
        }
        if self.envelope_id.is_nil()
            || self.tenant_id.is_nil()
            || self.authority_id.is_nil()
            || self.attempt_id.is_nil()
        {
            return Err(EnvelopeError::MetadataCorrupt("nil UUID in envelope metadata"));
        }
        if self.generation <= 0 {
            return Err(EnvelopeError::MetadataCorrupt("non-positive authority generation"));
        }
        if self.chunk_bytes != ENVELOPE_CHUNK_BYTES as u32 {
            return Err(EnvelopeError::UnsupportedFormat(format!("chunk size {}", self.chunk_bytes)));
        }
        decode_nonce_prefix(&self.nonce_prefix)?;
        validate_namespace(&self.namespace)?;
        validate_sha256_hex(&self.plaintext_sha256, "invalid plaintext sha256")?;
        validate_sha256_hex(&self.ciphertext_sha256, "invalid ciphertext sha256")?;
        if self.plaintext_length > MAX_OBJECT_BYTES || self.ciphertext_length > MAX_OBJECT_BYTES {
            return Err(EnvelopeError::MetadataCorrupt("object length exceeds ceiling"));
        }
        let expected_ct = expected_ciphertext_length(self.plaintext_length, self.chunk_bytes)?;
        if self.ciphertext_length != expected_ct {
            return Err(EnvelopeError::MetadataCorrupt("ciphertext length disagrees with chunk framing"));
        }
        self.wrapped_key()?;
        self.wrap_context()?;
        Ok(())
    }

    fn aad_params(&self) -> ChunkAadParams<'_> {
        ChunkAadParams {
            envelope_id: self.envelope_id,
            tenant_id: self.tenant_id,
            authority_id: self.authority_id,
            generation: self.generation,
            namespace: &self.namespace,
            plaintext_sha256: &self.plaintext_sha256,
            plaintext_length: self.plaintext_length,
            chunk_bytes: self.chunk_bytes,
        }
    }
}

impl fmt::Debug for EnvelopeMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnvelopeMetadata")
            .field("schema", &self.schema)
            .field("cipher", &self.cipher)
            .field("namespace", &self.namespace)
            .field("plaintext_length", &self.plaintext_length)
            .field("ciphertext_length", &self.ciphertext_length)
            .field("wrapped_key", &"<redacted>")
            .finish()
    }
}

/// Phase-1 staged ciphertext awaiting an attempt-bound [`BlobLocator`] so its
/// in-memory DEK can be wrapped and zeroized.
pub struct PreparedCiphertext {
    staging_file: TempPathGuard,
    dek: Zeroizing<[u8; DATA_KEY_BYTES]>,
    envelope_id: Uuid,
    nonce_prefix: [u8; ENVELOPE_NONCE_PREFIX_BYTES],
    spec: EnvelopeSpec,
    plaintext_sha256: String,
    plaintext_length: u64,
    ciphertext_sha256: String,
    ciphertext_length: u64,
}

impl PreparedCiphertext {
    pub fn ciphertext_sha256(&self) -> &str {
        &self.ciphertext_sha256
    }

    pub fn ciphertext_length(&self) -> u64 {
        self.ciphertext_length
    }

    pub fn plaintext_sha256(&self) -> &str {
        &self.plaintext_sha256
    }

    pub fn plaintext_length(&self) -> u64 {
        self.plaintext_length
    }

    pub fn ciphertext_path(&self) -> &Path {
        self.staging_file.path()
    }

    /// Bind this ciphertext to a store-minted `locator` (including its random
    /// `attempt_id`), wrap the ephemeral DEK via `key_provider`, and drop the
    /// plaintext DEK immediately.
    pub fn bind_and_wrap(
        self,
        key_provider: &dyn KeyProvider,
        locator: &BlobLocator,
    ) -> Result<SealedCiphertext, EnvelopeError> {
        ensure_local_envelope_provider(key_provider)?;
        if locator.tenant_id() != self.spec.tenant_id
            || locator.authority_id() != self.spec.authority_id
            || locator.generation() != self.spec.generation
            || locator.namespace() != self.spec.namespace
            || locator.sha256() != self.ciphertext_sha256
            || locator.length() != self.ciphertext_length
        {
            return Err(EnvelopeError::MetadataCorrupt("locator does not match prepared ciphertext"));
        }
        let wrap_ctx = WrapContext::new(
            locator.tenant_id(),
            locator.authority_id(),
            locator.generation(),
            locator.attempt_id(),
            locator.namespace(),
            &self.plaintext_sha256,
        )?;
        let wrapped = key_provider.wrap_data_key(&self.dek, &wrap_ctx)?;
        drop(self.dek);
        let metadata = EnvelopeMetadata {
            schema: ENVELOPE_SCHEMA,
            cipher: ENVELOPE_CIPHER.to_owned(),
            envelope_id: self.envelope_id,
            nonce_prefix: hex::encode(self.nonce_prefix),
            chunk_bytes: ENVELOPE_CHUNK_BYTES as u32,
            tenant_id: locator.tenant_id(),
            authority_id: locator.authority_id(),
            generation: locator.generation(),
            attempt_id: locator.attempt_id(),
            namespace: locator.namespace().to_owned(),
            plaintext_sha256: self.plaintext_sha256,
            plaintext_length: self.plaintext_length,
            ciphertext_sha256: self.ciphertext_sha256,
            ciphertext_length: self.ciphertext_length,
            wrapped_key_json: wrapped.to_json()?,
        };
        metadata.validate()?;
        Ok(SealedCiphertext { staging_file: self.staging_file, metadata })
    }
}

/// Phase-2 sealed ciphertext staging file paired with its wrapped [`EnvelopeMetadata`].
/// Drops and removes its staging ciphertext file automatically unless consumed.
pub struct SealedCiphertext {
    staging_file: TempPathGuard,
    metadata: EnvelopeMetadata,
}

impl SealedCiphertext {
    pub fn ciphertext_path(&self) -> &Path {
        self.staging_file.path()
    }

    pub fn metadata(&self) -> &EnvelopeMetadata {
        &self.metadata
    }

    pub fn into_parts(self) -> (TempPathGuard, EnvelopeMetadata) {
        (self.staging_file, self.metadata)
    }
}

/// Encrypt a regular local `source` file into a private `0o600` ciphertext temp
/// file under `staging_dir`. Does not touch any remote provider.
pub fn prepare_file_envelope(
    spec: &EnvelopeSpec,
    source: &Path,
    staging_dir: &Path,
    max_object_bytes: u64,
) -> Result<PreparedCiphertext, EnvelopeError> {
    spec.validate()?;
    verify_staging_dir(staging_dir)?;
    let (plaintext_sha256, plaintext_length) = hash_regular_file(source, max_object_bytes)?;
    let expected_ct = expected_ciphertext_length(plaintext_length, ENVELOPE_CHUNK_BYTES as u32)?;
    if expected_ct > max_object_bytes || expected_ct > MAX_OBJECT_BYTES {
        return Err(EnvelopeError::Blob(BlobError::LengthMismatch {
            expected: max_object_bytes.min(MAX_OBJECT_BYTES),
            actual: expected_ct,
        }));
    }

    let rng = SystemRandom::new();
    let mut dek = Zeroizing::new([0u8; DATA_KEY_BYTES]);
    rng.fill(&mut *dek).map_err(|_| KeyProviderError::RandomUnavailable)?;
    let mut nonce_prefix = [0u8; ENVELOPE_NONCE_PREFIX_BYTES];
    rng.fill(&mut nonce_prefix).map_err(|_| KeyProviderError::RandomUnavailable)?;
    let envelope_id = Uuid::new_v4();

    let (staging_file, dst) = create_private_temp_file(staging_dir, "ct")?;
    let key = LessSafeKey::new(UnboundKey::new(&aead::AES_256_GCM, &*dek).map_err(|_| KeyProviderError::CipherSetup)?);
    let aad_params = ChunkAadParams {
        envelope_id,
        tenant_id: spec.tenant_id,
        authority_id: spec.authority_id,
        generation: spec.generation,
        namespace: &spec.namespace,
        plaintext_sha256: &plaintext_sha256,
        plaintext_length,
        chunk_bytes: ENVELOPE_CHUNK_BYTES as u32,
    };

    let (ciphertext_sha256, ciphertext_length) =
        encrypt_chunks(source, dst, &key, &nonce_prefix, &aad_params, plaintext_length)?;
    if ciphertext_length != expected_ct {
        return Err(EnvelopeError::Io("encrypted file length did not match expected chunk framing"));
    }

    Ok(PreparedCiphertext {
        staging_file,
        dek,
        envelope_id,
        nonce_prefix,
        spec: spec.clone(),
        plaintext_sha256,
        plaintext_length,
        ciphertext_sha256,
        ciphertext_length,
    })
}

/// Authenticate and decrypt `ciphertext_path` using `metadata` and `key_provider`,
/// atomically writing the verified plaintext into `destination`.
pub fn open_ciphertext_file_to_path(
    metadata: &EnvelopeMetadata,
    key_provider: &dyn KeyProvider,
    ciphertext_path: &Path,
    destination: &Path,
) -> Result<PlaintextDigest, EnvelopeError> {
    decrypt_ciphertext_inner(metadata, key_provider, ciphertext_path, Some(destination))
}

/// Authenticate and verify `ciphertext_path` in full without materializing a
/// plaintext output file on disk.
pub fn verify_ciphertext_file(
    metadata: &EnvelopeMetadata,
    key_provider: &dyn KeyProvider,
    ciphertext_path: &Path,
) -> Result<PlaintextDigest, EnvelopeError> {
    decrypt_ciphertext_inner(metadata, key_provider, ciphertext_path, None)
}

/// Re-wrap `metadata` under `key_provider`'s current active key without reading
/// or modifying the immutable remote ciphertext object.
pub fn rewrap_envelope_metadata(
    metadata: &EnvelopeMetadata,
    key_provider: &dyn KeyProvider,
) -> Result<EnvelopeMetadata, EnvelopeError> {
    ensure_local_envelope_provider(key_provider)?;
    if !key_provider.capabilities().rewrap {
        return Err(EnvelopeError::Config("active KeyProvider does not support metadata rewrap".into()));
    }
    metadata.validate()?;
    let wrapped = metadata.wrapped_key()?;
    let context = metadata.wrap_context()?;
    let rotated = key_provider.rewrap_data_key(&wrapped, &context)?;
    let mut updated = metadata.clone();
    updated.wrapped_key_json = rotated.to_json()?;
    updated.validate()?;
    Ok(updated)
}

pub(super) fn ensure_local_envelope_provider(provider: &dyn KeyProvider) -> Result<(), EnvelopeError> {
    let caps = provider.capabilities();
    if !caps.local_envelope || caps.plaintext_fallback {
        return Err(EnvelopeError::EncryptionPolicyMismatch);
    }
    Ok(())
}
