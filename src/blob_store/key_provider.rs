//! Independent local-envelope `KeyProvider` for 32-byte data keys (#109).
//!
//! This module is a self-contained component. It does **not** change the legacy
//! `crate::storage::encrypted_objects::Envelope`/Vault byte format, does not
//! touch its callsites, and is not yet wired into serving, Blob publication,
//! backup, schema or runtime selection. Wrapping a data key here is a thin
//! envelope over ring's AES-256-GCM; no cipher, KDF or encoding is implemented
//! by this crate.
//!
//! # Keyring and key identity
//!
//! [`LocalFileKeyProvider::load`] is an explicit configuration-time operation.
//! It takes a clean absolute keyring directory that must be owned by the effective
//! uid with mode exactly `0700`. The directory holds:
//!
//! * `keyring.json` (regular file, owner euid, mode `0600`, at most 16 KiB) with
//!   schema, the explicit `current` key id and a list of `key_id`/`sha256`
//!   entries. The SHA-256 is over the raw 32-byte key file and makes the key id's
//!   external identity stable: replacing the bytes behind an existing id makes
//!   loading fail instead of silently changing a key version.
//! * `<key_id>.key` files (regular files, owner euid, mode `0600`, exactly 32
//!   bytes). The directory and each file are opened relative to a pinned
//!   directory descriptor with `O_NOFOLLOW|O_NONBLOCK`; every descriptor is
//!   `fstat`-checked before its bounded read, so a symlink, FIFO, device,
//!   directory, wrong owner, wrong mode or wrong length is refused.
//!
//! Keys are loaded once into zeroizing memory. Later file replacement does not
//! change a running provider, and there is no reload, generation, replacement or
//! deletion API. This snapshot is pinned in process memory only: it is not
//! `mlock`ed, not protected from same-uid process inspection, and Rust zeroize
//! wipes only the buffers this module owns. ring does not document erasure of
//! its expanded AES key state, so no secure-erasure claim is made beyond the
//! zeroize semantics of our buffers.
//!
//! # Honest path policy
//!
//! The keyring directory path must be a clean absolute path (no `.`/`..`
//! components), and its final component is opened with `O_NOFOLLOW`; this avoids
//! a racy relative lookup. Intermediate path
//! components are resolved by the kernel and are **not** re-walked or
//! independently pinned; the configured path must therefore live on an
//! operator-controlled filesystem that other users cannot rename or replace.
//! Entries inside a mode-`0700` directory are opened with `openat` on the pinned
//! descriptor, which prevents key-file path TOCTOU. A same-uid attacker is out of
//! scope: it can read the process/keyring anyway. Permission bits are checked,
//! not POSIX ACLs, immutable mounts, fs-verity or similar.
//!
//! # Backup and rotation boundary
//!
//! Backup manifests may record the non-secret `key_id` and wrapped metadata,
//! never the KEK or the keyring files. A restore needs the same key ids
//! provisioned out of band; a missing or mismatched key fails closed. Rotation
//! adds a new key id and selects it as `current`; old ids stay loaded so old
//! wrapped keys remain readable. [`KeyProvider::rewrap_data_key`] re-wraps the
//! same DEK under the current key and changes only wrapped metadata. This module
//! does not persist rewrap receipts or switch object references, and it exposes
//! no key deletion API: retaining old ids until every reference is rewrapped and
//! every dependent backup has expired remains an operator obligation.
//!
//! # Execution model
//!
//! Wrapping, unwrapping and rewrapping are synchronous CPU-only AES-GCM calls
//! over caller-provided metadata. File IO exists only in [`LocalFileKeyProvider::load`]
//! and is intentionally blocking, so callers must run it during configuration or
//! startup (or move it to `spawn_blocking`), never hidden on a request runtime.

use std::{
    collections::BTreeMap,
    ffi::CString,
    fmt,
    fs::{File, OpenOptions},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path},
};

use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Version of the wrapped-key metadata and AAD transcript.
pub const WRAP_FORMAT_VERSION: u32 = 1;
pub const DATA_KEY_BYTES: usize = 32;
pub const NONCE_BYTES: usize = 12;
pub const TAG_BYTES: usize = 16;
pub const WRAPPED_DEK_BYTES: usize = DATA_KEY_BYTES + TAG_BYTES;

pub const AAD_DIGEST_BYTES: usize = 32;
const AAD_DOMAIN: &[u8] = b"rootyard/blob-store/key-provider/dek-wrap";
const KEYRING_MANIFEST: &str = "keyring.json";
const KEYRING_SCHEMA: u32 = 1;
const MAX_KEYRING_MANIFEST_BYTES: u64 = 16 * 1024;
const MAX_KEYRING_ENTRIES: usize = 16;
const MAX_WRAPPED_KEY_JSON_BYTES: usize = 1024;

/// Explicit key version identity used in wrapped metadata and AAD. It is not a
/// secret, but it is stable: a keyring manifest binds it to the SHA-256 of its
/// key bytes.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId(String);

impl KeyId {
    /// Accept only file-name-safe ids so a manifest entry can never select a
    /// path outside the pinned keyring directory.
    pub fn parse(value: &str) -> Result<Self, KeyProviderError> {
        let valid = value.len() <= 64
            && value.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.');
        if !valid {
            return Err(KeyProviderError::InvalidKeyId);
        }
        Ok(Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("KeyId").field(&self.0).finish()
    }
}

impl fmt::Display for KeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Fail-closed provider errors. Messages and `Debug` output contain no key
/// material, no plaintext DEK, no wrapped bytes and no filesystem paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyProviderError {
    InvalidKeyId,
    InvalidContext,
    KeyRing(&'static str),
    KeyFile(&'static str),
    KeyIdentityMismatch(KeyId),
    MissingKey(KeyId),
    UnsupportedVersion(u32),
    InvalidWrappedKey(&'static str),
    ContextMismatch,
    AuthenticationFailed,
    CipherSetup,
    RandomUnavailable,
    Serialization,
}

impl fmt::Display for KeyProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyId => f.write_str("invalid key id"),
            Self::InvalidContext => f.write_str("invalid key-wrap context"),
            Self::KeyRing(reason) => write!(f, "keyring rejected: {reason}"),
            Self::KeyFile(reason) => write!(f, "key file rejected: {reason}"),
            Self::KeyIdentityMismatch(id) => {
                write!(f, "key file bytes do not match the manifest identity for key id `{id}`")
            }
            Self::MissingKey(id) => write!(f, "key id `{id}` is not available in this keyring"),
            Self::UnsupportedVersion(version) => write!(f, "unsupported wrapped-key version {version}"),
            Self::InvalidWrappedKey(reason) => write!(f, "invalid wrapped key metadata: {reason}"),
            Self::ContextMismatch => f.write_str("wrapped key AAD does not match the supplied context"),
            Self::AuthenticationFailed => f.write_str("wrapped key authentication failed"),
            Self::CipherSetup => f.write_str("AES-256-GCM setup failed"),
            Self::RandomUnavailable => f.write_str("system random source is unavailable"),
            Self::Serialization => f.write_str("wrapped key metadata could not be serialized"),
        }
    }
}

impl std::error::Error for KeyProviderError {}

/// Static capability description. `plaintext_fallback` is always `false` for
/// this provider; there is no configuration that enables plaintext storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyProviderCapabilities {
    pub local_envelope: bool,
    pub rewrap: bool,
    pub retained_key_versions: bool,
    pub provider_managed: bool,
    pub plaintext_fallback: bool,
}

/// Typed, validated identity of one wrapped object. Every variable field is
/// length-delimited in the AAD transcript, so moving bytes between adjacent
/// fields cannot create an ambiguous binding.
#[derive(Clone, PartialEq, Eq)]
pub struct WrapContext {
    tenant_id: Uuid,
    authority_id: Uuid,
    object_generation: i64,
    attempt_id: Uuid,
    namespace: String,
    content_digest: String,
}

impl WrapContext {
    pub fn new(
        tenant_id: Uuid,
        authority_id: Uuid,
        object_generation: i64,
        attempt_id: Uuid,
        namespace: &str,
        content_digest: &str,
    ) -> Result<Self, KeyProviderError> {
        if tenant_id.is_nil() || authority_id.is_nil() || attempt_id.is_nil() || object_generation <= 0 {
            return Err(KeyProviderError::InvalidContext);
        }
        if namespace.is_empty()
            || namespace.len() > super::MAX_NAMESPACE_BYTES
            || !namespace.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(KeyProviderError::InvalidContext);
        }
        if content_digest.len() != 64
            || !content_digest.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(KeyProviderError::InvalidContext);
        }
        Ok(Self {
            tenant_id,
            authority_id,
            object_generation,
            attempt_id,
            namespace: namespace.to_owned(),
            content_digest: content_digest.to_owned(),
        })
    }

    /// Canonical, non-secret AAD transcript for the current wrap version.
    pub fn aad(&self, key_id: &KeyId) -> Vec<u8> {
        let mut aad = Vec::with_capacity(256);
        push_field(&mut aad, AAD_DOMAIN);
        push_field(&mut aad, &WRAP_FORMAT_VERSION.to_be_bytes());
        push_field(&mut aad, key_id.as_str().as_bytes());
        push_field(&mut aad, self.tenant_id.as_bytes());
        push_field(&mut aad, self.authority_id.as_bytes());
        push_field(&mut aad, &self.object_generation.to_be_bytes());
        push_field(&mut aad, self.attempt_id.as_bytes());
        push_field(&mut aad, self.namespace.as_bytes());
        push_field(&mut aad, self.content_digest.as_bytes());
        aad
    }

    pub fn aad_digest(&self, key_id: &KeyId) -> [u8; AAD_DIGEST_BYTES] {
        sha256_array(&self.aad(key_id))
    }
}

impl fmt::Debug for WrapContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WrapContext")
            .field("tenant", &"<redacted>")
            .field("authority", &"<redacted>")
            .field("generation", &self.object_generation)
            .field("attempt", &"<redacted>")
            .field("namespace", &self.namespace)
            .field("content_digest", &"<redacted>")
            .finish()
    }
}

fn push_field(out: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
}

/// Authenticated wrapped data key. Only non-secret metadata is stored; the KEK
/// and plaintext DEK never appear in this value, its JSON form or `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct WrappedKey {
    version: u32,
    key_id: KeyId,
    nonce: [u8; NONCE_BYTES],
    wrapped_dek: [u8; WRAPPED_DEK_BYTES],
    aad_digest: [u8; AAD_DIGEST_BYTES],
}

impl WrappedKey {
    pub fn version(&self) -> u32 {
        self.version
    }
    pub fn key_id(&self) -> &KeyId {
        &self.key_id
    }
    pub fn nonce(&self) -> &[u8; NONCE_BYTES] {
        &self.nonce
    }
    pub fn wrapped_dek(&self) -> &[u8; WRAPPED_DEK_BYTES] {
        &self.wrapped_dek
    }
    pub fn aad_digest(&self) -> &[u8; AAD_DIGEST_BYTES] {
        &self.aad_digest
    }

    fn validate(&self) -> Result<(), KeyProviderError> {
        if self.version != WRAP_FORMAT_VERSION {
            return Err(KeyProviderError::UnsupportedVersion(self.version));
        }
        Ok(())
    }

    /// Parse bounded, non-secret metadata. Lengths, key id, version and the
    /// fixed nonce/tag/digest sizes are validated before any decryption.
    pub fn from_json(bytes: &[u8]) -> Result<Self, KeyProviderError> {
        if bytes.len() > MAX_WRAPPED_KEY_JSON_BYTES {
            return Err(KeyProviderError::InvalidWrappedKey("metadata exceeds the size limit"));
        }
        let wire: WrappedKeyWire = serde_json::from_slice(bytes)
            .map_err(|_| KeyProviderError::InvalidWrappedKey("metadata is not valid JSON"))?;
        if wire.version != WRAP_FORMAT_VERSION {
            return Err(KeyProviderError::UnsupportedVersion(wire.version));
        }
        Ok(Self {
            version: wire.version,
            key_id: KeyId::parse(&wire.key_id)?,
            nonce: decode_exact(&wire.nonce, "bad nonce length")?,
            wrapped_dek: decode_exact(&wire.wrapped_dek, "bad wrapped key length")?,
            aad_digest: decode_exact(&wire.aad_digest, "bad AAD digest length")?,
        })
    }

    /// Serialize only the non-secret envelope metadata. The KEK and DEK never
    /// enter this representation.
    pub fn to_json(&self) -> Result<String, KeyProviderError> {
        serde_json::to_string(&WrappedKeyWire {
            version: self.version,
            key_id: self.key_id.as_str().to_owned(),
            nonce: hex::encode(self.nonce),
            wrapped_dek: hex::encode(self.wrapped_dek),
            aad_digest: hex::encode(self.aad_digest),
        })
        .map_err(|_| KeyProviderError::Serialization)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WrappedKeyWire {
    version: u32,
    key_id: String,
    nonce: String,
    wrapped_dek: String,
    aad_digest: String,
}

impl fmt::Debug for WrappedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WrappedKey")
            .field("version", &self.version)
            .field("key_id", &"<redacted>")
            .field("nonce", &"<redacted>")
            .field("wrapped_dek", &"<redacted>")
            .field("aad_digest", &"<redacted>")
            .finish()
    }
}

fn decode_exact<const N: usize>(value: &str, reason: &'static str) -> Result<[u8; N], KeyProviderError> {
    if value.len() != N * 2 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(KeyProviderError::InvalidWrappedKey(reason));
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(value, &mut out).map_err(|_| KeyProviderError::InvalidWrappedKey(reason))?;
    Ok(out)
}

/// Returned plaintext data key. `Zeroizing` wipes the bytes on drop, but its
/// `Debug` prints the array, so this type redacts explicitly.
pub struct DataKey {
    bytes: Zeroizing<[u8; DATA_KEY_BYTES]>,
}

impl DataKey {
    fn new(bytes: [u8; DATA_KEY_BYTES]) -> Self {
        Self { bytes: Zeroizing::new(bytes) }
    }

    /// Borrow the plaintext key for the data-cipher call. Callers must not log,
    /// serialize or copy it into unzeroized storage.
    pub fn expose_secret(&self) -> &[u8; DATA_KEY_BYTES] {
        &self.bytes
    }
}

impl fmt::Debug for DataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DataKey(<redacted>)")
    }
}

/// Typed provider contract. Implementations must not silently return plaintext,
/// generate missing keys, or select a different key id than the one recorded in
/// [`WrappedKey`]; an unknown id must fail closed.
pub trait KeyProvider: fmt::Debug + Send + Sync {
    fn current_key_id(&self) -> &KeyId;
    fn wrap_data_key(
        &self,
        data_key: &[u8; DATA_KEY_BYTES],
        context: &WrapContext,
    ) -> Result<WrappedKey, KeyProviderError>;
    fn unwrap_data_key(
        &self,
        wrapped: &WrappedKey,
        context: &WrapContext,
    ) -> Result<DataKey, KeyProviderError>;
    fn capabilities(&self) -> KeyProviderCapabilities;

    /// Default rewrap keeps the DEK byte-for-byte and only mints new wrapped
    /// metadata under the provider's current key.
    fn rewrap_data_key(
        &self,
        wrapped: &WrappedKey,
        context: &WrapContext,
    ) -> Result<WrappedKey, KeyProviderError> {
        let data_key = self.unwrap_data_key(wrapped, context)?;
        self.wrap_data_key(data_key.expose_secret(), context)
    }
}

/// Local keyring-backed provider. Key material is loaded once, validated against
/// the manifest fingerprint, and stored in zeroizing buffers with no reload or
/// deletion path.
pub struct LocalFileKeyProvider {
    current: KeyId,
    keys: BTreeMap<KeyId, Zeroizing<[u8; DATA_KEY_BYTES]>>,
}

impl LocalFileKeyProvider {
    /// Load and validate the keyring. This is intentionally blocking
    /// configuration-time IO; call it during startup, not on a request path.
    pub fn load(directory: &Path) -> Result<Self, KeyProviderError> {
        let directory = open_keyring_dir(directory)?;
        let manifest = read_manifest(&directory)?;
        let mut keys = BTreeMap::new();
        for entry in &manifest.keys {
            let name = format!("{}.key", entry.key_id);
            let file = open_dir_entry(&directory, &name, KeyProviderError::KeyFile)?;
            let key = read_key_file(file)?;
            let actual = sha256_array(&key[..]);
            // Both values are public fingerprints, not secret key bytes.
            if actual != entry.fingerprint {
                return Err(KeyProviderError::KeyIdentityMismatch(entry.key_id.clone()));
            }
            keys.insert(entry.key_id.clone(), key);
        }
        Ok(Self { current: manifest.current, keys })
    }

    fn key(&self, key_id: &KeyId) -> Result<&Zeroizing<[u8; DATA_KEY_BYTES]>, KeyProviderError> {
        self.keys.get(key_id).ok_or_else(|| KeyProviderError::MissingKey(key_id.clone()))
    }

    fn wrap_with(
        &self,
        key_id: &KeyId,
        data_key: &[u8; DATA_KEY_BYTES],
        context: &WrapContext,
    ) -> Result<WrappedKey, KeyProviderError> {
        let kek = self.key(key_id)?;
        let mut nonce = [0u8; NONCE_BYTES];
        SystemRandom::new().fill(&mut nonce).map_err(|_| KeyProviderError::RandomUnavailable)?;
        let aad = context.aad(key_id);
        let wrapped_dek = seal(kek, &nonce, &aad, data_key)?;
        Ok(WrappedKey {
            version: WRAP_FORMAT_VERSION,
            key_id: key_id.clone(),
            nonce,
            wrapped_dek,
            aad_digest: sha256_array(&aad),
        })
    }
}

impl KeyProvider for LocalFileKeyProvider {
    fn current_key_id(&self) -> &KeyId {
        &self.current
    }

    fn wrap_data_key(
        &self,
        data_key: &[u8; DATA_KEY_BYTES],
        context: &WrapContext,
    ) -> Result<WrappedKey, KeyProviderError> {
        // New wraps always use the explicitly configured current key.
        self.wrap_with(&self.current, data_key, context)
    }

    fn unwrap_data_key(
        &self,
        wrapped: &WrappedKey,
        context: &WrapContext,
    ) -> Result<DataKey, KeyProviderError> {
        wrapped.validate()?;
        // Select exactly the recorded id; never try other retained keys.
        let kek = self.key(wrapped.key_id())?;
        let aad = context.aad(wrapped.key_id());
        let expected = sha256_array(&aad);
        // The digest and all AAD inputs are public metadata; the AEAD tag still
        // authenticates them with the secret key.
        if expected != wrapped.aad_digest {
            return Err(KeyProviderError::ContextMismatch);
        }
        let data_key = open(kek, &wrapped.nonce, &aad, &wrapped.wrapped_dek)?;
        Ok(DataKey::new(data_key))
    }

    fn capabilities(&self) -> KeyProviderCapabilities {
        KeyProviderCapabilities {
            local_envelope: true,
            rewrap: true,
            retained_key_versions: true,
            provider_managed: false,
            plaintext_fallback: false,
        }
    }
}

impl fmt::Debug for LocalFileKeyProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalFileKeyProvider")
            .field("current_key_id", &self.current)
            .field("retained_key_ids", &self.keys.keys().collect::<Vec<_>>())
            .field("key_material", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KeyRing {
    current: KeyId,
    keys: Vec<KeyRingEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KeyRingEntry {
    key_id: KeyId,
    fingerprint: [u8; AAD_DIGEST_BYTES],
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyRingWire {
    schema: u32,
    current: String,
    keys: Vec<KeyRingEntryWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyRingEntryWire {
    key_id: String,
    sha256: String,
}

fn parse_manifest(bytes: &[u8]) -> Result<KeyRing, KeyProviderError> {
    let wire: KeyRingWire = serde_json::from_slice(bytes)
        .map_err(|_| KeyProviderError::KeyRing("manifest is not valid JSON"))?;
    if wire.schema != KEYRING_SCHEMA {
        return Err(KeyProviderError::KeyRing("unsupported manifest schema"));
    }
    if wire.keys.is_empty() || wire.keys.len() > MAX_KEYRING_ENTRIES {
        return Err(KeyProviderError::KeyRing("manifest key count is out of range"));
    }
    let current = KeyId::parse(&wire.current)?;
    let mut keys = Vec::with_capacity(wire.keys.len());
    for entry in wire.keys {
        let key_id = KeyId::parse(&entry.key_id)?;
        if keys.iter().any(|seen: &KeyRingEntry| seen.key_id == key_id) {
            return Err(KeyProviderError::KeyRing("duplicate key id"));
        }
        let fingerprint = decode_exact::<AAD_DIGEST_BYTES>(&entry.sha256, "manifest fingerprint is malformed")
            .map_err(|_| KeyProviderError::KeyRing("manifest fingerprint is malformed"))?;
        keys.push(KeyRingEntry { key_id, fingerprint });
    }
    if !keys.iter().any(|entry| entry.key_id == current) {
        return Err(KeyProviderError::KeyRing("current key id is not listed"));
    }
    Ok(KeyRing { current, keys })
}

fn open_keyring_dir(directory: &Path) -> Result<File, KeyProviderError> {
    let clean = directory.is_absolute()
        && directory
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)));
    if !clean {
        return Err(KeyProviderError::KeyRing("keyring directory must be a clean absolute path"));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory)
        .map_err(|_| KeyProviderError::KeyRing("keyring directory cannot be opened"))?;
    let metadata = file.metadata().map_err(|_| KeyProviderError::KeyRing("directory metadata failed"))?;
    if !metadata.is_dir() {
        return Err(KeyProviderError::KeyRing("keyring path is not a directory"));
    }
    if metadata.uid() != libc::geteuid() {
        return Err(KeyProviderError::KeyRing("keyring directory owner is not the effective uid"));
    }
    if metadata.mode() & 0o777 != 0o700 {
        return Err(KeyProviderError::KeyRing("keyring directory mode must be exactly 0700"));
    }
    Ok(file)
}

fn open_dir_entry(
    directory: &File,
    name: &str,
    reject: fn(&'static str) -> KeyProviderError,
) -> Result<File, KeyProviderError> {
    let name = CString::new(name).map_err(|_| reject("entry name is invalid"))?;
    // SAFETY: `directory` is a live directory descriptor, `name` is a valid
    // NUL-terminated path component, and the flags never create or truncate.
    // On success the returned descriptor is immediately owned by `File`.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(reject("entry cannot be opened without following symlinks"));
    }
    // SAFETY: `fd` is a fresh, non-negative descriptor owned by this function.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn read_manifest(directory: &File) -> Result<KeyRing, KeyProviderError> {
    let file = open_dir_entry(directory, KEYRING_MANIFEST, KeyProviderError::KeyRing)?;
    let bytes = read_regular(file, MAX_KEYRING_MANIFEST_BYTES, None, KeyProviderError::KeyRing)?;
    parse_manifest(&bytes)
}

fn read_key_file(file: File) -> Result<Zeroizing<[u8; DATA_KEY_BYTES]>, KeyProviderError> {
    let bytes = read_regular(
        file,
        DATA_KEY_BYTES as u64,
        Some(DATA_KEY_BYTES as u64),
        KeyProviderError::KeyFile,
    )?;
    let mut key = Zeroizing::new([0u8; DATA_KEY_BYTES]);
    key[..].copy_from_slice(&bytes);
    Ok(key)
}

/// `fstat` the already-open descriptor (never a path), enforce owner/mode/size,
/// then perform one bounded read of at most `max + 1` bytes. FIFOs, symlinks,
/// devices and directories are rejected before any read, so a FIFO cannot block.
fn read_regular(
    file: File,
    max: u64,
    exact: Option<u64>,
    reject: fn(&'static str) -> KeyProviderError,
) -> Result<Zeroizing<Vec<u8>>, KeyProviderError> {
    let metadata = file.metadata().map_err(|_| reject("metadata failed"))?;
    if !metadata.is_file() {
        return Err(reject("not a regular file"));
    }
    if metadata.uid() != libc::geteuid() {
        return Err(reject("owner is not the effective uid"));
    }
    if metadata.mode() & 0o777 != 0o600 {
        return Err(reject("mode must be exactly 0600"));
    }
    if metadata.len() > max {
        return Err(reject("size exceeds the limit"));
    }
    if exact.is_some_and(|expected| metadata.len() != expected) {
        return Err(reject("size is not the required fixed length"));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    (&file)
        .take(max.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| reject("bounded read failed"))?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > max {
        return Err(reject("size changed during the bounded read"));
    }
    if exact.is_some_and(|expected| bytes.len() as u64 != expected) {
        return Err(reject("size is not the required fixed length"));
    }
    Ok(bytes)
}

fn sha256_array(bytes: &[u8]) -> [u8; AAD_DIGEST_BYTES] {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; AAD_DIGEST_BYTES];
    out.copy_from_slice(&digest);
    out
}

fn cipher(kek: &[u8; DATA_KEY_BYTES]) -> Result<LessSafeKey, KeyProviderError> {
    let key = UnboundKey::new(&aead::AES_256_GCM, &kek[..]).map_err(|_| KeyProviderError::CipherSetup)?;
    Ok(LessSafeKey::new(key))
}

fn seal(
    kek: &[u8; DATA_KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    data_key: &[u8; DATA_KEY_BYTES],
) -> Result<[u8; WRAPPED_DEK_BYTES], KeyProviderError> {
    let cipher = cipher(kek)?;
    let mut in_out = Zeroizing::new(*data_key);
    let tag = cipher
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            &mut in_out[..],
        )
        .map_err(|_| KeyProviderError::AuthenticationFailed)?;
    let mut wrapped = [0u8; WRAPPED_DEK_BYTES];
    wrapped[..DATA_KEY_BYTES].copy_from_slice(&in_out[..]);
    wrapped[DATA_KEY_BYTES..].copy_from_slice(tag.as_ref());
    Ok(wrapped)
}

fn open(
    kek: &[u8; DATA_KEY_BYTES],
    nonce: &[u8; NONCE_BYTES],
    aad: &[u8],
    wrapped: &[u8; WRAPPED_DEK_BYTES],
) -> Result<[u8; DATA_KEY_BYTES], KeyProviderError> {
    let cipher = cipher(kek)?;
    let mut in_out = Zeroizing::new(*wrapped);
    let plaintext = cipher
        .open_in_place(
            Nonce::assume_unique_for_key(*nonce),
            Aad::from(aad),
            &mut in_out[..],
        )
        .map_err(|_| KeyProviderError::AuthenticationFailed)?;
    if plaintext.len() != DATA_KEY_BYTES {
        return Err(KeyProviderError::AuthenticationFailed);
    }
    let mut data_key = [0u8; DATA_KEY_BYTES];
    data_key.copy_from_slice(plaintext);
    Ok(data_key)
}
