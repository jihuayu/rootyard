//! Low-level regular-file, staging, and chunked AES-256-GCM IO primitives for
//! [`super`] envelope sealing and opening.

use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use super::{
    ENVELOPE_CHUNK_BYTES, ENVELOPE_NONCE_PREFIX_BYTES, ENVELOPE_SCHEMA, ENVELOPE_TAG_BYTES, EnvelopeError,
    EnvelopeMetadata, PlaintextDigest, ensure_local_envelope_provider,
};
use crate::blob_store::{
    BlobError, MAX_NAMESPACE_BYTES, MAX_OBJECT_BYTES,
    key_provider::{KeyProvider, KeyProviderError, NONCE_BYTES},
};

const CHUNK_AAD_DOMAIN: &[u8] = b"rootyard/blob-store/envelope/chunk/v1";

pub(crate) struct TempPathGuard {
    path: PathBuf,
    remove_on_drop: bool,
}

impl TempPathGuard {
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    fn disarm(&mut self) {
        self.remove_on_drop = false;
    }
}

impl Drop for TempPathGuard {
    fn drop(&mut self) {
        if self.remove_on_drop {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

pub(super) struct ChunkAadParams<'a> {
    pub(super) envelope_id: Uuid,
    pub(super) tenant_id: Uuid,
    pub(super) authority_id: Uuid,
    pub(super) generation: i64,
    pub(super) namespace: &'a str,
    pub(super) plaintext_sha256: &'a str,
    pub(super) plaintext_length: u64,
    pub(super) chunk_bytes: u32,
}

struct ChunkSealWriter<'a> {
    dst: File,
    ct_hasher: Sha256,
    ct_written: u64,
    key: &'a LessSafeKey,
    nonce_prefix: &'a [u8; ENVELOPE_NONCE_PREFIX_BYTES],
    aad_params: &'a ChunkAadParams<'a>,
}

impl ChunkSealWriter<'_> {
    fn write_chunk(&mut self, chunk_index: u64, is_final: bool, chunk_buf: &mut Vec<u8>) -> Result<(), EnvelopeError> {
        let nonce = chunk_nonce(self.nonce_prefix, chunk_index);
        let aad = build_chunk_aad(self.aad_params, chunk_index, is_final);
        self.key
            .seal_in_place_append_tag(nonce, Aad::from(&aad), chunk_buf)
            .map_err(|_| EnvelopeError::CiphertextCorrupt("chunk encryption failed"))?;
        self.dst.write_all(chunk_buf).map_err(|_| EnvelopeError::Io("failed writing encrypted chunk"))?;
        self.ct_hasher.update(chunk_buf);
        self.ct_written = self
            .ct_written
            .checked_add(chunk_buf.len() as u64)
            .ok_or(EnvelopeError::Io("ciphertext length overflow"))?;
        Ok(())
    }

    fn finish(self) -> Result<(String, u64), EnvelopeError> {
        self.dst.sync_all().map_err(|_| EnvelopeError::Io("failed to sync ciphertext staging file"))?;
        Ok((hex::encode(self.ct_hasher.finalize()), self.ct_written))
    }
}

pub(super) fn encrypt_chunks(
    source: &Path,
    dst: File,
    key: &LessSafeKey,
    nonce_prefix: &[u8; ENVELOPE_NONCE_PREFIX_BYTES],
    aad_params: &ChunkAadParams<'_>,
    plaintext_length: u64,
) -> Result<(String, u64), EnvelopeError> {
    let (mut src, actual_len) = open_regular_readonly(source)?;
    if actual_len != plaintext_length {
        return Err(EnvelopeError::Io("source file changed length during envelope encryption"));
    }
    let mut writer = ChunkSealWriter { dst, ct_hasher: Sha256::new(), ct_written: 0, key, nonce_prefix, aad_params };
    let mut chunk_buf = Zeroizing::new(Vec::with_capacity(ENVELOPE_CHUNK_BYTES + ENVELOPE_TAG_BYTES));

    if plaintext_length == 0 {
        writer.write_chunk(0, true, &mut chunk_buf)?;
        chunk_buf.zeroize();
    } else {
        let mut remaining = plaintext_length;
        let mut chunk_index = 0u64;
        while remaining > 0 {
            let want = remaining.min(ENVELOPE_CHUNK_BYTES as u64) as usize;
            chunk_buf.resize(want, 0);
            read_exact_checked(&mut src, &mut chunk_buf, "source file shrank while encrypting")?;
            remaining -= want as u64;
            writer.write_chunk(chunk_index, remaining == 0, &mut chunk_buf)?;
            chunk_buf.zeroize();
            chunk_buf.clear();
            chunk_index += 1;
        }
        ensure_eof(&mut src, "source file grew while encrypting")?;
    }

    writer.finish()
}

pub(super) fn decrypt_ciphertext_inner(
    metadata: &EnvelopeMetadata,
    key_provider: &dyn KeyProvider,
    ciphertext_path: &Path,
    destination: Option<&Path>,
) -> Result<PlaintextDigest, EnvelopeError> {
    ensure_local_envelope_provider(key_provider)?;
    metadata.validate()?;
    let wrapped = metadata.wrapped_key()?;
    let wrap_ctx = metadata.wrap_context()?;
    let dek = key_provider.unwrap_data_key(&wrapped, &wrap_ctx)?;
    let prefix = decode_nonce_prefix(&metadata.nonce_prefix)?;
    let key = LessSafeKey::new(
        UnboundKey::new(&aead::AES_256_GCM, dek.expose_secret()).map_err(|_| KeyProviderError::CipherSetup)?,
    );
    drop(dek);

    let (mut src, actual_ct_len) = open_regular_readonly(ciphertext_path)?;
    if actual_ct_len != metadata.ciphertext_length {
        return Err(EnvelopeError::CiphertextCorrupt("ciphertext length mismatch"));
    }

    let mut out_guard: Option<(TempPathGuard, File, &Path)> = if let Some(dest) = destination {
        let parent = dest
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .ok_or(EnvelopeError::Io("destination path lacks a parent directory"))?;
        if dest.file_name().is_none() {
            return Err(EnvelopeError::Io("destination path lacks a file name"));
        }
        verify_staging_dir(parent)?;
        let (guard, file) = create_private_temp_file(parent, "pt")?;
        Some((guard, file, dest))
    } else {
        None
    };

    let aad_params = metadata.aad_params();
    let chunk_size = u64::from(metadata.chunk_bytes);
    let chunk_count = if metadata.plaintext_length == 0 { 1 } else { metadata.plaintext_length.div_ceil(chunk_size) };

    let mut ct_hasher = Sha256::new();
    let mut pt_hasher = Sha256::new();
    let mut pt_written = 0u64;
    let mut chunk_buf = Zeroizing::new(Vec::with_capacity(ENVELOPE_CHUNK_BYTES + ENVELOPE_TAG_BYTES));

    for chunk_index in 0..chunk_count {
        let is_final = chunk_index + 1 == chunk_count;
        let expected_pt = if metadata.plaintext_length == 0 {
            0usize
        } else if is_final {
            (metadata.plaintext_length - chunk_index * chunk_size) as usize
        } else {
            chunk_size as usize
        };
        let ct_chunk_len = expected_pt + ENVELOPE_TAG_BYTES;
        chunk_buf.resize(ct_chunk_len, 0);
        if read_exact_checked(&mut src, &mut chunk_buf, "ciphertext truncated before final chunk").is_err() {
            return Err(EnvelopeError::CiphertextCorrupt("ciphertext truncated"));
        }
        ct_hasher.update(&chunk_buf[..]);
        let nonce = chunk_nonce(&prefix, chunk_index);
        let aad = build_chunk_aad(&aad_params, chunk_index, is_final);
        let plaintext = key
            .open_in_place(nonce, Aad::from(&aad), &mut chunk_buf)
            .map_err(|_| EnvelopeError::CiphertextCorrupt("authenticated chunk decryption failed"))?;
        if plaintext.len() != expected_pt {
            return Err(EnvelopeError::CiphertextCorrupt("decrypted chunk length mismatch"));
        }
        pt_hasher.update(plaintext);
        if let Some((_, file, _)) = out_guard.as_mut() {
            file.write_all(plaintext).map_err(|_| EnvelopeError::Io("failed writing decrypted plaintext"))?;
        }
        pt_written = pt_written
            .checked_add(plaintext.len() as u64)
            .ok_or(EnvelopeError::PlaintextMismatch("plaintext length overflow"))?;
        chunk_buf.zeroize();
        chunk_buf.clear();
    }

    if ensure_eof(&mut src, "trailing bytes after final chunk").is_err() {
        return Err(EnvelopeError::CiphertextCorrupt("trailing bytes after final chunk"));
    }
    let actual_ct_sha = hex::encode(ct_hasher.finalize());
    if actual_ct_sha != metadata.ciphertext_sha256 {
        return Err(EnvelopeError::CiphertextCorrupt("ciphertext digest mismatch"));
    }
    let actual_pt_sha = hex::encode(pt_hasher.finalize());
    if pt_written != metadata.plaintext_length || actual_pt_sha != metadata.plaintext_sha256 {
        return Err(EnvelopeError::PlaintextMismatch("plaintext length or SHA-256 mismatch"));
    }

    if let Some((mut guard, file, dest)) = out_guard {
        file.sync_all().map_err(|_| EnvelopeError::Io("failed syncing decrypted plaintext"))?;
        drop(file);
        std::fs::rename(guard.path(), dest).map_err(|_| EnvelopeError::Io("failed renaming plaintext output"))?;
        guard.disarm();
    }

    Ok(PlaintextDigest { sha256: actual_pt_sha, length: pt_written })
}

pub(super) fn expected_ciphertext_length(plaintext_length: u64, chunk_bytes: u32) -> Result<u64, EnvelopeError> {
    let chunk_size = u64::from(chunk_bytes);
    if chunk_size == 0 {
        return Err(EnvelopeError::MetadataCorrupt("chunk size must be positive"));
    }
    let chunks = if plaintext_length == 0 { 1 } else { plaintext_length.div_ceil(chunk_size) };
    let tags =
        chunks.checked_mul(ENVELOPE_TAG_BYTES as u64).ok_or(EnvelopeError::MetadataCorrupt("tag length overflow"))?;
    plaintext_length.checked_add(tags).ok_or(EnvelopeError::MetadataCorrupt("ciphertext length overflow"))
}

fn chunk_nonce(prefix: &[u8; ENVELOPE_NONCE_PREFIX_BYTES], chunk_index: u64) -> Nonce {
    let mut raw = [0u8; NONCE_BYTES];
    raw[..ENVELOPE_NONCE_PREFIX_BYTES].copy_from_slice(prefix);
    raw[ENVELOPE_NONCE_PREFIX_BYTES..].copy_from_slice(&chunk_index.to_be_bytes());
    Nonce::assume_unique_for_key(raw)
}

fn build_chunk_aad(params: &ChunkAadParams<'_>, chunk_index: u64, is_final: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(180 + params.namespace.len());
    out.extend_from_slice(CHUNK_AAD_DOMAIN);
    out.extend_from_slice(&ENVELOPE_SCHEMA.to_be_bytes());
    out.extend_from_slice(params.envelope_id.as_bytes());
    out.extend_from_slice(params.tenant_id.as_bytes());
    out.extend_from_slice(params.authority_id.as_bytes());
    out.extend_from_slice(&params.generation.to_be_bytes());
    let ns_len = u32::try_from(params.namespace.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&ns_len.to_be_bytes());
    out.extend_from_slice(params.namespace.as_bytes());
    out.extend_from_slice(params.plaintext_sha256.as_bytes());
    out.extend_from_slice(&params.plaintext_length.to_be_bytes());
    out.extend_from_slice(&params.chunk_bytes.to_be_bytes());
    out.extend_from_slice(&chunk_index.to_be_bytes());
    out.push(u8::from(is_final));
    out
}

pub(crate) fn verify_staging_dir(dir: &Path) -> Result<(), EnvelopeError> {
    let meta = std::fs::symlink_metadata(dir).map_err(|_| EnvelopeError::Io("staging directory unavailable"))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(EnvelopeError::Io("staging directory must be a real directory"));
    }
    Ok(())
}

pub(crate) fn create_private_temp_file(dir: &Path, label: &str) -> Result<(TempPathGuard, File), EnvelopeError> {
    let path = dir.join(format!(".rootyard-env-{label}-{}.tmp", Uuid::new_v4().simple()));
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .map_err(|_| EnvelopeError::Io("failed creating private staging file"))?;
    Ok((TempPathGuard { path, remove_on_drop: true }, file))
}

fn open_regular_readonly(path: &Path) -> Result<(File, u64), EnvelopeError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| EnvelopeError::Io("failed opening local regular file"))?;
    let meta = file.metadata().map_err(|_| EnvelopeError::Io("failed inspecting local regular file"))?;
    if !meta.is_file() {
        return Err(EnvelopeError::Io("envelope source or ciphertext must be a regular file"));
    }
    Ok((file, meta.len()))
}

pub(super) fn hash_regular_file(path: &Path, max_bytes: u64) -> Result<(String, u64), EnvelopeError> {
    let (mut file, expected_len) = open_regular_readonly(path)?;
    if expected_len > max_bytes || expected_len > MAX_OBJECT_BYTES {
        return Err(EnvelopeError::Blob(BlobError::LengthMismatch {
            expected: max_bytes.min(MAX_OBJECT_BYTES),
            actual: expected_len,
        }));
    }
    let mut hasher = Sha256::new();
    let mut buf = Zeroizing::new(vec![0u8; ENVELOPE_CHUNK_BYTES]);
    let mut seen = 0u64;
    loop {
        let n = match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(EnvelopeError::Io("failed reading plaintext source")),
        };
        seen = seen.checked_add(n as u64).ok_or(EnvelopeError::Io("source length overflow"))?;
        if seen > expected_len {
            return Err(EnvelopeError::Io("source grew while hashing"));
        }
        hasher.update(&buf[..n]);
    }
    if seen != expected_len {
        return Err(EnvelopeError::Io("source shrank while hashing"));
    }
    Ok((hex::encode(hasher.finalize()), seen))
}

fn read_exact_checked(file: &mut File, buf: &mut [u8], msg: &'static str) -> Result<(), EnvelopeError> {
    let mut offset = 0usize;
    while offset < buf.len() {
        match file.read(&mut buf[offset..]) {
            Ok(0) => return Err(EnvelopeError::Io(msg)),
            Ok(n) => offset += n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(EnvelopeError::Io("failed reading local file")),
        }
    }
    Ok(())
}

fn ensure_eof(file: &mut File, msg: &'static str) -> Result<(), EnvelopeError> {
    let mut probe = [0u8; 1];
    loop {
        match file.read(&mut probe) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(EnvelopeError::Io(msg)),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(EnvelopeError::Io("failed confirming EOF")),
        }
    }
}

pub(super) fn decode_nonce_prefix(raw: &str) -> Result<[u8; ENVELOPE_NONCE_PREFIX_BYTES], EnvelopeError> {
    if raw.len() != ENVELOPE_NONCE_PREFIX_BYTES * 2
        || !raw.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(EnvelopeError::MetadataCorrupt("malformed nonce prefix hex"));
    }
    let decoded = hex::decode(raw).map_err(|_| EnvelopeError::MetadataCorrupt("invalid nonce prefix hex"))?;
    decoded.try_into().map_err(|_| EnvelopeError::MetadataCorrupt("unexpected nonce prefix length"))
}

pub(super) fn validate_namespace(namespace: &str) -> Result<(), EnvelopeError> {
    if namespace.is_empty()
        || namespace.len() > MAX_NAMESPACE_BYTES
        || !namespace.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(EnvelopeError::Config("invalid blob namespace".into()));
    }
    Ok(())
}

pub(super) fn validate_sha256_hex(raw: &str, msg: &'static str) -> Result<(), EnvelopeError> {
    if raw.len() != 64 || !raw.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(EnvelopeError::MetadataCorrupt(msg));
    }
    Ok(())
}
