use anyhow::{Context, Result, ensure};
use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    rand::{SecureRandom, SystemRandom},
};
use rootyard::blob_store::key_provider::{DATA_KEY_BYTES, WrapContext};
use super::data_key::PandoDataKey;
use super::provider::PandoKeyProvider;
use super::wrapped_dek::PandoWrappedDek;
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub const AUTHENTICATED_ENVELOPE_MODE: &str = "authenticated-envelope-v1";
pub const SYNTHETIC_METADATA_MODE: &str = "synthetic-metadata-lab-only";
pub const SEALED_PACK_MAGIC: &[u8; 8] = b"PANDOENC";
pub const SEALED_PACK_VERSION: u8 = 2;
pub const SEALED_HEADER_LEN: usize = 52;
pub const SEALED_CHUNK_BYTES: usize = 64 * 1024;
pub const AEAD_TAG_BYTES: usize = 16;
pub const AEAD_NONCE_BYTES: usize = 12;
pub const NONCE_PREFIX_BYTES: usize = 4;
const SEALED_AAD_DOMAIN: &[u8] = b"rootyard.pando.sealed-pack.v2";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackCipher {
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl PackCipher {
    pub fn from_suite(suite: &str) -> Result<Self> {
        match suite {
            "AES-256-GCM-HMAC-SHA256" => Ok(Self::Aes256Gcm),
            "CHACHA20-POLY1305-SHA256" => Ok(Self::ChaCha20Poly1305),
            other => anyhow::bail!("unsupported pack cipher suite '{other}'"),
        }
    }
    pub fn from_wire(id: u8) -> Result<Self> {
        match id {
            1 => Ok(Self::Aes256Gcm),
            2 => Ok(Self::ChaCha20Poly1305),
            other => anyhow::bail!("unsupported sealed-pack cipher id {other}"),
        }
    }
    pub fn suite_name(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "AES-256-GCM-HMAC-SHA256",
            Self::ChaCha20Poly1305 => "CHACHA20-POLY1305-SHA256",
        }
    }
    pub fn wire_id(self) -> u8 {
        if matches!(self, Self::Aes256Gcm) { 1 } else { 2 }
    }
    pub fn algorithm(self) -> &'static aead::Algorithm {
        if matches!(self, Self::Aes256Gcm) {
            &aead::AES_256_GCM
        } else {
            &aead::CHACHA20_POLY1305
        }
    }
}

#[derive(Debug, Clone)]
pub struct SealedHeader {
    pub cipher: PackCipher,
    pub chunk_size: usize,
    pub envelope_id: Uuid,
    pub nonce_prefix: [u8; NONCE_PREFIX_BYTES],
    pub plaintext_len: u64,
    pub chunk_count: u64,
}

#[derive(Debug, Clone)]
pub struct SealedPackArtifact {
    pub ciphertext: Vec<u8>,
    pub ciphertext_sha256: String,
    pub ciphertext_bytes: u64,
    pub plaintext_sha256: String,
    pub plaintext_bytes: u64,
    pub envelope_id: Uuid,
    pub nonce_prefix_hex: String,
    pub wrapped_key_json: String,
    pub key_id: String,
    pub key_version: i32,
    pub cipher_suite: String,
    pub encryption_mode: String,
}

#[derive(Clone, Copy)]
pub struct OpenSealedRequest<'a> {
    pub repo: Uuid,
    pub pack_id: Uuid,
    pub expected_plaintext_sha256: &'a str,
    pub expected_idx_sha256: &'a str,
    pub expected_cipher_suite: &'a str,
    pub expected_envelope_id: Option<Uuid>,
    pub expected_nonce_prefix: Option<&'a str>,
    pub wrapped_key_json: &'a str,
}

pub struct EnvelopeMacInputs<'a> {
    pub encryption_mode: &'a str,
    pub repo: Uuid,
    pub pack_id: Uuid,
    pub key_id: &'a str,
    pub key_version: i32,
    pub cipher_suite: &'a str,
    pub pack_sha256: &'a str,
    pub idx_sha256: &'a str,
    pub ciphertext_sha256: &'a str,
    pub ciphertext_bytes: u64,
    pub envelope_id: Uuid,
    pub nonce_prefix: &'a str,
    pub wrapped_key_json: &'a str,
}

struct ChunkAadParams<'a> {
    cipher: PackCipher,
    repo: Uuid,
    pack_id: Uuid,
    envelope_id: Uuid,
    plaintext_sha256: &'a str,
    idx_sha256: &'a str,
    plaintext_len: u64,
    chunk_size: u32,
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub fn is_valid_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn is_authenticated_mode(mode: &str) -> bool {
    mode == AUTHENTICATED_ENVELOPE_MODE
}

pub fn pack_wrap_context(
    repo: Uuid,
    pack_id: Uuid,
    envelope_id: Uuid,
    plaintext_sha256: &str,
) -> Result<WrapContext> {
    WrapContext::new(repo, pack_id, 1, envelope_id, "pando-pack", plaintext_sha256)
        .map_err(|err| anyhow::anyhow!("invalid KMS wrap context: {err}"))
}

fn push_aad_field(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn chunk_nonce(prefix: &[u8; NONCE_PREFIX_BYTES], chunk_index: u64) -> Nonce {
    let mut raw = [0u8; AEAD_NONCE_BYTES];
    raw[..NONCE_PREFIX_BYTES].copy_from_slice(prefix);
    raw[NONCE_PREFIX_BYTES..].copy_from_slice(&chunk_index.to_be_bytes());
    Nonce::assume_unique_for_key(raw)
}

fn build_chunk_aad(p: &ChunkAadParams<'_>, chunk_index: u64, is_final: bool) -> Vec<u8> {
    let mut aad = Vec::with_capacity(256);
    push_aad_field(&mut aad, SEALED_AAD_DOMAIN);
    push_aad_field(&mut aad, p.cipher.suite_name().as_bytes());
    push_aad_field(&mut aad, p.repo.as_bytes());
    push_aad_field(&mut aad, p.pack_id.as_bytes());
    push_aad_field(&mut aad, p.envelope_id.as_bytes());
    push_aad_field(&mut aad, p.plaintext_sha256.as_bytes());
    push_aad_field(&mut aad, p.idx_sha256.as_bytes());
    aad.extend_from_slice(&p.plaintext_len.to_be_bytes());
    aad.extend_from_slice(&p.chunk_size.to_be_bytes());
    aad.extend_from_slice(&chunk_index.to_be_bytes());
    aad.push(u8::from(is_final));
    aad
}

fn less_safe_key(cipher: PackCipher, dek: &[u8; DATA_KEY_BYTES]) -> Result<LessSafeKey> {
    let unbound = UnboundKey::new(cipher.algorithm(), dek)
        .map_err(|_| anyhow::anyhow!("AEAD cipher key initialization failed"))?;
    Ok(LessSafeKey::new(unbound))
}

fn ensure_provider_allows_encryption<P: PandoKeyProvider + ?Sized>(provider: &P) -> Result<()> {
    let caps = provider.capabilities();
    ensure!(
        !caps.plaintext_fallback,
        "key provider refuses fail-closed invariant by allowing plaintext_fallback"
    );
    ensure!(
        caps.local_envelope || caps.provider_managed,
        "key provider does not support envelope encryption"
    );
    Ok(())
}

pub async fn seal_pack_bytes<P: PandoKeyProvider + ?Sized>(
    provider: &P,
    repo: Uuid,
    pack_id: Uuid,
    idx_sha256: &str,
    cipher_suite: &str,
    key_version: i32,
    plaintext: &[u8],
) -> Result<SealedPackArtifact> {
    ensure_provider_allows_encryption(provider)?;
    ensure!(
        !repo.is_nil() && !pack_id.is_nil() && key_version >= 1,
        "invalid pack scope or key version for encryption"
    );
    ensure!(
        is_valid_sha256_hex(idx_sha256),
        "invalid idx_sha256 digest for pack encryption"
    );

    let cipher = PackCipher::from_suite(cipher_suite)?;
    let plaintext_sha256 = sha256_hex(plaintext);
    let plaintext_len = plaintext.len() as u64;
    let rng = SystemRandom::new();
    let dek = PandoDataKey::generate()?;
    let mut nonce_prefix = [0u8; NONCE_PREFIX_BYTES];
    rng.fill(&mut nonce_prefix)
        .map_err(|_| anyhow::anyhow!("system random generator failed while creating nonce"))?;
    let envelope_id = Uuid::new_v4();

    let chunk_count = if plaintext.is_empty() {
        1u64
    } else {
        plaintext.len().div_ceil(SEALED_CHUNK_BYTES) as u64
    };
    let expected_total = SEALED_HEADER_LEN
        .checked_add(plaintext.len())
        .and_then(|n| n.checked_add((chunk_count as usize) * AEAD_TAG_BYTES))
        .context("sealed pack ciphertext length overflow")?;

    let mut ciphertext = Vec::with_capacity(expected_total);
    ciphertext.extend_from_slice(SEALED_PACK_MAGIC);
    ciphertext.push(SEALED_PACK_VERSION);
    ciphertext.push(cipher.wire_id());
    ciphertext.extend_from_slice(&[0u8, 0u8]);
    ciphertext.extend_from_slice(&(SEALED_CHUNK_BYTES as u32).to_be_bytes());
    ciphertext.extend_from_slice(envelope_id.as_bytes());
    ciphertext.extend_from_slice(&nonce_prefix);
    ciphertext.extend_from_slice(&plaintext_len.to_be_bytes());
    ciphertext.extend_from_slice(&chunk_count.to_be_bytes());
    debug_assert_eq!(ciphertext.len(), SEALED_HEADER_LEN);

    let aad_params = ChunkAadParams {
        cipher,
        repo,
        pack_id,
        envelope_id,
        plaintext_sha256: &plaintext_sha256,
        idx_sha256,
        plaintext_len,
        chunk_size: SEALED_CHUNK_BYTES as u32,
    };
    let key = less_safe_key(cipher, dek.expose_secret())?;
    let total_chunks = if plaintext.is_empty() { 1 } else { chunk_count as usize };
    for idx in 0..total_chunks {
        let start = idx * SEALED_CHUNK_BYTES;
        let end = (start + SEALED_CHUNK_BYTES).min(plaintext.len());
        let chunk_index = idx as u64;
        let aad = build_chunk_aad(&aad_params, chunk_index, chunk_index + 1 == chunk_count);
        let mut block = Vec::with_capacity((end - start) + AEAD_TAG_BYTES);
        block.extend_from_slice(&plaintext[start..end]);
        key.seal_in_place_append_tag(
            chunk_nonce(&nonce_prefix, chunk_index),
            Aad::from(&aad),
            &mut block,
        )
        .map_err(|_| anyhow::anyhow!("AEAD chunk sealing failed"))?;
        ciphertext.extend_from_slice(&block);
    }
    ensure!(
        ciphertext.len() == expected_total && !ciphertext.starts_with(b"PACK"),
        "sealed pack invariant violation"
    );

    let wrap_ctx = pack_wrap_context(repo, pack_id, envelope_id, &plaintext_sha256)?;
    let wrapped = provider
        .wrap_data_key(&dek, &wrap_ctx)
        .await
        .map_err(|err| anyhow::anyhow!("KMS key wrapping failed: {err}"))?;
    let wrapped_key_json = wrapped
        .to_json()
        .map_err(|err| anyhow::anyhow!("wrapped DEK serialization failed: {err}"))?;

    Ok(SealedPackArtifact {
        ciphertext_sha256: sha256_hex(&ciphertext),
        ciphertext_bytes: ciphertext.len() as u64,
        ciphertext,
        plaintext_sha256,
        plaintext_bytes: plaintext_len,
        envelope_id,
        nonce_prefix_hex: hex::encode(nonce_prefix),
        wrapped_key_json,
        key_id: wrapped.key_id().to_owned(),
        key_version,
        cipher_suite: cipher.suite_name().to_owned(),
        encryption_mode: AUTHENTICATED_ENVELOPE_MODE.to_owned(),
    })
}

pub fn inspect_sealed_header(ciphertext: &[u8]) -> Result<SealedHeader> {
    ensure!(ciphertext.len() >= SEALED_HEADER_LEN, "sealed pack truncated before envelope header");
    ensure!(&ciphertext[0..8] == SEALED_PACK_MAGIC, "stored pack bytes lack PANDOENC envelope header");
    ensure!(ciphertext[8] == SEALED_PACK_VERSION, "unsupported sealed pack version {}", ciphertext[8]);
    let cipher = PackCipher::from_wire(ciphertext[9])?;
    ensure!(ciphertext[10] == 0 && ciphertext[11] == 0, "unexpected non-zero flags in sealed pack header");
    let chunk_size = u32::from_be_bytes(ciphertext[12..16].try_into()?) as usize;
    ensure!((1024..=1024 * 1024).contains(&chunk_size), "invalid chunk size {chunk_size} in sealed pack header");
    let envelope_id = Uuid::from_slice(&ciphertext[16..32])?;
    ensure!(!envelope_id.is_nil(), "nil envelope_id in sealed pack header");
    let mut nonce_prefix = [0u8; NONCE_PREFIX_BYTES];
    nonce_prefix.copy_from_slice(&ciphertext[32..36]);
    let plaintext_len = u64::from_be_bytes(ciphertext[36..44].try_into()?);
    let chunk_count = u64::from_be_bytes(ciphertext[44..52].try_into()?);
    let expected_chunks = if plaintext_len == 0 { 1u64 } else { plaintext_len.div_ceil(chunk_size as u64) };
    ensure!(chunk_count == expected_chunks, "sealed pack chunk_count {chunk_count} != {expected_chunks}");
    let expected_total = (SEALED_HEADER_LEN as u64)
        .checked_add(plaintext_len)
        .and_then(|n| n.checked_add(chunk_count.saturating_mul(AEAD_TAG_BYTES as u64)))
        .context("sealed pack total size overflow")?;
    ensure!(
        ciphertext.len() as u64 == expected_total,
        "sealed pack length {} != authenticated frame length {expected_total}",
        ciphertext.len()
    );
    Ok(SealedHeader { cipher, chunk_size, envelope_id, nonce_prefix, plaintext_len, chunk_count })
}

pub async fn open_sealed_pack_bytes<P: PandoKeyProvider + ?Sized>(
    provider: &P,
    req: &OpenSealedRequest<'_>,
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    ensure_provider_allows_encryption(provider)?;
    ensure!(
        is_valid_sha256_hex(req.expected_plaintext_sha256)
            && is_valid_sha256_hex(req.expected_idx_sha256),
        "invalid expected digest for pack decryption"
    );
    let header = inspect_sealed_header(ciphertext)?;
    ensure!(
        header.cipher.suite_name() == req.expected_cipher_suite,
        "sealed pack cipher '{}' does not match envelope suite '{}'",
        header.cipher.suite_name(),
        req.expected_cipher_suite
    );
    if let Some(exp_env) = req.expected_envelope_id {
        ensure!(
            header.envelope_id == exp_env,
            "sealed pack envelope_id {} does not match metadata {}",
            header.envelope_id,
            exp_env
        );
    }
    if let Some(exp_prefix) = req.expected_nonce_prefix {
        ensure!(
            hex::encode(header.nonce_prefix) == exp_prefix,
            "sealed pack nonce_prefix mismatch"
        );
    }

    let wrapped = PandoWrappedDek::from_json(req.wrapped_key_json.as_bytes())
        .map_err(|err| anyhow::anyhow!("invalid wrapped DEK metadata: {err}"))?;
    let wrap_ctx = pack_wrap_context(
        req.repo,
        req.pack_id,
        header.envelope_id,
        req.expected_plaintext_sha256,
    )?;
    let data_key: PandoDataKey = provider
        .unwrap_data_key(&wrapped, &wrap_ctx)
        .await
        .map_err(|err| anyhow::anyhow!("KMS key unwrap failed closed: {err}"))?;
    let key = less_safe_key(header.cipher, data_key.expose_secret())?;

    let aad_params = ChunkAadParams {
        cipher: header.cipher,
        repo: req.repo,
        pack_id: req.pack_id,
        envelope_id: header.envelope_id,
        plaintext_sha256: req.expected_plaintext_sha256,
        idx_sha256: req.expected_idx_sha256,
        plaintext_len: header.plaintext_len,
        chunk_size: header.chunk_size as u32,
    };
    let mut plaintext = Vec::with_capacity(usize::try_from(header.plaintext_len)?);
    let mut offset = SEALED_HEADER_LEN;
    for chunk_index in 0..header.chunk_count {
        let is_final = chunk_index + 1 == header.chunk_count;
        let remaining_plain = header.plaintext_len - (plaintext.len() as u64);
        let plain_chunk_len = if header.plaintext_len == 0 {
            0usize
        } else {
            remaining_plain.min(header.chunk_size as u64) as usize
        };
        let cipher_slice_len = plain_chunk_len + AEAD_TAG_BYTES;
        let slice = ciphertext
            .get(offset..offset + cipher_slice_len)
            .context("sealed pack truncated mid-chunk")?;
        let mut scratch = slice.to_vec();
        let aad = build_chunk_aad(&aad_params, chunk_index, is_final);
        let decrypted = key
            .open_in_place(
                chunk_nonce(&header.nonce_prefix, chunk_index),
                Aad::from(&aad),
                &mut scratch,
            )
            .map_err(|_| {
                anyhow::anyhow!(
                    "AEAD chunk {chunk_index} authentication failed for pack {}",
                    req.pack_id
                )
            })?;
        plaintext.extend_from_slice(decrypted);
        offset += cipher_slice_len;
    }
    ensure!(
        offset == ciphertext.len(),
        "unexpected trailing bytes after sealed pack chunks"
    );
    ensure!(
        plaintext.len() as u64 == header.plaintext_len
            && sha256_hex(&plaintext) == req.expected_plaintext_sha256,
        "decrypted pack plaintext digest mismatch"
    );
    Ok(plaintext)
}

pub async fn rewrap_pack_dek<P: PandoKeyProvider + ?Sized>(
    provider: &P,
    repo: Uuid,
    pack_id: Uuid,
    envelope_id: Uuid,
    plaintext_sha256: &str,
    wrapped_key_json: &str,
) -> Result<(String, String)> {
    ensure_provider_allows_encryption(provider)?;
    let wrapped = PandoWrappedDek::from_json(wrapped_key_json.as_bytes())
        .map_err(|err| anyhow::anyhow!("invalid wrapped DEK during rewrap: {err}"))?;
    let ctx = pack_wrap_context(repo, pack_id, envelope_id, plaintext_sha256)?;
    let rewrapped = provider
        .rewrap_data_key(&wrapped, &ctx)
        .await
        .map_err(|err| anyhow::anyhow!("KMS DEK rewrap failed closed: {err}"))?;
    let json = rewrapped
        .to_json()
        .map_err(|err| anyhow::anyhow!("rewrapped DEK serialization failed: {err}"))?;
    Ok((rewrapped.key_id().to_owned(), json))
}

pub fn compute_authenticated_envelope_mac(inputs: &EnvelopeMacInputs<'_>) -> String {
    let wrapped_digest = sha256_hex(inputs.wrapped_key_json.as_bytes());
    let transcript = format!(
        "v2||{}||{}||{}||{}||{}||{}||{}||{}||{}||{}||{}||{}||{}",
        inputs.encryption_mode,
        inputs.repo,
        inputs.pack_id,
        inputs.key_id,
        inputs.key_version,
        inputs.cipher_suite,
        inputs.pack_sha256,
        inputs.idx_sha256,
        inputs.ciphertext_sha256,
        inputs.ciphertext_bytes,
        inputs.envelope_id,
        inputs.nonce_prefix,
        wrapped_digest
    );
    sha256_hex(transcript.as_bytes())
}

#[cfg(test)]
#[path = "crypto_tests.rs"]
mod tests;
