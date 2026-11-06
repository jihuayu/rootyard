//! AES-256-GCM pack envelope with a Vault Transit-wrapped random data key.
//! Ciphertext is chunked for bounded memory; envelope generations are immutable.
use anyhow::{Context, Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::StreamExt;
use rand::RngCore;
use reqwest::{Client, Url};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{path::{Path, PathBuf}, time::Duration};
use tokio::{fs::{self, File}, io::{AsyncReadExt, AsyncWriteExt}, time::Instant};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const CHUNK_BYTES: usize = 64 * 1024;
const MAX_CIPHER_CHUNK: usize = CHUNK_BYTES + 16;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub version: u32,
    pub generation: u64,
    pub object_id: Uuid,
    pub cipher: String,
    pub provider: String,
    pub key_name: String,
    pub wrapped_key: String,
    pub plaintext_sha256: String,
    pub plaintext_bytes: u64,
    pub ciphertext_sha256: String,
    pub ciphertext_bytes: u64,
    pub chunk_bytes: usize,
}

#[derive(Clone)]
pub struct VaultTransit {
    client: Client,
    base: Url,
    token: Zeroizing<String>,
    mount: String,
    key_name: String,
}

impl VaultTransit {
    pub fn from_env() -> Result<Self> {
        let base = Url::parse(&std::env::var("ROOTYARD_KMS_VAULT_URL").context("Vault KMS URL missing")?)?;
        let loopback = matches!(base.host_str(), Some("127.0.0.1" | "::1" | "localhost"));
        ensure!(base.scheme() == "https" || base.scheme() == "http" && loopback, "Vault KMS requires TLS");
        ensure!(base.path() == "/" && base.query().is_none() && base.fragment().is_none()
            && base.username().is_empty() && base.password().is_none(), "Vault KMS URL must be an origin");
        let token = Zeroizing::new(std::env::var("ROOTYARD_KMS_VAULT_TOKEN").context("Vault KMS token missing")?);
        let mount = std::env::var("ROOTYARD_KMS_VAULT_MOUNT").unwrap_or_else(|_| "transit".into());
        let key_name = std::env::var("ROOTYARD_KMS_VAULT_KEY").context("Vault KMS key missing")?;
        for value in [&mount, &key_name] {
            ensure!(!value.is_empty() && value.len() <= 64 && value.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'), "invalid Vault KMS path");
        }
        let client = Client::builder().connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none()).build()?;
        Ok(Self { client, base, token, mount, key_name })
    }
    fn endpoint(&self, operation: &str) -> Result<Url> {
        let mut url = self.base.clone();
        url.set_path(&format!("/v1/{}/{operation}/{}", self.mount, self.key_name));
        Ok(url)
    }
    async fn call<T: Serialize>(&self, operation: &str, body: &T, deadline: Instant) -> Result<Zeroizing<String>> {
        #[derive(Deserialize)]
        struct TransitData { ciphertext: Option<String>, plaintext: Option<String> }
        impl Drop for TransitData {
            fn drop(&mut self) {
                if let Some(value) = &mut self.plaintext { value.zeroize(); }
            }
        }
        #[derive(Deserialize)]
        struct TransitResponse { data: TransitData }
        let request = Zeroizing::new(serde_json::to_vec(body)?);
        let response = tokio::time::timeout_at(deadline, self.client.post(self.endpoint(operation)?)
            .header("X-Vault-Token", self.token.as_str()).header("Content-Type", "application/json")
            .body(request.to_vec()).send()).await??;
        ensure!(response.status().is_success(), "Vault Transit operation failed: {}", response.status());
        let mut stream = response.bytes_stream();
        let mut bytes = Zeroizing::new(Vec::new());
        while let Some(chunk) = tokio::time::timeout_at(deadline, stream.next()).await? {
            let chunk = chunk?;
            ensure!(chunk.len() <= 16 * 1024 - bytes.len(), "Vault Transit response exceeds limit");
            bytes.extend_from_slice(&chunk);
        }
        let mut value: TransitResponse = serde_json::from_slice(&bytes)?;
        let result = if operation == "decrypt" { value.data.plaintext.take() }
            else { value.data.ciphertext.take() };
        result.map(Zeroizing::new).context("Vault Transit response missing data")
    }
    pub async fn wrap(&self, data_key: &[u8; 32], deadline: Instant) -> Result<String> {
        #[derive(Serialize)]
        struct Request<'a> { plaintext: &'a str }
        let encoded = Zeroizing::new(STANDARD.encode(data_key));
        Ok(self.call("encrypt", &Request { plaintext: &encoded }, deadline).await?.to_string())
    }
    pub async fn unwrap(&self, wrapped: &str, deadline: Instant) -> Result<Zeroizing<[u8; 32]>> {
        #[derive(Serialize)]
        struct Request<'a> { ciphertext: &'a str }
        let raw = self.call("decrypt", &Request { ciphertext: wrapped }, deadline).await?;
        let bytes = Zeroizing::new(STANDARD.decode(raw.as_bytes())?);
        ensure!(bytes.len() == 32, "Vault returned an invalid data key");
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&bytes);
        Ok(key)
    }
    pub async fn rewrap(&self, wrapped: &str, deadline: Instant) -> Result<String> {
        #[derive(Serialize)]
        struct Request<'a> { ciphertext: &'a str }
        Ok(self.call("rewrap", &Request { ciphertext: wrapped }, deadline).await?.to_string())
    }
    pub async fn rotate_master(&self, deadline: Instant) -> Result<()> {
        let mut url = self.base.clone();
        url.set_path(&format!("/v1/{}/keys/{}/rotate", self.mount, self.key_name));
        let response = tokio::time::timeout_at(deadline, self.client.post(url)
            .header("X-Vault-Token", self.token.as_str()).send()).await??;
        ensure!(response.status().is_success(), "Vault key rotation failed: {}", response.status());
        Ok(())
    }
}

fn data_cipher(data_key: &[u8; 32]) -> Result<LessSafeKey> {
    let key = UnboundKey::new(&aead::AES_256_GCM, data_key)
        .map_err(|_| anyhow::anyhow!("invalid AES-256-GCM key"))?;
    Ok(LessSafeKey::new(key))
}
fn aad(envelope: &Envelope, index: u64) -> Vec<u8> {
    let mut value = b"rootyard-pack-aes-gcm-v1\0".to_vec();
    value.extend_from_slice(envelope.object_id.as_bytes());
    value.extend_from_slice(&index.to_be_bytes());
    value.extend_from_slice(envelope.plaintext_sha256.as_bytes());
    value
}
fn envelope_path(dir: &Path, generation: u64) -> PathBuf { dir.join(format!("envelope-{generation:020}.json")) }
async fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).await?;
    file.write_all(bytes).await?;
    file.sync_all().await?;
    File::open(path.parent().context("envelope parent missing")?).await?.sync_all().await?;
    Ok(())
}
async fn read_current(dir: &Path) -> Result<u64> {
    let bytes = fs::read(dir.join("CURRENT")).await?;
    ensure!(bytes.len() <= 32, "invalid envelope pointer");
    Ok(std::str::from_utf8(&bytes)?.trim().parse()?)
}
pub async fn read_envelope(dir: &Path, generation: Option<u64>) -> Result<Envelope> {
    let generation = match generation { Some(v) => v, None => read_current(dir).await? };
    let bytes = fs::read(envelope_path(dir, generation)).await?;
    let envelope: Envelope = serde_json::from_slice(&bytes)?;
    ensure!(envelope.version == 1 && envelope.generation == generation && envelope.cipher == "AES-256-GCM-CHUNKED" && envelope.provider == "vault-transit" && envelope.chunk_bytes == CHUNK_BYTES, "invalid encrypted pack envelope");
    Ok(envelope)
}

pub async fn encrypt_file(provider: &VaultTransit, source: &Path, ciphertext: &Path, envelope_dir: &Path, deadline: Instant) -> Result<Envelope> {
    ensure!(!ciphertext.exists() && !envelope_dir.exists(), "encrypted pack already exists");
    let mut source_file = File::open(source).await?;
    let mut digest = Sha256::new();
    let mut plaintext_bytes = 0u64;
    let mut buf = Zeroizing::new(vec![0u8; CHUNK_BYTES]);
    loop {
        let n = tokio::time::timeout_at(deadline, source_file.read(&mut buf)).await??;
        if n == 0 { break; }
        digest.update(&buf[..n]); plaintext_bytes += n as u64;
    }
    let mut data_key = Zeroizing::new([0u8; 32]);
    rand::rng().fill_bytes(&mut *data_key);
    let wrapped_key = provider.wrap(&data_key, deadline).await?;
    let mut envelope = Envelope {
        version: 1, generation: 1, object_id: Uuid::new_v4(), cipher: "AES-256-GCM-CHUNKED".into(),
        provider: "vault-transit".into(), key_name: provider.key_name.clone(), wrapped_key,
        plaintext_sha256: hex::encode(digest.finalize()), plaintext_bytes,
        ciphertext_sha256: String::new(), ciphertext_bytes: 0, chunk_bytes: CHUNK_BYTES,
    };
    let parent = ciphertext.parent().context("ciphertext parent missing")?;
    fs::create_dir_all(parent).await?;
    // Allocate metadata first: a missing or unwritable envelope parent cannot
    // leave a published ciphertext that permanently poisons a retry.
    fs::create_dir(envelope_dir).await?;
    let temp = parent.join(format!(".cipher-{}", Uuid::new_v4()));
    let mut ciphertext_published = false;
    let result = async {
        let cipher = data_cipher(&data_key)?;
        let mut input = File::open(source).await?;
        let mut out = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temp).await?;
        let mut hash = Sha256::new();
        let mut size = 0u64;
        let mut index = 0u64;
        let mut plaintext_hash = Sha256::new();
        loop {
            let n = tokio::time::timeout_at(deadline, input.read(&mut buf)).await??;
            if n == 0 { break; }
            plaintext_hash.update(&buf[..n]);
            let mut nonce_bytes = [0u8; 12];
            rand::rng().fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::assume_unique_for_key(nonce_bytes);
            let mut chunk = Zeroizing::new(buf[..n].to_vec());
            cipher.seal_in_place_append_tag(nonce, Aad::from(aad(&envelope, index)), &mut *chunk)
                .map_err(|_| anyhow::anyhow!("AES-GCM seal failed"))?;
            let len = (chunk.len() as u32).to_be_bytes();
            for part in [&len[..], &nonce_bytes[..], &chunk[..]] {
                out.write_all(part).await?; hash.update(part); size += part.len() as u64;
            }
            index += 1;
        }
        ensure!(hex::encode(plaintext_hash.finalize()) == envelope.plaintext_sha256, "pack source changed during encryption");
        out.sync_all().await?;
        ensure!(!ciphertext.exists(), "ciphertext path appeared during encryption");
        fs::rename(&temp, ciphertext).await?;
        ciphertext_published = true;
        File::open(parent).await?.sync_all().await?;
        envelope.ciphertext_sha256 = hex::encode(hash.finalize());
        envelope.ciphertext_bytes = size;
        write_new(&envelope_path(envelope_dir, 1), &serde_json::to_vec(&envelope)?).await?;
        write_new(&envelope_dir.join("CURRENT"), b"1\n").await?;
        Ok::<(), anyhow::Error>(())
    }.await;
    if result.is_err() {
        let _ = fs::remove_file(&temp).await;
        if ciphertext_published { let _ = fs::remove_file(ciphertext).await; }
        let _ = fs::remove_dir_all(envelope_dir).await;
    }
    result?;
    Ok(envelope)
}

pub async fn decrypt_file(provider: &VaultTransit, ciphertext: &Path, envelope_dir: &Path, generation: Option<u64>, destination: &Path, deadline: Instant) -> Result<Envelope> {
    let envelope = read_envelope(envelope_dir, generation).await?;
    ensure!(envelope.key_name == provider.key_name, "wrong Vault key name");
    let parent = destination.parent().context("decrypted pack destination parent missing")?;
    let data_key = provider.unwrap(&envelope.wrapped_key, deadline).await?;
    let temp = parent.join(format!(".decrypted-{}", Uuid::new_v4()));
    let result = async {
        let cipher = data_cipher(&data_key)?;
        fs::create_dir_all(parent).await?;
        let mut input = File::open(ciphertext).await?;
        let mut output = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&temp).await?;
        let mut plaintext_hash = Sha256::new();
        let mut ciphertext_hash = Sha256::new();
        let mut plaintext_bytes = 0u64;
        let mut ciphertext_bytes = 0u64;
        let mut index = 0u64;
        loop {
            let mut len_bytes = [0u8; 4];
            let n = tokio::time::timeout_at(deadline, input.read(&mut len_bytes[..1])).await??;
            if n == 0 { break; }
            input.read_exact(&mut len_bytes[1..]).await?;
            let len = u32::from_be_bytes(len_bytes) as usize;
            ensure!((aead::AES_256_GCM.tag_len()..=MAX_CIPHER_CHUNK).contains(&len), "invalid encrypted chunk length");
            let mut nonce_bytes = [0u8; 12];
            input.read_exact(&mut nonce_bytes).await?;
            let mut chunk = Zeroizing::new(vec![0u8; len]);
            input.read_exact(&mut chunk).await?;
            for part in [&len_bytes[..], &nonce_bytes[..], &chunk[..]] {
                ciphertext_hash.update(part); ciphertext_bytes += part.len() as u64;
            }
            ensure!(ciphertext_bytes <= envelope.ciphertext_bytes, "ciphertext exceeds envelope size");
            let nonce = Nonce::assume_unique_for_key(nonce_bytes);
            let plaintext = cipher.open_in_place(nonce, Aad::from(aad(&envelope, index)), &mut chunk)
                .map_err(|_| anyhow::anyhow!("AES-GCM authentication failed"))?;
            plaintext_bytes += plaintext.len() as u64;
            ensure!(plaintext_bytes <= envelope.plaintext_bytes, "plaintext exceeds envelope size");
            plaintext_hash.update(&*plaintext);
            output.write_all(plaintext).await?;
            index += 1;
        }
        ensure!(plaintext_bytes == envelope.plaintext_bytes && ciphertext_bytes == envelope.ciphertext_bytes, "encrypted pack length mismatch");
        ensure!(hex::encode(plaintext_hash.finalize()) == envelope.plaintext_sha256 && hex::encode(ciphertext_hash.finalize()) == envelope.ciphertext_sha256, "encrypted pack digest mismatch");
        output.sync_all().await?;
        fs::rename(&temp, destination).await?;
        File::open(parent).await?.sync_all().await?;
        Ok::<(), anyhow::Error>(())
    }.await;
    if result.is_err() { let _ = fs::remove_file(&temp).await; }
    result?;
    Ok(envelope)
}

pub async fn rotate_envelope(provider: &VaultTransit, envelope_dir: &Path, deadline: Instant) -> Result<Envelope> {
    let current = read_envelope(envelope_dir, None).await?;
    ensure!(current.key_name == provider.key_name, "wrong Vault key name");
    let wrapped = provider.rewrap(&current.wrapped_key, deadline).await?;
    // Verify the new wrapper before making it current. Old generations remain
    // readable while Vault permits their key versions.
    let old_key = provider.unwrap(&current.wrapped_key, deadline).await?;
    let new_key = provider.unwrap(&wrapped, deadline).await?;
    let same_key = old_key == new_key;
    ensure!(same_key, "Vault rewrap changed the data key");
    let mut next = current.clone();
    next.wrapped_key = wrapped;
    next.generation = current.generation.checked_add(1).context("envelope generation exhausted")?;
    while envelope_path(envelope_dir, next.generation).exists() {
        next.generation = next.generation.checked_add(1).context("envelope generation exhausted")?;
    }
    write_new(&envelope_path(envelope_dir, next.generation), &serde_json::to_vec(&next)?).await?;
    let pointer = envelope_dir.join(format!(".CURRENT-{}", Uuid::new_v4()));
    write_new(&pointer, format!("{}\n", next.generation).as_bytes()).await?;
    fs::rename(&pointer, envelope_dir.join("CURRENT")).await?;
    File::open(envelope_dir).await?.sync_all().await?;
    Ok(next)
}
