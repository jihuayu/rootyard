use super::data_key::PandoDataKey;
use super::valid_kms_key_id;
use super::provider::PandoKeyProvider;
use super::wrapped_dek::{PandoProviderKind, PandoWrappedDek, parse_vault_ciphertext_version};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use futures_util::{StreamExt, future::BoxFuture};
use reqwest::{Body, Client, Method, Url};
use rootyard::blob_store::key_provider::{KeyId, KeyProviderCapabilities, KeyProviderError, WrapContext};
use serde::{Deserialize, Serialize};
use std::{fmt, time::Duration};
use tokio::time::{Instant, timeout_at};
use zeroize::{Zeroize, Zeroizing};

const MAX_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_CIPHERTEXT_BYTES: usize = 4096;
const MAX_MOUNT_BYTES: usize = 64;
const DEFAULT_OPERATION_TIMEOUT: Duration = Duration::from_secs(5);

pub struct VaultTransitConfig {
    base: Url,
    token: Zeroizing<String>,
    mount: String,
    key_name: String,
    key_id: KeyId,
    operation_timeout: Duration,
}

impl fmt::Debug for VaultTransitConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultTransitConfig")
            .field("base", &self.base.as_str())
            .field("token", &"<redacted>")
            .field("mount", &self.mount)
            .field("key_name", &self.key_name)
            .field("operation_timeout", &self.operation_timeout)
            .finish()
    }
}

impl VaultTransitConfig {
    pub(super) fn from_env() -> Result<Self> {
        let base = std::env::var("PANDO_KMS_VAULT_URL").context("PANDO_KMS_VAULT_URL missing")?;
        let token = Zeroizing::new(
            std::env::var("PANDO_KMS_VAULT_TOKEN").context("PANDO_KMS_VAULT_TOKEN missing")?,
        );
        let mount = std::env::var("PANDO_KMS_VAULT_MOUNT").context("PANDO_KMS_VAULT_MOUNT missing")?;
        let key_name = std::env::var("PANDO_KMS_VAULT_KEY").context("PANDO_KMS_VAULT_KEY missing")?;
        Self::from_owned_values(&base, token, &mount, &key_name, None)
    }

    pub(super) fn from_values(
        base: &str,
        token: String,
        mount: &str,
        key_name: &str,
        operation_timeout: Option<Duration>,
    ) -> Result<Self> {
        Self::from_owned_values(base, Zeroizing::new(token), mount, key_name, operation_timeout)
    }

    fn from_owned_values(
        base: &str,
        token: Zeroizing<String>,
        mount: &str,
        key_name: &str,
        operation_timeout: Option<Duration>,
    ) -> Result<Self> {
        let base = Url::parse(base).context("invalid Pando Vault URL")?;
        let loopback = matches!(base.host_str(), Some("127.0.0.1" | "::1" | "localhost"));
        ensure!(
            base.scheme() == "https" || base.scheme() == "http" && loopback,
            "Pando Vault requires TLS except loopback HTTP"
        );
        ensure!(
            base.path() == "/"
                && base.query().is_none()
                && base.fragment().is_none()
                && base.username().is_empty()
                && base.password().is_none(),
            "Pando Vault URL must be an origin without credentials, path, query or fragment"
        );
        ensure!(
            !token.is_empty()
                && token.len() <= MAX_RESPONSE_BYTES
                && token.bytes().all(|byte| !byte.is_ascii_control() && !byte.is_ascii_whitespace()),
            "invalid Pando Vault token"
        );
        ensure!(valid_component(mount, MAX_MOUNT_BYTES), "invalid Pando Vault mount");
        ensure!(
            key_name == key_name.trim() && valid_kms_key_id(key_name),
            "invalid Pando Vault key name"
        );
        let key_id = KeyId::parse(key_name).map_err(|_| anyhow::anyhow!("invalid Pando Vault key id"))?;
        let operation_timeout = operation_timeout.unwrap_or(DEFAULT_OPERATION_TIMEOUT);
        ensure!(
            !operation_timeout.is_zero() && operation_timeout <= Duration::from_secs(60),
            "invalid Pando Vault operation timeout"
        );
        Ok(Self {
            base,
            token,
            mount: mount.to_owned(),
            key_name: key_name.to_owned(),
            key_id,
            operation_timeout,
        })
    }
}

pub struct VaultTransitProvider {
    config: VaultTransitConfig,
    client: Client,
}

impl fmt::Debug for VaultTransitProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultTransitProvider")
            .field("base", &self.config.base.as_str())
            .field("token", &"<redacted>")
            .field("mount", &self.config.mount)
            .field("key_name", &self.config.key_name)
            .finish()
    }
}

impl VaultTransitProvider {
    pub(super) fn from_config(config: VaultTransitConfig) -> Result<Self> {
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("failed constructing Pando Vault client")?;
        Ok(Self { config, client })
    }

    pub(super) fn from_env() -> Result<Self> {
        Self::from_config(VaultTransitConfig::from_env()?)
    }

    pub(super) fn key_name(&self) -> &str {
        &self.config.key_name
    }

    pub(super) async fn latest_version(&self) -> Result<i32> {
        self.read_key_metadata(self.operation_deadline()).await
    }

    pub(super) async fn rotate_key(&self) -> Result<()> {
        let deadline = self.operation_deadline();
        let _ = self
            .call(
                Method::POST,
                &format!("keys/{}/rotate", self.config.key_name),
                None,
                deadline,
            )
            .await?;
        Ok(())
    }

    pub(super) async fn wrap_at_version(
        &self,
        data_key: &PandoDataKey,
        context: &WrapContext,
        requested_version: Option<i32>,
    ) -> Result<PandoWrappedDek> {
        let deadline = self.operation_deadline();
        let latest_version = self.read_key_metadata(deadline).await?;
        let target_version = requested_version.unwrap_or(latest_version);
        ensure!(
            target_version >= 1 && target_version <= latest_version,
            "requested Vault Transit key version is unavailable"
        );
        let context = self.context_b64(context)?;
        let plaintext = Zeroizing::new(STANDARD.encode(data_key.expose_secret()));
        let body = Zeroizing::new(serde_json::to_vec(&EncryptRequest {
            plaintext: plaintext.as_str(),
            context: &context,
            key_version: target_version,
        })?);
        let bytes =
            self.call(Method::POST, &format!("encrypt/{}", self.config.key_name), Some(body), deadline).await?;
        let mut response: TransitResponse = serde_json::from_slice(&bytes)?;
        let ciphertext =
            response.data.ciphertext.take().context("Vault Transit encrypt response missing ciphertext")?;
        ensure_ciphertext(&ciphertext, target_version)?;
        Ok(versioned_wrapped_dek(&self.config.key_name, target_version, ciphertext))
    }

    pub(super) async fn unwrap(&self, wrapped: &PandoWrappedDek, context: &WrapContext) -> Result<PandoDataKey> {
        let deadline = self.operation_deadline();
        let latest_version = self.read_key_metadata(deadline).await?;
        let (key_id, _key_version, ciphertext) = self.versioned_parts(wrapped, latest_version)?;
        ensure!(key_id == self.config.key_name.as_str(), "Vault Transit wrapped DEK key id mismatch");
        let context = self.context_b64(context)?;
        let body = Zeroizing::new(serde_json::to_vec(&DecryptRequest { ciphertext, context: &context })?);
        let bytes =
            self.call(Method::POST, &format!("decrypt/{}", self.config.key_name), Some(body), deadline).await?;
        let mut response: TransitResponse = serde_json::from_slice(&bytes)?;
        let plaintext =
            Zeroizing::new(response.data.plaintext.take().context("Vault Transit decrypt response missing plaintext")?);
        let decoded = Zeroizing::new(STANDARD.decode(plaintext.as_bytes())?);
        ensure!(decoded.len() == rootyard::blob_store::key_provider::DATA_KEY_BYTES, "Vault returned an invalid DEK");
        let bytes: &[u8; rootyard::blob_store::key_provider::DATA_KEY_BYTES] =
            decoded.as_slice().try_into().map_err(|_| anyhow::anyhow!("Vault returned an invalid DEK"))?;
        Ok(PandoDataKey::copy_from_slice(bytes))
    }

    pub(super) async fn rewrap_at_version(
        &self,
        wrapped: &PandoWrappedDek,
        context: &WrapContext,
        requested_version: Option<i32>,
    ) -> Result<PandoWrappedDek> {
        let deadline = self.operation_deadline();
        let latest_version = self.read_key_metadata(deadline).await?;
        let target_version = requested_version.unwrap_or(latest_version);
        ensure!(
            target_version >= 1 && target_version <= latest_version,
            "requested Vault Transit key version is unavailable"
        );
        let (_, _, ciphertext) = self.versioned_parts(wrapped, latest_version)?;
        let context = self.context_b64(context)?;
        let body = Zeroizing::new(serde_json::to_vec(&RewrapRequest {
            ciphertext,
            context: &context,
            key_version: target_version,
        })?);
        let bytes = self.call(Method::POST, &format!("rewrap/{}", self.config.key_name), Some(body), deadline).await?;
        let mut response: TransitResponse = serde_json::from_slice(&bytes)?;
        let ciphertext = response.data.ciphertext.take().context("Vault Transit rewrap response missing ciphertext")?;
        ensure_ciphertext(&ciphertext, target_version)?;
        Ok(versioned_wrapped_dek(&self.config.key_name, target_version, ciphertext))
    }

    fn operation_deadline(&self) -> Instant {
        Instant::now() + self.config.operation_timeout
    }

    fn context_b64(&self, context: &WrapContext) -> Result<String> {
        Ok(STANDARD.encode(context.aad_digest(&self.config.key_id)))
    }

    fn versioned_parts<'a>(
        &self,
        wrapped: &'a PandoWrappedDek,
        latest_version: i32,
    ) -> Result<(&'a str, i32, &'a str)> {
        let PandoWrappedDek::Versioned { provider_kind, key_id, key_version, payload } = wrapped else {
            bail!("wrapped DEK is not a Pando Vault Transit payload");
        };
        ensure!(
            *provider_kind == PandoProviderKind::VaultTransit
                && key_id == &self.config.key_name
                && *key_version >= 1
                && *key_version <= latest_version,
            "wrapped DEK provider identity does not match the configured Vault Transit key"
        );
        let ciphertext = std::str::from_utf8(payload).context("Vault ciphertext is not UTF-8")?;
        ensure_ciphertext(ciphertext, *key_version)?;
        Ok((key_id, *key_version, ciphertext))
    }

    async fn read_key_metadata(&self, deadline: Instant) -> Result<i32> {
        let bytes = self.call(Method::GET, &format!("keys/{}", self.config.key_name), None, deadline).await?;
        parse_key_metadata(&bytes)
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<Zeroizing<Vec<u8>>>,
        deadline: Instant,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let mut url = self.config.base.clone();
        url.set_path(&format!("/v1/{}/{}", self.config.mount, path));
        let mut request = self.client.request(method, url).header("X-Vault-Token", self.config.token.as_str());
        if let Some(body) = body {
            request = request
                .header("Content-Type", "application/json")
                .body(Body::from(Bytes::from_owner(body)));
        }
        let response =
            timeout_at(deadline, request.send()).await.context("Vault Transit request deadline exceeded")??;
        ensure!(response.status().is_success(), "Vault Transit request failed");
        let mut stream = response.bytes_stream();
        let mut bytes = Zeroizing::new(Vec::new());
        loop {
            let next = timeout_at(deadline, stream.next()).await.context("Vault Transit response deadline exceeded")?;
            let Some(chunk) = next else {
                break;
            };
            let chunk = chunk.context("Vault Transit response read failed")?;
            ensure!(chunk.len() <= MAX_RESPONSE_BYTES - bytes.len(), "Vault Transit response exceeds limit");
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }
}

impl PandoKeyProvider for VaultTransitProvider {
    fn current_key_id(&self) -> &KeyId {
        &self.config.key_id
    }

    fn capabilities(&self) -> KeyProviderCapabilities {
        KeyProviderCapabilities {
            local_envelope: false,
            rewrap: true,
            retained_key_versions: true,
            provider_managed: true,
            plaintext_fallback: false,
        }
    }

    fn wrap_data_key<'a>(
        &'a self,
        data_key: &'a PandoDataKey,
        context: &'a WrapContext,
    ) -> BoxFuture<'a, std::result::Result<PandoWrappedDek, KeyProviderError>> {
        Box::pin(async move {
            self.wrap_at_version(data_key, context, None)
                .await
                .map_err(|_| KeyProviderError::KeyRing("Vault Transit operation failed closed"))
        })
    }

    fn unwrap_data_key<'a>(
        &'a self,
        wrapped: &'a PandoWrappedDek,
        context: &'a WrapContext,
    ) -> BoxFuture<'a, std::result::Result<PandoDataKey, KeyProviderError>> {
        Box::pin(async move {
            self.unwrap(wrapped, context)
                .await
                .map_err(|_| KeyProviderError::KeyRing("Vault Transit operation failed closed"))
        })
    }

    fn rewrap_data_key<'a>(
        &'a self,
        wrapped: &'a PandoWrappedDek,
        context: &'a WrapContext,
    ) -> BoxFuture<'a, std::result::Result<PandoWrappedDek, KeyProviderError>> {
        Box::pin(async move {
            self.rewrap_at_version(wrapped, context, None)
                .await
                .map_err(|_| KeyProviderError::KeyRing("Vault Transit operation failed closed"))
        })
    }
}

#[derive(Deserialize)]
struct MetadataEnvelope {
    data: KeyMetadata,
}

#[derive(Deserialize)]
struct KeyMetadata {
    #[serde(rename = "type")]
    key_type: Option<String>,
    derived: Option<bool>,
    latest_version: Option<i32>,
}

fn parse_key_metadata(bytes: &[u8]) -> Result<i32> {
    let envelope: MetadataEnvelope = serde_json::from_slice(bytes).context("invalid Vault key metadata")?;
    ensure!(envelope.data.key_type.as_deref() == Some("aes256-gcm96"), "Vault key is not aes256-gcm96");
    ensure!(envelope.data.derived == Some(true), "Vault key is not configured for derived contexts");
    let latest = envelope.data.latest_version.context("Vault key metadata missing latest_version")?;
    ensure!(latest >= 1, "Vault key latest_version is invalid");
    Ok(latest)
}

#[derive(Deserialize)]
struct TransitResponse {
    data: TransitData,
}

#[derive(Deserialize)]
struct TransitData {
    ciphertext: Option<String>,
    plaintext: Option<String>,
}

impl Drop for TransitData {
    fn drop(&mut self) {
        if let Some(plaintext) = &mut self.plaintext {
            plaintext.zeroize();
        }
    }
}

#[derive(Serialize)]
struct EncryptRequest<'a> {
    plaintext: &'a str,
    context: &'a str,
    key_version: i32,
}

#[derive(Serialize)]
struct DecryptRequest<'a> {
    ciphertext: &'a str,
    context: &'a str,
}

#[derive(Serialize)]
struct RewrapRequest<'a> {
    ciphertext: &'a str,
    context: &'a str,
    key_version: i32,
}

fn valid_component(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn ensure_ciphertext(ciphertext: &str, expected_version: i32) -> Result<()> {
    ensure!(
        !ciphertext.is_empty() && ciphertext.len() <= MAX_CIPHERTEXT_BYTES,
        "Vault ciphertext is empty or exceeds limit"
    );
    let version =
        parse_vault_ciphertext_version(ciphertext.as_bytes()).context("Vault ciphertext version is malformed")?;
    ensure!(version == expected_version, "Vault ciphertext version does not match the target key version");
    Ok(())
}

fn versioned_wrapped_dek(key_id: &str, key_version: i32, ciphertext: String) -> PandoWrappedDek {
    PandoWrappedDek::Versioned {
        provider_kind: PandoProviderKind::VaultTransit,
        key_id: key_id.to_owned(),
        key_version,
        payload: ciphertext.into_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_requires_strict_origin_tls_and_components() {
        let timeout = Some(Duration::from_secs(3));
        assert!(
            VaultTransitConfig::from_values(
                "https://vault.example.com",
                "token-value".to_owned(),
                "transit",
                "pando-vault-key",
                timeout,
            )
            .is_ok()
        );
        assert!(
            VaultTransitConfig::from_values(
                "http://127.0.0.1:8200",
                "token-value".to_owned(),
                "transit",
                "pando-vault-key",
                timeout,
            )
            .is_ok()
        );
        for base in [
            "http://vault.example.com",
            "https://vault.example.com/v1/transit",
            "https://vault.example.com/?x=1",
            "https://vault.example.com/#fragment",
            "https://user:pass@vault.example.com",
        ] {
            assert!(
                VaultTransitConfig::from_values(base, "token-value".to_owned(), "transit", "pando-vault-key", timeout)
                    .is_err(),
                "accepted {base}"
            );
        }
        for (mount, key) in [("", "pando-vault-key"), ("transit", ""), ("bad/mount", "pando-vault-key")] {
            assert!(
                VaultTransitConfig::from_values(
                    "https://vault.example.com",
                    "token-value".to_owned(),
                    mount,
                    key,
                    timeout,
                )
                .is_err()
            );
        }
        for key_name in ["a", "ab", " pando-vault-key", "pando-vault-key "] {
            assert!(
                VaultTransitConfig::from_values(
                    "https://vault.example.com",
                    "token-value".to_owned(),
                    "transit",
                    key_name,
                    timeout,
                )
                .is_err(),
                "accepted key name {key_name:?}"
            );
        }
        assert!(
            VaultTransitConfig::from_values(
                "https://vault.example.com",
                "token-value".to_owned(),
                "transit",
                "abc",
                timeout,
            )
            .is_ok()
        );
        let config = VaultTransitConfig::from_values(
            "https://vault.example.com",
            "super-secret-token".to_owned(),
            "transit",
            "pando-vault-key",
            timeout,
        )
        .unwrap();
        assert!(!format!("{config:?}").contains("super-secret-token"));
    }

    #[test]
    fn key_metadata_requires_derived_aes256_and_positive_latest_version() {
        let valid = br#"{"data":{"type":"aes256-gcm96","derived":true,"latest_version":3}}"#;
        assert_eq!(parse_key_metadata(valid).unwrap(), 3);
        for invalid in [
            br#"{"data":{"type":"aes256-gcm96","derived":false,"latest_version":3}}"#.as_slice(),
            br#"{"data":{"type":"rsa-2048","derived":true,"latest_version":3}}"#.as_slice(),
            br#"{"data":{"type":"aes256-gcm96","derived":true}}"#.as_slice(),
            br#"{"data":{"type":"aes256-gcm96","derived":true,"latest_version":0}}"#.as_slice(),
        ] {
            assert!(parse_key_metadata(invalid).is_err());
        }
    }

    #[test]
    fn ciphertext_version_parser_rejects_mismatch_and_malformed_values() {
        assert_eq!(parse_vault_ciphertext_version(b"vault:v3:abcdef"), Some(3));
        for value in [b"".as_slice(), b"vault:v0:abc", b"vault:vx:abc", b"vault:v2:", b"other:v2:abc"] {
            assert_eq!(parse_vault_ciphertext_version(value), None);
        }
        assert!(ensure_ciphertext("vault:v2:abcdef", 3).is_err());
        assert!(ensure_ciphertext("vault:v3:abcdef", 3).is_ok());
    }
}
