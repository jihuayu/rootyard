//! Short-lived domain-separated HMAC-SHA256 offload URL signing, key rotation,
//! strict claim/scope binding, and mandatory live per-request authorization.

use std::{collections::HashMap, fmt};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::hmac;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::cache_wake::replica_cache::{is_lower_hex_exact, lease_pin::AuthTask};

use super::{
    ssrf_guard::{validate_offload_host_pattern, validate_offload_uri, validate_policy_config},
    types::{
        MAX_OFFLOAD_TTL_SECS, OffloadPolicyConfig, PackObjectFormat, PackfileUriError, SignedPackfileDescriptor,
        validate_catalog_pack_oid, validate_hex_sha256, validate_pack_oid,
    },
};

const SIGNING_DOMAIN: &[u8] = b"rootyard-packfile-uri-v1";
const MIN_SIGNING_SECRET_BYTES: usize = 32;
const EXPECTED_QUERY_KEY_COUNT: usize = 9;

/// Async live authorization hook invoked on EVERY download before reading or streaming bytes.
pub trait LivePackReadAuthorizer: Send + Sync {
    fn authorize_pack_download<'a>(
        &'a self,
        tenant_id: Uuid,
        repository_id: Uuid,
        actor_id: Uuid,
        pack_oid: &'a str,
        pin_id: Uuid,
    ) -> AuthTask<'a, Result<(), PackfileUriError>>;
}

/// Zeroizing wrapper holding one named HMAC-SHA256 offload signing secret.
#[derive(Clone)]
pub struct SigningKeyMaterial {
    key_id: String,
    secret: Zeroizing<Vec<u8>>,
    active_for_signing: bool,
}

impl fmt::Debug for SigningKeyMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKeyMaterial")
            .field("key_id", &self.key_id)
            .field("secret", &"[REDACTED]")
            .field("active_for_signing", &self.active_for_signing)
            .finish()
    }
}

impl SigningKeyMaterial {
    /// Constructs validated signing key material (`secret.len() >= 32`).
    pub fn new(key_id: impl Into<String>, secret: Vec<u8>) -> Result<Self, PackfileUriError> {
        let key_id = key_id.into();
        if key_id.is_empty()
            || key_id.len() > 64
            || !key_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(PackfileUriError::InvalidPolicy("invalid signing key_id".to_owned()));
        }
        if secret.len() < MIN_SIGNING_SECRET_BYTES {
            return Err(PackfileUriError::InvalidPolicy(format!(
                "signing secret must be at least {MIN_SIGNING_SECRET_BYTES} bytes"
            )));
        }
        Ok(Self { key_id, secret: Zeroizing::new(secret), active_for_signing: true })
    }
}

/// Keyring supporting zero-downtime key rotation and immediate compromised-key revocation.
#[derive(Clone, Default)]
pub struct PackUriKeyring {
    keys: HashMap<String, SigningKeyMaterial>,
}

impl fmt::Debug for PackUriKeyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PackUriKeyring").field("key_count", &self.keys.len()).finish()
    }
}

impl PackUriKeyring {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_active(&mut self, material: SigningKeyMaterial) {
        self.keys.insert(material.key_id.clone(), material);
    }

    /// Retires `key_id` from issuing new URLs while continuing to verify existing unexpired URLs.
    pub fn retire_for_signing(&mut self, key_id: &str) -> bool {
        if let Some(entry) = self.keys.get_mut(key_id) {
            entry.active_for_signing = false;
            true
        } else {
            false
        }
    }

    /// Immediately revokes `key_id` so neither signing nor verification succeeds under it.
    pub fn revoke_key(&mut self, key_id: &str) -> bool {
        self.keys.remove(key_id).is_some()
    }

    fn sign_bytes(&self, key_id: &str, message: &[u8]) -> Result<String, PackfileUriError> {
        let mat = self
            .keys
            .get(key_id)
            .filter(|m| m.active_for_signing)
            .ok_or_else(|| PackfileUriError::InvalidPolicy(format!("active signing key '{key_id}' missing")))?;
        let key = hmac::Key::new(hmac::HMAC_SHA256, &mat.secret);
        let tag = hmac::sign(&key, message);
        Ok(URL_SAFE_NO_PAD.encode(tag.as_ref()))
    }

    fn verify_bytes(&self, key_id: &str, message: &[u8], sig_b64: &str) -> Result<(), PackfileUriError> {
        let mat = self
            .keys
            .get(key_id)
            .ok_or_else(|| PackfileUriError::InvalidSignature("unknown or revoked signing key".to_owned()))?;
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(sig_b64.as_bytes())
            .map_err(|_| PackfileUriError::InvalidSignature("malformed signature encoding".to_owned()))?;
        let key = hmac::Key::new(hmac::HMAC_SHA256, &mat.secret);
        hmac::verify(&key, message, &sig_bytes)
            .map_err(|_| PackfileUriError::InvalidSignature("offload url hmac verification failed".to_owned()))
    }
}

/// Canonical claims embedded inside a signed `packfile-uris` download URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedDownloadClaims {
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub pack_oid: String,
    pub object_format: PackObjectFormat,
    pub allowed_host: String,
    pub canonical_path: String,
    pub expires_at_unix: u64,
    pub key_id: String,
    pub scope_nonce: String,
    pub pin_id: Uuid,
}

impl SignedDownloadClaims {
    fn canonical_transcript(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        append_lp(&mut out, SIGNING_DOMAIN);
        append_lp(&mut out, self.tenant_id.hyphenated().to_string().as_bytes());
        append_lp(&mut out, self.repository_id.hyphenated().to_string().as_bytes());
        append_lp(&mut out, self.pack_oid.as_bytes());
        append_lp(&mut out, self.object_format.as_str().as_bytes());
        append_lp(&mut out, b"https");
        append_lp(&mut out, self.allowed_host.as_bytes());
        append_lp(&mut out, b"443");
        append_lp(&mut out, self.canonical_path.as_bytes());
        append_lp(&mut out, self.expires_at_unix.to_string().as_bytes());
        append_lp(&mut out, self.key_id.as_bytes());
        append_lp(&mut out, self.scope_nonce.as_bytes());
        append_lp(&mut out, self.pin_id.hyphenated().to_string().as_bytes());
        out
    }
}

fn append_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Arguments required to mint one short-lived signed HTTPS offload descriptor.
pub struct MintUriRequest<'a> {
    pub tenant_id: Uuid,
    pub repository_id: Uuid,
    pub pack_oid: &'a str,
    pub pack_hash_hex: &'a str,
    pub sha256_hex: &'a str,
    pub byte_len: u64,
    pub object_format: PackObjectFormat,
    pub allowed_host: &'a str,
    pub pin_id: Uuid,
    pub scope_nonce: &'a str,
    pub now_unix: u64,
    pub policy: &'a OffloadPolicyConfig,
    pub resolved_ips: &'a [std::net::IpAddr],
}

/// Mints and SSRF-validates a signed short-lived `https://` offload URL.
pub fn mint_signed_offload_uri(
    keyring: &PackUriKeyring,
    req: &MintUriRequest<'_>,
) -> Result<SignedPackfileDescriptor, PackfileUriError> {
    validate_policy_config(req.policy)?;
    let host = validate_offload_host_pattern(req.allowed_host)?;
    if !req.policy.allowed_hosts.iter().any(|allowed| allowed == &host) {
        return Err(PackfileUriError::SsrfBlocked("target host outside policy allowlist".to_owned()));
    }
    validate_catalog_pack_oid(req.pack_oid, req.object_format)?;
    validate_pack_oid(req.pack_hash_hex, req.object_format)?;
    validate_hex_sha256(req.sha256_hex)?;
    if req.byte_len == 0 {
        return Err(PackfileUriError::InvalidPolicy("cannot offload empty pack".to_owned()));
    }
    if !(16..=64).contains(&req.scope_nonce.len()) || !is_lower_hex_exact(req.scope_nonce, req.scope_nonce.len()) {
        return Err(PackfileUriError::InvalidPolicy(
            "scope_nonce must be 16..=64 lowercase hex characters".to_owned(),
        ));
    }
    let expires_at_unix = req
        .now_unix
        .checked_add(req.policy.ttl_secs)
        .ok_or_else(|| PackfileUriError::InvalidPolicy("ttl overflow".to_owned()))?;
    let canonical_path = build_canonical_pack_path(
        &req.policy.path_prefix,
        req.tenant_id,
        req.repository_id,
        req.pack_oid,
    );
    let claims = SignedDownloadClaims {
        tenant_id: req.tenant_id,
        repository_id: req.repository_id,
        pack_oid: req.pack_oid.to_owned(),
        object_format: req.object_format,
        allowed_host: host.clone(),
        canonical_path: canonical_path.clone(),
        expires_at_unix,
        key_id: req.policy.key_id.clone(),
        scope_nonce: req.scope_nonce.to_owned(),
        pin_id: req.pin_id,
    };
    let sig = keyring.sign_bytes(&req.policy.key_id, &claims.canonical_transcript())?;
    let uri = format!(
        "https://{host}{canonical_path}?tenant={}&repo={}&pack={}&fmt={}&exp={}&kid={}&nonce={}&pin={}&sig={}",
        req.tenant_id.hyphenated(),
        req.repository_id.hyphenated(),
        req.pack_oid,
        req.object_format.as_str(),
        expires_at_unix,
        req.policy.key_id,
        req.scope_nonce,
        req.pin_id.hyphenated(),
        sig
    );
    validate_offload_uri(&uri, req.policy, req.resolved_ips)?;
    Ok(SignedPackfileDescriptor {
        pack_oid: req.pack_oid.to_owned(),
        pack_hash_hex: req.pack_hash_hex.to_owned(),
        sha256_hex: req.sha256_hex.to_owned(),
        byte_len: req.byte_len,
        uri,
        expires_at_unix,
        pin_id: req.pin_id,
        key_id: req.policy.key_id.clone(),
        scope_nonce: req.scope_nonce.to_owned(),
    })
}

/// Parameters verifying an inbound signed offload download request.
pub struct VerifyDownloadParams<'a> {
    pub raw_uri: &'a str,
    pub expected_tenant_id: Uuid,
    pub expected_repository_id: Uuid,
    pub expected_pack_oid: &'a str,
    pub expected_format: PackObjectFormat,
    pub actor_id: Uuid,
    pub now_unix: u64,
    pub policy: &'a OffloadPolicyConfig,
    pub resolved_ips: &'a [std::net::IpAddr],
}

/// Verified download claims returned only after SSRF, scope, HMAC, TTL, and live auth pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedDownloadContext {
    pub claims: SignedDownloadClaims,
}

/// Verifies URL SSRF safety, strict claim/path binding, HMAC-SHA256 tag, expiry, and live authorization.
pub async fn verify_signed_download_request(
    keyring: &PackUriKeyring,
    authorizer: &dyn LivePackReadAuthorizer,
    params: &VerifyDownloadParams<'_>,
) -> Result<VerifiedDownloadContext, PackfileUriError> {
    let validated = validate_offload_uri(params.raw_uri, params.policy, params.resolved_ips)?;
    let query_map = parse_strict_query(&validated.query)?;
    let claims = extract_and_bind_claims(&validated.host, &validated.path, &query_map, params)?;
    let sig = query_map
        .get("sig")
        .ok_or_else(|| PackfileUriError::InvalidSignature("missing signature".to_owned()))?;
    keyring.verify_bytes(&claims.key_id, &claims.canonical_transcript(), sig)?;
    if params.now_unix > claims.expires_at_unix {
        return Err(PackfileUriError::TokenExpired);
    }
    if claims.expires_at_unix.saturating_sub(params.now_unix) > MAX_OFFLOAD_TTL_SECS {
        return Err(PackfileUriError::InvalidSignature("excessive token lifetime".to_owned()));
    }
    authorizer
        .authorize_pack_download(
            claims.tenant_id,
            claims.repository_id,
            params.actor_id,
            &claims.pack_oid,
            claims.pin_id,
        )
        .await?;
    Ok(VerifiedDownloadContext { claims })
}

fn build_canonical_pack_path(prefix: &str, tenant_id: Uuid, repository_id: Uuid, pack_oid: &str) -> String {
    let base = if prefix == "/" { "" } else { prefix };
    format!(
        "{base}/{}/{}/{}.pack",
        tenant_id.hyphenated(),
        repository_id.hyphenated(),
        pack_oid
    )
}

fn parse_strict_query(query: &str) -> Result<HashMap<&str, &str>, PackfileUriError> {
    if query.is_empty() {
        return Err(PackfileUriError::InvalidSignature("missing signed query parameters".to_owned()));
    }
    let mut map = HashMap::with_capacity(EXPECTED_QUERY_KEY_COUNT);
    for pair in query.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            return Err(PackfileUriError::InvalidSignature("malformed query parameter".to_owned()));
        };
        if v.is_empty() || !matches!(k, "tenant" | "repo" | "pack" | "fmt" | "exp" | "kid" | "nonce" | "pin" | "sig") {
            return Err(PackfileUriError::InvalidSignature("unexpected or empty query key".to_owned()));
        }
        if map.insert(k, v).is_some() {
            return Err(PackfileUriError::InvalidSignature("duplicate query parameter".to_owned()));
        }
    }
    if map.len() != EXPECTED_QUERY_KEY_COUNT {
        return Err(PackfileUriError::InvalidSignature("incomplete signed query set".to_owned()));
    }
    Ok(map)
}

fn extract_and_bind_claims(
    host: &str,
    path: &str,
    map: &HashMap<&str, &str>,
    params: &VerifyDownloadParams<'_>,
) -> Result<SignedDownloadClaims, PackfileUriError> {
    let tenant_id = Uuid::parse_str(map["tenant"])
        .map_err(|_| PackfileUriError::ScopeMismatch("invalid tenant uuid".to_owned()))?;
    let repository_id = Uuid::parse_str(map["repo"])
        .map_err(|_| PackfileUriError::ScopeMismatch("invalid repo uuid".to_owned()))?;
    let pin_id = Uuid::parse_str(map["pin"])
        .map_err(|_| PackfileUriError::ScopeMismatch("invalid pin uuid".to_owned()))?;
    let pack_oid = map["pack"].to_owned();
    let fmt = match map["fmt"] {
        "sha1" => PackObjectFormat::Sha1,
        "sha256" => PackObjectFormat::Sha256,
        _ => return Err(PackfileUriError::ScopeMismatch("invalid object format claim".to_owned())),
    };
    if tenant_id != params.expected_tenant_id
        || repository_id != params.expected_repository_id
        || pack_oid != params.expected_pack_oid
        || fmt != params.expected_format
    {
        return Err(PackfileUriError::ScopeMismatch("tenant, repo, pack, or format mismatch".to_owned()));
    }
    let expected_path = build_canonical_pack_path(
        &params.policy.path_prefix,
        tenant_id,
        repository_id,
        &pack_oid,
    );
    if path != expected_path {
        return Err(PackfileUriError::ScopeMismatch("url path does not match signed scope".to_owned()));
    }
    let expires_at_unix = map["exp"]
        .parse::<u64>()
        .map_err(|_| PackfileUriError::InvalidSignature("invalid expiration timestamp".to_owned()))?;
    let scope_nonce = map["nonce"];
    if !(16..=64).contains(&scope_nonce.len()) || !is_lower_hex_exact(scope_nonce, scope_nonce.len()) {
        return Err(PackfileUriError::InvalidSignature("invalid scope nonce".to_owned()));
    }
    Ok(SignedDownloadClaims {
        tenant_id,
        repository_id,
        pack_oid,
        object_format: fmt,
        allowed_host: host.to_owned(),
        canonical_path: expected_path,
        expires_at_unix,
        key_id: map["kid"].to_owned(),
        scope_nonce: scope_nonce.to_owned(),
        pin_id,
    })
}
