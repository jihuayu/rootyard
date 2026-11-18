//! Bounded HTTP packfile downloader enforcing single-resolution pinned DNS
//! (`resolve_to_addrs`), redirect refusal, chunked byte caps, shared inflight
//! byte budgets, and SHA-256 + `.pack` trailer checksum verification.

use std::{sync::Arc, time::Duration};

use reqwest::redirect;
use tokio::sync::Semaphore;

use super::{
    delivery::validate_pack_bytes_integrity,
    ssrf_guard::{PackUriDnsResolver, SystemDnsResolver, validate_offload_uri_and_resolve, validate_policy_config},
    types::{
        FallbackReason, InflightBytesLimiter, OffloadPolicyConfig, PackObjectFormat, PackfileUriError,
        SignedPackfileDescriptor,
    },
};

/// Bounded HTTP pack download client config enforcing pinned DNS, no redirects, and shared byte caps.
#[derive(Clone)]
pub struct PackDownloaderConfig {
    pub resolver: Arc<dyn PackUriDnsResolver>,
    pub extra_root_certs: Vec<reqwest::Certificate>,
    pub concurrency_limit: Arc<Semaphore>,
    pub inflight_bytes: Arc<InflightBytesLimiter>,
    pub request_deadline: Duration,
    pub max_retries: usize,
    pub max_pack_bytes: u64,
}

impl PackDownloaderConfig {
    /// Constructs a validated downloader config; fails closed when `!policy.enabled`.
    pub fn build(policy: &OffloadPolicyConfig) -> Result<Self, PackfileUriError> {
        validate_policy_config(policy)?;
        Ok(Self {
            resolver: Arc::new(SystemDnsResolver),
            extra_root_certs: Vec::new(),
            concurrency_limit: Arc::new(Semaphore::new(policy.max_inflight_downloads.max(1))),
            inflight_bytes: Arc::new(InflightBytesLimiter::new(policy.max_inflight_bytes)),
            request_deadline: Duration::from_millis(policy.request_deadline_ms),
            max_retries: policy.max_retries_per_pack,
            max_pack_bytes: policy.max_pack_bytes_per_request,
        })
    }
}

/// Outcome of downloading and verifying a signed pack URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchAttemptResult {
    Verified {
        bytes: Vec<u8>,
        attempts: usize,
        retransmitted_bytes: u64,
    },
    NeedsInlineFallback(FallbackReason),
}

/// Resolves + validates peer IPs once, pins them into `reqwest`, streams bounded chunks,
/// and verifies exact byte length, SHA-256, and `.pack` trailer checksum.
pub async fn fetch_pack_with_integrity_and_retry(
    cfg: &PackDownloaderConfig,
    desc: &SignedPackfileDescriptor,
    object_format: PackObjectFormat,
    policy: &OffloadPolicyConfig,
) -> Result<FetchAttemptResult, PackfileUriError> {
    let validated = validate_offload_uri_and_resolve(&desc.uri, policy, cfg.resolver.as_ref())?;
    if desc.byte_len == 0 || desc.byte_len > cfg.max_pack_bytes {
        return Err(PackfileUriError::CapacityExceeded("pack exceeds byte cap".to_owned()));
    }
    let _permit = cfg
        .concurrency_limit
        .clone()
        .acquire_owned()
        .await
        .map_err(|_| PackfileUriError::CapacityExceeded("downloader semaphore closed".to_owned()))?;
    let _bytes_guard = cfg.inflight_bytes.try_reserve(desc.byte_len)?;

    let mut builder = reqwest::Client::builder()
        .redirect(redirect::Policy::none())
        .no_proxy()
        .timeout(cfg.request_deadline)
        .resolve_to_addrs(&validated.host, &validated.pinned_addrs);
    for cert in &cfg.extra_root_certs {
        builder = builder.add_root_certificate(cert.clone());
    }
    let pinned_client = builder
        .build()
        .map_err(|e| PackfileUriError::Internal(format!("pinned client build failed: {e}")))?;

    let hard_cap = desc.byte_len.min(cfg.max_pack_bytes);
    let mut retransmitted_bytes = 0u64;
    let total_attempts = cfg.max_retries.saturating_add(1);
    for attempt in 1..=total_attempts {
        let fut = single_chunked_fetch(&pinned_client, &desc.uri, hard_cap);
        let bytes = match tokio::time::timeout(cfg.request_deadline, fut).await {
            Ok(Ok(data)) => data,
            Ok(Err(
                err @ (PackfileUriError::SsrfBlocked(_)
                | PackfileUriError::CapacityExceeded(_)
                | PackfileUriError::Unauthorized
                | PackfileUriError::RetentionPinMissing(_)),
            )) => return Err(err),
            Ok(Err(_)) | Err(_) => {
                if attempt == total_attempts {
                    return Ok(FetchAttemptResult::NeedsInlineFallback(
                        FallbackReason::PreDownloadRetryExhausted,
                    ));
                }
                continue;
            }
        };
        if bytes.len() as u64 != desc.byte_len && attempt < total_attempts {
            retransmitted_bytes = retransmitted_bytes.saturating_add(bytes.len() as u64);
            continue;
        }
        validate_pack_bytes_integrity(&bytes, desc.byte_len, &desc.sha256_hex, &desc.pack_hash_hex, object_format)?;
        return Ok(FetchAttemptResult::Verified { bytes, attempts: attempt, retransmitted_bytes });
    }
    Ok(FetchAttemptResult::NeedsInlineFallback(
        FallbackReason::PreDownloadRetryExhausted,
    ))
}

async fn single_chunked_fetch(
    client: &reqwest::Client,
    uri: &str,
    hard_cap: u64,
) -> Result<Vec<u8>, PackfileUriError> {
    let mut resp = client
        .get(uri)
        .send()
        .await
        .map_err(|_| PackfileUriError::CdnUnavailable("offload http transport error".to_owned()))?;
    if resp.status().is_redirection() {
        return Err(PackfileUriError::SsrfBlocked(
            "unexpected redirect blocked by SSRF policy".to_owned(),
        ));
    }
    if resp.status() == reqwest::StatusCode::UNAUTHORIZED || resp.status() == reqwest::StatusCode::FORBIDDEN {
        return Err(PackfileUriError::Unauthorized);
    }
    if resp.status() == reqwest::StatusCode::GONE {
        return Err(PackfileUriError::RetentionPinMissing(
            "offload lease revoked or expired".to_owned(),
        ));
    }
    if !resp.status().is_success() {
        return Err(PackfileUriError::CdnUnavailable(format!(
            "offload endpoint returned {}",
            resp.status().as_u16()
        )));
    }
    if let Some(cl) = resp.content_length()
        && cl > hard_cap
    {
        return Err(PackfileUriError::CapacityExceeded("response content-length exceeds cap".to_owned()));
    }
    let cap_usize = usize::try_from(hard_cap).unwrap_or(usize::MAX);
    let mut out = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|_| PackfileUriError::CdnUnavailable("interrupted response chunk".to_owned()))?
    {
        if out.len().saturating_add(chunk.len()) > cap_usize {
            return Err(PackfileUriError::CapacityExceeded("chunked response exceeded pack byte cap".to_owned()));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}
