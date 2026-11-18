//! Strict HTTPS-only SSRF, host allowlist, path-traversal, and DNS IP guards
//! for signed `packfile-uris` offload delivery.

use std::net::IpAddr;

use axum::http::Uri;

use crate::webhooks::policy::{host_is_loopback, permitted_peer};

use super::types::{
    MAX_DEADLINE_MS, MAX_OFFLOAD_BYTES_HARD_CAP, MAX_OFFLOAD_TTL_SECS, MAX_RETENTION_GRACE_SECS,
    MAX_RETRIES_HARD_CAP, MAX_URIS_PER_FETCH_CAP, MIN_DEADLINE_MS, MIN_OFFLOAD_TTL_SECS, OffloadPolicyConfig,
    PackfileUriError,
};

const MAX_URI_LEN: usize = 2048;

/// Canonical parsed offload URI validated against scheme, allowlist, path, and DNS IP rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedOffloadUri {
    pub scheme: String,
    pub host: String,
    pub port: Option<u16>,
    pub path: String,
    pub query: String,
}

/// Validates an offload host allowlist entry: lowercase public multi-label DNS name only.
pub fn validate_offload_host_pattern(host: &str) -> Result<String, PackfileUriError> {
    let trimmed = host.trim();
    if trimmed.is_empty() || trimmed.len() > 253 {
        return Err(PackfileUriError::SsrfBlocked("empty or overlong offload host".to_owned()));
    }
    if trimmed.bytes().any(|b| b <= 32 || b == 127 || b.is_ascii_uppercase()) {
        return Err(PackfileUriError::SsrfBlocked(
            "offload host must be lowercase ASCII without control/whitespace chars".to_owned(),
        ));
    }
    if trimmed.contains('*') || trimmed.contains('@') || trimmed.contains(':') || trimmed.contains('/') {
        return Err(PackfileUriError::SsrfBlocked(
            "wildcard, port, or delimiter not allowed in offload host".to_owned(),
        ));
    }
    if trimmed.parse::<IpAddr>().is_ok() {
        return Err(PackfileUriError::SsrfBlocked(
            "raw IP literals are forbidden as offload hosts".to_owned(),
        ));
    }
    if is_blocked_internal_hostname(trimmed) {
        return Err(PackfileUriError::SsrfBlocked(format!(
            "internal or loopback hostname forbidden: {trimmed}"
        )));
    }
    if !trimmed.contains('.') || trimmed.starts_with('.') || trimmed.ends_with('.') {
        return Err(PackfileUriError::SsrfBlocked(
            "offload host must be a multi-label DNS name".to_owned(),
        ));
    }
    for label in trimmed.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(PackfileUriError::SsrfBlocked(format!("invalid DNS label in offload host: {trimmed}")));
        }
    }
    Ok(trimmed.to_owned())
}

fn is_blocked_internal_hostname(host: &str) -> bool {
    host_is_loopback(host)
        || host == "metadata.google.internal"
        || host == "metadata"
        || host.ends_with(".internal")
        || host.ends_with(".local")
        || host.ends_with(".localdomain")
        || host.ends_with(".home.arpa")
}

/// Validates and normalizes the CDN path prefix (leading `/`, no traversal or trailing `/`).
pub fn validate_path_prefix(prefix: &str) -> Result<String, PackfileUriError> {
    if prefix.is_empty() || !prefix.starts_with('/') {
        return Err(PackfileUriError::InvalidPolicy("path_prefix must start with '/'".to_owned()));
    }
    if prefix.len() > 1 && prefix.ends_with('/') {
        return Err(PackfileUriError::InvalidPolicy(
            "path_prefix must not end with '/'".to_owned(),
        ));
    }
    validate_clean_path(prefix)?;
    Ok(prefix.to_owned())
}

/// Validates [`OffloadPolicyConfig`] before advertising or minting offload URIs.
pub fn validate_policy_config(policy: &OffloadPolicyConfig) -> Result<(), PackfileUriError> {
    if policy.allowed_scheme != "https" {
        return Err(PackfileUriError::UnsupportedProtocol(format!(
            "only 'https' offload scheme is permitted, got '{}'",
            policy.allowed_scheme
        )));
    }
    validate_path_prefix(&policy.path_prefix)?;
    if policy.key_id.is_empty()
        || policy.key_id.len() > 64
        || !policy.key_id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(PackfileUriError::InvalidPolicy(
            "key_id must be 1..=64 ASCII alphanumeric, '-', or '_' characters".to_owned(),
        ));
    }
    if !(MIN_OFFLOAD_TTL_SECS..=MAX_OFFLOAD_TTL_SECS).contains(&policy.ttl_secs) {
        return Err(PackfileUriError::InvalidPolicy(format!(
            "ttl_secs must stay within {MIN_OFFLOAD_TTL_SECS}..={MAX_OFFLOAD_TTL_SECS}"
        )));
    }
    if policy.retention_grace_secs > MAX_RETENTION_GRACE_SECS {
        return Err(PackfileUriError::InvalidPolicy(format!(
            "retention_grace_secs exceeds {MAX_RETENTION_GRACE_SECS}"
        )));
    }
    if policy.max_uris_per_fetch == 0 || policy.max_uris_per_fetch > MAX_URIS_PER_FETCH_CAP {
        return Err(PackfileUriError::InvalidPolicy(format!(
            "max_uris_per_fetch must stay within 1..={MAX_URIS_PER_FETCH_CAP}"
        )));
    }
    if policy.max_pack_bytes_per_request == 0 || policy.max_pack_bytes_per_request > MAX_OFFLOAD_BYTES_HARD_CAP {
        return Err(PackfileUriError::InvalidPolicy("invalid max_pack_bytes_per_request".to_owned()));
    }
    if policy.max_inflight_downloads == 0 || policy.max_inflight_downloads > 64 {
        return Err(PackfileUriError::InvalidPolicy("max_inflight_downloads must stay in 1..=64".to_owned()));
    }
    if policy.max_retries_per_pack > MAX_RETRIES_HARD_CAP {
        return Err(PackfileUriError::InvalidPolicy(format!(
            "max_retries_per_pack exceeds {MAX_RETRIES_HARD_CAP}"
        )));
    }
    if !(MIN_DEADLINE_MS..=MAX_DEADLINE_MS).contains(&policy.request_deadline_ms) {
        return Err(PackfileUriError::InvalidPolicy("request_deadline_ms out of bounds".to_owned()));
    }
    if policy.enabled && policy.allowed_hosts.is_empty() {
        return Err(PackfileUriError::InvalidPolicy(
            "enabled offload policy requires at least one allowlisted host".to_owned(),
        ));
    }
    for host in &policy.allowed_hosts {
        validate_offload_host_pattern(host)?;
    }
    Ok(())
}

/// Validates a concrete offload URI against HTTPS-only, allowlist, traversal, port, and resolved DNS IPs.
pub fn validate_offload_uri(
    raw_uri: &str,
    policy: &OffloadPolicyConfig,
    resolved_ips: &[IpAddr],
) -> Result<ValidatedOffloadUri, PackfileUriError> {
    validate_policy_config(policy)?;
    if raw_uri.is_empty() || raw_uri.len() > MAX_URI_LEN {
        return Err(PackfileUriError::SsrfBlocked("offload uri length out of bounds".to_owned()));
    }
    if raw_uri.bytes().any(|b| b <= 32 || b == 127 || b == b'\\' || b == b'#') {
        return Err(PackfileUriError::SsrfBlocked(
            "offload uri contains forbidden control, backslash, whitespace, or fragment chars".to_owned(),
        ));
    }
    let parsed: Uri = raw_uri
        .parse()
        .map_err(|_| PackfileUriError::SsrfBlocked("unparseable offload uri".to_owned()))?;
    if parsed.scheme_str() != Some("https") {
        return Err(PackfileUriError::UnsupportedProtocol("offload uri must use https".to_owned()));
    }
    let authority = parsed
        .authority()
        .ok_or_else(|| PackfileUriError::SsrfBlocked("offload uri missing authority".to_owned()))?;
    if authority.as_str().contains('@') {
        return Err(PackfileUriError::SsrfBlocked("userinfo '@' is forbidden in offload uri".to_owned()));
    }
    if let Some(port) = parsed.port_u16()
        && port != 443
    {
        return Err(PackfileUriError::SsrfBlocked(format!(
            "arbitrary offload port :{port} is forbidden"
        )));
    }
    let host = validate_offload_host_pattern(authority.host())?;
    if !policy.allowed_hosts.iter().any(|allowed| allowed == &host) {
        return Err(PackfileUriError::SsrfBlocked(format!(
            "host '{host}' is not in offload allowlist"
        )));
    }
    for &ip in resolved_ips {
        if !permitted_peer(host_is_loopback(&host), ip, false) {
            return Err(PackfileUriError::SsrfBlocked(format!(
                "resolved peer address {ip} violates public-egress SSRF policy"
            )));
        }
    }
    let path = parsed.path();
    validate_clean_path(path)?;
    if !path_matches_prefix(path, &policy.path_prefix) {
        return Err(PackfileUriError::SsrfBlocked(
            "offload uri path outside configured path_prefix".to_owned(),
        ));
    }
    let query = parsed.query().unwrap_or_default().to_owned();
    Ok(ValidatedOffloadUri {
        scheme: "https".to_owned(),
        host,
        port: parsed.port_u16(),
        path: path.to_owned(),
        query,
    })
}

fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    if prefix == "/" {
        return path.starts_with('/');
    }
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn validate_clean_path(path: &str) -> Result<(), PackfileUriError> {
    if !path.starts_with('/') || path.contains("//") {
        return Err(PackfileUriError::SsrfBlocked("invalid offload path slashes".to_owned()));
    }
    let lower = path.to_ascii_lowercase();
    if lower.contains("%2e") || lower.contains("%2f") || lower.contains("%5c") || lower.contains("%00") {
        return Err(PackfileUriError::SsrfBlocked("encoded traversal sequence blocked".to_owned()));
    }
    for segment in path.split('/').skip(1) {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(PackfileUriError::SsrfBlocked("dot/empty path traversal blocked".to_owned()));
        }
    }
    Ok(())
}

/// Strips signed query parameters/credentials before writing any offload URI into logs or errors.
pub fn redact_uri_for_log(raw_uri: &str) -> String {
    let Ok(parsed) = raw_uri.parse::<Uri>() else {
        return "[invalid-uri]".to_owned();
    };
    let scheme = parsed.scheme_str().unwrap_or("unknown");
    let host = parsed.host().unwrap_or("unknown");
    let path = parsed.path();
    if parsed.query().is_some() {
        format!("{scheme}://{host}{path}?[REDACTED]")
    } else {
        format!("{scheme}://{host}{path}")
    }
}
