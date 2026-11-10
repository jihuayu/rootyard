//! RFC 2104 HMAC-SHA256 webhook payload signing, constant-time signature verification,
//! standard `X-Rootyard-*` delivery header construction, and SSRF-safe HTTP/1.1 socket transport.
use crate::{
    Error,
    auth::idempotency_key,
    pulls::models::{CHECK_FIELDS, CheckRun},
    webhooks::{
        models::{CiCallbackInput, validate_webhook_url_with_policy},
        policy,
    },
};
use axum::http::{HeaderMap, StatusCode};
use deadpool_postgres::Transaction;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{future::Future, net::SocketAddr, pin::Pin, time::Duration};
use tokio::time::Instant;
use uuid::Uuid;

pub const SIGNATURE_PREFIX: &str = "sha256=";
pub const HEADER_SIGNATURE_256: &str = "x-rootyard-signature-256";
pub const HEADER_EVENT: &str = "x-rootyard-event";
pub const HEADER_DELIVERY: &str = "x-rootyard-delivery";
pub const HEADER_HOOK_ID: &str = "x-rootyard-hook-id";
pub const HEADER_ATTEMPT: &str = "x-rootyard-attempt";
const HMAC_BLOCK_SIZE: usize = 64;

/// Returns the lowercase 64-character hexadecimal SHA-256 digest of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Computes raw 32-byte RFC 2104 `HMAC-SHA256(secret, payload)` using 64-byte block padding
/// (`ipad = 0x36`, `opad = 0x5c`) over `sha2::Sha256`.
pub fn hmac_sha256_bytes(secret: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; HMAC_BLOCK_SIZE];
    if secret.len() > HMAC_BLOCK_SIZE {
        let digest = Sha256::digest(secret);
        key_block[..32].copy_from_slice(&digest);
    } else {
        key_block[..secret.len()].copy_from_slice(secret);
    }

    let mut ipad = [0x36u8; HMAC_BLOCK_SIZE];
    let mut opad = [0x5cu8; HMAC_BLOCK_SIZE];
    for idx in 0..HMAC_BLOCK_SIZE {
        ipad[idx] ^= key_block[idx];
        opad[idx] ^= key_block[idx];
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(payload);
    let inner_hash = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    let outer_hash = outer.finalize();

    let mut mac = [0u8; 32];
    mac.copy_from_slice(&outer_hash);
    mac
}

/// Computes lowercase 64-character hex `HMAC-SHA256(secret, payload)`.
pub fn hmac_sha256_hex(secret: &str, payload: &[u8]) -> String {
    hex::encode(hmac_sha256_bytes(secret.as_bytes(), payload))
}

/// Formats the canonical `X-Rootyard-Signature-256` header value (`sha256=<64-hex>`).
pub fn signature_header(secret: &str, payload: &[u8]) -> String {
    format!("{SIGNATURE_PREFIX}{}", hmac_sha256_hex(secret, payload))
}

/// Constant-time byte slice equality check without early-return branching on content.
pub fn constant_time_eq(lhs: &[u8], rhs: &[u8]) -> bool {
    let mut diff = lhs.len() ^ rhs.len();
    let max_len = lhs.len().max(rhs.len());
    for idx in 0..max_len {
        let a = lhs.get(idx).copied().unwrap_or(0);
        let b = rhs.get(idx).copied().unwrap_or(0);
        diff |= (a ^ b) as usize;
    }
    diff == 0
}

/// Verifies an incoming `X-Rootyard-Signature-256` header (`sha256=<64-hex>`) against
/// `secret` and `payload` using constant-time comparison across all 32 MAC bytes.
pub fn verify_signature_header(secret: &str, payload: &[u8], header_value: &str) -> bool {
    let trimmed = header_value.trim();
    let expected_mac = hmac_sha256_bytes(secret.as_bytes(), payload);

    let (prefix_ok, hex_part) = match trimmed.strip_prefix(SIGNATURE_PREFIX) {
        Some(rest) => (true, rest),
        None => (false, ""),
    };

    let mut candidate_mac = [0u8; 32];
    let hex_ok = if hex_part.len() == 64 && hex_part.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        hex::decode_to_slice(hex_part, &mut candidate_mac).is_ok()
    } else {
        false
    };

    let mac_matches = constant_time_eq(&expected_mac, &candidate_mac);
    prefix_ok && hex_ok && mac_matches
}

/// Builds the canonical JSON representation of outbound HTTP headers for a webhook delivery.
pub fn build_delivery_headers(
    event_type: &str,
    delivery_id: Uuid,
    hook_id: Uuid,
    attempt: i64,
    signature_256: &str,
) -> Value {
    json!({
        "User-Agent": "Rootyard-Hookshot/1.0",
        "Content-Type": "application/json",
        "X-Rootyard-Event": event_type,
        "X-Rootyard-Delivery": delivery_id.to_string(),
        "X-Rootyard-Hook-Id": hook_id.to_string(),
        "X-Rootyard-Signature-256": signature_256,
        "X-Rootyard-Attempt": attempt.to_string(),
    })
}

/// Resolves the callback `event_id` and canonical request SHA-256 digest for idempotent replay.
pub fn resolve_callback_identity(
    headers: &HeaderMap,
    hook_id: Uuid,
    input: &CiCallbackInput,
    context: &str,
    output: &str,
) -> Result<(String, String), Error> {
    let header_key = idempotency_key(headers)?.map(str::to_owned);
    let delivery_hdr = headers.get(HEADER_DELIVERY).and_then(|v| v.to_str().ok()).map(str::to_owned);
    let event_id = header_key
        .or_else(|| input.event_id.clone())
        .or(delivery_hdr)
        .or_else(|| input.delivery_id.map(|d| d.to_string()))
        .unwrap_or_else(|| {
            format!(
                "cb:{}:{}:{}:{}",
                input.commit_oid,
                context,
                input.attempt.unwrap_or(1),
                input.sequence.unwrap_or(1)
            )
        });
    if event_id.is_empty() || event_id.len() > 128 {
        return Err(Error::bad_request());
    }
    let canonical_req = json!({
        "hook_id": hook_id,
        "commit_oid": input.commit_oid,
        "context": context,
        "status": input.status,
        "conclusion": input.conclusion,
        "attempt": input.attempt,
        "sequence": input.sequence,
        "output": output,
        "ci_run_id": input.ci_run_id,
        "ci_job_id": input.ci_job_id,
        "base_oid": input.base_oid,
        "lease_generation": input.lease_generation,
    });
    let req_sha256 = sha256_hex(&serde_json::to_vec(&canonical_req).map_err(Error::internal)?);
    Ok((event_id, req_sha256))
}

/// Resolver result future used by the transport. Tests inject an owned,
/// deliberately delayed resolver; production always uses `lookup_host`.
type ResolveFuture = Pin<Box<dyn Future<Output = std::io::Result<Vec<SocketAddr>>> + Send>>;

/// Dispatches over a verified TLS-capable HTTP transport. DNS is resolved and checked
/// before use, then pinned to prevent a second lookup from bypassing SSRF policy.
pub async fn send_http11_webhook(
    url: &str,
    timeout_ms: i64,
    event_type: &str,
    delivery_id: Uuid,
    hook_id: Uuid,
    attempt: i64,
    signature_256: &str,
    body_bytes: &[u8],
) -> Result<u16, String> {
    send_http11_webhook_with_resolver(
        url,
        timeout_ms,
        event_type,
        delivery_id,
        hook_id,
        attempt,
        signature_256,
        body_bytes,
        // Egress policy is re-evaluated for every attempt, so a hook persisted
        // while the loopback opt-in was active stops delivering as soon as it
        // is withdrawn.
        policy::loopback_targets_allowed(),
        |host, port| {
            Box::pin(async move {
                let resolved = tokio::net::lookup_host((host.as_str(), port)).await?;
                Ok(resolved.collect())
            })
        },
    )
    .await
}

/// Transport with an explicit loopback decision and resolver seam. Both are
/// private to the crate: no request data can relax SSRF policy, and the public
/// path always combines the operator policy with the system resolver.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn send_http11_webhook_with_resolver<F>(
    url: &str,
    timeout_ms: i64,
    event_type: &str,
    delivery_id: Uuid,
    hook_id: Uuid,
    attempt: i64,
    signature_256: &str,
    body_bytes: &[u8],
    loopback_allowed: bool,
    resolve: F,
) -> Result<u16, String>
where
    F: FnOnce(String, u16) -> ResolveFuture,
{
    let target = validate_webhook_url_with_policy(url, loopback_allowed)
        .map_err(|_| "invalid or SSRF-blocked target URL".to_owned())?;
    let timeout_dur = Duration::from_millis(timeout_ms.clamp(100, 30_000) as u64);
    // ONE absolute deadline for DNS, connect, TLS and the response. Giving the
    // resolver and then the HTTP client separate full timeouts would let a hook
    // with a 30 s timeout occupy about 60 s and break both the scan reserve and
    // the claim-lease assumption.
    let deadline = Instant::now() + timeout_dur;
    let addresses: Vec<SocketAddr> = tokio::time::timeout_at(deadline, resolve(target.host.clone(), target.port))
        .await
        .map_err(|_| "webhook DNS timed out".to_owned())?
        .map_err(|e| format!("webhook DNS error: {e}"))?;
    // Every answer of a non-loopback name must be publicly routable; a mixed
    // answer fails closed before any connection is attempted.
    if addresses.is_empty()
        || addresses.iter().any(|a| !policy::permitted_peer(target.is_loopback, a.ip(), loopback_allowed))
    {
        return Err("webhook DNS resolved to a blocked address".to_owned());
    }
    let remaining = remaining_transport_budget(deadline)?;
    let mut builder = reqwest::Client::builder()
        .timeout(remaining)
        .connect_timeout(remaining)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .resolve(&target.host, addresses[0]);
    if let Ok(pem_path) = std::env::var("ROOTYARD_WEBHOOK_CA_FILE") {
        let pem = std::fs::read(pem_path).map_err(|_| "webhook CA file unreadable".to_owned())?;
        let cert = reqwest::Certificate::from_pem(&pem).map_err(|_| "invalid webhook CA certificate".to_owned())?;
        builder = builder.add_root_certificate(cert);
    }
    let client = builder.build().map_err(|e| format!("webhook client error: {e}"))?;
    let remaining = remaining_transport_budget(deadline)?;
    let response = tokio::time::timeout_at(
        deadline,
        client
            .post(url)
            .header("User-Agent", "Rootyard-Hookshot/1.0")
            .header("Content-Type", "application/json")
            .header("X-Rootyard-Event", event_type)
            .header("X-Rootyard-Delivery", delivery_id.to_string())
            .header("X-Rootyard-Hook-Id", hook_id.to_string())
            .header("X-Rootyard-Signature-256", signature_256)
            .header("X-Rootyard-Attempt", attempt.to_string())
            .timeout(remaining)
            .body(body_bytes.to_vec())
            .send(),
    )
    .await
    .map_err(|_| "webhook transport timed out".to_owned())?
    .map_err(|e| format!("webhook transport error: {e:?}"))?;
    Ok(response.status().as_u16())
}

/// Time left before the one end-to-end transport deadline. Exhaustion is a
/// failed attempt, never a fresh full timeout per stage.
fn remaining_transport_budget(deadline: Instant) -> Result<Duration, String> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err("webhook transport timed out".to_owned());
    }
    Ok(remaining)
}

/// Upserts a commit-bound `CheckRun` from a verified webhook callback with monotonic
/// `(attempt, sequence)` enforcement.
pub async fn upsert_callback_check_run(
    tx: &Transaction<'_>,
    tenant_id: Uuid,
    repo_id: Uuid,
    commit_oid: &str,
    context: &str,
    status: &str,
    conclusion: Option<&String>,
    attempt_opt: Option<i64>,
    sequence_opt: Option<i64>,
    output: &str,
) -> Result<CheckRun, Error> {
    let existing = tx
        .query_opt(
            &format!(
                "SELECT {CHECK_FIELDS} FROM forge_check_runs WHERE tenant_id=$1 AND repository_id=$2 AND commit_oid=$3 AND context=$4 FOR UPDATE"
            ),
            &[&tenant_id, &repo_id, &commit_oid, &context],
        )
        .await
        .map_err(Error::internal)?;

    match existing {
        None => {
            let (att, seq) = (attempt_opt.unwrap_or(1), sequence_opt.unwrap_or(1));
            let row = tx
                .query_one(
                    &format!(
                        "INSERT INTO forge_check_runs (tenant_id,repository_id,commit_oid,context,attempt,sequence,status,conclusion,output) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING {CHECK_FIELDS}"
                    ),
                    &[
                        &tenant_id,
                        &repo_id,
                        &commit_oid,
                        &context,
                        &att,
                        &seq,
                        &status,
                        &conclusion,
                        &output,
                    ],
                )
                .await
                .map_err(Error::internal)?;
            Ok(CheckRun::row(&row))
        }
        Some(row) => {
            let cur = CheckRun::row(&row);
            let att = attempt_opt.unwrap_or(1);
            let seq = match sequence_opt {
                Some(explicit_seq) => explicit_seq,
                None if att == cur.attempt && cur.sequence == 1 && cur.status == "queued" && status != "queued" => 2,
                None if att == cur.attempt
                    && cur.status == status
                    && cur.conclusion.as_ref() == conclusion
                    && cur.output == output =>
                {
                    cur.sequence
                }
                None => 1,
            };
            if (att, seq) > (cur.attempt, cur.sequence) {
                let updated = tx
                    .query_one(
                        &format!(
                            "UPDATE forge_check_runs SET attempt=$5, sequence=$6, status=$7, conclusion=$8, output=$9, updated_at=clock_timestamp() WHERE tenant_id=$1 AND repository_id=$2 AND commit_oid=$3 AND context=$4 RETURNING {CHECK_FIELDS}"
                        ),
                        &[
                            &tenant_id,
                            &repo_id,
                            &commit_oid,
                            &context,
                            &att,
                            &seq,
                            &status,
                            &conclusion,
                            &output,
                        ],
                    )
                    .await
                    .map_err(Error::internal)?;
                Ok(CheckRun::row(&updated))
            } else if (att, seq) == (cur.attempt, cur.sequence) {
                if cur.status == status && cur.conclusion.as_ref() == conclusion && cur.output == output {
                    Ok(cur)
                } else {
                    Err(Error(StatusCode::CONFLICT, "conflicting check run state for same attempt and sequence"))
                }
            } else {
                Err(Error(StatusCode::CONFLICT, "stale check run attempt or sequence"))
            }
        }
    }
}

#[cfg(test)]
#[path = "signing_tests.rs"]
mod tests;
