//! RFC 2104 HMAC-SHA256 webhook payload signing, constant-time signature verification,
//! standard `X-Rootyard-*` delivery header construction, and SSRF-safe HTTP/1.1 socket transport.
use crate::{
    Error,
    auth::idempotency_key,
    pulls::models::{CHECK_FIELDS, CheckRun},
    webhooks::models::{CiCallbackInput, validate_webhook_url},
};
use axum::http::{HeaderMap, StatusCode};
use deadpool_postgres::Transaction;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
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
    let hex_ok = if hex_part.len() == 64
        && hex_part
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
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
    let delivery_hdr = headers
        .get(HEADER_DELIVERY)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
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
    });
    let req_sha256 = sha256_hex(&serde_json::to_vec(&canonical_req).map_err(Error::internal)?);
    Ok((event_id, req_sha256))
}

/// Dispatches a signed HTTP/1.1 POST request over `tokio::net::TcpStream` with SSRF verification
/// and strict connect/read/write timeouts.
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
    let target =
        validate_webhook_url(url).map_err(|_| "invalid or SSRF-blocked target URL".to_owned())?;
    if target.scheme == "https" && !target.is_loopback {
        return Err("outbound TLS transport not configured in isolated environment".to_owned());
    }
    let timeout_dur = Duration::from_millis(timeout_ms.clamp(100, 30_000) as u64);
    let addr_str = if target.host.contains(':') {
        format!("[{}]:{}", target.host, target.port)
    } else {
        format!("{}:{}", target.host, target.port)
    };

    let mut stream = tokio::time::timeout(timeout_dur, TcpStream::connect(&addr_str))
        .await
        .map_err(|_| "webhook connection timed out".to_owned())?
        .map_err(|e| format!("webhook connect error: {e}"))?;
    if let Ok(peer) = stream.peer_addr() {
        if target.is_loopback && !peer.ip().is_loopback() {
            return Err("resolved peer address is not loopback".to_owned());
        }
    }

    let request_head = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Rootyard-Hookshot/1.0\r\nContent-Type: application/json\r\nContent-Length: {}\r\nX-Rootyard-Event: {}\r\nX-Rootyard-Delivery: {}\r\nX-Rootyard-Hook-Id: {}\r\nX-Rootyard-Signature-256: {}\r\nX-Rootyard-Attempt: {}\r\nConnection: close\r\n\r\n",
        target.path_and_query,
        target.host_header,
        body_bytes.len(),
        event_type,
        delivery_id,
        hook_id,
        signature_256,
        attempt,
    );
    tokio::time::timeout(timeout_dur, async {
        stream.write_all(request_head.as_bytes()).await?;
        stream.write_all(body_bytes).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| "webhook write timed out".to_owned())?
    .map_err(|e| format!("webhook write error: {e}"))?;

    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(timeout_dur, stream.read(&mut buf))
        .await
        .map_err(|_| "webhook read timed out".to_owned())?
        .map_err(|e| format!("webhook read error: {e}"))?;
    if n == 0 {
        return Err("empty HTTP response from webhook receiver".to_owned());
    }
    let head_str = String::from_utf8_lossy(&buf[..n]);
    let mut parts = head_str.lines().next().unwrap_or("").split_whitespace();
    let proto = parts.next().unwrap_or("");
    let code_str = parts.next().unwrap_or("");
    if !proto.starts_with("HTTP/1.") {
        return Err("invalid HTTP response status line".to_owned());
    }
    let code: u16 = code_str
        .parse()
        .map_err(|_| "malformed HTTP status code".to_owned())?;
    if !(100..=599).contains(&code) {
        return Err("HTTP status code out of range".to_owned());
    }
    Ok(code)
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
                None if att == cur.attempt
                    && cur.sequence == 1
                    && cur.status == "queued"
                    && status != "queued" =>
                {
                    2
                }
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
                if cur.status == status
                    && cur.conclusion.as_ref() == conclusion
                    && cur.output == output
                {
                    Ok(cur)
                } else {
                    Err(Error(
                        StatusCode::CONFLICT,
                        "conflicting check run state for same attempt and sequence",
                    ))
                }
            } else {
                Err(Error(
                    StatusCode::CONFLICT,
                    "stale check run attempt or sequence",
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4231_hmac_sha256_test_vectors() {
        let key1 = [0x0bu8; 20];
        assert_eq!(
            hex::encode(hmac_sha256_bytes(&key1, b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hmac_sha256_hex("Jefe", b"what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        let key3 = [0xaau8; 20];
        let data3 = [0xddu8; 50];
        assert_eq!(
            hex::encode(hmac_sha256_bytes(&key3, &data3)),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
        let key6 = [0xaau8; 131];
        let data6 = b"Test Using Larger Than Block-Size Key - Hash Key First";
        assert_eq!(
            hex::encode(hmac_sha256_bytes(&key6, data6)),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
        let data7 = b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.";
        assert_eq!(
            hex::encode(hmac_sha256_bytes(&key6, data7)),
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
        );
    }

    #[test]
    fn signature_header_and_constant_time_verification() {
        let secret = "whsec_rootyard_super_secret_key";
        let payload = br#"{"event":"pull_request","action":"opened","pull_number":1}"#;
        let sig = signature_header(secret, payload);
        assert!(sig.starts_with("sha256="));
        assert_eq!(sig.len(), 71);
        assert!(verify_signature_header(secret, payload, &sig));
        assert!(!verify_signature_header(secret, b"{}", &sig));
        assert!(!verify_signature_header("wrong_secret_value", payload, &sig));
        assert!(!verify_signature_header(secret, payload, &sig.to_uppercase()));
        assert!(!verify_signature_header(secret, payload, &sig[7..]));
        assert!(!verify_signature_header(secret, payload, "sha256=deadbeef"));
    }

    #[test]
    fn delivery_headers_include_required_metadata() {
        let d_id = Uuid::new_v4();
        let h_id = Uuid::new_v4();
        let sig = "sha256=b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
        let hdrs = build_delivery_headers("push", d_id, h_id, 2, sig);
        assert_eq!(hdrs["X-Rootyard-Event"], "push");
        assert_eq!(hdrs["X-Rootyard-Delivery"], d_id.to_string());
        assert_eq!(hdrs["X-Rootyard-Hook-Id"], h_id.to_string());
        assert_eq!(hdrs["X-Rootyard-Signature-256"], sig);
        assert_eq!(hdrs["X-Rootyard-Attempt"], "2");
    }
}
