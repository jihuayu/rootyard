//! Strict, bounded, versioned keyset-cursor codec shared by list endpoints.
//!
//! A cursor is an opaque, URL-safe `v1` payload with length-prefixed
//! components. The first component binds the cursor to one authorized list
//! scope (for example tenant/repository/issue); the remaining components are
//! the complete keyset ordering columns including the unique tie-breaker.
//! Decoding rejects unknown versions, wrong field counts, foreign scopes,
//! malformed lengths, oversized payloads and invalid UTF-8.
use crate::Error;
use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

/// Maximum accepted encoded cursor length before any decoding work.
pub const MAX_CURSOR_BYTES: usize = 512;
const VERSION: &str = "v1";

fn bad_cursor() -> Error {
    Error(StatusCode::BAD_REQUEST, "invalid pagination cursor")
}

/// Encode a scoped keyset position. `fields` must be the ordering columns in
/// query order, ending with a unique tie-breaker.
pub fn encode(scope: &str, fields: &[&str]) -> String {
    let mut raw = String::with_capacity(32 + scope.len());
    raw.push_str(VERSION);
    push_field(&mut raw, scope);
    for field in fields {
        push_field(&mut raw, field);
    }
    URL_SAFE_NO_PAD.encode(raw.as_bytes())
}

fn push_field(raw: &mut String, field: &str) {
    raw.push(':');
    raw.push_str(&field.len().to_string());
    raw.push(':');
    raw.push_str(field);
}

/// Decode and validate an opaque cursor for `scope`, returning its ordered key
/// fields. Any mismatch is a client error, never a silent fallback.
pub fn decode(raw: &str, scope: &str, fields: usize) -> Result<Vec<String>, Error> {
    if raw.is_empty() || raw.len() > MAX_CURSOR_BYTES {
        return Err(bad_cursor());
    }
    let decoded = URL_SAFE_NO_PAD.decode(raw).map_err(|_| bad_cursor())?;
    let text = std::str::from_utf8(&decoded).map_err(|_| bad_cursor())?;
    let mut rest = text.strip_prefix(VERSION).ok_or_else(bad_cursor)?;
    let (decoded_scope, tail) = read_field(rest).ok_or_else(bad_cursor)?;
    if decoded_scope != scope {
        return Err(bad_cursor());
    }
    rest = tail;
    let mut parts = Vec::with_capacity(fields.min(4));
    while !rest.is_empty() {
        if parts.len() == fields {
            return Err(bad_cursor());
        }
        let (part, tail) = read_field(rest).ok_or_else(bad_cursor)?;
        parts.push(part.to_owned());
        rest = tail;
    }
    if parts.len() != fields {
        return Err(bad_cursor());
    }
    Ok(parts)
}

fn read_field(input: &str) -> Option<(&str, &str)> {
    let input = input.strip_prefix(':')?;
    let (length, after) = input.split_once(':')?;
    if length.is_empty() || length.len() > 6 || !length.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let length: usize = length.parse().ok()?;
    if length > after.len() {
        return None;
    }
    // Lengths count bytes. `after` is valid UTF-8, so a byte length that ends
    // inside a multi-byte scalar must be a clean error rather than a panic.
    let head = after.get(..length)?;
    let tail = after.get(length..)?;
    Some((head, tail))
}

/// Percent-encode a cursor for a URL query value. The cursor alphabet is
/// already URL-safe, but output must not depend on that implementation detail.
pub fn query_value(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_rejects_foreign_or_malformed_cursors() {
        let cursor = encode("teams:org", &["alpha", "00000000-0000-0000-0000-000000000001"]);
        assert_eq!(decode(&cursor, "teams:org", 2).unwrap(), vec!["alpha", "00000000-0000-0000-0000-000000000001"]);
        assert!(decode(&cursor, "teams:other", 2).is_err());
        assert!(decode(&cursor, "teams:org", 1).is_err());
        assert!(decode("not-a-cursor", "teams:org", 2).is_err());
        assert!(decode(&"a".repeat(MAX_CURSOR_BYTES + 1), "teams:org", 2).is_err());
        assert_eq!(query_value("ab+/c="), "ab%2B%2Fc%3D");
    }

    #[test]
    fn utf8_split_boundary_is_rejected_without_panicking() {
        // Prefix lengths count bytes, never characters. This payload is valid
        // UTF-8, but the declared field length ends inside the two-byte e-acute.
        let raw = "v1:5:scope:1:é";
        let cursor = URL_SAFE_NO_PAD.encode(raw.as_bytes());
        assert!(decode(&cursor, "scope", 1).is_err());
    }
}
