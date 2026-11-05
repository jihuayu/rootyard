//! Data models, media type validators, and pointer parser for Track 2B Git LFS.
use crate::{Error, db};
use axum::http::{HeaderMap, StatusCode, header};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const LFS_MEDIA_TYPE: &str = "application/vnd.git-lfs+json";
pub const LFS_HASH_ALGO: &str = "sha256";
pub const MAX_BATCH_OBJECTS: usize = 100;

pub fn valid_lfs_oid(oid: &str) -> bool {
    oid.len() == 64
        && oid
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn normalize_repo_name(raw: &str) -> Result<&str, Error> {
    let name = raw.strip_suffix(".git").unwrap_or(raw);
    if !db::valid_name(name) {
        return Err(Error::not_found());
    }
    Ok(name)
}

pub fn check_lfs_json_headers(headers: &HeaderMap) -> Result<(), Error> {
    if let Some(ct) = headers.get(header::CONTENT_TYPE) {
        let raw = ct.to_str().map_err(|_| Error::bad_request())?;
        let media = raw.split(';').next().unwrap_or("").trim();
        if !media.eq_ignore_ascii_case(LFS_MEDIA_TYPE)
            && !media.eq_ignore_ascii_case("application/json")
        {
            return Err(Error(
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "invalid LFS content type",
            ));
        }
    }
    if let Some(accept) = headers.get(header::ACCEPT) {
        let raw = accept.to_str().map_err(|_| Error::bad_request())?;
        let accepted = raw.split(',').any(|part| {
            let media = part.split(';').next().unwrap_or("").trim();
            media.is_empty()
                || media.eq_ignore_ascii_case(LFS_MEDIA_TYPE)
                || media.eq_ignore_ascii_case("application/json")
                || media.eq_ignore_ascii_case("application/*")
                || media == "*/*"
        });
        if !accepted {
            return Err(Error(
                StatusCode::NOT_ACCEPTABLE,
                "unsupported LFS accept header",
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchRequest {
    pub operation: String,
    #[serde(default)]
    pub transfers: Vec<String>,
    #[serde(default)]
    pub r#ref: Option<BatchRef>,
    pub objects: Vec<BatchObjectSpec>,
    #[serde(default)]
    pub hash_algo: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BatchRef {
    pub name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BatchObjectSpec {
    pub oid: String,
    pub size: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchResponse {
    pub transfer: &'static str,
    pub objects: Vec<BatchObjectResult>,
    pub hash_algo: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchObjectResult {
    pub oid: String,
    pub size: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actions: Option<BatchActions>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<BatchObjectError>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchActions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload: Option<BatchActionLink>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub download: Option<BatchActionLink>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify: Option<BatchActionLink>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchActionLink {
    pub href: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub header: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchObjectError {
    pub code: u16,
    pub message: String,
}

/// Parses a canonical Git LFS v1 pointer file into `(oid, size)`.
pub fn parse_pointer(bytes: &[u8]) -> Option<BatchObjectSpec> {
    if bytes.len() > 1024 {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let mut version_ok = false;
    let mut oid_val: Option<String> = None;
    let mut size_val: Option<i64> = None;

    for (idx, line) in text.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        if idx == 0 {
            if line != "version https://git-lfs.github.com/spec/v1" {
                return None;
            }
            version_ok = true;
        } else if let Some(rest) = line.strip_prefix("oid sha256:") {
            if oid_val.is_some() || !valid_lfs_oid(rest) {
                return None;
            }
            oid_val = Some(rest.to_owned());
        } else if let Some(rest) = line.strip_prefix("size ") {
            if size_val.is_some() || rest.is_empty() || !rest.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let parsed = rest.parse::<i64>().ok()?;
            if parsed < 0 {
                return None;
            }
            size_val = Some(parsed);
        }
    }
    if !version_ok {
        return None;
    }
    Some(BatchObjectSpec {
        oid: oid_val?,
        size: size_val?,
    })
}

/// Verifies that a canonical Git LFS v1 pointer (`oid sha256:<64-hex>`) is valid alongside
/// either a 40-hex SHA-1 or 64-hex SHA-256 Git blob OID, returning the parsed spec and repo format.
pub fn verify_lfs_pointer_compatibility(
    pointer_bytes: &[u8],
    git_blob_oid: &str,
) -> Option<(BatchObjectSpec, &'static str)> {
    let spec = parse_pointer(pointer_bytes)?;
    if !valid_lfs_oid(&spec.oid) {
        return None;
    }
    let is_lower_hex = git_blob_oid
        .bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    let repo_format = match (git_blob_oid.len(), is_lower_hex) {
        (40, true) => "sha1",
        (64, true) => "sha256",
        _ => return None,
    };
    Some((spec, repo_format))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lfs_oid_and_pointer_parsing() {
        let oid = "a".repeat(64);
        assert!(valid_lfs_oid(&oid));
        assert!(!valid_lfs_oid(&"a".repeat(40)));
        assert!(!valid_lfs_oid(&"A".repeat(64)));

        let pointer = format!(
            "version https://git-lfs.github.com/spec/v1\noid sha256:{oid}\nsize 12345\n"
        );
        let parsed = parse_pointer(pointer.as_bytes()).unwrap();
        assert_eq!(
            parsed,
            BatchObjectSpec {
                oid: oid.clone(),
                size: 12345
            }
        );
        assert!(parse_pointer(b"not a pointer").is_none());

        let sha1_blob = "b".repeat(40);
        let sha256_blob = "c".repeat(64);
        assert_eq!(
            verify_lfs_pointer_compatibility(pointer.as_bytes(), &sha1_blob),
            Some((parsed.clone(), "sha1"))
        );
        assert_eq!(
            verify_lfs_pointer_compatibility(pointer.as_bytes(), &sha256_blob),
            Some((parsed, "sha256"))
        );
        assert!(verify_lfs_pointer_compatibility(pointer.as_bytes(), "invalid").is_none());
    }
}
