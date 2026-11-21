//! Canonical bounded validators and length-delimited digest encoding (#122).

use sha2::{Digest, Sha256};

use super::super::SafeGcError;
use super::{MAX_STRING_FIELD_BYTES, SafeGcObjectFormat};

pub(crate) fn validate_non_zero_oid(format: SafeGcObjectFormat, oid: &str) -> Result<(), SafeGcError> {
    if oid.len() != format.oid_hex_len()
        || !oid.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || oid.bytes().all(|b| b == b'0')
    {
        return Err(SafeGcError::InvalidInput("invalid or zero Git OID".into()));
    }
    Ok(())
}

pub(crate) fn validate_sha256_hex(value: &str) -> Result<(), SafeGcError> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(SafeGcError::InvalidInput("invalid 64-hex SHA-256 digest".into()));
    }
    Ok(())
}

pub(crate) fn validate_bounded_name(label: &str, value: &str) -> Result<(), SafeGcError> {
    if value.is_empty() || value.len() > MAX_STRING_FIELD_BYTES || value.contains('\0') || value.contains("..") {
        return Err(SafeGcError::InvalidInput(format!("invalid {label}")));
    }
    Ok(())
}

pub(crate) fn encode_len_bytes(h: &mut Sha256, bytes: &[u8]) {
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
}
