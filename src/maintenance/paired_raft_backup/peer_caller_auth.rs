//! X.509 SAN + SHA-256 caller-identity authorization for `PeerAttestationDaemon`
//! mTLS clients, plus the PEM trust-anchor/leaf/key loaders shared with the daemon (#153).

use std::collections::BTreeSet;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use sha2::{Digest, Sha256};

use super::types::{PairedBackupError, validate_hex64};

/// The single authorized `raft-client` workgroup DNS identity for peer attestor callers.
pub const AUTHORIZED_ATTESTOR_CLIENT_DNS: &str = "raft-client.refcas.internal";

const OID_SUBJECT_ALT_NAME: [u8; 3] = [0x55, 0x1d, 0x11];
const TAG_SEQUENCE: u8 = 0x30;
const TAG_OID: u8 = 0x06;
const TAG_BOOLEAN: u8 = 0x01;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_EXPLICIT_EXTENSIONS: u8 = 0xa3;
const TAG_DNS_NAME: u8 = 0x82;

fn malformed(detail: &'static str) -> PairedBackupError {
    PairedBackupError::FreezeNotHeld(detail)
}

/// Split one DER `tag || length || value` triple, returning `(tag, value, rest)`.
fn split_tlv(buf: &[u8]) -> Result<(u8, &[u8], &[u8]), PairedBackupError> {
    if buf.len() < 2 {
        return Err(malformed("truncated DER element in peer attestor caller certificate"));
    }
    let (len, header) = if buf[1] & 0x80 == 0 {
        (usize::from(buf[1]), 2usize)
    } else {
        let octets = usize::from(buf[1] & 0x7f);
        if octets == 0 || octets > 3 || buf.len() < 2 + octets {
            return Err(malformed("invalid DER length in peer attestor caller certificate"));
        }
        let len = buf[2..2 + octets].iter().fold(0usize, |acc, byte| (acc << 8) | usize::from(*byte));
        (len, 2 + octets)
    };
    let Some(end) = header.checked_add(len).filter(|end| *end <= buf.len()) else {
        return Err(malformed("DER element overruns peer attestor caller certificate"));
    };
    Ok((buf[0], &buf[header..end], &buf[end..]))
}

/// Pure-Rust X.509v3 `subjectAltName` (`OID 2.5.29.17`) `dNSName` extractor.
pub fn extract_der_san_dns_names(cert_der: &[u8]) -> Result<Vec<String>, PairedBackupError> {
    let (tag, certificate, _) = split_tlv(cert_der)?;
    if tag != TAG_SEQUENCE {
        return Err(malformed("peer attestor caller certificate is not a DER SEQUENCE"));
    }
    let (tag, tbs, _) = split_tlv(certificate)?;
    if tag != TAG_SEQUENCE {
        return Err(malformed("peer attestor caller tbsCertificate is not a DER SEQUENCE"));
    }
    let mut names = Vec::new();
    let mut rest = tbs;
    while !rest.is_empty() {
        let (tag, body, tail) = split_tlv(rest)?;
        rest = tail;
        if tag != TAG_EXPLICIT_EXTENSIONS {
            continue;
        }
        let (tag, extensions, _) = split_tlv(body)?;
        if tag != TAG_SEQUENCE {
            return Err(malformed("peer attestor caller Extensions is not a DER SEQUENCE"));
        }
        let mut pending = extensions;
        while !pending.is_empty() {
            let (tag, extension, tail) = split_tlv(pending)?;
            pending = tail;
            if tag != TAG_SEQUENCE {
                return Err(malformed("peer attestor caller Extension is not a DER SEQUENCE"));
            }
            let (tag, oid, mut value) = split_tlv(extension)?;
            if tag != TAG_OID || oid != OID_SUBJECT_ALT_NAME.as_slice() {
                continue;
            }
            if value.first() == Some(&TAG_BOOLEAN) {
                value = split_tlv(value)?.2;
            }
            let (tag, general_names, _) = split_tlv(value)?;
            if tag != TAG_OCTET_STRING {
                return Err(malformed("peer attestor caller subjectAltName is not an OCTET STRING"));
            }
            let (tag, general_names, _) = split_tlv(general_names)?;
            if tag != TAG_SEQUENCE {
                return Err(malformed("peer attestor caller GeneralNames is not a DER SEQUENCE"));
            }
            let mut entries = general_names;
            while !entries.is_empty() {
                let (tag, entry, tail) = split_tlv(entries)?;
                entries = tail;
                if tag != TAG_DNS_NAME {
                    continue;
                }
                if !entry.is_ascii() {
                    return Err(malformed("peer attestor caller dNSName is not ASCII"));
                }
                names.push(String::from_utf8(entry.to_vec()).map_err(|_| malformed("invalid dNSName bytes"))?);
            }
        }
    }
    Ok(names)
}

/// Require the pinned `raft-client` DNS SAN and reject voter/tenant leaf identities.
pub fn verify_caller_leaf_san_identity(cert_der: &[u8]) -> Result<(), PairedBackupError> {
    let names = extract_der_san_dns_names(cert_der)?;
    let authorized = names.iter().any(|name| name.eq_ignore_ascii_case(AUTHORIZED_ATTESTOR_CLIENT_DNS));
    let forbidden = names.iter().any(|name| name.starts_with("raft-node-") || name.starts_with("raft-client-tenant-"));
    if !authorized || forbidden {
        return Err(malformed("peer attestor caller certificate SAN identity is not authorized"));
    }
    Ok(())
}

fn caller_digest(leaf: &CertificateDer<'_>) -> String {
    hex::encode(Sha256::digest(leaf.as_ref()))
}

/// Pin the configured `raft-client` leaf (or the explicit allowlist) as the only callers.
pub(super) fn build_allowed_caller_digests(
    raft_client_cert_pem: &Path,
    explicit_allowlist: &[String],
    node_cert_sha256: &str,
) -> Result<BTreeSet<String>, PairedBackupError> {
    let certs = load_cert_chain(raft_client_cert_pem)?;
    let leaf =
        certs.first().ok_or_else(|| malformed("peer attestor caller certificate chain has no leaf certificate"))?;
    verify_caller_leaf_san_identity(leaf.as_ref())?;
    let pinned = caller_digest(leaf);
    if pinned == node_cert_sha256 {
        return Err(PairedBackupError::FreezeNotHeld("peer attestor caller cert must not match voter server cert"));
    }
    let mut allowed = BTreeSet::new();
    if explicit_allowlist.is_empty() {
        allowed.insert(pinned);
        return Ok(allowed);
    }
    for digest in explicit_allowlist {
        if !validate_hex64(digest) || digest == node_cert_sha256 {
            return Err(malformed("invalid peer attestor caller allowlist SHA-256 digest"));
        }
        allowed.insert(digest.clone());
    }
    Ok(allowed)
}

/// Authorize the presented mTLS leaf against the pinned caller digest set.
pub(super) fn authorize_caller_peer_certs(
    peer_certs: Option<&[CertificateDer<'_>]>,
    allowed_caller_cert_sha256s: &BTreeSet<String>,
) -> Result<String, PairedBackupError> {
    let certs = peer_certs.ok_or_else(|| malformed("peer attestation client presented no X.509 certificate"))?;
    let leaf = certs.first().ok_or_else(|| malformed("peer attestation client X.509 chain is empty"))?;
    verify_caller_leaf_san_identity(leaf.as_ref())?;
    let caller_sha = caller_digest(leaf);
    if !allowed_caller_cert_sha256s.contains(&caller_sha) {
        return Err(PairedBackupError::FreezeNotHeld("unauthorized peer attestation caller identity"));
    }
    Ok(caller_sha)
}

pub(super) fn load_ca_roots(path: &Path) -> Result<Arc<RootCertStore>, PairedBackupError> {
    let mut roots = RootCertStore::empty();
    for item in rustls_pemfile::certs(&mut BufReader::new(File::open(path)?)) {
        let der = item.map_err(|_| malformed("failed to parse peer attestor CA PEM"))?;
        roots.add(der).map_err(|_| malformed("invalid peer attestor CA certificate"))?;
    }
    Ok(Arc::new(roots))
}

pub(super) fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>, PairedBackupError> {
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut BufReader::new(File::open(path)?))
        .collect::<Result<_, _>>()
        .map_err(|_| malformed("invalid peer attestor certificate PEM"))?;
    if certs.is_empty() {
        return Err(malformed("empty peer attestor certificate chain"));
    }
    Ok(certs)
}

pub(super) fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, PairedBackupError> {
    rustls_pemfile::private_key(&mut BufReader::new(File::open(path)?))
        .map_err(|_| malformed("invalid peer attestor private key PEM"))?
        .ok_or_else(|| malformed("missing peer attestor private key"))
}
