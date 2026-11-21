//! Synthetic DER X.509v3 SAN extraction tests for the voter mTLS boundary (#122).

use super::{extract_x509_dns_sans, peer_cert_matches_allowed_san};

const SAN_OID: [u8; 3] = [0x55, 0x1d, 0x11];
const WORKER_SAN: &str = "safe-gc-worker.refcas.internal";

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if value.len() < 128 {
        out.push(value.len() as u8);
    } else {
        out.push(0x81);
        out.push(value.len() as u8);
    }
    out.extend_from_slice(value);
    out
}

fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(0x30, &parts.concat())
}

fn extension(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let mut parts = vec![tlv(0x06, oid)];
    if critical {
        parts.push(tlv(0x01, &[0xff]));
    }
    parts.push(tlv(0x04, value));
    seq(&parts)
}

fn san_extension(critical: bool, names: &[Vec<u8>]) -> Vec<u8> {
    extension(&SAN_OID, critical, &seq(names))
}

fn certificate(with_v3_version: bool, extensions: &[Vec<u8>]) -> Vec<u8> {
    let mut fields = Vec::new();
    if with_v3_version {
        fields.push(tlv(0xa0, &tlv(0x02, &[0x02])));
    }
    fields.extend([tlv(0x02, &[0x01]), tlv(0x30, &[]), tlv(0x30, &[]), tlv(0x30, &[]), tlv(0x30, &[]), tlv(0x30, &[])]);
    if !extensions.is_empty() {
        fields.push(tlv(0xa3, &seq(extensions)));
    }
    seq(&[seq(&fields), tlv(0x30, &[])])
}

#[test]
fn dns_san_extraction_ignores_ip_addresses_and_honors_critical_flag() {
    let names = vec![tlv(0x82, WORKER_SAN.as_bytes()), tlv(0x87, &[127, 0, 0, 1])];
    let der = certificate(true, &[san_extension(true, &names)]);
    assert_eq!(extract_x509_dns_sans(&der).unwrap(), vec![WORKER_SAN.to_owned()]);
    assert!(peer_cert_matches_allowed_san(&der, WORKER_SAN));
    assert!(!peer_cert_matches_allowed_san(&der, "wrong-caller.refcas.internal"));
    assert!(!peer_cert_matches_allowed_san(&der, ""));
}

#[test]
fn certificate_without_extensions_has_no_dns_sans() {
    let der = certificate(false, &[]);
    assert!(extract_x509_dns_sans(&der).unwrap().is_empty());
    assert!(!peer_cert_matches_allowed_san(&der, WORKER_SAN));
}

#[test]
fn duplicate_subject_alt_name_extension_is_rejected() {
    let san = san_extension(false, &[tlv(0x82, WORKER_SAN.as_bytes())]);
    let der = certificate(true, &[san.clone(), san]);
    assert!(extract_x509_dns_sans(&der).is_err());
}

#[test]
fn indefinite_truncated_and_non_minimal_der_lengths_are_rejected() {
    for der in
        [vec![0x30, 0x80, 0x00], vec![0x30, 0x05, 0x01], vec![0x30, 0x81, 0x05, 0x01], vec![0x30, 0x82, 0x00, 0x80]]
    {
        assert!(extract_x509_dns_sans(&der).is_err(), "malformed DER must be rejected: {der:?}");
    }
}
