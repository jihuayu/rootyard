//! X.509 SAN tenant, group, and capability scope parsing and verification.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use x509_cert::Certificate;
use x509_cert::der::Decode;
use x509_cert::der::oid::AssociatedOid;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::ext::pkix::name::GeneralName;

use crate::mtls::{PeerIdentity, parse_peer_dns_name};
use crate::{E, Res};

/// SAN DNS prefix identifying a tenant-scoped Ref-CAS client certificate.
pub const TENANT_CLIENT_DNS_PREFIX: &str = "raft-client-tenant-";
/// SAN DNS suffix identifying a tenant-scoped Ref-CAS client certificate.
pub const TENANT_DNS_SUFFIX: &str = ".raft.internal";
/// URI SAN prefix carrying bound tenant, group, and capability claims.
pub const TENANT_URI_PREFIX: &str = "urn:rootyard:refcas:tenant:";

/// Narrow capability authorized inside a tenant-scoped mTLS certificate SAN.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum RpcCapability {
    Read,
    Write,
    Stream,
    Admin,
}

impl RpcCapability {
    /// Canonical lowercase representation used in URI SANs and scoped tokens.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Stream => "stream",
            Self::Admin => "admin",
        }
    }

    /// Parses one explicit narrow capability name (rejects wildcards/broad aliases).
    pub fn parse(raw: &str) -> Res<Self> {
        match raw {
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            "stream" => Ok(Self::Stream),
            "admin" => Ok(Self::Admin),
            _ => Err(E::Refused(format!("invalid or overly broad RPC capability {raw:?}"))),
        }
    }
}

/// Verified tenant, group, and capability binding extracted from an mTLS leaf cert.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TenantCertScope {
    pub tenant_id: String,
    pub group_id: String,
    pub capabilities: BTreeSet<RpcCapability>,
}

impl TenantCertScope {
    /// Returns true if the verified certificate scope grants `cap`.
    pub fn allows(&self, cap: RpcCapability) -> bool {
        self.capabilities.contains(&cap)
    }

    /// Canonical DNS SAN string required for this tenant.
    pub fn canonical_dns_name(&self) -> Res<String> {
        tenant_client_dns_name(&self.tenant_id)
    }

    /// Canonical URI SAN string encoding tenant, group, and narrow capabilities.
    pub fn canonical_scope_uri(&self) -> Res<String> {
        tenant_scope_uri(&self.tenant_id, &self.group_id, &self.capabilities)
    }
}

/// Disjoint identity extracted from an mTLS client or peer leaf certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifiedPeer {
    Cluster(PeerIdentity),
    TenantClient(TenantCertScope),
}

/// Formats `raft-client-tenant-<tenant_uuid>.raft.internal` after validating `tenant_id`.
pub fn tenant_client_dns_name(tenant_id: &str) -> Res<String> {
    let norm = validate_non_nil_uuid(tenant_id)?;
    Ok(format!("{TENANT_CLIENT_DNS_PREFIX}{norm}{TENANT_DNS_SUFFIX}"))
}

/// Formats `urn:rootyard:refcas:tenant:<tenant_uuid>:group:<group_id>:scope:<caps>`.
pub fn tenant_scope_uri(tenant_id: &str, group_id: &str, caps: &BTreeSet<RpcCapability>) -> Res<String> {
    let norm_tenant = validate_non_nil_uuid(tenant_id)?;
    let norm_group = validate_group_id(group_id)?;
    if caps.is_empty() {
        return Err(E::Refused("tenant scope requires at least one explicit capability".into()));
    }
    let caps_joined: Vec<&'static str> = caps.iter().map(|c| c.as_str()).collect();
    Ok(format!("{TENANT_URI_PREFIX}{norm_tenant}:group:{norm_group}:scope:{}", caps_joined.join("+")))
}

/// Validates canonical lowercase non-nil hyphenated UUID (`8-4-4-4-12`).
pub fn validate_non_nil_uuid(raw: &str) -> Res<String> {
    let b = raw.as_bytes();
    let valid_shape = b.len() == 36
        && [8, 13, 18, 23].into_iter().all(|i| b[i] == b'-')
        && b.iter().enumerate().all(|(i, c)| matches!(i, 8 | 13 | 18 | 23) || matches!(c, b'0'..=b'9' | b'a'..=b'f'));
    if !valid_shape || b.iter().all(|&c| c == b'0' || c == b'-') {
        return Err(E::Refused(format!("invalid or nil tenant UUID {raw:?}")));
    }
    Ok(raw.to_owned())
}

/// Validates bounded Ref-CAS group id (rejects empty strings, wildcards, and broad aliases).
pub fn validate_group_id(raw: &str) -> Res<String> {
    let bad_alias = matches!(raw, "" | "*" | "all" | "global" | "default");
    let valid_chars = !raw.is_empty()
        && raw.len() <= 64
        && raw.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
        && !raw.starts_with('.');
    if bad_alias || !valid_chars {
        return Err(E::Refused(format!("invalid or overly broad group_id {raw:?}")));
    }
    Ok(raw.to_owned())
}

/// Parses `raft-client-tenant-<tenant_uuid>.raft.internal` -> canonical tenant UUID.
pub fn parse_tenant_client_dns(dns: &str) -> Option<String> {
    let lower = dns.to_ascii_lowercase();
    let raw_tenant = lower.strip_prefix(TENANT_CLIENT_DNS_PREFIX)?.strip_suffix(TENANT_DNS_SUFFIX)?;
    validate_non_nil_uuid(raw_tenant).ok()
}

/// Parses `urn:rootyard:refcas:tenant:<tenant_uuid>:group:<group_id>:scope:<cap1+cap2>`.
pub fn parse_tenant_scope_uri(uri: &str) -> Res<TenantCertScope> {
    let rest = uri
        .strip_prefix(TENANT_URI_PREFIX)
        .ok_or_else(|| E::Refused(format!("unrecognized Ref-CAS tenant URI SAN {uri:?}")))?;
    let parts: Vec<&str> = rest.split(':').collect();
    if parts.len() != 5 || parts[1] != "group" || parts[3] != "scope" {
        return Err(E::Refused(format!("malformed Ref-CAS tenant URI SAN {uri:?}")));
    }
    let tenant_id = validate_non_nil_uuid(parts[0])?;
    let group_id = validate_group_id(parts[2])?;
    let caps_part = parts[4];
    if caps_part.is_empty() {
        return Err(E::Refused("tenant URI SAN has empty capability scope".into()));
    }
    let mut capabilities = BTreeSet::new();
    for token in caps_part.split('+') {
        let cap = RpcCapability::parse(token)?;
        if !capabilities.insert(cap) {
            return Err(E::Refused(format!("duplicate capability {token:?} in tenant URI SAN")));
        }
    }
    Ok(TenantCertScope { tenant_id, group_id, capabilities })
}

/// Extracts a disjoint cluster-peer or tenant-scoped client identity from an X.509 leaf DER cert.
pub fn extract_verified_peer(cert_der: &[u8]) -> Res<VerifiedPeer> {
    let cert = Certificate::from_der(cert_der).map_err(|e| E::Codec(format!("decode X.509 cert: {e}")))?;
    let Some(exts) = cert.tbs_certificate.extensions.as_ref() else {
        return Err(E::Refused("certificate lacks X.509 extensions/SAN".into()));
    };

    let mut cluster_id: Option<PeerIdentity> = None;
    let mut tenant_dns: Option<String> = None;
    let mut tenant_uri: Option<TenantCertScope> = None;

    for ext in exts {
        if ext.extn_id != SubjectAltName::OID {
            continue;
        }
        let san = SubjectAltName::from_der(ext.extn_value.as_bytes())
            .map_err(|e| E::Codec(format!("decode SubjectAltName: {e}")))?;
        for name in san.0 {
            match name {
                GeneralName::DnsName(ia5) => {
                    let s = ia5.as_str();
                    if let Some(peer) = parse_peer_dns_name(s) {
                        if let Some(prev) = cluster_id
                            && prev != peer
                        {
                            return Err(E::Refused(format!(
                                "conflicting cluster SAN identities: {prev:?} vs {peer:?}"
                            )));
                        }
                        cluster_id = Some(peer);
                    } else if let Some(tid) = parse_tenant_client_dns(s) {
                        if let Some(prev) = tenant_dns.as_ref()
                            && prev != &tid
                        {
                            return Err(E::Refused(format!("conflicting tenant DNS SANs: {prev} vs {tid}")));
                        }
                        tenant_dns = Some(tid);
                    } else {
                        return Err(E::Refused(format!("unrecognized Ref-CAS mTLS SAN DNS {s:?}")));
                    }
                }
                GeneralName::UniformResourceIdentifier(ia5) => {
                    let scope = parse_tenant_scope_uri(ia5.as_str())?;
                    if tenant_uri.is_some() {
                        return Err(E::Refused(
                            "multiple tenant scope URI SANs are forbidden; cert must bind exactly one scope".into(),
                        ));
                    }
                    tenant_uri = Some(scope);
                }
                _ => {
                    return Err(E::Refused("unsupported GeneralName in Ref-CAS mTLS SAN".into()));
                }
            }
        }
    }

    match (cluster_id, tenant_dns, tenant_uri) {
        (Some(peer), None, None) => Ok(VerifiedPeer::Cluster(peer)),
        (Some(_), _, _) => {
            Err(E::Refused("role confusion: cluster peer/client cert must not mix tenant DNS or URI SAN scopes".into()))
        }
        (None, Some(dns_tid), Some(uri_scope)) => {
            if dns_tid != uri_scope.tenant_id {
                return Err(E::Refused(format!(
                    "cross-tenant SAN mismatch: DNS binds {dns_tid}, URI binds {}",
                    uri_scope.tenant_id
                )));
            }
            Ok(VerifiedPeer::TenantClient(uri_scope))
        }
        (None, Some(_), None) => {
            Err(E::Refused("unscoped tenant certificate rejected: missing group/capability URI SAN".into()))
        }
        (None, None, Some(_)) => Err(E::Refused("tenant URI SAN requires matching tenant DNS SAN".into())),
        (None, None, None) => Err(E::Refused("certificate lacks a valid Ref-CAS mTLS SAN identity".into())),
    }
}

/// Extracts and enforces a strict tenant-scoped client identity, rejecting node/unscoped certs.
pub fn extract_tenant_client_scope(cert_der: &[u8]) -> Res<TenantCertScope> {
    match extract_verified_peer(cert_der)? {
        VerifiedPeer::TenantClient(scope) => Ok(scope),
        VerifiedPeer::Cluster(PeerIdentity::Node(id)) => {
            Err(E::Refused(format!("role confusion: Raft peer node-{id} cert cannot invoke tenant client RPC")))
        }
        VerifiedPeer::Cluster(PeerIdentity::Client) => {
            Err(E::Refused("unscoped cluster client cert rejected on tenant-scoped RPC endpoint".into()))
        }
    }
}
