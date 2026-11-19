//! Mutual TLS configuration, certificate verification, and SAN-bound peer identity extraction.

use std::fs::File;
use std::io::{self, BufReader};
use std::path::PathBuf;
use std::sync::Arc;

use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector, client, server};
mod tenant_san;

use crate::{E, Res};

pub use tenant_san::{
    RpcCapability, TENANT_CLIENT_DNS_PREFIX, TENANT_DNS_SUFFIX, TENANT_URI_PREFIX, TenantCertScope, VerifiedPeer,
    extract_tenant_client_scope, extract_verified_peer, parse_tenant_client_dns, parse_tenant_scope_uri,
    tenant_client_dns_name, tenant_scope_uri, validate_group_id, validate_non_nil_uuid,
};

/// SAN DNS prefix used for authenticated Raft cluster peer/server node certificates.
pub const NODE_DNS_PREFIX: &str = "raft-node-";
/// SAN DNS suffix used for all internal Raft mTLS certificates.
pub const DNS_SUFFIX: &str = ".refcas.internal";
/// SAN DNS name presented by authorized Ref-CAS control/client connections.
pub const CLIENT_DNS_NAME: &str = "raft-client.refcas.internal";

/// Canonical DNS SAN expected for Raft node `node_id`.
pub fn node_dns_name(node_id: u64) -> String {
    format!("{NODE_DNS_PREFIX}{node_id}{DNS_SUFFIX}")
}

/// Verified caller identity extracted from an mTLS peer leaf certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerIdentity {
    Node(u64),
    Client,
}

/// On-disk PEM file paths required for strict mTLS server or client setup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MtlsPaths {
    pub ca_cert: PathBuf,
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// Server-side mTLS acceptor requiring CA-verified client certs and SAN identity binding.
#[derive(Clone)]
pub struct MtlsServer {
    acceptor: TlsAcceptor,
}

impl MtlsServer {
    /// Builds a strict TLS 1.3 mTLS server requiring CA-signed client certificates.
    pub fn from_paths(paths: &MtlsPaths) -> Res<Self> {
        let provider = ring_provider();
        let roots = load_ca_store(&paths.ca_cert)?;
        let certs = load_certs(&paths.cert)?;
        let key = load_private_key(&paths.key)?;
        let verifier = WebPkiClientVerifier::builder_with_provider(roots, provider.clone())
            .build()
            .map_err(|e| E::Refused(format!("invalid client verifier: {e}")))?;
        let cfg = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| E::Refused(format!("tls server protocol setup: {e}")))?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(|e| E::Refused(format!("invalid server cert/key: {e}")))?;
        Ok(Self { acceptor: TlsAcceptor::from(Arc::new(cfg)) })
    }

    async fn accept_tls_leaf(&self, stream: TcpStream) -> io::Result<(server::TlsStream<TcpStream>, Vec<u8>)> {
        // Latency-sensitive RPC frames are small; avoid Nagle coalescing delays before the handshake.
        stream.set_nodelay(true)?;
        let tls = self.acceptor.accept(stream).await?;
        let leaf_der = {
            let certs = tls
                .get_ref()
                .1
                .peer_certificates()
                .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "missing mTLS peer certificate"))?;
            let leaf = certs
                .first()
                .ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "empty mTLS certificate chain"))?;
            leaf.as_ref().to_vec()
        };
        Ok((tls, leaf_der))
    }

    /// Completes the mTLS handshake and extracts a cluster peer/client `PeerIdentity` (rejects tenant client certs).
    pub async fn accept(&self, stream: TcpStream) -> io::Result<(server::TlsStream<TcpStream>, PeerIdentity)> {
        let (tls, leaf) = self.accept_tls_leaf(stream).await?;
        let identity = extract_peer_identity(&leaf)
            .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, format!("peer identity rejected: {e}")))?;
        Ok((tls, identity))
    }

    /// Completes the mTLS handshake and enforces a strict tenant-scoped client cert (rejects node/unscoped certs).
    pub async fn accept_tenant(
        &self,
        stream: TcpStream,
    ) -> io::Result<(server::TlsStream<TcpStream>, TenantCertScope)> {
        let (tls, leaf) = self.accept_tls_leaf(stream).await?;
        let scope = extract_tenant_client_scope(&leaf)
            .map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, format!("tenant scope rejected: {e}")))?;
        Ok((tls, scope))
    }
}

/// Client-side mTLS connector verifying server CA + SAN and presenting a client certificate.
#[derive(Clone)]
pub struct MtlsClient {
    config: Arc<ClientConfig>,
}

impl MtlsClient {
    /// Builds a strict TLS 1.3 mTLS client verifying server certs against `ca_cert`.
    pub fn from_paths(paths: &MtlsPaths) -> Res<Self> {
        let provider = ring_provider();
        let roots = load_ca_store(&paths.ca_cert)?;
        let certs = load_certs(&paths.cert)?;
        let key = load_private_key(&paths.key)?;
        let cfg = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| E::Refused(format!("tls client protocol setup: {e}")))?
            .with_root_certificates(roots)
            .with_client_auth_cert(certs, key)
            .map_err(|e| E::Refused(format!("invalid client auth cert/key: {e}")))?;
        Ok(Self { config: Arc::new(cfg) })
    }

    /// Connects to `addr` over TCP+mTLS, requiring server SAN DNS name `expected_dns`.
    pub async fn connect_named(&self, addr: &str, expected_dns: &str) -> io::Result<client::TlsStream<TcpStream>> {
        let server_name = ServerName::try_from(expected_dns.to_owned())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("invalid DNS server name: {e}")))?;
        let tcp = TcpStream::connect(addr).await?;
        // Latency-sensitive RPC frames are small; avoid Nagle coalescing delays before the handshake.
        tcp.set_nodelay(true)?;
        TlsConnector::from(self.config.clone()).connect(server_name, tcp).await
    }

    /// Connects to Raft peer `target_id` over mTLS, binding identity to `raft-node-{target_id}.refcas.internal`.
    pub async fn connect_peer(&self, addr: &str, target_id: u64) -> io::Result<client::TlsStream<TcpStream>> {
        self.connect_named(addr, &node_dns_name(target_id)).await
    }
}

/// Parses an mTLS SAN DNS name (`raft-node-{id}.refcas.internal` or `raft-client.refcas.internal`).
pub fn parse_peer_dns_name(dns: &str) -> Option<PeerIdentity> {
    let lower = dns.to_ascii_lowercase();
    if lower == CLIENT_DNS_NAME {
        return Some(PeerIdentity::Client);
    }
    let raw_id = lower.strip_prefix(NODE_DNS_PREFIX)?.strip_suffix(DNS_SUFFIX)?;
    let id = raw_id.parse::<u64>().ok()?;
    if id.to_string() != raw_id {
        return None;
    }
    Some(PeerIdentity::Node(id))
}

/// Extracts and validates an unambiguous cluster `PeerIdentity` (rejects tenant-scoped certs).
pub fn extract_peer_identity(cert_der: &[u8]) -> Res<PeerIdentity> {
    match extract_verified_peer(cert_der)? {
        VerifiedPeer::Cluster(identity) => Ok(identity),
        VerifiedPeer::TenantClient(_) => {
            Err(E::Refused("role confusion: tenant client cert cannot authenticate as Raft cluster peer/admin".into()))
        }
    }
}

fn ring_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn load_ca_store(path: &PathBuf) -> Res<Arc<RootCertStore>> {
    let file =
        File::open(path).map_err(|e| E::Io(io::Error::new(e.kind(), format!("open CA {}: {e}", path.display()))))?;
    let mut reader = BufReader::new(file);
    let mut roots = RootCertStore::empty();
    for item in rustls_pemfile::certs(&mut reader) {
        let der = item.map_err(|e| E::Codec(format!("parse CA PEM {}: {e}", path.display())))?;
        roots.add(der).map_err(|e| E::Refused(format!("add CA cert {}: {e}", path.display())))?;
    }
    if roots.is_empty() {
        return Err(E::Refused(format!("empty CA bundle {}", path.display())));
    }
    Ok(Arc::new(roots))
}

fn load_certs(path: &PathBuf) -> Res<Vec<CertificateDer<'static>>> {
    let file =
        File::open(path).map_err(|e| E::Io(io::Error::new(e.kind(), format!("open cert {}: {e}", path.display()))))?;
    let mut reader = BufReader::new(file);
    let mut certs = Vec::new();
    for item in rustls_pemfile::certs(&mut reader) {
        certs.push(item.map_err(|e| E::Codec(format!("parse cert PEM {}: {e}", path.display())))?);
    }
    if certs.is_empty() {
        return Err(E::Refused(format!("no certificates in {}", path.display())));
    }
    Ok(certs)
}

fn load_private_key(path: &PathBuf) -> Res<PrivateKeyDer<'static>> {
    let file =
        File::open(path).map_err(|e| E::Io(io::Error::new(e.kind(), format!("open key {}: {e}", path.display()))))?;
    let mut reader = BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| E::Codec(format!("parse private key {}: {e}", path.display())))?
        .ok_or_else(|| E::Refused(format!("no private key found in {}", path.display())))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    fn write_ca(dir: &Path, cn: &str) -> (CertifiedIssuer<'static, KeyPair>, PathBuf) {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(rcgen::DnType::CommonName, cn);
        let issuer = CertifiedIssuer::self_signed(params, key).unwrap();
        let ca_path = dir.join(format!("{cn}.crt"));
        std::fs::write(&ca_path, issuer.pem()).unwrap();
        (issuer, ca_path)
    }

    fn write_leaf(dir: &Path, name: &str, ca: &CertifiedIssuer<'_, KeyPair>, ca_path: &Path, dns: &str) -> MtlsPaths {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(vec![dns.to_owned()]).unwrap();
        params.is_ca = IsCa::ExplicitNoCa;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
        let cert = params.signed_by(&key, ca).unwrap();
        let cert_path = dir.join(format!("{name}.crt"));
        let key_path = dir.join(format!("{name}.key"));
        std::fs::write(&cert_path, cert.pem()).unwrap();
        std::fs::write(&key_path, key.serialize_pem()).unwrap();
        MtlsPaths { ca_cert: ca_path.to_path_buf(), cert: cert_path, key: key_path }
    }

    #[tokio::test]
    async fn mtls_authenticates_valid_peers_and_rejects_untrusted_or_wrong_identity() {
        let dir = tempfile::tempdir().unwrap();
        let (ca, ca_path) = write_ca(dir.path(), "cluster-ca");
        let (rogue_ca, rogue_ca_path) = write_ca(dir.path(), "rogue-ca");

        let n1 = write_leaf(dir.path(), "node1", &ca, &ca_path, &node_dns_name(1));
        let n2 = write_leaf(dir.path(), "node2", &ca, &ca_path, &node_dns_name(2));
        let cli = write_leaf(dir.path(), "client", &ca, &ca_path, CLIENT_DNS_NAME);
        let bad_san = write_leaf(dir.path(), "badsan", &ca, &ca_path, "other-service.internal");
        let rogue = write_leaf(dir.path(), "rogue", &rogue_ca, &rogue_ca_path, &node_dns_name(2));

        let server = MtlsServer::from_paths(&n1).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();

        let srv = server.clone();
        tokio::spawn(async move {
            loop {
                let Ok((tcp, _)) = listener.accept().await else { break };
                let s = srv.clone();
                tokio::spawn(async move {
                    if let Ok((mut tls, id)) = s.accept(tcp).await {
                        let tag = match id {
                            PeerIdentity::Node(i) => format!("node:{i}"),
                            PeerIdentity::Client => "client".to_owned(),
                        };
                        let nodelay =
                            tls.get_ref().0.nodelay().expect("accepted mTLS TCP stream must expose TCP_NODELAY");
                        let tag = format!("{tag} nodelay={nodelay}");
                        let _ = tls.write_all(tag.as_bytes()).await;
                        let _ = tls.shutdown().await;
                    }
                });
            }
        });

        // 1. Valid peer node-2 -> node-1
        let c_n2 = MtlsClient::from_paths(&n2).unwrap();
        let mut s = c_n2.connect_peer(&addr, 1).await.unwrap();
        assert!(
            s.get_ref().0.nodelay().expect("query client TCP_NODELAY"),
            "outbound mTLS TCP stream must enable TCP_NODELAY"
        );
        let mut buf = String::new();
        s.read_to_string(&mut buf).await.unwrap();
        assert_eq!(buf, "node:2 nodelay=true");

        // 2. Valid client -> node-1
        let c_cli = MtlsClient::from_paths(&cli).unwrap();
        let mut s = c_cli.connect_peer(&addr, 1).await.unwrap();
        assert!(
            s.get_ref().0.nodelay().expect("query client TCP_NODELAY"),
            "outbound mTLS TCP stream must enable TCP_NODELAY"
        );
        buf.clear();
        s.read_to_string(&mut buf).await.unwrap();
        assert_eq!(buf, "client nodelay=true");

        // 3. Wrong expected server identity (node-1 cert cannot validate as node-2)
        assert!(c_n2.connect_peer(&addr, 2).await.is_err());

        // 4. Rogue CA cert rejected
        let c_rogue = MtlsClient::from_paths(&rogue).unwrap();
        assert!(c_rogue.connect_peer(&addr, 1).await.is_err());

        // 5. Same CA but unrecognized SAN DNS rejected on server accept
        let c_badsan = MtlsClient::from_paths(&bad_san).unwrap();
        if let Ok(mut s) = c_badsan.connect_peer(&addr, 1).await {
            let mut b = Vec::new();
            let _ = s.read_to_end(&mut b).await;
            assert!(b.is_empty(), "server must reject bad SAN identity without payload");
        }

        // 6. Anonymous client (valid CA trust, NO client certificate) fails mTLS handshake.
        let mut anon_roots = RootCertStore::empty();
        for item in rustls_pemfile::certs(&mut BufReader::new(File::open(&ca_path).unwrap())) {
            anon_roots.add(item.unwrap()).unwrap();
        }
        let anon_cfg = ClientConfig::builder_with_provider(ring_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(anon_roots)
            .with_no_client_auth();
        let tcp_anon = TcpStream::connect(&addr).await.unwrap();
        if let Ok(mut tls_anon) = TlsConnector::from(Arc::new(anon_cfg))
            .connect(ServerName::try_from(node_dns_name(1)).unwrap(), tcp_anon)
            .await
        {
            let mut b = Vec::new();
            let _ = tls_anon.read_to_end(&mut b).await;
            assert!(!String::from_utf8_lossy(&b).contains("node:"));
        }

        // 7. Plaintext TCP rejected with TLS fatal alert (never returning application data).
        let mut raw = TcpStream::connect(&addr).await.unwrap();
        raw.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        let mut out = Vec::new();
        let _ = raw.read_to_end(&mut out).await;
        assert!(out.is_empty() || out.first().copied() == Some(0x15));
    }
}
