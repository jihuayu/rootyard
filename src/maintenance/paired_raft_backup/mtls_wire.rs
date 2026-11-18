//! TLS 1.3 mutual-TLS client framing, X.509 peer certificate identity binding,
//! and durable Raft freeze record wire types (#153).

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::types::{PairedBackupError, sha256_json_tagged, validate_hex64};

const MAX_RPC_FRAME_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct MtlsRaftClusterConfig {
    pub group_id: i64,
    pub local_node_id: u64,
    pub voter_endpoints: BTreeMap<u64, String>,
    pub ca_cert_pem: PathBuf,
    pub client_cert_pem: PathBuf,
    pub client_key_pem: PathBuf,
    pub rpc_timeout: Duration,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DurableRaftFreezeRecord {
    pub frozen: bool,
    pub barrier_id: Uuid,
    pub fenced_deleter_epoch: u64,
    pub app_fence_seq: u64,
    pub repo_access_floors: BTreeMap<Uuid, i64>,
    pub seal_receipt_digest: Option<String>,
    pub record_seal: String,
}

impl DurableRaftFreezeRecord {
    pub fn seal(mut self) -> Result<Self, PairedBackupError> {
        self.record_seal.clear();
        self.record_seal = sha256_json_tagged(b"rootyard-raft-freeze-record-v1", &self)?;
        Ok(self)
    }

    pub fn verify(&self) -> Result<(), PairedBackupError> {
        if self.barrier_id.is_nil() {
            return Err(PairedBackupError::FreezeNotHeld("nil barrier_id in durable Raft freeze record"));
        }
        if !self.frozen && !self.seal_receipt_digest.as_deref().is_some_and(validate_hex64) {
            return Err(PairedBackupError::FreezeNotHeld("thawed Raft record missing verified seal_receipt_digest"));
        }
        let mut clean = self.clone();
        clean.record_seal.clear();
        if sha256_json_tagged(b"rootyard-raft-freeze-record-v1", &clean)? != self.record_seal {
            return Err(PairedBackupError::FreezeNotHeld("durable Raft freeze record seal tampered"));
        }
        Ok(())
    }
}

pub(super) fn derive_voter_uuid(group_id: i64, node_id: u64, cert_sha256: &str) -> Uuid {
    let mut h = Sha256::new();
    h.update(b"rootyard-mtls-voter-uuid-v1\0");
    h.update(group_id.to_be_bytes());
    h.update(node_id.to_be_bytes());
    h.update(cert_sha256.as_bytes());
    let digest = h.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

pub fn build_mtls_client_config(cfg: &MtlsRaftClusterConfig) -> Result<Arc<ClientConfig>, PairedBackupError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = RootCertStore::empty();
    for item in rustls_pemfile::certs(&mut BufReader::new(File::open(&cfg.ca_cert_pem)?)) {
        let der = item.map_err(|_| PairedBackupError::FreezeNotHeld("failed to parse mTLS CA PEM"))?;
        roots.add(der).map_err(|_| PairedBackupError::FreezeNotHeld("invalid CA certificate in trust store"))?;
    }
    let certs: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(File::open(&cfg.client_cert_pem)?))
        .collect::<Result<_, _>>()
        .map_err(|_| PairedBackupError::FreezeNotHeld("invalid mTLS client certificate PEM"))?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(&cfg.client_key_pem)?))
        .map_err(|_| PairedBackupError::FreezeNotHeld("invalid mTLS client key PEM"))?
        .ok_or(PairedBackupError::FreezeNotHeld("missing mTLS client private key"))?;
    let client_cfg = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|_| PairedBackupError::FreezeNotHeld("TLS 1.3 provider setup failed"))?
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .map_err(|_| PairedBackupError::FreezeNotHeld("mTLS client cert/key rejected"))?;
    Ok(Arc::new(client_cfg))
}

pub fn mtls_rpc_call(
    tls_cfg: &Arc<ClientConfig>,
    addr: &str,
    node_id: u64,
    req: &Value,
    timeout: Duration,
) -> Result<(Value, String), PairedBackupError> {
    let sock: SocketAddr =
        addr.parse().map_err(|_| PairedBackupError::InvalidArgument("invalid Raft peer SocketAddr"))?;
    let tcp = TcpStream::connect_timeout(&sock, timeout)
        .map_err(|_| PairedBackupError::FreezeNotHeld("mTLS TCP connect to Raft peer failed"))?;
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;
    let dns = format!("raft-node-{node_id}.refcas.internal");
    let server_name =
        ServerName::try_from(dns).map_err(|_| PairedBackupError::InvalidArgument("invalid peer SAN DNS"))?;
    let conn = ClientConnection::new(tls_cfg.clone(), server_name)
        .map_err(|_| PairedBackupError::FreezeNotHeld("TLS ClientConnection init failed"))?;
    let mut tls = StreamOwned::new(conn, tcp);

    let payload = serde_json::to_vec(req).map_err(|_| PairedBackupError::IncompleteCut("RPC JSON encode"))?;
    tls.write_all(&(payload.len() as u32).to_be_bytes())
        .map_err(|_| PairedBackupError::FreezeNotHeld("mTLS handshake or peer authentication rejected"))?;
    tls.write_all(&payload).map_err(|_| PairedBackupError::FreezeNotHeld("mTLS frame write rejected by peer"))?;
    tls.flush().map_err(|_| PairedBackupError::FreezeNotHeld("mTLS flush rejected by peer"))?;

    let cert_sha256 = {
        let certs = tls
            .conn
            .peer_certificates()
            .ok_or(PairedBackupError::FreezeNotHeld("Raft peer presented no X.509 certificate"))?;
        let leaf = certs.first().ok_or(PairedBackupError::FreezeNotHeld("empty peer certificate chain"))?;
        hex::encode(Sha256::digest(leaf.as_ref()))
    };

    let mut len_buf = [0u8; 4];
    tls.read_exact(&mut len_buf)
        .map_err(|_| PairedBackupError::FreezeNotHeld("peer closed mTLS stream (unauthorized cert or partition)"))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_RPC_FRAME_BYTES {
        return Err(PairedBackupError::FreezeNotHeld("invalid mTLS RPC frame length"));
    }
    let mut body = vec![0u8; len];
    tls.read_exact(&mut body).map_err(|_| PairedBackupError::FreezeNotHeld("truncated mTLS RPC response"))?;
    tls.conn.send_close_notify();
    let _ = tls.flush();
    let val: Value =
        serde_json::from_slice(&body).map_err(|_| PairedBackupError::StateMachine("bad RPC JSON".into()))?;
    Ok((val, cert_sha256))
}
