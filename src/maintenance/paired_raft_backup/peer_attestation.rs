//! Server-side Ed25519 per-peer durable attestations bound to the voter's X.509
//! certificate AND Ed25519 public key, plus the per-voter mTLS attestation daemon (#153).

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ring::rand::SystemRandom;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, RootCertStore, ServerConfig, ServerConnection, StreamOwned};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::mtls_raft::MtlsLiveRaftBackend;
use super::mtls_wire::{MtlsRaftClusterConfig, build_mtls_client_config, mtls_rpc_call};
use super::types::{PairedBackupError, validate_hex64};

pub const PEER_ATTESTOR_KEY_FILE: &str = "peer_attestor.pk8";
const MAX_ATTEST_FRAME_BYTES: usize = 16 * 1024 * 1024;

/// Canonical `voter_id` derivation binding the voter's X.509 leaf SHA-256 AND its
/// Ed25519 public key to the Raft group/node identity (`rootyard-mtls-voter-uuid-v2`).
pub fn derive_voter_uuid_bound(group_id: i64, node_id: u64, cert_sha256: &str, ed25519_pubkey_hex: &str) -> Uuid {
    let mut h = Sha256::new();
    h.update(b"rootyard-mtls-voter-uuid-v2\0");
    h.update(group_id.to_be_bytes());
    h.update(node_id.to_be_bytes());
    h.update(cert_sha256.as_bytes());
    h.update(b":");
    h.update(ed25519_pubkey_hex.as_bytes());
    let digest = h.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PeerDurableAttestationClaims {
    pub kind: String,
    pub group_id: i64,
    pub group_epoch: i64,
    pub node_id: u64,
    pub voter_id: Uuid,
    pub peer_cert_sha256: String,
    pub ed25519_pubkey_hex: String,
    pub raft_term: u64,
    pub raft_committed_index: u64,
    pub refcas_seq: u64,
    pub subject_digest: String,
    pub secondary_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PeerDurableAttestation {
    pub claims: PeerDurableAttestationClaims,
    pub signature_hex: String,
}

fn canonical_message(claims: &PeerDurableAttestationClaims) -> Result<Vec<u8>, PairedBackupError> {
    serde_json::to_vec(&("rootyard-peer-durable-attestation-v1", claims))
        .map_err(|_| PairedBackupError::IncompleteCut("peer attestation canonical JSON encode failed"))
}

impl PeerDurableAttestation {
    pub fn sign(claims: PeerDurableAttestationClaims, keypair: &Ed25519KeyPair) -> Result<Self, PairedBackupError> {
        let msg = canonical_message(&claims)?;
        let signature_hex = hex::encode(keypair.sign(&msg).as_ref());
        let attestation = Self { claims, signature_hex };
        attestation.verify()?;
        Ok(attestation)
    }

    pub fn verify(&self) -> Result<(), PairedBackupError> {
        let c = &self.claims;
        if c.group_id < 0
            || c.group_epoch < 1
            || c.raft_term < 1
            || c.voter_id.is_nil()
            || !validate_hex64(&c.peer_cert_sha256)
            || !validate_hex64(&c.ed25519_pubkey_hex)
            || !validate_hex64(&c.subject_digest)
            || !validate_hex64(&c.secondary_digest)
            || self.signature_hex.len() != 128
            || !self.signature_hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(PairedBackupError::FreezeNotHeld("malformed peer Ed25519 durable attestation"));
        }
        if c.kind != "commit" && c.kind != "cutpoint" {
            return Err(PairedBackupError::FreezeNotHeld("unsupported peer durable attestation kind"));
        }
        if derive_voter_uuid_bound(c.group_id, c.node_id, &c.peer_cert_sha256, &c.ed25519_pubkey_hex) != c.voter_id {
            return Err(PairedBackupError::FreezeNotHeld(
                "peer voter_id is not cryptographically bound to its X.509 cert and Ed25519 key",
            ));
        }
        let pubkey_bytes = hex::decode(&c.ed25519_pubkey_hex)
            .map_err(|_| PairedBackupError::FreezeNotHeld("invalid peer Ed25519 public key hex"))?;
        let sig_bytes = hex::decode(&self.signature_hex)
            .map_err(|_| PairedBackupError::FreezeNotHeld("invalid peer Ed25519 signature hex"))?;
        if pubkey_bytes.len() != 32 || sig_bytes.len() != 64 {
            return Err(PairedBackupError::FreezeNotHeld("invalid peer Ed25519 key or signature length"));
        }
        let msg = canonical_message(c)?;
        UnparsedPublicKey::new(&ED25519, &pubkey_bytes)
            .verify(&msg, &sig_bytes)
            .map_err(|_| PairedBackupError::FreezeNotHeld("invalid peer Ed25519 durable attestation signature"))?;
        Ok(())
    }
}

/// Load a voter's private PKCS#8 Ed25519 keypair (`0o600` on Unix) or create it once.
pub fn load_or_create_ed25519_keypair(path: &Path) -> Result<(Ed25519KeyPair, String), PairedBackupError> {
    let pkcs8 = if path.exists() {
        fs::read(path)?
    } else {
        let generated = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|_| PairedBackupError::FreezeNotHeld("failed to generate peer Ed25519 keypair"))?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(path)?;
        file.write_all(generated.as_ref())?;
        file.sync_all()?;
        generated.as_ref().to_vec()
    };
    let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_slice())
        .map_err(|_| PairedBackupError::FreezeNotHeld("invalid peer Ed25519 PKCS#8 keypair"))?;
    let pubkey_hex = hex::encode(keypair.public_key().as_ref());
    Ok((keypair, pubkey_hex))
}

/// fsync an existing state file (missing files are a no-op).
pub(super) fn sync_file_if_exists(path: &Path) -> Result<(), PairedBackupError> {
    let opened = OpenOptions::new().read(true).write(true).open(path).or_else(|_| File::open(path));
    match opened {
        Ok(file) => {
            file.sync_data()?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(PairedBackupError::Io(error)),
    }
}

pub struct PeerAttestationConfig {
    pub node_id: u64,
    pub group_id: i64,
    pub data_dir: PathBuf,
    pub raft_node_addr: String,
    /// Listener address; `None` binds an ephemeral loopback port (`127.0.0.1:0`).
    pub bind_addr: Option<String>,
    pub ca_cert_pem: PathBuf,
    /// TLS server leaf for this daemon (`DNS:raft-node-{id}.refcas.internal`), whose
    /// SHA-256 is also the pinned voter identity.
    pub node_cert_pem: PathBuf,
    pub node_key_pem: PathBuf,
    /// mTLS client leaf for calling the local `raft-node` control RPCs
    /// (`Metrics`, `InspectReplicaKv`), which require `DNS:raft-client.refcas.internal`.
    pub raft_client_cert_pem: PathBuf,
    pub raft_client_key_pem: PathBuf,
    pub rpc_timeout: Duration,
}

pub(super) struct PeerAttestorState {
    pub(super) node_id: u64,
    pub(super) group_id: i64,
    pub(super) data_dir: PathBuf,
    pub(super) raft_node_addr: String,
    pub(super) cert_sha256: String,
    pub(super) pubkey_hex: String,
    pub(super) voter_id: Uuid,
    pub(super) keypair: Arc<Ed25519KeyPair>,
    pub(super) tls_cfg: Arc<ClientConfig>,
    pub(super) server_cfg: Arc<ServerConfig>,
    pub(super) rpc_timeout: Duration,
}

/// Server-side mTLS Ed25519 durable-attestation daemon for one Raft voter.
pub struct PeerAttestationDaemon {
    addr: String,
    voter_id: Uuid,
    pubkey_hex: String,
    stop: Arc<AtomicBool>,
    join: Mutex<Option<thread::JoinHandle<()>>>,
}

impl PeerAttestationDaemon {
    pub fn spawn(cfg: PeerAttestationConfig) -> Result<Self, PairedBackupError> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        fs::create_dir_all(&cfg.data_dir)?;
        let (keypair, pubkey_hex) = load_or_create_ed25519_keypair(&cfg.data_dir.join(PEER_ATTESTOR_KEY_FILE))?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let roots = load_ca_roots(&cfg.ca_cert_pem)?;
        let certs = load_cert_chain(&cfg.node_cert_pem)?;
        let leaf =
            certs.first().ok_or(PairedBackupError::FreezeNotHeld("peer attestor has no X.509 leaf certificate"))?;
        let cert_sha256 = hex::encode(Sha256::digest(leaf.as_ref()));
        let key = load_private_key(&cfg.node_key_pem)?;
        let verifier = WebPkiClientVerifier::builder_with_provider(roots, provider.clone())
            .build()
            .map_err(|_| PairedBackupError::FreezeNotHeld("invalid peer attestor client verifier"))?;
        let server_cfg = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|_| PairedBackupError::FreezeNotHeld("peer attestor TLS server setup failed"))?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)
            .map_err(|_| PairedBackupError::FreezeNotHeld("peer attestor cert/key rejected"))?;
        let tls_cfg = build_mtls_client_config(&MtlsRaftClusterConfig {
            group_id: cfg.group_id,
            local_node_id: cfg.node_id,
            voter_endpoints: BTreeMap::new(),
            attestor_endpoints: BTreeMap::new(),
            ca_cert_pem: cfg.ca_cert_pem.clone(),
            client_cert_pem: cfg.raft_client_cert_pem.clone(),
            client_key_pem: cfg.raft_client_key_pem.clone(),
            rpc_timeout: cfg.rpc_timeout,
        })?;
        let voter_id = derive_voter_uuid_bound(cfg.group_id, cfg.node_id, &cert_sha256, &pubkey_hex);
        let state = Arc::new(PeerAttestorState {
            node_id: cfg.node_id,
            group_id: cfg.group_id,
            data_dir: cfg.data_dir,
            raft_node_addr: cfg.raft_node_addr,
            cert_sha256,
            pubkey_hex,
            voter_id,
            keypair: Arc::new(keypair),
            tls_cfg,
            server_cfg: Arc::new(server_cfg),
            rpc_timeout: cfg.rpc_timeout,
        });
        let listener = TcpListener::bind(cfg.bind_addr.as_deref().unwrap_or("127.0.0.1:0"))?;
        let addr = listener.local_addr()?.to_string();
        let (voter_id, pubkey_hex) = (state.voter_id, state.pubkey_hex.clone());
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let join = thread::Builder::new()
            .name(format!("peer-attestor-{}", cfg.node_id))
            .spawn(move || {
                for stream in listener.incoming() {
                    if thread_stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let Ok(tcp) = stream else { continue };
                    let _ = handle_connection(&state, tcp);
                }
            })
            .map_err(PairedBackupError::Io)?;
        Ok(Self { addr, voter_id, pubkey_hex, stop, join: Mutex::new(Some(join)) })
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }

    pub fn voter_id(&self) -> Uuid {
        self.voter_id
    }

    pub fn pubkey_hex(&self) -> &str {
        &self.pubkey_hex
    }

    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(&self.addr);
    }
}

impl Drop for PeerAttestationDaemon {
    fn drop(&mut self) {
        self.shutdown();
        let handle = self.join.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).take();
        if let Some(handle) = handle {
            let _ = handle.join();
        }
    }
}

fn handle_connection(state: &PeerAttestorState, tcp: TcpStream) -> Result<(), PairedBackupError> {
    tcp.set_read_timeout(Some(state.rpc_timeout))?;
    tcp.set_write_timeout(Some(state.rpc_timeout))?;
    let conn = ServerConnection::new(state.server_cfg.clone())
        .map_err(|_| PairedBackupError::FreezeNotHeld("peer attestor TLS server init failed"))?;
    let mut tls = StreamOwned::new(conn, tcp);

    let mut len_buf = [0u8; 4];
    tls.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_ATTEST_FRAME_BYTES {
        return Err(PairedBackupError::FreezeNotHeld("invalid peer attestation request frame length"));
    }
    let mut body = vec![0u8; len];
    tls.read_exact(&mut body)?;
    tls.conn
        .peer_certificates()
        .ok_or(PairedBackupError::FreezeNotHeld("peer attestation client presented no X.509 certificate"))?;

    let request: Value = serde_json::from_slice(&body)
        .map_err(|_| PairedBackupError::InvalidArgument("malformed peer attestation JSON request"))?;
    let response = dispatch(state, &request);
    let payload = serde_json::to_vec(&response)
        .map_err(|_| PairedBackupError::IncompleteCut("peer attestation response encode failed"))?;
    tls.write_all(&(payload.len() as u32).to_be_bytes())?;
    tls.write_all(&payload)?;
    tls.flush()?;
    tls.conn.send_close_notify();
    Ok(())
}

fn dispatch(state: &PeerAttestorState, request: &Value) -> Value {
    if request.get("Identity").is_some() {
        return json!({ "Identity": {
            "node_id": state.node_id,
            "peer_cert_sha256": state.cert_sha256,
            "ed25519_pubkey_hex": state.pubkey_hex,
        }});
    }
    let attested = if let Some(body) = request.get("AttestCommit") {
        super::peer_attestation_rpc::attest_commit(state, body)
    } else if let Some(body) = request.get("AttestCutpoint") {
        super::peer_attestation_rpc::attest_cutpoint(state, body)
    } else {
        Err(PairedBackupError::InvalidArgument("unknown peer attestation request kind"))
    };
    match attested {
        Ok(attestation) => json!({ "Attestation": attestation }),
        Err(error) => json!({ "Error": error.to_string() }),
    }
}

/// Wait until the local `raft-node` replica has applied `required_seq`, returning its leaf digest.
pub(super) fn verify_local_replica_caught_up(
    raft: &MtlsLiveRaftBackend,
    required_seq: u64,
) -> Result<String, PairedBackupError> {
    let local_addr = &raft.cfg.voter_endpoints[&raft.cfg.local_node_id];
    let deadline = std::time::Instant::now() + Duration::from_millis(900);
    while std::time::Instant::now() < deadline {
        if let Ok((response, cert_sha)) = mtls_rpc_call(
            &raft.tls_cfg,
            local_addr,
            raft.cfg.local_node_id,
            &json!({ "InspectReplicaKv": { "key": "refcas/head_seq" } }),
            raft.cfg.rpc_timeout,
        ) {
            let seq = parse_replica_head_seq(&response);
            if seq.is_some_and(|seq| seq >= required_seq) {
                return Ok(cert_sha);
            }
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    Err(PairedBackupError::FreezeNotHeld(
        "consensus quorum committed on remote mTLS peers, but local Raft replica WAL/apply lagged",
    ))
}

/// Parse the replica's applied `refcas/head_seq`; a pristine replica reports it as `null`,
/// which is sequence zero. Error responses and malformed values fail closed (`None`).
fn parse_replica_head_seq(response: &Value) -> Option<u64> {
    match response.pointer("/KvValue/value") {
        Some(Value::Null) => Some(0u64),
        Some(Value::String(raw)) => raw.parse::<u64>().ok(),
        _ => None,
    }
}

/// Probe one voter's `PeerAttestationDaemon` and prove its `Identity` is bound to the
/// same X.509 leaf certificate the `raft-node` presented.
pub(super) fn probe_attestor_identity(
    tls_cfg: &Arc<ClientConfig>,
    endpoint: &str,
    node_id: u64,
    observed_cert_sha: &str,
    timeout: Duration,
) -> Result<(String, String), PairedBackupError> {
    let (response, handshake_cert_sha) =
        mtls_rpc_call(tls_cfg, endpoint, node_id, &json!({ "Identity": {} }), timeout)?;
    if handshake_cert_sha != observed_cert_sha {
        return Err(PairedBackupError::FreezeNotHeld(
            "peer attestor certificate differs from the voter's raft-node certificate",
        ));
    }
    let identity = response
        .get("Identity")
        .ok_or(PairedBackupError::FreezeNotHeld("peer attestation daemon rejected Identity probe"))?;
    let reported_cert = identity["peer_cert_sha256"]
        .as_str()
        .ok_or(PairedBackupError::FreezeNotHeld("peer attestation daemon returned no certificate digest"))?;
    let pubkey_hex = identity["ed25519_pubkey_hex"]
        .as_str()
        .ok_or(PairedBackupError::FreezeNotHeld("peer attestation daemon returned no Ed25519 public key"))?;
    if reported_cert != observed_cert_sha
        || identity["node_id"].as_u64() != Some(node_id)
        || !validate_hex64(pubkey_hex)
    {
        return Err(PairedBackupError::FreezeNotHeld(
            "peer attestation identity is not bound to the live voter certificate/key",
        ));
    }
    Ok((reported_cert.to_owned(), pubkey_hex.to_owned()))
}

fn load_ca_roots(path: &Path) -> Result<Arc<RootCertStore>, PairedBackupError> {
    let mut roots = RootCertStore::empty();
    for item in rustls_pemfile::certs(&mut BufReader::new(File::open(path)?)) {
        let der = item.map_err(|_| PairedBackupError::FreezeNotHeld("failed to parse peer attestor CA PEM"))?;
        roots.add(der).map_err(|_| PairedBackupError::FreezeNotHeld("invalid peer attestor CA certificate"))?;
    }
    Ok(Arc::new(roots))
}

fn load_cert_chain(path: &Path) -> Result<Vec<CertificateDer<'static>>, PairedBackupError> {
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut BufReader::new(File::open(path)?))
        .collect::<Result<_, _>>()
        .map_err(|_| PairedBackupError::FreezeNotHeld("invalid peer attestor certificate PEM"))?;
    if certs.is_empty() {
        return Err(PairedBackupError::FreezeNotHeld("empty peer attestor certificate chain"));
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, PairedBackupError> {
    rustls_pemfile::private_key(&mut BufReader::new(File::open(path)?))
        .map_err(|_| PairedBackupError::FreezeNotHeld("invalid peer attestor private key PEM"))?
        .ok_or(PairedBackupError::FreezeNotHeld("missing peer attestor private key"))
}

#[cfg(test)]
mod tests {
    use super::parse_replica_head_seq;
    use serde_json::json;

    #[test]
    fn pristine_replica_null_head_seq_is_zero() {
        let response = json!({ "KvValue": { "key": "refcas/head_seq", "value": null } });
        let required_seq = 0u64;
        assert_eq!(parse_replica_head_seq(&response), Some(0));
        assert!(parse_replica_head_seq(&response).is_some_and(|seq| seq >= required_seq));
        assert!(!parse_replica_head_seq(&response).is_some_and(|seq| seq >= 1));
    }

    #[test]
    fn numeric_head_seq_is_parsed() {
        let response = json!({ "KvValue": { "key": "refcas/head_seq", "value": "42" } });
        assert_eq!(parse_replica_head_seq(&response), Some(42));
    }

    #[test]
    fn error_response_fails_closed() {
        let response = json!({ "Error": "node unavailable" });
        assert_eq!(parse_replica_head_seq(&response), None);
    }

    #[test]
    fn malformed_head_seq_fails_closed() {
        let response = json!({ "KvValue": { "key": "refcas/head_seq", "value": "not-a-number" } });
        assert_eq!(parse_replica_head_seq(&response), None);
        assert_eq!(parse_replica_head_seq(&json!({ "KvValue": { "value": true } })), None);
        assert_eq!(parse_replica_head_seq(&json!({ "KvValue": { "value": [] } })), None);
    }
}
