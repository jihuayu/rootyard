//! Deployed mTLS Raft-replica cutpoint voter daemon (`rootyard-safe-gc-voter`, #122).
//!
//! Each voter process binds exactly one local `raft-node` replica, replays its committed
//! `pm/*` entries, and signs one Ed25519 cutpoint attestation over the exact snapshot bytes.

use std::{
    io::{BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use axum::{
    Json, Router,
    extract::{Path as AxumPath, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned, pki_types::ServerName};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::ref_store::core::state_machine::{
    AppliedLogId, ApplyResponse, RefCasCommand, RefCasSnapshot, RefCasStateMachine, StateMachineError,
};

use super::{SafeGcEd25519Signer, SafeGcError, VoterCutpointClaims, sign_single_voter_cutpoint_attestation};

const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

fn io_error(err: impl std::fmt::Display) -> SafeGcError {
    SafeGcError::Io(err.to_string())
}

fn json_error(err: serde_json::Error) -> SafeGcError {
    SafeGcError::Serialization(err.to_string())
}

fn default_voter_key_id() -> u8 {
    1
}

fn default_voter_group_id() -> i64 {
    0
}

fn default_voter_rpc_timeout_ms() -> u64 {
    5_000
}

/// Configuration for a deployed `rootyard-safe-gc-voter` daemon bound to one local mTLS `raft-node` replica.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafeGcVoterServiceConfig {
    pub voter_id: u64,
    #[serde(default = "default_voter_key_id")]
    pub key_id: u8,
    #[serde(default = "default_voter_group_id")]
    pub group_id: i64,
    pub bind_addr: String,
    pub signer_seed_path: PathBuf,
    pub raft_node_addr: String,
    pub raft_server_name: String,
    pub ca_cert_pem: PathBuf,
    pub client_cert_pem: PathBuf,
    pub client_key_pem: PathBuf,
    #[serde(default = "default_voter_rpc_timeout_ms")]
    pub rpc_timeout_ms: u64,
}

impl SafeGcVoterServiceConfig {
    pub fn validate(&self) -> Result<(), SafeGcError> {
        if self.voter_id == 0 || self.key_id == 0 || self.group_id < 0 {
            return Err(SafeGcError::ArmingRejected("safe-gc voter identity is invalid"));
        }
        if !(100..=60_000).contains(&self.rpc_timeout_ms) {
            return Err(SafeGcError::ArmingRejected("safe-gc voter rpc_timeout_ms is out of bounds"));
        }
        if self.bind_addr.trim().is_empty()
            || self.raft_node_addr.trim().is_empty()
            || self.raft_server_name.trim().is_empty()
        {
            return Err(SafeGcError::ArmingRejected("safe-gc voter addresses must be non-empty"));
        }
        Ok(())
    }
}

/// Readiness receipt atomically written when `serve_safe_gc_voter` binds its listener.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SafeGcVoterReadyReceipt {
    pub voter_id: u64,
    pub key_id: u8,
    pub group_id: i64,
    pub bind_addr: String,
    pub endpoint_url: String,
    pub pubkey_hex: String,
}

/// One pinned mTLS `raft-node` replica connection owned by a single voter process.
#[derive(Clone)]
pub struct MtlsReplicaEndpoint {
    pub addr: String,
    pub server_name: String,
    pub tls_config: Arc<rustls::ClientConfig>,
    pub timeout: Duration,
}

/// Build the one pinned mTLS client config used by both the voter daemon and integration harnesses.
pub fn build_mtls_client_config(
    ca_cert_pem: &Path,
    client_cert_pem: &Path,
    client_key_pem: &Path,
) -> Result<Arc<rustls::ClientConfig>, SafeGcError> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut roots = RootCertStore::empty();
    let ca = std::fs::File::open(ca_cert_pem).map_err(io_error)?;
    for cert in rustls_pemfile::certs(&mut BufReader::new(ca)) {
        roots.add(cert.map_err(io_error)?).map_err(io_error)?;
    }
    let certs = rustls_pemfile::certs(&mut BufReader::new(std::fs::File::open(client_cert_pem).map_err(io_error)?))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(io_error)?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(std::fs::File::open(client_key_pem).map_err(io_error)?))
        .map_err(io_error)?
        .ok_or(SafeGcError::ArmingRejected("mTLS client private key missing"))?;
    let config = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(io_error)?
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)
        .map_err(io_error)?;
    Ok(Arc::new(config))
}

/// Issue one length-prefixed JSON request over the voter's pinned mTLS replica connection.
pub async fn raft_mtls_rpc(endpoint: &MtlsReplicaEndpoint, req: Value) -> Result<Value, SafeGcError> {
    let endpoint = endpoint.clone();
    tokio::task::spawn_blocking(move || {
        let addr: SocketAddr =
            endpoint.addr.parse().map_err(|_| SafeGcError::ArmingRejected("invalid raft-node socket address"))?;
        let tcp = TcpStream::connect_timeout(&addr, endpoint.timeout).map_err(io_error)?;
        tcp.set_read_timeout(Some(endpoint.timeout)).map_err(io_error)?;
        tcp.set_write_timeout(Some(endpoint.timeout)).map_err(io_error)?;
        let server_name = ServerName::try_from(endpoint.server_name.clone())
            .map_err(|_| SafeGcError::ArmingRejected("invalid raft-node mTLS server name"))?;
        let connection = ClientConnection::new(endpoint.tls_config.clone(), server_name).map_err(io_error)?;
        let mut tls = StreamOwned::new(connection, tcp);
        let payload = serde_json::to_vec(&req).map_err(json_error)?;
        tls.write_all(&(payload.len() as u32).to_be_bytes()).map_err(io_error)?;
        tls.write_all(&payload).map_err(io_error)?;
        tls.flush().map_err(io_error)?;
        let mut len = [0_u8; 4];
        tls.read_exact(&mut len).map_err(io_error)?;
        let len = u32::from_be_bytes(len) as usize;
        if len > MAX_FRAME_BYTES {
            return Err(SafeGcError::Serialization("raft-node response frame exceeds 16 MiB".into()));
        }
        let mut buf = vec![0_u8; len];
        tls.read_exact(&mut buf).map_err(io_error)?;
        tls.conn.send_close_notify();
        let _ = tls.flush();
        serde_json::from_slice(&buf).map_err(json_error)
    })
    .await
    .map_err(io_error)?
}

async fn inspect_value(endpoint: &MtlsReplicaEndpoint, key: &str) -> Result<Option<String>, SafeGcError> {
    let response = raft_mtls_rpc(endpoint, json!({ "InspectReplicaKv": { "key": key } })).await?;
    Ok(response.pointer("/KvValue/value").and_then(Value::as_str).map(str::to_owned))
}

/// Replayed committed state plus the exact Raft commands that produced it.
pub struct ReplicaReplay {
    pub sm: RefCasStateMachine,
    pub entries: Vec<(u64, RefCasCommand)>,
    pub last: Option<std::result::Result<ApplyResponse, StateMachineError>>,
}

/// Replay every committed `pm/*` entry from one voter's own replica, in slot order.
pub async fn replay_raft_replica(endpoint: &MtlsReplicaEndpoint) -> Result<ReplicaReplay, SafeGcError> {
    let head = inspect_value(endpoint, "pm/head").await?.unwrap_or_else(|| "0".to_owned());
    let n: u64 = head.parse().map_err(|_| SafeGcError::Serialization("raft-node pm/head is not a slot".into()))?;
    let (mut sm, mut entries, mut last) = (RefCasStateMachine::new(), Vec::new(), None);
    for slot in 1..=n {
        let raw = inspect_value(endpoint, &format!("pm/{slot:08}"))
            .await?
            .ok_or_else(|| SafeGcError::Serialization(format!("raft-node pm/{slot:08} is missing")))?;
        let command: RefCasCommand = serde_json::from_str(&raw).map_err(json_error)?;
        let index = inspect_value(endpoint, &format!("pm/{slot:08}/idx"))
            .await?
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(slot);
        let term = inspect_value(endpoint, &format!("pm/{slot:08}/term"))
            .await?
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(1);
        last = Some(sm.apply(AppliedLogId { term, index }, command.clone()));
        entries.push((index, command));
    }
    Ok(ReplicaReplay { sm, entries, last })
}

/// Canonical SHA-256 over the replayed Raft commit transcript.
pub fn compute_raft_commit_digest(entries: &[(u64, RefCasCommand)]) -> Result<String, SafeGcError> {
    let mut hasher = Sha256::new();
    hasher.update(b"rootyard/safe-gc-refcas-raft-commit/v1");
    hasher.update((entries.len() as u64).to_be_bytes());
    for (log_index, command) in entries {
        let payload = serde_json::to_vec(command).map_err(json_error)?;
        hasher.update(log_index.to_be_bytes());
        hasher.update((payload.len() as u64).to_be_bytes());
        hasher.update(&payload);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[derive(Clone)]
struct VoterState {
    config: Arc<SafeGcVoterServiceConfig>,
    signer: Arc<SafeGcEd25519Signer>,
    replica: MtlsReplicaEndpoint,
}

fn service_failure(err: impl std::fmt::Display) -> (StatusCode, Json<Value>) {
    (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": err.to_string() })))
}

async fn voter_health(State(state): State<Arc<VoterState>>) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "ok": true,
            "voter_id": state.config.voter_id,
            "key_id": state.config.key_id,
            "group_id": state.config.group_id,
            "pubkey_hex": state.signer.pubkey_hex(),
        })),
    )
}

async fn voter_cutpoint(
    State(state): State<Arc<VoterState>>,
    AxumPath(repo_id): AxumPath<Uuid>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let replay = replay_raft_replica(&state.replica).await.map_err(service_failure)?;
    let snapshot: RefCasSnapshot = replay.sm.snapshot().map_err(service_failure)?;
    let Some(applied) = replay.sm.last_applied() else {
        return Err((StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": "voter has no committed Raft entry" }))));
    };
    let Some(gate) = snapshot.body.gates.iter().find(|gate| gate.repository_id == repo_id) else {
        return Err((
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "committed snapshot has no gate for the repository" })),
        ));
    };
    let claims = VoterCutpointClaims {
        voter_id: state.config.voter_id,
        key_id: state.config.key_id,
        group_id: state.config.group_id,
        history_incarnation: gate.history_incarnation,
        group_epoch: gate.group_epoch,
        authority_epoch: gate.authority_epoch,
        raft_term: applied.term,
        committed_log_index: applied.index,
        raft_commit_digest_hex: compute_raft_commit_digest(&replay.entries).map_err(service_failure)?,
    };
    let attestation =
        sign_single_voter_cutpoint_attestation(&state.signer, &claims, &snapshot).map_err(service_failure)?;
    let value = serde_json::to_value(&attestation)
        .map_err(|err| service_failure(SafeGcError::Serialization(err.to_string())))?;
    Ok(Json(value))
}

fn write_ready_receipt(path: &Path, receipt: &SafeGcVoterReadyReceipt) -> Result<(), SafeGcError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(io_error)?;
    }
    let bytes = serde_json::to_vec_pretty(receipt).map_err(json_error)?;
    let tmp = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    std::fs::write(&tmp, &bytes).map_err(io_error)?;
    std::fs::rename(&tmp, path).map_err(io_error)
}

async fn voter_shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
        match terminate.as_mut() {
            Some(term) => tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            },
            None => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Bind the voter HTTP listener, publish its readiness receipt, and serve until shutdown.
pub async fn serve_safe_gc_voter(
    config: SafeGcVoterServiceConfig,
    ready_file: Option<&Path>,
) -> Result<(), SafeGcError> {
    config.validate()?;
    let signer = Arc::new(SafeGcEd25519Signer::load_seed_file(&config.signer_seed_path)?);
    let tls_config = build_mtls_client_config(&config.ca_cert_pem, &config.client_cert_pem, &config.client_key_pem)?;
    let replica = MtlsReplicaEndpoint {
        addr: config.raft_node_addr.clone(),
        server_name: config.raft_server_name.clone(),
        tls_config,
        timeout: Duration::from_millis(config.rpc_timeout_ms),
    };
    let sock_addr: SocketAddr = config
        .bind_addr
        .parse()
        .map_err(|_| SafeGcError::ArmingRejected("voter bind_addr must be a socket address"))?;
    let socket = (if sock_addr.is_ipv4() { tokio::net::TcpSocket::new_v4() } else { tokio::net::TcpSocket::new_v6() })
        .map_err(io_error)?;
    socket.set_reuseaddr(true).map_err(io_error)?;
    socket.bind(sock_addr).map_err(io_error)?;
    let listener = socket.listen(128).map_err(io_error)?;
    let local_addr = listener.local_addr().map_err(io_error)?;
    let receipt = SafeGcVoterReadyReceipt {
        voter_id: config.voter_id,
        key_id: config.key_id,
        group_id: config.group_id,
        bind_addr: local_addr.to_string(),
        endpoint_url: format!("http://{local_addr}"),
        pubkey_hex: signer.pubkey_hex().to_owned(),
    };
    if let Some(path) = ready_file {
        write_ready_receipt(path, &receipt)?;
    }
    let state = Arc::new(VoterState { config: Arc::new(config), signer, replica });
    let app = Router::new()
        .route("/healthz", get(voter_health))
        .route("/v1/safe-gc/cutpoint/{repo_id}", get(voter_cutpoint))
        .with_state(state);
    axum::serve(listener, app).with_graceful_shutdown(voter_shutdown_signal()).await.map_err(io_error)
}
