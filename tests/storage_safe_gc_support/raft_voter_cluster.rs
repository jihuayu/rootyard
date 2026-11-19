//! Real 3-node mTLS `raft-node` cluster with three independent cutpoint voter servers (#122).
//!
//! Each voter process holds exactly one replica connection, replays the committed `pm/*` KV
//! entries from ONLY its own replica, and signs its own Ed25519 cutpoint attestation. The
//! worker test never holds a voter, quorum, bridge or backup private key.

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use axum::{
    Json, Router, extract::Path as AxumPath, extract::State, http::StatusCode, response::IntoResponse, routing::get,
};
use rootyard::ref_store::core::state_machine::{
    AppliedLogId, ApplyResponse, RefCasCommand, RefCasStateMachine, StateMachineError,
};
use rootyard::storage_lifecycle::safe_gc::{
    SafeGcEd25519Signer, TrustedConsensusVoter, VoterCutpointAttestation, VoterCutpointClaims,
    sign_single_voter_cutpoint_attestation,
};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::task::JoinHandle;
use uuid::Uuid;

pub const RAFT_NODE_BIN_ENV: &str = "ROOTYARD_REFCAS_NODE_BIN";
const VOTER_KEY_ID: u8 = 1;
const VOTER_SEEDS: [[u8; 32]; 3] = [[0x71; 32], [0x72; 32], [0x73; 32]];

/// Resolve the multi-process `raft-node` binary, or `Ok(None)` when optional tests may skip.
pub fn resolve_raft_node_bin() -> Result<Option<PathBuf>> {
    let required = std::env::var_os("ROOTYARD_SAFE_GC_REQUIRE_PG").is_some();
    let candidate = std::env::var_os(RAFT_NODE_BIN_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("crates/refcas-log/target/debug/raft-node"));
    if candidate.is_file() {
        return Ok(Some(candidate));
    }
    ensure!(!required, "ROOTYARD_SAFE_GC_REQUIRE_PG=1 but the raft-node binary is missing at {}", candidate.display());
    eprintln!("skipping: raft-node binary not found at {}", candidate.display());
    Ok(None)
}

struct OwnedChild(Option<Child>);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct MtlsNode {
    id: u64,
    addr: String,
    cfg: Arc<ClientConfig>,
    _child: std::sync::Mutex<OwnedChild>,
}

impl MtlsNode {
    fn spawn(
        bin: &Path,
        ca: &Path,
        crt: &Path,
        key: &Path,
        id: u64,
        dir: PathBuf,
        cfg: Arc<ClientConfig>,
    ) -> Result<Self> {
        let stderr = File::create(dir.join("node.stderr"))?;
        let args = [
            "--id",
            &id.to_string(),
            "--dir",
            &dir.to_string_lossy(),
            "--tls-ca",
            &ca.to_string_lossy(),
            "--tls-cert",
            &crt.to_string_lossy(),
            "--tls-key",
            &key.to_string_lossy(),
            "--check-on-open",
            "true",
            "--heartbeat-ms",
            "250",
            "--election-min-ms",
            "800",
            "--election-max-ms",
            "1300",
            "--write-timeout-ms",
            "8000",
        ];
        let mut child = Command::new(bin).args(args).stdout(Stdio::piped()).stderr(Stdio::from(stderr)).spawn()?;
        let stdout = child.stdout.take().context("raft-node stdout")?;
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = tx.send(BufReader::new(stdout).read_line(&mut line).map(|_| line));
        });
        let raw = rx.recv_timeout(Duration::from_secs(15))??;
        let banner: Value = serde_json::from_str(raw.trim().strip_prefix("READY ").context("raft-node READY banner")?)?;
        let addr = banner["addr"].as_str().context("raft-node addr")?.to_owned();
        Ok(Self { id, addr, cfg, _child: std::sync::Mutex::new(OwnedChild(Some(child))) })
    }

    async fn rpc(&self, req: Value) -> Result<Value> {
        let (addr, cfg, dns) = (self.addr.clone(), self.cfg.clone(), format!("raft-node-{}.refcas.internal", self.id));
        tokio::task::spawn_blocking(move || {
            let tcp = TcpStream::connect(addr)?;
            tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
            tcp.set_write_timeout(Some(Duration::from_secs(10)))?;
            let mut tls = StreamOwned::new(ClientConnection::new(cfg, ServerName::try_from(dns)?)?, tcp);
            let payload = serde_json::to_vec(&req)?;
            tls.write_all(&(payload.len() as u32).to_be_bytes())?;
            tls.write_all(&payload)?;
            tls.flush()?;
            let mut len = [0_u8; 4];
            tls.read_exact(&mut len)?;
            let mut buf = vec![0_u8; u32::from_be_bytes(len) as usize];
            tls.read_exact(&mut buf)?;
            let _ = tls.conn.send_close_notify();
            let _ = tls.flush();
            Ok(serde_json::from_slice(&buf)?)
        })
        .await?
    }
}

async fn inspect_value(node: &MtlsNode, key: &str) -> Result<Option<String>> {
    let response = node.rpc(json!({ "InspectReplicaKv": { "key": key } })).await?;
    Ok(response.pointer("/KvValue/value").and_then(Value::as_str).map(str::to_owned))
}

struct Replay {
    sm: RefCasStateMachine,
    entries: Vec<(u64, RefCasCommand)>,
    last: Option<std::result::Result<ApplyResponse, StateMachineError>>,
}

async fn replay_node(node: &MtlsNode) -> Result<Replay> {
    let head = inspect_value(node, "pm/head").await?.unwrap_or_else(|| "0".into());
    let n: u64 = head.parse()?;
    let (mut sm, mut entries, mut last) = (RefCasStateMachine::new(), Vec::new(), None);
    for slot in 1..=n {
        let raw = inspect_value(node, &format!("pm/{slot:08}")).await?.context("committed Ref-CAS command")?;
        let command: RefCasCommand = serde_json::from_str(&raw)?;
        let index = inspect_value(node, &format!("pm/{slot:08}/idx"))
            .await?
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(slot);
        let term = inspect_value(node, &format!("pm/{slot:08}/term"))
            .await?
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(1);
        last = Some(sm.apply(AppliedLogId { term, index }, command.clone()));
        entries.push((index, command));
    }
    Ok(Replay { sm, entries, last })
}

fn commit_digest(entries: &[(u64, RefCasCommand)]) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"rootyard/safe-gc-refcas-raft-commit/v1");
    hasher.update((entries.len() as u64).to_be_bytes());
    for (log_index, command) in entries {
        let payload = serde_json::to_vec(command)?;
        hasher.update(log_index.to_be_bytes());
        hasher.update((payload.len() as u64).to_be_bytes());
        hasher.update(&payload);
    }
    Ok(hex::encode(hasher.finalize()))
}

struct VoterHttpState {
    voter_id: u64,
    pubkey_hex: String,
    signer: SafeGcEd25519Signer,
    node: Arc<MtlsNode>,
    enabled: Arc<AtomicBool>,
}

impl VoterHttpState {
    async fn attest(&self, repo_id: Uuid) -> Result<VoterCutpointAttestation> {
        let replay = replay_node(&self.node).await?;
        let snapshot = replay.sm.snapshot()?;
        let (raft_term, committed_log_index) =
            replay.sm.last_applied().map(|id| (id.term, id.index)).context("voter has no committed entry")?;
        let gate = snapshot
            .body
            .gates
            .iter()
            .find(|gate| gate.repository_id == repo_id)
            .context("committed snapshot has no gate for the repository")?;
        let claims = VoterCutpointClaims {
            voter_id: self.voter_id,
            key_id: VOTER_KEY_ID,
            group_id: 0,
            history_incarnation: gate.history_incarnation,
            group_epoch: gate.group_epoch,
            authority_epoch: gate.authority_epoch,
            raft_term,
            committed_log_index,
            raft_commit_digest_hex: commit_digest(&replay.entries)?,
        };
        Ok(sign_single_voter_cutpoint_attestation(&self.signer, &claims, &snapshot)?)
    }
}

async fn voter_cutpoint(
    State(state): State<Arc<VoterHttpState>>,
    AxumPath(repo_id): AxumPath<Uuid>,
) -> impl IntoResponse {
    if !state.enabled.load(Ordering::SeqCst) {
        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": "voter disabled" })));
    }
    match state.attest(repo_id).await {
        Ok(attestation) => match serde_json::to_value(&attestation) {
            Ok(body) => (StatusCode::OK, Json(body)),
            Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "encode" }))),
        },
        Err(err) => (StatusCode::SERVICE_UNAVAILABLE, Json(json!({ "error": format!("{err:#}") }))),
    }
}

struct VoterHandle {
    endpoint_url: String,
    pubkey_hex: String,
    enabled: Arc<AtomicBool>,
    task: JoinHandle<()>,
}

/// Live 3-node mTLS OpenRaft cluster plus three independent voter HTTP endpoints.
pub struct LiveRaftVoterCluster {
    _pki: TempDir,
    _data: TempDir,
    nodes: BTreeMap<u64, Arc<MtlsNode>>,
    voters: BTreeMap<u64, VoterHandle>,
    seq: u64,
}

fn run_ssl(dir: &Path, args: &str) -> Result<()> {
    let output = Command::new("openssl").args(args.split_whitespace()).current_dir(dir).output()?;
    ensure!(output.status.success(), "openssl: {}", String::from_utf8_lossy(&output.stderr));
    Ok(())
}

fn generate_pki(pki: &Path) -> Result<Arc<ClientConfig>> {
    run_ssl(
        pki,
        "req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -keyout ca.key -out ca.crt -subj /CN=p299-ca",
    )?;
    let sign = |stem: &str, dns: &str| -> Result<(PathBuf, PathBuf)> {
        let (ext, key, csr, crt) =
            (format!("{stem}.ext"), format!("{stem}.key"), format!("{stem}.csr"), format!("{stem}.crt"));
        fs::write(
            pki.join(&ext),
            format!(
                "[v3]\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:{dns}\n"
            ),
        )?;
        run_ssl(
            pki,
            &format!(
                "req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout {key} -out {csr} -subj /CN={dns}"
            ),
        )?;
        run_ssl(
            pki,
            &format!(
                "x509 -req -in {csr} -CA ca.crt -CAkey ca.key -CAcreateserial -out {crt} -days 2 -extfile {ext} -extensions v3"
            ),
        )?;
        Ok((pki.join(crt), pki.join(key)))
    };
    let (client_crt, client_key) = sign("cli", "raft-client.refcas.internal")?;
    for id in [1_u64, 2, 3] {
        let _ = sign(&format!("n{id}"), &format!("raft-node-{id}.refcas.internal"))?;
    }
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut BufReader::new(File::open(pki.join("ca.crt"))?)) {
        roots.add(cert?)?;
    }
    let certs = rustls_pemfile::certs(&mut BufReader::new(File::open(&client_crt)?))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(&client_key)?))?.context("client key")?;
    Ok(Arc::new(
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_client_auth_cert(certs, key)?,
    ))
}

impl LiveRaftVoterCluster {
    pub async fn start(bin: PathBuf) -> Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (pki, data) = (TempDir::new()?, TempDir::new()?);
        let cfg = generate_pki(pki.path())?;
        let mut nodes = BTreeMap::new();
        let mut peers = BTreeMap::new();
        for id in [1_u64, 2, 3] {
            let (crt, key) = (pki.path().join(format!("n{id}.crt")), pki.path().join(format!("n{id}.key")));
            let dir = data.path().join(format!("n{id}"));
            fs::create_dir_all(&dir)?;
            let node = MtlsNode::spawn(&bin, &pki.path().join("ca.crt"), &crt, &key, id, dir, cfg.clone())?;
            peers.insert(id, node.addr.clone());
            nodes.insert(id, Arc::new(node));
        }
        for node in nodes.values() {
            ensure!(node.rpc(json!({ "UpdatePeers": { "peers": peers } })).await? == json!("Ok"));
        }
        ensure!(nodes[&1].rpc(json!({ "Bootstrap": { "members": peers } })).await? == json!("Ok"));
        let mut cluster = Self { _pki: pki, _data: data, nodes, voters: BTreeMap::new(), seq: 0 };
        let _ = cluster.wait_leader().await?;
        cluster.spawn_voters().await?;
        Ok(cluster)
    }

    async fn spawn_voters(&mut self) -> Result<()> {
        for voter_id in [1_u64, 2, 3] {
            let signer = SafeGcEd25519Signer::from_seed(VOTER_SEEDS[(voter_id - 1) as usize])?;
            let state = Arc::new(VoterHttpState {
                voter_id,
                pubkey_hex: signer.pubkey_hex().to_owned(),
                signer,
                node: Arc::clone(&self.nodes[&voter_id]),
                enabled: Arc::new(AtomicBool::new(false)),
            });
            let app = Router::new()
                .route("/v1/safe-gc/cutpoint/{repo_id}", get(voter_cutpoint))
                .with_state(Arc::clone(&state));
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
            let addr = listener.local_addr()?;
            let task = tokio::spawn(async move {
                let _ = axum::serve(listener, app).await;
            });
            self.voters.insert(
                voter_id,
                VoterHandle {
                    endpoint_url: format!("http://{addr}"),
                    pubkey_hex: state.pubkey_hex.clone(),
                    enabled: Arc::clone(&state.enabled),
                    task,
                },
            );
        }
        Ok(())
    }

    pub fn trusted_voters(&self) -> Vec<TrustedConsensusVoter> {
        self.voters
            .iter()
            .map(|(voter_id, voter)| TrustedConsensusVoter {
                voter_id: *voter_id,
                key_id: VOTER_KEY_ID,
                ed25519_pubkey_hex: voter.pubkey_hex.clone(),
                endpoint_url: voter.endpoint_url.clone(),
            })
            .collect()
    }

    pub fn set_voter_enabled(&mut self, voter_id: u64, enabled: bool) {
        if let Some(voter) = self.voters.get(&voter_id) {
            voter.enabled.store(enabled, Ordering::SeqCst);
        }
    }

    pub fn enabled_voter_ids(&self) -> Vec<u64> {
        self.voters.iter().filter(|(_, voter)| voter.enabled.load(Ordering::SeqCst)).map(|(id, _)| *id).collect()
    }

    pub async fn current_term(&self) -> Result<u64> {
        let leader = self.wait_leader().await?;
        let metrics = self.nodes[&leader].rpc(json!("Metrics")).await?;
        metrics.pointer("/Metrics/current_term").and_then(Value::as_u64).context("current_term")
    }

    pub async fn wait_leader(&self) -> Result<u64> {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            for node in self.nodes.values() {
                if let Ok(metrics) = node.rpc(json!("Metrics")).await
                    && metrics.pointer("/Metrics/running_ok").and_then(Value::as_bool) == Some(true)
                    && let Some(leader) = metrics.pointer("/Metrics/current_leader").and_then(Value::as_u64)
                    && self.nodes.contains_key(&leader)
                    && self.nodes[&leader]
                        .rpc(json!("EnsureReadIndex"))
                        .await
                        .is_ok_and(|v| v.get("ReadIndex").is_some())
                {
                    return Ok(leader);
                }
            }
            tokio::time::sleep(Duration::from_millis(60)).await;
        }
        bail!("raft-node leader election timeout")
    }

    async fn kv_put(&self, key: &str, value: &str) -> Result<u64> {
        let payload = serde_json::to_vec(&json!({ "Put": { "key": key, "value": value } }))?;
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut last = String::new();
        let mut hint = None;
        while Instant::now() < deadline {
            let leader = match hint.take() {
                Some(id) if self.nodes.contains_key(&id) => id,
                _ => self.wait_leader().await?,
            };
            match self.nodes[&leader].rpc(json!({ "ClientWrite": { "payload": payload.clone() } })).await {
                Ok(written) => {
                    if let Some(index) = written.pointer("/ClientWrite/log_index").and_then(Value::as_u64) {
                        return Ok(index);
                    }
                    if let Some(forward) = written.pointer("/Error/forward_to_leader_id").and_then(Value::as_u64) {
                        hint = Some(forward);
                    }
                    last = written.to_string();
                }
                Err(err) => last = err.to_string(),
            }
            tokio::time::sleep(Duration::from_millis(80)).await;
        }
        bail!("raft-node ClientWrite timeout for {key}: {last}")
    }

    async fn wait_applied(&self, slot: u64) -> Result<()> {
        let wanted = slot.to_string();
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            let mut applied = 0;
            for node in self.nodes.values() {
                if inspect_value(node, "pm/head").await.ok().flatten().as_deref() == Some(wanted.as_str()) {
                    applied += 1;
                }
            }
            if applied == self.nodes.len() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        bail!("replicas never applied pm/head={slot}")
    }

    /// Append one command to `pm/{slot}`, its index, its term and `pm/head`, then await all replicas.
    pub async fn append(
        &mut self,
        command: &RefCasCommand,
    ) -> Result<(AppliedLogId, RefCasStateMachine, Option<std::result::Result<ApplyResponse, StateMachineError>>)> {
        let slot = self.seq + 1;
        let payload = serde_json::to_string(command)?;
        let index = self.kv_put(&format!("pm/{slot:08}"), &payload).await?;
        let term = self.current_term().await?;
        let _ = self.kv_put(&format!("pm/{slot:08}/idx"), &index.to_string()).await?;
        let _ = self.kv_put(&format!("pm/{slot:08}/term"), &term.to_string()).await?;
        let _ = self.kv_put("pm/head", &slot.to_string()).await?;
        self.seq = slot;
        self.wait_applied(slot).await?;
        let replay = replay_node(&self.nodes[&1]).await?;
        Ok((AppliedLogId { term, index }, replay.sm, replay.last))
    }

    pub async fn state_machine(&self) -> Result<RefCasStateMachine> {
        Ok(replay_node(&self.nodes[&1]).await?.sm)
    }
}

impl Drop for LiveRaftVoterCluster {
    fn drop(&mut self) {
        for voter in self.voters.values() {
            voter.task.abort();
        }
    }
}

#[path = "raft_merge_backend.rs"]
pub mod raft_merge_backend;
pub use raft_merge_backend::LiveRaft3MergeBackend;
