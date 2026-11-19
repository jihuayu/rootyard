//! Real 3-node mTLS `raft-node` cluster with three deployed `rootyard-safe-gc-voter` OS processes (#122).
//!
//! Each voter process holds exactly one replica connection, replays committed `pm/*` entries from
//! ONLY its own replica, and signs its own Ed25519 cutpoint attestation. Tests never hold a voter.

use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use rootyard::{
    ref_store::core::state_machine::{
        AppliedLogId, ApplyResponse, RefCasCommand, RefCasStateMachine, StateMachineError,
    },
    storage_lifecycle::safe_gc::{
        SafeGcEd25519Signer, SafeGcRaftCommitWriter, TrustedConsensusVoter,
        voter_service::{
            MtlsReplicaEndpoint, ReplicaReplay, SafeGcVoterClientAuth, SafeGcVoterReadyReceipt,
            SafeGcVoterServiceConfig, build_mtls_client_config, raft_mtls_rpc, replay_raft_replica,
        },
    },
};
use serde_json::{Value, json};
use tempfile::TempDir;

use super::dist_auth_harness::publish_live_voter_auth;

pub const RAFT_NODE_BIN_ENV: &str = "ROOTYARD_REFCAS_NODE_BIN";
pub const SAFE_GC_VOTER_BIN_ENV: &str = "ROOTYARD_SAFE_GC_VOTER_BIN";
const VOTER_KEY_ID: u8 = 1;
const VOTER_SEEDS: [[u8; 32]; 3] = [[0x71; 32], [0x72; 32], [0x73; 32]];
const VOTER_DNS: &str = "safe-gc-voter.refcas.internal";
const VOTER_AUTH_TOKEN: &str = "9f2c4d7a1b6e8c0d3a5f7b9e1c2d4f6a8b0c1d3e5f7a9b2c4d6e8f0a1b3c5d7e";

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

/// Resolve the deployed `rootyard-safe-gc-voter` binary, or `Ok(None)` when optional tests may skip.
pub fn resolve_voter_bin() -> Result<Option<PathBuf>> {
    let required = std::env::var_os("ROOTYARD_SAFE_GC_REQUIRE_PG").is_some();
    let mut candidates = Vec::new();
    if let Some(path) = std::env::var_os(SAFE_GC_VOTER_BIN_ENV) {
        candidates.push(PathBuf::from(path));
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(parent) = exe.parent()
    {
        candidates.push(parent.join("rootyard-safe-gc-voter"));
        if let Some(grandparent) = parent.parent() {
            candidates.push(grandparent.join("rootyard-safe-gc-voter"));
        }
    }
    candidates.push(PathBuf::from("target/debug/rootyard-safe-gc-voter"));
    if let Some(found) = candidates.into_iter().find(|path| path.is_file()) {
        return Ok(Some(found));
    }
    ensure!(!required, "ROOTYARD_SAFE_GC_REQUIRE_PG=1 but the rootyard-safe-gc-voter binary is missing");
    eprintln!("skipping: rootyard-safe-gc-voter binary not found");
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
    endpoint: MtlsReplicaEndpoint,
    _child: Mutex<OwnedChild>,
}

impl MtlsNode {
    fn spawn(bin: &Path, ca: &Path, crt: &Path, key: &Path, id: u64, dir: PathBuf) -> Result<Self> {
        let stderr = File::create(dir.join("node.stderr"))?;
        let mut child = Command::new(bin)
            .arg("--id")
            .arg(id.to_string())
            .arg("--dir")
            .arg(&dir)
            .arg("--tls-ca")
            .arg(ca)
            .arg("--tls-cert")
            .arg(crt)
            .arg("--tls-key")
            .arg(key)
            .arg("--check-on-open")
            .arg("true")
            .arg("--heartbeat-ms")
            .arg("250")
            .arg("--election-min-ms")
            .arg("800")
            .arg("--election-max-ms")
            .arg("1300")
            .arg("--write-timeout-ms")
            .arg("8000")
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr))
            .spawn()?;
        let stdout = child.stdout.take().context("raft-node stdout")?;
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = tx.send(BufReader::new(stdout).read_line(&mut line).map(|_| line));
        });
        let raw = rx.recv_timeout(Duration::from_secs(15))??;
        let banner: Value = serde_json::from_str(raw.trim().strip_prefix("READY ").context("raft-node READY banner")?)?;
        let addr = banner["addr"].as_str().context("raft-node addr")?.to_owned();
        let client = build_mtls_client_config(ca, &crt.with_file_name("cli.crt"), &key.with_file_name("cli.key"))?;
        let endpoint = MtlsReplicaEndpoint {
            addr,
            server_name: format!("raft-node-{id}.refcas.internal"),
            tls_config: client,
            timeout: Duration::from_secs(10),
        };
        Ok(Self { endpoint, _child: Mutex::new(OwnedChild(Some(child))) })
    }

    async fn rpc(&self, req: Value) -> Result<Value> {
        Ok(raft_mtls_rpc(&self.endpoint, req).await?)
    }
}

async fn replay_node(node: &MtlsNode) -> Result<ReplicaReplay> {
    Ok(replay_raft_replica(&node.endpoint).await?)
}

struct VoterProcess {
    voter_id: u64,
    bin: PathBuf,
    dir: PathBuf,
    config_path: PathBuf,
    ready_file: PathBuf,
    endpoint_url: String,
    pubkey_hex: String,
    child: Option<Child>,
}

fn create_private_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn write_voter_config(path: &Path, config: &SafeGcVoterServiceConfig) -> Result<()> {
    fs::write(path, serde_json::to_vec_pretty(config)?)?;
    Ok(())
}

fn launch_voter(voter: &VoterProcess) -> Result<(Child, SafeGcVoterReadyReceipt)> {
    let _ = fs::remove_file(&voter.ready_file);
    let stderr = File::create(voter.dir.join("voter.stderr"))?;
    let mut child = Command::new(&voter.bin)
        .arg("--config")
        .arg(&voter.config_path)
        .arg("--ready-file")
        .arg(&voter.ready_file)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr))
        .spawn()?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait()? {
            bail!("rootyard-safe-gc-voter {} exited before readiness: {status}", voter.voter_id);
        }
        if let Ok(raw) = fs::read(&voter.ready_file)
            && let Ok(receipt) = serde_json::from_slice::<SafeGcVoterReadyReceipt>(&raw)
            && receipt.voter_id == voter.voter_id
        {
            return Ok((child, receipt));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("rootyard-safe-gc-voter {} readiness timeout", voter.voter_id);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

pub type ApplyOutcome = Option<std::result::Result<ApplyResponse, StateMachineError>>;

/// Live 3-node mTLS OpenRaft cluster plus three deployed voter OS processes.
pub struct LiveRaftVoterCluster {
    _pki: TempDir,
    _data: TempDir,
    nodes: BTreeMap<u64, Arc<MtlsNode>>,
    voters: BTreeMap<u64, VoterProcess>,
    writer: SafeGcRaftCommitWriter,
}

fn run_ssl(dir: &Path, args: &str) -> Result<()> {
    let output = Command::new("openssl").args(args.split_whitespace()).current_dir(dir).output()?;
    ensure!(output.status.success(), "openssl: {}", String::from_utf8_lossy(&output.stderr));
    Ok(())
}

fn sign_cert(pki: &Path, stem: &str, cn: &str, eku: &str, san: &str) -> Result<()> {
    let (ext, key, csr, crt) =
        (format!("{stem}.ext"), format!("{stem}.key"), format!("{stem}.csr"), format!("{stem}.crt"));
    fs::write(
        pki.join(&ext),
        format!("[v3]\nbasicConstraints=CA:FALSE\nextendedKeyUsage={eku}\nsubjectAltName={san}\n"),
    )?;
    run_ssl(
        pki,
        &format!(
            "req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -keyout {key} -out {csr} -subj /CN={cn}"
        ),
    )?;
    run_ssl(
        pki,
        &format!(
            "x509 -req -in {csr} -CA ca.crt -CAkey ca.key -CAcreateserial -out {crt} -days 2 -extfile {ext} -extensions v3"
        ),
    )?;
    Ok(())
}

fn generate_pki(pki: &Path) -> Result<()> {
    run_ssl(
        pki,
        "req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -keyout ca.key -out ca.crt -subj /CN=p299-ca",
    )?;
    sign_cert(pki, "cli", "raft-client", "serverAuth,clientAuth", "DNS:raft-client.refcas.internal")?;
    sign_cert(pki, "vc", "rootyard-safe-gc-worker", "clientAuth", "DNS:safe-gc-worker.refcas.internal")?;
    for id in [1_u64, 2, 3] {
        let node_name = format!("raft-node-{id}.refcas.internal");
        sign_cert(pki, &format!("n{id}"), &node_name, "serverAuth,clientAuth", &format!("DNS:{node_name}"))?;
        sign_cert(pki, &format!("vs{id}"), VOTER_DNS, "serverAuth", &format!("DNS:{VOTER_DNS},IP:127.0.0.1"))?;
        let client_name = "raft-client.refcas.internal";
        sign_cert(pki, &format!("v{id}"), client_name, "serverAuth,clientAuth", &format!("DNS:{client_name}"))?;
    }
    write_private_file(&pki.join("voter-auth.token"), VOTER_AUTH_TOKEN.as_bytes())?;
    Ok(())
}

impl LiveRaftVoterCluster {
    pub async fn start(bin: PathBuf) -> Result<Self> {
        let voter_bin = resolve_voter_bin()?.context("rootyard-safe-gc-voter binary required alongside raft-node")?;
        let (pki, data) = (TempDir::new()?, TempDir::new()?);
        generate_pki(pki.path())?;
        let mut nodes = BTreeMap::new();
        let mut peers = BTreeMap::new();
        for id in [1_u64, 2, 3] {
            let (crt, key) = (pki.path().join(format!("n{id}.crt")), pki.path().join(format!("n{id}.key")));
            let dir = data.path().join(format!("n{id}"));
            fs::create_dir_all(&dir)?;
            let node = MtlsNode::spawn(&bin, &pki.path().join("ca.crt"), &crt, &key, id, dir)?;
            peers.insert(id, node.endpoint.addr.clone());
            nodes.insert(id, Arc::new(node));
        }
        for node in nodes.values() {
            ensure!(node.rpc(json!({ "UpdatePeers": { "peers": peers } })).await? == json!("Ok"));
        }
        ensure!(nodes[&1].rpc(json!({ "Bootstrap": { "members": peers } })).await? == json!("Ok"));
        let replicas = nodes.iter().map(|(id, node)| (*id, node.endpoint.clone())).collect();
        let writer = SafeGcRaftCommitWriter::new(replicas, Duration::from_secs(20))?;
        let mut cluster = Self { _pki: pki, _data: data, nodes, voters: BTreeMap::new(), writer };
        let _ = cluster.writer.wait_active_leader().await?;
        cluster.spawn_voters(&voter_bin)?;
        Ok(cluster)
    }

    fn spawn_voters(&mut self, voter_bin: &Path) -> Result<()> {
        let pki = self._pki.path();
        for voter_id in [1_u64, 2, 3] {
            let dir = self._data.path().join(format!("voter-{voter_id}"));
            create_private_dir(&dir)?;
            let seed_path = dir.join("voter.seed");
            let signer = SafeGcEd25519Signer::from_seed(VOTER_SEEDS[(voter_id - 1) as usize])?;
            signer.write_seed_file(&seed_path)?;
            let config_path = dir.join("config.json");
            let ready_file = dir.join("voter.ready");
            let mut voter = VoterProcess {
                voter_id,
                bin: voter_bin.to_path_buf(),
                dir,
                config_path,
                ready_file,
                endpoint_url: String::new(),
                pubkey_hex: signer.pubkey_hex().to_owned(),
                child: None,
            };
            let config = SafeGcVoterServiceConfig {
                voter_id,
                key_id: VOTER_KEY_ID,
                group_id: 0,
                bind_addr: "127.0.0.1:0".into(),
                signer_seed_path: seed_path,
                raft_node_addr: self.nodes[&voter_id].endpoint.addr.clone(),
                raft_server_name: format!("raft-node-{voter_id}.refcas.internal"),
                ca_cert_pem: pki.join("ca.crt"),
                client_cert_pem: pki.join(format!("v{voter_id}.crt")),
                client_key_pem: pki.join(format!("v{voter_id}.key")),
                listener_ca_cert_pem: pki.join("ca.crt"),
                listener_server_cert_pem: pki.join(format!("vs{voter_id}.crt")),
                listener_server_key_pem: pki.join(format!("vs{voter_id}.key")),
                listener_auth_token_path: pki.join("voter-auth.token"),
                rpc_timeout_ms: 5_000,
            };
            write_voter_config(&voter.config_path, &config)?;
            let (mut child, receipt) = launch_voter(&voter)?;
            ensure!(receipt.pubkey_hex == voter.pubkey_hex, "voter receipt pubkey disagrees with its own seed");
            let _ = child.kill();
            let _ = child.wait();
            let _ = fs::remove_file(&voter.ready_file);
            voter.endpoint_url = receipt.endpoint_url;
            let fixed = SafeGcVoterServiceConfig { bind_addr: receipt.bind_addr, ..config };
            write_voter_config(&voter.config_path, &fixed)?;
            self.voters.insert(voter_id, voter);
        }
        publish_live_voter_auth(self.voter_client_auth());
        Ok(())
    }

    /// Pinned mTLS + `0600` Bearer credentials the worker uses to poll these three voter listeners.
    pub fn voter_client_auth(&self) -> SafeGcVoterClientAuth {
        let pki = self._pki.path();
        SafeGcVoterClientAuth {
            ca_cert_pem: pki.join("ca.crt"),
            client_cert_pem: pki.join("vc.crt"),
            client_key_pem: pki.join("vc.key"),
            server_name: VOTER_DNS.to_owned(),
            auth_token_path: pki.join("voter-auth.token"),
        }
    }

    /// Mint a client certificate from an unrelated CA to prove the listener's mTLS verifier rejects it.
    pub fn foreign_voter_client_auth(&self, foreign: &Path) -> Result<SafeGcVoterClientAuth> {
        run_ssl(
            foreign,
            "req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 2 -keyout ca.key -out ca.crt -subj /CN=p299-foreign-ca",
        )?;
        sign_cert(foreign, "fc", "foreign-worker", "clientAuth", "DNS:foreign-worker.refcas.internal")?;
        let pki = self._pki.path();
        Ok(SafeGcVoterClientAuth {
            ca_cert_pem: pki.join("ca.crt"),
            client_cert_pem: foreign.join("fc.crt"),
            client_key_pem: foreign.join("fc.key"),
            server_name: VOTER_DNS.to_owned(),
            auth_token_path: pki.join("voter-auth.token"),
        })
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
        let Some(voter) = self.voters.get_mut(&voter_id) else { return };
        if enabled {
            if voter.child.is_some() {
                return;
            }
            let expected = voter.pubkey_hex.clone();
            match launch_voter(voter) {
                Ok((child, receipt)) if receipt.pubkey_hex == expected => voter.child = Some(child),
                Ok((mut child, _)) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    eprintln!("rootyard-safe-gc-voter {voter_id} readiness receipt mismatch");
                }
                Err(err) => eprintln!("rootyard-safe-gc-voter {voter_id} failed to start: {err:#}"),
            }
        } else if let Some(mut child) = voter.child.take() {
            let _ = child.kill();
            let _ = child.wait();
            let _ = fs::remove_file(&voter.ready_file);
        }
    }

    pub fn enabled_voter_ids(&self) -> Vec<u64> {
        self.voters.iter().filter(|(_, voter)| voter.child.is_some()).map(|(id, _)| *id).collect()
    }

    /// Append one command to the next `pm/*` slot through the production committed writer.
    pub async fn append(
        &mut self,
        command: &RefCasCommand,
    ) -> Result<(AppliedLogId, RefCasStateMachine, ApplyOutcome)> {
        Ok(self.writer.commit_command(command).await?)
    }

    pub async fn state_machine(&self) -> Result<RefCasStateMachine> {
        Ok(replay_node(&self.nodes[&1]).await?.sm)
    }
}

impl Drop for LiveRaftVoterCluster {
    fn drop(&mut self) {
        for voter in self.voters.values_mut() {
            if let Some(mut child) = voter.child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

#[path = "raft_merge_backend.rs"]
pub mod raft_merge_backend;
pub use raft_merge_backend::LiveRaft3MergeBackend;
