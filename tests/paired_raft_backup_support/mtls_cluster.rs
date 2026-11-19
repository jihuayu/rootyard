//! Multi-process 3-voter mTLS `raft-node` cluster harness for Issue #153 E2E qualification.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use rustls::ClientConfig;
use serde_json::{Value, json};
use tempfile::TempDir;

use rootyard::maintenance::paired_raft_backup::{
    MtlsLiveRaftBackend, MtlsRaftClusterConfig, mtls_wire::build_mtls_client_config, mtls_wire::mtls_rpc_call,
};

struct OwnedChild(Option<Child>);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            let _ = c.kill();
            let _ = reap(&mut c, Duration::from_secs(3));
        }
    }
}

fn reap(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let dl = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(st)) => return Some(st),
            Ok(None) if Instant::now() < dl => std::thread::sleep(Duration::from_millis(20)),
            _ => return None,
        }
    }
}

fn run_openssl(dir: &Path, args: &[&str]) -> Result<()> {
    let out = Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("openssl {args:?}"))?;
    if !out.status.success() {
        bail!("openssl {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(())
}

pub struct MtlsGroupPki {
    _dir: TempDir,
    pub ca_cert: PathBuf,
    pub client_cert: PathBuf,
    pub client_key: PathBuf,
    pub unpinned_client_cert: PathBuf,
    pub unpinned_client_key: PathBuf,
    pub wrong_san_cert: PathBuf,
    pub wrong_san_key: PathBuf,
    pub rogue_ca_cert: PathBuf,
    pub rogue_client_cert: PathBuf,
    pub rogue_client_key: PathBuf,
    node_paths: BTreeMap<u64, (PathBuf, PathBuf)>,
}

impl MtlsGroupPki {
    pub fn generate(node_ids: &[u64]) -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let r = dir.path();
        for (ca_name, cn) in [("ca", "paired-raft-ca"), ("rogue", "rogue-ca")] {
            run_openssl(
                r,
                &[
                    "req",
                    "-x509",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:prime256v1",
                    "-nodes",
                    "-days",
                    "2",
                    "-keyout",
                    &format!("{ca_name}.key"),
                    "-out",
                    &format!("{ca_name}.crt"),
                    "-subj",
                    &format!("/CN={cn}"),
                ],
            )?;
        }
        let sign = |ca: &str, stem: &str, dns: &str| -> Result<(PathBuf, PathBuf)> {
            let ext = r.join(format!("{stem}.ext"));
            fs::write(
                &ext,
                format!(
                    "[v3_req]\nbasicConstraints = CA:FALSE\nkeyUsage = digitalSignature, keyEncipherment\n\
                     extendedKeyUsage = serverAuth, clientAuth\nsubjectAltName = DNS:{dns}\n"
                ),
            )?;
            let (key, csr, crt) = (format!("{stem}.key"), format!("{stem}.csr"), format!("{stem}.crt"));
            run_openssl(
                r,
                &[
                    "req",
                    "-new",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:prime256v1",
                    "-nodes",
                    "-keyout",
                    &key,
                    "-out",
                    &csr,
                    "-subj",
                    &format!("/CN={dns}"),
                ],
            )?;
            run_openssl(
                r,
                &[
                    "x509",
                    "-req",
                    "-in",
                    &csr,
                    "-CA",
                    &format!("{ca}.crt"),
                    "-CAkey",
                    &format!("{ca}.key"),
                    "-CAcreateserial",
                    "-out",
                    &crt,
                    "-days",
                    "2",
                    "-extfile",
                    &ext.to_string_lossy(),
                    "-extensions",
                    "v3_req",
                ],
            )?;
            Ok((r.join(crt), r.join(key)))
        };
        let (client_cert, client_key) = sign("ca", "client", "raft-client.refcas.internal")?;
        let (unpinned_client_cert, unpinned_client_key) = sign("ca", "unpinned-cli", "raft-client.refcas.internal")?;
        let (wrong_san_cert, wrong_san_key) = sign("ca", "wrong-san", "unauthorized-caller.internal")?;
        let (rogue_client_cert, rogue_client_key) = sign("rogue", "rogue-cli", "raft-client.refcas.internal")?;
        let mut node_paths = BTreeMap::new();
        for &id in node_ids {
            node_paths.insert(id, sign("ca", &format!("node-{id}"), &format!("raft-node-{id}.refcas.internal"))?);
        }
        Ok(Self {
            ca_cert: r.join("ca.crt"),
            rogue_ca_cert: r.join("rogue.crt"),
            client_cert,
            client_key,
            unpinned_client_cert,
            unpinned_client_key,
            wrong_san_cert,
            wrong_san_key,
            rogue_client_cert,
            rogue_client_key,
            node_paths,
            _dir: dir,
        })
    }

    /// `(node_cert_pem, node_key_pem)` for one voter, reused by its attestor daemon.
    pub fn node_cert_key(&self, id: u64) -> Option<(PathBuf, PathBuf)> {
        self.node_paths.get(&id).cloned()
    }
}

pub struct NodeProc {
    pub id: u64,
    pub addr: String,
    pub data_dir: PathBuf,
    tls_cfg: Arc<ClientConfig>,
    child: Mutex<OwnedChild>,
}
fn wait_ready(spawned: &mut Child) -> Result<Value> {
    let stdout = spawned.stdout.take().context("stdout")?;
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = tx.send(BufReader::new(stdout).read_line(&mut line).map(|_| line));
    });
    let raw = rx.recv_timeout(Duration::from_secs(15)).context("READY timeout")??;
    serde_json::from_str(raw.trim().strip_prefix("READY ").context("READY prefix")?).context("READY json")
}
impl NodeProc {
    fn spawn(bin: &Path, pki: &MtlsGroupPki, id: u64, data_dir: PathBuf, tls_cfg: Arc<ClientConfig>) -> Result<Self> {
        let (cert, key) = pki.node_paths.get(&id).context("node cert")?;
        let stderr_f = File::create(data_dir.join("node.stderr"))?;
        let mut spawned = Command::new(bin)
            .args([
                "--id",
                &id.to_string(),
                "--dir",
                &data_dir.to_string_lossy(),
                "--tls-ca",
                &pki.ca_cert.to_string_lossy(),
                "--tls-cert",
                &cert.to_string_lossy(),
                "--tls-key",
                &key.to_string_lossy(),
                "--check-on-open",
                "true",
                "--heartbeat-ms",
                "120",
                "--election-min-ms",
                "400",
                "--election-max-ms",
                "750",
                "--write-timeout-ms",
                "5000",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr_f))
            .spawn()?;
        let addr = wait_ready(&mut spawned)?["addr"].as_str().context("addr")?.to_owned();
        Ok(Self { id, addr, data_dir, tls_cfg, child: Mutex::new(OwnedChild(Some(spawned))) })
    }
    pub fn rpc(&self, req: &Value) -> Result<Value> {
        let (val, _) = mtls_rpc_call(&self.tls_cfg, &self.addr, self.id, req, Duration::from_secs(6))
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(val)
    }
    pub fn kill_hard(&self) {
        if let Some(mut c) = self.child.lock().unwrap().0.take() {
            let _ = c.kill();
            let _ = reap(&mut c, Duration::from_secs(3));
        }
    }
}

pub fn raft_node_bin() -> Result<PathBuf> {
    let raw = std::env::var("ROOTYARD_REFCAS_NODE_BIN")
        .unwrap_or_else(|_| "crates/refcas-log/target/debug/raft-node".to_owned());
    let pb = PathBuf::from(&raw);
    if !pb.is_file() {
        bail!("raft-node binary missing at {}; build crates/refcas-log --bin raft-node first", pb.display());
    }
    Ok(pb.canonicalize()?)
}

pub fn peer_attestor_bin() -> Result<PathBuf> {
    let raw = std::env::var("ROOTYARD_PEER_ATTESTOR_BIN")
        .ok()
        .or_else(|| option_env!("CARGO_BIN_EXE_rootyard-peer-attestor").map(str::to_owned))
        .unwrap_or_else(|| "target/debug/rootyard-peer-attestor".to_owned());
    let pb = PathBuf::from(&raw);
    if !pb.is_file() {
        bail!("rootyard-peer-attestor binary missing at {}; build --bin rootyard-peer-attestor first", pb.display());
    }
    Ok(pb.canonicalize()?)
}

pub struct AttestorProc {
    pub addr: String,
    child: Mutex<OwnedChild>,
}

impl AttestorProc {
    fn spawn(
        bin: &Path,
        pki: &MtlsGroupPki,
        id: u64,
        group_id: i64,
        data_dir: PathBuf,
        raft_node_addr: &str,
    ) -> Result<Self> {
        let (cert, key) = pki.node_paths.get(&id).context("node cert")?;
        let stderr_f = File::create(data_dir.join("attestor.stderr"))?;
        let mut spawned = Command::new(bin)
            .args([
                "--node-id",
                &id.to_string(),
                "--group-id",
                &group_id.to_string(),
                "--dir",
                &data_dir.to_string_lossy(),
                "--raft-node-addr",
                raft_node_addr,
                "--tls-ca",
                &pki.ca_cert.to_string_lossy(),
                "--tls-cert",
                &cert.to_string_lossy(),
                "--tls-key",
                &key.to_string_lossy(),
                "--raft-client-cert",
                &pki.client_cert.to_string_lossy(),
                "--raft-client-key",
                &pki.client_key.to_string_lossy(),
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr_f))
            .spawn()?;
        let addr = wait_ready(&mut spawned)?["addr"].as_str().context("addr")?.to_owned();
        Ok(Self { addr, child: Mutex::new(OwnedChild(Some(spawned))) })
    }

    pub fn kill_hard(&self) {
        if let Some(mut c) = self.child.lock().unwrap().0.take() {
            let _ = c.kill();
            let _ = reap(&mut c, Duration::from_secs(3));
        }
    }
}

pub struct LiveMtlsRaftGroup {
    _root: TempDir,
    bin: PathBuf,
    attestor_bin: PathBuf,
    pub group_id: i64,
    pub pki: MtlsGroupPki,
    pub nodes: BTreeMap<u64, NodeProc>,
    attestors: BTreeMap<u64, AttestorProc>,
    tls_cfg: Arc<ClientConfig>,
}

impl LiveMtlsRaftGroup {
    pub fn start_three(group_id: i64) -> Result<Self> {
        let bin = raft_node_bin()?;
        let attestor_bin = peer_attestor_bin()?;
        let root = tempfile::tempdir()?;
        let pki = MtlsGroupPki::generate(&[1, 2, 3])?;
        let dummy_cfg = MtlsRaftClusterConfig {
            group_id,
            local_node_id: 1,
            voter_endpoints: BTreeMap::from([(1, "127.0.0.1:1".into())]),
            attestor_endpoints: BTreeMap::new(),
            ca_cert_pem: pki.ca_cert.clone(),
            client_cert_pem: pki.client_cert.clone(),
            client_key_pem: pki.client_key.clone(),
            rpc_timeout: Duration::from_secs(5),
        };
        let tls_cfg = build_mtls_client_config(&dummy_cfg).map_err(|e| anyhow::anyhow!("{e}"))?;
        let mut nodes = BTreeMap::new();
        let mut members = BTreeMap::new();
        for id in [1u64, 2, 3] {
            let nd = root.path().join(format!("node-{id}"));
            fs::create_dir_all(&nd)?;
            let proc = NodeProc::spawn(&bin, &pki, id, nd, tls_cfg.clone())?;
            members.insert(id, proc.addr.clone());
            nodes.insert(id, proc);
        }
        for n in nodes.values() {
            assert_eq!(n.rpc(&json!({ "UpdatePeers": { "peers": members } }))?, json!("Ok"));
        }
        assert_eq!(nodes[&1].rpc(&json!({ "Bootstrap": { "members": members } }))?, json!("Ok"));
        let mut attestors = BTreeMap::new();
        for id in [1u64, 2, 3] {
            let nd = nodes[&id].data_dir.clone();
            let addr = nodes[&id].addr.clone();
            let attestor = AttestorProc::spawn(&attestor_bin, &pki, id, group_id, nd, &addr)?;
            attestors.insert(id, attestor);
        }
        let grp = Self { _root: root, bin, attestor_bin, group_id, pki, nodes, attestors, tls_cfg };
        grp.wait_leader()?;
        Ok(grp)
    }

    pub fn endpoints(&self) -> BTreeMap<u64, String> {
        self.nodes.iter().map(|(&id, n)| (id, n.addr.clone())).collect()
    }

    /// One server-side Ed25519 attestor daemon per voter (bound to that voter's X.509 cert).
    pub fn attestor_endpoints(&self) -> BTreeMap<u64, String> {
        self.attestors.iter().map(|(&id, a)| (id, a.addr.clone())).collect()
    }

    pub fn tls_config(&self) -> Arc<ClientConfig> {
        self.tls_cfg.clone()
    }

    pub fn connect_backend(&self, local_node_id: u64) -> Result<MtlsLiveRaftBackend> {
        MtlsLiveRaftBackend::connect(MtlsRaftClusterConfig {
            group_id: self.group_id,
            local_node_id,
            voter_endpoints: self.endpoints(),
            attestor_endpoints: self.attestor_endpoints(),
            ca_cert_pem: self.pki.ca_cert.clone(),
            client_cert_pem: self.pki.client_cert.clone(),
            client_key_pem: self.pki.client_key.clone(),
            rpc_timeout: Duration::from_secs(4),
        })
        .map_err(|e| anyhow::anyhow!("{e}"))
    }

    pub fn wait_leader(&self) -> Result<u64> {
        let dl = Instant::now() + Duration::from_secs(12);
        while Instant::now() < dl {
            for n in self.nodes.values() {
                if let Ok(r) = n.rpc(&json!("Metrics"))
                    && let Some(lid) = r.pointer("/Metrics/current_leader").and_then(Value::as_u64)
                    && let Some(leader) = self.nodes.get(&lid)
                    && leader.rpc(&json!("EnsureReadIndex")).is_ok_and(|ri| ri.get("ReadIndex").is_some())
                {
                    return Ok(lid);
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        bail!("timed out awaiting 3-voter mTLS Raft leader on group {}", self.group_id);
    }

    pub fn isolate_nodes(&self, isolated: &[u64]) -> Result<()> {
        let iso: BTreeSet<u64> = isolated.iter().copied().collect();
        for &id in &iso {
            anyhow::ensure!(self.nodes.contains_key(&id), "unknown voter node_id {id}");
        }
        let rest: BTreeSet<u64> = self.nodes.keys().copied().filter(|id| !iso.contains(id)).collect();
        for (&id, blocked) in iso.iter().map(|id| (id, &rest)).chain(rest.iter().map(|id| (id, &iso))) {
            let resp = self.nodes[&id].rpc(&json!({ "PartitionPeers": { "blocked": blocked } }))?;
            anyhow::ensure!(resp == json!("Ok"), "PartitionPeers on voter {id} rejected: {resp}");
        }
        Ok(())
    }

    /// Partition every voter from every other voter (`{1} | {2} | {3}`): no pair retains a 2-of-3
    /// quorum anywhere, while direct test-client RPC probes still reach all three voters.
    pub fn partition_all_nodes(&self) -> Result<()> {
        for (&id, node) in &self.nodes {
            let others: BTreeSet<u64> = self.nodes.keys().copied().filter(|&other| other != id).collect();
            let resp = node.rpc(&json!({ "PartitionPeers": { "blocked": others } }))?;
            anyhow::ensure!(resp == json!("Ok"), "PartitionPeers on voter {id} rejected: {resp}");
        }
        Ok(())
    }

    pub fn heal_all(&self) -> Result<()> {
        let peers = self.endpoints();
        for n in self.nodes.values() {
            n.rpc(&json!({ "PartitionPeers": { "blocked": [] } }))?;
            n.rpc(&json!({ "UpdatePeers": { "peers": peers } }))?;
        }
        self.wait_leader()?;
        Ok(())
    }

    pub fn kill_and_restart_node(&mut self, node_id: u64) -> Result<()> {
        let old_term = self
            .nodes
            .values()
            .filter_map(|n| n.rpc(&json!("Metrics")).ok()?.pointer("/Metrics/current_term")?.as_u64())
            .max()
            .unwrap_or(1);
        let was_leader = self.nodes.get(&node_id).is_some_and(|n| {
            n.rpc(&json!("Metrics")).ok().and_then(|m| m.pointer("/Metrics/current_leader").and_then(Value::as_u64))
                == Some(node_id)
        });
        if let Some(old_att) = self.attestors.remove(&node_id) {
            old_att.kill_hard();
        }
        let dir = {
            let n = self.nodes.remove(&node_id).context("missing node")?;
            let d = n.data_dir.clone();
            n.kill_hard();
            d
        };
        if was_leader {
            let deadline = Instant::now() + Duration::from_secs(6);
            loop {
                let elected = self.nodes.values().any(|n| {
                    n.rpc(&json!("Metrics")).ok().is_some_and(|m| {
                        let leader = m.pointer("/Metrics/current_leader").and_then(Value::as_u64);
                        let term = m.pointer("/Metrics/current_term").and_then(Value::as_u64);
                        leader.is_some_and(|lid| lid != node_id) && term.is_some_and(|t| t > old_term)
                    })
                });
                if elected {
                    break;
                }
                if Instant::now() >= deadline {
                    bail!("timed out awaiting leader failover beyond term {old_term} after killing node {node_id}");
                }
                std::thread::sleep(Duration::from_millis(60));
            }
        }
        let respawned = NodeProc::spawn(&self.bin, &self.pki, node_id, dir, self.tls_cfg.clone())?;
        let new_addr = respawned.addr.clone();
        let data_dir = respawned.data_dir.clone();
        self.nodes.insert(node_id, respawned);
        let attestor = AttestorProc::spawn(&self.attestor_bin, &self.pki, node_id, self.group_id, data_dir, &new_addr)?;
        self.attestors.insert(node_id, attestor);
        self.heal_all()
    }
}
