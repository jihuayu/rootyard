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
    MtlsLiveRaftBackend, MtlsRaftClusterConfig, PeerAttestationConfig, PeerAttestationDaemon,
    mtls_wire::build_mtls_client_config, mtls_wire::mtls_rpc_call,
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
        let stdout = spawned.stdout.take().context("stdout")?;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = tx.send(BufReader::new(stdout).read_line(&mut line).map(|_| line));
        });
        let raw = rx.recv_timeout(Duration::from_secs(15)).context("raft-node READY timeout")??;
        let banner: Value = serde_json::from_str(raw.trim().strip_prefix("READY ").context("READY prefix")?)?;
        let addr = banner["addr"].as_str().context("addr")?.to_owned();
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

pub struct LiveMtlsRaftGroup {
    _root: TempDir,
    bin: PathBuf,
    pub group_id: i64,
    pub pki: MtlsGroupPki,
    pub nodes: BTreeMap<u64, NodeProc>,
    attestors: BTreeMap<u64, PeerAttestationDaemon>,
    tls_cfg: Arc<ClientConfig>,
}

impl LiveMtlsRaftGroup {
    pub fn start_three(group_id: i64) -> Result<Self> {
        let bin = raft_node_bin()?;
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
            let (cert, key) = pki.node_cert_key(id).context("missing node PKI")?;
            let data_dir = nodes[&id].data_dir.clone();
            let daemon = PeerAttestationDaemon::spawn(PeerAttestationConfig {
                node_id: id,
                group_id,
                data_dir,
                raft_node_addr: nodes[&id].addr.clone(),
                ca_cert_pem: pki.ca_cert.clone(),
                node_cert_pem: cert,
                node_key_pem: key,
                raft_client_cert_pem: pki.client_cert.clone(),
                raft_client_key_pem: pki.client_key.clone(),
                rpc_timeout: Duration::from_secs(4),
            })
            .map_err(|e| anyhow::anyhow!("{e}"))?;
            attestors.insert(id, daemon);
        }
        let grp = Self { _root: root, bin, group_id, pki, nodes, attestors, tls_cfg };
        grp.wait_leader()?;
        Ok(grp)
    }

    pub fn endpoints(&self) -> BTreeMap<u64, String> {
        self.nodes.iter().map(|(&id, n)| (id, n.addr.clone())).collect()
    }

    /// One server-side Ed25519 attestor daemon per voter (bound to that voter's X.509 cert).
    pub fn attestor_endpoints(&self) -> BTreeMap<u64, String> {
        self.attestors.iter().map(|(&id, a)| (id, a.addr().to_owned())).collect()
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
        let rest: BTreeSet<u64> = self.nodes.keys().copied().filter(|id| !iso.contains(id)).collect();
        for &id in &iso {
            if let Some(n) = self.nodes.get(&id) {
                let _ = n.rpc(&json!({ "PartitionPeers": { "blocked": rest } }));
            }
        }
        for &id in &rest {
            if let Some(n) = self.nodes.get(&id) {
                let _ = n.rpc(&json!({ "PartitionPeers": { "blocked": iso } }));
            }
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
        if let Some(old_att) = self.attestors.remove(&node_id) {
            old_att.shutdown();
        }
        let dir = {
            let n = self.nodes.remove(&node_id).context("missing node")?;
            let d = n.data_dir.clone();
            n.kill_hard();
            d
        };
        let respawned = NodeProc::spawn(&self.bin, &self.pki, node_id, dir, self.tls_cfg.clone())?;
        let new_addr = respawned.addr.clone();
        self.nodes.insert(node_id, respawned);
        // Rebind the voter's attestor daemon to the restarted node address; the persisted
        // `peer_attestor.pk8` keeps the same Ed25519 identity across restarts.
        if let Some((cert, key)) = self.pki.node_cert_key(node_id) {
            let data_dir = self.nodes[&node_id].data_dir.clone();
            let daemon = PeerAttestationDaemon::spawn(PeerAttestationConfig {
                node_id,
                group_id: self.group_id,
                data_dir,
                raft_node_addr: new_addr,
                ca_cert_pem: self.pki.ca_cert.clone(),
                node_cert_pem: cert,
                node_key_pem: key,
                raft_client_cert_pem: self.pki.client_cert.clone(),
                raft_client_key_pem: self.pki.client_key.clone(),
                rpc_timeout: Duration::from_secs(4),
            })
            .map_err(|e| anyhow::anyhow!("{e}"))?;
            self.attestors.insert(node_id, daemon);
        }
        self.heal_all()
    }
}
