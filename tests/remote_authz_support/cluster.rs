//! Multi-process 3-node mTLS `raft-node` cluster harness for #152 E2E tests.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::{Value, json};
use uuid::Uuid;

use rootyard::ref_store::core::state_machine::{ApplyResponse, RefCasCommand, RefCasStateMachine, StateMachineError};
use rootyard::ref_store::projector::{AuthoritySourceKind, LinearizableScopeProbe};

struct OwnedChild(Option<Child>);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = reap_bounded(&mut child, Duration::from_secs(4));
        }
    }
}

fn reap_bounded(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) | Err(_) => return None,
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
        .with_context(|| format!("spawn openssl {:?}", args))?;
    if !out.status.success() {
        bail!("openssl {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr));
    }
    Ok(())
}

pub struct MtlsClusterPki {
    _dir: tempfile::TempDir,
    ca_cert: PathBuf,
    client_cfg: Arc<ClientConfig>,
    node_paths: BTreeMap<u64, (PathBuf, PathBuf)>,
}

impl MtlsClusterPki {
    pub fn create(node_ids: &[u64]) -> Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir()?;
        let root = dir.path();
        run_openssl(
            root,
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
                "ca.key",
                "-out",
                "ca.crt",
                "-subj",
                "/CN=refcas-remote-authz-ca",
            ],
        )?;
        let ca_cert = root.join("ca.crt");

        let sign_leaf = |stem: &str, dns: &str| -> Result<(PathBuf, PathBuf)> {
            let ext_path = root.join(format!("{stem}.ext"));
            let ext_body = format!(
                "[v3_req]\nbasicConstraints = CA:FALSE\nkeyUsage = digitalSignature, keyEncipherment\n\
                 extendedKeyUsage = serverAuth, clientAuth\nsubjectAltName = DNS:{dns}\n"
            );
            fs::write(&ext_path, ext_body)?;
            let key = format!("{stem}.key");
            let csr = format!("{stem}.csr");
            let crt = format!("{stem}.crt");
            let subj = format!("/CN={dns}");
            run_openssl(
                root,
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
                    &subj,
                ],
            )?;
            let ext_str = ext_path.to_string_lossy().into_owned();
            run_openssl(
                root,
                &[
                    "x509",
                    "-req",
                    "-in",
                    &csr,
                    "-CA",
                    "ca.crt",
                    "-CAkey",
                    "ca.key",
                    "-CAcreateserial",
                    "-out",
                    &crt,
                    "-days",
                    "2",
                    "-extfile",
                    &ext_str,
                    "-extensions",
                    "v3_req",
                ],
            )?;
            Ok((root.join(crt), root.join(key)))
        };

        let (cli_crt, cli_key) = sign_leaf("client", "raft-client.refcas.internal")?;
        let mut node_paths = BTreeMap::new();
        for &id in node_ids {
            node_paths.insert(id, sign_leaf(&format!("node-{id}"), &format!("raft-node-{id}.refcas.internal"))?);
        }

        let mut roots = RootCertStore::empty();
        for c in rustls_pemfile::certs(&mut BufReader::new(File::open(&ca_cert)?)) {
            roots.add(c?)?;
        }
        let certs = rustls_pemfile::certs(&mut BufReader::new(File::open(&cli_crt)?))
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(&cli_key)?))?.context("client key")?;
        let cfg = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_client_auth_cert(certs, key)?;
        Ok(Self { _dir: dir, ca_cert, client_cfg: Arc::new(cfg), node_paths })
    }
}

pub struct RaftNodeProc {
    pub id: u64,
    pub addr: String,
    pub data_dir: PathBuf,
    client_cfg: Arc<ClientConfig>,
    child: Mutex<OwnedChild>,
}

impl RaftNodeProc {
    pub fn spawn_in_dir(bin: &Path, pki: &MtlsClusterPki, id: u64, data_dir: PathBuf) -> Result<Self> {
        let (cert, key) = pki.node_paths.get(&id).context("missing node cert")?;
        let stderr_file = File::create(data_dir.join("node.stderr"))?;
        let spawned = Command::new(bin)
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
                "350",
                "--election-min-ms",
                "1100",
                "--election-max-ms",
                "1800",
                "--write-timeout-ms",
                "8000",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::from(stderr_file))
            .spawn()
            .with_context(|| format!("spawn raft-node {id}"))?;
        let mut child = OwnedChild(Some(spawned));
        let stdout = child.0.as_mut().context("child")?.stdout.take().context("stdout")?;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut line = String::new();
            let res = BufReader::new(stdout).read_line(&mut line).map(|_| line);
            let _ = tx.send(res);
        });
        let raw = rx.recv_timeout(Duration::from_secs(15)).context("raft-node READY timeout")??;
        let banner: Value = serde_json::from_str(
            raw.trim().strip_prefix("READY ").with_context(|| format!("expected READY banner, got {raw:?}"))?,
        )?;
        let addr = banner["addr"].as_str().context("missing READY addr")?.to_owned();
        Ok(Self { id, addr, data_dir, client_cfg: pki.client_cfg.clone(), child: Mutex::new(child) })
    }

    pub async fn rpc(&self, req: Value) -> Result<Value> {
        let addr = self.addr.clone();
        let cfg = self.client_cfg.clone();
        let dns = format!("raft-node-{}.refcas.internal", self.id);
        tokio::task::spawn_blocking(move || rpc_sync(&cfg, &addr, &dns, &req)).await.context("rpc join")?
    }

    pub fn kill_hard(&self) {
        if let Some(mut c) = self.child.lock().expect("child mutex").0.take() {
            let _ = c.kill();
            let _ = reap_bounded(&mut c, Duration::from_secs(4));
        }
    }

    pub async fn shutdown(&self) {
        let _ = tokio::time::timeout(Duration::from_millis(800), self.rpc(json!("Shutdown"))).await;
        if let Some(mut c) = self.child.lock().expect("child mutex").0.take()
            && reap_bounded(&mut c, Duration::from_secs(4)).is_none()
        {
            let _ = c.kill();
            let _ = reap_bounded(&mut c, Duration::from_secs(2));
        }
    }
}

fn rpc_sync(cfg: &Arc<ClientConfig>, addr: &str, dns: &str, req: &Value) -> Result<Value> {
    let tcp = TcpStream::connect(addr)?;
    tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(10)))?;
    let server_name = ServerName::try_from(dns.to_owned())?;
    let conn = ClientConnection::new(cfg.clone(), server_name)?;
    let mut tls = StreamOwned::new(conn, tcp);
    let payload = serde_json::to_vec(req)?;
    tls.write_all(&(payload.len() as u32).to_be_bytes())?;
    tls.write_all(&payload)?;
    tls.flush()?;

    let mut len_buf = [0u8; 4];
    tls.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > 16 * 1024 * 1024 {
        bail!("invalid rpc response frame length {len}");
    }
    let mut body = vec![0u8; len];
    tls.read_exact(&mut body)?;
    tls.conn.send_close_notify();
    let _ = tls.flush();
    Ok(serde_json::from_slice(&body)?)
}

pub fn raft_node_bin() -> PathBuf {
    let path = std::env::var("ROOTYARD_REFCAS_NODE_BIN")
        .unwrap_or_else(|_| "crates/refcas-log/target/debug/raft-node".to_owned());
    let pb = PathBuf::from(&path);
    assert!(pb.is_file(), "raft-node binary missing at {}; build crates/refcas-log first", pb.display());
    pb
}

pub struct LiveRaftCluster {
    _root_dir: tempfile::TempDir,
    pki: MtlsClusterPki,
    bin: PathBuf,
    pub nodes: BTreeMap<u64, RaftNodeProc>,
    next_seq: u64,
}

impl LiveRaftCluster {
    pub async fn start_three() -> Result<Self> {
        let bin = raft_node_bin();
        let root_dir = tempfile::tempdir()?;
        let pki = MtlsClusterPki::create(&[1, 2, 3])?;
        let mut nodes = BTreeMap::new();
        let mut members = BTreeMap::new();
        for id in [1u64, 2, 3] {
            let nd = root_dir.path().join(format!("node-{id}"));
            fs::create_dir_all(&nd)?;
            let proc = RaftNodeProc::spawn_in_dir(&bin, &pki, id, nd)?;
            members.insert(id, proc.addr.clone());
            nodes.insert(id, proc);
        }
        for id in [1u64, 2, 3] {
            assert_eq!(nodes[&id].rpc(json!({ "UpdatePeers": { "peers": members } })).await?, json!("Ok"));
        }
        assert_eq!(nodes[&1].rpc(json!({ "Bootstrap": { "members": members } })).await?, json!("Ok"));
        let cluster = Self { _root_dir: root_dir, pki, bin, nodes, next_seq: 0 };
        let lid = cluster.wait_leader(None).await?;
        assert!(cluster.nodes.contains_key(&lid));
        Ok(cluster)
    }

    pub async fn wait_leader(&self, excluded: Option<u64>) -> Result<u64> {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            for (&id, n) in &self.nodes {
                if excluded == Some(id) {
                    continue;
                }
                if let Ok(resp) = n.rpc(json!("Metrics")).await
                    && let Some(m) = resp.get("Metrics")
                    && m["running_ok"].as_bool() == Some(true)
                    && let Some(lid) = m["current_leader"].as_u64()
                    && excluded != Some(lid)
                    && let Some(leader) = self.nodes.get(&lid)
                    && let Ok(ri) = leader.rpc(json!("EnsureReadIndex")).await
                    && ri.get("ReadIndex").is_some()
                {
                    return Ok(lid);
                }
            }
            if Instant::now() >= deadline {
                bail!("timed out awaiting raft leader");
            }
            tokio::time::sleep(Duration::from_millis(60)).await;
        }
    }

    pub async fn commit_sm_cmd(
        &mut self,
        cmd: &RefCasCommand,
    ) -> Result<(u64, u64, Result<ApplyResponse, StateMachineError>)> {
        let next = self.next_seq + 1;
        let cmd_json = serde_json::to_string(cmd)?;
        let log_key = format!("refcas/cmd/{next:08}");
        let log_idx = self.kv_put(&log_key, &cmd_json).await?;
        self.kv_put("refcas/head_seq", &next.to_string()).await?;
        self.next_seq = next;
        let (_, mut results) = self.replay_linearizable_on_any().await?;
        let last_res = results.pop().context("missing replayed result")?;
        Ok((next, log_idx, last_res))
    }

    async fn kv_put(&self, key: &str, value: &str) -> Result<u64> {
        let payload = serde_json::to_vec(&json!({ "Put": { "key": key, "value": value } }))?;
        let deadline = Instant::now() + Duration::from_secs(25);
        let mut last_err = String::new();
        let mut target_override: Option<u64> = None;
        while Instant::now() < deadline {
            let lid = match target_override.take() {
                Some(id) if self.nodes.contains_key(&id) => Ok(id),
                _ => self.wait_leader(None).await,
            };
            if let Ok(id) = lid
                && let Some(leader) = self.nodes.get(&id)
            {
                match leader.rpc(json!({ "ClientWrite": { "payload": payload.clone() } })).await {
                    Ok(resp) => {
                        if let Some(idx) = resp.pointer("/ClientWrite/log_index").and_then(Value::as_u64) {
                            return Ok(idx);
                        }
                        if let Some(fwd) = resp.pointer("/Error/forward_to_leader_id").and_then(Value::as_u64)
                            && fwd != id
                        {
                            target_override = Some(fwd);
                        }
                        last_err = resp.to_string();
                    }
                    Err(e) => last_err = e.to_string(),
                }
            }
            tokio::time::sleep(Duration::from_millis(80)).await;
        }
        let mut diag = Vec::new();
        for (&id, n) in &self.nodes {
            let m = n.rpc(json!("Metrics")).await.map(|v| v.to_string()).unwrap_or_else(|e| e.to_string());
            let err_tail = fs::read_to_string(n.data_dir.join("node.stderr")).unwrap_or_default();
            let tail: String = err_tail.chars().rev().take(240).collect::<String>().chars().rev().collect();
            diag.push(format!("node-{id}: metrics={m}, stderr_tail={tail:?}"));
        }
        bail!("ClientWrite timeout for {key}: {last_err}; diag=[{}]", diag.join(" | "));
    }

    pub async fn replay_linearizable_on(
        &self,
        node_id: u64,
    ) -> Result<(RefCasStateMachine, Vec<Result<ApplyResponse, StateMachineError>>)> {
        let node = self.nodes.get(&node_id).context("missing node")?;
        let head_resp = node.rpc(json!({ "KvGet": { "key": "refcas/head_seq" } })).await?;
        if let Some(err) = head_resp.get("Error") {
            bail!("KvGet ReadIndex error: {}", err);
        }
        let head_seq: u64 = head_resp.pointer("/KvValue/value").and_then(Value::as_str).unwrap_or("0").parse()?;
        let mut sm = RefCasStateMachine::new();
        let mut outcomes = Vec::with_capacity(head_seq as usize);
        for seq in 1..=head_seq {
            let k = format!("refcas/cmd/{seq:08}");
            let r = node.rpc(json!({ "KvGet": { "key": k } })).await?;
            let raw = r.pointer("/KvValue/value").and_then(Value::as_str).context("missing cmd entry")?;
            let cmd: RefCasCommand = serde_json::from_str(raw)?;
            outcomes.push(sm.apply(super::fixtures::log_id(seq), cmd));
        }
        Ok((sm, outcomes))
    }

    async fn replay_linearizable_on_any(
        &self,
    ) -> Result<(RefCasStateMachine, Vec<Result<ApplyResponse, StateMachineError>>)> {
        let lid = self.wait_leader(None).await?;
        self.replay_linearizable_on(lid).await
    }

    pub async fn probe_scope_via_read_index(
        &self,
        node_id: u64,
        scope_kind: &str,
        scope_id: Uuid,
    ) -> Result<LinearizableScopeProbe, String> {
        let node = self.nodes.get(&node_id).ok_or_else(|| format!("node {node_id} down"))?;
        let ri = node.rpc(json!("EnsureReadIndex")).await.map_err(|e| e.to_string())?;
        if let Some(err) = ri.get("Error") {
            return Err(err["message"].as_str().unwrap_or("ReadIndex failed").to_owned());
        }
        let read_log_index = ri.pointer("/ReadIndex/read_log_id/index").and_then(Value::as_u64);
        let metrics = node.rpc(json!("Metrics")).await.map_err(|e| e.to_string())?;
        let applied_log_index = metrics.pointer("/Metrics/last_applied/index").and_then(Value::as_u64).unwrap_or(0);
        let (sm, _) = self.replay_linearizable_on(node_id).await.map_err(|e| e.to_string())?;
        let drain = sm.inspect_scope_drain(scope_kind, scope_id).map_err(|e| e.to_string())?;
        Ok(LinearizableScopeProbe {
            source: AuthoritySourceKind::RaftReadIndexQuorum,
            read_log_index,
            applied_log_index,
            drain,
        })
    }

    pub async fn kill_and_restart_node(&mut self, node_id: u64) -> Result<()> {
        let dir = {
            let n = self.nodes.remove(&node_id).context("node not present")?;
            let d = n.data_dir.clone();
            n.kill_hard();
            d
        };
        let respawned = RaftNodeProc::spawn_in_dir(&self.bin, &self.pki, node_id, dir)?;
        self.nodes.insert(node_id, respawned);
        let peers: BTreeMap<u64, String> = self.nodes.iter().map(|(&id, n)| (id, n.addr.clone())).collect();
        for n in self.nodes.values() {
            n.rpc(json!({ "UpdatePeers": { "peers": peers } })).await?;
        }
        Ok(())
    }

    pub async fn isolate_node(&self, isolated_id: u64) -> Result<()> {
        let others: BTreeSet<u64> = self.nodes.keys().copied().filter(|&id| id != isolated_id).collect();
        if let Some(n) = self.nodes.get(&isolated_id) {
            n.rpc(json!({ "PartitionPeers": { "blocked": others } })).await?;
        }
        for id in others {
            if let Some(n) = self.nodes.get(&id) {
                n.rpc(json!({ "PartitionPeers": { "blocked": [isolated_id] } })).await?;
            }
        }
        Ok(())
    }

    pub async fn heal_all(&self) -> Result<()> {
        let peers: BTreeMap<u64, String> = self.nodes.iter().map(|(&id, n)| (id, n.addr.clone())).collect();
        for n in self.nodes.values() {
            n.rpc(json!({ "PartitionPeers": { "blocked": [] } })).await?;
            n.rpc(json!({ "UpdatePeers": { "peers": peers } })).await?;
        }
        Ok(())
    }

    pub async fn shutdown_all(&self) {
        for n in self.nodes.values() {
            n.shutdown().await;
        }
    }
}
