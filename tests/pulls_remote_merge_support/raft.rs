use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use rootyard::pulls::remote_merge_finalizer::coordinator::{
    BackendFuture, map_commit_receipt_to_outcome, map_sm_error_to_outcome,
};
use rootyard::pulls::remote_merge_finalizer::{AuthorityCommitOutcome, MergeAuthorityBackend, RemoteMergeError};
use rootyard::ref_store::contract::{OperationLookup, OperationState};
use rootyard::ref_store::core::state_machine::{
    AppliedLogId, ApplyResponse, CommitScopedRefsCommand, InstallScopedDecisionCommand, RefCasCommand,
    RefCasStateMachine, StateMachineError,
};
use rootyard::ref_store::core::terminal::CommitTerminal;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

struct OwnedChild(Option<Child>);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

struct MtlsNode {
    id: u64,
    addr: String,
    dir: PathBuf,
    cfg: Arc<ClientConfig>,
    child: Mutex<OwnedChild>,
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
        let mut ch = Command::new(bin).args(args).stdout(Stdio::piped()).stderr(Stdio::from(stderr)).spawn()?;
        let stdout = ch.stdout.take().context("stdout")?;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut s = String::new();
            let _ = tx.send(BufReader::new(stdout).read_line(&mut s).map(|_| s));
        });
        let raw = rx.recv_timeout(Duration::from_secs(15))??;
        let banner: Value = serde_json::from_str(raw.trim().strip_prefix("READY ").context("READY")?)?;
        let addr = banner["addr"].as_str().context("addr")?.into();
        Ok(Self { id, addr, dir, cfg, child: Mutex::new(OwnedChild(Some(ch))) })
    }

    async fn rpc(&self, req: Value) -> Result<Value> {
        let (addr, cfg, dns) = (self.addr.clone(), self.cfg.clone(), format!("raft-node-{}.refcas.internal", self.id));
        tokio::task::spawn_blocking(move || {
            let tcp = TcpStream::connect(addr)?;
            tcp.set_read_timeout(Some(Duration::from_secs(10)))?;
            tcp.set_write_timeout(Some(Duration::from_secs(10)))?;
            let mut tls = StreamOwned::new(ClientConnection::new(cfg, ServerName::try_from(dns)?)?, tcp);
            let p = serde_json::to_vec(&req)?;
            tls.write_all(&(p.len() as u32).to_be_bytes())?;
            tls.write_all(&p)?;
            tls.flush()?;
            let mut lb = [0u8; 4];
            tls.read_exact(&mut lb)?;
            let mut buf = vec![0u8; u32::from_be_bytes(lb) as usize];
            tls.read_exact(&mut buf)?;
            tls.conn.send_close_notify();
            let _ = tls.flush();
            Ok(serde_json::from_slice(&buf)?)
        })
        .await?
    }
}

pub struct LiveRaft3 {
    _pki: TempDir,
    _data: TempDir,
    ca: PathBuf,
    cfg: Arc<ClientConfig>,
    bin: PathBuf,
    pems: BTreeMap<u64, (PathBuf, PathBuf)>,
    nodes: BTreeMap<u64, MtlsNode>,
    seq: u64,
}

fn run_ssl(dir: &Path, args: &[&str]) -> Result<()> {
    let o = Command::new("openssl").args(args).current_dir(dir).output()?;
    ensure!(o.status.success(), "openssl: {}", String::from_utf8_lossy(&o.stderr));
    Ok(())
}

impl LiveRaft3 {
    pub async fn start() -> Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let bin = PathBuf::from(
            std::env::var("ROOTYARD_REFCAS_NODE_BIN")
                .unwrap_or_else(|_| "crates/refcas-log/target/debug/raft-node".into()),
        );
        ensure!(bin.is_file(), "missing {}", bin.display());
        let (pki, data) = (TempDir::new()?, TempDir::new()?);
        let r = pki.path();
        run_ssl(
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
                "ca.key",
                "-out",
                "ca.crt",
                "-subj",
                "/CN=p156-ca",
            ],
        )?;
        let sign = |st: &str, dns: &str| -> Result<(PathBuf, PathBuf)> {
            fs::write(
                r.join(format!("{st}.ext")),
                format!(
                    "[v3]\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:{dns}\n"
                ),
            )?;
            run_ssl(
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
                    &format!("{st}.key"),
                    "-out",
                    &format!("{st}.csr"),
                    "-subj",
                    &format!("/CN={dns}"),
                ],
            )?;
            run_ssl(
                r,
                &[
                    "x509",
                    "-req",
                    "-in",
                    &format!("{st}.csr"),
                    "-CA",
                    "ca.crt",
                    "-CAkey",
                    "ca.key",
                    "-CAcreateserial",
                    "-out",
                    &format!("{st}.crt"),
                    "-days",
                    "2",
                    "-extfile",
                    &format!("{st}.ext"),
                    "-extensions",
                    "v3",
                ],
            )?;
            Ok((r.join(format!("{st}.crt")), r.join(format!("{st}.key"))))
        };
        let (cc, ck) = sign("cli", "raft-client.refcas.internal")?;
        let mut roots = RootCertStore::empty();
        for c in rustls_pemfile::certs(&mut BufReader::new(File::open(r.join("ca.crt"))?)) {
            roots.add(c?)?;
        }
        let certs =
            rustls_pemfile::certs(&mut BufReader::new(File::open(&cc)?)).collect::<std::result::Result<Vec<_>, _>>()?;
        let key = rustls_pemfile::private_key(&mut BufReader::new(File::open(&ck)?))?.context("key")?;
        let cfg = Arc::new(
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()?
                .with_root_certificates(roots)
                .with_client_auth_cert(certs, key)?,
        );
        let (mut pems, mut nodes, mut peers) = (BTreeMap::new(), BTreeMap::new(), BTreeMap::new());
        for id in [1u64, 2, 3] {
            let (c, k) = sign(&format!("n{id}"), &format!("raft-node-{id}.refcas.internal"))?;
            let nd = data.path().join(format!("n{id}"));
            fs::create_dir_all(&nd)?;
            let proc = MtlsNode::spawn(&bin, &r.join("ca.crt"), &c, &k, id, nd, cfg.clone())?;
            peers.insert(id, proc.addr.clone());
            pems.insert(id, (c, k));
            nodes.insert(id, proc);
        }
        for n in nodes.values() {
            ensure!(n.rpc(json!({ "UpdatePeers": { "peers": peers } })).await? == json!("Ok"));
        }
        ensure!(nodes[&1].rpc(json!({ "Bootstrap": { "members": peers } })).await? == json!("Ok"));
        let me = Self { _pki: pki, _data: data, ca: r.join("ca.crt"), cfg, bin, pems, nodes, seq: 0 };
        let _ = me.wait_leader().await?;
        Ok(me)
    }

    pub async fn wait_leader(&self) -> Result<u64> {
        let dl = Instant::now() + Duration::from_secs(15);
        while Instant::now() < dl {
            for n in self.nodes.values() {
                if let Ok(m) = n.rpc(json!("Metrics")).await
                    && m.pointer("/Metrics/running_ok").and_then(Value::as_bool) == Some(true)
                    && let Some(lid) = m.pointer("/Metrics/current_leader").and_then(Value::as_u64)
                    && self.nodes.contains_key(&lid)
                    && self.nodes[&lid].rpc(json!("EnsureReadIndex")).await.is_ok_and(|v| v.get("ReadIndex").is_some())
                {
                    return Ok(lid);
                }
            }
            tokio::time::sleep(Duration::from_millis(60)).await;
        }
        bail!("leader timeout")
    }

    async fn kv_put(&self, key: &str, value: &str) -> Result<u64> {
        let p = serde_json::to_vec(&json!({ "Put": { "key": key, "value": value } }))?;
        let dl = Instant::now() + Duration::from_secs(20);
        let mut last = String::new();
        let mut hint = None;
        while Instant::now() < dl {
            let lid = match hint.take() {
                Some(id) if self.nodes.contains_key(&id) => id,
                _ => self.wait_leader().await?,
            };
            match self.nodes[&lid].rpc(json!({ "ClientWrite": { "payload": p.clone() } })).await {
                Ok(w) => {
                    if let Some(idx) = w.pointer("/ClientWrite/log_index").and_then(Value::as_u64) {
                        return Ok(idx);
                    }
                    if let Some(f) = w.pointer("/Error/forward_to_leader_id").and_then(Value::as_u64) {
                        hint = Some(f);
                    }
                    last = w.to_string();
                }
                Err(e) => last = e.to_string(),
            }
            tokio::time::sleep(Duration::from_millis(80)).await;
        }
        bail!("kv_put timeout {key}: {last}")
    }

    pub async fn append(
        &mut self,
        cmd: &RefCasCommand,
    ) -> Result<(u64, RefCasStateMachine, Option<Result<ApplyResponse, StateMachineError>>)> {
        let next = self.seq + 1;
        let idx = self.kv_put(&format!("pm/{next:08}"), &serde_json::to_string(cmd)?).await?;
        let _ = self.kv_put("pm/head", &next.to_string()).await?;
        self.seq = next;
        let (sm, last) = self.replay_sm().await?;
        Ok((idx, sm, last))
    }

    pub async fn replay_sm(&self) -> Result<(RefCasStateMachine, Option<Result<ApplyResponse, StateMachineError>>)> {
        let lid = self.wait_leader().await?;
        let node = &self.nodes[&lid];
        let _ = node.rpc(json!("EnsureReadIndex")).await?;
        let n: u64 = node
            .rpc(json!({ "KvGet": { "key": "pm/head" } }))
            .await?
            .pointer("/KvValue/value")
            .and_then(Value::as_str)
            .unwrap_or("0")
            .parse()?;
        let (mut sm, mut last) = (RefCasStateMachine::new(), None);
        for s in 1..=n {
            let r = node.rpc(json!({ "KvGet": { "key": format!("pm/{s:08}") } })).await?;
            let cmd: RefCasCommand =
                serde_json::from_str(r.pointer("/KvValue/value").and_then(Value::as_str).context("cmd")?)?;
            last = Some(sm.apply(AppliedLogId { term: 1, index: s }, cmd));
        }
        Ok((sm, last))
    }

    pub async fn restart_leader(&mut self) -> Result<()> {
        let lid = self.wait_leader().await?;
        let _ = self.nodes[&lid].rpc(json!("TriggerSnapshot")).await?;
        let dir = {
            let n = self.nodes.remove(&lid).context("lid")?;
            let d = n.dir.clone();
            drop(n);
            d
        };
        let (c, k) = self.pems[&lid].clone();
        self.nodes.insert(lid, MtlsNode::spawn(&self.bin, &self.ca, &c, &k, lid, dir, self.cfg.clone())?);
        let peers: BTreeMap<u64, String> = self.nodes.iter().map(|(&id, n)| (id, n.addr.clone())).collect();
        for n in self.nodes.values() {
            n.rpc(json!({ "UpdatePeers": { "peers": peers } })).await?;
        }
        let _ = self.wait_leader().await?;
        Ok(())
    }
}

pub struct LiveRaft3Backend(pub Arc<AsyncMutex<LiveRaft3>>);

impl MergeAuthorityBackend for LiveRaft3Backend {
    fn install_and_commit_scoped<'a>(
        &'a self,
        repo: Uuid,
        base_ref: &'a str,
        install: InstallScopedDecisionCommand,
        commit: CommitScopedRefsCommand,
    ) -> BackendFuture<'a, AuthorityCommitOutcome> {
        Box::pin(async move {
            let mut r = self.0.lock().await;
            let (i1, sm1, r1) = r
                .append(&RefCasCommand::InstallScopedDecision(install))
                .await
                .map_err(|e| RemoteMergeError::UnknownOutcome(e.to_string()))?;
            if let Some(Err(e)) = r1 {
                return Ok(map_sm_error_to_outcome(
                    Some(AppliedLogId { term: 1, index: i1 }),
                    e,
                    sm1.read_refs(repo).get(base_ref).cloned(),
                ));
            }
            let (i2, sm2, r2) = r
                .append(&RefCasCommand::CommitScopedRefs(commit))
                .await
                .map_err(|e| RemoteMergeError::UnknownOutcome(e.to_string()))?;
            match r2.context("res").map_err(|e| RemoteMergeError::UnknownOutcome(e.to_string()))? {
                Ok(ApplyResponse::RefsCommitted(rec)) => Ok(map_commit_receipt_to_outcome(
                    AppliedLogId { term: 1, index: i2 },
                    base_ref,
                    &rec.terminal,
                    rec.replayed,
                    sm2.read_refs(repo).get(base_ref).cloned(),
                )),
                Ok(o) => Err(RemoteMergeError::Equivocation(format!("unexpected {o:?}"))),
                Err(e) => Ok(map_sm_error_to_outcome(
                    Some(AppliedLogId { term: 1, index: i2 }),
                    e,
                    sm2.read_refs(repo).get(base_ref).cloned(),
                )),
            }
        })
    }

    fn query_operation_outcome<'a>(
        &'a self,
        repo: Uuid,
        op: Uuid,
        base_ref: &'a str,
    ) -> BackendFuture<'a, Option<AuthorityCommitOutcome>> {
        Box::pin(async move {
            let (sm, _) =
                self.0.lock().await.replay_sm().await.map_err(|e| RemoteMergeError::UnknownOutcome(e.to_string()))?;
            match sm.query_operation(repo, op).map_err(|e| RemoteMergeError::RemoteAuthzDenied(e.to_string()))? {
                OperationLookup::Unknown => Ok(None),
                OperationLookup::Known(rec)
                    if matches!(rec.state(), OperationState::Committed | OperationState::Rejected) =>
                {
                    let t: CommitTerminal = serde_json::from_value(rec.terminal_result().unwrap().value().clone())
                        .map_err(|e| RemoteMergeError::Equivocation(e.to_string()))?;
                    Ok(Some(map_commit_receipt_to_outcome(
                        AppliedLogId { term: 1, index: 1 },
                        base_ref,
                        &t,
                        true,
                        sm.read_refs(repo).get(base_ref).cloned(),
                    )))
                }
                _ => Ok(Some(AuthorityCommitOutcome::UnknownPending { reason: "pending".into() })),
            }
        })
    }

    fn read_ref_oid<'a>(&'a self, repo: Uuid, ref_name: &'a str) -> BackendFuture<'a, Option<String>> {
        Box::pin(async move {
            Ok(self
                .0
                .lock()
                .await
                .replay_sm()
                .await
                .map_err(|e| RemoteMergeError::UnknownOutcome(e.to_string()))?
                .0
                .read_refs(repo)
                .get(ref_name)
                .cloned())
        })
    }
}
