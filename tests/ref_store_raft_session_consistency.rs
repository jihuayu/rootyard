//! Multi-process mTLS Raft + real Axum HTTP + real PG17 + stock Git consistency
//! acceptance tests for Issue #175.
//!
//! Offline deterministic tests run unconditionally via `cargo test --test ref_store_raft_session_consistency`.
//! Full multi-process Raft (`crates/refcas-log` `raft-node`), Axum HTTP, PG17, and stock Git E2E tests
//! run explicitly via `cargo test --test ref_store_raft_session_consistency -- --ignored --test-threads=1`
//! with `ROOTYARD_TEST_DATABASE_URL` and `ROOTYARD_REFCAS_NODE_BIN` set.

use anyhow::{Context, Result, bail};
use async_compression::tokio::bufread::GzipDecoder;
use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use deadpool_postgres::{Manager, Pool};
use rootyard::db;
use rootyard::ref_store::core::state_machine::{
    AcquireHoldBatchCommand, AppliedLogId, CommitRefsCommand, CreateSnapshotPinCommand, InitializeGateCommand,
    MarkHoldConsumedCommand, RefCasCommand, RefCasStateMachine, RegisterRootCommand, ReleaseRootCommand,
    RepositoryLane, RetireHoldBatchCommand, SmHoldState, SmPackMode, SmRootState, WireCommitRefsRequest, WireGateInit,
    WireHoldArtifactSpec,
};
use rootyard::ref_store::projector::{
    AuthoritySourceKind, CallerAccessState, InMemorySmEventSource, ProjectionDependencyError,
    ProjectionDependencyTarget, ProjectionError, ProjectionRealm, RAFT_SESSION_HEADER, RaftProbeOutcome, RaftReadProof,
    RaftSessionCodec, RaftSessionLowerBound, RaftSessionRealm, SessionFenceError, apply_projection_step_atomically,
    apply_projection_stream_stop_on_gap, assert_authoritative_source, await_projected_event,
    await_raft_read_or_redirect, derive_operation_event_id, verify_projected_operation_non_authorizing,
};
use rootyard::ref_store::{
    CommitMode, CommitRefsRequest, CoreGateInit, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, MetadataPinPurpose,
    RefName, RefPrecondition, RefTarget, RefUpdate, RequestDigest,
};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Cursor, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock, mpsc};
use std::time::{Duration, Instant};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RaftRepoStateValue {
    realm: RaftSessionRealm,
    repo_ref_version: i64,
    refs: BTreeMap<String, String>,
    committed_op_id: Uuid,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InfoRefsQuery {
    service: String,
}

fn make_realm(
    group_id: i64,
    history: Uuid,
    authority: Uuid,
    cluster: Uuid,
    tenant: Uuid,
    repo: Uuid,
) -> RaftSessionRealm {
    RaftSessionRealm {
        group_id,
        group_epoch: 1,
        history_incarnation: history,
        authority_id: authority,
        authority_epoch: 1,
        cluster_incarnation: cluster,
        tenant_id: tenant,
        repository_id: repo,
        object_format: GitObjectFormat::Sha256,
    }
}

fn test_codec() -> RaftSessionCodec {
    RaftSessionCodec::new([(1u8, Zeroizing::new([0x33u8; 32])), (2u8, Zeroizing::new([0x44u8; 32]))], 2, 180)
        .expect("build test codec")
}

#[test]
fn unit_cross_group_and_term_never_satisfy_lower_bound_and_fallback_rejected() {
    let g1 = make_realm(
        1,
        Uuid::from_u128(10),
        Uuid::from_u128(20),
        Uuid::from_u128(30),
        Uuid::from_u128(40),
        Uuid::from_u128(50),
    );
    let g2 = make_realm(
        2,
        Uuid::from_u128(10),
        Uuid::from_u128(20),
        Uuid::from_u128(30),
        Uuid::from_u128(40),
        Uuid::from_u128(50),
    );
    let bound = RaftSessionLowerBound {
        realm: g1.clone(),
        raft_log_index: 5,
        repo_ref_version: 2,
        key_id: 2,
        issued_unix: 1_700_000_000,
        lifetime_seconds: 180,
    };
    assert_eq!(bound.satisfies(100, 100, 50, &g2), Err(SessionFenceError::RealmMismatch));
    assert_eq!(bound.satisfies(4, 4, 2, &g1).unwrap_err().status_code(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(matches!(
        assert_authoritative_source(AuthoritySourceKind::PgRefsProjection),
        Err(SessionFenceError::AuthorityViolation(_))
    ));
    assert!(matches!(
        assert_authoritative_source(AuthoritySourceKind::RedisCache),
        Err(SessionFenceError::AuthorityViolation(_))
    ));
}

struct OwnedChild(Option<Child>);

impl OwnedChild {
    fn take(&mut self) -> Option<Child> {
        self.0.take()
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = reap_bounded(&mut child, Duration::from_secs(5));
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

struct MtlsClusterPki {
    _dir: tempfile::TempDir,
    ca_cert: PathBuf,
    client_cfg: Arc<ClientConfig>,
    node_paths: BTreeMap<u64, (PathBuf, PathBuf)>,
}

impl MtlsClusterPki {
    fn create(node_ids: &[u64]) -> Result<Self> {
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
                "/CN=refcas-test-ca",
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
        let key =
            rustls_pemfile::private_key(&mut BufReader::new(File::open(&cli_key)?))?.context("client key missing")?;
        let cfg = ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_client_auth_cert(certs, key)?;
        Ok(Self { _dir: dir, ca_cert, client_cfg: Arc::new(cfg), node_paths })
    }
}

struct RaftNodeProc {
    id: u64,
    addr: String,
    _dir: tempfile::TempDir,
    client_cfg: Arc<ClientConfig>,
    child: OwnedChild,
}

impl RaftNodeProc {
    fn spawn(bin: &Path, pki: &MtlsClusterPki, id: u64) -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let (cert, key) = pki.node_paths.get(&id).context("missing node cert")?;
        let spawned = Command::new(bin)
            .args([
                "--id",
                &id.to_string(),
                "--dir",
                &dir.path().to_string_lossy(),
                "--tls-ca",
                &pki.ca_cert.to_string_lossy(),
                "--tls-cert",
                &cert.to_string_lossy(),
                "--tls-key",
                &key.to_string_lossy(),
                "--check-on-open",
                "true",
                "--heartbeat-ms",
                "60",
                "--election-min-ms",
                "200",
                "--election-max-ms",
                "380",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("spawn raft-node {id}"))?;
        let mut child = OwnedChild(Some(spawned));
        let stdout = child.0.as_mut().context("child missing")?.stdout.take().context("stdout missing")?;
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
        Ok(Self { id, addr, _dir: dir, client_cfg: pki.client_cfg.clone(), child })
    }

    async fn rpc(&self, req: Value) -> Result<Value> {
        let addr = self.addr.clone();
        let cfg = self.client_cfg.clone();
        let dns = format!("raft-node-{}.refcas.internal", self.id);
        tokio::task::spawn_blocking(move || rpc_sync(&cfg, &addr, &dns, &req)).await.context("rpc join")?
    }

    async fn shutdown(mut self) {
        let _ = self.rpc(json!("Shutdown")).await;
        if let Some(mut c) = self.child.take() {
            let _ = reap_bounded(&mut c, Duration::from_secs(5));
        }
    }
}

fn rpc_sync(cfg: &Arc<ClientConfig>, addr: &str, dns: &str, req: &Value) -> Result<Value> {
    let tcp = TcpStream::connect(addr)?;
    tcp.set_read_timeout(Some(Duration::from_secs(5)))?;
    tcp.set_write_timeout(Some(Duration::from_secs(5)))?;
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
    let _ = tls.conn.send_close_notify();
    let _ = tls.flush();
    Ok(serde_json::from_slice(&body)?)
}

fn raft_node_bin() -> PathBuf {
    let path = std::env::var("ROOTYARD_REFCAS_NODE_BIN")
        .unwrap_or_else(|_| "crates/refcas-log/target/debug/raft-node".to_owned());
    let pb = PathBuf::from(&path);
    assert!(pb.is_file(), "raft-node binary missing at {}; build crates/refcas-log first", pb.display());
    pb
}

fn test_database_url() -> String {
    std::env::var("ROOTYARD_TEST_DATABASE_URL")
        .expect("ROOTYARD_TEST_DATABASE_URL must be set for ignored ref_store_raft_session_consistency tests")
}

async fn setup_pg_schema() -> Result<(Pool, Pool, String, Uuid, Uuid)> {
    let url = test_database_url();
    let admin = db::pool(&url)?;
    let schema = format!("raft_sess175_{}", Uuid::new_v4().simple());
    admin.get().await?.batch_execute(&format!("CREATE SCHEMA {schema}")).await?;
    let mut config: tokio_postgres::Config = url.parse()?;
    config.options(format!("-c search_path={schema} -c timezone=UTC -c statement_timeout=15000 -c lock_timeout=10000"));
    let pool = Pool::builder(Manager::new(config, tokio_postgres::NoTls))
        .runtime(deadpool_postgres::Runtime::Tokio1)
        .max_size(10)
        .build()?;
    db::migrate(&pool).await?;
    let tenant = Uuid::new_v4();
    let repo = Uuid::new_v4();
    let user_slug = format!("s175_{}", &tenant.simple().to_string()[..10]);
    let client = pool.get().await?;
    client.execute("INSERT INTO users(id,username) VALUES($1,$2)", &[&tenant, &user_slug]).await?;
    client
        .execute(
            "INSERT INTO repositories(id,owner_id,name,state,object_format) VALUES($1,$2,'raft-demo','ready','sha256')",
            &[&repo, &tenant],
        )
        .await?;
    Ok((admin, pool, schema, tenant, repo))
}

async fn teardown_pg_schema(admin: &Pool, schema: &str) {
    if let Ok(c) = admin.get().await {
        let _ = c.batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE")).await;
    }
}

async fn wait_cluster_leader(nodes: &[&RaftNodeProc], excluded: Option<u64>) -> Result<u64> {
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        for n in nodes {
            if excluded == Some(n.id) {
                continue;
            }
            if let Ok(resp) = n.rpc(json!("Metrics")).await
                && let Some(m) = resp.get("Metrics")
                && m["running_ok"].as_bool() == Some(true)
                && let Some(lid) = m["current_leader"].as_u64()
                && excluded != Some(lid)
                && nodes.iter().any(|p| p.id == lid)
            {
                return Ok(lid);
            }
        }
        if Instant::now() >= deadline {
            bail!("timed out waiting for raft cluster leader (excluded={excluded:?})");
        }
        tokio::time::sleep(Duration::from_millis(60)).await;
    }
}

async fn wait_nodes_converged(nodes: &[&RaftNodeProc], target_idx: u64) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        let mut all_ok = true;
        for n in nodes {
            let Ok(resp) = n.rpc(json!("Metrics")).await else {
                all_ok = false;
                break;
            };
            let idx = resp.pointer("/Metrics/last_applied/index").and_then(Value::as_u64).unwrap_or(0);
            if idx < target_idx {
                all_ok = false;
                break;
            }
        }
        if all_ok {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("timed out waiting for raft nodes to apply log_index {target_idx}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn commit_state_to_raft(nodes: &[&RaftNodeProc], key: &str, state: &RaftRepoStateValue) -> Result<(u64, u64)> {
    let leader_id = wait_cluster_leader(nodes, None).await?;
    let leader = nodes.iter().find(|n| n.id == leader_id).context("leader missing")?;
    let value = serde_json::to_string(state)?;
    let cmd = json!({ "Put": { "key": key, "value": value } });
    let payload = serde_json::to_vec(&cmd)?;
    let resp = leader.rpc(json!({ "ClientWrite": { "payload": payload } })).await?;
    if let Some(idx) = resp.pointer("/ClientWrite/log_index").and_then(Value::as_u64) {
        return Ok((leader_id, idx));
    }
    bail!("ClientWrite rejected on leader {leader_id}: {resp}");
}

struct GatewayState {
    nodes: RwLock<BTreeMap<u64, Arc<RaftNodeProc>>>,
    codec: RaftSessionCodec,
    realm: RwLock<RaftSessionRealm>,
    repo_key: String,
    authenticated: AtomicBool,
    has_read_permission: AtomicBool,
    pin_closure_intact: AtomicBool,
    force_pg_fallback: AtomicBool,
    bare_git_repo: RwLock<Option<PathBuf>>,
    wait_budget_ms: RwLock<u64>,
}

async fn probe_raft_node(
    st: &GatewayState,
    preferred_node_id: u64,
    override_leader: Option<u64>,
) -> Result<RaftProbeOutcome, SessionFenceError> {
    if st.force_pg_fallback.load(Ordering::SeqCst) {
        assert_authoritative_source(AuthoritySourceKind::PgRefsProjection)?;
    }
    let node_id = override_leader.unwrap_or(preferred_node_id);
    let node = {
        let guard = st.nodes.read().map_err(|_| SessionFenceError::Internal("lock poisoned"))?;
        guard.get(&node_id).cloned()
    }
    .ok_or_else(|| SessionFenceError::QuorumUnavailable(format!("node {node_id} unavailable")))?;

    let kv_resp = node
        .rpc(json!({ "KvGet": { "key": st.repo_key } }))
        .await
        .map_err(|e| SessionFenceError::QuorumUnavailable(format!("rpc error to node {node_id}: {e}")))?;

    if let Some(err) = kv_resp.get("Error") {
        if let Some(fwd) = err["forward_to_leader_id"].as_u64() {
            return Ok(RaftProbeOutcome::ForwardToLeader(fwd));
        }
        let msg = err["message"].as_str().unwrap_or("quorum unavailable").to_owned();
        return Ok(RaftProbeOutcome::QuorumUnavailable(msg));
    }

    let read_log_idx = kv_resp.pointer("/KvValue/read_log_id/index").and_then(Value::as_u64).unwrap_or(0);
    let raw_val = kv_resp
        .pointer("/KvValue/value")
        .and_then(Value::as_str)
        .ok_or_else(|| SessionFenceError::QuorumUnavailable("empty repo state in Raft ReadIndex".into()))?;
    let parsed: RaftRepoStateValue =
        serde_json::from_str(raw_val).map_err(|_| SessionFenceError::Internal("decode state value"))?;

    let metrics = node
        .rpc(json!("Metrics"))
        .await
        .map_err(|e| SessionFenceError::QuorumUnavailable(format!("metrics error: {e}")))?;
    let last_applied = metrics.pointer("/Metrics/last_applied/index").and_then(Value::as_u64).unwrap_or(0);
    let state_digest_hex =
        metrics.pointer("/Metrics/sm_summary/state_digest_hex").and_then(Value::as_str).unwrap_or("").to_owned();
    let live_realm = st.realm.read().map_err(|_| SessionFenceError::Internal("realm lock"))?.clone();
    if parsed.realm != live_realm || parsed.committed_op_id.is_nil() || parsed.refs.is_empty() {
        return Err(SessionFenceError::RealmMismatch);
    }
    Ok(RaftProbeOutcome::Ready(RaftReadProof {
        source: AuthoritySourceKind::RaftReadIndexQuorum,
        realm: live_realm,
        leader_id: Some(node_id),
        committed_log_index: read_log_idx,
        last_applied_log_index: last_applied.max(read_log_idx),
        repo_ref_version: parsed.repo_ref_version,
        state_digest_hex,
        pin_closure_intact: st.pin_closure_intact.load(Ordering::SeqCst),
    }))
}

fn error_response(err: SessionFenceError) -> Response {
    (err.status_code(), err.to_string()).into_response()
}

async fn http_read_refs(
    State(st): State<Arc<GatewayState>>,
    AxumPath(node_id): AxumPath<u64>,
    headers: HeaderMap,
) -> Response {
    let presented = match RaftSessionCodec::extract_header(&headers) {
        Ok(v) => v.map(str::to_owned),
        Err(e) => return error_response(e),
    };
    let access = CallerAccessState {
        authenticated: st.authenticated.load(Ordering::SeqCst),
        has_read_permission: st.has_read_permission.load(Ordering::SeqCst),
    };
    let budget = Duration::from_millis(*st.wait_budget_ms.read().unwrap());
    let res = await_raft_read_or_redirect(
        access,
        &st.codec,
        presented.as_deref(),
        budget,
        Duration::from_millis(25),
        3,
        |leader| {
            let st_ref = st.clone();
            async move { probe_raft_node(&st_ref, node_id, leader).await }
        },
    )
    .await;

    match res {
        Ok(admitted) => {
            let mut resp = (StatusCode::OK, axum::Json(admitted.clone())).into_response();
            resp.headers_mut().insert(
                HeaderName::from_static(RAFT_SESSION_HEADER),
                HeaderValue::from_str(&admitted.session_token).expect("valid token header"),
            );
            resp
        }
        Err(err) => error_response(err),
    }
}

async fn http_git_info_refs(
    State(st): State<Arc<GatewayState>>,
    AxumPath(node_id): AxumPath<u64>,
    Query(q): Query<InfoRefsQuery>,
    headers: HeaderMap,
) -> Response {
    if q.service != "git-upload-pack" {
        return (StatusCode::FORBIDDEN, "unsupported service").into_response();
    }
    let presented = match RaftSessionCodec::extract_header(&headers) {
        Ok(v) => v.map(str::to_owned),
        Err(e) => return error_response(e),
    };
    let access = CallerAccessState {
        authenticated: st.authenticated.load(Ordering::SeqCst),
        has_read_permission: st.has_read_permission.load(Ordering::SeqCst),
    };
    let admitted = match await_raft_read_or_redirect(
        access,
        &st.codec,
        presented.as_deref(),
        Duration::from_millis(500),
        Duration::from_millis(25),
        3,
        |leader| {
            let st_ref = st.clone();
            async move { probe_raft_node(&st_ref, node_id, leader).await }
        },
    )
    .await
    {
        Ok(ok) => ok,
        Err(e) => return error_response(e),
    };
    let repo_path = st.bare_git_repo.read().unwrap().clone().expect("bare repo configured");
    let output = Command::new("git")
        .args(["upload-pack", "--stateless-rpc", "--advertise-refs"])
        .arg(&repo_path)
        .output()
        .expect("run git upload-pack --advertise-refs");
    assert!(output.status.success(), "git advertise-refs failed");
    let header_line = b"# service=git-upload-pack\n";
    let pkt_header = format!("{:04x}", header_line.len() + 4);
    let mut body = Vec::new();
    body.extend_from_slice(pkt_header.as_bytes());
    body.extend_from_slice(header_line);
    body.extend_from_slice(b"0000");
    body.extend_from_slice(&output.stdout);
    let mut resp = (StatusCode::OK, body).into_response();
    resp.headers_mut().insert("content-type", HeaderValue::from_static("application/x-git-upload-pack-advertisement"));
    resp.headers_mut().insert(
        HeaderName::from_static(RAFT_SESSION_HEADER),
        HeaderValue::from_str(&admitted.session_token).expect("valid token header"),
    );
    resp
}

async fn http_git_upload_pack(
    State(st): State<Arc<GatewayState>>,
    AxumPath(node_id): AxumPath<u64>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let presented = match RaftSessionCodec::extract_header(&headers) {
        Ok(v) => v.map(str::to_owned),
        Err(e) => return error_response(e),
    };
    let access = CallerAccessState {
        authenticated: st.authenticated.load(Ordering::SeqCst),
        has_read_permission: st.has_read_permission.load(Ordering::SeqCst),
    };
    let admitted = match await_raft_read_or_redirect(
        access,
        &st.codec,
        presented.as_deref(),
        Duration::from_millis(500),
        Duration::from_millis(25),
        3,
        |leader| {
            let st_ref = st.clone();
            async move { probe_raft_node(&st_ref, node_id, leader).await }
        },
    )
    .await
    {
        Ok(ok) => ok,
        Err(e) => return error_response(e),
    };
    let raw_req = if headers.get("content-encoding").and_then(|v| v.to_str().ok()) == Some("gzip") {
        let mut dec = GzipDecoder::new(Cursor::new(body));
        let mut out = Vec::new();
        dec.read_to_end(&mut out).await.expect("decode gzip upload-pack");
        out
    } else {
        body.to_vec()
    };
    let repo_path = st.bare_git_repo.read().unwrap().clone().expect("bare repo");
    let mut child = Command::new("git")
        .args(["upload-pack", "--stateless-rpc"])
        .arg(&repo_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn git upload-pack");
    child.stdin.take().unwrap().write_all(&raw_req).expect("write upload-pack stdin");
    let out = child.wait_with_output().expect("wait git upload-pack");
    assert!(out.status.success(), "git upload-pack failed");
    let mut resp = (StatusCode::OK, out.stdout).into_response();
    resp.headers_mut().insert("content-type", HeaderValue::from_static("application/x-git-upload-pack-result"));
    resp.headers_mut().insert(
        HeaderName::from_static(RAFT_SESSION_HEADER),
        HeaderValue::from_str(&admitted.session_token).expect("valid token header"),
    );
    resp
}

async fn bootstrap_three_nodes(
    bin: &Path,
) -> Result<(MtlsClusterPki, Arc<RaftNodeProc>, Arc<RaftNodeProc>, Arc<RaftNodeProc>)> {
    let pki = MtlsClusterPki::create(&[1, 2, 3])?;
    let n1 = Arc::new(RaftNodeProc::spawn(bin, &pki, 1)?);
    let n2 = Arc::new(RaftNodeProc::spawn(bin, &pki, 2)?);
    let n3 = Arc::new(RaftNodeProc::spawn(bin, &pki, 3)?);
    let members = BTreeMap::from([(1u64, n1.addr.clone()), (2u64, n2.addr.clone()), (3u64, n3.addr.clone())]);
    for n in [&n1, &n2, &n3] {
        assert_eq!(n.rpc(json!({ "UpdatePeers": { "peers": members } })).await?, json!("Ok"));
    }
    assert_eq!(n1.rpc(json!({ "Bootstrap": { "members": members } })).await?, json!("Ok"));
    Ok((pki, n1, n2, n3))
}

async fn start_gateway_server(st: Arc<GatewayState>) -> Result<String> {
    let app = Router::new()
        .route("/api/raft/nodes/{node_id}/refs", get(http_read_refs))
        .route("/git/nodes/{node_id}/repo.git/info/refs", get(http_git_info_refs))
        .route("/git/nodes/{node_id}/repo.git/git-upload-pack", post(http_git_upload_pack))
        .with_state(st);
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?.to_string();
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok(format!("http://{addr}"))
}

#[tokio::test]
#[ignore = "requires multi-process raft-node binary, openssl, and PostgreSQL 17"]
async fn real_raft_cluster_http_read_your_writes_monotonic_failover_lag_and_quorum_loss() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup_pg_schema().await?;
    let bin = raft_node_bin();
    let (_pki, n1, n2, n3) = bootstrap_three_nodes(&bin).await?;
    let all = [n1.as_ref(), n2.as_ref(), n3.as_ref()];
    let leader_id = wait_cluster_leader(&all, None).await?;
    let follower_id = [1u64, 2, 3].into_iter().find(|&id| id != leader_id).unwrap();

    let history = Uuid::new_v4();
    let realm = make_realm(11, history, Uuid::new_v4(), Uuid::new_v4(), tenant, repo);
    let st = Arc::new(GatewayState {
        nodes: RwLock::new(BTreeMap::from([(1, n1.clone()), (2, n2.clone()), (3, n3.clone())])),
        codec: test_codec(),
        realm: RwLock::new(realm.clone()),
        repo_key: format!("repo:{}", realm.repository_id),
        authenticated: AtomicBool::new(true),
        has_read_permission: AtomicBool::new(true),
        pin_closure_intact: AtomicBool::new(true),
        force_pg_fallback: AtomicBool::new(false),
        bare_git_repo: RwLock::new(None),
        wait_budget_ms: RwLock::new(400),
    });
    let base_url = start_gateway_server(st.clone()).await?;
    let http = reqwest::Client::new();

    // Commit #1 into 3-node mTLS Raft cluster AND project only rev=1 to PostgreSQL refs.
    let op1 = Uuid::new_v4();
    let v1 = RaftRepoStateValue {
        realm: realm.clone(),
        repo_ref_version: 2,
        refs: BTreeMap::from([("refs/heads/main".into(), "11".repeat(32))]),
        committed_op_id: op1,
    };
    let (_, idx1) = commit_state_to_raft(&all, &st.repo_key, &v1).await?;
    wait_nodes_converged(&all, idx1).await?;
    let mut sm_pg = RefCasStateMachine::new();
    let init =
        CoreGateInit::new(repo, tenant, GitObjectFormat::Sha256, history, 1, 1, RefName::branch("refs/heads/main")?)?;
    sm_pg.apply(
        AppliedLogId { term: 1, index: 1 },
        RefCasCommand::InitializeGate(InitializeGateCommand {
            gate: WireGateInit::from(&init),
            pack_mode: SmPackMode::MetadataOnly,
            lane: RepositoryLane::ServingRefStore,
            authz_floor: 1,
        }),
    )?;
    let req1 = CommitRefsRequest::new(
        repo,
        tenant,
        tenant,
        IssuerLane::new("s175-pg-stale")?,
        1,
        op1,
        GitObjectFormat::Sha256,
        history,
        1,
        1,
        1,
        HeadUpdate::Keep,
        CommitMode::Atomic,
        vec![RefUpdate::new(
            RefName::branch("refs/heads/main")?,
            RefPrecondition::Absent,
            RefTarget::Oid(GitOid::Sha256([0x11; 32])),
        )],
    )?;
    sm_pg.apply(
        AppliedLogId { term: 1, index: 2 },
        RefCasCommand::CommitRefs(CommitRefsCommand {
            request: WireCommitRefsRequest::from(&req1),
            decision_id: None,
            required_holds: vec![],
            policy_rejects: BTreeMap::new(),
            logical_tick: 101,
        }),
    )?;
    let src_pg = InMemorySmEventSource::from_state_machine(
        &sm_pg,
        ProjectionRealm::new(history, 11, 1)?,
        Some(tenant),
        Some(tenant),
        None,
    )?;
    apply_projection_step_atomically(&pool, &src_pg.events[0], None, false).await?;

    // 1. Read-Your-Writes from leader yields 200 + rrs1. token.
    let r_leader = http.get(format!("{base_url}/api/raft/nodes/{leader_id}/refs")).send().await?;
    assert_eq!(r_leader.status(), 200);
    let tok1 = r_leader.headers().get(RAFT_SESSION_HEADER).unwrap().to_str()?.to_owned();
    assert!(tok1.starts_with("rrs1."));

    // 2. Cross-replica monotonic read hitting follower redirects via ReadIndex to leader -> 200.
    let r_follower = http
        .get(format!("{base_url}/api/raft/nodes/{follower_id}/refs"))
        .header(RAFT_SESSION_HEADER, &tok1)
        .send()
        .await?;
    assert_eq!(r_follower.status(), 200);
    let body_f: Value = r_follower.json().await?;
    assert!(body_f["committed_log_index"].as_u64().unwrap() >= idx1);
    assert_eq!(body_f["repo_ref_version"].as_i64(), Some(2));

    // 3. Prohibits falling back to PG projection / Redis even when configured or behind.
    st.force_pg_fallback.store(true, Ordering::SeqCst);
    let r_pg_fb = http.get(format!("{base_url}/api/raft/nodes/{leader_id}/refs")).send().await?;
    assert_eq!(r_pg_fb.status(), 503);
    st.force_pg_fallback.store(false, Ordering::SeqCst);

    // 4. Lagged replica behind client's bound fails closed with 503 (never silent stale read).
    *st.wait_budget_ms.write().unwrap() = 80;
    let ahead_tok =
        st.codec.mint_token(&realm, idx1 + 50, 99, rootyard::ref_store::projector::current_unix_seconds())?;
    let r_behind = http
        .get(format!("{base_url}/api/raft/nodes/{leader_id}/refs"))
        .header(RAFT_SESSION_HEADER, &ahead_tok)
        .send()
        .await?;
    assert_eq!(r_behind.status(), 503);
    *st.wait_budget_ms.write().unwrap() = 400;

    // 5. Partition old leader into minority; surviving 2 voters elect new leader and commit rev=2.
    let old_leader = all.iter().copied().find(|n| n.id == leader_id).unwrap();
    let majority: Vec<&RaftNodeProc> = all.iter().copied().filter(|n| n.id != leader_id).collect();
    let follower_set: BTreeSet<u64> = majority.iter().map(|n| n.id).collect();
    old_leader.rpc(json!({ "PartitionPeers": { "blocked": follower_set } })).await?;
    for p in &majority {
        p.rpc(json!({ "PartitionPeers": { "blocked": [leader_id] } })).await?;
    }
    let stale_old_leader = http
        .get(format!("{base_url}/api/raft/nodes/{leader_id}/refs"))
        .header(RAFT_SESSION_HEADER, &tok1)
        .send()
        .await?;
    assert_eq!(stale_old_leader.status(), 503, "minority partitioned old leader MUST refuse ReadIndex");

    let new_leader_id = wait_cluster_leader(&majority, Some(leader_id)).await?;
    let v2 = RaftRepoStateValue {
        realm: realm.clone(),
        repo_ref_version: 3,
        refs: BTreeMap::from([("refs/heads/main".into(), "22".repeat(32))]),
        committed_op_id: Uuid::new_v4(),
    };
    let (_, idx2) = commit_state_to_raft(&majority, &st.repo_key, &v2).await?;
    wait_nodes_converged(&majority, idx2).await?;

    let r_failover = http
        .get(format!("{base_url}/api/raft/nodes/{new_leader_id}/refs"))
        .header(RAFT_SESSION_HEADER, &tok1)
        .send()
        .await?;
    assert_eq!(r_failover.status(), 200);
    let f_json: Value = r_failover.json().await?;
    assert_eq!(f_json["repo_ref_version"].as_i64(), Some(3));
    let pg_rev: i64 = pool
        .get()
        .await?
        .query_one("SELECT revision FROM ref_cas_projected_refs WHERE repository_id=$1", &[&repo])
        .await?
        .get(0);
    assert_eq!(pg_rev, 2, "PG refs projection stays stale at rev=2 while Raft ReadIndex served rev=3");

    // 6. Total quorum loss: remove 2 voters -> surviving node MUST fail closed 503.
    let survivor_id = majority[0].id;
    let to_stop: Vec<u64> = [1u64, 2, 3].into_iter().filter(|&id| id != survivor_id).collect();
    for sid in to_stop {
        let proc_arc = st.nodes.write().unwrap().remove(&sid).unwrap();
        if let Ok(owned) = Arc::try_unwrap(proc_arc) {
            owned.shutdown().await;
        }
    }
    let r_quorum_lost = http
        .get(format!("{base_url}/api/raft/nodes/{survivor_id}/refs"))
        .header(RAFT_SESSION_HEADER, &tok1)
        .send()
        .await?;
    assert_eq!(r_quorum_lost.status(), 503);

    if let Some(last) = st.nodes.write().unwrap().remove(&survivor_id)
        && let Ok(owned) = Arc::try_unwrap(last)
    {
        owned.shutdown().await;
    }
    teardown_pg_schema(&admin, &schema).await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires multi-process raft-node binary and openssl"]
async fn real_http_rejects_rotated_history_authority_restore_forged_token_and_revoked_perms() -> Result<()> {
    let bin = raft_node_bin();
    let (_pki, n1, n2, n3) = bootstrap_three_nodes(&bin).await?;
    let all = [n1.as_ref(), n2.as_ref(), n3.as_ref()];
    let leader_id = wait_cluster_leader(&all, None).await?;
    let realm1 = make_realm(21, Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let st = Arc::new(GatewayState {
        nodes: RwLock::new(BTreeMap::from([(1, n1.clone()), (2, n2.clone()), (3, n3.clone())])),
        codec: test_codec(),
        realm: RwLock::new(realm1.clone()),
        repo_key: format!("repo:{}", realm1.repository_id),
        authenticated: AtomicBool::new(true),
        has_read_permission: AtomicBool::new(true),
        pin_closure_intact: AtomicBool::new(true),
        force_pg_fallback: AtomicBool::new(false),
        bare_git_repo: RwLock::new(None),
        wait_budget_ms: RwLock::new(300),
    });
    let base_url = start_gateway_server(st.clone()).await?;
    let http = reqwest::Client::new();

    let v1 = RaftRepoStateValue {
        realm: realm1.clone(),
        repo_ref_version: 1,
        refs: BTreeMap::from([("refs/heads/main".into(), "33".repeat(32))]),
        committed_op_id: Uuid::new_v4(),
    };
    let (_, idx1) = commit_state_to_raft(&all, &st.repo_key, &v1).await?;
    wait_nodes_converged(&all, idx1).await?;
    let r1 = http.get(format!("{base_url}/api/raft/nodes/{leader_id}/refs")).send().await?;
    assert_eq!(r1.status(), 200);
    let old_tok = r1.headers().get(RAFT_SESSION_HEADER).unwrap().to_str()?.to_owned();

    // Rotate history_incarnation & cluster_incarnation (e.g. restore/reset) with higher log_index & rev=99.
    let mut rotated = realm1.clone();
    rotated.history_incarnation = Uuid::new_v4();
    rotated.cluster_incarnation = Uuid::new_v4();
    *st.realm.write().unwrap() = rotated.clone();
    let v_rot = RaftRepoStateValue {
        realm: rotated.clone(),
        repo_ref_version: 99,
        refs: BTreeMap::from([("refs/heads/main".into(), "44".repeat(32))]),
        committed_op_id: Uuid::new_v4(),
    };
    let (_, idx2) = commit_state_to_raft(&all, &st.repo_key, &v_rot).await?;
    wait_nodes_converged(&all, idx2).await?;

    let r_rot = http
        .get(format!("{base_url}/api/raft/nodes/{leader_id}/refs"))
        .header(RAFT_SESSION_HEADER, &old_tok)
        .send()
        .await?;
    assert_eq!(r_rot.status(), 409, "old token MUST NOT validate against rotated history/incarnation");

    // Forged / tampered token fails closed 401.
    let mut bad = old_tok.clone().into_bytes();
    let end = bad.len() - 1;
    bad[end] = if bad[end] == b'x' { b'y' } else { b'x' };
    let r_forged = http
        .get(format!("{base_url}/api/raft/nodes/{leader_id}/refs"))
        .header(RAFT_SESSION_HEADER, String::from_utf8(bad)?)
        .send()
        .await?;
    assert_eq!(r_forged.status(), 401);

    // Revoked live repository permission fails 403 BEFORE version/token issuance.
    st.has_read_permission.store(false, Ordering::SeqCst);
    let r_revoked = http.get(format!("{base_url}/api/raft/nodes/{leader_id}/refs")).send().await?;
    assert_eq!(r_revoked.status(), 403);
    assert!(r_revoked.headers().get(RAFT_SESSION_HEADER).is_none());

    st.has_read_permission.store(true, Ordering::SeqCst);
    st.authenticated.store(false, Ordering::SeqCst);
    let r_unauth = http.get(format!("{base_url}/api/raft/nodes/{leader_id}/refs")).send().await?;
    assert_eq!(r_unauth.status(), 401);

    for sid in [1u64, 2, 3] {
        if let Some(p) = st.nodes.write().unwrap().remove(&sid)
            && let Ok(owned) = Arc::try_unwrap(p)
        {
            owned.shutdown().await;
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires PostgreSQL 17 with Migration 149"]
async fn real_pg17_projection_dependency_atomicity_duplicates_gap_abort_and_timeout() -> Result<()> {
    let (admin, pool, schema, tenant, repo) = setup_pg_schema().await?;
    let history = Uuid::from_u128(0xABCD_EF01);
    let realm = ProjectionRealm::new(history, 42, 1)?;
    let issuer = Uuid::new_v4();
    let lane = IssuerLane::new("s175-pg-dep")?;

    let mut sm = RefCasStateMachine::new();
    let init =
        CoreGateInit::new(repo, tenant, GitObjectFormat::Sha256, history, 1, 1, RefName::branch("refs/heads/main")?)?;
    sm.apply(
        AppliedLogId { term: 1, index: 1 },
        RefCasCommand::InitializeGate(InitializeGateCommand {
            gate: WireGateInit::from(&init),
            pack_mode: SmPackMode::MetadataOnly,
            lane: RepositoryLane::ServingRefStore,
            authz_floor: 1,
        }),
    )?;

    let mut op_ids = Vec::new();
    for seq in 1..=3i64 {
        let op_id = Uuid::new_v4();
        op_ids.push(op_id);
        let req = CommitRefsRequest::new(
            repo,
            tenant,
            issuer,
            lane.clone(),
            seq,
            op_id,
            GitObjectFormat::Sha256,
            history,
            1,
            1,
            seq,
            HeadUpdate::Keep,
            CommitMode::Atomic,
            vec![RefUpdate::new(
                RefName::branch(&format!("refs/heads/b{seq}"))?,
                RefPrecondition::Absent,
                RefTarget::Oid(GitOid::Sha256([seq as u8; 32])),
            )],
        )?;
        sm.apply(
            AppliedLogId { term: 1, index: (seq as u64) + 1 },
            RefCasCommand::CommitRefs(CommitRefsCommand {
                request: WireCommitRefsRequest::from(&req),
                decision_id: None,
                required_holds: vec![],
                policy_rejects: BTreeMap::new(),
                logical_tick: 100 + seq as u64,
            }),
        )?;
    }

    let src = InMemorySmEventSource::from_state_machine(&sm, realm, Some(tenant), Some(issuer), None)?;
    assert_eq!(src.events.len(), 3);

    // 1. Project seq=1 atomically, then replay duplicate -> no-op.
    apply_projection_step_atomically(&pool, &src.events[0], None, false).await?;
    let dup = apply_projection_step_atomically(&pool, &src.events[0], None, false).await?;
    assert!(matches!(dup, rootyard::ref_store::projector::SingleEventOutcome::DuplicateSkipped { .. }));

    // 2. Simulated pre-commit TX rollback on seq=2 leaves zero partial rows & cursor=1.
    assert!(apply_projection_step_atomically(&pool, &src.events[1], None, true).await.is_err());
    let c1 =
        rootyard::ref_store::projector::load_cursor(&**pool.get().await?, realm.group_id, realm.history_incarnation)
            .await?
            .unwrap();
    assert_eq!(c1.applied_event_seq, 1);

    // 3. Out-of-order seq=3 stops with SequenceGap and does NOT advance cursor or commit seq=3 ref.
    let (done_before_gap, gap_err) = apply_projection_stream_stop_on_gap(&pool, &[src.events[2].clone()], None).await?;
    assert!(done_before_gap.is_empty());
    assert!(matches!(gap_err, Some((0, ProjectionError::SequenceGap { expected_min_event_seq: 2, got_event_seq: 3 }))));
    let refs_count: i64 = pool
        .get()
        .await?
        .query_one("SELECT COUNT(*) FROM ref_cas_projected_refs WHERE repository_id=$1", &[&repo])
        .await?
        .get(0);
    assert_eq!(refs_count, 1);

    // 4. Waiting for seq=3 while stuck at cursor=1 returns explicit Timeout.
    let op3_event_id = derive_operation_event_id(&realm, src.events[2].log_index, op_ids[2], repo)?;
    let target3 = ProjectionDependencyTarget {
        realm,
        min_log_index: src.events[2].log_index,
        min_event_seq: 3,
        required_op_event_id: Some(op3_event_id.clone()),
        required_repository_id: Some(repo),
        min_repo_revision: Some(4),
    };
    let timeout_err =
        await_projected_event(&pool, &target3, Duration::from_millis(80), Duration::from_millis(20)).await.unwrap_err();
    assert!(matches!(timeout_err, ProjectionDependencyError::Timeout { .. }));

    // 5. Complete contiguous replay seq=2, seq=3 -> dependency succeeds & non-authorizing verified.
    let (applied_rest, no_gap) =
        apply_projection_stream_stop_on_gap(&pool, &[src.events[1].clone(), src.events[2].clone()], None).await?;
    assert_eq!(applied_rest.len(), 2);
    assert!(no_gap.is_none());
    let wait_ok = await_projected_event(&pool, &target3, Duration::from_millis(200), Duration::from_millis(20)).await?;
    assert_eq!(wait_ok.cursor.applied_event_seq, 3);
    assert_eq!(wait_ok.verified_op_event_id.as_deref(), Some(op3_event_id.as_str()));
    assert!(verify_projected_operation_non_authorizing(&**pool.get().await?, &op3_event_id).await?);

    teardown_pg_schema(&admin, &schema).await;
    Ok(())
}

#[tokio::test]
#[ignore = "requires multi-process raft-node, openssl, and stock git"]
async fn stock_git_compatibility_fixed_oid_closure_and_pin_gc_safety() -> Result<()> {
    let work = tempfile::tempdir()?;
    let bare = work.path().join("origin.git");
    let src_tree = work.path().join("src");
    let clone_dest = work.path().join("clone");
    fs::create_dir_all(&src_tree)?;

    let git_ok = |cwd: &Path, args: &[&str]| -> Result<String> {
        let out = Command::new("git").args(args).current_dir(cwd).output()?;
        if !out.status.success() {
            bail!("git {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    };
    git_ok(work.path(), &["init", "--bare", "--object-format=sha256", bare.to_str().unwrap()])?;
    git_ok(&bare, &["config", "uploadpack.allowFilter", "false"])?;
    git_ok(&src_tree, &["init", "-b", "main", "--object-format=sha256"])?;
    git_ok(&src_tree, &["config", "user.name", "Session Consistency"])?;
    git_ok(&src_tree, &["config", "user.email", "s175@rootyard.invalid"])?;
    fs::write(src_tree.join("README.md"), b"raft session consistency fixture\n")?;
    git_ok(&src_tree, &["add", "README.md"])?;
    git_ok(&src_tree, &["commit", "-m", "init commit"])?;
    let expected_oid = git_ok(&src_tree, &["rev-parse", "HEAD"])?;
    git_ok(&src_tree, &["push", bare.to_str().unwrap(), "refs/heads/main:refs/heads/main"])?;
    let _ = git_ok(&bare, &["symbolic-ref", "HEAD", "refs/heads/main"])?;

    let bin = raft_node_bin();
    let (_pki, n1, n2, n3) = bootstrap_three_nodes(&bin).await?;
    let all = [n1.as_ref(), n2.as_ref(), n3.as_ref()];
    let leader_id = wait_cluster_leader(&all, None).await?;
    let follower_id = [1u64, 2, 3].into_iter().find(|&id| id != leader_id).unwrap();

    let realm = make_realm(31, Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let st = Arc::new(GatewayState {
        nodes: RwLock::new(BTreeMap::from([(1, n1.clone()), (2, n2.clone()), (3, n3.clone())])),
        codec: test_codec(),
        realm: RwLock::new(realm.clone()),
        repo_key: format!("repo:{}", realm.repository_id),
        authenticated: AtomicBool::new(true),
        has_read_permission: AtomicBool::new(true),
        pin_closure_intact: AtomicBool::new(true),
        force_pg_fallback: AtomicBool::new(false),
        bare_git_repo: RwLock::new(Some(bare.clone())),
        wait_budget_ms: RwLock::new(400),
    });
    let base_url = start_gateway_server(st.clone()).await?;
    let v1 = RaftRepoStateValue {
        realm: realm.clone(),
        repo_ref_version: 1,
        refs: BTreeMap::from([("refs/heads/main".into(), expected_oid.clone())]),
        committed_op_id: Uuid::new_v4(),
    };
    let (_, idx1) = commit_state_to_raft(&all, &st.repo_key, &v1).await?;
    wait_nodes_converged(&all, idx1).await?;

    // Stock `git ls-remote` & `git clone` send ZERO custom `x-rootyard-session` headers,
    // hit follower URL -> server ReadIndex redirects cleanly -> clone succeeds with exact OID & fsck=0!
    let remote_url = format!("{base_url}/git/nodes/{follower_id}/repo.git");
    let ls_out = git_ok(work.path(), &["ls-remote", &remote_url, "refs/heads/main"])?;
    assert!(ls_out.starts_with(&expected_oid), "expected OID {expected_oid}, got {ls_out}");
    git_ok(work.path(), &["clone", &remote_url, clone_dest.to_str().unwrap()])?;
    assert_eq!(git_ok(&clone_dest, &["rev-parse", "HEAD"])?, expected_oid);
    let _ = git_ok(&clone_dest, &["fsck", "--strict"])?;

    // Verify RefCasStateMachine holds cannot retire while an active retention root binds them (pin/GC safety).
    let mut sm = RefCasStateMachine::new();
    let (repo, tenant, owner) = (realm.repository_id, realm.tenant_id, Uuid::new_v4());
    let history = realm.history_incarnation;
    let d = |s: &str| RequestDigest::of("s175-gc", &[s.as_bytes()]).as_hex();
    let gate =
        CoreGateInit::new(repo, tenant, GitObjectFormat::Sha256, history, 1, 1, RefName::branch("refs/heads/main")?)?;
    sm.apply(
        AppliedLogId { term: 1, index: 1 },
        RefCasCommand::InitializeGate(InitializeGateCommand {
            gate: WireGateInit::from(&gate),
            pack_mode: SmPackMode::MetadataOnly,
            lane: RepositoryLane::ServingRefStore,
            authz_floor: 1,
        }),
    )?;
    let gate_digest = sm.read_gate_version(repo)?.unwrap().digest().as_hex();
    let (snap_id, pin_id, hold_id, root_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let (hold_req, hold_consume, op_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    sm.apply(
        AppliedLogId { term: 1, index: 2 },
        RefCasCommand::CreateSnapshotPin(CreateSnapshotPinCommand {
            request_id: Uuid::new_v4(),
            repository_id: repo,
            tenant_id: tenant,
            owner_id: owner,
            purpose: MetadataPinPurpose::Verification,
            snapshot_id: snap_id,
            pin_id,
            object_format: GitObjectFormat::Sha256,
            history_incarnation: history,
            authority_epoch: 1,
            group_epoch: 1,
            expected_gate_digest: gate_digest.clone(),
            lease_ticks: 50,
            logical_tick: 10,
            pack_digests: vec![],
            request_digest: d("pin"),
        }),
    )?;
    sm.apply(
        AppliedLogId { term: 1, index: 3 },
        RefCasCommand::AcquireHoldBatch(AcquireHoldBatchCommand {
            request_id: hold_req,
            consume_request_id: hold_consume,
            operation_id: op_id,
            repository_id: repo,
            tenant_id: tenant,
            owner_id: owner,
            purpose: "pin_closure".into(),
            backend_identity: d("backend"),
            authority_id: realm.authority_id,
            authority_generation: 1,
            expected_gate_digest: gate_digest,
            artifacts: vec![WireHoldArtifactSpec {
                hold_id,
                slot: 0,
                artifact_digest: d("pack"),
                declared_bytes: 512,
                logical_bytes: 256,
            }],
        }),
    )?;
    sm.apply(
        AppliedLogId { term: 1, index: 4 },
        RefCasCommand::MarkHoldConsumed(MarkHoldConsumedCommand {
            consume_request_id: hold_consume,
            request_id: hold_req,
            repository_id: repo,
            tenant_id: tenant,
            hold_ids: vec![hold_id],
        }),
    )?;
    let reg_digest = d("reg-digest");
    sm.apply(
        AppliedLogId { term: 1, index: 5 },
        RefCasCommand::RegisterRoot(RegisterRootCommand {
            request_id: Uuid::new_v4(),
            root_id,
            operation_id: op_id,
            repository_id: repo,
            tenant_id: tenant,
            owner_id: owner,
            purpose: "clone_pin".into(),
            business_intent_digest: d("intent"),
            object_format: GitObjectFormat::Sha256,
            history_incarnation: history,
            authority_epoch: 1,
            group_epoch: 1,
            source_snapshot_id: snap_id,
            source_pin_id: pin_id,
            source_pin_generation: 1,
            selector_kind: "snapshot".into(),
            selector_digest: d("sel"),
            refs_digest: d("refs"),
            pack_set_digest: d("packs"),
            bound_hold_ids: vec![hold_id],
            register_digest: reg_digest.clone(),
            request_digest: d("req-root"),
        }),
    )?;
    assert_eq!(sm.read_root(root_id).unwrap().state, SmRootState::Active);
    assert!(
        sm.apply(
            AppliedLogId { term: 1, index: 6 },
            RefCasCommand::RetireHoldBatch(RetireHoldBatchCommand {
                request_id: Uuid::new_v4(),
                repository_id: repo,
                tenant_id: tenant,
                hold_ids: vec![hold_id],
            }),
        )
        .is_err(),
        "active retention root MUST block hold retirement"
    );
    sm.apply(
        AppliedLogId { term: 1, index: 6 },
        RefCasCommand::ReleaseRoot(ReleaseRootCommand {
            request_id: Uuid::new_v4(),
            root_id,
            repository_id: repo,
            tenant_id: tenant,
            owner_id: owner,
            expected_register_digest: reg_digest,
            intent_digest: d("release"),
        }),
    )?;
    sm.apply(
        AppliedLogId { term: 1, index: 7 },
        RefCasCommand::RetireHoldBatch(RetireHoldBatchCommand {
            request_id: Uuid::new_v4(),
            repository_id: repo,
            tenant_id: tenant,
            hold_ids: vec![hold_id],
        }),
    )?;
    assert_eq!(sm.read_hold(hold_id).unwrap().state, SmHoldState::Retired);

    for sid in [1u64, 2, 3] {
        if let Some(p) = st.nodes.write().unwrap().remove(&sid)
            && let Ok(owned) = Arc::try_unwrap(p)
        {
            owned.shutdown().await;
        }
    }
    Ok(())
}
