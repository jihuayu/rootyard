//! Real 3-node in-process mTLS openraft + SQLite integration for the Root Ref-CAS backend.
//!
//! This drives the existing Root `RefCasCommand` business commands through the actual
//! `PersistentStateMachine::apply` callback and real Raft quorum, not generic KV commands plus a
//! separate local state machine. It proves the backend component boundary only: it is not a
//! multi-process production HTTP/PG/Blob or multi-host durability qualification.

use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use openraft::entry::RaftEntry as _;
use openraft::storage::{RaftSnapshotBuilder, RaftStateMachine};
use openraft::{BasicNode, CommittedLeaderId, Config, Entry, EntryPayload, LogId, Raft, ServerState, SnapshotPolicy};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use rootyard::ref_store::core::state_machine::{
    CommitRefsCommand, InitializeGateCommand, RefCasCommand, RepositoryLane, SmPackMode, WireCommitRefsRequest,
    WireGateInit,
};
use rootyard::ref_store::raft_backend::{
    BackendOptions, ROOT_REF_CAS_VERSION, RaftBackendError, RealmBinding, RootRaftRefCasBackend, RootRefCasStateMachine,
};
use rootyard::ref_store::{
    CommitMode, CommitRefsRequest, CoreGateInit, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, OperationLookup,
    RefName, RefPrecondition, RefTarget, RefUpdate, VersionCheck,
};
use rootyard_refcas_log::cluster::{
    MtlsNetworkFactory, PeerDirectory, RpcRequest, RpcResponse, read_frame_async, write_frame_async,
};
use rootyard_refcas_log::mtls::{MtlsClient, MtlsPaths, MtlsServer, PeerIdentity, node_dns_name};
use rootyard_refcas_log::state_machine::{
    ApplicationCommand, ApplicationError, ApplicationLogId, ApplicationStateMachine, PersistentStateMachine, SmCommand,
};
use rootyard_refcas_log::{LogTypeConfig, PersistentLog};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::watch;
use uuid::Uuid;

const TEST_GROUP: &str = "group-175";
const CLUSTER_NAME: &str = "issue175-real-raft-backend";

fn lid(term: u64, node: u64, index: u64) -> LogId<u64> {
    LogId::new(CommittedLeaderId::new(term, node), index)
}

fn lane() -> IssuerLane {
    IssuerLane::new("real-raft-backend-test").expect("valid lane")
}

fn ref_name(value: &str) -> RefName {
    RefName::new(value).expect("valid ref name")
}

fn oid(byte: u8) -> GitOid {
    GitOid::Sha256([byte; 32])
}

fn init_command(repo: Uuid, tenant: Uuid, history: Uuid) -> RefCasCommand {
    let gate = CoreGateInit::new(
        repo,
        tenant,
        GitObjectFormat::Sha256,
        history,
        1,
        1,
        RefName::branch("refs/heads/main").expect("valid HEAD branch"),
    )
    .expect("valid gate init");
    RefCasCommand::InitializeGate(InitializeGateCommand {
        gate: WireGateInit::from(&gate),
        lane: RepositoryLane::ServingRefStore,
        pack_mode: SmPackMode::MetadataOnly,
        authz_floor: 1,
    })
}

#[allow(clippy::too_many_arguments)]
fn commit_command(
    repo: Uuid,
    tenant: Uuid,
    issuer: Uuid,
    history: Uuid,
    sequence: i64,
    operation_id: Uuid,
    expected_revision: i64,
    name: &str,
    old: Option<GitOid>,
    new: GitOid,
) -> RefCasCommand {
    let target_name = ref_name(name);
    let request = CommitRefsRequest::new(
        repo,
        tenant,
        issuer,
        lane(),
        sequence,
        operation_id,
        GitObjectFormat::Sha256,
        history,
        1,
        1,
        expected_revision,
        HeadUpdate::Retarget(target_name.clone()),
        CommitMode::Atomic,
        vec![RefUpdate::new(
            target_name,
            old.map_or(RefPrecondition::Absent, RefPrecondition::Present),
            RefTarget::Oid(new),
        )],
    )
    .expect("valid commit request");
    RefCasCommand::CommitRefs(CommitRefsCommand {
        request: WireCommitRefsRequest::from(&request),
        decision_id: None,
        required_holds: vec![],
        policy_rejects: BTreeMap::new(),
        logical_tick: 10,
    })
}

struct TestPki {
    _dir: tempfile::TempDir,
    ca_cert: PathBuf,
    ca_key: KeyPair,
    ca_params: CertificateParams,
}

impl TestPki {
    fn new() -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(rcgen::DnType::CommonName, "issue175-real-raft-ca");
        let issuer = CertifiedIssuer::self_signed(params.clone(), clone_key(&key)?)?;
        let ca_cert = dir.path().join("ca.crt");
        std::fs::write(&ca_cert, issuer.pem())?;
        Ok(Self { _dir: dir, ca_cert, ca_key: key, ca_params: params })
    }

    fn node_paths(&self, node_id: u64) -> Result<MtlsPaths> {
        let issuer = CertifiedIssuer::self_signed(self.ca_params.clone(), clone_key(&self.ca_key)?)?;
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let mut params = CertificateParams::new(vec![node_dns_name(node_id)])?;
        params.is_ca = IsCa::ExplicitNoCa;
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
        let cert = params.signed_by(&key, &issuer)?;
        let stem = format!("node-{node_id}");
        let cert_path = self._dir.path().join(format!("{stem}.crt"));
        let key_path = self._dir.path().join(format!("{stem}.key"));
        std::fs::write(&cert_path, cert.pem())?;
        std::fs::write(&key_path, key.serialize_pem())?;
        Ok(MtlsPaths { ca_cert: self.ca_cert.clone(), cert: cert_path, key: key_path })
    }
}

fn clone_key(key: &KeyPair) -> Result<KeyPair> {
    Ok(KeyPair::from_pem(&key.serialize_pem())?)
}

struct TestNode {
    id: u64,
    dir: tempfile::TempDir,
    raft: Raft<LogTypeConfig>,
    sm: PersistentStateMachine,
    peer_dir: PeerDirectory,
    stop: watch::Sender<bool>,
}

struct TestCluster {
    #[allow(dead_code)]
    _pki: TestPki,
    nodes: Vec<TestNode>,
}

impl TestCluster {
    async fn start_three() -> Result<Self> {
        let pki = TestPki::new()?;
        let mut nodes = Vec::new();
        let mut raft_map = BTreeMap::new();

        for id in [1_u64, 2, 3] {
            let dir = tempfile::tempdir()?;
            let paths = pki.node_paths(id)?;
            let mtls_server = MtlsServer::from_paths(&paths)?;
            let mtls_client = MtlsClient::from_paths(&paths)?;
            let peer_dir = PeerDirectory::new();

            let log = PersistentLog::open(dir.path(), id, true).await.context("open persistent log")?;
            let sm =
                PersistentStateMachine::open_application(dir.path(), id, true, Box::new(RootRefCasStateMachine::new()))
                    .await
                    .context("open application state machine")?;
            let config = Arc::new(
                Config {
                    cluster_name: CLUSTER_NAME.into(),
                    heartbeat_interval: 50,
                    election_timeout_min: 500,
                    election_timeout_max: 900,
                    snapshot_policy: SnapshotPolicy::LogsSinceLast(1_000),
                    ..Default::default()
                }
                .validate()
                .map_err(|e| anyhow::anyhow!("raft config: {e}"))?,
            );
            let network = MtlsNetworkFactory::new(peer_dir.clone(), mtls_client);
            let raft = Raft::new(id, config, network, log, sm.clone())
                .await
                .map_err(|e| anyhow::anyhow!("create raft node {id}: {e}"))?;

            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let raft_addr = listener.local_addr()?.to_string();
            raft_map.insert(id, raft_addr.clone());
            let (stop, stop_rx) = watch::channel(false);
            spawn_rpc_listener(mtls_server, listener, raft.clone(), peer_dir.clone(), stop_rx);

            nodes.push(TestNode { id, dir, raft, sm, peer_dir, stop });
        }

        for node in &nodes {
            node.peer_dir.update(raft_map.clone());
        }
        let initial: BTreeMap<u64, BasicNode> =
            raft_map.iter().map(|(id, addr)| (*id, BasicNode { addr: addr.clone() })).collect();
        nodes[0].raft.initialize(initial).await.map_err(|e| anyhow::anyhow!("initialize raft cluster: {e}"))?;
        let cluster = Self { _pki: pki, nodes };
        cluster.wait_leader(Duration::from_secs(20)).await?;
        Ok(cluster)
    }

    async fn wait_leader(&self, timeout: Duration) -> Result<(u64, u64)> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            for node in &self.nodes {
                let metrics = node.raft.metrics().borrow().clone();
                if metrics.state != ServerState::Leader || metrics.current_leader != Some(node.id) {
                    continue;
                }
                let all_ready = self.nodes.iter().all(|peer| {
                    let peer_metrics = peer.raft.metrics().borrow().clone();
                    peer_metrics.current_leader == Some(node.id)
                        && peer_metrics.last_applied.is_some()
                        && peer_metrics.membership_config.membership().voter_ids().count() == 3
                });
                if all_ready {
                    return Ok((node.id, metrics.current_term));
                }
            }
            if tokio::time::Instant::now() >= deadline {
                bail!("cluster did not elect a converged leader within {timeout:?}");
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }

    fn node(&self, id: u64) -> &TestNode {
        self.nodes.iter().find(|node| node.id == id).expect("node exists")
    }

    fn first_follower_id(&self, leader_id: u64) -> u64 {
        self.nodes.iter().find(|node| node.id != leader_id).expect("follower exists").id
    }

    fn partition_node(&self, isolated: u64) {
        let others: BTreeSet<u64> = self.nodes.iter().map(|node| node.id).filter(|id| *id != isolated).collect();
        let isolated_set = BTreeSet::from([isolated]);
        for node in &self.nodes {
            if node.id == isolated {
                node.peer_dir.set_blocked(others.clone());
            } else {
                node.peer_dir.set_blocked(isolated_set.clone());
            }
        }
    }

    fn heal_partitions(&self) {
        for node in &self.nodes {
            node.peer_dir.set_blocked(BTreeSet::new());
        }
    }

    async fn shutdown(self) -> Vec<(u64, tempfile::TempDir)> {
        let mut dirs = Vec::new();
        for node in self.nodes {
            let TestNode { id, dir, raft, sm, stop, .. } = node;
            let _ = stop.send(true);
            let _ = raft.shutdown().await;
            drop(raft);
            drop(sm);
            dirs.push((id, dir));
        }
        dirs
    }
}

fn spawn_rpc_listener(
    server: MtlsServer,
    listener: TcpListener,
    raft: Raft<LogTypeConfig>,
    peers: PeerDirectory,
    stop: watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let mut stop_accept = stop.clone();
        loop {
            tokio::select! {
                result = stop_accept.changed() => {
                    if result.is_err() || *stop_accept.borrow() {
                        break;
                    }
                }
                accepted = listener.accept() => {
                    let Ok((tcp, _)) = accepted else { break };
                    let server = server.clone();
                    let raft = raft.clone();
                    let peers = peers.clone();
                    let mut conn_stop = stop.clone();
                    tokio::spawn(async move {
                        let Ok((mut tls, PeerIdentity::Node(sender))) = server.accept(tcp).await else {
                            return;
                        };
                        if peers.is_blocked(sender) {
                            return;
                        }
                        loop {
                            let request = tokio::select! {
                                result = conn_stop.changed() => {
                                    if result.is_err() || *conn_stop.borrow() {
                                        break;
                                    }
                                    continue;
                                }
                                frame = read_frame_async::<_, RpcRequest>(&mut tls) => {
                                    match frame {
                                        Ok(Some(request)) => request,
                                        _ => break,
                                    }
                                }
                            };
                            if peers.is_blocked(sender) {
                                break;
                            }
                            let response = match request {
                                RpcRequest::Vote(vote) if vote.vote.leader_id.node_id == sender => {
                                    RpcResponse::Vote(Box::new(raft.vote(vote).await))
                                }
                                RpcRequest::AppendEntries(append) if append.vote.leader_id.node_id == sender => {
                                    RpcResponse::AppendEntries(Box::new(raft.append_entries(append).await))
                                }
                                RpcRequest::InstallSnapshot(snapshot) if snapshot.vote.leader_id.node_id == sender => {
                                    RpcResponse::InstallSnapshot(Box::new(raft.install_snapshot(snapshot).await))
                                }
                                _ => RpcResponse::Error {
                                    message: "unauthorized peer rpc".into(),
                                    forward_to_leader_id: None,
                                },
                            };
                            if write_frame_async(&mut tls, &response).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            }
        }
    });
}

async fn backend_on(
    cluster: &TestCluster,
    node_id: u64,
    repo: Uuid,
    tenant: Uuid,
    realm: RealmBinding,
    options: BackendOptions,
) -> Result<RootRaftRefCasBackend> {
    let node = cluster.node(node_id);
    Ok(RootRaftRefCasBackend::open(node.raft.clone(), node.sm.clone(), repo, tenant, realm, options).await?)
}

fn reducer_snapshot(
    snapshot: &rootyard_refcas_log::state_machine::ApplicationRuntimeSnapshot,
) -> &RootRefCasStateMachine {
    snapshot.reducer.as_any().downcast_ref::<RootRefCasStateMachine>().expect("root reducer")
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct ForeignState {
    last_applied: Option<ApplicationLogId>,
}

#[derive(Clone, Debug, Default)]
struct ForeignReducer {
    state: ForeignState,
}

impl ForeignReducer {
    fn new() -> Self {
        Self::default()
    }
}

impl ApplicationStateMachine for ForeignReducer {
    fn domain(&self) -> &'static str {
        "foreign.refcas.app"
    }

    fn version(&self) -> u16 {
        ROOT_REF_CAS_VERSION
    }

    fn apply(&mut self, _log_id: ApplicationLogId, _payload: &[u8]) -> Result<(), ApplicationError> {
        Err(ApplicationError::new("foreign reducer refuses commands"))
    }

    fn advance_applied(&mut self, log_id: ApplicationLogId) -> Result<(), ApplicationError> {
        self.state.last_applied = Some(log_id);
        Ok(())
    }

    fn export_state(&self) -> Result<Vec<u8>, ApplicationError> {
        serde_json::to_vec(&self.state).map_err(|e| ApplicationError::new(format!("foreign export: {e}")))
    }

    fn restore_state(&mut self, bytes: &[u8]) -> Result<(), ApplicationError> {
        self.state =
            serde_json::from_slice(bytes).map_err(|e| ApplicationError::new(format!("foreign restore: {e}")))?;
        Ok(())
    }

    fn last_applied(&self) -> Option<ApplicationLogId> {
        self.state.last_applied
    }

    fn state_digest_hex(&self) -> Result<String, ApplicationError> {
        let bytes = self.export_state()?;
        Ok(hex_encode(Sha256::digest(&bytes)))
    }

    fn clone_box(&self) -> Box<dyn ApplicationStateMachine> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

fn hex_encode(bytes: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[allow(clippy::type_complexity)]
async fn build_snapshot(sm: &PersistentStateMachine) -> Result<(openraft::SnapshotMeta<u64, BasicNode>, Vec<u8>)> {
    let mut sm = sm.clone();
    let mut builder = sm.get_snapshot_builder().await;
    let snapshot = builder.build_snapshot().await.map_err(|e| anyhow::anyhow!("build application snapshot: {e}"))?;
    Ok((snapshot.meta, snapshot.snapshot.into_inner()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_root_refcas_commands_through_quorum_mtls_sqlite_and_restart() -> Result<()> {
    let cluster = TestCluster::start_three().await?;
    let (leader_id, _leader_term) = cluster.wait_leader(Duration::from_secs(20)).await?;
    let repo = Uuid::new_v4();
    let tenant = Uuid::new_v4();
    let issuer = Uuid::new_v4();
    let history = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let realm = RealmBinding::new(tenant, TEST_GROUP, authority, history, 1, 1)?;
    let options = BackendOptions {
        quorum_timeout: Duration::from_secs(3),
        apply_timeout: Duration::from_secs(5),
        poll_interval: Duration::from_millis(20),
    };
    let backend = backend_on(&cluster, leader_id, repo, tenant, realm.clone(), options).await?;

    backend.propose(init_command(repo, tenant, history)).await?;
    let operation_id = Uuid::new_v4();
    let commit = commit_command(repo, tenant, issuer, history, 1, operation_id, 1, "refs/heads/main", None, oid(1));
    let commit_coordinate = backend.propose(commit.clone()).await?;

    let view = backend.read_committed_view().await?;
    assert!(view.last_applied().is_some_and(|id| id.index >= commit_coordinate.index));
    let expected_oid = oid(1).as_hex();
    assert_eq!(view.read_ref("refs/heads/main").as_deref(), Some(expected_oid.as_str()));
    assert_eq!(view.read_head_ref().as_deref(), Some("refs/heads/main"));
    assert_eq!(view.repository_id(), repo);
    assert_eq!(view.tenant_id(), tenant);
    assert_eq!(view.realm(), &realm);

    let gate = view.read_gate_version()?.expect("gate version");
    assert_eq!(gate.revision(), 2);
    assert!(matches!(view.check_version(None)?, VersionCheck::Changed(version) if version == gate));
    assert!(matches!(
        view.check_version(Some(&gate))?,
        VersionCheck::Unchanged(version) if version == gate
    ));
    assert!(matches!(view.query_operation(operation_id)?, OperationLookup::Known(_)));
    assert!(view.state_digest_hex()?.len() == 64);

    // A real KV fallback is unavailable in application mode.
    assert!(cluster.node(leader_id).sm.kv_get("refs/heads/main").await.is_err());
    assert!(cluster.node(leader_id).sm.kv_snapshot().await.is_err());

    // Follower boundary: both write and committed read fail closed with an explicit redirect.
    let follower_id = cluster.first_follower_id(leader_id);
    let follower = backend_on(&cluster, follower_id, repo, tenant, realm.clone(), options).await?;
    assert!(matches!(
        follower.read_committed_view().await,
        Err(RaftBackendError::FollowerRedirect(Some(id))) if id == leader_id
    ));
    assert!(matches!(follower.propose(commit.clone()).await, Err(RaftBackendError::FollowerRedirect(_))));

    // Stale realm/epoch refuses before any quorum or local read.
    let stale_realm = RealmBinding::new(tenant, TEST_GROUP, authority, history, 2, 1)?;
    assert!(matches!(backend.read_committed_view_for(&stale_realm).await, Err(RaftBackendError::StaleRealm)));

    // Coordinate isolation: another repository cannot see or write repo A's state.
    let repo_b = Uuid::new_v4();
    let backend_b = backend_on(&cluster, leader_id, repo_b, tenant, realm.clone(), options).await?;
    let view_b = backend_b.read_committed_view().await?;
    assert!(view_b.read_refs().is_empty());
    assert!(view_b.read_ref("refs/heads/main").is_none());
    assert!(matches!(backend_b.propose(commit.clone()).await, Err(RaftBackendError::ScopeMismatch("repository_id"))));

    // A real malformed/foreign-domain command is refused by the same reducer callback without
    // advancing its applied coordinate.
    let malformed_dir = tempfile::tempdir()?;
    let mut malformed = PersistentStateMachine::open_application(
        malformed_dir.path(),
        90,
        true,
        Box::new(RootRefCasStateMachine::new()),
    )
    .await?;
    let wrong_domain = ApplicationCommand::new("foreign.refcas.app", ROOT_REF_CAS_VERSION, b"x".to_vec())?.encode()?;
    assert!(
        malformed
            .apply(vec![Entry { log_id: lid(1, 90, 1), payload: EntryPayload::Normal(wrong_domain) }])
            .await
            .is_err()
    );
    let kv_payload = SmCommand::Put { key: "k".into(), value: "v".into() }.encode()?;
    assert!(
        malformed
            .apply(vec![Entry { log_id: lid(1, 90, 2), payload: EntryPayload::Normal(kv_payload) }])
            .await
            .is_err()
    );
    assert!(malformed.application_summary().await?.expect("application row").last_applied.is_none());

    // A snapshot from a different application domain is refused on install, not restored as
    // empty/local state.
    let foreign_dir = tempfile::tempdir()?;
    let mut foreign =
        PersistentStateMachine::open_application(foreign_dir.path(), 91, true, Box::new(ForeignReducer::new())).await?;
    foreign
        .apply(vec![Entry::new_blank(lid(1, 91, 1))])
        .await
        .map_err(|e| anyhow::anyhow!("foreign blank apply: {e}"))?;
    let (foreign_meta, foreign_bytes) = build_snapshot(&foreign).await?;
    let install_dir = tempfile::tempdir()?;
    let mut install_target =
        PersistentStateMachine::open_application(install_dir.path(), 92, true, Box::new(RootRefCasStateMachine::new()))
            .await?;
    let install_err = install_target
        .install_snapshot(&foreign_meta, Box::new(Cursor::new(foreign_bytes)))
        .await
        .expect_err("foreign-domain snapshot must fail closed");
    assert!(format!("{install_err:#}").contains("application snapshot identity mismatch"));
    assert!(install_target.application_summary().await?.expect("application row").last_applied.is_none());

    // Build a real application-mode snapshot from the committed Root state, install it into a
    // fresh SQLite state machine, and reopen that state machine to prove actual Root state restore.
    let (snapshot_meta, snapshot_bytes) = build_snapshot(&cluster.node(leader_id).sm).await?;
    let restored_dir = tempfile::tempdir()?;
    let mut restored = PersistentStateMachine::open_application(
        restored_dir.path(),
        93,
        true,
        Box::new(RootRefCasStateMachine::new()),
    )
    .await?;
    restored
        .install_snapshot(&snapshot_meta, Box::new(Cursor::new(snapshot_bytes)))
        .await
        .map_err(|e| anyhow::anyhow!("install application snapshot: {e}"))?;
    let restored_snapshot = restored.application_snapshot().await?.expect("application state");
    let restored_reducer = reducer_snapshot(&restored_snapshot);
    assert_eq!(restored_reducer.read_refs(repo).get("refs/heads/main"), Some(&expected_oid));
    assert_eq!(restored_reducer.read_head_ref(repo).as_deref(), Some("refs/heads/main"));
    assert!(restored_reducer.last_applied_coordinate().is_some_and(|id| id.index >= commit_coordinate.index));
    drop(restored);

    let reopened = PersistentStateMachine::open_application(
        restored_dir.path(),
        93,
        true,
        Box::new(RootRefCasStateMachine::new()),
    )
    .await?;
    let reopened_snapshot = reopened.application_snapshot().await?.expect("application state");
    let reopened_reducer = reducer_snapshot(&reopened_snapshot);
    assert_eq!(reopened_reducer.read_refs(repo).get("refs/heads/main"), Some(&expected_oid));

    // Real no-quorum boundary: isolate the leader, use a short-bounded backend, and require an
    // explicit quorum/redirect refusal. No PG/Redis/local view is returned.
    let no_quorum_options = BackendOptions {
        quorum_timeout: Duration::from_millis(400),
        apply_timeout: Duration::from_millis(400),
        poll_interval: Duration::from_millis(20),
    };
    let (current_leader, _) = cluster.wait_leader(Duration::from_secs(10)).await?;
    let isolated = backend_on(&cluster, current_leader, repo, tenant, realm.clone(), no_quorum_options).await?;
    cluster.partition_node(current_leader);
    let no_quorum = isolated.read_committed_view().await;
    let observed =
        no_quorum.as_ref().err().map(ToString::to_string).unwrap_or_else(|| "unexpected committed view".into());
    assert!(
        matches!(no_quorum, Err(RaftBackendError::QuorumUnavailable(_)) | Err(RaftBackendError::FollowerRedirect(_))),
        "isolated leader must fail closed, got {observed}"
    );
    cluster.heal_partitions();
    let (healed_leader, _) = cluster.wait_leader(Duration::from_secs(20)).await?;

    // Restart actual cluster SQLite state: shut down all nodes, reopen the leader's application
    // state machine from its own directory, and verify the committed Root refs/coordinate.
    let dirs = cluster.shutdown().await;
    let (reopen_id, reopen_dir) =
        dirs.iter().find(|entry| entry.0 == healed_leader).or_else(|| dirs.first()).context("cluster dirs")?;
    let restarted = reopen_application(reopen_dir.path(), *reopen_id).await?;
    let restarted_snapshot = restarted.application_snapshot().await?.expect("application state");
    let restarted_reducer = reducer_snapshot(&restarted_snapshot);
    assert_eq!(restarted_reducer.read_refs(repo).get("refs/heads/main"), Some(&expected_oid));
    assert_eq!(restarted_reducer.read_head_ref(repo).as_deref(), Some("refs/heads/main"));
    assert!(restarted_reducer.last_applied_coordinate().is_some());
    Ok(())
}

async fn reopen_application(dir: &std::path::Path, node_id: u64) -> Result<PersistentStateMachine> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    loop {
        match PersistentStateMachine::open_application(dir, node_id, true, Box::new(RootRefCasStateMachine::new()))
            .await
        {
            Ok(sm) => return Ok(sm),
            Err(error) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(anyhow::anyhow!("reopen restarted application state machine: {error}"));
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}
