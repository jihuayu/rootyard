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
use openraft::{BasicNode, CommittedLeaderId, Config, Entry, EntryPayload, LogId, ServerState, SnapshotPolicy};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use rootyard::ref_store::core::state_machine::{
    CommitRefsCommand, CreateSnapshotPinCommand, InitializeGateCommand, NoopCommand, RefCasCommand, RepositoryLane,
    ScopeLifecycle, SetRepositoryLaneCommand, SmPackMode, WireCommitRefsRequest, WireGateInit, encode_command,
};
use rootyard::ref_store::raft_backend::{
    BackendOptions, NodeTrust, ProposalAttemptKind, ProposalEnvelope, ProposalId, ProposalLookup, ProposalOutcome,
    ROOT_REF_CAS_DOMAIN, ROOT_REF_CAS_VERSION, RaftBackendError, RealmBinding, RootRaftNode, RootRaftNodeConfig,
    RootRaftRefCasBackend, RootRefCasOutcome, RootRefCasRefusalKind, RootRefCasStateMachine,
};
use rootyard::ref_store::{
    CommitMode, CommitRefsRequest, CoreGateInit, GitObjectFormat, GitOid, HeadUpdate, IssuerLane, MetadataPinPurpose,
    OperationLookup, RefName, RefPrecondition, RefTarget, RefUpdate, VersionCheck,
};
use rootyard_refcas_log::cluster::{
    MtlsNetworkFactory, PeerDirectory, RpcRequest, RpcResponse, read_frame_async, write_frame_async,
};
use rootyard_refcas_log::fault::{FaultController, FaultMode, FaultPoint, FaultSpec};
use rootyard_refcas_log::mtls::{MtlsClient, MtlsPaths, MtlsServer, PeerIdentity, node_dns_name};
use rootyard_refcas_log::state_machine::{
    ApplicationCommand, ApplicationError, ApplicationLogId, ApplicationStateMachine, PersistentStateMachine, SmCommand,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::watch;
use uuid::Uuid;

mod scope_drain_support;

use scope_drain_support::failure_phase::{Class, Phase, PhaseGuard};

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
fn create_pin_command(
    repo: Uuid,
    tenant: Uuid,
    owner: Uuid,
    history: Uuid,
    request_id: Uuid,
    snapshot_id: Uuid,
    pin_id: Uuid,
    lease_ticks: u64,
) -> RefCasCommand {
    RefCasCommand::CreateSnapshotPin(CreateSnapshotPinCommand {
        request_id,
        repository_id: repo,
        tenant_id: tenant,
        owner_id: owner,
        purpose: MetadataPinPurpose::Verification,
        snapshot_id,
        pin_id,
        object_format: GitObjectFormat::Sha256,
        history_incarnation: history,
        authority_epoch: 1,
        group_epoch: 1,
        expected_gate_digest: "00".repeat(32),
        lease_ticks,
        logical_tick: 999,
        pack_digests: vec![],
        request_digest: "11".repeat(32),
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
    node: RootRaftNode,
    peer_dir: PeerDirectory,
    stop: watch::Sender<bool>,
}

struct TestCluster {
    #[allow(dead_code)]
    _pki: TestPki,
    nodes: Vec<TestNode>,
}

impl TestCluster {
    async fn start_three(trust: NodeTrust) -> Result<Self> {
        let pki = TestPki::new()?;
        let mut nodes = Vec::new();
        let mut raft_map = BTreeMap::new();

        for id in [1_u64, 2, 3] {
            let dir = tempfile::tempdir()?;
            let paths = pki.node_paths(id)?;
            let mtls_server = MtlsServer::from_paths(&paths)?;
            let mtls_client = MtlsClient::from_paths(&paths)?;
            let peer_dir = PeerDirectory::new();

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
            let node = RootRaftNode::start(RootRaftNodeConfig {
                node_id: id,
                store_dir: dir.path().to_path_buf(),
                raft_config: config,
                network,
                check_on_open: true,
                trust: trust.clone(),
            })
            .await?;

            let listener = TcpListener::bind("127.0.0.1:0").await?;
            let raft_addr = listener.local_addr()?.to_string();
            raft_map.insert(id, raft_addr.clone());
            let (stop, stop_rx) = watch::channel(false);
            spawn_rpc_listener(mtls_server, listener, node.clone(), peer_dir.clone(), stop_rx);

            nodes.push(TestNode { id, dir, node, peer_dir, stop });
        }

        for node in &nodes {
            node.peer_dir.update(raft_map.clone());
        }
        let initial: BTreeMap<u64, BasicNode> =
            raft_map.iter().map(|(id, addr)| (*id, BasicNode { addr: addr.clone() })).collect();
        nodes[0].node.initialize_cluster(initial).await.map_err(|e| anyhow::anyhow!("initialize raft cluster: {e}"))?;
        let cluster = Self { _pki: pki, nodes };
        cluster.wait_leader(Duration::from_secs(20)).await?;
        Ok(cluster)
    }

    async fn wait_leader(&self, timeout: Duration) -> Result<(u64, u64)> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            for node in &self.nodes {
                let metrics = node.node.metrics();
                if metrics.state != ServerState::Leader || metrics.current_leader != Some(node.id) {
                    continue;
                }
                let all_ready = self.nodes.iter().all(|peer| {
                    let peer_metrics = peer.node.metrics();
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
            let TestNode { id, dir, node, stop, .. } = node;
            let _ = stop.send(true);
            let _ = node.shutdown().await;
            drop(node);
            dirs.push((id, dir));
        }
        dirs
    }
}

fn spawn_rpc_listener(
    server: MtlsServer,
    listener: TcpListener,
    node: RootRaftNode,
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
                    let node = node.clone();
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
                                    node.handle_peer_rpc(RpcRequest::Vote(vote)).await
                                }
                                RpcRequest::AppendEntries(append) if append.vote.leader_id.node_id == sender => {
                                    node.handle_peer_rpc(RpcRequest::AppendEntries(append)).await
                                }
                                RpcRequest::InstallSnapshot(snapshot) if snapshot.vote.leader_id.node_id == sender => {
                                    node.handle_peer_rpc(RpcRequest::InstallSnapshot(snapshot)).await
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
    Ok(RootRaftRefCasBackend::open(node.node.clone(), repo, tenant, realm, options).await?)
}

fn proposal_outcome(result: &ProposalOutcome) -> &RootRefCasOutcome {
    result.outcome.as_ref().expect("proposal outcome present")
}

fn reducer_snapshot(
    snapshot: &rootyard_refcas_log::state_machine::ApplicationRuntimeSnapshot,
) -> &RootRefCasStateMachine {
    snapshot.reducer.as_any().downcast_ref::<RootRefCasStateMachine>().expect("root reducer")
}

async fn wait_applied_through(cluster: &TestCluster, index: u64, timeout: Duration) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let ready =
            cluster.nodes.iter().all(|node| node.node.metrics().last_applied.is_some_and(|id| id.index >= index));
        if ready {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("cluster did not apply coordinate {index} on every replica within {timeout:?}");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
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
    let mut phase = PhaseGuard::new(Phase::Bootstrap);
    let outcome = real_root_refcas_commands_through_quorum_mtls_sqlite_and_restart_body(&mut phase).await;
    match outcome {
        Ok(()) => {
            phase.complete();
            Ok(())
        }
        Err(error) => {
            phase.fail(Class::from_error(&error));
            Err(anyhow::anyhow!("root raft case failed"))
        }
    }
}

async fn real_root_refcas_commands_through_quorum_mtls_sqlite_and_restart_body(phase: &mut PhaseGuard) -> Result<()> {
    let repo = Uuid::new_v4();
    let tenant = Uuid::new_v4();
    let issuer = Uuid::new_v4();
    let history = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let trust = NodeTrust::new(TEST_GROUP, authority, 1)?;
    let realm = RealmBinding::new(tenant, TEST_GROUP, authority, history, 1, 1, GitObjectFormat::Sha256, 1)?;
    phase.set(Phase::Bootstrap);
    let cluster = TestCluster::start_three(trust.clone()).await?;
    let (leader_id, _leader_term) = cluster.wait_leader(Duration::from_secs(20)).await?;
    let options = BackendOptions {
        quorum_timeout: Duration::from_secs(3),
        apply_timeout: Duration::from_secs(5),
        poll_interval: Duration::from_millis(20),
    };
    let backend = backend_on(&cluster, leader_id, repo, tenant, realm.clone(), options).await?;

    phase.set(Phase::Provision);
    let init_outcome = backend.propose(init_command(repo, tenant, history)).await?;
    assert!(proposal_outcome(&init_outcome).is_applied());
    phase.set(Phase::Commit);
    let operation_id = Uuid::new_v4();
    let commit = commit_command(repo, tenant, issuer, history, 1, operation_id, 1, "refs/heads/main", None, oid(1));
    let commit_outcome = backend.propose(commit.clone()).await?;
    let commit_coordinate = commit_outcome.log_id;
    assert!(proposal_outcome(&commit_outcome).is_applied());

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

    phase.set(Phase::Refusal);
    // Decoded normal commands with semantic-invalid fields are durable typed refusals, not fatal
    // storage/apply errors. Zero lease ticks is valid JSON but core-semantic-invalid; a nil
    // request id is a core InvalidIdentity. Both must advance the applied coordinate without
    // changing business state or the logical clock.
    let before_semantic_floor = view.logical_clock_floor();
    let before_semantic_refs = view.read_refs();
    let invalid_input = backend
        .propose(create_pin_command(
            repo,
            tenant,
            Uuid::new_v4(),
            history,
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            0,
        ))
        .await?;
    let invalid_input_kind = match proposal_outcome(&invalid_input) {
        RootRefCasOutcome::Refused(refusal) => refusal.kind,
        RootRefCasOutcome::Applied(_) => panic!("zero-lease pin unexpectedly applied"),
    };
    assert_eq!(invalid_input_kind, RootRefCasRefusalKind::InvalidInput);
    wait_applied_through(&cluster, invalid_input.log_id.index, Duration::from_secs(10)).await?;
    let after_invalid_input = backend.read_committed_view().await?;
    assert!(after_invalid_input.last_applied().is_some_and(|id| id.index >= invalid_input.log_id.index));
    assert_eq!(after_invalid_input.logical_clock_floor(), before_semantic_floor);
    assert_eq!(after_invalid_input.read_refs(), before_semantic_refs);

    let invalid_identity = backend
        .propose(create_pin_command(
            repo,
            tenant,
            Uuid::new_v4(),
            history,
            Uuid::nil(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            1,
        ))
        .await?;
    let invalid_identity_kind = match proposal_outcome(&invalid_identity) {
        RootRefCasOutcome::Refused(refusal) => refusal.kind,
        RootRefCasOutcome::Applied(_) => panic!("nil-request-id pin unexpectedly applied"),
    };
    assert_eq!(invalid_identity_kind, RootRefCasRefusalKind::InvalidIdentity);
    wait_applied_through(&cluster, invalid_identity.log_id.index, Duration::from_secs(10)).await?;
    let after_invalid_identity = backend.read_committed_view().await?;
    assert!(after_invalid_identity.last_applied().is_some_and(|id| id.index >= invalid_identity.log_id.index));
    assert_eq!(after_invalid_identity.logical_clock_floor(), before_semantic_floor);
    assert_eq!(after_invalid_identity.read_refs(), before_semantic_refs);

    // The same quorum still accepts a valid command and serves a fresh ReadIndex view.
    let healthy_after_semantic = backend.propose(RefCasCommand::Noop(NoopCommand { logical_tick: None })).await?;
    assert!(proposal_outcome(&healthy_after_semantic).is_applied());
    let healthy_after_semantic_view = backend.read_committed_view().await?;
    assert!(
        healthy_after_semantic_view.last_applied().is_some_and(|id| id.index >= healthy_after_semantic.log_id.index)
    );

    phase.set(Phase::Concurrent);
    // Concurrent proposals can advance the applied snapshot beyond another write's exact index.
    // Propose must recover its own receipt with a >= apply barrier, not return a Storage error.
    let concurrent_a = backend.clone();
    let concurrent_b = backend.clone();
    let (concurrent_a, concurrent_b) = tokio::join!(
        concurrent_a.propose(RefCasCommand::Noop(NoopCommand { logical_tick: None })),
        concurrent_b.propose(RefCasCommand::Noop(NoopCommand { logical_tick: None })),
    );
    let concurrent_a = concurrent_a?;
    let concurrent_b = concurrent_b?;
    assert!(proposal_outcome(&concurrent_a).is_applied());
    assert!(proposal_outcome(&concurrent_b).is_applied());
    assert_ne!(concurrent_a.log_id, concurrent_b.log_id);
    assert_ne!(concurrent_a.proposal_id, concurrent_b.proposal_id);

    phase.set(Phase::Transition);
    // A valid gate transition to Closing is applied. A subsequent same-scope CommitRefs is a
    // deterministic business refusal: it must advance the replicated applied coordinate and
    // return a durable typed outcome, not become a fatal OpenRaft apply/storage error.
    let closing = RefCasCommand::SetRepositoryLane(SetRepositoryLaneCommand {
        repository_id: repo,
        tenant_id: tenant,
        lane: RepositoryLane::ServingRefStore,
        lifecycle: ScopeLifecycle::Closing,
        authz_floor: 1,
        history_incarnation: history,
        authority_epoch: 1,
        group_epoch: 1,
        pack_mode: SmPackMode::MetadataOnly,
    });
    let close_outcome = backend.propose(closing).await?;
    assert!(proposal_outcome(&close_outcome).is_applied());
    let closing_view = backend.read_committed_view().await?;
    assert_eq!(closing_view.read_scope_lifecycle().map(|(lifecycle, _)| lifecycle), Some(ScopeLifecycle::Closing));

    let refused_operation = Uuid::new_v4();
    let refused_commit =
        commit_command(repo, tenant, issuer, history, 2, refused_operation, 2, "refs/heads/refused", None, oid(2));
    let refusal = backend.propose(refused_commit.clone()).await?;
    let refusal_kind = match proposal_outcome(&refusal) {
        RootRefCasOutcome::Refused(refusal) => refusal.kind,
        RootRefCasOutcome::Applied(_) => panic!("gate-closed commit unexpectedly applied"),
    };
    assert_eq!(refusal_kind, RootRefCasRefusalKind::ScopeClosingOrClosed);
    wait_applied_through(&cluster, refusal.log_id.index, Duration::from_secs(10)).await?;
    let refused_view = backend.read_committed_view().await?;
    assert!(refused_view.last_applied().is_some_and(|id| id.index >= refusal.log_id.index));
    assert!(refused_view.read_ref("refs/heads/refused").is_none());
    let stored_refusal = backend.query_proposal(refusal.proposal_id.clone()).await?;
    let stored_outcome = match stored_refusal {
        ProposalLookup::Found { original_log_id, observed_log_id, outcome, .. } => {
            assert_eq!(original_log_id, refusal.log_id);
            assert_eq!(observed_log_id, refusal.log_id);
            outcome
        }
        other => panic!("durable typed refusal lookup mismatch: {other:?}"),
    };
    assert!(matches!(
        stored_outcome,
        RootRefCasOutcome::Refused(refusal) if refusal.kind == RootRefCasRefusalKind::ScopeClosingOrClosed
    ));

    // Same caller-stable ID and canonical digest advances the coordinate on retry but never
    // re-executes the business command; the first typed refusal remains the result.
    let refusal_retry = backend.propose_with_id(refusal.proposal_id.clone(), refused_commit).await?;
    assert_eq!(refusal_retry.decision, ProposalAttemptKind::Replayed);
    assert_eq!(refusal_retry.original_log_id, Some(refusal.log_id));
    assert!(matches!(
        proposal_outcome(&refusal_retry),
        RootRefCasOutcome::Refused(refusal) if refusal.kind == RootRefCasRefusalKind::ScopeClosingOrClosed
    ));

    // The healthy quorum still works after the refusal: a valid Noop applies, the applied index
    // advances, and a new ReadIndex-backed view is minted.
    let healthy = backend.propose(RefCasCommand::Noop(NoopCommand { logical_tick: None })).await?;
    assert!(proposal_outcome(&healthy).is_applied());
    let healthy_view = backend.read_committed_view().await?;
    assert!(healthy_view.last_applied().is_some_and(|id| id.index >= healthy.log_id.index));

    // A same-node-id standalone SM cannot be attached: the public constructor takes the owned
    // factory node, not a caller-selected SM. Application-mode KV reads remain unavailable too.
    let same_id_dir = tempfile::tempdir()?;
    let same_id_sm = PersistentStateMachine::open_application(
        same_id_dir.path(),
        leader_id,
        true,
        Box::new(RootRefCasStateMachine::new()),
    )
    .await?;
    assert_eq!(same_id_sm.summary().await?.node_id, leader_id);
    let kv_probe_dir = tempfile::tempdir()?;
    let kv_probe = PersistentStateMachine::open_application(
        kv_probe_dir.path(),
        95,
        true,
        Box::new(RootRefCasStateMachine::new()),
    )
    .await?;
    assert!(kv_probe.kv_get("refs/heads/main").await.is_err());
    assert!(kv_probe.kv_snapshot().await.is_err());

    phase.set(Phase::Follower);
    // Follower boundary: both write and committed read fail closed with an explicit redirect.
    let follower_id = cluster.first_follower_id(leader_id);
    let follower = backend_on(&cluster, follower_id, repo, tenant, realm.clone(), options).await?;
    assert!(matches!(
        follower.read_committed_view().await,
        Err(RaftBackendError::FollowerRedirect(Some(id))) if id == leader_id
    ));
    assert!(matches!(follower.propose(commit.clone()).await, Err(RaftBackendError::FollowerRedirect(_))));

    // Stale realm/epoch refuses before any quorum or local read.
    let stale_realm = RealmBinding::new(tenant, TEST_GROUP, authority, history, 2, 1, GitObjectFormat::Sha256, 1)?;
    assert!(matches!(backend.read_committed_view_for(&stale_realm).await, Err(RaftBackendError::StaleRealm)));

    phase.set(Phase::Isolation);
    // Coordinate isolation: initialize and commit repository B, then prove repository A's
    // committed view does not see B and a B-scoped backend cannot write A.
    let repo_b = Uuid::new_v4();
    let backend_b = backend_on(&cluster, leader_id, repo_b, tenant, realm.clone(), options).await?;
    assert!(matches!(backend_b.read_committed_view().await, Err(RaftBackendError::StaleGate("gate_missing"))));

    // A proposal identity can be prepared before the gate exists. Retrying the same ID and digest
    // after a lost ACK replays the original typed outcome without re-executing InitializeGate.
    let init_b_id = backend_b.prepare_proposal_id().await?;
    let init_b = backend_b.propose_with_id(init_b_id.clone(), init_command(repo_b, tenant, history)).await?;
    assert_eq!(init_b.decision, ProposalAttemptKind::First);
    assert_eq!(init_b.original_log_id, Some(init_b.log_id));
    assert!(proposal_outcome(&init_b).is_applied());
    let init_b_replay = backend_b.propose_with_id(init_b_id.clone(), init_command(repo_b, tenant, history)).await?;
    assert_eq!(init_b_replay.decision, ProposalAttemptKind::Replayed);
    assert_eq!(init_b_replay.original_log_id, Some(init_b.log_id));
    assert_eq!(proposal_outcome(&init_b_replay), proposal_outcome(&init_b));
    let init_b_lookup = backend_b.query_proposal(init_b_id.clone()).await?;
    assert!(matches!(
        init_b_lookup,
        ProposalLookup::Found { original_log_id, outcome, .. }
            if original_log_id == init_b.log_id && &outcome == proposal_outcome(&init_b)
    ));
    assert!(matches!(backend.query_proposal(init_b_id.clone()).await, Err(RaftBackendError::ProposalScopeMismatch(_))));

    // Same identity with a different canonical command is a durable typed conflict and never
    // replaces the first decision.
    let conflicting_lane = RefCasCommand::SetRepositoryLane(SetRepositoryLaneCommand {
        repository_id: repo_b,
        tenant_id: tenant,
        lane: RepositoryLane::ServingRefStore,
        lifecycle: ScopeLifecycle::Open,
        authz_floor: 1,
        history_incarnation: history,
        authority_epoch: 1,
        group_epoch: 1,
        pack_mode: SmPackMode::MetadataOnly,
    });
    let conflict = backend_b.propose_with_id(init_b_id.clone(), conflicting_lane).await?;
    assert_eq!(conflict.decision, ProposalAttemptKind::Conflict);
    assert!(matches!(
        proposal_outcome(&conflict),
        RootRefCasOutcome::Refused(refusal) if refusal.kind == RootRefCasRefusalKind::ProposalConflict
    ));
    assert!(matches!(
        backend_b.query_proposal(init_b_id.clone()).await?,
        ProposalLookup::Found { original_log_id, outcome, .. }
            if original_log_id == init_b.log_id && &outcome == proposal_outcome(&init_b)
    ));

    let operation_b = Uuid::new_v4();
    let commit_b =
        commit_command(repo_b, tenant, issuer, history, 1, operation_b, 1, "refs/heads/b-only", None, oid(3));
    let expected_b_oid = oid(3).as_hex();
    let commit_b_outcome = backend_b.propose(commit_b).await?;
    assert!(proposal_outcome(&commit_b_outcome).is_applied());
    let view_b = backend_b.read_committed_view().await?;
    assert_eq!(view_b.read_ref("refs/heads/b-only").as_deref(), Some(expected_b_oid.as_str()));
    assert!(view_b.read_ref("refs/heads/main").is_none());
    let view_a = backend.read_committed_view().await?;
    assert_eq!(view_a.read_ref("refs/heads/main").as_deref(), Some(expected_oid.as_str()));
    assert!(view_a.read_ref("refs/heads/b-only").is_none());
    assert!(matches!(
        backend_b.propose(commit.clone()).await,
        Err(RaftBackendError::ProposalScopeMismatch("command does not match proposal identity"))
    ));

    phase.set(Phase::LiveAxes);
    // Live realm/gate axes that are not covered by the old static binding: object format,
    // tenant, and a missing repository gate all fail before a view can be minted. These reads
    // still perform a real ReadIndex first and fail on the applied gate afterwards.
    let sha1_realm = RealmBinding::new(tenant, TEST_GROUP, authority, history, 1, 1, GitObjectFormat::Sha1, 1)?;
    let sha1_backend = backend_on(&cluster, leader_id, repo, tenant, sha1_realm, options).await?;
    assert!(matches!(sha1_backend.read_committed_view().await, Err(RaftBackendError::StaleGate("object_format"))));

    let tenant_b = Uuid::new_v4();
    let tenant_b_realm = RealmBinding::new(tenant_b, TEST_GROUP, authority, history, 1, 1, GitObjectFormat::Sha256, 1)?;
    let tenant_b_backend = backend_on(&cluster, leader_id, repo, tenant_b, tenant_b_realm, options).await?;
    assert!(matches!(tenant_b_backend.read_committed_view().await, Err(RaftBackendError::StaleGate("tenant_id"))));

    let repo_c = Uuid::new_v4();
    let repo_c_backend = backend_on(&cluster, leader_id, repo_c, tenant, realm.clone(), options).await?;
    assert!(matches!(repo_c_backend.read_committed_view().await, Err(RaftBackendError::StaleGate("gate_missing"))));

    phase.set(Phase::Snapshot);
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
    let unknown_wire =
        ApplicationCommand::new(ROOT_REF_CAS_DOMAIN, ROOT_REF_CAS_VERSION, b"{bad".to_vec())?.encode()?;
    assert!(
        malformed
            .apply(vec![Entry { log_id: lid(1, 90, 3), payload: EntryPayload::Normal(unknown_wire) }])
            .await
            .is_err()
    );
    assert!(malformed.application_summary().await?.expect("application row").last_applied.is_none());

    // Storage/commit faults remain fatal and never advance the applied coordinate or manufacture a
    // typed business outcome.
    let fault = Arc::new(FaultController::default());
    let faulty_dir = tempfile::tempdir()?;
    let mut faulty = PersistentStateMachine::open_application_with_faults(
        faulty_dir.path(),
        94,
        true,
        Box::new(RootRefCasStateMachine::new()),
        fault.clone(),
    )
    .await?;
    fault.arm(FaultSpec { point: FaultPoint::SmApplySync, mode: FaultMode::Once });
    let noop_payload = encode_command(&RefCasCommand::Noop(NoopCommand { logical_tick: None }))?;
    let noop_envelope = ApplicationCommand::new(ROOT_REF_CAS_DOMAIN, ROOT_REF_CAS_VERSION, noop_payload)?.encode()?;
    assert!(
        faulty
            .apply(vec![Entry { log_id: lid(1, 94, 1), payload: EntryPayload::Normal(noop_envelope) }])
            .await
            .is_err()
    );
    assert!(faulty.application_summary().await?.expect("application row").last_applied.is_none());

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

    phase.set(Phase::Install);
    // Build a real application-mode snapshot from the committed Root state, install it into a
    // fresh SQLite state machine, and reopen that state machine to prove actual Root state restore.
    let leader_snapshot = cluster.node(leader_id).node.build_snapshot().await?;
    let snapshot_meta = leader_snapshot.meta;
    let snapshot_bytes = leader_snapshot.snapshot.into_inner();
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
    let restored_refusal = restored_reducer.query_proposal(&refusal.proposal_id);
    let restored_outcome = match restored_refusal {
        ProposalLookup::Found { original_log_id, outcome, .. } => {
            assert_eq!(original_log_id, refusal.log_id);
            outcome
        }
        other => panic!("refusal did not survive snapshot install: {other:?}"),
    };
    assert!(matches!(
        &restored_outcome,
        RootRefCasOutcome::Refused(refusal) if refusal.kind == RootRefCasRefusalKind::ScopeClosingOrClosed
    ));
    drop(restored);

    phase.set(Phase::Reopen);
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
    let reopened_refusal = reopened_reducer.query_proposal(&refusal.proposal_id);
    assert!(matches!(
        reopened_refusal,
        ProposalLookup::Found { original_log_id, outcome: RootRefCasOutcome::Refused(_), .. }
            if original_log_id == refusal.log_id
    ));

    phase.set(Phase::Partition);
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

    phase.set(Phase::Heal);
    // The live gate, not only the cached realm, must match before a view is minted. A controlled
    // SetRepositoryLane transition is allowed to install a new history/authority realm; old
    // backends then fail on the actual applied gate. The transition command is exempt from the
    // pre-append live-gate read because it is the operation that changes those axes.
    let history_2 = Uuid::new_v4();
    let realm_h2a2 = RealmBinding::new(tenant, TEST_GROUP, authority, history_2, 1, 2, GitObjectFormat::Sha256, 1)?;
    let backend_h2a2 = backend_on(&cluster, healed_leader, repo, tenant, realm_h2a2.clone(), options).await?;
    let change_history_id = backend_h2a2.prepare_proposal_id().await?;
    let change_history = RefCasCommand::SetRepositoryLane(SetRepositoryLaneCommand {
        repository_id: repo,
        tenant_id: tenant,
        lane: RepositoryLane::ServingRefStore,
        lifecycle: ScopeLifecycle::Closing,
        authz_floor: 1,
        history_incarnation: history_2,
        authority_epoch: 2,
        group_epoch: 1,
        pack_mode: SmPackMode::MetadataOnly,
    });
    let change_history_outcome =
        backend_h2a2.propose_with_id(change_history_id.clone(), change_history.clone()).await?;
    assert_eq!(change_history_outcome.decision, ProposalAttemptKind::First);
    assert!(proposal_outcome(&change_history_outcome).is_applied());
    let revision_after_first = backend_h2a2
        .read_committed_view()
        .await?
        .read_gate_version()?
        .expect("live gate after history transition")
        .revision();
    let change_history_replay = backend_h2a2.propose_with_id(change_history_id.clone(), change_history.clone()).await?;
    assert_eq!(change_history_replay.decision, ProposalAttemptKind::Replayed);
    assert_eq!(change_history_replay.original_log_id, Some(change_history_outcome.log_id));
    assert_eq!(proposal_outcome(&change_history_replay), proposal_outcome(&change_history_outcome));
    let revision_after_replay =
        backend_h2a2.read_committed_view().await?.read_gate_version()?.expect("live gate after replay").revision();
    assert_eq!(revision_after_first, revision_after_replay);
    assert!(matches!(
        backend_h2a2.query_proposal(change_history_id.clone()).await?,
        ProposalLookup::Found { original_log_id, outcome, .. }
            if original_log_id == change_history_outcome.log_id
                && &outcome == proposal_outcome(&change_history_outcome)
    ));
    let stale_h1 = backend_on(&cluster, healed_leader, repo, tenant, realm.clone(), options).await?;
    assert!(matches!(
        stale_h1.query_proposal(change_history_id.clone()).await,
        Err(RaftBackendError::ProposalScopeMismatch(_))
    ));
    assert!(matches!(stale_h1.read_committed_view().await, Err(RaftBackendError::StaleGate("history_incarnation"))));

    let realm_h2a3 = RealmBinding::new(tenant, TEST_GROUP, authority, history_2, 1, 3, GitObjectFormat::Sha256, 1)?;
    let backend_h2a3 = backend_on(&cluster, healed_leader, repo, tenant, realm_h2a3, options).await?;
    let change_authority = RefCasCommand::SetRepositoryLane(SetRepositoryLaneCommand {
        repository_id: repo,
        tenant_id: tenant,
        lane: RepositoryLane::ServingRefStore,
        lifecycle: ScopeLifecycle::Closing,
        authz_floor: 1,
        history_incarnation: history_2,
        authority_epoch: 3,
        group_epoch: 1,
        pack_mode: SmPackMode::MetadataOnly,
    });
    let change_authority_outcome = backend_h2a3.propose(change_authority).await?;
    assert!(proposal_outcome(&change_authority_outcome).is_applied());
    assert!(matches!(backend_h2a2.read_committed_view().await, Err(RaftBackendError::StaleGate("authority_epoch"))));

    // A retained First receipt takes precedence over the live fence. Replaying the original H2/A2
    // SetLane after H2/A3 must return the exact original outcome and must not relabel the gate.
    let view_after_h2a3 = backend_h2a3.read_committed_view().await?;
    let revision_before_old_replay = view_after_h2a3.read_gate_version()?.expect("gate H2/A3").revision();
    let floor_before_fences = view_after_h2a3.logical_clock_floor();
    let old_replay_after_h3 = backend_h2a2.propose_with_id(change_history_id.clone(), change_history.clone()).await?;
    assert_eq!(old_replay_after_h3.decision, ProposalAttemptKind::Replayed);
    assert_eq!(old_replay_after_h3.original_log_id, Some(change_history_outcome.log_id));
    assert_eq!(proposal_outcome(&old_replay_after_h3), proposal_outcome(&change_history_outcome));
    let revision_after_old_replay =
        backend_h2a3.read_committed_view().await?.read_gate_version()?.expect("gate H2/A3").revision();
    assert_eq!(revision_before_old_replay, revision_after_old_replay);

    // A fresh old-realm writer cannot revive H1/A1 or regress H2/A2 after H2/A3. These are typed
    // first decisions at apply, not preflight-only checks, and they do not mutate the gate/clock.
    let stale_id = stale_h1.prepare_proposal_id().await?;
    let stale_lane = RefCasCommand::SetRepositoryLane(SetRepositoryLaneCommand {
        repository_id: repo,
        tenant_id: tenant,
        lane: RepositoryLane::ServingRefStore,
        lifecycle: ScopeLifecycle::Closing,
        authz_floor: 1,
        history_incarnation: history,
        authority_epoch: 1,
        group_epoch: 1,
        pack_mode: SmPackMode::MetadataOnly,
    });
    let stale_result = stale_h1.propose_with_id(stale_id, stale_lane).await?;
    assert_eq!(stale_result.decision, ProposalAttemptKind::First);
    assert!(matches!(
        proposal_outcome(&stale_result),
        RootRefCasOutcome::Refused(refusal) if refusal.kind == RootRefCasRefusalKind::GateTransitionRefused
    ));

    let regress_id = backend_h2a2.prepare_proposal_id().await?;
    let regress_lane = RefCasCommand::SetRepositoryLane(SetRepositoryLaneCommand {
        repository_id: repo,
        tenant_id: tenant,
        lane: RepositoryLane::ServingRefStore,
        lifecycle: ScopeLifecycle::Closing,
        authz_floor: 1,
        history_incarnation: history_2,
        authority_epoch: 2,
        group_epoch: 1,
        pack_mode: SmPackMode::MetadataOnly,
    });
    let regress_result = backend_h2a2.propose_with_id(regress_id, regress_lane).await?;
    assert_eq!(regress_result.decision, ProposalAttemptKind::First);
    assert!(matches!(
        proposal_outcome(&regress_result),
        RootRefCasOutcome::Refused(refusal) if refusal.kind == RootRefCasRefusalKind::GateTransitionRefused
    ));

    // The target may be a new history with a strict epoch increase, but SetLane cannot migrate
    // object format. A Sha1 target against the live Sha256 gate is refused.
    let history_3 = Uuid::new_v4();
    let realm_h3a4_sha1 = RealmBinding::new(tenant, TEST_GROUP, authority, history_3, 1, 4, GitObjectFormat::Sha1, 1)?;
    let backend_h3a4_sha1 = backend_on(&cluster, healed_leader, repo, tenant, realm_h3a4_sha1, options).await?;
    let format_id = backend_h3a4_sha1.prepare_proposal_id().await?;
    let format_lane = RefCasCommand::SetRepositoryLane(SetRepositoryLaneCommand {
        repository_id: repo,
        tenant_id: tenant,
        lane: RepositoryLane::ServingRefStore,
        lifecycle: ScopeLifecycle::Closing,
        authz_floor: 1,
        history_incarnation: history_3,
        authority_epoch: 4,
        group_epoch: 1,
        pack_mode: SmPackMode::MetadataOnly,
    });
    let format_result = backend_h3a4_sha1.propose_with_id(format_id, format_lane).await?;
    assert_eq!(format_result.decision, ProposalAttemptKind::First);
    assert!(matches!(
        proposal_outcome(&format_result),
        RootRefCasOutcome::Refused(refusal) if refusal.kind == RootRefCasRefusalKind::GateTransitionRefused
    ));

    // A different history with equal epochs has no UUID ordering and is refused.
    let realm_h3a3 = RealmBinding::new(tenant, TEST_GROUP, authority, history_3, 1, 3, GitObjectFormat::Sha256, 1)?;
    let backend_h3a3 = backend_on(&cluster, healed_leader, repo, tenant, realm_h3a3, options).await?;
    let foreign_id = backend_h3a3.prepare_proposal_id().await?;
    let foreign_lane = RefCasCommand::SetRepositoryLane(SetRepositoryLaneCommand {
        repository_id: repo,
        tenant_id: tenant,
        lane: RepositoryLane::ServingRefStore,
        lifecycle: ScopeLifecycle::Closing,
        authz_floor: 1,
        history_incarnation: history_3,
        authority_epoch: 3,
        group_epoch: 1,
        pack_mode: SmPackMode::MetadataOnly,
    });
    let foreign_result = backend_h3a3.propose_with_id(foreign_id, foreign_lane).await?;
    assert_eq!(foreign_result.decision, ProposalAttemptKind::First);
    assert!(matches!(
        proposal_outcome(&foreign_result),
        RootRefCasOutcome::Refused(refusal) if refusal.kind == RootRefCasRefusalKind::GateTransitionRefused
    ));
    let floor_after_fences = backend_h2a3.read_committed_view().await?.logical_clock_floor();
    assert_eq!(floor_before_fences, floor_after_fences);

    // Concurrent monotonic target preflights cannot overwrite the higher winner backwards. The
    // higher H2/A6 target must win regardless of apply order; the lower H2/A5 may apply first or
    // lose to the monotonic fence.
    let realm_h4a5 = RealmBinding::new(tenant, TEST_GROUP, authority, history_2, 1, 5, GitObjectFormat::Sha256, 1)?;
    let backend_h4a5 = backend_on(&cluster, healed_leader, repo, tenant, realm_h4a5, options).await?;
    let realm_h5a6 = RealmBinding::new(tenant, TEST_GROUP, authority, history_2, 1, 6, GitObjectFormat::Sha256, 1)?;
    let backend_h5a6 = backend_on(&cluster, healed_leader, repo, tenant, realm_h5a6, options).await?;
    let h4_id = backend_h4a5.prepare_proposal_id().await?;
    let h5_id = backend_h5a6.prepare_proposal_id().await?;
    let h4_lane = RefCasCommand::SetRepositoryLane(SetRepositoryLaneCommand {
        repository_id: repo,
        tenant_id: tenant,
        lane: RepositoryLane::ServingRefStore,
        lifecycle: ScopeLifecycle::Closing,
        authz_floor: 1,
        history_incarnation: history_2,
        authority_epoch: 5,
        group_epoch: 1,
        pack_mode: SmPackMode::MetadataOnly,
    });
    let h5_lane = RefCasCommand::SetRepositoryLane(SetRepositoryLaneCommand {
        repository_id: repo,
        tenant_id: tenant,
        lane: RepositoryLane::ServingRefStore,
        lifecycle: ScopeLifecycle::Closing,
        authz_floor: 1,
        history_incarnation: history_2,
        authority_epoch: 6,
        group_epoch: 1,
        pack_mode: SmPackMode::MetadataOnly,
    });
    let (h4_result, h5_result) =
        tokio::join!(backend_h4a5.propose_with_id(h4_id, h4_lane), backend_h5a6.propose_with_id(h5_id, h5_lane),);
    let h4_result = h4_result?;
    let h5_result = h5_result?;
    assert!(proposal_outcome(&h5_result).is_applied());
    assert!(
        proposal_outcome(&h4_result).is_applied()
            || matches!(
                proposal_outcome(&h4_result),
                RootRefCasOutcome::Refused(refusal) if refusal.kind == RootRefCasRefusalKind::GateTransitionRefused
            )
    );
    let final_gate =
        backend_h5a6.read_committed_view().await?.read_gate_version()?.expect("live gate after concurrent transitions");
    assert_eq!(final_gate.history_incarnation(), history_2);
    assert_eq!(final_gate.authority_epoch(), 6);
    assert_eq!(final_gate.group_epoch(), 1);
    assert_eq!(floor_before_fences, backend_h5a6.read_committed_view().await?.logical_clock_floor());

    phase.set(Phase::FinalReopen);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pruned_receipts_export_restore_and_sqlite_reopen() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let repo = Uuid::new_v4();
    let tenant = Uuid::new_v4();
    let history = Uuid::new_v4();
    let authority = Uuid::new_v4();
    let node_id = 211;
    let gate =
        CoreGateInit::new(repo, tenant, GitObjectFormat::Sha256, history, 1, 1, RefName::branch("refs/heads/main")?)?;
    let init = RefCasCommand::InitializeGate(InitializeGateCommand {
        gate: WireGateInit::from(&gate),
        lane: RepositoryLane::ServingRefStore,
        pack_mode: SmPackMode::MetadataOnly,
        authz_floor: 1,
    });
    let id = ProposalId::new(
        repo,
        tenant,
        history,
        TEST_GROUP,
        1,
        authority,
        1,
        1,
        GitObjectFormat::Sha256,
        0,
        Uuid::new_v4(),
    )?;
    let proposal = ProposalEnvelope::encode(&id, &encode_command(&init)?)?;
    let app_command = ApplicationCommand::new(ROOT_REF_CAS_DOMAIN, ROOT_REF_CAS_VERSION, proposal)?.encode()?;

    let mut sm =
        PersistentStateMachine::open_application(dir.path(), node_id, true, Box::new(RootRefCasStateMachine::new()))
            .await?;
    sm.apply(vec![Entry { log_id: lid(1, node_id, 1), payload: EntryPayload::Normal(app_command.clone()) }]).await?;
    for index in 2..=30 {
        sm.apply(vec![Entry::new_blank(lid(1, node_id, index))]).await?;
    }
    sm.apply(vec![Entry { log_id: lid(1, node_id, 31), payload: EntryPayload::Normal(app_command) }]).await?;
    for index in 32..=33 {
        sm.apply(vec![Entry::new_blank(lid(1, node_id, index))]).await?;
    }
    let snapshot = sm.application_snapshot().await?.expect("application state at index 33");
    let reducer = reducer_snapshot(&snapshot);
    assert_eq!(reducer.retained_attempt_count(), 0);
    let exported = reducer.export_state()?;
    let digest = reducer.state_digest_hex()?;
    drop(sm);

    let reopened =
        PersistentStateMachine::open_application(dir.path(), node_id, true, Box::new(RootRefCasStateMachine::new()))
            .await?;
    let snapshot = reopened.application_snapshot().await?.expect("reopened application state");
    let reducer = reducer_snapshot(&snapshot);
    assert_eq!(reducer.retained_attempt_count(), 0);
    assert_eq!(reducer.state_digest_hex()?, digest);
    assert_eq!(reducer.export_state()?, exported);
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
