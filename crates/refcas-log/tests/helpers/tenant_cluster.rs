//! Multi-node mTLS Raft cluster + custom X.509 SAN PKI fixture for tenant RPC integration tests.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use openraft::{BasicNode, Config, Raft, ServerState, SnapshotPolicy};
use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType};
use tokio::net::TcpListener;
use tokio::sync::watch;

use rootyard_refcas_log::cluster::{
    MtlsNetworkFactory, PeerDirectory, RpcRequest, RpcResponse, read_frame_async, write_frame_async,
};
use rootyard_refcas_log::mtls::{
    CLIENT_DNS_NAME, MtlsClient, MtlsPaths, MtlsServer, PeerIdentity, RpcCapability, node_dns_name,
    tenant_client_dns_name, tenant_scope_uri,
};
use rootyard_refcas_log::state_machine::PersistentStateMachine;
use rootyard_refcas_log::tenant_rpc::{
    GroupRealmRegistry, RealmEpoch, TenantRpcServer, TenantServerConfig, format_scoped_bearer_token,
};
use rootyard_refcas_log::{LogTypeConfig, PersistentLog};

pub const TENANT_A: &str = "11111111-1111-4111-8111-111111111111";
pub const TENANT_B: &str = "22222222-2222-4222-8222-222222222222";
pub const AUTH_1: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
pub const AUTH_2: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
pub const HIST_1: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
pub const HIST_2: &str = "dddddddd-dddd-4ddd-8ddd-dddddddddddd";
pub const GROUP_ALPHA: &str = "group-alpha";
pub const GROUP_BETA: &str = "group-beta";

pub fn realm(
    tenant_id: &str,
    group_id: &str,
    authority_id: &str,
    history_id: &str,
    epoch: u64,
    storage_gen: u64,
) -> RealmEpoch {
    RealmEpoch {
        tenant_id: tenant_id.to_owned(),
        group_id: group_id.to_owned(),
        authority_id: authority_id.to_owned(),
        history_id: history_id.to_owned(),
        group_epoch: epoch,
        storage_generation: storage_gen,
    }
}

pub fn default_realm() -> RealmEpoch {
    realm(TENANT_A, GROUP_ALPHA, AUTH_1, HIST_1, 3, 7)
}

pub fn token(tenant_id: &str, group_id: &str, authority_id: &str, cap: RpcCapability) -> String {
    format_scoped_bearer_token(tenant_id, group_id, authority_id, cap).unwrap()
}

pub fn read_der(pem_path: &Path) -> Vec<u8> {
    let f = std::fs::File::open(pem_path).unwrap();
    let mut r = std::io::BufReader::new(f);
    rustls_pemfile::certs(&mut r).next().unwrap().unwrap().to_vec()
}

pub struct TenantPki {
    dir: tempfile::TempDir,
    ca_cert_path: PathBuf,
    ca_key: KeyPair,
    ca_params: CertificateParams,
}

impl TenantPki {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("pki dir");
        let (ca_key, ca_params, ca_cert_path) = write_ca(dir.path(), "tenant-cluster-ca");
        Self { dir, ca_cert_path, ca_key, ca_params }
    }

    pub fn node_paths(&self, node_id: u64) -> MtlsPaths {
        let san = vec![SanType::DnsName(node_dns_name(node_id).try_into().unwrap())];
        self.issue(&format!("node-{node_id}"), san)
    }

    pub fn generic_client_paths(&self) -> MtlsPaths {
        let san = vec![SanType::DnsName(CLIENT_DNS_NAME.to_owned().try_into().unwrap())];
        self.issue("generic-client", san)
    }

    pub fn tenant_paths(&self, tag: &str, tenant_id: &str, group_id: &str, caps: &[RpcCapability]) -> MtlsPaths {
        let dns = tenant_client_dns_name(tenant_id).unwrap();
        let cap_set: BTreeSet<RpcCapability> = caps.iter().copied().collect();
        let uri = tenant_scope_uri(tenant_id, group_id, &cap_set).unwrap();
        self.issue_san_strings(tag, vec![dns], vec![uri])
    }

    pub fn issue_san_strings(&self, tag: &str, dns_list: Vec<String>, uri_list: Vec<String>) -> MtlsPaths {
        let mut sans = Vec::new();
        for d in dns_list {
            sans.push(SanType::DnsName(d.try_into().expect("valid dns ia5")));
        }
        for u in uri_list {
            sans.push(SanType::URI(u.try_into().expect("valid uri ia5")));
        }
        self.issue(tag, sans)
    }

    pub fn issue_untrusted(&self, tag: &str, dns: &str, uri: &str) -> MtlsPaths {
        let (rogue_key, rogue_params, rogue_ca_path) = write_ca(self.dir.path(), &format!("rogue-{tag}"));
        let issuer = CertifiedIssuer::self_signed(rogue_params, rogue_key).unwrap();
        let sans = vec![
            SanType::DnsName(dns.to_owned().try_into().unwrap()),
            SanType::URI(uri.to_owned().try_into().unwrap()),
        ];
        let mut paths = sign_san_leaf(self.dir.path(), &format!("rogue-leaf-{tag}"), &issuer, &rogue_ca_path, sans);
        paths.ca_cert = self.ca_cert_path.clone();
        paths
    }

    pub fn client_from(&self, paths: &MtlsPaths) -> MtlsClient {
        MtlsClient::from_paths(paths).expect("build mtls client")
    }

    fn issue(&self, tag: &str, sans: Vec<SanType>) -> MtlsPaths {
        let key_clone = KeyPair::from_pem(&self.ca_key.serialize_pem()).unwrap();
        let issuer = CertifiedIssuer::self_signed(self.ca_params.clone(), key_clone).unwrap();
        sign_san_leaf(self.dir.path(), tag, &issuer, &self.ca_cert_path, sans)
    }
}

fn write_ca(dir: &Path, name: &str) -> (KeyPair, CertificateParams, PathBuf) {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(rcgen::DnType::CommonName, name);
    let key_copy = KeyPair::from_pem(&key.serialize_pem()).unwrap();
    let issuer = CertifiedIssuer::self_signed(params.clone(), key_copy).unwrap();
    let ca_path = dir.join(format!("{name}.crt"));
    std::fs::write(&ca_path, issuer.pem()).unwrap();
    (key, params, ca_path)
}

fn sign_san_leaf(
    dir: &Path,
    stem: &str,
    ca: &CertifiedIssuer<'_, KeyPair>,
    ca_path: &Path,
    sans: Vec<SanType>,
) -> MtlsPaths {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::default();
    params.subject_alt_names = sans;
    params.is_ca = IsCa::ExplicitNoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth, ExtendedKeyUsagePurpose::ClientAuth];
    let cert = params.signed_by(&key, ca).unwrap();
    let cert_path = dir.join(format!("{stem}.crt"));
    let key_path = dir.join(format!("{stem}.key"));
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    MtlsPaths { ca_cert: ca_path.to_path_buf(), cert: cert_path, key: key_path }
}

pub struct ClusterNode {
    pub id: u64,
    pub _dir: tempfile::TempDir,
    pub raft_addr: String,
    pub raft: Raft<LogTypeConfig>,
    pub rpc_server: TenantRpcServer,
    pub peer_dir: PeerDirectory,
    pub registry: Arc<RwLock<GroupRealmRegistry>>,
    peer_stop: watch::Sender<bool>,
}

pub struct TenantTestCluster {
    pub pki: TenantPki,
    pub nodes: Vec<ClusterNode>,
}

impl TenantTestCluster {
    pub async fn start_three(initial_epoch: RealmEpoch) -> Self {
        let pki = TenantPki::new();
        let tenant_peers = PeerDirectory::new();
        let mut nodes = Vec::new();
        let mut raft_map = BTreeMap::new();

        for id in [1_u64, 2, 3] {
            let dir = tempfile::tempdir().unwrap();
            let paths = pki.node_paths(id);
            let mtls_srv = MtlsServer::from_paths(&paths).unwrap();
            let mtls_cli = MtlsClient::from_paths(&paths).unwrap();
            let peer_dir = PeerDirectory::new();

            let log = PersistentLog::open(dir.path(), id, true).await.unwrap();
            let sm = PersistentStateMachine::open(dir.path(), id, true).await.unwrap();
            let cfg = Arc::new(
                Config {
                    cluster_name: "tenant-rpc-test".into(),
                    heartbeat_interval: 60,
                    election_timeout_min: 220,
                    election_timeout_max: 450,
                    snapshot_policy: SnapshotPolicy::LogsSinceLast(2_000),
                    ..Default::default()
                }
                .validate()
                .unwrap(),
            );
            let net = MtlsNetworkFactory::new(peer_dir.clone(), mtls_cli);
            let raft = Raft::new(id, cfg, net, log, sm.clone()).await.unwrap();

            let peer_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let raft_addr = peer_listener.local_addr().unwrap().to_string();
            raft_map.insert(id, raft_addr.clone());

            let (peer_stop, mut stop_rx) = watch::channel(false);
            let p_raft = raft.clone();
            let p_dirs = peer_dir.clone();
            let p_tls = mtls_srv.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        _ = stop_rx.changed() => { if *stop_rx.borrow() { break; } }
                        res = peer_listener.accept() => {
                            let Ok((tcp, _)) = res else { break };
                            let r = p_raft.clone();
                            let d = p_dirs.clone();
                            let t = p_tls.clone();
                            tokio::spawn(async move {
                                let Ok((mut tls, id)) = t.accept(tcp).await else { return };
                                if let PeerIdentity::Node(sid) = id
                                    && d.is_blocked(sid)
                                {
                                    return;
                                }
                                while let Ok(Some(req)) = read_frame_async::<_, RpcRequest>(&mut tls).await {
                                    if let PeerIdentity::Node(sid) = id
                                        && d.is_blocked(sid)
                                    {
                                        break;
                                    }
                                    let resp = match (id, req) {
                                        (PeerIdentity::Node(sid), RpcRequest::Vote(v)) if v.vote.leader_id.node_id == sid => {
                                            RpcResponse::Vote(Box::new(r.vote(v).await))
                                        }
                                        (PeerIdentity::Node(sid), RpcRequest::AppendEntries(a)) if a.vote.leader_id.node_id == sid => {
                                            RpcResponse::AppendEntries(Box::new(r.append_entries(a).await))
                                        }
                                        (PeerIdentity::Node(sid), RpcRequest::InstallSnapshot(s)) if s.vote.leader_id.node_id == sid => {
                                            RpcResponse::InstallSnapshot(Box::new(r.install_snapshot(s).await))
                                        }
                                        _ => RpcResponse::Error { message: "unauthorized peer rpc".into(), forward_to_leader_id: None },
                                    };
                                    if write_frame_async(&mut tls, &resp).await.is_err() { break; }
                                }
                            });
                        }
                    }
                }
            });

            let mut reg = GroupRealmRegistry::new(&initial_epoch.group_id);
            reg.upsert_tenant(initial_epoch.clone());
            let registry = Arc::new(RwLock::new(reg));

            let srv_cfg = TenantServerConfig {
                node_id: id,
                mtls: mtls_srv,
                tenant_peers: tenant_peers.clone(),
                registry: registry.clone(),
                quorum_timeout: Duration::from_millis(1_000),
                write_timeout: Duration::from_millis(2_000),
            };
            let rpc_server = TenantRpcServer::spawn(raft.clone(), sm, srv_cfg).await.unwrap();

            nodes.push(ClusterNode { id, _dir: dir, raft_addr, raft, rpc_server, peer_dir, registry, peer_stop });
        }

        let mut init_nodes = BTreeMap::new();
        for (id, addr) in &raft_map {
            init_nodes.insert(*id, BasicNode { addr: addr.clone() });
        }
        for n in &nodes {
            n.peer_dir.update(raft_map.clone());
        }
        nodes[0].raft.initialize(init_nodes).await.unwrap();

        let cluster = Self { pki, nodes };
        cluster.wait_leader(Duration::from_secs(15)).await;
        cluster
    }

    pub async fn wait_leader(&self, timeout: Duration) -> (u64, u64) {
        let stop = Instant::now() + timeout;
        while Instant::now() < stop {
            let leader_term = self.nodes.iter().find_map(|n| {
                let m = n.raft.metrics().borrow().clone();
                (m.state == ServerState::Leader && m.current_leader == Some(n.id) && m.current_term > 0)
                    .then_some((n.id, m.current_term))
            });
            if let Some((lid, term)) = leader_term {
                let all_ready = self.nodes.iter().all(|n| {
                    let m = n.raft.metrics().borrow().clone();
                    m.current_leader == Some(lid)
                        && m.last_applied.is_some()
                        && m.membership_config.membership().voter_ids().count() == 3
                });
                if all_ready {
                    return (lid, term);
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("cluster did not elect a converged leader within {timeout:?}");
    }

    pub async fn wait_leader_excluding(&self, excluded_id: u64, min_term: u64, timeout: Duration) -> (u64, u64) {
        let stop = Instant::now() + timeout;
        while Instant::now() < stop {
            for n in &self.nodes {
                if n.id == excluded_id {
                    continue;
                }
                let m = n.raft.metrics().borrow().clone();
                if m.state == ServerState::Leader && m.current_leader == Some(n.id) && m.current_term >= min_term {
                    let peer_agrees = self.nodes.iter().any(|p| {
                        p.id != excluded_id && p.id != n.id && p.raft.metrics().borrow().current_leader == Some(n.id)
                    });
                    if peer_agrees {
                        return (n.id, m.current_term);
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("cluster did not elect replacement leader excluding {excluded_id} within {timeout:?}");
    }

    pub fn node(&self, id: u64) -> &ClusterNode {
        self.nodes.iter().find(|n| n.id == id).expect("node id exists")
    }

    pub fn first_follower_id(&self, leader_id: u64) -> u64 {
        self.nodes.iter().find(|n| n.id != leader_id).unwrap().id
    }

    pub fn partition_node(&self, isolated_id: u64) {
        let all_others: BTreeSet<u64> = self.nodes.iter().map(|n| n.id).filter(|&i| i != isolated_id).collect();
        let iso_set = BTreeSet::from([isolated_id]);
        for n in &self.nodes {
            if n.id == isolated_id {
                n.peer_dir.set_blocked(all_others.clone());
            } else {
                n.peer_dir.set_blocked(iso_set.clone());
            }
        }
    }

    pub fn heal_partitions(&self) {
        for n in &self.nodes {
            n.peer_dir.set_blocked(BTreeSet::new());
        }
    }

    pub async fn shutdown(self) {
        for n in self.nodes {
            n.rpc_server.shutdown();
            let _ = n.peer_stop.send(true);
            let _ = n.raft.shutdown().await;
        }
    }
}
