//! Owned real Raft node factory: the Raft handle and its application state machine are created
//! together from one store directory, so a caller cannot attach an unrelated same-node-id SM.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use openraft::storage::{RaftSnapshotBuilder, RaftStateMachine};
use openraft::{BasicNode, Config, Raft, RaftMetrics, Snapshot};
use rootyard_refcas_log::cluster::{MtlsNetworkFactory, RpcRequest, RpcResponse};
use rootyard_refcas_log::state_machine::PersistentStateMachine;
use rootyard_refcas_log::{LogTypeConfig, PersistentLog};

use crate::ref_store::raft_backend::backend::{BackendOptions, read_scope_drain as read_scope_drain_from_node};
use crate::ref_store::raft_backend::error::RaftBackendError;
use crate::ref_store::raft_backend::realm::NodeTrust;
use crate::ref_store::raft_backend::reducer::{ROOT_REF_CAS_DOMAIN, ROOT_REF_CAS_VERSION, RootRefCasStateMachine};
use crate::ref_store::raft_backend::scope_close_requirement::ScopeCloseRequirement;
use crate::ref_store::raft_backend::scope_drain::CommittedScopeDrain;

/// Inputs for one owned, real mTLS Raft node. No state-machine handle is accepted; the factory
/// opens the log and application state machine from `store_dir` itself.
pub struct RootRaftNodeConfig {
    pub node_id: u64,
    pub store_dir: PathBuf,
    pub raft_config: Arc<Config>,
    pub network: MtlsNetworkFactory,
    pub check_on_open: bool,
    pub trust: NodeTrust,
}

/// Cohesive Raft/application-SM pair created by [`RootRaftNode::start`].
#[derive(Clone)]
pub struct RootRaftNode {
    node_id: u64,
    raft: Raft<LogTypeConfig>,
    sm: PersistentStateMachine,
    trust: NodeTrust,
}

impl RootRaftNode {
    /// Opens the persistent log and application SM from `store_dir`, then constructs Raft with
    /// that exact SM clone. The raw `open(raft, sm, ...)` pair constructor no longer exists.
    pub async fn start(config: RootRaftNodeConfig) -> Result<Self, RaftBackendError> {
        let log = PersistentLog::open(&config.store_dir, config.node_id, config.check_on_open)
            .await
            .map_err(|_| RaftBackendError::Storage("open persistent Raft log"))?;
        let sm = PersistentStateMachine::open_application(
            &config.store_dir,
            config.node_id,
            config.check_on_open,
            Box::new(RootRefCasStateMachine::new()),
        )
        .await
        .map_err(|_| RaftBackendError::Storage("open owned application state machine"))?;
        let node_summary = sm.summary().await.map_err(|_| RaftBackendError::Storage("owned state-machine summary"))?;
        if node_summary.node_id != config.node_id {
            return Err(RaftBackendError::InvalidConfig("owned state-machine node id differs from factory node id"));
        }
        let app_summary = sm
            .application_summary()
            .await
            .map_err(|_| RaftBackendError::Storage("owned application summary"))?
            .ok_or(RaftBackendError::NotApplicationMode)?;
        if app_summary.domain != ROOT_REF_CAS_DOMAIN || app_summary.version != ROOT_REF_CAS_VERSION {
            return Err(RaftBackendError::WrongReducer);
        }
        let raft = Raft::new(config.node_id, config.raft_config, config.network, log, sm.clone())
            .await
            .map_err(|_| RaftBackendError::NodeStart("create owned Raft node"))?;
        Ok(Self { node_id: config.node_id, raft, sm, trust: config.trust })
    }

    pub fn node_id(&self) -> u64 {
        self.node_id
    }

    pub fn trust(&self) -> &NodeTrust {
        &self.trust
    }

    /// Privileged group-level control read: current committed scope drain for one bound close
    /// requirement.
    ///
    /// The whole `NodeTrust` and Root application domain/version are checked before any quorum or
    /// numerical barrier. This performs an actual openraft `ReadIndex` and an atomic applied
    /// barrier before reading the owned reducer's complete `(scope_kind, scope_id)` drain. It is
    /// deliberately exposed only on the trusted node/control surface, not on a repository-scoped
    /// committed view. The result is a current-state observation, not a reconstruction of an
    /// earlier close receipt's lists.
    pub async fn read_scope_drain(
        &self,
        requirement: &ScopeCloseRequirement,
        options: BackendOptions,
    ) -> Result<CommittedScopeDrain, RaftBackendError> {
        read_scope_drain_from_node(self, requirement, options).await
    }

    /// Raw Raft handle is crate-private. External callers get only the narrow control/peer-RPC
    /// methods below, and never the application state machine.
    pub(crate) fn raft(&self) -> Raft<LogTypeConfig> {
        self.raft.clone()
    }

    /// Privileged host control: initialize the real cluster membership.
    pub async fn initialize_cluster(&self, members: BTreeMap<u64, BasicNode>) -> Result<(), RaftBackendError> {
        self.raft
            .initialize(members)
            .await
            .map_err(|_| RaftBackendError::NodeControl("initialize cluster membership"))?;
        Ok(())
    }

    /// Narrow peer RPC surface: only vote, append-entries, and install-snapshot. Business writes,
    /// reads, control mutations, and fault injection are not exposed through this method.
    pub async fn handle_peer_rpc(&self, request: RpcRequest) -> RpcResponse {
        match request {
            RpcRequest::Vote(vote) => RpcResponse::Vote(Box::new(self.raft.vote(vote).await)),
            RpcRequest::AppendEntries(append) => {
                RpcResponse::AppendEntries(Box::new(self.raft.append_entries(append).await))
            }
            RpcRequest::InstallSnapshot(snapshot) => {
                RpcResponse::InstallSnapshot(Box::new(self.raft.install_snapshot(snapshot).await))
            }
            _ => RpcResponse::Error {
                message: "owned node permits only peer vote/append/install RPC".into(),
                forward_to_leader_id: None,
            },
        }
    }

    pub fn metrics(&self) -> RaftMetrics<u64, BasicNode> {
        self.raft.metrics().borrow().clone()
    }

    /// Builds an actual application/SQLite snapshot from this owned node's exact SM.
    pub async fn build_snapshot(&self) -> Result<Snapshot<LogTypeConfig>, RaftBackendError> {
        let mut sm = self.sm.clone();
        let mut builder = sm.get_snapshot_builder().await;
        builder.build_snapshot().await.map_err(|_| RaftBackendError::Storage("build owned application snapshot"))
    }

    pub async fn shutdown(&self) -> Result<(), RaftBackendError> {
        self.raft.shutdown().await.map_err(|_| RaftBackendError::NodeShutdown("shutdown owned Raft node"))
    }

    pub(crate) fn sm(&self) -> &PersistentStateMachine {
        &self.sm
    }
}
