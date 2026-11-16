//! Real openraft quorum backend and authoritative committed-view minting.

use std::time::Duration;

use openraft::error::{CheckIsLeaderError, ClientWriteError, RaftError};
use openraft::{LogId, Raft};
use rootyard_refcas_log::LogTypeConfig;
use rootyard_refcas_log::state_machine::{
    ApplicationCommand, ApplicationLogId, ApplicationStateMachine, PersistentStateMachine,
};
use tokio::time::Instant;
use uuid::Uuid;

use crate::ref_store::core::state_machine::{RefCasCommand, encode_command};
use crate::ref_store::raft_backend::error::RaftBackendError;
use crate::ref_store::raft_backend::realm::RealmBinding;
use crate::ref_store::raft_backend::reducer::{ROOT_REF_CAS_DOMAIN, ROOT_REF_CAS_VERSION, RootRefCasStateMachine};
use crate::ref_store::raft_backend::scope::validate_command_scope;
use crate::ref_store::raft_backend::view::CommittedRefCasView;

const MAX_DEADLINE: Duration = Duration::from_secs(60);

/// Bounded timeouts for actual quorum and local apply barriers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BackendOptions {
    pub quorum_timeout: Duration,
    pub apply_timeout: Duration,
    pub poll_interval: Duration,
}

impl Default for BackendOptions {
    fn default() -> Self {
        Self {
            quorum_timeout: Duration::from_secs(3),
            apply_timeout: Duration::from_secs(5),
            poll_interval: Duration::from_millis(20),
        }
    }
}

impl BackendOptions {
    fn validate(self) -> Result<Self, RaftBackendError> {
        if self.quorum_timeout.is_zero() || self.quorum_timeout > MAX_DEADLINE {
            return Err(RaftBackendError::InvalidConfig("quorum_timeout must be in (0, 60s]"));
        }
        if self.apply_timeout.is_zero() || self.apply_timeout > MAX_DEADLINE {
            return Err(RaftBackendError::InvalidConfig("apply_timeout must be in (0, 60s]"));
        }
        if self.poll_interval.is_zero() || self.poll_interval > Duration::from_secs(1) {
            return Err(RaftBackendError::InvalidConfig("poll_interval must be in (0, 1s]"));
        }
        Ok(self)
    }
}

/// Backend bound to exactly one repository, tenant, and trusted realm on one real openraft node.
#[derive(Clone)]
pub struct RootRaftRefCasBackend {
    raft: Raft<LogTypeConfig>,
    sm: PersistentStateMachine,
    repository_id: Uuid,
    tenant_id: Uuid,
    realm: RealmBinding,
    options: BackendOptions,
}

impl RootRaftRefCasBackend {
    /// Binds a real Raft handle and application-mode persistent state machine to trusted scope.
    ///
    /// The constructor refuses a KV-mode state machine, a different reducer, mismatched realm
    /// tenant, nil ids, or unbounded deadlines. It performs no network read and mints no view.
    pub async fn open(
        raft: Raft<LogTypeConfig>,
        sm: PersistentStateMachine,
        repository_id: Uuid,
        tenant_id: Uuid,
        realm: RealmBinding,
        options: BackendOptions,
    ) -> Result<Self, RaftBackendError> {
        if repository_id.is_nil() || tenant_id.is_nil() {
            return Err(RaftBackendError::InvalidConfig("repository and tenant ids must be non-nil"));
        }
        if realm.tenant_id() != tenant_id {
            return Err(RaftBackendError::InvalidConfig("realm tenant differs from backend tenant"));
        }
        let options = options.validate()?;
        let node_summary = sm.summary().await.map_err(|_| RaftBackendError::Storage("state-machine summary"))?;
        if node_summary.node_id != raft.metrics().borrow().id {
            return Err(RaftBackendError::InvalidConfig("raft node id differs from persistent state-machine node id"));
        }
        let summary = sm
            .application_summary()
            .await
            .map_err(|_| RaftBackendError::Storage("application summary"))?
            .ok_or(RaftBackendError::NotApplicationMode)?;
        if summary.domain != ROOT_REF_CAS_DOMAIN || summary.version != ROOT_REF_CAS_VERSION {
            return Err(RaftBackendError::WrongReducer);
        }
        Ok(Self { raft, sm, repository_id, tenant_id, realm, options })
    }

    pub fn repository_id(&self) -> Uuid {
        self.repository_id
    }

    pub fn tenant_id(&self) -> Uuid {
        self.tenant_id
    }

    pub fn realm(&self) -> &RealmBinding {
        &self.realm
    }

    /// Proposes one Root Ref-CAS business command through the real Raft WAL/quorum path.
    ///
    /// A follower returns `FollowerRedirect`; a timeout/minority returns `QuorumUnavailable`.
    /// There is no direct local state-machine write or PostgreSQL fallback.
    ///
    /// This validates canonical codec bounds and the trusted repository/tenant/realm scope only.
    /// Production business prevalidation (live authorization, expected revision/policy, pack
    /// closure) must happen before this call; a deterministic RSM refusal is an openraft apply
    /// error. That prevalidation/HTTP boundary is a later qualification task, not claimed here.
    pub async fn propose(&self, command: RefCasCommand) -> Result<ApplicationLogId, RaftBackendError> {
        validate_command_scope(&command, self.repository_id, self.tenant_id, &self.realm)?;
        let payload =
            encode_command(&command).map_err(|_| RaftBackendError::Encode("root Ref-CAS command codec refused"))?;
        let envelope = ApplicationCommand::new(ROOT_REF_CAS_DOMAIN, ROOT_REF_CAS_VERSION, payload)
            .map_err(|_| RaftBackendError::Encode("application envelope bounds refused"))?
            .encode()
            .map_err(|_| RaftBackendError::Encode("application envelope codec refused"))?;

        match tokio::time::timeout(self.options.quorum_timeout, self.raft.client_write(envelope)).await {
            Ok(Ok(response)) => Ok(ApplicationLogId::from_log_id(response.log_id)),
            Ok(Err(RaftError::APIError(ClientWriteError::ForwardToLeader(fwd)))) => {
                Err(RaftBackendError::FollowerRedirect(fwd.leader_id))
            }
            Ok(Err(_)) => Err(RaftBackendError::QuorumUnavailable("client write")),
            Err(_) => Err(RaftBackendError::QuorumUnavailable("client write timeout")),
        }
    }

    /// Mints an authoritative view only after a real quorum ReadIndex and local apply barrier.
    pub async fn read_committed_view(&self) -> Result<CommittedRefCasView, RaftBackendError> {
        self.read_committed_view_for(&self.realm).await
    }

    /// Same as [`Self::read_committed_view`], but first verifies a caller-presented trusted realm.
    ///
    /// A stale realm/epoch/storage generation fails before any quorum or local read.
    pub async fn read_committed_view_for(
        &self,
        presented: &RealmBinding,
    ) -> Result<CommittedRefCasView, RaftBackendError> {
        if presented != &self.realm {
            return Err(RaftBackendError::StaleRealm);
        }
        let read_log_id = match tokio::time::timeout(self.options.quorum_timeout, self.raft.ensure_linearizable()).await
        {
            Ok(Ok(read_log_id)) => read_log_id,
            Ok(Err(RaftError::APIError(CheckIsLeaderError::ForwardToLeader(fwd)))) => {
                return Err(RaftBackendError::FollowerRedirect(fwd.leader_id));
            }
            Ok(Err(_)) => return Err(RaftBackendError::QuorumUnavailable("read index")),
            Err(_) => return Err(RaftBackendError::QuorumUnavailable("read index timeout")),
        };

        self.await_applied_and_mint(read_log_id).await
    }

    async fn await_applied_and_mint(
        &self,
        read_log_id: Option<LogId<u64>>,
    ) -> Result<CommittedRefCasView, RaftBackendError> {
        let required = read_log_id.map(ApplicationLogId::from_log_id);
        let deadline = Instant::now() + self.options.apply_timeout;
        loop {
            let snapshot = self
                .sm
                .application_snapshot()
                .await
                .map_err(|_| RaftBackendError::Storage("application snapshot"))?
                .ok_or(RaftBackendError::NotApplicationMode)?;
            if snapshot.summary.domain != ROOT_REF_CAS_DOMAIN || snapshot.summary.version != ROOT_REF_CAS_VERSION {
                return Err(RaftBackendError::WrongReducer);
            }
            let applied = snapshot.applied.map(ApplicationLogId::from_log_id);
            if required.is_none_or(|required| applied.is_some_and(|applied| applied.index >= required.index)) {
                let reducer = snapshot
                    .reducer
                    .as_any()
                    .downcast_ref::<RootRefCasStateMachine>()
                    .ok_or(RaftBackendError::WrongReducer)?;
                if reducer.last_applied() != applied {
                    return Err(RaftBackendError::Storage("root reducer coordinate mismatch"));
                }
                return Ok(CommittedRefCasView::mint(
                    reducer.machine().clone(),
                    applied,
                    self.repository_id,
                    self.tenant_id,
                    self.realm.clone(),
                ));
            }
            if Instant::now() >= deadline {
                return Err(RaftBackendError::ApplyBarrierTimeout { applied, required });
            }
            tokio::time::sleep(self.options.poll_interval).await;
        }
    }
}
