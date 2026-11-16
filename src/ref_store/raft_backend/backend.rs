//! Real openraft quorum backend and authoritative committed-view minting.

use std::time::Duration;

use openraft::LogId;
use openraft::error::{CheckIsLeaderError, ClientWriteError, RaftError};
use rootyard_refcas_log::state_machine::{
    ApplicationCommand, ApplicationLogId, ApplicationRuntimeSnapshot, ApplicationStateMachine,
};
use tokio::time::Instant;
use uuid::Uuid;

use crate::ref_store::core::state_machine::{RefCasCommand, encode_command};
use crate::ref_store::raft_backend::error::RaftBackendError;
use crate::ref_store::raft_backend::node::RootRaftNode;
use crate::ref_store::raft_backend::proposal::{
    ProposalAttemptKind, ProposalEnvelope, ProposalId, ProposalLookup, ProposalOutcome, command_digest_hex,
};
use crate::ref_store::raft_backend::realm::RealmBinding;
use crate::ref_store::raft_backend::reducer::{ROOT_REF_CAS_DOMAIN, ROOT_REF_CAS_VERSION, RootRefCasStateMachine};
use crate::ref_store::raft_backend::scope::{requires_live_gate_precheck, validate_command_scope};
use crate::ref_store::raft_backend::scope_close_requirement::{
    ScopeCloseRequirement, scope_close_requirement_from_lookup,
};
use crate::ref_store::raft_backend::scope_drain::CommittedScopeDrain;
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
    pub(crate) fn validate(self) -> Result<Self, RaftBackendError> {
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
    node: RootRaftNode,
    repository_id: Uuid,
    tenant_id: Uuid,
    realm: RealmBinding,
    options: BackendOptions,
}

impl RootRaftRefCasBackend {
    /// Binds one **owned** Raft/application-SM pair to trusted repository/tenant/realm scope.
    ///
    /// There is deliberately no raw `(Raft, PersistentStateMachine)` constructor. The node
    /// factory opens both stores in one directory and constructs Raft with that exact SM, so a
    /// same-node-id but unrelated local SM cannot be attached accidentally.
    ///
    /// The realm's `group_id`, `authority_id`, and `storage_generation` are checked against the
    /// owned node/factory trust identity. They are explicitly factory/storage configuration, not
    /// inferred from Raft membership.
    ///
    /// ```compile_fail
    /// # use rootyard::ref_store::raft_backend::RootRaftRefCasBackend;
    /// # async fn old_raw_pair(
    /// #     raft: openraft::Raft<rootyard_refcas_log::LogTypeConfig>,
    /// #     sm: rootyard_refcas_log::state_machine::PersistentStateMachine,
    /// # ) {
    /// let _ = RootRaftRefCasBackend::open(
    ///     raft,
    ///     sm,
    ///     uuid::Uuid::nil(),
    ///     uuid::Uuid::nil(),
    ///     todo!(),
    ///     todo!(),
    /// )
    /// .await;
    /// # }
    /// ```
    pub async fn open(
        node: RootRaftNode,
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
        if realm.group_id() != node.trust().group_id() {
            return Err(RaftBackendError::InvalidConfig("realm group_id differs from owned node trust"));
        }
        if realm.authority_id() != node.trust().authority_id() {
            return Err(RaftBackendError::InvalidConfig("realm authority_id differs from owned node trust"));
        }
        if realm.storage_generation() != node.trust().storage_generation() {
            return Err(RaftBackendError::InvalidConfig(
                "realm storage_generation differs from owned node storage generation",
            ));
        }
        let options = options.validate()?;
        let summary = node
            .sm()
            .application_summary()
            .await
            .map_err(|_| RaftBackendError::Storage("application summary"))?
            .ok_or(RaftBackendError::NotApplicationMode)?;
        if summary.domain != ROOT_REF_CAS_DOMAIN || summary.version != ROOT_REF_CAS_VERSION {
            return Err(RaftBackendError::WrongReducer);
        }
        Ok(Self { node, repository_id, tenant_id, realm, options })
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

    /// Prepares a caller-stable proposal identity at the current applied coordinate.
    ///
    /// This performs the actual quorum ReadIndex plus local applied barrier but deliberately does
    /// not validate or mint a ref view, so it also works before `InitializeGate` exists.
    pub async fn prepare_proposal_id(&self) -> Result<ProposalId, RaftBackendError> {
        let read_log_id = ensure_linearizable_read(
            &self.node,
            self.options.quorum_timeout,
            "prepare read index",
            "prepare read index timeout",
        )
        .await?;
        let snapshot = self.await_applied_snapshot(read_log_id.map(ApplicationLogId::from_log_id)).await?;
        let issued_at_index =
            snapshot.applied.map(ApplicationLogId::from_log_id).map(|coordinate| coordinate.index).unwrap_or(0);
        ProposalId::new(
            self.repository_id,
            self.tenant_id,
            self.realm.history_id(),
            self.realm.group_id().to_owned(),
            self.realm.group_epoch(),
            self.realm.authority_id(),
            self.realm.authority_epoch(),
            self.realm.storage_generation(),
            self.realm.object_format(),
            issued_at_index,
            Uuid::new_v4(),
        )
        .map_err(|_| RaftBackendError::InvalidProposal("proposal identity construction failed"))
    }

    /// Proposes one command under a caller-stable proposal identity.
    ///
    /// The identity is the invocation identity. Same ID and canonical digest never execute the
    /// business command again; a different digest is a typed conflict. The fixed expiry is not
    /// refreshed by retries.
    pub async fn propose_with_id(
        &self,
        proposal_id: ProposalId,
        command: RefCasCommand,
    ) -> Result<ProposalOutcome, RaftBackendError> {
        self.validate_proposal_scope(&proposal_id)?;
        if !proposal_id.matches_command(&command) {
            return Err(RaftBackendError::ProposalScopeMismatch("command does not match proposal identity"));
        }
        validate_command_scope(&command, self.repository_id, self.tenant_id, &self.realm)?;
        if requires_live_gate_precheck(&command) {
            self.read_committed_view().await?;
        }
        let command_payload =
            encode_command(&command).map_err(|_| RaftBackendError::Encode("root Ref-CAS command codec refused"))?;
        let digest_hex = command_digest_hex(&command_payload);
        let proposal_payload = ProposalEnvelope::encode(&proposal_id, &command_payload)
            .map_err(|_| RaftBackendError::Encode("proposal envelope bounds refused"))?;
        let envelope = ApplicationCommand::new(ROOT_REF_CAS_DOMAIN, ROOT_REF_CAS_VERSION, proposal_payload)
            .map_err(|_| RaftBackendError::Encode("application envelope bounds refused"))?
            .encode()
            .map_err(|_| RaftBackendError::Encode("application envelope codec refused"))?;

        let raft = self.node.raft();
        match tokio::time::timeout(self.options.quorum_timeout, raft.client_write(envelope)).await {
            Ok(Ok(response)) => {
                let log_id = ApplicationLogId::from_log_id(response.log_id);
                let snapshot = self.await_applied_snapshot(Some(log_id)).await?;
                let reducer = snapshot
                    .reducer
                    .as_any()
                    .downcast_ref::<RootRefCasStateMachine>()
                    .ok_or(RaftBackendError::WrongReducer)?;
                if let Some(attempt) = reducer.query_attempt(log_id) {
                    if attempt.command_digest_hex != digest_hex {
                        return Err(RaftBackendError::OutcomeDigestMismatch(log_id));
                    }
                    return Ok(ProposalOutcome::from_attempt(proposal_id, log_id, attempt));
                }
                match reducer.query_proposal(&proposal_id) {
                    ProposalLookup::Found { original_log_id, outcome, .. } => Ok(ProposalOutcome {
                        proposal_id,
                        log_id,
                        original_log_id: Some(original_log_id),
                        decision: ProposalAttemptKind::First,
                        outcome: Some(outcome),
                    }),
                    ProposalLookup::Expired { .. } => Ok(ProposalOutcome::expired(proposal_id, log_id)),
                    ProposalLookup::NotObserved { .. } => {
                        Err(RaftBackendError::RecoveryNotObserved(Box::new(proposal_id)))
                    }
                    ProposalLookup::Invalid { reason, .. } => Err(RaftBackendError::InvalidProposal(reason)),
                }
            }
            Ok(Err(RaftError::APIError(ClientWriteError::ForwardToLeader(fwd)))) => {
                Err(RaftBackendError::FollowerRedirect(fwd.leader_id))
            }
            Ok(Err(_)) => Err(RaftBackendError::QuorumUnavailable("client write")),
            Err(_) => Err(RaftBackendError::QuorumUnavailable("client write timeout")),
        }
    }

    /// Proposes one command with a fresh caller-stable identity.
    pub async fn propose(&self, command: RefCasCommand) -> Result<ProposalOutcome, RaftBackendError> {
        let proposal_id = self.prepare_proposal_id().await?;
        self.propose_with_id(proposal_id, command).await
    }

    /// Linearized receipt-only lookup. This checks proposal scope but deliberately does not
    /// revalidate the current live gate, so a lost ACK for a gate-transition command can be
    /// resolved by the old-realm backend that owns the identity.
    pub async fn query_proposal(&self, proposal_id: ProposalId) -> Result<ProposalLookup, RaftBackendError> {
        self.validate_proposal_scope(&proposal_id)?;
        let reducer = self.read_receipt_reducer().await?;
        Ok(reducer.query_proposal(&proposal_id))
    }

    /// Recovers a successful close requirement from an actual retained close receipt.
    ///
    /// This reuses the scope-checked quorum receipt read and deliberately does not require the old
    /// live gate to still match. Only a retained `Found` applied `AuthScopeClosedV2` or legacy
    /// `AuthScopeClosed` with Closing/Closed lifecycle and positive floor can mint the capability.
    /// Refused, non-close, Expired, NotObserved and Invalid results never mint one.
    pub async fn recover_scope_close_requirement(
        &self,
        proposal_id: ProposalId,
    ) -> Result<ScopeCloseRequirement, RaftBackendError> {
        let lookup = self.query_proposal(proposal_id.clone()).await?;
        scope_close_requirement_from_lookup(lookup, self.node.trust().clone(), proposal_id)
    }

    fn validate_proposal_scope(&self, proposal_id: &ProposalId) -> Result<(), RaftBackendError> {
        proposal_id.validate_shape().map_err(|_| RaftBackendError::InvalidProposal("malformed proposal identity"))?;
        if !proposal_id.matches_scope(
            self.repository_id,
            self.tenant_id,
            self.realm.history_id(),
            self.realm.group_id(),
            self.realm.group_epoch(),
            self.realm.authority_id(),
            self.realm.authority_epoch(),
            self.realm.storage_generation(),
            self.realm.object_format(),
        ) {
            return Err(RaftBackendError::ProposalScopeMismatch("proposal scope"));
        }
        Ok(())
    }

    async fn read_receipt_reducer(&self) -> Result<RootRefCasStateMachine, RaftBackendError> {
        let read_log_id = ensure_linearizable_read(
            &self.node,
            self.options.quorum_timeout,
            "receipt read index",
            "receipt read index timeout",
        )
        .await?;
        let snapshot = self.await_applied_snapshot(read_log_id.map(ApplicationLogId::from_log_id)).await?;
        snapshot
            .reducer
            .as_any()
            .downcast_ref::<RootRefCasStateMachine>()
            .cloned()
            .ok_or(RaftBackendError::WrongReducer)
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
        let read_log_id =
            ensure_linearizable_read(&self.node, self.options.quorum_timeout, "read index", "read index timeout")
                .await?;

        self.await_applied_and_mint(read_log_id).await
    }

    async fn await_applied_and_mint(
        &self,
        read_log_id: Option<LogId<u64>>,
    ) -> Result<CommittedRefCasView, RaftBackendError> {
        let required = read_log_id.map(ApplicationLogId::from_log_id);
        let snapshot = self.await_applied_snapshot(required).await?;
        let applied = snapshot.applied.map(ApplicationLogId::from_log_id);
        let reducer =
            snapshot.reducer.as_any().downcast_ref::<RootRefCasStateMachine>().ok_or(RaftBackendError::WrongReducer)?;
        if reducer.last_applied() != applied {
            return Err(RaftBackendError::Storage("root reducer coordinate mismatch"));
        }
        self.validate_live_gate(reducer)?;
        Ok(CommittedRefCasView::mint(reducer.clone(), applied, self.repository_id, self.tenant_id, self.realm.clone()))
    }

    fn validate_live_gate(&self, reducer: &RootRefCasStateMachine) -> Result<(), RaftBackendError> {
        let gate = reducer
            .machine()
            .read_gate_version(self.repository_id)
            .map_err(|_| RaftBackendError::Storage("live gate query"))?
            .ok_or(RaftBackendError::StaleGate("gate_missing"))?;
        if gate.repository_id() != self.repository_id {
            return Err(RaftBackendError::StaleGate("repository_id"));
        }
        if gate.tenant_id() != self.tenant_id {
            return Err(RaftBackendError::StaleGate("tenant_id"));
        }
        if gate.history_incarnation() != self.realm.history_id() {
            return Err(RaftBackendError::StaleGate("history_incarnation"));
        }
        let expected_group_epoch = i64::try_from(self.realm.group_epoch())
            .map_err(|_| RaftBackendError::InvalidConfig("group_epoch does not fit gate i64"))?;
        if gate.group_epoch() != expected_group_epoch {
            return Err(RaftBackendError::StaleGate("group_epoch"));
        }
        if gate.authority_epoch() != self.realm.authority_epoch() {
            return Err(RaftBackendError::StaleGate("authority_epoch"));
        }
        if gate.object_format() != self.realm.object_format() {
            return Err(RaftBackendError::StaleGate("object_format"));
        }
        Ok(())
    }

    async fn await_applied_snapshot(
        &self,
        required: Option<ApplicationLogId>,
    ) -> Result<ApplicationRuntimeSnapshot, RaftBackendError> {
        await_applied_snapshot(&self.node, required, self.options.apply_timeout, self.options.poll_interval).await
    }
}

/// Shared actual ReadIndex with explicit follower/no-quorum/timeout mapping.
pub(crate) async fn ensure_linearizable_read(
    node: &RootRaftNode,
    timeout: Duration,
    operation: &'static str,
    timeout_operation: &'static str,
) -> Result<Option<LogId<u64>>, RaftBackendError> {
    let raft = node.raft();
    match tokio::time::timeout(timeout, raft.ensure_linearizable()).await {
        Ok(Ok(read_log_id)) => Ok(read_log_id),
        Ok(Err(RaftError::APIError(CheckIsLeaderError::ForwardToLeader(fwd)))) => {
            Err(RaftBackendError::FollowerRedirect(fwd.leader_id))
        }
        Ok(Err(_)) => Err(RaftBackendError::QuorumUnavailable(operation)),
        Err(_) => Err(RaftBackendError::QuorumUnavailable(timeout_operation)),
    }
}

/// Shared applied barrier over the same application snapshot validation used by view/receipt reads.
pub(crate) async fn await_applied_snapshot(
    node: &RootRaftNode,
    required: Option<ApplicationLogId>,
    apply_timeout: Duration,
    poll_interval: Duration,
) -> Result<ApplicationRuntimeSnapshot, RaftBackendError> {
    let deadline = Instant::now() + apply_timeout;
    loop {
        let snapshot = node
            .sm()
            .application_snapshot()
            .await
            .map_err(|_| RaftBackendError::Storage("application snapshot"))?
            .ok_or(RaftBackendError::NotApplicationMode)?;
        if snapshot.summary.domain != ROOT_REF_CAS_DOMAIN || snapshot.summary.version != ROOT_REF_CAS_VERSION {
            return Err(RaftBackendError::WrongReducer);
        }
        let applied = snapshot.applied.map(ApplicationLogId::from_log_id);
        if required.is_none_or(|required| applied.is_some_and(|applied| applied.index >= required.index)) {
            return Ok(snapshot);
        }
        if Instant::now() >= deadline {
            return Err(RaftBackendError::ApplyBarrierTimeout { applied, required });
        }
        tokio::time::sleep(poll_interval).await;
    }
}

/// Privileged group-level current drain read. This is the only public path to a full core drain;
/// it is intentionally not exposed on a repository-scoped `CommittedRefCasView`.
pub(crate) async fn read_scope_drain(
    node: &RootRaftNode,
    requirement: &ScopeCloseRequirement,
    options: BackendOptions,
) -> Result<CommittedScopeDrain, RaftBackendError> {
    options.validate()?;
    requirement.validate_node_binding(node.trust())?;
    let read_log_id = ensure_linearizable_read(
        node,
        options.quorum_timeout,
        "scope drain read index",
        "scope drain read index timeout",
    )
    .await?;
    let read_index = read_log_id.map(|log_id| log_id.index);
    let close_index = requirement.close_log_id().index;
    let barrier_index = read_index.map_or(close_index, |read| read.max(close_index));
    let barrier = (barrier_index > 0).then(|| ApplicationLogId::new(0, barrier_index));
    let snapshot = await_applied_snapshot(node, barrier, options.apply_timeout, options.poll_interval).await?;
    let applied = snapshot.applied.map(ApplicationLogId::from_log_id);
    let reducer =
        snapshot.reducer.as_any().downcast_ref::<RootRefCasStateMachine>().ok_or(RaftBackendError::WrongReducer)?;
    if reducer.last_applied() != applied {
        return Err(RaftBackendError::Storage("root reducer coordinate mismatch"));
    }
    let drain = reducer
        .machine()
        .inspect_scope_drain(requirement.scope_kind(), requirement.scope_id())
        .map_err(|error| RaftBackendError::Command(format!("scope drain inspection refused: {error}")))?;
    Ok(CommittedScopeDrain::new(
        drain,
        read_index,
        applied.map(|coordinate| coordinate.index).unwrap_or(0),
        requirement.clone(),
    ))
}
