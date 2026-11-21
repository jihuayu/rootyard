//! Thin delegation to the production `SafeGcRaftMergeBackend` over the live 3-node mTLS cluster (#122).

use anyhow::Result;
use rootyard::{
    pulls::remote_merge_finalizer::{
        AuthorityCommitOutcome, MergeAuthorityBackend, RemoteMergeError, coordinator::BackendFuture,
    },
    ref_store::core::state_machine::{
        ApplyResponse, CommitScopedRefsCommand, InstallScopedDecisionCommand, RefCasCommand, RefCasStateMachine,
    },
    storage_lifecycle::safe_gc::{SafeGcRaftCommitWriter, SafeGcRaftMergeBackend},
};
use uuid::Uuid;

/// Live production-shaped Ref-CAS authority whose sole commit point is the Raft log.
pub struct LiveRaft3MergeBackend {
    inner: SafeGcRaftMergeBackend,
}

impl LiveRaft3MergeBackend {
    pub fn new(writer: SafeGcRaftCommitWriter) -> Self {
        Self { inner: SafeGcRaftMergeBackend::new(writer) }
    }

    pub fn as_production(&self) -> &SafeGcRaftMergeBackend {
        &self.inner
    }

    pub fn set_abort_after_install_once(&self, value: bool) {
        self.inner.set_abort_after_install_once(value);
    }

    pub async fn apply_repo_command(&self, command: RefCasCommand) -> Result<ApplyResponse, RemoteMergeError> {
        self.inner.apply_repo_command(command).await
    }

    pub async fn state_machine(&self) -> Result<RefCasStateMachine> {
        Ok(self.inner.state_machine().await?)
    }
}

impl MergeAuthorityBackend for LiveRaft3MergeBackend {
    fn install_and_commit_scoped<'a>(
        &'a self,
        repository_id: Uuid,
        base_ref: &'a str,
        install: InstallScopedDecisionCommand,
        commit: CommitScopedRefsCommand,
    ) -> BackendFuture<'a, AuthorityCommitOutcome> {
        self.inner.install_and_commit_scoped(repository_id, base_ref, install, commit)
    }

    fn query_operation_outcome<'a>(
        &'a self,
        repository_id: Uuid,
        operation_id: Uuid,
        base_ref: &'a str,
    ) -> BackendFuture<'a, Option<AuthorityCommitOutcome>> {
        self.inner.query_operation_outcome(repository_id, operation_id, base_ref)
    }

    fn read_ref_oid<'a>(&'a self, repository_id: Uuid, ref_name: &'a str) -> BackendFuture<'a, Option<String>> {
        self.inner.read_ref_oid(repository_id, ref_name)
    }
}
