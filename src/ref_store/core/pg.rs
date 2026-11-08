//! Short owned-transaction PostgreSQL adapter for the isolated metadata core.
//!
//! Every public method opens and owns one short transaction from a caller
//! `&mut tokio_postgres::Client`:
//!
//! - a returned receipt means `COMMIT` was acknowledged;
//! - every `Err` before `COMMIT` is issued (validation, deadline, authority
//!   fence or database) rolls the transaction back before returning, so such a
//!   Rust error cannot leave refs/revision/pending/terminal/event writes
//!   committable by the caller;
//! - a `BEGIN` past the absolute deadline is cancelled through the pinned SDK,
//!   whose rollback guard queues `ROLLBACK` on the borrowed connection;
//! - once `COMMIT` is issued, a deadline timeout or an error reply is reported
//!   as `CommitUnknown`, never as a false abort or a successful receipt. The
//!   commit may still land, so callers query the same operation identity.
//!   Only an acknowledged `COMMIT` returns `Ok`.
//!
//! No method performs Git/pack/blob/network IO or holds a long-lived request
//! connection. Lock order is fixed:
//!
//! operation advisory key -> issuer lane -> repository row -> core gate -> ref rows.
//!
//! `begin`, `cancel`, `record_terminal` and `get` are the migration-138
//! registry and keep their own operation -> lane order. A core commit calls
//! `begin` first and only then locks the repository/gate/refs, so replay and
//! cancel use a prefix of the same order. Bootstrap is restricted to an
//! explicitly unserved `provisioning` repository on the legacy `gitfs` backend,
//! with a `stable` transition, no Pando authority and no legacy refs. Each new
//! commit rechecks the same repository row; if the repository becomes
//! ready/draining/Pando, new core mutations are rejected while immutable
//! terminal replay/lookup still return the existing proof. This component never
//! updates `repositories`, `pando_repository_states` or `pando_refs` and is not
//! a serving cutover.
use super::super::contract::{
    CancelReceipt, Capabilities, OperationIdentity, OperationLookup, OperationState, RefStoreError, TerminalOutcome,
};
use super::super::pg::{self, PgRefStore};
use super::super::tx::{begin_bounded, commit_bounded};
use super::command::CommitRefsRequest;
use super::contract::{CoreGate, CoreGateInit, CoreGateVersion, VersionCheck};
use super::sql::{
    check_cas, check_existing_prefixes, gate_from_row, gate_row, insert_event, lock_relevant_refs, lookup_names,
    reject, replay_terminal,
};
use super::terminal::{CommitRefsReceipt, CommitRejectCode, CommitTerminal, RefCommitResult};
use super::types::{GitObjectFormat, GitOid, RefTarget, resolve_head};
use tokio::time::Instant;
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, Default)]
pub struct PgRefStoreCore;

impl PgRefStoreCore {
    pub const fn capabilities(&self) -> Capabilities {
        Capabilities::pg_core_increment()
    }

    /// Create the explicit gate for an unserved repository in one short
    /// transaction. Idempotent only for exactly the same gate parameters.
    ///
    /// Bootstrap requires `repositories.state='provisioning'`,
    /// `storage_backend='gitfs'`, `transition_state='stable'`, no
    /// `pando_repository_states` row, no legacy `repository_ref_projection`
    /// rows, the same tenant and the same object format. It never changes
    /// serving authority. Errors before `COMMIT` roll the owned transaction
    /// back; a `COMMIT` timeout or error reply is `CommitUnknown`, whose
    /// resolution is an idempotent retry/`check_version` for this repository.
    pub async fn initialize(
        &self,
        client: &mut Client,
        init: &CoreGateInit,
        deadline: Instant,
    ) -> Result<CoreGate, RefStoreError> {
        let tx = begin_bounded(client, deadline).await?;
        let result = self.initialize_in_tx(&tx, init, deadline).await;
        match result {
            Ok(gate) => {
                commit_bounded(tx, deadline, init.repository_id(), None).await?;
                Ok(gate)
            }
            Err(error) => {
                let _ = tx.rollback().await;
                Err(error)
            }
        }
    }

    async fn initialize_in_tx(
        &self,
        tx: &Transaction<'_>,
        init: &CoreGateInit,
        deadline: Instant,
    ) -> Result<CoreGate, RefStoreError> {
        pg::before_deadline(deadline, self.initialize_checked(tx, init, deadline)).await
    }

    async fn initialize_checked(
        &self,
        tx: &Transaction<'_>,
        init: &CoreGateInit,
        deadline: Instant,
    ) -> Result<CoreGate, RefStoreError> {
        pg::bound(tx, deadline).await?;
        let row = tx
            .query_opt(
                "SELECT r.owner_id,r.object_format,r.state,r.storage_backend,r.transition_state,
                        EXISTS(SELECT 1 FROM pando_repository_states s WHERE s.repository_id=r.id),
                        EXISTS(SELECT 1 FROM repository_ref_projection p WHERE p.repository_id=r.id)
                 FROM repositories r WHERE r.id=$1 FOR UPDATE",
                &[&init.repository_id()],
            )
            .await
            .map_err(pg::db_error)?
            .ok_or(RefStoreError::RepositoryNotFound)?;
        let owner: Uuid = row.get(0);
        let object_format: String = row.get(1);
        let state: String = row.get(2);
        let storage_backend: String = row.get(3);
        let transition_state: String = row.get(4);
        let pando_authority: bool = row.get(5);
        let legacy_refs: bool = row.get(6);
        if owner != init.tenant_id() {
            return Err(RefStoreError::RepositoryNotFound);
        }
        if state != "provisioning" {
            return Err(RefStoreError::Unsupported(
                "core bootstrap requires an explicitly unserved provisioning repository",
            ));
        }
        if transition_state != "stable" {
            return Err(RefStoreError::Unsupported("core bootstrap requires a stable storage transition"));
        }
        if storage_backend != "gitfs" {
            return Err(RefStoreError::Unsupported(
                "repository has a non-gitfs serving backend; core initialization cannot create a second writable authority",
            ));
        }
        if pando_authority {
            return Err(RefStoreError::Unsupported(
                "repository has a live legacy pando authority; core initialization cannot create a second writable authority",
            ));
        }
        if legacy_refs {
            return Err(RefStoreError::Unsupported(
                "repository already has legacy refs; core bootstrap requires an empty unserved repository",
            ));
        }
        if GitObjectFormat::parse(&object_format)? != init.object_format() {
            return Err(RefStoreError::InvalidIdentity(
                "gate object format differs from the repository object format".into(),
            ));
        }

        let inserted = tx
            .query_opt(
                "INSERT INTO ref_store_core_gates(
                     repository_id,tenant_id,object_format,history_incarnation,
                     authority_epoch,group_epoch,head_ref,revision)
                 VALUES($1,$2,$3,$4,$5,$6,$7,1)
                 ON CONFLICT(repository_id) DO NOTHING
                 RETURNING tenant_id,object_format,history_incarnation,authority_epoch,group_epoch,head_ref,revision",
                &[
                    &init.repository_id(),
                    &init.tenant_id(),
                    &init.object_format().as_str(),
                    &init.history_incarnation(),
                    &init.authority_epoch(),
                    &init.group_epoch(),
                    &init.head_ref().as_str(),
                ],
            )
            .await
            .map_err(pg::db_error)?;
        let gate = match inserted {
            Some(row) => gate_from_row(init.repository_id(), &row)?,
            None => gate_row(tx, init.repository_id(), true)
                .await?
                .ok_or_else(|| RefStoreError::Database("gate disappeared during initialization".into()))?,
        };
        if gate.tenant_id() != init.tenant_id()
            || gate.object_format() != init.object_format()
            || gate.history_incarnation() != init.history_incarnation()
            || gate.authority_epoch() != init.authority_epoch()
            || gate.group_epoch() != init.group_epoch()
            || gate.head_ref() != init.head_ref()
        {
            return Err(RefStoreError::GateConflict);
        }
        Ok(gate)
    }

    /// Linearized gate-version observation. Unknown is not unchanged. This is a
    /// read-only short transaction and may still return the old proof after the
    /// repository stops being an isolated unserved core repository.
    pub async fn check_version(
        &self,
        client: &mut Client,
        repository_id: Uuid,
        tenant_id: Uuid,
        known: Option<&CoreGateVersion>,
        deadline: Instant,
    ) -> Result<VersionCheck, RefStoreError> {
        let tx = begin_bounded(client, deadline).await?;
        let result = self.check_version_in_tx(&tx, repository_id, tenant_id, known, deadline).await;
        let _ = tx.rollback().await;
        result
    }

    async fn check_version_in_tx(
        &self,
        tx: &Transaction<'_>,
        repository_id: Uuid,
        tenant_id: Uuid,
        known: Option<&CoreGateVersion>,
        deadline: Instant,
    ) -> Result<VersionCheck, RefStoreError> {
        if repository_id.is_nil() || tenant_id.is_nil() {
            return Err(RefStoreError::InvalidIdentity("gate lookup ids must be non-nil".into()));
        }
        pg::before_deadline(deadline, self.check_version_checked(tx, repository_id, tenant_id, known, deadline)).await
    }

    async fn check_version_checked(
        &self,
        tx: &Transaction<'_>,
        repository_id: Uuid,
        tenant_id: Uuid,
        known: Option<&CoreGateVersion>,
        deadline: Instant,
    ) -> Result<VersionCheck, RefStoreError> {
        pg::bound(tx, deadline).await?;
        let Some(gate) = gate_row(tx, repository_id, false).await? else {
            return Ok(VersionCheck::Unknown);
        };
        if gate.tenant_id() != tenant_id {
            return Err(RefStoreError::RepositoryNotFound);
        }
        let version = gate.version();
        if known == Some(&version) { Ok(VersionCheck::Unchanged(version)) } else { Ok(VersionCheck::Changed(version)) }
    }

    /// Exact old/new CAS in one owned short transaction.
    ///
    /// The request is fully validated (including the worst-case 64 KiB
    /// terminal budget of both a committed and a rejected outcome) before the
    /// registry is touched. `PgRefStore::begin` registers the stable identity
    /// first; the same transaction then locks the repository authority row,
    /// the gate and the relevant refs, validates tenant/format/history/epoch/
    /// revision, exact old OIDs, prefix conflicts and HEAD rules, applies all
    /// refs plus the gate revision increment, records the immutable operation
    /// terminal and inserts the correlated event. Domain rejections are
    /// returned as `Ok(receipt)` only after that terminal+event pair commits;
    /// callers MUST inspect [`CommitRefsReceipt::is_committed`].
    ///
    /// Infrastructure/deadline errors before `COMMIT` return `Err` after the
    /// owned transaction was rolled back. An expired deadline is checked
    /// before `COMMIT` is issued, so that case never sends `COMMIT`. Once
    /// `COMMIT` is issued, only an acknowledged success returns the receipt;
    /// a timeout or error reply returns `CommitUnknown`, never a claimed abort.
    /// Callers resolve it with `query_operation` for this exact operation id.
    pub async fn commit_refs(
        &self,
        client: &mut Client,
        request: &CommitRefsRequest,
        deadline: Instant,
    ) -> Result<CommitRefsReceipt, RefStoreError> {
        request.validate()?;
        let tx = begin_bounded(client, deadline).await?;
        let result = self.commit_refs_in_tx(&tx, request, deadline).await;
        match result {
            Ok(receipt) => {
                commit_bounded(tx, deadline, request.repository_id(), Some(request.identity().operation_id())).await?;
                Ok(receipt)
            }
            Err(error) => {
                let _ = tx.rollback().await;
                Err(error)
            }
        }
    }

    async fn commit_refs_in_tx(
        &self,
        tx: &Transaction<'_>,
        request: &CommitRefsRequest,
        deadline: Instant,
    ) -> Result<CommitRefsReceipt, RefStoreError> {
        pg::before_deadline(deadline, self.commit_refs_checked(tx, request, deadline)).await
    }

    async fn commit_refs_checked(
        &self,
        tx: &Transaction<'_>,
        request: &CommitRefsRequest,
        deadline: Instant,
    ) -> Result<CommitRefsReceipt, RefStoreError> {
        let registry = PgRefStore;
        let begun = registry.begin(tx, request.identity(), deadline).await?;
        if !begun.created {
            // Immutable replay is proof of an older operation and stays valid
            // even after the repository left the isolated bootstrap state.
            return replay_terminal(begun);
        }
        if begun.record.state() == OperationState::Cancelled {
            return Err(RefStoreError::Cancelled { operation_id: request.identity().operation_id() });
        }
        pg::bound(tx, deadline).await?;

        // Same repository row as bootstrap, rechecked under a shared row lock
        // after the operation/lane registry and before the core gate. A
        // transition writer or bootstrap needs the exclusive row lock, so this
        // check cannot race either of them; concurrent commits then serialize
        // on the gate row below.
        let repository = tx
            .query_opt(
                "SELECT r.owner_id,r.state,r.storage_backend,r.transition_state,
                        EXISTS(SELECT 1 FROM pando_repository_states s WHERE s.repository_id=r.id)
                 FROM repositories r WHERE r.id=$1 FOR SHARE",
                &[&request.repository_id()],
            )
            .await
            .map_err(pg::db_error)?
            .ok_or(RefStoreError::RepositoryNotFound)?;
        let owner: Uuid = repository.get(0);
        if owner != request.tenant_id() {
            return reject(tx, request, None, CommitRejectCode::TenantMismatch, None, None, None, deadline).await;
        }
        let state: String = repository.get(1);
        let storage_backend: String = repository.get(2);
        let transition_state: String = repository.get(3);
        let pando_authority: bool = repository.get(4);
        if state != "provisioning" || storage_backend != "gitfs" || transition_state != "stable" || pando_authority {
            return Err(RefStoreError::Unsupported(
                "repository is no longer an isolated unserved core repository; new core mutations are rejected",
            ));
        }

        let Some(gate) = gate_row(tx, request.repository_id(), true).await? else {
            return reject(tx, request, None, CommitRejectCode::GateNotFound, None, None, None, deadline).await;
        };
        if gate.tenant_id() != request.tenant_id() {
            return reject(tx, request, Some(&gate), CommitRejectCode::TenantMismatch, None, None, None, deadline)
                .await;
        }
        if gate.object_format() != request.object_format() {
            return reject(
                tx,
                request,
                Some(&gate),
                CommitRejectCode::ObjectFormatMismatch,
                None,
                Some(request.object_format().to_string()),
                Some(gate.object_format().to_string()),
                deadline,
            )
            .await;
        }
        if gate.history_incarnation() != request.history_incarnation() {
            return reject(
                tx,
                request,
                Some(&gate),
                CommitRejectCode::HistoryIncarnationMismatch,
                None,
                Some(request.history_incarnation().to_string()),
                Some(gate.history_incarnation().to_string()),
                deadline,
            )
            .await;
        }
        if gate.authority_epoch() != request.authority_epoch() {
            return reject(
                tx,
                request,
                Some(&gate),
                CommitRejectCode::AuthorityEpochMismatch,
                None,
                Some(request.authority_epoch().to_string()),
                Some(gate.authority_epoch().to_string()),
                deadline,
            )
            .await;
        }
        if gate.group_epoch() != request.group_epoch() {
            return reject(
                tx,
                request,
                Some(&gate),
                CommitRejectCode::GroupEpochMismatch,
                None,
                Some(request.group_epoch().to_string()),
                Some(gate.group_epoch().to_string()),
                deadline,
            )
            .await;
        }
        if gate.revision() != request.expected_revision() {
            return reject(
                tx,
                request,
                Some(&gate),
                CommitRejectCode::RevisionMismatch,
                None,
                Some(request.expected_revision().to_string()),
                Some(gate.revision().to_string()),
                deadline,
            )
            .await;
        }

        // A4a persistent fence: once one verified pack commit has activated this
        // gate, every fresh metadata-only A1 write is refused while immutable
        // terminal replay above stays available. The gate row is already locked.
        let pack_mode: String = tx
            .query_one("SELECT pack_mode FROM ref_store_core_gates WHERE repository_id=$1", &[&request.repository_id()])
            .await
            .map_err(pg::db_error)?
            .get(0);
        if pack_mode != "metadata_only" {
            return Err(RefStoreError::Unsupported(
                "gate is pack_verified; fresh metadata-only ref commits are refused",
            ));
        }

        let existing = lock_relevant_refs(tx, request.repository_id(), lookup_names(request, gate.head_ref())).await?;
        if let Err((code, name, expected, actual)) = check_cas(request, &existing) {
            return reject(tx, request, Some(&gate), code, Some(name), expected, actual, deadline).await;
        }
        if let Err((name, conflict)) = check_existing_prefixes(request, &existing) {
            return reject(
                tx,
                request,
                Some(&gate),
                CommitRejectCode::PrefixConflict,
                Some(name),
                None,
                Some(conflict),
                deadline,
            )
            .await;
        }
        let new_head = match resolve_head(gate.head_ref().as_str(), &existing, request.refs(), request.head()) {
            Ok(head) => head,
            Err((code, name)) => return reject(tx, request, Some(&gate), code, name, None, None, deadline).await,
        };

        let new_revision = gate.revision() + 1;
        let mut results = Vec::with_capacity(request.refs().len());
        for update in request.refs() {
            let name = update.name().as_str();
            match update.target() {
                RefTarget::Delete => {
                    let changed = tx
                        .execute(
                            "DELETE FROM ref_store_core_refs WHERE repository_id=$1 AND ref_name=$2",
                            &[&request.repository_id(), &name],
                        )
                        .await
                        .map_err(pg::db_error)?;
                    if changed != 1 {
                        return Err(RefStoreError::Database("locked ref disappeared during delete".into()));
                    }
                }
                RefTarget::Oid(oid) => {
                    tx.execute(
                        "INSERT INTO ref_store_core_refs(repository_id,ref_name,oid,revision)
                         VALUES($1,$2,$3,$4)
                         ON CONFLICT(repository_id,ref_name) DO UPDATE
                         SET oid=EXCLUDED.oid,revision=EXCLUDED.revision,updated_at=clock_timestamp()",
                        &[&request.repository_id(), &name, &oid.as_hex(), &new_revision],
                    )
                    .await
                    .map_err(pg::db_error)?;
                }
            }
            results.push(RefCommitResult::Applied {
                name: name.to_owned(),
                old_oid: update.precondition().oid().map(GitOid::as_hex),
                new_oid: update.target().oid().map(GitOid::as_hex),
            });
        }
        let updated = tx
            .query_opt(
                "UPDATE ref_store_core_gates
                 SET revision=$2,head_ref=$3,updated_at=clock_timestamp()
                 WHERE repository_id=$1 AND revision=$4
                 RETURNING revision",
                &[&request.repository_id(), &new_revision, &new_head, &gate.revision()],
            )
            .await
            .map_err(pg::db_error)?;
        if updated.is_none() {
            return Err(RefStoreError::Database("gate revision changed while its row was locked".into()));
        }
        // Every field was already accepted by the pre-begin terminal budget, so
        // this conversion cannot fail after the writes inside this transaction.
        let terminal = CommitTerminal::committed(request.repository_id(), new_revision, new_head, results);
        let result = terminal.to_terminal_result()?;
        let receipt =
            registry.record_terminal(tx, request.identity(), TerminalOutcome::Committed, &result, deadline).await?;
        let operation_id = receipt.record.identity().operation_id();
        insert_event(tx, request.repository_id(), new_revision, operation_id, "committed", &result).await?;
        Ok(CommitRefsReceipt { replayed: receipt.replayed, record: receipt.record, terminal })
    }

    /// Internal repository-scoped read over the migration-138 registry in a
    /// read-only short transaction. A missing row is `Unknown`, never aborted.
    pub async fn query_operation(
        &self,
        client: &mut Client,
        repository_id: Uuid,
        operation_id: Uuid,
        deadline: Instant,
    ) -> Result<OperationLookup, RefStoreError> {
        let tx = begin_bounded(client, deadline).await?;
        let result = PgRefStore.get(&tx, repository_id, operation_id, deadline).await;
        let _ = tx.rollback().await;
        result
    }

    /// Cancel through the migration-138 registry in one owned short
    /// transaction, including the cancel-before-register tombstone. Cancelling
    /// an unknown operation is registry state, not a ref mutation, so it stays
    /// available after the repository left the isolated bootstrap state.
    pub async fn cancel(
        &self,
        client: &mut Client,
        identity: &OperationIdentity,
        deadline: Instant,
    ) -> Result<CancelReceipt, RefStoreError> {
        let tx = begin_bounded(client, deadline).await?;
        let result = PgRefStore.cancel(&tx, identity, deadline).await;
        match result {
            Ok(receipt) => {
                commit_bounded(tx, deadline, identity.repository_id(), Some(identity.operation_id())).await?;
                Ok(receipt)
            }
            Err(error) => {
                let _ = tx.rollback().await;
                Err(error)
            }
        }
    }
}
