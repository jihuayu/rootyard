//! Owned short-transaction adapter for the A4a pack commit slice.
//!
//! Every public method opens and owns exactly one short transaction from a
//! caller `&mut Client`, performs no Blob/Git/provider IO and holds no pool
//! lease. A returned receipt means `COMMIT` was acknowledged; every error before
//! `COMMIT` rolls the transaction back; an ambiguous `COMMIT` is reported as
//! [`PackCommitError::CommitUnknown`] and never as a claimed abort.
//!
//! Lock order: migration-138 operation advisory prefix → repository existence →
//! issuer lane/pending+cancellation tombstone → request key → tenant usage →
//! repository usage → core gate → sorted registrations/holds.
use super::closure::PackClosureContext;
use super::context::PackCommitBaseline;
use super::contract::{MAX_ACTIVE_MEMBERSHIPS, MAX_CAPTURE_REFS, PackMode};
use super::error::{PackCommitError, PackCommitRejectCode, PackCommitRejection};
use super::plan::PackCommitPlan;
use super::receipt::{PackCommitTerminal, PackRegistrationReceipt};
use super::request::PackPendingToken;
use super::sql;
use crate::ref_store::contract::{OperationState, RefStoreError};
use crate::ref_store::core::contract::CoreGate;
use crate::ref_store::pg::PgRefStore;
use crate::ref_store::tx::{begin_bounded, commit_bounded};
use tokio::time::Instant;
use tokio_postgres::{Client, Transaction};
use uuid::Uuid;

/// One absolute-deadline guard for a whole owned SQL stage.
///
/// `pg::bound` only refreshes the server statement timeout; this guard is the
/// real client-side bound around *all* statements of a stage (capture, pending,
/// registration, verified commit, lookup). On expiry the caller rolls the owned
/// transaction back as best-effort cleanup: that rollback is not a proven hard
/// network-return bound, exactly like the existing `tx.rs` contract, and a
/// `COMMIT` that was already issued stays `CommitUnknown` (never a false abort).
pub(super) async fn stage_bounded<T, F>(deadline: Instant, future: F) -> Result<T, PackCommitError>
where
    F: std::future::Future<Output = Result<T, PackCommitError>>,
{
    match tokio::time::timeout_at(deadline, future).await {
        Ok(result) => result,
        Err(_) => Err(PackCommitError::from(RefStoreError::Timeout)),
    }
}

/// Force WAL durability for this A4 mutation transaction only.
///
/// `SET LOCAL` is scoped to the owned transaction (never a session/global
/// `SET`), so a pool role/database `synchronous_commit=off` cannot let this
/// adapter acknowledge a pending row, registration or terminal before the WAL
/// flush. Read-only capture/lookup stages deliberately do not pay this.
pub(super) async fn set_ack_durability(tx: &Transaction<'_>, deadline: Instant) -> Result<(), PackCommitError> {
    crate::ref_store::pg::before_deadline(deadline, async {
        tx.execute("SET LOCAL synchronous_commit = 'on'", &[]).await.map_err(crate::ref_store::pg::db_error)
    })
    .await?;
    Ok(())
}

#[derive(Clone, Copy, Debug)]
pub struct PgPackCommit;

impl PgPackCommit {
    pub const fn new() -> Self {
        Self
    }

    /// Complete short-read capture of the current gate/refs/HEAD/memberships.
    /// Never truncates: an overflow is a typed refusal.
    pub async fn capture_baseline(
        &self,
        client: &mut Client,
        repository_id: Uuid,
        tenant_id: Uuid,
        deadline: Instant,
    ) -> Result<PackCommitBaseline, PackCommitError> {
        let tx = begin_bounded(client, deadline).await?;
        let result =
            stage_bounded(deadline, self.capture_baseline_in_tx(&tx, repository_id, tenant_id, deadline)).await;
        let _ = tx.rollback().await;
        result
    }

    async fn capture_baseline_in_tx(
        &self,
        tx: &Transaction<'_>,
        repository_id: Uuid,
        tenant_id: Uuid,
        deadline: Instant,
    ) -> Result<PackCommitBaseline, PackCommitError> {
        // The whole owned read stage (gate row lock, ref page, membership page)
        // is bounded by the caller's absolute deadline; a blocking lock cannot
        // outlive it silently.
        crate::ref_store::pg::bound(tx, deadline).await?;
        let (gate, mode) = sql::gate_locked(tx, repository_id)
            .await?
            .ok_or(PackCommitError::from(RefStoreError::RepositoryNotFound))?;
        if gate.tenant_id() != tenant_id {
            return Err(reject(PackCommitRejectCode::TenantMismatch, "gate belongs to another tenant"));
        }
        let refs = sql::capture_refs(tx, repository_id, gate.object_format(), MAX_CAPTURE_REFS).await?;
        let old_packs = super::registration::old_memberships(tx, &gate, deadline).await?;
        PackCommitBaseline::new(gate.version(), mode, refs, old_packs)
    }

    /// Establish (or exactly confirm) the durable Pending row for this plan and
    /// return an opaque identity token. An already terminal operation is a typed
    /// replay refusal; an exact existing Pending row is resumed unchanged.
    pub async fn begin_pending(
        &self,
        client: &mut Client,
        plan: &PackCommitPlan,
        deadline: Instant,
    ) -> Result<PackPendingToken, PackCommitError> {
        let tx = begin_bounded(client, deadline).await?;
        let result = stage_bounded(deadline, async {
            // Hosted policy may be synchronous_commit=off; this transaction must
            // not acknowledge a pending row before the WAL flush.
            set_ack_durability(&tx, deadline).await?;
            self.begin_pending_in_tx(&tx, plan, deadline).await
        })
        .await;
        match result {
            Ok((token, _created)) => {
                commit_bounded(tx, deadline, plan.repository_id(), Some(plan.identity().operation_id()))
                    .await
                    .map_err(PackCommitError::from)?;
                Ok(token)
            }
            Err(error) => {
                let _ = tx.rollback().await;
                Err(error)
            }
        }
    }

    /// Exact migration-138 pending prefix on a caller-owned transaction.
    ///
    /// Returns the opaque token **and** whether this transaction inserted the
    /// pending row (`BeginReceipt::created`). Callers that atomically attach
    /// another durable row to the operation must only do so when `created` is
    /// true; an existing pending row may never gain a new binding after the
    /// fact.
    pub(super) async fn begin_pending_in_tx(
        &self,
        tx: &Transaction<'_>,
        plan: &PackCommitPlan,
        deadline: Instant,
    ) -> Result<(PackPendingToken, bool), PackCommitError> {
        let begun = PgRefStore.begin(tx, plan.identity(), deadline).await?;
        let created = begun.created;
        match begun.record.state() {
            OperationState::Committed | OperationState::Rejected => {
                return Err(reject(PackCommitRejectCode::AlreadyVerified, "operation is already terminal"));
            }
            OperationState::Cancelled => {
                return Err(reject(PackCommitRejectCode::Cancelled, "cancellation tombstone won"));
            }
            OperationState::Pending => {}
        }
        if begun.record.identity() != plan.identity() {
            return Err(PackCommitError::from(RefStoreError::DigestConflict));
        }
        // Repository authority is re-checked after the registry prefix and
        // before any pack/ref write.
        ensure_repository(tx, plan, false).await?;
        let (gate, mode) = sql::gate_locked(tx, plan.repository_id())
            .await?
            .ok_or_else(|| reject(PackCommitRejectCode::GateNotFound, "core gate missing"))?;
        ensure_gate_matches(plan, &gate, mode)?;
        let token = PackPendingToken::established(
            plan.repository_id(),
            plan.tenant_id(),
            plan.identity().operation_id(),
            *plan.parent_digest(),
        )?;
        Ok((token, created))
    }

    /// Capture the closure context at the plan's exact expected revision with the
    /// durable same-parent registrations (complete old+new locator data).
    pub async fn capture_context(
        &self,
        client: &mut Client,
        plan: &PackCommitPlan,
        deadline: Instant,
    ) -> Result<PackClosureContext, PackCommitError> {
        let tx = begin_bounded(client, deadline).await?;
        let result = stage_bounded(deadline, self.capture_context_in_tx(&tx, plan, deadline)).await;
        let _ = tx.rollback().await;
        result
    }

    async fn capture_context_in_tx(
        &self,
        tx: &Transaction<'_>,
        plan: &PackCommitPlan,
        deadline: Instant,
    ) -> Result<PackClosureContext, PackCommitError> {
        crate::ref_store::pg::bound(tx, deadline).await?;
        let baseline = self.context_baseline(tx, plan, deadline).await?;
        let new_packs = sql::registered_for_parent(tx, plan).await?;
        PackClosureContext::capture(plan, &baseline, new_packs)
    }

    async fn context_baseline(
        &self,
        tx: &Transaction<'_>,
        plan: &PackCommitPlan,
        deadline: Instant,
    ) -> Result<PackCommitBaseline, PackCommitError> {
        crate::ref_store::pg::bound(tx, deadline).await?;
        ensure_repository(tx, plan, true).await?;
        let (gate, mode) = sql::gate_locked(tx, plan.repository_id())
            .await?
            .ok_or_else(|| reject(PackCommitRejectCode::GateNotFound, "core gate missing"))?;
        ensure_gate_matches(plan, &gate, mode)?;
        let refs = sql::capture_refs(tx, plan.repository_id(), gate.object_format(), MAX_CAPTURE_REFS).await?;
        let old_packs = super::registration::old_memberships(tx, &gate, deadline).await?;
        if old_packs.len() as i64 > MAX_ACTIVE_MEMBERSHIPS {
            return Err(reject(PackCommitRejectCode::CaptureOverflow, "membership capture overflow"));
        }
        PackCommitBaseline::new(gate.version(), mode, refs, old_packs)
    }

    /// Read-only historical resolution of one registration id.
    ///
    /// Requires the caller's expected durable scope (repository, tenant, owner,
    /// object format, history incarnation and both gate epochs) and validates the
    /// complete immutable row/body/artifact/A3-ledger set through the single
    /// bounded reader. A missing row is `None`; a partial or corrupt row is a
    /// typed `LedgerIntegrity` refusal, never `Some`. This path never requires a
    /// current pending operation and stays available after the parent operation
    /// committed/was cancelled or the business repository row was deleted.
    pub async fn query_registration(
        &self,
        client: &mut Client,
        scope: &super::plan::PackCommitScope,
        registration_id: Uuid,
        deadline: Instant,
    ) -> Result<Option<PackRegistrationReceipt>, PackCommitError> {
        if registration_id.is_nil() {
            return Err(PackCommitError::Invalid("registration lookup id must be non-nil"));
        }
        let tx = begin_bounded(client, deadline).await?;
        let result = stage_bounded(deadline, async {
            crate::ref_store::pg::bound(&tx, deadline).await?;
            Ok(super::registration::by_registration_id(&tx, scope, registration_id, deadline)
                .await?
                .map(|stored| stored.replay()))
        })
        .await;
        let _ = tx.rollback().await;
        result
    }
}

impl Default for PgPackCommit {
    fn default() -> Self {
        Self::new()
    }
}

pub(super) fn reject(code: PackCommitRejectCode, detail: &'static str) -> PackCommitError {
    PackCommitError::Rejected(PackCommitRejection::new(code, detail))
}

pub(super) fn ensure_gate_matches(
    plan: &PackCommitPlan,
    gate: &CoreGate,
    mode: PackMode,
) -> Result<(), PackCommitError> {
    if gate.tenant_id() != plan.tenant_id() {
        return Err(reject(PackCommitRejectCode::TenantMismatch, "gate tenant differs"));
    }
    if gate.object_format() != plan.object_format() {
        return Err(reject(PackCommitRejectCode::ObjectFormatMismatch, "gate object format differs"));
    }
    if gate.history_incarnation() != plan.history_incarnation()
        || gate.authority_epoch() != plan.authority_epoch()
        || gate.group_epoch() != plan.group_epoch()
    {
        return Err(reject(PackCommitRejectCode::HistoryIncarnationMismatch, "gate epochs differ"));
    }
    if gate.revision() != plan.expected().revision() {
        return Err(reject(PackCommitRejectCode::RevisionMismatch, "gate revision differs"));
    }
    if gate.digest() != plan.expected().gate_digest() {
        return Err(reject(PackCommitRejectCode::GateDigestMismatch, "gate digest differs"));
    }
    if mode != plan.expected().mode() {
        return Err(reject(PackCommitRejectCode::ModeMismatch, "gate pack mode differs"));
    }
    Ok(())
}

/// Repository authority recheck through the one shared strict predicate.
///
/// `require_core` additionally requires a fresh-write lane: the unserved
/// `gitfs` fixture repository, or the ready `pg_refstore` serving authority
/// whose durable binding is exactly this plan realm (owner, object format,
/// history incarnation, authority/group epochs) and whose Blob backend is the
/// live store. A plain ready row or a backend string is never enough.
pub(super) async fn ensure_repository(
    tx: &Transaction<'_>,
    plan: &PackCommitPlan,
    require_core: bool,
) -> Result<crate::ref_store::core::serving_scope::LockedScope, PackCommitError> {
    let scope = crate::ref_store::core::serving_scope::LockedScope::lock(tx, plan.repository_id(), false)
        .await?
        .ok_or_else(|| PackCommitError::from(RefStoreError::RepositoryNotFound))?;
    if scope.owner_id() != plan.tenant_id() {
        return Err(reject(PackCommitRejectCode::TenantMismatch, "repository belongs to another tenant"));
    }
    if !require_core {
        return Ok(scope);
    }
    let realm = crate::ref_store::core::serving_scope::CoreRealm::new(
        plan.tenant_id(),
        plan.object_format(),
        plan.history_incarnation(),
        plan.authority_epoch(),
        plan.group_epoch(),
    );
    match scope.require_fresh_core(&realm) {
        Ok(_lane) => Ok(scope),
        Err(crate::ref_store::core::serving_scope::ScopeRefusal::Realm(
            crate::ref_store::core::serving_scope::RealmField::ObjectFormat,
        )) => Err(reject(PackCommitRejectCode::ObjectFormatMismatch, "repository object format differs")),
        Err(crate::ref_store::core::serving_scope::ScopeRefusal::Realm(_)) => {
            Err(reject(PackCommitRejectCode::HistoryIncarnationMismatch, "repository gate epochs differ"))
        }
        Err(refusal) => Err(PackCommitError::from(RefStoreError::Unsupported(refusal.reason()))),
    }
}

/// Terminal replay of an already committed/rejected pack operation.
pub(super) fn replay_terminal(
    begun: crate::ref_store::contract::BeginReceipt,
) -> Result<super::receipt::PackCommitReceipt, PackCommitError> {
    let record = begun.record;
    match record.state() {
        OperationState::Committed | OperationState::Rejected => {
            let stored = record
                .terminal_result()
                .ok_or_else(|| PackCommitError::from(RefStoreError::Database("terminal has no result".into())))?;
            let terminal = PackCommitTerminal::from_terminal_result(stored)?;
            Ok(super::receipt::PackCommitReceipt { record, replayed: true, terminal })
        }
        OperationState::Cancelled => Err(reject(PackCommitRejectCode::Cancelled, "cancellation tombstone won")),
        OperationState::Pending => Err(reject(PackCommitRejectCode::PendingMissing, "operation is still pending")),
    }
}

/// Exact migration-138 prefix for a fresh registration.
///
/// `PgRefStore::begin` takes the operation advisory key, the repository
/// existence check and the issuer-lane lock, and holds them until the caller's
/// `COMMIT`, so a concurrent cancel cannot commit a tombstone between this read
/// and the registration writes. It is also the only supported way to observe an
/// existing Pending row: when this transaction had to *create* the pending row
/// the registration must fail (the caller rolls the whole transaction back, so
/// no pending row survives) instead of silently acquiring authority.
pub(super) async fn acquire_pending_prefix(
    tx: &Transaction<'_>,
    plan: &PackCommitPlan,
    deadline: Instant,
) -> Result<(), PackCommitError> {
    let begun = PgRefStore.begin(tx, plan.identity(), deadline).await?;
    if begun.record.state() == OperationState::Cancelled {
        return Err(reject(PackCommitRejectCode::Cancelled, "cancellation tombstone won"));
    }
    if begun.created {
        return Err(reject(
            PackCommitRejectCode::PendingMissing,
            "registration requires an existing pending operation and never creates one",
        ));
    }
    if begun.record.identity() != plan.identity() {
        return Err(PackCommitError::from(RefStoreError::DigestConflict));
    }
    match begun.record.state() {
        OperationState::Pending => Ok(()),
        OperationState::Committed | OperationState::Rejected => {
            Err(reject(PackCommitRejectCode::AlreadyVerified, "operation is already terminal"))
        }
        OperationState::Cancelled => Err(reject(PackCommitRejectCode::Cancelled, "cancellation tombstone won")),
    }
}
