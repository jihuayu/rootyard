//! One short transaction consumes the decision and records every publication effect.
use super::super::context::{PackCommitBaseline, refs_digest};
use super::super::contract::{MAX_CAPTURE_REFS, PackMode};
use super::super::error::{PackCommitError, PackCommitRejectCode, PackCommitRejection};
use super::super::receipt::{
    PackCommitReceipt, PackCommitTerminal, PackTerminalRegistration, ensure_pack_terminal_budget,
};
use super::super::{pg, pg_commit, registration, sql, usage};
use super::{
    AuthorizedCommitError, PgAuthorizedCommit, VerifiedAuthorizedPublication, effective_deadline, pooled_client,
};
use crate::ref_store::contract::{OperationRecord, OperationState, RequestDigest, TerminalOutcome};
use crate::ref_store::core::decision_commit::{self, RealmExpectation};
use crate::ref_store::core::publication_decision::{self as decisions, ConsumptionRecord};
use crate::ref_store::core::subset::RefRejectReason;
use crate::ref_store::core::terminal::{CommitRejectCode, RefCommitResult};
use crate::ref_store::pg::PgRefStore;
use crate::ref_store::tx::{begin_bounded, commit_bounded};
use tokio::time::{Instant, timeout_at};
use tokio_postgres::Transaction;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizedCommitReceipt {
    pub record: OperationRecord,
    pub replayed: bool,
    pub terminal: PackCommitTerminal,
    pub selection_digest: RequestDigest,
    /// True only when this same transaction durably enqueued the exact
    /// `audit-log` outbox event(s) for this fresh committed terminal. A replay
    /// or rejected terminal stays false; a projection conflict/failure aborts
    /// the whole commit instead of returning a receipt.
    pub audit_enqueued: bool,
}

impl AuthorizedCommitReceipt {
    pub fn is_committed(&self) -> bool {
        self.record.state() == OperationState::Committed && self.terminal.is_committed()
    }
}

impl PgAuthorizedCommit {
    pub async fn commit(
        &self,
        pool: &deadpool_postgres::Pool,
        verified: &VerifiedAuthorizedPublication,
        deadline: Instant,
    ) -> Result<AuthorizedCommitReceipt, AuthorizedCommitError> {
        let deadline = effective_deadline(deadline)?;
        let plan = verified.selection().prepared().plan();
        ensure_pack_terminal_budget(plan)?;
        let mut client = pooled_client(pool, deadline).await?;
        let tx = begin_bounded(&mut client, deadline).await?;
        let backend_identity = self.store.backend_identity().as_hex();
        let outcome = match timeout_at(deadline, commit_in_tx(&tx, verified, backend_identity, deadline)).await {
            Ok(value) => value,
            Err(_) => Err(AuthorizedCommitError::Timeout),
        };
        match outcome {
            Ok(receipt) => {
                commit_bounded(tx, deadline, plan.repository_id(), Some(plan.identity().operation_id()))
                    .await
                    .map_err(PackCommitError::from)?;
                Ok(receipt)
            }
            Err(error) => {
                let _cleanup = super::rollback(tx, deadline).await;
                Err(error)
            }
        }
    }
}

async fn commit_in_tx(
    tx: &Transaction<'_>,
    verified: &VerifiedAuthorizedPublication,
    backend_identity: &str,
    deadline: Instant,
) -> Result<AuthorizedCommitReceipt, AuthorizedCommitError> {
    let selection = verified.selection();
    let prepared = selection.prepared();
    let plan = prepared.plan();
    pg::set_ack_durability(tx, deadline).await?;
    let begun = PgRefStore.begin(tx, plan.identity(), deadline).await?;
    match begun.record.state() {
        OperationState::Committed | OperationState::Rejected => {
            return Ok(receipt(pg::replay_terminal(begun)?, *selection.selection_digest(), false));
        }
        OperationState::Cancelled => {
            return Err(super::reject(PackCommitRejectCode::Cancelled, "cancellation tombstone won"));
        }
        OperationState::Pending if begun.created => {
            return Err(super::reject(
                PackCommitRejectCode::PendingMissing,
                "publication needs an existing pending operation",
            ));
        }
        OperationState::Pending => {}
    }
    // SHARE NOWAIT is taken before any authorization reads and retained through COMMIT.
    decisions::sql_locks::lock_source_tables(tx, selection.selected().action()).await.map_err(super::decision_error)?;
    pg::ensure_repository(tx, plan, true).await?;
    decisions::sql_locks::lock_usage(tx, plan.repository_id(), plan.tenant_id())
        .await
        .map_err(super::decision_error)?;
    let locked = usage::lock(tx, plan.repository_id(), plan.tenant_id()).await?;
    let (gate, mode) = sql::gate_locked(tx, plan.repository_id())
        .await?
        .ok_or_else(|| pg::reject(PackCommitRejectCode::GateNotFound, "core gate missing"))?;
    pg::ensure_gate_matches(plan, &gate, mode)?;
    decision_commit::lock_and_enforce(tx, &RealmExpectation::from_gate(&gate)).await?;
    let refs = sql::capture_refs(tx, plan.repository_id(), gate.object_format(), MAX_CAPTURE_REFS).await?;
    if refs_digest(&refs) != *prepared.refs_digest() {
        return Err(super::reject(PackCommitRejectCode::OldOidMismatch, "captured ref set changed"));
    }
    let old_packs = registration::old_memberships(tx, &gate, deadline).await?;
    let baseline = PackCommitBaseline::new(gate.version(), mode, refs, old_packs)?;
    if baseline.membership_digest() != prepared.baseline().membership_digest() {
        return Err(super::reject(PackCommitRejectCode::OldMembershipMismatch, "captured membership changed"));
    }
    let new_packs = sql::registered_for_parent(tx, plan).await?;
    let projection = selection.selected().selected_plan();
    let context = if projection.is_all_rejected() {
        None
    } else {
        let context = super::super::PackClosureContext::capture_selected(projection, &baseline, new_packs)?;
        let proof = verified
            .proof()
            .ok_or_else(|| super::reject(PackCommitRejectCode::ClosureMismatch, "missing selected closure"))?;
        if !proof.binds(plan, &context) {
            return Err(super::reject(PackCommitRejectCode::ClosureMismatch, "selected closure binding changed"));
        }
        Some(context)
    };
    let consumed = decisions::authorized_final_check(
        tx,
        selection.selected(),
        plan,
        selection.actor(),
        verified.proof(),
        selection.facts(),
        plan.identity().operation_id(),
        deadline,
    )
    .await
    .map_err(super::decision_error)?;
    let rejection = match consumed {
        ConsumptionRecord::Consumed { .. } if !projection.is_all_rejected() => None,
        ConsumptionRecord::Consumed { .. } => {
            Some(PackCommitRejection::new(PackCommitRejectCode::NoRefApplied, "no ref accepted"))
        }
        ConsumptionRecord::Rejected { code, .. } => Some(PackCommitRejection::new(
            if projection.is_all_rejected() {
                PackCommitRejectCode::NoRefApplied
            } else {
                PackCommitRejectCode::DecisionRejected
            },
            code.as_str(),
        )),
    };
    let mut outcomes = outcomes(projection);
    if rejection.is_some() && !projection.is_all_rejected() {
        outcomes = plan
            .refs()
            .iter()
            .map(|update| RefCommitResult::NotApplied {
                name: update.name().as_str().to_owned(),
                reason: CommitRejectCode::PolicyDenied,
            })
            .collect();
    }
    let terminal = if let Some(reason) = rejection {
        PackCommitTerminal::rejected(
            plan.repository_id(),
            gate.revision(),
            Some(gate.head_ref().as_str().to_owned()),
            mode,
            outcomes,
            reason,
        )
    } else {
        let context = context
            .as_ref()
            .ok_or_else(|| super::reject(PackCommitRejectCode::ClosureMismatch, "missing selected context"))?;
        let revision =
            gate.revision().checked_add(1).ok_or(AuthorizedCommitError::Unverifiable("revision exhausted"))?;
        PackCommitTerminal::committed(
            plan.repository_id(),
            revision,
            context.resulting_head().as_str().to_owned(),
            PackMode::PackVerified,
            outcomes,
            context
                .new_packs()
                .iter()
                .map(|pack| PackTerminalRegistration {
                    pack_id: pack.pack_id(),
                    registration_id: pack.registration_id(),
                    artifact_set_digest: pack.artifact_set_digest().as_hex(),
                })
                .collect(),
        )
    };
    let result = terminal.to_terminal_result()?;
    let body_bytes = serde_json::to_vec(&terminal)
        .map_err(|_| AuthorizedCommitError::Unverifiable("terminal encoding failed"))?
        .len();
    let history = verified.proof().map(|proof| proof.context_digest().as_hex()).unwrap_or_default();
    let quota = usage::plan(
        &locked,
        usage::Charge::membership(
            if terminal.is_committed() { plan.packs().len() as i64 } else { 0 },
            history.len(),
            body_bytes,
        )?,
    )?;
    let mut audit_enqueued = false;
    let committed = if terminal.is_committed() {
        let prepared = pg_commit::PreparedCommit {
            new_revision: terminal.revision,
            new_head: terminal.head_ref.clone().ok_or(AuthorizedCommitError::Unverifiable("terminal HEAD missing"))?,
            terminal,
            result,
            terminal_body_bytes: body_bytes,
        };
        let committed = pg_commit::write_verified_commit(
            tx,
            plan,
            projection.accepted(),
            &history,
            context.as_ref().ok_or(AuthorizedCommitError::Unverifiable("selected context missing"))?,
            &gate,
            &prepared,
            deadline,
        )
        .await?;
        // Same transaction, after the core terminal/event/ref/gate writes. The
        // returned flag is the only authority for a later wake hint: it is true
        // only when the exact applied refs are durably present in the existing
        // `audit-log` delivery queue. The core commit never waits on the hint.
        audit_enqueued = enqueue_core_audit(
            tx,
            plan,
            selection.actor(),
            &committed.terminal,
            gate.object_format(),
            backend_identity,
        )
        .await?;
        committed
    } else {
        let record =
            PgRefStore.record_terminal(tx, plan.identity(), TerminalOutcome::Rejected, &result, deadline).await?;
        crate::ref_store::core::sql::insert_event(
            tx,
            plan.repository_id(),
            gate.revision(),
            plan.identity().operation_id(),
            "rejected",
            &result,
        )
        .await?;
        PackCommitReceipt { record: record.record, replayed: record.replayed, terminal }
    };
    usage::apply(tx, &quota).await?;
    Ok(receipt(committed, *selection.selection_digest(), audit_enqueued))
}

/// Build the exact applied-ref set for the existing durable outbox. The core
/// terminal is the source; a rejected ref contributes no event. The all-zero
/// old/new value is the outbox's existing create/delete representation.
fn audit_changes(
    format: crate::ref_store::core::types::GitObjectFormat,
    refs: &[RefCommitResult],
) -> Vec<crate::events::RefEventInput> {
    let zero = "0".repeat(format.oid_hex_len());
    refs.iter()
        .filter_map(|result| match result {
            RefCommitResult::Applied { name, old_oid, new_oid } => Some(crate::events::RefEventInput {
                transaction_sequence: 0,
                ref_name: name.clone(),
                old_oid: old_oid.clone().unwrap_or_else(|| zero.clone()),
                new_oid: new_oid.clone().unwrap_or_else(|| zero.clone()),
            }),
            RefCommitResult::NotApplied { .. } => None,
        })
        .enumerate()
        .map(|(index, mut change)| {
            change.transaction_sequence = i64::try_from(index).unwrap_or(i64::MAX - 1).saturating_add(1);
            change
        })
        .collect()
}

/// Enqueue the audit-only outbox projection of one fresh core commit.
///
/// Every field is read from the same DB-owned A4 completion transaction: the
/// exact locked repository generation, the core gate/serving-binding realm, the
/// just-written `ref_store_core_events` outcome and the cluster restore
/// incarnation. A mismatch is a typed fail-closed error, so the core commit
/// rolls back rather than ACKing content without its audit delivery. A local
/// byte-identical duplicate is the only case that may be confirmed.
async fn enqueue_core_audit(
    tx: &Transaction<'_>,
    plan: &crate::ref_store::core::pack_commit::PackCommitPlan,
    actor: &crate::db::Identity,
    terminal: &PackCommitTerminal,
    format: crate::ref_store::core::types::GitObjectFormat,
    backend_identity: &str,
) -> Result<bool, crate::ref_store::contract::RefStoreError> {
    let changes = audit_changes(format, &terminal.refs);
    if changes.is_empty() {
        return Ok(false);
    }
    let realm = tx
        .query_opt(
            "SELECT r.owner_id,r.storage_backend,r.state,r.transition_state,r.storage_generation,r.object_format, \
                    (r.deleted_at IS NULL AND r.purge_after IS NULL), \
                    g.tenant_id,g.history_incarnation,g.authority_epoch,g.group_epoch,g.object_format, \
                    b.owner_id,b.history_incarnation,b.authority_epoch,b.group_epoch,b.object_format,b.state,b.backend_identity, \
                    EXISTS(SELECT 1 FROM repository_ref_projection p WHERE p.repository_id=r.id) \
             FROM repositories r \
             JOIN ref_store_core_gates g ON g.repository_id=r.id \
             LEFT JOIN ref_store_serving_repositories b ON b.repository_id=r.id \
             WHERE r.id=$1",
            &[&plan.repository_id()],
        )
        .await
        .map_err(crate::ref_store::pg::db_error)?
        .ok_or(crate::ref_store::contract::RefStoreError::RepositoryNotFound)?;
    let storage_generation: i64 = realm.get(4);
    let active: bool = realm.get(6);
    let legacy_projection: bool = realm.get(19);
    let realm_matches = realm.get::<_, Uuid>(0) == plan.tenant_id()
        && realm.get::<_, String>(1) == "pg_refstore"
        && realm.get::<_, String>(2) == "ready"
        && realm.get::<_, String>(3) == "stable"
        && storage_generation > 0
        && active
        && realm.get::<_, String>(5) == plan.object_format().as_str()
        && realm.get::<_, Uuid>(7) == plan.tenant_id()
        && realm.get::<_, Uuid>(8) == plan.history_incarnation()
        && realm.get::<_, i64>(9) == plan.authority_epoch()
        && realm.get::<_, i64>(10) == plan.group_epoch()
        && realm.get::<_, String>(11) == plan.object_format().as_str()
        && realm.get::<_, Option<Uuid>>(12) == Some(plan.tenant_id())
        && realm.get::<_, Option<Uuid>>(13) == Some(plan.history_incarnation())
        && realm.get::<_, Option<i64>>(14) == Some(plan.authority_epoch())
        && realm.get::<_, Option<i64>>(15) == Some(plan.group_epoch())
        && realm.get::<_, Option<String>>(16).as_deref() == Some(plan.object_format().as_str())
        && realm.get::<_, Option<String>>(17).as_deref() == Some("ready")
        && realm.get::<_, Option<String>>(18).as_deref() == Some(backend_identity);
    if !realm_matches {
        return Err(crate::ref_store::contract::RefStoreError::GateConflict);
    }
    if legacy_projection {
        return Err(crate::ref_store::contract::RefStoreError::IdentityConflict);
    }
    let core_outcome: String = tx
        .query_one(
            "SELECT outcome FROM ref_store_core_events WHERE repository_id=$1 AND operation_id=$2 AND revision=$3",
            &[&plan.repository_id(), &plan.identity().operation_id(), &terminal.revision],
        )
        .await
        .map_err(crate::ref_store::pg::db_error)?
        .get(0);
    if core_outcome != "committed" {
        return Err(crate::ref_store::contract::RefStoreError::GateConflict);
    }
    let restore_incarnation: Uuid = tx
        .query_one("SELECT incarnation FROM cluster_authority WHERE singleton=true FOR SHARE", &[])
        .await
        .map_err(crate::ref_store::pg::db_error)?
        .get(0);
    if restore_incarnation.is_nil() {
        return Err(crate::ref_store::contract::RefStoreError::GateConflict);
    }
    let record = crate::events::OperationRecord {
        id: plan.identity().operation_id(),
        repository_id: plan.repository_id(),
        actor_id: actor.id,
        // Use the governing API token for a browser session so the durable
        // outbox row keeps its existing `(token_id, actor_id)` FK meaning.
        token_id: actor.scope_token_id(),
        service_principal_id: None,
        actor_name: actor.username.clone(),
        // The legacy sequence is a projection-local uniqueness/order value. The
        // core per-repository revision is deterministic, monotonic and never
        // renumbered; a different operation already owning it fails closed.
        sequence: terminal.revision,
        storage_generation,
        outcome: "recorded".to_owned(),
        evidence: serde_json::json!({
            "kind": "pg_refstore_core_commit_audit",
            "authority": "pg_refstore",
            "delivery": "audit-log",
            "source": "ref_store_core_events",
            "blob_backend_identity": backend_identity,
            "tenant_id": plan.tenant_id(),
            "repository_id": plan.repository_id(),
            "storage_generation": storage_generation,
            "object_format": plan.object_format().as_str(),
            "history_incarnation": plan.history_incarnation(),
            "authority_epoch": plan.authority_epoch(),
            "group_epoch": plan.group_epoch(),
            "restore_incarnation": restore_incarnation,
            "core_operation_id": plan.identity().operation_id(),
            "core_operation_sequence": plan.identity().sequence(),
            "core_revision": terminal.revision,
            "core_outcome": core_outcome,
            "head_ref": terminal.head_ref.clone(),
            "refs": terminal.refs.clone(),
        }),
        admission: None,
    };
    crate::events::publish_core_commit_audit_in_tx(tx, &record, &changes).await?;
    Ok(true)
}

fn receipt(value: PackCommitReceipt, selection_digest: RequestDigest, audit_enqueued: bool) -> AuthorizedCommitReceipt {
    let fresh_committed = !value.replayed && value.terminal.is_committed();
    AuthorizedCommitReceipt {
        audit_enqueued: audit_enqueued && fresh_committed,
        record: value.record,
        replayed: value.replayed,
        terminal: value.terminal,
        selection_digest,
    }
}

fn outcomes(projection: &crate::ref_store::core::subset::SelectedPackPlan) -> Vec<RefCommitResult> {
    projection
        .original()
        .refs()
        .iter()
        .zip(projection.selection().verdicts())
        .map(|(update, verdict)| {
            if verdict.is_accepted() {
                RefCommitResult::Applied {
                    name: update.name().as_str().to_owned(),
                    old_oid: update.precondition().oid().map(|oid| oid.as_hex()),
                    new_oid: update.target().oid().map(|oid| oid.as_hex()),
                }
            } else {
                let reason = match verdict.reason() {
                    Some(RefRejectReason::Cas) => CommitRejectCode::OldOidMismatch,
                    Some(RefRejectReason::MissingTarget) => CommitRejectCode::MissingTarget,
                    Some(RefRejectReason::BadObjectType) => CommitRejectCode::BadObjectType,
                    Some(RefRejectReason::PrefixConflict) => CommitRejectCode::PrefixConflict,
                    Some(RefRejectReason::HeadDependency) => CommitRejectCode::HeadDependencyMissing,
                    _ => CommitRejectCode::PolicyDenied,
                };
                RefCommitResult::NotApplied { name: update.name().as_str().to_owned(), reason }
            }
        })
        .collect()
}

#[cfg(test)]
mod audit_projection_tests {
    use super::*;
    use crate::ref_store::core::types::GitObjectFormat;

    #[test]
    fn applied_refs_become_exact_outbox_changes_and_rejected_refs_are_absent() {
        let a = "a".repeat(40);
        let b = "b".repeat(40);
        let changes = audit_changes(
            GitObjectFormat::Sha1,
            &[
                RefCommitResult::Applied { name: "refs/heads/new".into(), old_oid: None, new_oid: Some(a.clone()) },
                RefCommitResult::Applied { name: "refs/heads/removed".into(), old_oid: Some(b.clone()), new_oid: None },
                RefCommitResult::NotApplied {
                    name: "refs/heads/rejected".into(),
                    reason: CommitRejectCode::OldOidMismatch,
                },
            ],
        );
        assert_eq!(changes.len(), 2);
        assert_eq!(changes[0].transaction_sequence, 1);
        assert_eq!(changes[0].ref_name, "refs/heads/new");
        assert_eq!(changes[0].old_oid, "0".repeat(40));
        assert_eq!(changes[0].new_oid, a);
        assert_eq!(changes[1].transaction_sequence, 2);
        assert_eq!(changes[1].ref_name, "refs/heads/removed");
        assert_eq!(changes[1].old_oid, b);
        assert_eq!(changes[1].new_oid, "0".repeat(40));
    }

    #[test]
    fn sha256_zero_side_matches_the_gate_object_format() {
        let oid = "c".repeat(64);
        let changes = audit_changes(
            GitObjectFormat::Sha256,
            &[RefCommitResult::Applied { name: "refs/heads/main".into(), old_oid: None, new_oid: Some(oid.clone()) }],
        );
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].old_oid.len(), 64);
        assert_eq!(changes[0].old_oid, "0".repeat(64));
        assert_eq!(changes[0].new_oid, oid);
    }
}
