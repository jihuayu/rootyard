//! `select_and_install`: mint the one durable `OPEN` publication decision for an operation.
//!
//! This is the only minting site of [`SelectedDecision`]/[`DecisionCapability`]. It persists, in one
//! short caller-owned transaction and after the frozen `NOWAIT` source locks and the ordered usage
//! rows:
//!
//! * the sealed [`SelectedPackPlan`] projection produced by
//!   `subset::SelectedPackPlan::seal(original.clone(), &facts, &policies)` **before** any persist — so
//!   the persisted selection digest is exactly the proved selection digest, not a second domain;
//! * every per-ref verdict of that sealed projection (accept **and** reject, exact canonical detail);
//! * the exact dependency observations, native fact digest, authorization digest and absolute
//!   `not_after` (real DB clock read after every lock wait);
//! * the retained usage charge for all of that new data.
//!
//! It holds no PG client, no native/view permit and no Blob handle across IO, and it never writes refs,
//! packs, the gate, `forge_*` or `repositories` (the optional merge finalizer is a separate explicit
//! call in the final commit transaction).
use super::auth_deps;
use super::capability::DecisionCapability;
use super::contract::{
    DecisionError, DecisionKind, DecisionState, DenialCode, MAX_DECISION_REFS, MAX_DECISION_WINDOW_MILLIS,
    PublicationAction, SelectedDecision,
};
use super::digest::{self, DecisionDigests};
use super::facts_bridge;
use super::query;
use super::select::{self, SelectionInput};
use super::sql_locks::{self, DecisionRow};
use super::subset::{PolicyVerdict, SelectedPackPlan};
use super::usage;
use crate::db::Identity;
use crate::ref_store::core::pack_commit::VerifiedPublicationFacts;
use crate::ref_store::core::pack_commit::plan::PackCommitPlan;
use std::collections::BTreeMap;
use tokio::time::Instant;
use tokio_postgres::Transaction;
use uuid::Uuid;

/// Default entry point used by the authorized facade: an explicit direct push.
pub(crate) async fn select_and_install(
    tx: &Transaction<'_>,
    plan: &PackCommitPlan,
    facts: &VerifiedPublicationFacts,
    actor: &Identity,
    kind: DecisionKind,
    deadline: Instant,
) -> Result<SelectedDecision, DecisionError> {
    select_and_install_action(tx, plan, facts, actor, kind, &PublicationAction::Push, deadline).await
}

/// Full entry point: the semantic action is explicit and never inferred from ref names or PR rows.
pub(crate) async fn select_and_install_action(
    tx: &Transaction<'_>,
    plan: &PackCommitPlan,
    facts: &VerifiedPublicationFacts,
    actor: &Identity,
    kind: DecisionKind,
    action: &PublicationAction,
    deadline: Instant,
) -> Result<SelectedDecision, DecisionError> {
    // PR producer integration needs a native head-to-merge attestation and an
    // atomic business finalizer. Until that separate integration exists, no
    // caller may turn a Push fact set into a Merge grant.
    if action.is_merge() {
        return Err(DecisionError::Denied(DenialCode::UnsupportedAction));
    }
    if plan.identity().issuer_id() != actor.id {
        return Err(DecisionError::Denied(DenialCode::TokenInvalid));
    }
    if plan.refs().is_empty() || plan.refs().len() > MAX_DECISION_REFS {
        return Err(DecisionError::Ledger("decision ref count is out of bounds"));
    }
    facts_bridge::ensure_binds(plan, facts)?;
    crate::ref_store::pg::bound(tx, deadline).await?;
    install_in_tx(tx, plan, facts, actor, kind, action).await
}

async fn install_in_tx(
    tx: &Transaction<'_>,
    plan: &PackCommitPlan,
    facts: &VerifiedPublicationFacts,
    actor: &Identity,
    kind: DecisionKind,
    action: &PublicationAction,
) -> Result<SelectedDecision, DecisionError> {
    // 1. Coarse, fixed-order source locks (`NOWAIT`) before any authority read.
    sql_locks::lock_source_tables(tx, action).await?;
    sql_locks::lock_repository_row(tx, plan.repository_id()).await?;
    // 2. Ordered retained-usage rows: tenant, then repository. Integration may already have done it.
    sql_locks::lock_usage(tx, plan.repository_id(), plan.tenant_id()).await?;

    // 3. Exact replay or conflict of this operation identity (control row, by row).
    if let Some(existing) =
        sql_locks::decision_by_operation(tx, plan.repository_id(), plan.identity().operation_id(), true).await?
    {
        return replay(tx, plan, facts, &existing, kind, actor, action).await;
    }

    // 4. Cancel-before-install tombstone wins over a fresh decision.
    let tombstone = tx
        .query_opt(
            "SELECT request_digest FROM ref_store_decision_cancellations
             WHERE repository_id=$1 AND operation_id=$2 FOR UPDATE",
            &[&plan.repository_id(), &plan.identity().operation_id()],
        )
        .await
        .map_err(sql_locks::sql_error)?;
    if let Some(row) = tombstone {
        let request_digest: String = row.get(0);
        if request_digest != plan.identity().digest().as_hex() {
            return Err(DecisionError::Ledger("cancellation tombstone binds another operation digest"));
        }
        return Err(DecisionError::Cancelled { operation_id: plan.identity().operation_id(), decision_id: None });
    }

    // 5. Live authorization (gate -> protocol realm exact match) and policy facts.
    let mut authority = auth_deps::load_live_authority(tx, plan, actor, action).await?;
    let pointer_oids = select::collect_lfs_oids(plan.refs(), facts)?;
    authority.policy.lfs_objects = auth_deps::read_lfs_objects(tx, plan, &pointer_oids).await?;

    // 6. One policy verdict per original ref, then the ONLY selection constructor.
    let outcome = select::policy_verdicts(&SelectionInput {
        action,
        format: plan.object_format(),
        refs: plan.refs(),
        actor_id: actor.id,
        policy: &authority.policy,
        facts,
    })?;
    let projection =
        SelectedPackPlan::seal(plan.clone(), facts, &outcome.policy).map_err(facts_bridge::native_error)?;
    let verdict_rows = projection.selection().canonical_rows();

    // 7. Digests bind the exact sealed projection; no decision-owned selection domain.
    let captured = facts_bridge::captured_oid_digest(facts)?;
    let digests = DecisionDigests::compute(
        plan,
        *projection.selection_digest(),
        &authority.policy,
        authority.authz_digest(),
        &authority.dependencies,
        facts_bridge::facts_digest(facts),
        captured,
    );

    // 8. Scope control rows (frozen order), retained charge, then the fresh DB clock after all waits.
    let mut scope_locks = authority.dependencies.iter().collect::<Vec<_>>();
    scope_locks.sort_by_key(|dependency| (dependency.kind.as_str(), dependency.id));
    for dependency in scope_locks {
        sql_locks::observe_scope(tx, dependency.kind, dependency.id, dependency.version).await?;
    }
    let token_digest = hex::encode(&actor.token_digest);
    let delta = usage::delta_for(&verdict_rows, authority.dependencies.len(), token_digest.len())?;
    usage::charge(tx, plan.repository_id(), plan.tenant_id(), delta).await?;
    let now = sql_locks::db_clock(tx).await?;
    let not_after_millis = not_after(now, authority.earliest_expiry_millis())?;

    let decision_id = Uuid::new_v4();
    insert_decision(
        tx,
        NewDecision {
            decision_id,
            plan,
            actor,
            kind,
            action,
            state: DecisionState::Open,
            not_after_millis,
            created_db_millis: now,
            digests: &digests,
        },
        &token_digest,
    )
    .await?;
    insert_verdicts(tx, decision_id, &verdict_rows).await?;
    insert_dependencies(tx, decision_id, &authority.dependencies).await?;

    let capability = mint_capability(decision_id, plan, actor, kind, action, now, not_after_millis, digests);
    Ok(SelectedDecision::mint(capability, projection))
}

/// Earliest hard lifetime of a decision: policy cap, then the credential's own expiry.
fn not_after(now: i64, token_expiry: Option<i64>) -> Result<i64, DecisionError> {
    let mut not_after =
        now.checked_add(MAX_DECISION_WINDOW_MILLIS).ok_or(DecisionError::Ledger("decision not_after overflows i64"))?;
    if let Some(expiry) = token_expiry {
        not_after = not_after.min(expiry);
    }
    if not_after <= now {
        return Err(DecisionError::Denied(DenialCode::TokenExpired));
    }
    Ok(not_after)
}

struct NewDecision<'a> {
    decision_id: Uuid,
    plan: &'a PackCommitPlan,
    actor: &'a Identity,
    kind: DecisionKind,
    action: &'a PublicationAction,
    state: DecisionState,
    not_after_millis: i64,
    created_db_millis: i64,
    digests: &'a DecisionDigests,
}

async fn insert_decision(tx: &Transaction<'_>, new: NewDecision<'_>, token_digest: &str) -> Result<(), DecisionError> {
    let plan = new.plan;
    let identity = plan.identity();
    let repository_id = plan.repository_id();
    let tenant_id = plan.tenant_id();
    let owner_id = plan.owner_id();
    let operation_id = identity.operation_id();
    let issuer_id = identity.issuer_id();
    let lane = identity.lane().as_str();
    let sequence = identity.sequence();
    let mode = new.kind.as_str();
    let action = new.action.as_str();
    let (merge_pull_number, merge_version, merge_head, merge_base) = match new.action.merge_binding() {
        Some(binding) => (
            Some(binding.pull_number()),
            Some(binding.version()),
            Some(binding.head_oid().to_owned()),
            Some(binding.base_oid().to_owned()),
        ),
        None => (None, None, None, None),
    };
    let object_format = plan.object_format().as_str();
    let history_incarnation = plan.history_incarnation();
    let authority_epoch = plan.authority_epoch();
    let group_epoch = plan.group_epoch();
    let base_revision = plan.expected().revision();
    let state = new.state.as_str();
    let closed_code: Option<&str> = None;
    let base_gate_digest = new.digests.base_gate_digest.as_hex();
    let command_digest = new.digests.command_digest.as_hex();
    let refs_digest = new.digests.refs_digest.as_hex();
    let selected_refs_digest = new.digests.selected_refs_digest.as_hex();
    let selection_digest = new.digests.selection_digest.as_hex();
    let policy_digest = new.digests.policy_digest.as_hex();
    let facts_digest = new.digests.facts_digest.as_hex();
    let authz_digest = new.digests.authz_digest.as_hex();
    let dependencies_digest = new.digests.dependencies_digest.as_hex();
    let packs_digest = new.digests.packs_digest.as_hex();
    let hold_receipts_digest = new.digests.hold_receipts_digest.as_hex();
    let captured_oid_digest = new.digests.captured_oid_digest.as_hex();
    let params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = vec![
        &new.decision_id,
        &repository_id,
        &tenant_id,
        &owner_id,
        &new.actor.id,
        &new.actor.token_id,
        &token_digest,
        &operation_id,
        &issuer_id,
        &lane,
        &sequence,
        &mode,
        &object_format,
        &history_incarnation,
        &authority_epoch,
        &group_epoch,
        &base_revision,
        &base_gate_digest,
        &command_digest,
        &refs_digest,
        &selected_refs_digest,
        &selection_digest,
        &policy_digest,
        &facts_digest,
        &authz_digest,
        &dependencies_digest,
        &packs_digest,
        &hold_receipts_digest,
        &captured_oid_digest,
        &new.not_after_millis,
        &new.created_db_millis,
        &state,
        &closed_code,
        &action,
        &merge_pull_number,
        &merge_version,
        &merge_head,
        &merge_base,
    ];
    tx.execute(
        "INSERT INTO ref_store_publication_decisions(
             decision_id,repository_id,tenant_id,owner_id,actor_id,token_id,token_digest,operation_id,
             issuer_id,lane,sequence,mode,object_format,history_incarnation,authority_epoch,group_epoch,
             base_revision,base_gate_digest,command_digest,refs_digest,selected_refs_digest,
             selection_digest,policy_digest,facts_digest,authz_digest,dependencies_digest,packs_digest,
             hold_receipts_digest,captured_oid_digest,not_after_millis,created_db_millis,state,
             closed_code,action,merge_pull_number,merge_version,merge_head_oid,merge_base_oid)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,
                $23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,$37,$38)",
        &params,
    )
    .await
    .map_err(sql_locks::sql_error)?;
    Ok(())
}

pub(super) fn reject_code_of(canonical: &str) -> Option<&'static str> {
    let mut parts = canonical.splitn(3, ':');
    if parts.next()? != "rejected" {
        return None;
    }
    let reason = parts.next()?;
    let detail = parts.next().unwrap_or_default();
    use super::codes::DecisionRejectCode as Code;
    Some(
        match reason {
            "cas" => Code::OldOidMismatch,
            "missing_target" => Code::MissingTarget,
            "bad_object_type" => Code::BadObjectType,
            "prefix_conflict" => Code::PrefixConflict,
            "head_dependency" => Code::HeadDependencyMissing,
            _ => Code::parse(detail).unwrap_or(Code::PolicyDenied),
        }
        .as_str(),
    )
}

async fn insert_verdicts(
    tx: &Transaction<'_>,
    decision_id: Uuid,
    rows: &[(String, String)],
) -> Result<(), DecisionError> {
    for (ordinal, (name, canonical)) in rows.iter().enumerate() {
        let ordinal = ordinal as i32;
        let verdict = if canonical == "accepted" { "accept" } else { "reject" };
        let reject_code = reject_code_of(canonical);
        tx.execute(
            "INSERT INTO ref_store_decision_refs(
                 decision_id,ref_ordinal,ref_name,verdict,reject_code,old_oid,new_oid,selection_verdict)
             VALUES($1,$2,$3,$4,$5,NULL,NULL,$6)",
            &[&decision_id, &ordinal, &name, &verdict, &reject_code, &canonical],
        )
        .await
        .map_err(sql_locks::sql_error)?;
    }
    Ok(())
}

async fn insert_dependencies(
    tx: &Transaction<'_>,
    decision_id: Uuid,
    dependencies: &[super::contract::DependencyObservation],
) -> Result<(), DecisionError> {
    for dependency in dependencies {
        let kind = dependency.kind.as_str();
        let digest = dependency.digest.as_hex();
        tx.execute(
            "INSERT INTO ref_store_decision_dependencies(
                 decision_id,scope_kind,scope_id,observed_version,observed_digest)
             VALUES($1,$2,$3,$4,$5)",
            &[&decision_id, &kind, &dependency.id, &dependency.version, &digest],
        )
        .await
        .map_err(sql_locks::sql_error)?;
    }
    Ok(())
}

/// Exact replay of an existing decision for the same operation: a new capability is never minted for a
/// terminal decision, and a different plan/action/facts set under the same identity is a conflict.
async fn replay(
    tx: &Transaction<'_>,
    plan: &PackCommitPlan,
    facts: &VerifiedPublicationFacts,
    existing: &DecisionRow,
    kind: DecisionKind,
    actor: &Identity,
    action: &PublicationAction,
) -> Result<SelectedDecision, DecisionError> {
    if existing.operation_id != plan.identity().operation_id()
        || existing.repository_id != plan.repository_id()
        || existing.tenant_id != plan.tenant_id()
        || existing.owner_id != plan.owner_id()
        || existing.actor_id != actor.id
        || existing.token_id != actor.token_id
        || existing.mode != kind
        || &existing.action != action
        || existing.command_digest != *plan.parent_digest()
        || existing.refs_digest != digest::refs_digest(plan.refs())
        || existing.facts_digest != digest::native_facts_digest(&facts_bridge::facts_digest(facts))
    {
        return Err(DecisionError::Ledger("replayed decision does not bind this exact plan/action/facts"));
    }
    match existing.state {
        DecisionState::Open => {}
        DecisionState::Consumed => {
            return Err(DecisionError::Consumed {
                decision_id: existing.decision_id,
                receipt_id: existing.consume_receipt_id.unwrap_or_else(Uuid::nil),
            });
        }
        DecisionState::Cancelled => {
            return Err(DecisionError::Cancelled {
                operation_id: existing.operation_id,
                decision_id: Some(existing.decision_id),
            });
        }
        DecisionState::Rejected => {
            return Err(DecisionError::DecisionConflict {
                decision_id: existing.decision_id,
                state: DecisionState::Rejected,
            });
        }
    }
    let stored = query::load_selection_rows(tx, existing.decision_id).await?;
    let policy = replay_policy(plan, &stored)?;
    let projection = SelectedPackPlan::seal(plan.clone(), facts, &policy).map_err(facts_bridge::native_error)?;
    let current = projection.selection().canonical_rows();
    let stored_map: BTreeMap<&str, &str> =
        stored.iter().map(|(name, canonical)| (name.as_str(), canonical.as_str())).collect();
    let current_map: BTreeMap<&str, &str> =
        current.iter().map(|(name, canonical)| (name.as_str(), canonical.as_str())).collect();
    if stored_map != current_map || projection.selection_digest() != &existing.selection_digest {
        return Err(DecisionError::Denied(DenialCode::SelectionChanged));
    }
    let capability = mint_capability(
        existing.decision_id,
        plan,
        actor,
        kind,
        action,
        existing.created_db_millis,
        existing.not_after_millis,
        digests_from_row(existing),
    );
    Ok(SelectedDecision::mint(capability, projection))
}

/// Reconstruct the policy input from the sealed persisted rows. Deterministic subset outcomes are
/// re-derived by `seal` from the same facts (they were never policy decisions); only `policy` rows are
/// replayed, and any unknown detail is rejected rather than widened.
fn replay_policy(plan: &PackCommitPlan, stored: &[(String, String)]) -> Result<Vec<PolicyVerdict>, DecisionError> {
    let map: BTreeMap<&str, &str> =
        stored.iter().map(|(name, canonical)| (name.as_str(), canonical.as_str())).collect();
    let mut policy = Vec::with_capacity(plan.refs().len());
    for update in plan.refs() {
        let canonical =
            map.get(update.name().as_str()).ok_or(DecisionError::Ledger("stored selection is missing a plan ref"))?;
        if *canonical == "accepted" {
            policy.push(PolicyVerdict::accept(update.name().clone()));
            continue;
        }
        let mut parts = canonical.splitn(3, ':');
        let (tag, reason, detail) =
            (parts.next().unwrap_or_default(), parts.next().unwrap_or_default(), parts.next().unwrap_or_default());
        if tag != "rejected" || reason != "policy" || detail == "atomic-batch-rejected" {
            policy.push(PolicyVerdict::accept(update.name().clone()));
            continue;
        }
        let Ok(code) = super::codes::DecisionRejectCode::parse(detail) else {
            // Native failures are re-derived from the sealed facts. An unknown
            // stored policy cannot grant anything: the exact projection digest
            // must still match after reconstruction.
            policy.push(PolicyVerdict::accept(update.name().clone()));
            continue;
        };
        policy.push(
            PolicyVerdict::reject(update.name().clone(), super::subset::RefRejectReason::Policy, code.as_str())
                .map_err(|_| DecisionError::Ledger("stored policy detail is not a stable literal"))?,
        );
    }
    Ok(policy)
}

pub(super) fn digests_from_row(row: &DecisionRow) -> DecisionDigests {
    DecisionDigests {
        base_gate_digest: row.base_gate_digest,
        command_digest: row.command_digest,
        refs_digest: row.refs_digest,
        selected_refs_digest: row.selected_refs_digest,
        selection_digest: row.selection_digest,
        policy_digest: row.policy_digest,
        facts_digest: row.facts_digest,
        authz_digest: row.authz_digest,
        dependencies_digest: row.dependencies_digest,
        packs_digest: row.packs_digest,
        hold_receipts_digest: row.hold_receipts_digest,
        captured_oid_digest: row.captured_oid_digest,
    }
}

#[allow(clippy::too_many_arguments)]
fn mint_capability(
    decision_id: Uuid,
    plan: &PackCommitPlan,
    actor: &Identity,
    kind: DecisionKind,
    action: &PublicationAction,
    created_db_millis: i64,
    not_after_millis: i64,
    digests: DecisionDigests,
) -> DecisionCapability {
    DecisionCapability::mint(
        decision_id,
        plan.repository_id(),
        plan.tenant_id(),
        plan.owner_id(),
        actor.id,
        actor.token_id,
        plan.identity().operation_id(),
        kind,
        action.clone(),
        plan.object_format(),
        plan.expected().revision(),
        not_after_millis,
        created_db_millis,
        digests,
    )
}
